//! Pure-Rust systemd `journald` backend matching Fail2Ban 1.1.1
//! `fail2ban/server/filtersystemd.py`, backed by `journalctl --output=json --follow`.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};

use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};

use super::super::LogEncoding;
use super::{JournalConfig, LogEvent};

/// `SD_JOURNAL_SYSTEM` bit flag in `libsystemd/sd-journal.h`.
const SD_JOURNAL_SYSTEM: u32 = 4;
/// `SD_JOURNAL_CURRENT_USER` bit flag in `libsystemd/sd-journal.h`.
const SD_JOURNAL_CURRENT_USER: u32 = 8;
/// How long a newly spawned `journalctl` child must stay alive without error before clearing a prior backend error.
const HEALTHY_WINDOW: Duration = Duration::from_secs(2);
/// Timeout for one-shot `journalctl --lines=0` configuration validation probes.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Validate and split `journalmatch` tokens on `+` into OR-groups matching `libsystemd` field rules.
pub fn validate_journal_match_tokens(tokens: &[String]) -> Result<Vec<Vec<String>>> {
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let mut groups: Vec<Vec<String>> = vec![Vec::new()];
    for tok in tokens {
        if tok == "+" {
            if groups.last().is_some_and(Vec::is_empty) {
                return Err(Error::Value(
                    "Invalid journal match: '+' can only be used between match terms".to_owned(),
                ));
            }
            groups.push(Vec::new());
            continue;
        }
        let Some((field, _value)) = tok.split_once('=') else {
            return Err(Error::Value(format!(
                "Invalid journal match {tok:?}: expected FIELD=VALUE"
            )));
        };
        let bytes = field.as_bytes();
        let valid_field = !bytes.is_empty()
            && bytes.len() <= 64
            && matches!(bytes[0], b'A'..=b'Z' | b'_')
            && bytes
                .iter()
                .all(|&b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
        if !valid_field {
            return Err(Error::Value(format!(
                "Invalid journal match field in {tok:?}"
            )));
        }
        if let Some(last) = groups.last_mut() {
            last.push(tok.clone());
        }
    }
    if groups.last().is_some_and(Vec::is_empty) {
        return Err(Error::Value(
            "Invalid journal match: trailing '+' without following match terms".to_owned(),
        ));
    }
    Ok(groups)
}

/// Probe a proposed [`JournalConfig`] with `journalctl --output=json --no-pager --lines=0`
/// before adopting or replacing a live reader.
pub async fn validate_journal_config(cfg: &JournalConfig, journalctl_bin: &str) -> Result<()> {
    for grp in &cfg.matches {
        validate_journal_match_tokens(grp)?;
    }
    let mut args = vec![
        "--output=json".to_owned(),
        "--no-pager".to_owned(),
        "--lines=0".to_owned(),
    ];
    append_journal_source_and_matches(&mut args, cfg);

    let output = tokio::time::timeout(
        VALIDATE_TIMEOUT,
        Command::new(journalctl_bin)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        Error::Value(format!(
            "Timed out validating journal reader ({journalctl_bin})"
        ))
    })?
    .map_err(|err| Error::io(format!("Failed to spawn {journalctl_bin} {args:?}"), err))?;

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let detail = if stderr.is_empty() {
        format!("exited with {}", output.status)
    } else {
        stderr
    };
    Err(Error::Value(format!(
        "Journal reader rejected configuration: {detail}"
    )))
}

/// Systemd journal log reader spawning `journalctl --output=json --follow`.
#[derive(Debug, Clone)]
pub struct FilterSystemd {
    config: JournalConfig,
    encoding: LogEncoding,
    tail: bool,
    since_epoch: Option<f64>,
    after_cursor: Option<String>,
    journalctl_bin: String,
    health: Option<Arc<Mutex<Option<String>>>>,
}

impl FilterSystemd {
    /// Construct a new [`FilterSystemd`] reader for `config`.
    pub fn new(config: JournalConfig, encoding: LogEncoding, tail: bool) -> Self {
        Self {
            config,
            encoding,
            tail,
            since_epoch: None,
            after_cursor: None,
            journalctl_bin: "journalctl".to_owned(),
            health: None,
        }
    }

    /// Resume reading journal entries starting from Unix epoch `since_epoch` seconds.
    pub fn with_since(mut self, since_epoch: Option<f64>) -> Self {
        self.since_epoch = since_epoch;
        self
    }

    /// Resume reading journal entries strictly after systemd journal `__CURSOR`.
    pub fn with_after_cursor(mut self, cursor: Option<String>) -> Self {
        self.after_cursor = cursor;
        self
    }

    /// Attach a shared backend health slot so unexpected exits surface in jail status.
    pub fn with_health_sink(mut self, health: Arc<Mutex<Option<String>>>) -> Self {
        self.health = Some(health);
        self
    }

    /// Override the `journalctl` executable path (useful for testing).
    pub fn with_journalctl_bin(mut self, bin: impl Into<String>) -> Self {
        self.journalctl_bin = bin.into();
        self
    }

    /// Return the resolved `journalctl` CLI arguments for this configuration.
    pub fn args(&self) -> Vec<String> {
        build_journalctl_args_with_cursor(
            &self.config,
            self.since_epoch,
            self.after_cursor.as_deref(),
            self.tail,
        )
    }

    fn set_health(&self, err: Option<String>) {
        if let Some(ref slot) = self.health
            && let Ok(mut guard) = slot.lock()
        {
            *guard = err;
        }
    }

    /// Spawn `journalctl`, supervise unexpected exits with backoff, and forward
    /// formatted journal entries until `shutdown` signals `true` or `tx` closes.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<LogEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let start_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let mut in_operation = self.tail || self.after_cursor.is_some();
        let mut backoff = Duration::from_millis(100);

        loop {
            if *shutdown.borrow() {
                return Ok(());
            }

            let args = self.args();
            let mut child = match Command::new(&self.journalctl_bin)
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
            {
                Ok(child) => child,
                Err(err) => {
                    let msg = format!("Failed to spawn {} {:?}: {err}", self.journalctl_bin, args);
                    self.set_health(Some(msg.clone()));
                    return Err(Error::io(msg, err));
                }
            };

            let Some(stdout) = child.stdout.take() else {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let msg = "journalctl child stdout not captured".to_owned();
                self.set_health(Some(msg.clone()));
                return Err(Error::io(
                    msg,
                    std::io::Error::other("stdout pipe unavailable"),
                ));
            };
            let mut stderr = child.stderr.take();

            // Keep the startup cutoff fixed for this child so consecutive equal-timestamp
            // or older `_SOURCE_REALTIME_TIMESTAMP` entries are never dropped.
            let cutoff_since = if self.after_cursor.is_none() {
                self.since_epoch
            } else {
                None
            };
            let mut next_cursor: Option<String> = None;
            let mut last_ts: Option<f64> = None;
            let mut reader = BufReader::new(stdout);
            let mut line_buf = String::new();
            let mut stop_requested = false;
            let mut made_progress = false;
            let mut health_cleared = false;
            let healthy_timer = tokio::time::sleep(HEALTHY_WINDOW);
            tokio::pin!(healthy_timer);

            loop {
                line_buf.clear();
                tokio::select! {
                    res = shutdown.changed() => {
                        if res.is_err() || *shutdown.borrow() {
                            stop_requested = true;
                            break;
                        }
                    }
                    () = &mut healthy_timer, if !health_cleared => {
                        health_cleared = true;
                        self.set_health(None);
                    }
                    read_res = reader.read_line(&mut line_buf) => {
                        match read_res {
                            Ok(0) => break,
                            Ok(_) => {
                                let trimmed = line_buf.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                match serde_json::from_str::<serde_json::Value>(trimmed) {
                                    Ok(val) => {
                                        if let Some((formatted, preset_date)) = format_journal_entry(&val, self.encoding) {
                                            let realtime_ts = extract_u128_field(val.get("__REALTIME_TIMESTAMP"))
                                                .map(|us| us as f64 / 1_000_000.0)
                                                .or(preset_date);
                                            if let (Some(min_ts), Some(rt)) = (cutoff_since, realtime_ts)
                                                && rt < min_ts
                                            {
                                                continue;
                                            }
                                            if let Some(ts) = preset_date {
                                                if !in_operation && ts >= start_wall - 1.0 {
                                                    in_operation = true;
                                                }
                                                last_ts = Some(last_ts.map_or(ts, |prev| prev.max(ts)));
                                            }
                                            let cursor = val
                                                .get("__CURSOR")
                                                .and_then(serde_json::Value::as_str)
                                                .filter(|s| !s.is_empty())
                                                .map(str::to_owned);
                                            made_progress = true;
                                            if !health_cleared {
                                                health_cleared = true;
                                                self.set_health(None);
                                            }
                                            let ev = LogEvent::Line {
                                                line: formatted,
                                                preset_date,
                                                log_path: None,
                                                in_operation,
                                                checkpoint: None,
                                                journal_cursor: cursor.clone(),
                                            };
                                            tokio::select! {
                                                biased;
                                                res = shutdown.changed() => {
                                                    if res.is_err() || *shutdown.borrow() {
                                                        stop_requested = true;
                                                        break;
                                                    }
                                                }
                                                send_res = tx.send(ev) => {
                                                    if send_res.is_err() {
                                                        stop_requested = true;
                                                        break;
                                                    }
                                                    if let Some(c) = cursor {
                                                        next_cursor = Some(c);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        log_msg(
                                            LogLevel::Debug,
                                            "fail2ban.filter",
                                            &format!("Skipping malformed journalctl JSON line: {err}"),
                                        );
                                    }
                                }
                            }
                            Err(err) => {
                                log_msg(
                                    LogLevel::Warning,
                                    "fail2ban.filter",
                                    &format!("Error reading journalctl stdout: {err}"),
                                );
                                break;
                            }
                        }
                    }
                }
            }

            if stop_requested || *shutdown.borrow() || tx.is_closed() {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Ok(());
            }

            let status = child.wait().await;
            let mut stderr_buf = Vec::new();
            if let Some(ref mut err_pipe) = stderr {
                let _ = err_pipe.take(1024).read_to_end(&mut stderr_buf).await;
            }
            let stderr_text = String::from_utf8_lossy(&stderr_buf).trim().to_owned();
            let err_summary = match &status {
                Ok(code) if stderr_text.is_empty() => format!("Journal reader exited ({code})"),
                Ok(code) => format!("Journal reader exited ({code}): {stderr_text}"),
                Err(err) => format!("Journal reader wait error: {err}"),
            };
            self.set_health(Some(err_summary.clone()));

            if let Some(cursor) = next_cursor {
                self.after_cursor = Some(cursor);
            } else if self.after_cursor.is_none()
                && let Some(ts) = last_ts
            {
                let next_since = ts + 0.000_001;
                self.since_epoch = Some(
                    self.since_epoch
                        .map_or(next_since, |prev| prev.max(next_since)),
                );
            }

            log_msg(
                LogLevel::Warning,
                "fail2ban.filter",
                &format!(
                    "{err_summary}, reopening journal (cursor={}, since={:?})",
                    self.after_cursor.is_some(),
                    self.since_epoch
                ),
            );
            in_operation = true;
            if made_progress {
                backoff = Duration::from_millis(100);
            } else {
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                () = tokio::time::sleep(backoff) => {}
            }
        }
    }
}

/// Build `journalctl` CLI arguments matching `JournalConfig`, `since_epoch`, and `tail`.
pub fn build_journalctl_args(
    cfg: &JournalConfig,
    since_epoch: Option<f64>,
    tail: bool,
) -> Vec<String> {
    build_journalctl_args_with_cursor(cfg, since_epoch, None, tail)
}

/// Build `journalctl` CLI arguments preferring `--after-cursor` over `--since`/`--lines`.
pub fn build_journalctl_args_with_cursor(
    cfg: &JournalConfig,
    since_epoch: Option<f64>,
    after_cursor: Option<&str>,
    tail: bool,
) -> Vec<String> {
    let mut args = vec![
        "--output=json".to_owned(),
        "--follow".to_owned(),
        "--no-pager".to_owned(),
    ];

    if let Some(cursor) = after_cursor {
        args.push(format!("--after-cursor={cursor}"));
    } else if let Some(ts) = since_epoch {
        args.push(format!("--since={}", format_journal_since(ts)));
    } else if tail {
        args.push("--lines=0".to_owned());
    } else {
        args.push("--lines=all".to_owned());
    }

    append_journal_source_and_matches(&mut args, cfg);
    args
}

fn append_journal_source_and_matches(args: &mut Vec<String>, cfg: &JournalConfig) {
    if !cfg.files.is_empty() {
        for file in &cfg.files {
            args.push(format!("--file={}", file.display()));
        }
    } else {
        if let Some(ref ns) = cfg.namespace
            && !ns.is_empty()
        {
            args.push(format!("--namespace={ns}"));
        }

        if let Some(ref path) = cfg.path {
            let is_file = path.is_file() || path.extension().is_some_and(|ext| ext == "journal");
            if is_file {
                args.push(format!("--file={}", path.display()));
            } else {
                args.push(format!("--directory={}", path.display()));
            }
        }

        if let Some(flags) = cfg.flags {
            if (flags & SD_JOURNAL_SYSTEM) != 0 {
                args.push("--system".to_owned());
            }
            if (flags & SD_JOURNAL_CURRENT_USER) != 0 {
                args.push("--user".to_owned());
            }
        }
    }

    // Join OR-groups with `+` while keeping empty groups skipped.
    let mut non_empty_groups = 0usize;
    for group in &cfg.matches {
        let items: Vec<&str> = group
            .iter()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect();
        if items.is_empty() {
            continue;
        }
        if non_empty_groups > 0 {
            args.push("+".to_owned());
        }
        for item in items {
            args.push(item.to_owned());
        }
        non_empty_groups += 1;
    }
}

/// Format a parsed `journalctl --output=json` object into Fail2Ban's exact syslog-like line
/// format (`[<HOSTNAME> ]<IDENT>[<PID>]: [<kernel_ts> ]<MESSAGE>`) and extract its Unix
/// timestamp in seconds (`_SOURCE_REALTIME_TIMESTAMP` preferred over `__REALTIME_TIMESTAMP`).
pub fn format_journal_entry(
    entry: &serde_json::Value,
    encoding: LogEncoding,
) -> Option<(String, Option<f64>)> {
    let message = extract_message(entry.get("MESSAGE")?, encoding)?;
    let mut tokens: Vec<String> = Vec::new();

    if let Some(host) = extract_str_field(entry.get("_HOSTNAME"), encoding)
        && !host.is_empty()
    {
        tokens.push(host);
    }

    let ident = extract_str_field(entry.get("SYSLOG_IDENTIFIER"), encoding)
        .or_else(|| extract_str_field(entry.get("_COMM"), encoding));

    if let Some(id) = ident
        && !id.is_empty()
    {
        let pid = extract_str_field(entry.get("SYSLOG_PID"), encoding)
            .or_else(|| extract_str_field(entry.get("_PID"), encoding))
            .and_then(|s| parse_pid_base0(&s));

        let head = match pid {
            Some(p) => format!("{id}[{p}]:"),
            None => format!("{id}:"),
        };
        let is_kernel = head == "kernel:";
        tokens.push(head);

        if is_kernel
            && let Some(mono_us) = extract_u128_field(
                entry
                    .get("_SOURCE_MONOTONIC_TIMESTAMP")
                    .or_else(|| entry.get("__MONOTONIC_TIMESTAMP")),
            )
        {
            let secs = mono_us as f64 / 1_000_000.0;
            tokens.push(format!("[{secs:12.6}]"));
        }
    }

    tokens.push(message.replace('\n', "\\n"));
    let line = tokens.join(" ");

    let preset_date = extract_u128_field(
        entry
            .get("_SOURCE_REALTIME_TIMESTAMP")
            .or_else(|| entry.get("__REALTIME_TIMESTAMP")),
    )
    .map(|us| us as f64 / 1_000_000.0);

    Some((line, preset_date))
}

fn format_journal_since(ts: f64) -> String {
    let total_us = (ts * 1_000_000.0).round() as i64;
    let secs = total_us.div_euclid(1_000_000);
    let micros = total_us.rem_euclid(1_000_000) as u32;
    if let Some(dt) = DateTime::<Utc>::from_timestamp(secs, micros * 1000) {
        if micros == 0 {
            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        } else {
            format!("{} UTC", dt.format("%Y-%m-%d %H:%M:%S.%6f"))
        }
    } else {
        format!("@{secs}")
    }
}

fn parse_pid_base0(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

fn extract_u128_field(val: Option<&serde_json::Value>) -> Option<u128> {
    match val? {
        serde_json::Value::String(s) => s.trim().parse::<u128>().ok(),
        serde_json::Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

fn try_decode_byte_array(items: &[serde_json::Value], encoding: LogEncoding) -> Option<String> {
    if !items.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255)) {
        return None;
    }
    let bytes: Vec<u8> = items
        .iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();
    Some(encoding.decode(&bytes))
}

fn extract_str_field(val: Option<&serde_json::Value>, encoding: LogEncoding) -> Option<String> {
    match val? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(items) => try_decode_byte_array(items, encoding),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn extract_message(val: &serde_json::Value, encoding: LogEncoding) -> Option<String> {
    match val {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(items) => {
            if let Some(s) = try_decode_byte_array(items, encoding) {
                return Some(s);
            }
            let parts: Vec<String> = items
                .iter()
                .filter_map(|v| extract_str_field(Some(v), encoding))
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(" "))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_journalctl_args_formats_matches_flags_path_and_since() {
        let cfg = JournalConfig {
            matches: vec![
                vec!["_SYSTEMD_UNIT=sshd.service".into()],
                vec!["SYSLOG_IDENTIFIER=sshd".into(), "_TRANSPORT=syslog".into()],
            ],
            flags: Some(SD_JOURNAL_SYSTEM),
            path: Some(PathBuf::from("/var/log/journal")),
            files: Vec::new(),
            namespace: None,
        };

        let tail_args = build_journalctl_args(&cfg, None, true);
        assert_eq!(
            tail_args,
            vec![
                "--output=json",
                "--follow",
                "--no-pager",
                "--lines=0",
                "--directory=/var/log/journal",
                "--system",
                "_SYSTEMD_UNIT=sshd.service",
                "+",
                "SYSLOG_IDENTIFIER=sshd",
                "_TRANSPORT=syslog",
            ]
        );

        let since_args = build_journalctl_args(&cfg, Some(1_715_675_415.0), true);
        assert!(since_args.contains(&"--since=2024-05-14 08:30:15 UTC".to_owned()));
        assert!(!since_args.contains(&"--lines=0".to_owned()));

        let subsec_args = build_journalctl_args(&cfg, Some(1_715_675_415.25), true);
        assert!(subsec_args.contains(&"--since=2024-05-14 08:30:15.250000 UTC".to_owned()));

        let file_cfg = JournalConfig {
            matches: vec![],
            flags: Some(SD_JOURNAL_CURRENT_USER),
            path: Some(PathBuf::from("/tmp/system.journal")),
            files: Vec::new(),
            namespace: Some("myns".to_owned()),
        };
        let file_args = build_journalctl_args(&file_cfg, None, false);
        assert!(file_args.contains(&"--lines=all".to_owned()));
        assert!(file_args.contains(&"--namespace=myns".to_owned()));
        assert!(file_args.contains(&"--file=/tmp/system.journal".to_owned()));
        assert!(file_args.contains(&"--user".to_owned()));

        let multi_files_cfg = JournalConfig {
            matches: vec![],
            flags: Some(SD_JOURNAL_SYSTEM),
            path: Some(PathBuf::from("/var/log/journal")),
            files: vec![
                PathBuf::from("/tmp/a.journal"),
                PathBuf::from("/tmp/b.journal"),
            ],
            namespace: None,
        };
        let multi_args = build_journalctl_args(&multi_files_cfg, None, false);
        assert!(multi_args.contains(&"--file=/tmp/a.journal".to_owned()));
        assert!(multi_args.contains(&"--file=/tmp/b.journal".to_owned()));
        assert!(!multi_args.contains(&"--system".to_owned()));
        assert!(!multi_args.contains(&"--directory=/var/log/journal".to_owned()));
    }

    #[test]
    fn format_journal_entry_handles_systemd_kernel_bytes_and_multiline() {
        let sshd: serde_json::Value = serde_json::json!({
            "_HOSTNAME": "srv01",
            "SYSLOG_IDENTIFIER": "sshd",
            "SYSLOG_PID": "4321",
            "MESSAGE": "Failed password for invalid user admin\nfrom 192.0.2.55 port 22",
            "__REALTIME_TIMESTAMP": "1715675415500000"
        });
        let (line, ts) = format_journal_entry(&sshd, LogEncoding::Utf8).unwrap();
        assert_eq!(
            line,
            "srv01 sshd[4321]: Failed password for invalid user admin\\nfrom 192.0.2.55 port 22"
        );
        assert!((ts.unwrap() - 1_715_675_415.5).abs() < 1e-6);

        let kernel: serde_json::Value = serde_json::json!({
            "_COMM": "kernel",
            "_SOURCE_MONOTONIC_TIMESTAMP": "123456789",
            "_SOURCE_REALTIME_TIMESTAMP": "1715675416000000",
            "__REALTIME_TIMESTAMP": "1715675415000000",
            "MESSAGE": [79, 107]
        });
        let (kline, kts) = format_journal_entry(&kernel, LogEncoding::Utf8).unwrap();
        assert_eq!(kline, "kernel: [  123.456789] Ok");
        assert!((kts.unwrap() - 1_715_675_416.0).abs() < 1e-6);
    }
}
