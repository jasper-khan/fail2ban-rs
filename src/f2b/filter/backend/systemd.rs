//! Pure-Rust systemd `journald` backend matching Fail2Ban 1.1.1
//! `fail2ban/server/filtersystemd.py`, backed by `journalctl --output=json --follow`.

use std::process::Stdio;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncBufReadExt, BufReader};
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

/// Systemd journal log reader spawning `journalctl --output=json --follow`.
#[derive(Debug, Clone)]
pub struct FilterSystemd {
    config: JournalConfig,
    encoding: LogEncoding,
    tail: bool,
    since_epoch: Option<f64>,
    journalctl_bin: String,
}

impl FilterSystemd {
    /// Construct a new [`FilterSystemd`] reader for `config`.
    pub fn new(config: JournalConfig, encoding: LogEncoding, tail: bool) -> Self {
        Self {
            config,
            encoding,
            tail,
            since_epoch: None,
            journalctl_bin: "journalctl".to_owned(),
        }
    }

    /// Resume reading journal entries starting from Unix epoch `since_epoch` seconds.
    pub fn with_since(mut self, since_epoch: Option<f64>) -> Self {
        self.since_epoch = since_epoch;
        self
    }

    /// Override the `journalctl` executable path (useful for testing).
    pub fn with_journalctl_bin(mut self, bin: impl Into<String>) -> Self {
        self.journalctl_bin = bin.into();
        self
    }

    /// Return the resolved `journalctl` CLI arguments for this configuration.
    pub fn args(&self) -> Vec<String> {
        build_journalctl_args(&self.config, self.since_epoch, self.tail)
    }

    /// Spawn `journalctl` and forward formatted journal entries until `shutdown` signals
    /// `true`, `tx` closes, or `journalctl` exits.
    pub async fn run(
        self,
        tx: mpsc::Sender<LogEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        if *shutdown.borrow() {
            return Ok(());
        }

        let args = self.args();
        let mut child = Command::new(&self.journalctl_bin)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| {
                Error::io(
                    format!("Failed to spawn {} {:?}", self.journalctl_bin, args),
                    err,
                )
            })?;

        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(Error::io(
                "journalctl child stdout not captured",
                std::io::Error::other("stdout pipe unavailable"),
            ));
        };

        let mut reader = BufReader::new(stdout);
        let mut line_buf = String::new();

        loop {
            line_buf.clear();
            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
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
                                    if let Some((formatted, preset_date)) = format_journal_entry(&val, self.encoding)
                                        && tx.send(LogEvent::Line {
                                            line: formatted,
                                            preset_date,
                                            log_path: None,
                                        }).await.is_err()
                                    {
                                        break;
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

        let _ = child.kill().await;
        let _ = child.wait().await;
        Ok(())
    }
}

/// Build `journalctl` CLI arguments matching `JournalConfig`, `since_epoch`, and `tail`.
pub fn build_journalctl_args(
    cfg: &JournalConfig,
    since_epoch: Option<f64>,
    tail: bool,
) -> Vec<String> {
    let mut args = vec![
        "--output=json".to_owned(),
        "--follow".to_owned(),
        "--no-pager".to_owned(),
    ];

    if let Some(ts) = since_epoch {
        args.push(format!("--since={}", format_journal_since(ts)));
    } else if tail {
        args.push("--lines=0".to_owned());
    } else {
        args.push("--lines=all".to_owned());
    }

    if let Some(ref path) = cfg.path {
        let is_file =
            path.is_file() || path.extension().is_some_and(|ext| ext == "journal");
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

    args
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
    let secs = ts.floor() as i64;
    if let Some(dt) = DateTime::<Utc>::from_timestamp(secs, 0) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
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

        let file_cfg = JournalConfig {
            matches: vec![],
            flags: Some(SD_JOURNAL_CURRENT_USER),
            path: Some(PathBuf::from("/tmp/system.journal")),
        };
        let file_args = build_journalctl_args(&file_cfg, None, false);
        assert!(file_args.contains(&"--lines=all".to_owned()));
        assert!(file_args.contains(&"--file=/tmp/system.journal".to_owned()));
        assert!(file_args.contains(&"--user".to_owned()));
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
