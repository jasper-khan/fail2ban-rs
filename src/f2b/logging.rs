//! Fail2Ban 1.1.1 logging subsystem (`loglevel`, `logtarget`, `syslogsocket`, `flushlogs`).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::Local;

use crate::config::spec;
use crate::duration::parse_bool;
use crate::error::{Error, Result};

/// Numeric levels matching Python `logging` + Fail2Ban custom levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    HeavyDebug = 5,
    TraceDebug = 7,
    Debug = 10,
    Info = 20,
    Notice = 25,
    Warning = 30,
    Error = 40,
    Critical = 50,
}

impl LogLevel {
    pub fn parse(raw: &str) -> Result<Self> {
        let s = raw.trim();
        if let Ok(n) = s.parse::<i64>() {
            return match n {
                ..=5 => Ok(Self::HeavyDebug),
                6..=7 => Ok(Self::TraceDebug),
                8..=10 => Ok(Self::Debug),
                11..=20 => Ok(Self::Info),
                21..=25 => Ok(Self::Notice),
                26..=30 => Ok(Self::Warning),
                31..=40 => Ok(Self::Error),
                _ => Ok(Self::Critical),
            };
        }
        match s.to_ascii_uppercase().as_str() {
            "HEAVYDEBUG" => Ok(Self::HeavyDebug),
            "TRACEDEBUG" => Ok(Self::TraceDebug),
            "DEBUG" => Ok(Self::Debug),
            "INFO" => Ok(Self::Info),
            "NOTICE" => Ok(Self::Notice),
            "WARNING" | "WARN" => Ok(Self::Warning),
            "ERROR" => Ok(Self::Error),
            "CRITICAL" | "FATAL" => Ok(Self::Critical),
            _ => Err(Error::config(format!("Invalid log level {raw:?}"))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeavyDebug => "HEAVYDEBUG",
            Self::TraceDebug => "TRACEDEBUG",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Notice => "NOTICE",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Critical => "CRITICAL",
        }
    }

    pub const fn as_i64(self) -> i64 {
        self as i64
    }

    const fn syslog_severity(self) -> u8 {
        match self {
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug | Self::TraceDebug | Self::HeavyDebug => 7,
        }
    }
}

fn syslog_facility_code(raw: &str) -> u8 {
    match raw.trim().to_ascii_uppercase().as_str() {
        "KERN" => 0 << 3,
        "USER" => 1 << 3,
        "MAIL" => 2 << 3,
        "DAEMON" => 3 << 3,
        "AUTH" => 4 << 3,
        "SYSLOG" => 5 << 3,
        "LPR" => 6 << 3,
        "NEWS" => 7 << 3,
        "UUCP" => 8 << 3,
        "CRON" => 9 << 3,
        "AUTHPRIV" => 10 << 3,
        "FTP" => 11 << 3,
        "LOCAL0" => 16 << 3,
        "LOCAL1" => 17 << 3,
        "LOCAL2" => 18 << 3,
        "LOCAL3" => 19 << 3,
        "LOCAL4" => 20 << 3,
        "LOCAL5" => 21 << 3,
        "LOCAL6" => 22 << 3,
        "LOCAL7" => 23 << 3,
        _ => 3 << 3,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogTarget {
    Stdout,
    Sysout,
    Stderr,
    Syslog,
    SystemdJournal,
    File(PathBuf),
}

impl LogTarget {
    pub fn parse(raw: &str) -> Self {
        let base = split_target_options(raw).0;
        match base.to_ascii_uppercase().as_str() {
            "STDOUT" => Self::Stdout,
            "SYSOUT" => Self::Sysout,
            "STDERR" => Self::Stderr,
            "SYSLOG" => Self::Syslog,
            "SYSTEMD-JOURNAL" => Self::SystemdJournal,
            _ => Self::File(PathBuf::from(base)),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::Stdout => "STDOUT".to_owned(),
            Self::Sysout => "SYSOUT".to_owned(),
            Self::Stderr => "STDERR".to_owned(),
            Self::Syslog => "SYSLOG".to_owned(),
            Self::SystemdJournal => "SYSTEMD-JOURNAL".to_owned(),
            Self::File(p) => p.to_string_lossy().into_owned(),
        }
    }
}

fn split_target_options(raw: &str) -> (String, std::collections::BTreeMap<String, String>) {
    let trimmed = raw.trim();
    if trimmed.contains('[')
        && let Ok(parsed) = spec::parse(trimmed)
    {
        return (parsed.name.trim().to_owned(), parsed.parameters);
    }
    (trimmed.to_owned(), std::collections::BTreeMap::new())
}

fn resolve_syslog_socket_path(raw: &str) -> &str {
    if raw.eq_ignore_ascii_case("auto") {
        "/dev/log"
    } else {
        raw
    }
}

fn is_valid_unix_socket(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
}

const SYSTEMD_JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

struct LoggerState {
    level: LogLevel,
    target: LogTarget,
    syslog_socket: String,
    syslog_facility: u8,
    add_datetime: bool,
    padding: bool,
    custom_format: Option<String>,
    file: Option<File>,
}

impl Default for LoggerState {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            target: LogTarget::Stderr,
            syslog_socket: "auto".to_owned(),
            syslog_facility: 3 << 3,
            add_datetime: true,
            padding: true,
            custom_format: None,
            file: None,
        }
    }
}

fn state() -> &'static Mutex<LoggerState> {
    static STATE: OnceLock<Mutex<LoggerState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(LoggerState::default()))
}

pub fn set_level(level: LogLevel) {
    if let Ok(mut g) = state().lock() {
        g.level = level;
    }
}

pub fn get_level() -> LogLevel {
    state().lock().map(|g| g.level).unwrap_or(LogLevel::Info)
}

pub fn set_syslog_socket(socket: String) -> Result<()> {
    let mut g = state()
        .lock()
        .map_err(|_| Error::config("logger lock poisoned"))?;
    if g.syslog_socket == socket {
        return Ok(());
    }
    if g.target == LogTarget::Syslog {
        let resolved = resolve_syslog_socket_path(&socket);
        if !is_valid_unix_socket(resolved) {
            return Err(Error::config("Failed to change syslog socket"));
        }
    }
    g.syslog_socket = socket;
    Ok(())
}

pub fn get_syslog_socket() -> String {
    state()
        .lock()
        .map(|g| g.syslog_socket.clone())
        .unwrap_or_else(|_| "auto".to_owned())
}

pub fn set_target(target_str: &str) -> Result<()> {
    let (base, opts) = split_target_options(target_str);
    let upper = base.to_ascii_uppercase();
    if upper == "INHERITED" {
        return Ok(());
    }
    let target = match upper.as_str() {
        "STDOUT" => LogTarget::Stdout,
        "SYSOUT" => LogTarget::Sysout,
        "STDERR" => LogTarget::Stderr,
        "SYSLOG" => LogTarget::Syslog,
        "SYSTEMD-JOURNAL" => LogTarget::SystemdJournal,
        _ => LogTarget::File(PathBuf::from(&base)),
    };

    let mut g = state()
        .lock()
        .map_err(|_| Error::config("logger lock poisoned"))?;

    let opened = match &target {
        LogTarget::Syslog => {
            let resolved = resolve_syslog_socket_path(&g.syslog_socket);
            if !is_valid_unix_socket(resolved) {
                return Err(Error::config("Failed to change log target"));
            }
            if g.syslog_socket.eq_ignore_ascii_case("auto") {
                g.syslog_socket = resolved.to_owned();
            }
            None
        }
        LogTarget::File(path) => match open_log_file(path) {
            Ok(f) => Some(f),
            Err(_) => return Err(Error::config("Failed to change log target")),
        },
        _ => None,
    };

    let add_datetime = opts
        .get("datetime")
        .and_then(|v| parse_bool(v).ok())
        .unwrap_or(!matches!(target, LogTarget::Syslog | LogTarget::Sysout));
    let padding = opts
        .get("padding")
        .and_then(|v| parse_bool(v).ok())
        .unwrap_or(target != LogTarget::Syslog);
    let facility = opts
        .get("facility")
        .map_or(3 << 3, |v| syslog_facility_code(v));
    let custom_format = opts.get("format").filter(|v| !v.is_empty()).cloned();

    g.target = target;
    g.add_datetime = add_datetime;
    g.padding = padding;
    g.syslog_facility = facility;
    g.custom_format = custom_format;
    g.file = opened;
    Ok(())
}

pub fn get_target() -> String {
    state()
        .lock()
        .map(|g| g.target.as_str())
        .unwrap_or_else(|_| "STDERR".to_owned())
}

/// Reopen log file after logrotate (`flushlogs`). Returns `"rolled over"` or `"flushed"`.
pub fn flush_logs() -> Result<&'static str> {
    let mut g = state()
        .lock()
        .map_err(|_| Error::config("logger lock poisoned"))?;
    match &g.target {
        LogTarget::File(path) => {
            let new_file = open_log_file(path)?;
            g.file = Some(new_file);
            Ok("rolled over")
        }
        LogTarget::Sysout => {
            let _ = io::stdout().flush();
            Ok("rolled over")
        }
        LogTarget::Stdout | LogTarget::Stderr | LogTarget::Syslog | LogTarget::SystemdJournal => {
            let _ = io::stdout().flush();
            let _ = io::stderr().flush();
            Ok("flushed")
        }
    }
}

fn open_log_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::io(format!("opening log file {}", path.display()), e))
}

/// Format a Python `logging.Formatter`-style pattern (`%(asctime)s`, `%(name)-24s`,
/// `%(process)d`, `%(levelname)-7s`, `%(levelno)d`, `%(message)s`, `%(module)s`, `%(thread)X`).
fn format_custom_log_line(
    fmt: &str,
    asctime: &str,
    module: &str,
    pid: u32,
    level: LogLevel,
    msg: &str,
) -> String {
    let bytes = fmt.as_bytes();
    let mut out = String::with_capacity(fmt.len() + msg.len() + 32);
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'%' {
                i += 1;
            }
            out.push_str(&fmt[start..i]);
            continue;
        }
        if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
            out.push('%');
            i += 2;
            continue;
        }
        if i + 1 < bytes.len()
            && bytes[i + 1] == b'('
            && let Some(rel_close) = fmt[i + 2..].find(')')
        {
            let key = &fmt[i + 2..i + 2 + rel_close];
            let mut j = i + 2 + rel_close + 1;
            let mut left_align = false;
            let mut zero_pad = false;
            while j < bytes.len() && matches!(bytes[j], b'-' | b'+' | b' ' | b'#' | b'0') {
                if bytes[j] == b'-' {
                    left_align = true;
                } else if bytes[j] == b'0' {
                    zero_pad = true;
                }
                j += 1;
            }
            let w_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let width: Option<usize> = fmt[w_start..j].parse().ok();
            let mut prec: Option<usize> = None;
            if j < bytes.len() && bytes[j] == b'.' {
                j += 1;
                let p_start = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                prec = fmt[p_start..j].parse().ok();
            }
            if j < bytes.len() {
                let conv = bytes[j] as char;
                let resolved = match key {
                    "asctime" => Some(asctime.to_owned()),
                    "name" => Some(module.to_owned()),
                    "module" => Some(module.rsplit('.').next().unwrap_or(module).to_owned()),
                    "process" => Some(format_int_conv(u64::from(pid), conv)),
                    "levelname" => Some(level.as_str().to_owned()),
                    "levelno" => Some(format_int_conv(level.as_i64() as u64, conv)),
                    "message" => Some(msg.to_owned()),
                    "thread" => Some(format_int_conv(u64::from(pid), conv)),
                    _ => None,
                };
                if let Some(mut val) = resolved {
                    if conv == 's'
                        && let Some(max_chars) = prec
                    {
                        val = val.chars().take(max_chars).collect();
                    }
                    if let Some(w) = width {
                        let len = val.chars().count();
                        if len < w {
                            let pad = w - len;
                            if left_align {
                                out.push_str(&val);
                                for _ in 0..pad {
                                    out.push(' ');
                                }
                            } else {
                                let fill = if zero_pad && matches!(conv, 'd' | 'i' | 'x' | 'X') {
                                    '0'
                                } else {
                                    ' '
                                };
                                for _ in 0..pad {
                                    out.push(fill);
                                }
                                out.push_str(&val);
                            }
                        } else {
                            out.push_str(&val);
                        }
                    } else {
                        out.push_str(&val);
                    }
                    i = j + 1;
                    continue;
                }
            }
        }
        out.push('%');
        i += 1;
    }

    out
}

fn format_int_conv(n: u64, conv: char) -> String {
    match conv {
        'X' => format!("{n:X}"),
        'x' => format!("{n:x}"),
        _ => n.to_string(),
    }
}

fn encode_journal_field(buf: &mut Vec<u8>, key: &str, val: &str) {
    buf.extend_from_slice(key.as_bytes());
    if !val.contains('\n') {
        buf.push(b'=');
        buf.extend_from_slice(val.as_bytes());
        buf.push(b'\n');
    } else {
        buf.push(b'\n');
        buf.extend_from_slice(&(val.len() as u64).to_le_bytes());
        buf.extend_from_slice(val.as_bytes());
        buf.push(b'\n');
    }
}

fn encode_journal_datagram(prio: u8, module: &str, pid: u32, msg: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(msg.len() + module.len() + 96);
    encode_journal_field(&mut payload, "MESSAGE", msg);
    encode_journal_field(&mut payload, "PRIORITY", &prio.to_string());
    encode_journal_field(&mut payload, "SYSLOG_IDENTIFIER", "fail2ban");
    encode_journal_field(&mut payload, "SYSLOG_PID", &pid.to_string());
    encode_journal_field(&mut payload, "LOGGER", module);
    payload
}

fn send_to_journal_socket(sock_path: &str, prio: u8, module: &str, pid: u32, msg: &str) -> bool {
    let Ok(sock) = UnixDatagram::unbound() else {
        return false;
    };
    let payload = encode_journal_datagram(prio, module, pid, msg);
    sock.send_to(&payload, sock_path).is_ok()
}

/// Emit a Fail2Ban-formatted log line:
/// `YYYY-MM-DD HH:MM:SS,mmm fail2ban.<module> [pid]: LEVEL   msg`
/// (exact format parsed by stock `filter.d/recidive.conf`!).
pub fn log_msg(level: LogLevel, module: &str, msg: &str) {
    let Ok(mut g) = state().lock() else {
        return;
    };
    if level < g.level {
        return;
    }
    let pid = std::process::id();
    let lvl = level.as_str();
    let line = if let Some(ref fmt) = g.custom_format {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S,%3f").to_string();
        let mut rendered = format_custom_log_line(fmt, &ts, module, pid, level, msg);
        rendered.push('\n');
        rendered
    } else {
        let body = if g.padding {
            format!("{module:<24}[{pid}]: {lvl:<7} {msg}\n")
        } else {
            format!("{module}[{pid}]: {lvl} {msg}\n")
        };
        if g.add_datetime {
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S,%3f");
            format!("{ts} {body}")
        } else {
            body
        }
    };

    match &g.target {
        LogTarget::Stdout | LogTarget::Sysout => {
            let _ = io::stdout().write_all(line.as_bytes());
        }
        LogTarget::Stderr => {
            let _ = io::stderr().write_all(line.as_bytes());
        }
        LogTarget::SystemdJournal => {
            let prio = level.syslog_severity();
            if !send_to_journal_socket(SYSTEMD_JOURNAL_SOCKET, prio, module, pid, msg) {
                let jline = format!("<{prio}>{module}[{pid}]: {lvl} {msg}\n");
                let _ = io::stderr().write_all(jline.as_bytes());
            }
        }
        LogTarget::Syslog => {
            let sock_path = resolve_syslog_socket_path(&g.syslog_socket);
            let prio = g.syslog_facility + level.syslog_severity();
            let payload = format!("<{prio}>{}", line.trim_end_matches('\n'));
            if let Ok(sock) = UnixDatagram::unbound() {
                let _ = sock.send_to(payload.as_bytes(), sock_path);
            }
        }
        LogTarget::File(_) => {
            if let Some(f) = g.file.as_mut() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
    }
}

#[macro_export]
macro_rules! f2b_log {
    ($level:expr, $module:expr, $($arg:tt)*) => {{
        if $level >= $crate::logging::get_level() {
            $crate::logging::log_msg($level, $module, &format!($($arg)*));
        }
    }};
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn logtarget_options_sysout_and_syslog_socket_validation() {
        let prev_target = get_target();
        let prev_sock = get_syslog_socket();

        set_target("SYSOUT").unwrap();
        assert_eq!(get_target(), "SYSOUT");
        assert_eq!(flush_logs().unwrap(), "rolled over");

        set_target("STDOUT[datetime=off, padding=0]").unwrap();
        assert_eq!(get_target(), "STDOUT");
        assert_eq!(flush_logs().unwrap(), "flushed");

        set_syslog_socket("/nonexistent/fail2ban-test-syslog.sock".to_owned()).unwrap();
        assert!(set_target("SYSLOG").is_err());
        assert_eq!(get_target(), "STDOUT");

        // Non-existent parent directory must fail without creating directories (servertestcase.py:931).
        assert!(set_target("/nonexistent-f2b-parent-dir/test.log").is_err());
        assert_eq!(get_target(), "STDOUT");

        set_target("STDOUT[format=\"%(message)s\"]").unwrap();
        assert_eq!(get_target(), "STDOUT");

        let rendered = format_custom_log_line(
            "%(asctime)s %(name)-24s[%(process)d]: %(levelname)-5.5s %(message)s %%",
            "2024-05-14 08:30:00,123",
            "fail2ban.actions",
            42,
            LogLevel::Notice,
            "[sshd] Ban 192.0.2.1",
        );
        assert_eq!(
            rendered,
            "2024-05-14 08:30:00,123 fail2ban.actions        [42]: NOTIC [sshd] Ban 192.0.2.1 %"
        );

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("journal.sock");
        let server = UnixDatagram::bind(&sock_path).unwrap();
        assert!(send_to_journal_socket(
            sock_path.to_str().unwrap(),
            5,
            "fail2ban.actions",
            99,
            "line1\nline2",
        ));
        let mut recv_buf = [0u8; 512];
        let n = server.recv(&mut recv_buf).unwrap();
        let data = &recv_buf[..n];
        assert!(data.starts_with(b"MESSAGE\n\x0b\0\0\0\0\0\0\0line1\nline2\n"));
        assert!(
            data.windows(27)
                .any(|w| w == b"SYSLOG_IDENTIFIER=fail2ban\n")
        );
        assert!(data.windows(11).any(|w| w == b"PRIORITY=5\n"));

        let _ = set_syslog_socket(prev_sock);
        let _ = set_target(&prev_target);
    }
}
