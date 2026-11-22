//! Fail2Ban 1.1.1 logging subsystem (`loglevel`, `logtarget`, `syslogsocket`, `flushlogs`).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::Local;

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

    const fn syslog_priority(self) -> u8 {
        // LOG_DAEMON (3 << 3 = 24) + severity
        let sev = match self {
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug | Self::TraceDebug | Self::HeavyDebug => 7,
        };
        24 + sev
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogTarget {
    Stdout,
    Stderr,
    Syslog,
    SystemdJournal,
    File(PathBuf),
}

impl LogTarget {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_uppercase().as_str() {
            "STDOUT" => Self::Stdout,
            "STDERR" | "SYSOUT" => Self::Stderr,
            "SYSLOG" => Self::Syslog,
            "SYSTEMD-JOURNAL" => Self::SystemdJournal,
            _ => Self::File(PathBuf::from(raw.trim())),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::Stdout => "STDOUT".to_owned(),
            Self::Stderr => "STDERR".to_owned(),
            Self::Syslog => "SYSLOG".to_owned(),
            Self::SystemdJournal => "SYSTEMD-JOURNAL".to_owned(),
            Self::File(p) => p.to_string_lossy().into_owned(),
        }
    }
}

struct LoggerState {
    level: LogLevel,
    target: LogTarget,
    syslog_socket: String,
    file: Option<File>,
}

impl Default for LoggerState {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            target: LogTarget::Stderr,
            syslog_socket: "auto".to_owned(),
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
    let target = LogTarget::parse(target_str);
    let opened = match &target {
        LogTarget::File(path) => Some(open_log_file(path)?),
        _ => None,
    };
    let mut g = state()
        .lock()
        .map_err(|_| Error::config("logger lock poisoned"))?;
    g.target = target;
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
    if let LogTarget::File(path) = &g.target {
        let new_file = open_log_file(path)?;
        g.file = Some(new_file);
        Ok("rolled over")
    } else {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        Ok("flushed")
    }
}

fn open_log_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::io(format!("opening log file {}", path.display()), e))
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
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S,%3f");
    let line = format!("{ts} {module:<23} [{pid}]: {lvl:<7} {msg}\n");

    match &g.target {
        LogTarget::Stdout => {
            let _ = io::stdout().write_all(line.as_bytes());
        }
        LogTarget::Stderr => {
            let _ = io::stderr().write_all(line.as_bytes());
        }
        LogTarget::SystemdJournal => {
            let prio = level.syslog_priority() & 0x07;
            let jline = format!("<{prio}>{module}[{pid}]: {lvl} {msg}\n");
            let _ = io::stderr().write_all(jline.as_bytes());
        }
        LogTarget::Syslog => {
            let sock_path = if g.syslog_socket == "auto" {
                "/dev/log"
            } else {
                g.syslog_socket.as_str()
            };
            let prio = level.syslog_priority();
            let payload = format!("<{prio}>{module}[{pid}]: {lvl} {msg}");
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
