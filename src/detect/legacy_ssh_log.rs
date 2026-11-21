//! Offline parser for a single plain RFC3164-derived SSH authentication line.
//!
//! Supported envelope: `Mmm dd HH:MM:SS HOST sshd[PID]: MESSAGE` (also
//! `sshd-session`). The caller supplies the UTC year; this parser never uses
//! the wall clock, guesses year rollover, or parses an explicit zone. No PRI,
//! RFC5424/journal wrappers, undated lines, missing PIDs, or multi-line input.
//! Hosts with a year-like prefix that the original date matcher can mistake
//! for an explicit year (e.g. `2001:db8::1`) are outside this subset too.

use chrono::NaiveDate;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct LegacySshLog<'a> {
    pub(super) host: &'a str,
    pub(super) program: &'a str,
    pub(super) pid: u32,
    pub(super) timestamp_text: &'a str,
    /// Exact date-stripped envelope used as the stock F-MLFID prefix.
    pub(super) session_key: &'a str,
    pub(super) message: &'a str,
    pub(super) unix_seconds: i64,
}

const TIMESTAMP_LEN: usize = 15;

fn month(abbr: &str) -> Option<u32> {
    match abbr {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn digits(a: u8, b: u8) -> Option<u32> {
    if a.is_ascii_digit() && b.is_ascii_digit() {
        Some(u32::from(a - b'0') * 10 + u32::from(b - b'0'))
    } else {
        None
    }
}

fn utc_timestamp(text: &str, year: i32) -> Option<i64> {
    let (month_name, rest) = text.split_at_checked(3)?;
    let &[b' ', d0, d1, b' ', h0, h1, b':', m0, m1, b':', s0, s1] = rest.as_bytes() else {
        return None;
    };
    let day = digits(if d0 == b' ' { b'0' } else { d0 }, d1)?;
    let date = NaiveDate::from_ymd_opt(year, month(month_name)?, day)?;
    let time = date.and_hms_opt(digits(h0, h1)?, digits(m0, m1)?, digits(s0, s1)?)?;
    Some(time.and_utc().timestamp())
}

fn looks_like_year(host: &str) -> bool {
    // Fail2Ban's first month-name template also accepts an explicit year
    // after HH:MM:SS. Don't apply the plain envelope parser if it could
    // claim a prefix of HOST as part of the date.
    let [b'2', b'0', decade, digit, tail @ ..] = host.as_bytes() else {
        return false;
    };
    decade.is_ascii_digit()
        && digit.is_ascii_digit()
        && tail
            .first()
            .is_none_or(|ch| !ch.is_ascii_alphanumeric() && *ch != b'_')
}

/// Parse a dated, PID-bearing SSH log envelope. Every text field borrows the
/// original input; the returned message excludes only its `]: ` delimiter.
pub(super) fn parse_ssh_syslog_utc(line: &str, year: i32) -> Option<LegacySshLog<'_>> {
    if !(1..=9999).contains(&year) || line.contains(['\r', '\n', '\0']) {
        return None;
    }
    let (timestamp_text, envelope) = line.split_at_checked(TIMESTAMP_LEN)?;
    let unix_seconds = utc_timestamp(timestamp_text, year)?;
    let (host, tail) = envelope.strip_prefix(' ')?.split_once(' ')?;
    if host.is_empty() || !host.bytes().all(|byte| byte.is_ascii_graphic()) || looks_like_year(host)
    {
        return None;
    }
    let (program, tail) = tail.split_once('[')?;
    if !matches!(program, "sshd" | "sshd-session") {
        return None;
    }
    let (pid, message) = tail.split_once("]: ")?;
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) || message.trim().is_empty()
    {
        return None;
    }
    let pid = pid.parse::<u32>().ok().filter(|&value| value != 0)?;
    Some(LegacySshLog {
        host,
        program,
        pid,
        timestamp_text,
        session_key: envelope.strip_suffix(message)?,
        message,
        unix_seconds,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_date_host_program_pid_and_exact_message() {
        let body = "Failed password for demo from 192.0.2.45 port 55231 ssh2  ";
        let line = format!("Jan  5 02:03:04 lab.example sshd[42]: {body}");
        assert_eq!(
            parse_ssh_syslog_utc(&line, 2026),
            Some(LegacySshLog {
                host: "lab.example",
                program: "sshd",
                pid: 42,
                timestamp_text: "Jan  5 02:03:04",
                session_key: " lab.example sshd[42]: ",
                message: body,
                unix_seconds: 1_767_578_584,
            })
        );
        let line = "Jan 05 02:03:04 fd00::10 sshd-session[318]: Accepted publickey";
        let parsed = parse_ssh_syslog_utc(line, 2026).unwrap();
        assert_eq!(
            (parsed.host, parsed.program, parsed.pid, parsed.message),
            ("fd00::10", "sshd-session", 318, "Accepted publickey")
        );
    }

    #[test]
    fn session_key_preserves_lexical_pid_and_program() {
        let line = "Jan  5 02:03:04 lab sshd-session[00042]: example";
        let parsed = parse_ssh_syslog_utc(line, 2026).unwrap();
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.session_key, " lab sshd-session[00042]: ");
    }

    #[test]
    fn year_is_explicit_utc_and_never_adjusted() {
        let december = "Dec 31 23:59:59 lab sshd[7]: Session closed";
        let january = "Jan  1 00:00:00 lab sshd[7]: Session opened";
        let last = parse_ssh_syslog_utc(december, 2025).unwrap().unix_seconds;
        let next = parse_ssh_syslog_utc(january, 2026).unwrap().unix_seconds;
        assert_eq!(next - last, 1);
        assert_ne!(
            parse_ssh_syslog_utc(january, 2025).unwrap().unix_seconds,
            next
        );
        let leap = "Feb 29 12:00:00 lab sshd[7]: Session opened";
        assert!(parse_ssh_syslog_utc(leap, 2024).is_some());
        assert!(parse_ssh_syslog_utc(leap, 2025).is_none());
        assert!(parse_ssh_syslog_utc(leap, 0).is_none());
    }

    #[test]
    fn malformed_and_non_plain_envelopes_fail_closed() {
        for line in [
            "Feb 30 12:00:00 lab sshd[7]: Session opened",
            "Jun 15 24:00:00 lab sshd[7]: Session opened",
            "Jun 15 23:59:60 lab sshd[7]: Session opened",
            "Jun  0 00:00:00 lab sshd[7]: Session opened",
            "JUN 15 00:00:00 lab sshd[7]: Session opened",
            "Jun 15 00:00:00  sshd[7]: Session opened",
            "Jun 15 00:00:00 lab sshd: Session opened",
            "Jun 15 00:00:00 2001:db8::1 sshd[7]: Session opened",
            "Jun 15 00:00:00 2026.lab sshd[7]: Session opened",
            "Jun 15 00:00:00 lab ssh[7]: Session opened",
            "Jun 15 00:00:00 lab sshd[0]: Session opened",
            "Jun 15 00:00:00 lab sshd[+7]: Session opened",
            "Jun 15 00:00:00 lab sshd[4294967296]: Session opened",
            "Jun 15 00:00:00 lab sshd[7]: ",
            "Jun 15 00:00:00 lab sshd[7]: Session\nopened",
            "<34>Jun 15 00:00:00 lab sshd[7]: Session opened",
            "2026-06-15T00:00:00Z lab sshd[7]: Session opened",
            "lab sshd[7]: Session opened",
        ] {
            assert!(parse_ssh_syslog_utc(line, 2026).is_none(), "{line}");
        }
    }
}
