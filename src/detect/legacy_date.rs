//! Offline-only date extraction for the stock Nginx error-log subset of
//! Fail2Ban 1.1.1's `{^LN-BEG}` template set.
//!
//! Supports fixed-width `YYYY/MM/DD HH:MM:SS` without fractional seconds or
//! an explicit zone, interpreted in UTC. This is not the general Fail2Ban
//! date detector: alternate templates, variable widths, timezone syntax and
//! cross-line reuse of the most recent date are outside this subset.

use std::sync::OnceLock;

use chrono::{Datelike, NaiveDate, Utc};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LegacyDate<'a> {
    pub(crate) before: &'a str,
    /// The exact group 1 text; any allowed punctuation prefix remains outside.
    pub(crate) matched: &'a str,
    pub(crate) after: &'a str,
    /// A syntactically matched but impossible date (e.g. February 30) has no
    /// timestamp, though the original offline matcher still removes its span.
    pub(crate) unix_seconds: Option<i64>,
}

const DATE_LEN: usize = 19;

fn is_word(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

fn boundary(text: &str) -> bool {
    text.chars().next().is_none_or(|ch| !is_word(ch))
}

fn unsupported_suffix(after: &str) -> bool {
    if !boundary(after) {
        return true;
    }
    if after
        .strip_prefix(['.', ','])
        .and_then(|rest| rest.as_bytes().first())
        .is_some_and(u8::is_ascii_digit)
    {
        return true;
    }
    let suffix = after.trim_start_matches(char::is_whitespace);
    if ["Z", "UTC", "GMT"]
        .iter()
        .any(|zone| suffix.strip_prefix(zone).is_some_and(boundary))
    {
        return true;
    }
    matches!(suffix.as_bytes(), [b'+' | b'-', b'0' | b'1', digit, ..] if digit.is_ascii_digit())
}

fn two_digits(a: u8, b: u8) -> Option<u32> {
    if [a, b].iter().all(u8::is_ascii_digit) {
        Some(u32::from(a - b'0') * 10 + u32::from(b - b'0'))
    } else {
        None
    }
}

// Upstream's %ExY recognizes whole decades from 2000 through the decade
// containing the current year plus three, fixed when its templates load.
fn max_template_year() -> i32 {
    static MAX_YEAR: OnceLock<i32> = OnceLock::new();
    *MAX_YEAR.get_or_init(|| (Utc::now().year() + 3).div_euclid(10) * 10 + 9)
}

/// Split a supported line-begin date exactly at the original date group span.
/// No supported span means the offline regex caller tests the unchanged line,
/// with no timestamp; it should not invent a timestamp or discard the line.
pub(crate) fn split_nginx_ln_begin(line: &str) -> Option<LegacyDate<'_>> {
    let prefix_bytes = line
        .chars()
        .take(2)
        .take_while(|&ch| !is_word(ch))
        .map(char::len_utf8)
        .sum();
    let (before, rest) = line.split_at_checked(prefix_bytes)?;
    let (matched, after) = rest.split_at_checked(DATE_LEN)?;
    if unsupported_suffix(after) {
        return None;
    }
    let &[
        y0,
        y1,
        y2,
        y3,
        b'/',
        m0,
        m1,
        b'/',
        d0,
        d1,
        b' ',
        h0,
        h1,
        b':',
        i0,
        i1,
        b':',
        s0,
        s1,
    ] = matched.as_bytes()
    else {
        return None;
    };
    let year = i32::try_from(two_digits(y0, y1)? * 100 + two_digits(y2, y3)?).ok()?;
    let (month, day, hour, minute, second) = (
        two_digits(m0, m1)?,
        two_digits(d0, d1)?,
        two_digits(h0, h1)?,
        two_digits(i0, i1)?,
        two_digits(s0, s1)?,
    );
    if !(2000..=max_template_year()).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 61
    {
        return None;
    }
    let unix_seconds = NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .map(|date| date.and_utc().timestamp());
    Some(LegacyDate {
        before,
        matched,
        after,
        unix_seconds,
    })
}

/// Split a Fail2Ban 1.1.1 `{^LN-BEG}` line timestamp supporting:
/// 1. Nginx `YYYY/MM/DD HH:MM:SS`
/// 2. ISO 8601 `YYYY-MM-DD[T ]HH:MM:SS[.,frac][tz]` (e.g. `recidive`)
/// 3. Apache `Day Mon DD HH:MM:SS[.frac] YYYY` (preserving surrounding `[` and `]` as `[]`)
/// 4. Syslog `Mon [ ]D HH:MM:SS` (e.g. `postfix`, `dovecot`, `sshd`)
pub(crate) fn split_legacy_ln_begin(line: &str) -> Option<LegacyDate<'_>> {
    if let Some(d) = split_nginx_ln_begin(line) {
        return Some(d);
    }
    if let Some(d) = split_iso_ln_begin(line) {
        return Some(d);
    }
    if let Some(d) = split_apache_ln_begin(line) {
        return Some(d);
    }
    split_syslog_ln_begin(line)
}

fn split_iso_ln_begin(line: &str) -> Option<LegacyDate<'_>> {
    // Allow optional leading `[` or single space.
    let (before, rest) = if let Some(r) = line.strip_prefix('[') {
        ("[", r)
    } else if let Some(r) = line.strip_prefix(' ') {
        (" ", r)
    } else {
        ("", line)
    };
    let head = rest.get(..19)?;
    let b = head.as_bytes();
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || !matches!(b.get(10), Some(b' ' | b'T'))
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let year: i32 = head.get(0..4)?.parse().ok()?;
    let month: u32 = head.get(5..7)?.parse().ok()?;
    let day: u32 = head.get(8..10)?.parse().ok()?;
    let hour: u32 = head.get(11..13)?.parse().ok()?;
    let min: u32 = head.get(14..16)?.parse().ok()?;
    let sec: u32 = head.get(17..19)?.parse().ok()?;
    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
    let mut after = rest.get(19..)?;
    if let Some(frac) = after.strip_prefix(['.', ',']) {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        after = frac.get(digits..)?;
    }
    if let Some(rem) = after.strip_prefix('Z') {
        after = rem;
    }
    let unix_seconds = naive
        .and_local_timezone(chrono::Local)
        .earliest()
        .map(|dt| dt.timestamp())
        .or_else(|| Some(naive.and_utc().timestamp()));
    let matched = rest
        .get(..rest.len().saturating_sub(after.len()))
        .unwrap_or("");
    Some(LegacyDate {
        before,
        matched,
        after,
        unix_seconds,
    })
}

fn parse_month_abbrev(m: &str) -> Option<u32> {
    match m {
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

fn split_apache_ln_begin(line: &str) -> Option<LegacyDate<'_>> {
    let (before, rest) = if let Some(r) = line.strip_prefix('[') {
        ("[", r)
    } else {
        ("", line)
    };
    // Format: `Sat Nov 21 12:10:00[.123456] 2026`
    let _dow = rest.get(0..3)?;
    if rest.as_bytes().get(3) != Some(&b' ') {
        return None;
    }
    let month = parse_month_abbrev(rest.get(4..7)?)?;
    if rest.as_bytes().get(7) != Some(&b' ') {
        return None;
    }
    let day_str = rest.get(8..10)?.trim();
    let day: u32 = day_str.parse().ok()?;
    if rest.as_bytes().get(10) != Some(&b' ') {
        return None;
    }
    let hms = rest.get(11..19)?;
    if hms.as_bytes().get(2) != Some(&b':') || hms.as_bytes().get(5) != Some(&b':') {
        return None;
    }
    let hour: u32 = hms.get(0..2)?.parse().ok()?;
    let min: u32 = hms.get(3..5)?.parse().ok()?;
    let sec: u32 = hms.get(6..8)?.parse().ok()?;
    let mut tail = rest.get(19..)?;
    if let Some(frac) = tail.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        tail = frac.get(digits..)?;
    }
    let tail = tail.strip_prefix(' ')?;
    let year: i32 = tail.get(0..4)?.parse().ok()?;
    let after = tail.get(4..)?;
    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
    let unix_seconds = naive
        .and_local_timezone(chrono::Local)
        .earliest()
        .map(|dt| dt.timestamp())
        .or_else(|| Some(naive.and_utc().timestamp()));
    let matched = rest
        .get(..rest.len().saturating_sub(after.len()))
        .unwrap_or("");
    Some(LegacyDate {
        before,
        matched,
        after,
        unix_seconds,
    })
}

fn split_syslog_ln_begin(line: &str) -> Option<LegacyDate<'_>> {
    // Format: `Nov 21 12:10:00` or `Nov  1 12:10:00`
    let month = parse_month_abbrev(line.get(0..3)?)?;
    if line.as_bytes().get(3) != Some(&b' ') {
        return None;
    }
    let day_str = line.get(4..6)?.trim();
    let day: u32 = day_str.parse().ok()?;
    if line.as_bytes().get(6) != Some(&b' ') {
        return None;
    }
    let hms = line.get(7..15)?;
    if hms.as_bytes().get(2) != Some(&b':') || hms.as_bytes().get(5) != Some(&b':') {
        return None;
    }
    let hour: u32 = hms.get(0..2)?.parse().ok()?;
    let min: u32 = hms.get(3..5)?.parse().ok()?;
    let sec: u32 = hms.get(6..8)?.parse().ok()?;
    let after = line.get(15..)?;
    let year = chrono::Datelike::year(&chrono::Local::now());
    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
    let unix_seconds = naive
        .and_local_timezone(chrono::Local)
        .earliest()
        .map(|dt| dt.timestamp())
        .or_else(|| Some(naive.and_utc().timestamp()));
    let matched = line.get(..15).unwrap_or("");
    Some(LegacyDate {
        before: "",
        matched,
        after,
        unix_seconds,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn exact_date_span_keeps_prefix_and_native_whitespace() {
        for prefix in ["", " ", "[", "[]", "☃☃"] {
            let entry = format!("{prefix}2026/01/15 12:34:56 [error] example");
            assert_eq!(
                split_nginx_ln_begin(&entry),
                Some(LegacyDate {
                    before: prefix,
                    matched: "2026/01/15 12:34:56",
                    after: " [error] example",
                    unix_seconds: Some(1_768_480_496),
                })
            );
        }
        let bracket = split_nginx_ln_begin("[2026/01/15 12:34:56] [error] example").unwrap();
        assert_eq!((bracket.before, bracket.after), ("[", "] [error] example"));
        let adjacent = split_nginx_ln_begin("2026/01/15 12:34:56[error] example").unwrap();
        assert_eq!(adjacent.after, "[error] example");
    }

    #[test]
    fn syntax_match_without_calendar_time_still_has_a_span() {
        for date in [
            "2026/02/30 12:34:56",
            "2026/01/15 12:34:60",
            "2026/01/15 12:34:61",
        ] {
            let entry = format!("{date} [error] example");
            let parts = split_nginx_ln_begin(&entry).unwrap();
            assert_eq!(parts.matched, date);
            assert_eq!(parts.unix_seconds, None);
        }
    }

    #[test]
    fn missing_or_unsupported_date_leaves_original_line_to_the_caller() {
        for line in [
            " [error] example",
            "prefix 2026/01/15 12:34:56 [error] example",
            "三2026/01/15 12:34:56 [error] example",
            "   2026/01/15 12:34:56 [error] example",
            "2026/01/15 12:34:56X",
            "2026/01/15 12:34:567",
            "2026/13/02 12:34:56 [error] example",
            "2026/01/15 24:34:56 [error] example",
            "2026/01/15 12:34:56.123 -0300 example",
            "2026/01/15 12:34:56Z [error] example",
            "2026/01/15 12:34:56 UTC [error] example",
            "2026/01/15 12:34:56 +00:00 [error] example",
            "2026/01/05  2:03:04 example",
            "2026/1/5 2:3:4 example",
            "2026-01-15T12:34:56 [error] example",
        ] {
            assert_eq!(split_nginx_ln_begin(line), None, "{line}");
        }
    }
}
