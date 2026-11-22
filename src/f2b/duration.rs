//! Fail2Ban 1.1.1 `MyTime` duration & timestamp helpers (`str2seconds`, `seconds2str`, `time2str`).

use crate::error::{Error, Result};
use chrono::{Local, TimeZone};

const YEAR_SECONDS: f64 = ((365 * 3 + 366) as f64) * 86400.0 / 4.0; // 31_557_600.0
const MONTH_SECONDS: f64 = YEAR_SECONDS / 12.0; // 2_629_800.0

/// Parse a Fail2Ban 1.1.1 time expression (`MyTime.str2seconds`) into seconds.
///
/// Examples: `"10m"` -> `600.0`, `"1h 30m"` -> `5400.0`, `"1d12h"` -> `129600.0`,
/// `"1year-6mo"` -> `15778800.0`, `"-1"` -> `-1.0`, `"2*60"` -> `120.0`.
pub fn str2seconds(raw: &str) -> Result<f64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::config("empty duration expression"));
    }
    if let Ok(n) = trimmed.parse::<i64>() {
        return Ok(n as f64);
    }
    if let Ok(n) = trimmed.parse::<f64>()
        && n.is_finite()
    {
        return Ok(n);
    }

    let tokens = tokenize_duration(trimmed)?;
    let mut pos = 0;
    let val = parse_add_sub(&tokens, &mut pos)?;
    if pos != tokens.len() || !val.is_finite() {
        return Err(Error::config(format!(
            "invalid duration expression: {raw:?}"
        )));
    }
    Ok(val)
}

/// Parse a Fail2Ban 1.1.1 time expression as integer seconds (matching upstream `int(...)` / truncation).
pub fn str2seconds_i64(raw: &str) -> Result<i64> {
    let v = str2seconds(raw)?;
    if !v.is_finite() || v < (i64::MIN as f64) || v > (i64::MAX as f64) {
        return Err(Error::config(format!("duration out of range: {raw:?}")));
    }
    Ok(v.round() as i64)
}

/// Format seconds using Fail2Ban 1.1.1 `MyTime.seconds2str` rules.
pub fn seconds2str(sec: f64) -> String {
    let s_f = sec;
    if s_f >= 31_536_000.0 {
        let mut s = (s_f / 86400.0).round_ties_even() as i64;
        let mut r = format!("{}y ", s / 365);
        s %= 365;
        if s >= 7 {
            r.push_str(&format!("{}w ", s / 7));
            s %= 7;
        }
        if s > 0 {
            r.push_str(&format!("{s}d "));
        }
        r.pop();
        return r;
    }
    if s_f >= 604_800.0 {
        let mut s = (s_f / 3600.0).round_ties_even() as i64;
        let mut r = format!("{}w ", s / 168);
        s %= 168;
        if s >= 24 {
            r.push_str(&format!("{}d ", s / 24));
            s %= 24;
        }
        if s > 0 {
            r.push_str(&format!("{s}h "));
        }
        r.pop();
        return r;
    }
    if s_f >= 86_400.0 {
        let mut s = (s_f / 60.0).round_ties_even() as i64;
        let mut r = format!("{}d ", s / 1440);
        s %= 1440;
        if s >= 60 {
            r.push_str(&format!("{}h ", s / 60));
            s %= 60;
        }
        if s > 0 {
            r.push_str(&format!("{s}m "));
        }
        r.pop();
        return r;
    }
    if s_f >= 3595.0 {
        let mut s = (s_f / 10.0).round_ties_even() as i64;
        let mut r = format!("{}h ", s / 360);
        s %= 360;
        if s >= 6 {
            r.push_str(&format!("{}m ", s / 6));
        }
        r.pop();
        return r;
    }
    let mut s = s_f as i64;
    let mut r = String::new();
    if s >= 60 {
        r.push_str(&format!("{}m ", s / 60));
        s %= 60;
    }
    if s != 0 {
        r.push_str(&format!("{s}s "));
    } else if s_f == 0.0 {
        r.push_str("0 ");
    }
    r.pop();
    r
}

/// Format unix timestamp as local ISO string `YYYY-MM-DD HH:MM:SS` (`MyTime.time2str`).
pub fn time2str(unix_secs: f64) -> String {
    if unix_secs >= 253_402_214_400.0 {
        return "9999-12-31 23:59:59".to_owned();
    }
    let secs = unix_secs.floor() as i64;
    match Local.timestamp_opt(secs, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "1970-01-01 00:00:00".to_owned(),
    }
}

/// Parse Fail2Ban boolean values (`_as_bool`).
pub fn parse_bool(raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(Error::config(format!("Unable to convert {raw:?} to bool"))),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Plus,
    Minus,
    Star,
    Slash,
    LParen,
    RParen,
}

fn unit_multiplier(unit: &str) -> Option<f64> {
    match unit.to_ascii_lowercase().as_str() {
        "s" | "ss" | "se" | "sec" | "second" | "seconds" => Some(1.0),
        "m" | "mm" | "mi" | "min" | "minute" | "minutes" => Some(60.0),
        "h" | "hh" | "ho" | "hou" | "hour" | "hours" => Some(3600.0),
        "d" | "dd" | "da" | "day" | "days" => Some(86400.0),
        "w" | "ww" | "we" | "wee" | "week" | "weeks" => Some(7.0 * 86400.0),
        "mo" | "mon" | "month" | "months" => Some(MONTH_SECONDS),
        "y" | "yy" | "ye" | "yea" | "year" | "years" => Some(YEAR_SECONDS),
        _ => None,
    }
}

fn tokenize_duration(input: &str) -> Result<Vec<Tok>> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out: Vec<Tok> = Vec::new();
    let mut last_was_value = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b.is_ascii_digit() || (b == b'.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit())
        {
            if last_was_value {
                out.push(Tok::Plus);
            }
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let num: f64 = input[start..i]
                .parse()
                .map_err(|_| Error::config(format!("invalid number in duration: {input:?}")))?;
            out.push(Tok::Num(num));
            last_was_value = true;
            continue;
        }
        if b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let word = &input[start..i];
            let mult = unit_multiplier(word).ok_or_else(|| {
                Error::config(format!("unknown duration unit {word:?} in {input:?}"))
            })?;
            if !last_was_value {
                return Err(Error::config(format!(
                    "unit {word:?} without leading value in {input:?}"
                )));
            }
            out.push(Tok::Star);
            out.push(Tok::Num(mult));
            last_was_value = true;
            continue;
        }
        match b {
            b'+' => {
                out.push(Tok::Plus);
                last_was_value = false;
            }
            b'-' => {
                out.push(Tok::Minus);
                last_was_value = false;
            }
            b'*' => {
                out.push(Tok::Star);
                last_was_value = false;
            }
            b'/' => {
                out.push(Tok::Slash);
                last_was_value = false;
            }
            b'(' => {
                if last_was_value {
                    out.push(Tok::Plus);
                }
                out.push(Tok::LParen);
                last_was_value = false;
            }
            b')' => {
                out.push(Tok::RParen);
                last_was_value = true;
            }
            _ => {
                return Err(Error::config(format!(
                    "unexpected character {:?} in duration {input:?}",
                    b as char
                )));
            }
        }
        i += 1;
    }
    Ok(out)
}

fn parse_add_sub(toks: &[Tok], pos: &mut usize) -> Result<f64> {
    let mut lhs = parse_mul_div(toks, pos)?;
    while let Some(op) = toks.get(*pos) {
        match op {
            Tok::Plus => {
                *pos += 1;
                lhs += parse_mul_div(toks, pos)?;
            }
            Tok::Minus => {
                *pos += 1;
                lhs -= parse_mul_div(toks, pos)?;
            }
            _ => break,
        }
    }
    Ok(lhs)
}

fn parse_mul_div(toks: &[Tok], pos: &mut usize) -> Result<f64> {
    let mut lhs = parse_unary(toks, pos)?;
    while let Some(op) = toks.get(*pos) {
        match op {
            Tok::Star => {
                *pos += 1;
                lhs *= parse_unary(toks, pos)?;
            }
            Tok::Slash => {
                *pos += 1;
                let rhs = parse_unary(toks, pos)?;
                if rhs == 0.0 {
                    return Err(Error::config("division by zero in duration expression"));
                }
                lhs /= rhs;
            }
            _ => break,
        }
    }
    Ok(lhs)
}

fn parse_unary(toks: &[Tok], pos: &mut usize) -> Result<f64> {
    match toks.get(*pos) {
        Some(Tok::Plus) => {
            *pos += 1;
            parse_unary(toks, pos)
        }
        Some(Tok::Minus) => {
            *pos += 1;
            Ok(-parse_unary(toks, pos)?)
        }
        Some(Tok::Num(n)) => {
            *pos += 1;
            Ok(*n)
        }
        Some(Tok::LParen) => {
            *pos += 1;
            let v = parse_add_sub(toks, pos)?;
            if toks.get(*pos) != Some(&Tok::RParen) {
                return Err(Error::config("unclosed '(' in duration expression"));
            }
            *pos += 1;
            Ok(v)
        }
        _ => Err(Error::config("unexpected token in duration expression")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str2seconds_matches_upstream_examples() {
        assert_eq!(str2seconds("10m").ok(), Some(600.0));
        assert_eq!(str2seconds("1h 2m 3s").ok(), Some(3723.0));
        assert_eq!(str2seconds("1hour+30min").ok(), Some(5400.0));
        assert_eq!(str2seconds("0d 1h 30m").ok(), Some(5400.0));
        assert_eq!(str2seconds("1d12h").ok(), Some(129600.0));
        assert_eq!(str2seconds("1year-6mo").ok(), Some(15_778_800.0));
        assert_eq!(str2seconds("6 months").ok(), Some(15_778_800.0));
        assert_eq!(str2seconds("-1").ok(), Some(-1.0));
    }

    #[test]
    fn seconds2str_matches_upstream_examples() {
        assert_eq!(seconds2str(86400.0 * 390.0), "1y 3w 4d");
        assert_eq!(seconds2str(86400.0 * 368.0), "1y 3d");
        assert_eq!(seconds2str(86400.0 * 365.4), "1y");
        assert_eq!(seconds2str(86400.0 * 365.5), "1y 1d");
        assert_eq!(
            seconds2str(86400.0 * 2.0 + 3600.0 * 7.0 + 60.0 * 15.0),
            "2d 7h 15m"
        );
        assert_eq!(seconds2str(86400.0 * 2.0 + 3599.0), "2d 1h");
        assert_eq!(seconds2str(3600.0 - 5.0), "1h");
        assert_eq!(seconds2str(3600.0 - 10.0), "59m 50s");
        assert_eq!(seconds2str(59.0), "59s");
        assert_eq!(seconds2str(0.0), "0");
    }
}
