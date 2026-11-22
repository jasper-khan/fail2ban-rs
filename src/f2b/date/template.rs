//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/datetemplate.py`.
//!
//! Defines [`DateTemplate`] supporting regex/`strptime` date templates,
//! `EPOCH`/`LEPOCH` Unix epoch timestamps, `TAI64N` stamps, `{NONE}`,
//! `{UNB}`, and `{^LN-BEG}` boundary wrapping.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::error::{Error, Result};
use crate::filter::regex::CompiledRegex;

use super::strptime::{expand_date_pattern, re_group_dict_strptime};

/// Flag indicating template is anchored at beginning of line.
pub const FLAG_LINE_BEGIN: u8 = 8;
/// Flag indicating template is anchored at end of line.
pub const FLAG_LINE_END: u8 = 4;
/// Flag indicating template wraps start with word boundary.
pub const FLAG_WORD_BEGIN: u8 = 2;
/// Flag indicating template wraps end with word boundary.
pub const FLAG_WORD_END: u8 = 1;

const EPOCH_RE: &str = r"\d{10,11}\b(?:\.\d{3,6})?";
const LONG_EPOCH_RE: &str = r"\d{10,11}(?:\d{3}(?:\.\d{1,6}|\d{3})?)?";
const TAI64N_RE: &str = r"@[0-9a-f]{24}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateKind {
    Pattern,
    Epoch { long_frm: bool },
    Tai64n,
    NoneSentinel,
}

/// Compiled Fail2Ban date matching template and usage counters.
#[derive(Debug)]
pub struct DateTemplate {
    /// Human-readable template name (matching Fail2Ban `DateTemplate.name`).
    pub name: String,
    /// Original Fail2Ban datepattern string, if any.
    pub pattern: Option<String>,
    /// Expanded regular expression string.
    pub regex: String,
    compiled: Option<CompiledRegex>,
    /// Bitmask of `FLAG_*` boundary flags.
    pub flags: u8,
    /// Priority weight (`100.0` for line-begin templates, `0.0` otherwise).
    pub weight: f64,
    /// Successful timestamp hit counter (used by [`super::DateDetector`] adaptive ordering).
    pub hits: usize,
    /// Last match timestamp (monotonic wall clock when available).
    pub last_used: f64,
    kind: TemplateKind,
}

impl DateTemplate {
    /// Build a [`DateTemplate`] from a Fail2Ban pattern string.
    ///
    /// Supports `{NONE}`, `EPOCH`/`LEPOCH`/`{EPOCH}`/`{LEPOCH}`, `TAI64N`,
    /// `{^LN-BEG}` line-begin anchoring, `{UNB}` unbinding, `**` boundary
    /// suppression, and `%...` `strptime` directives.
    pub fn from_pattern(pattern: &str) -> Result<Self> {
        let trimmed = pattern.trim();
        if trimmed.eq_ignore_ascii_case("{NONE}") {
            return Ok(Self {
                name: "{NONE}".to_owned(),
                pattern: Some(pattern.to_owned()),
                regex: String::new(),
                compiled: None,
                flags: 0,
                weight: 0.0,
                hits: 0,
                last_used: 0.0,
                kind: TemplateKind::NoneSentinel,
            });
        }

        if let Some((line_begin, long_frm)) = match_standalone_epoch(trimmed) {
            return Self::new_epoch(pattern, line_begin, long_frm);
        }

        if let Some(line_begin) = match_standalone_tai64n(trimmed) {
            return Self::new_tai64n(pattern, line_begin);
        }

        Self::new_pattern(pattern)
    }

    fn new_epoch(orig_pattern: &str, line_begin: bool, long_frm: bool) -> Result<Self> {
        let num_re = if long_frm { LONG_EPOCH_RE } else { EPOCH_RE };
        let rx = if line_begin {
            format!(
                r"(?:^({num_re})|(?<=^\[)({num_re})(?=\]))(?=\b|\W|$)"
            )
        } else {
            format!(
                r"(?:^({num_re})|(?<=^\[)({num_re})(?=\])|(?<=\baudit\()({num_re})(?=:\d+\)))(?=\b|\W|$)"
            )
        };
        let compiled = CompiledRegex::compile(&rx, false)?;
        let flags = if line_begin {
            FLAG_LINE_BEGIN | FLAG_WORD_END
        } else {
            FLAG_WORD_END
        };
        let name = if long_frm { "LEPOCH" } else { "EPOCH" }.to_owned();
        Ok(Self {
            name,
            pattern: Some(orig_pattern.to_owned()),
            regex: rx,
            compiled: Some(compiled),
            flags,
            weight: 0.0,
            hits: 0,
            last_used: 0.0,
            kind: TemplateKind::Epoch { long_frm },
        })
    }

    fn new_tai64n(orig_pattern: &str, line_begin: bool) -> Result<Self> {
        let (rx, flags) = if line_begin {
            (
                format!(r"^(?:\W{{0,2}})?({TAI64N_RE})(?=\b|\W|$)"),
                FLAG_LINE_BEGIN | FLAG_WORD_END,
            )
        } else {
            (
                format!(r"(?:^|\b|\W)({TAI64N_RE})(?=\b|\W|$)"),
                FLAG_WORD_BEGIN | FLAG_WORD_END,
            )
        };
        let compiled = CompiledRegex::compile(&rx, false)?;
        Ok(Self {
            name: "TAI64N".to_owned(),
            pattern: Some(orig_pattern.to_owned()),
            regex: rx,
            compiled: Some(compiled),
            flags,
            weight: 0.0,
            hits: 0,
            last_used: 0.0,
            kind: TemplateKind::Tai64n,
        })
    }

    fn new_pattern(orig_pattern: &str) -> Result<Self> {
        let mut work = orig_pattern.to_owned();
        let mut unbound = false;
        let mut line_beg_tag = false;

        if let Some(rest) = work.strip_prefix("{UNB}") {
            unbound = true;
            work = rest.to_owned();
        }
        if let Some(rest) = work.strip_prefix("{^LN-BEG}") {
            line_beg_tag = true;
            work = rest.to_owned();
        }

        let no_wrd_beg = re_no_wrd_bound_beg().is_match(&work);
        let no_wrd_end = re_no_wrd_bound_end().is_match(&work);
        work = strip_double_star_bounds(&work);

        // Embedded {EPOCH} / {LEPOCH} tags inside a custom pattern.
        let (work_epoch, embedded_epoch) = replace_embedded_epoch(&work);

        let alpha_icase = re_alpha_pattern().is_match(&work_epoch);
        let (human_name, mut expanded) = expand_date_pattern(&work_epoch)?;

        let mut flags = 0u8;
        if !has_unnamed_capture(&expanded) {
            expanded = wrap_pattern_in_group(&expanded);
        }

        if line_beg_tag {
            expanded = insert_after_leading_flags(&expanded, r"^(?:\W{0,2})?");
            flags |= FLAG_LINE_BEGIN;
        } else if !unbound {
            if re_line_bound_beg().is_match(&expanded) {
                flags |= FLAG_LINE_BEGIN;
            } else if !no_wrd_beg {
                expanded = insert_after_leading_flags(&expanded, r"(?:^|\b|\W)");
                flags |= FLAG_WORD_BEGIN;
            }
        }

        if !unbound {
            if re_line_bound_end().is_match(&expanded) {
                flags |= FLAG_LINE_END;
            } else if !no_wrd_end {
                expanded.push_str(r"(?=\b|\W|$)");
                flags |= FLAG_WORD_END;
            }
        }

        if alpha_icase && !starts_with_icase_flag(&expanded) {
            expanded = format!("(?iu){expanded}");
        }

        let compiled = CompiledRegex::compile(&expanded, false)?;
        let kind = match embedded_epoch {
            Some(long_frm) => TemplateKind::Epoch { long_frm },
            None => TemplateKind::Pattern,
        };

        Ok(Self {
            name: human_name,
            pattern: Some(orig_pattern.to_owned()),
            regex: expanded,
            compiled: Some(compiled),
            flags,
            weight: 0.0,
            hits: 0,
            last_used: 0.0,
            kind,
        })
    }

    /// Return `true` if this template is the `{NONE}` sentinel.
    pub fn is_none_sentinel(&self) -> bool {
        self.kind == TemplateKind::NoneSentinel
    }

    /// Return `true` if this template requires matching at the start of a line.
    pub fn is_line_begin(&self) -> bool {
        (self.flags & FLAG_LINE_BEGIN) != 0
    }

    /// Return `true` if this template anchors at the end of a line.
    pub fn is_line_end(&self) -> bool {
        (self.flags & FLAG_LINE_END) != 0
    }

    /// Combined ranking score used when reordering templates on hits.
    pub fn score(&self) -> f64 {
        self.weight + self.hits as f64
    }

    /// Search `line[start..end]` and return `(span_start, span_end, named_groups)`.
    pub fn match_date_range(
        &self,
        line: &str,
        start: usize,
        end: usize,
    ) -> Option<(usize, usize, BTreeMap<String, String>)> {
        let re = self.compiled.as_ref()?;
        let m = re.search_range(line, start, end)?;
        let (s, e) = match self.kind {
            TemplateKind::Epoch { .. } => {
                // Epoch templates may have alternative capture groups 1..3 (or group 1 in custom patterns).
                first_present_group_span(&m).unwrap_or_else(|| (m.start(), m.end()))
            }
            TemplateKind::Pattern | TemplateKind::Tai64n => m
                .group_span(1)
                .unwrap_or_else(|| (m.start(), m.end())),
            TemplateKind::NoneSentinel => return None,
        };
        let groups = m.named_groups(re.capture_names());
        Some((s, e, groups))
    }

    /// Search the full `line` and return `(span_start, span_end, named_groups)`.
    pub fn match_date(
        &self,
        line: &str,
    ) -> Option<(usize, usize, BTreeMap<String, String>)> {
        self.match_date_range(line, 0, line.len())
    }

    /// Match and convert timestamp in `line[start..end]` to Unix seconds.
    ///
    /// Returns `Ok(None)` if the regex did not match, `Ok(Some((ts, start, end)))`
    /// on success, or `Err(...)` if the regex matched text that is not a valid date
    /// (e.g. Feb 30 or unknown timezone abbreviation).
    pub fn get_date(
        &self,
        line: &str,
        default_tz: Option<i32>,
        start: usize,
        end: usize,
    ) -> Result<Option<(f64, usize, usize)>> {
        let Some((s, e, mut groups)) = self.match_date_range(line, start, end) else {
            return Ok(None);
        };
        let ts = match self.kind {
            TemplateKind::NoneSentinel => return Ok(None),
            TemplateKind::Pattern => re_group_dict_strptime(&groups, true, default_tz)?,
            TemplateKind::Epoch { long_frm } => {
                let raw = groups
                    .remove("_f2b_epoch")
                    .unwrap_or_else(|| line[s..e].to_owned());
                parse_epoch_value(&raw, long_frm)?
            }
            TemplateKind::Tai64n => parse_tai64n_value(&line[s..e])?,
        };
        Ok(Some((ts, s, e)))
    }
}

/// Remove automatic line/word boundary wrappers from a Fail2Ban date pattern
/// (matching `datetemplate.DateTemplate.unboundPattern`).
pub fn unbound_pattern(pattern: &str) -> String {
    let mut s = pattern.to_owned();
    if let Some(rest) = s.strip_prefix("{UNB}") {
        s = rest.to_owned();
    }
    if let Some(rest) = s.strip_prefix("{^LN-BEG}") {
        s = rest.to_owned();
    }
    for prefix in [r"^(?:\W{0,2})?", r"(?:\^|\b|\W)", r"(?:^|\b|\W)", r"(^|\b|\W)"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_owned();
            break;
        }
    }
    for suffix in [r"(?=\b|\W|$)", r"(?=\b|\W|\$)"] {
        if let Some(rest) = s.strip_suffix(suffix) {
            s = rest.to_owned();
            break;
        }
    }
    s
}

fn match_standalone_epoch(trimmed: &str) -> Option<(bool, bool)> {
    let mut rest = trimmed;
    let mut line_begin = false;
    if let Some(after) = rest.strip_prefix("{^LN-BEG}") {
        line_begin = true;
        rest = after;
    } else if let Some(after) = rest.strip_prefix('^') {
        line_begin = true;
        rest = after;
    }
    if let Some(before) = rest.strip_suffix('$') {
        rest = before;
    }
    match rest.to_ascii_uppercase().as_str() {
        "EPOCH" | "{EPOCH}" => Some((line_begin, false)),
        "LEPOCH" | "{LEPOCH}" => Some((line_begin, true)),
        _ => None,
    }
}

fn match_standalone_tai64n(trimmed: &str) -> Option<bool> {
    let mut rest = trimmed;
    let mut line_begin = false;
    if let Some(after) = rest.strip_prefix("{^LN-BEG}") {
        line_begin = true;
        rest = after;
    } else if let Some(after) = rest.strip_prefix('^') {
        line_begin = true;
        rest = after;
    }
    if let Some(before) = rest.strip_suffix('$') {
        rest = before;
    }
    if rest.eq_ignore_ascii_case("TAI64N") || rest.eq_ignore_ascii_case("{TAI64N}") {
        Some(line_begin)
    } else {
        None
    }
}

fn replace_embedded_epoch(pattern: &str) -> (String, Option<bool>) {
    let mut out = String::with_capacity(pattern.len());
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut found = None;

    while i < bytes.len() {
        let escaped = i > 0 && bytes[i - 1] == b'\\';
        if !escaped && bytes[i] == b'{' {
            let tail = &pattern[i..];
            if tail.len() >= 7 && tail[..7].eq_ignore_ascii_case("{EPOCH}") {
                out.push_str(&format!("(?P<_f2b_epoch>{EPOCH_RE})"));
                found.get_or_insert(false);
                i += 7;
                continue;
            }
            if tail.len() >= 8 && tail[..8].eq_ignore_ascii_case("{LEPOCH}") {
                out.push_str(&format!("(?P<_f2b_epoch>{LONG_EPOCH_RE})"));
                found = Some(true);
                i += 8;
                continue;
            }
        }
        if let Some(ch) = pattern[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    (out, found)
}

fn parse_epoch_value(raw: &str, long_frm: bool) -> Result<f64> {
    let val: f64 = raw
        .parse()
        .map_err(|_| Error::date(format!("invalid epoch timestamp {raw:?}")))?;
    if long_frm {
        let int_len = raw.split('.').next().map_or(0, str::len);
        if int_len >= 16 {
            return Ok(val / 1_000_000.0);
        }
        if int_len >= 13 {
            return Ok(val / 1_000.0);
        }
    }
    Ok(val)
}

fn parse_tai64n_value(raw: &str) -> Result<f64> {
    if raw.len() < 17 || !raw.starts_with('@') {
        return Err(Error::date(format!("invalid TAI64N timestamp {raw:?}")));
    }
    let hex_secs = &raw[2..17];
    let secs = u64::from_str_radix(hex_secs, 16)
        .map_err(|_| Error::date(format!("invalid TAI64N hex {raw:?}")))?;
    Ok(secs as f64)
}

fn first_present_group_span(m: &crate::filter::regex::RegexMatch<'_>) -> Option<(usize, usize)> {
    if let Some(span) = m.group_span(1) {
        return Some(span);
    }
    if let Some(span) = m.group_span(2) {
        return Some(span);
    }
    m.group_span(3)
}

fn strip_double_star_bounds(pattern: &str) -> String {
    let mut s = pattern.to_owned();
    if let Some(m) = re_del_wrd_bounds().search(&s)
        && m.start() == 0
    {
        s = format!("{}{}", m.group_str(0).unwrap_or("").replace("**", ""), &s[m.end()..]);
    }
    if let Some(rest) = s.strip_suffix("**")
        && !rest.ends_with('\\')
    {
        s = rest.to_owned();
    } else if s.ends_with("**)") && !s[..s.len() - 3].ends_with('\\') {
        s = format!("{})", &s[..s.len() - 3]);
    }
    s
}

/// Check if regex contains an unnamed capturing group `(...)` outside `[...]` and escapes.
fn has_unnamed_capture(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut escaped = false;
    let mut in_class = false;
    let mut class_start = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if in_class {
            if b == b']' && i > class_start + 1 {
                in_class = false;
            }
            i += 1;
            continue;
        }
        if b == b'[' {
            in_class = true;
            class_start = i;
            if bytes.get(i + 1) == Some(&b'^') {
                class_start = i + 1;
            }
            i += 1;
            continue;
        }
        if b == b'(' && bytes.get(i + 1) != Some(&b'?') {
            return true;
        }
        i += 1;
    }
    false
}

/// Wrap the regex body in `(...)` preserving leading inline flags/`^` and trailing `$`.
fn wrap_pattern_in_group(pattern: &str) -> String {
    let mut prefix_end = 0usize;
    if pattern.starts_with("(?")
        && let Some(close) = pattern.find(')')
    {
        let inside = &pattern[2..close];
        if !inside.is_empty() && inside.bytes().all(|b| b.is_ascii_alphabetic()) {
            prefix_end = close + 1;
        }
    }
    if pattern[prefix_end..].starts_with('^') {
        prefix_end += 1;
    }

    let mut suffix_start = pattern.len();
    if pattern[prefix_end..].ends_with('$') {
        let dollar_pos = pattern.len() - 1;
        let backslash_count = pattern[prefix_end..dollar_pos]
            .bytes()
            .rev()
            .take_while(|&b| b == b'\\')
            .count();
        if backslash_count % 2 == 0 {
            suffix_start = dollar_pos;
        }
    }

    format!(
        "{}({}){}",
        &pattern[..prefix_end],
        &pattern[prefix_end..suffix_start],
        &pattern[suffix_start..]
    )
}

fn insert_after_leading_flags(pattern: &str, insert: &str) -> String {
    if pattern.starts_with("(?")
        && let Some(close) = pattern.find(')')
    {
        let inside = &pattern[2..close];
        if !inside.is_empty() && inside.bytes().all(|b| b.is_ascii_alphabetic()) {
            return format!("{}{insert}{}", &pattern[..=close], &pattern[close + 1..]);
        }
    }
    format!("{insert}{pattern}")
}

fn starts_with_icase_flag(pattern: &str) -> bool {
    if pattern.starts_with("(?")
        && let Some(close) = pattern.find(')')
    {
        let inside = &pattern[2..close];
        return inside.contains('i');
    }
    false
}

fn re_no_wrd_bound_beg() -> &'static CompiledRegex {
    static RE: OnceLock<CompiledRegex> = OnceLock::new();
    RE.get_or_init(|| {
        compile_static_rx(r"^\(*(?:\(\?\w+\))?(?:\^|\(*\*\*|\((?:\?:)?\^)")
    })
}

fn re_no_wrd_bound_end() -> &'static CompiledRegex {
    static RE: OnceLock<CompiledRegex> = OnceLock::new();
    RE.get_or_init(|| {
        compile_static_rx(r"(?<!\\)(?:\$\)?|\\b|\\s|\*\*\)*)$")
    })
}

fn re_del_wrd_bounds() -> &'static CompiledRegex {
    static RE: OnceLock<CompiledRegex> = OnceLock::new();
    RE.get_or_init(|| compile_static_rx(r"^\(*(?:\(\?\w+\))?\(*\*\*"))
}

fn re_line_bound_beg() -> &'static CompiledRegex {
    static RE: OnceLock<CompiledRegex> = OnceLock::new();
    RE.get_or_init(|| {
        compile_static_rx(r"^(?:\(\?\w+\))?(?:\^|\((?:\?:)?\^(?!\|))")
    })
}

fn re_line_bound_end() -> &'static CompiledRegex {
    static RE: OnceLock<CompiledRegex> = OnceLock::new();
    RE.get_or_init(|| compile_static_rx(r"(?<![\\\|])(?:\$\)?)$"))
}

fn re_alpha_pattern() -> &'static CompiledRegex {
    static RE: OnceLock<CompiledRegex> = OnceLock::new();
    RE.get_or_init(|| compile_static_rx(r"(?<!\%)\%[aAbBpc]"))
}

fn compile_static_rx(pattern: &str) -> CompiledRegex {
    // Hardcoded compile-time validated helper regexes.
    CompiledRegex::compile(pattern, false).unwrap_or_else(|_| match CompiledRegex::compile("$^", false) {
        Ok(fallback) => fallback,
        Err(_) => unreachable!(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn iso_date_captures_exact_span_without_surrounding_space() {
        let tmpl = DateTemplate::from_pattern(
            r"%ExY(?P<_sep>[-/.])%m(?P=_sep)%d(?:T|  ?)%H:%M:%S(?:[.,]%f)?(?:\s*%z)?",
        )
        .unwrap();
        let line = "prefix 2024-05-14 08:30:15.123 +0200 user root";
        let (ts, s, e) = tmpl.get_date(line, None, 0, line.len()).unwrap().unwrap();
        assert_eq!(&line[s..e], "2024-05-14 08:30:15.123 +0200");
        assert!(ts > 1_715_000_000.0);
    }

    #[test]
    fn line_begin_bracketed_apache_date() {
        let tmpl =
            DateTemplate::from_pattern(r"{^LN-BEG}(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?")
                .unwrap();
        assert!(tmpl.is_line_begin());
        let line = "[Sun May 14 08:30:15 2023] [error] client 1.2.3.4";
        let (ts, s, e) = tmpl.get_date(line, None, 0, line.len()).unwrap().unwrap();
        assert_eq!(&line[s..e], "Sun May 14 08:30:15 2023");
        assert!(ts > 1_680_000_000.0);

        let mid = "prefix [Sun May 14 08:30:15 2023]";
        assert!(tmpl.get_date(mid, None, 0, mid.len()).unwrap().is_none());
    }

    #[test]
    fn epoch_and_lepoch_and_audit() {
        let t_epoch = DateTemplate::from_pattern("EPOCH").unwrap();
        let audit = "type=AVC msg=audit(1700000000.123:456): avc: denied";
        let (ts, s, e) = t_epoch.get_date(audit, None, 0, audit.len()).unwrap().unwrap();
        assert_eq!(&audit[s..e], "1700000000.123");
        assert!((ts - 1_700_000_000.123).abs() < 1e-6);

        let square = "[1700000000] foo";
        let (ts2, s2, e2) = t_epoch
            .get_date(square, None, 0, square.len())
            .unwrap()
            .unwrap();
        assert_eq!(&square[s2..e2], "1700000000");
        assert!((ts2 - 1_700_000_000.0).abs() < 1e-6);

        // Must not match plain numeric word in middle of line.
        let noise = "port 1700000000 failed";
        assert!(t_epoch.get_date(noise, None, 0, noise.len()).unwrap().is_none());

        let t_lepoch = DateTemplate::from_pattern("^LEPOCH").unwrap();
        let ms = "1700000000456 event";
        let (ts3, _, _) = t_lepoch.get_date(ms, None, 0, ms.len()).unwrap().unwrap();
        assert!((ts3 - 1_700_000_000.456).abs() < 1e-6);

        let us = "1700000000123456 event";
        let (ts4, _, _) = t_lepoch.get_date(us, None, 0, us.len()).unwrap().unwrap();
        assert!((ts4 - 1_700_000_000.123_456).abs() < 1e-6);
    }

    #[test]
    fn embedded_epoch_and_tai64n_and_none() {
        let emb = DateTemplate::from_pattern(r"^ts={EPOCH} msg").unwrap();
        let line = "ts=1700000000 msg=ok";
        let (ts, s, e) = emb.get_date(line, None, 0, line.len()).unwrap().unwrap();
        assert_eq!(&line[s..e], "ts=1700000000 msg");
        assert!((ts - 1_700_000_000.0).abs() < 1e-6);

        let tai = DateTemplate::from_pattern("TAI64N").unwrap();
        let tline = "@4000000050606b6c2c8e12f4 info: hello";
        let (tts, ts_s, ts_e) = tai.get_date(tline, None, 0, tline.len()).unwrap().unwrap();
        assert_eq!(&tline[ts_s..ts_e], "@4000000050606b6c2c8e12f4");
        assert!((tts - 1_348_496_236.0).abs() < 1e-6);

        let none_t = DateTemplate::from_pattern("{NONE}").unwrap();
        assert!(none_t.is_none_sentinel());
        assert!(none_t.match_date("2024-01-01 12:00:00").is_none());
    }

    #[test]
    fn unbound_and_explicit_unb_marker() {
        assert_eq!(unbound_pattern("{^LN-BEG}%H:%M:%S"), "%H:%M:%S");
        assert_eq!(unbound_pattern("{UNB}%H:%M:%S"), "%H:%M:%S");
        let t = DateTemplate::from_pattern("{UNB}%Y-%m-%d").unwrap();
        let line = "abc2024-01-02def";
        let (_, s, e) = t.get_date(line, None, 0, line.len()).unwrap().unwrap();
        assert_eq!(&line[s..e], "2024-01-02");
    }
}
