//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/failregex.py` with
//! dual-engine compilation (`regex::Regex` fast path + `fancy_regex::Regex` fallback).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};

use super::ipdns::{IP_4_RE, IP_6_RE, UseDns};

const FAILURE_ID_GROUPS: &[&str] = &["fid", "ip4", "ip6", "dns"];
const FAILURE_ID_PRESENTS: &[&str] = &["fid", "ip4", "ip6", "dns", "mlfid"];

#[derive(Debug, Clone)]
enum Engine {
    Fast(regex::Regex),
    Fancy(Box<fancy_regex::Regex>),
}

/// Dual-engine regex wrapper: compiles with linear-time `regex::Regex` first
/// and falls back to `fancy_regex::Regex` for lookaround, backreferences, and
/// conditionals.
#[derive(Debug, Clone)]
pub struct CompiledRegex {
    engine: Engine,
    capture_names: Vec<Option<String>>,
}

/// Borrowed match result over either `regex::Captures` or `fancy_regex::Captures`.
pub enum RegexMatch<'t> {
    Fast(regex::Captures<'t>),
    Fancy(fancy_regex::Captures<'t>),
}

impl<'t> RegexMatch<'t> {
    pub fn start(&self) -> usize {
        match self {
            Self::Fast(c) => c.get(0).map_or(0, |m| m.start()),
            Self::Fancy(c) => c.get(0).map_or(0, |m| m.start()),
        }
    }

    pub fn end(&self) -> usize {
        match self {
            Self::Fast(c) => c.get(0).map_or(0, |m| m.end()),
            Self::Fancy(c) => c.get(0).map_or(0, |m| m.end()),
        }
    }

    pub fn group_span(&self, idx: usize) -> Option<(usize, usize)> {
        match self {
            Self::Fast(c) => c.get(idx).map(|m| (m.start(), m.end())),
            Self::Fancy(c) => c.get(idx).map(|m| (m.start(), m.end())),
        }
    }

    pub fn group_str(&self, idx: usize) -> Option<&'t str> {
        match self {
            Self::Fast(c) => c.get(idx).map(|m| m.as_str()),
            Self::Fancy(c) => c.get(idx).map(|m| m.as_str()),
        }
    }

    pub fn name(&self, name: &str) -> Option<&'t str> {
        match self {
            Self::Fast(c) => c.name(name).map(|m| m.as_str()),
            Self::Fancy(c) => c.name(name).map(|m| m.as_str()),
        }
    }

    /// Return all matched named capture groups (absent optional groups are omitted).
    pub fn named_groups(&self, capture_names: &[Option<String>]) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (idx, maybe_name) in capture_names.iter().enumerate() {
            let Some(name) = maybe_name else {
                continue;
            };
            if let Some(val) = self.group_str(idx) {
                out.insert(name.clone(), val.to_owned());
            }
        }
        out
    }
}

impl CompiledRegex {
    /// Compile a Python-flavored regex pattern using `regex::Regex` first and
    /// falling back to `fancy_regex::Regex` on lookaround/backref/conditionals.
    pub fn compile(pattern: &str, multiline: bool) -> Result<Self> {
        let norm = normalize_python_regex(pattern);
        if let Ok(re) = regex::RegexBuilder::new(&norm)
            .multi_line(multiline)
            .build()
        {
            let capture_names = re.capture_names().map(|n| n.map(str::to_owned)).collect();
            return Ok(Self {
                engine: Engine::Fast(re),
                capture_names,
            });
        }

        let raw_fancy = if multiline {
            format!("(?m){norm}")
        } else {
            norm
        };
        let (fancy_pat, extracted_names) = strip_group_names_for_fancy(&raw_fancy);
        let re = fancy_regex::RegexBuilder::new(&fancy_pat)
            .backtrack_limit(200_000)
            .build()
            .map_err(|err| {
                Error::regex(format!(
                    "Unable to compile regular expression {pattern:?}: {err}"
                ))
            })?;
        let capture_names = if extracted_names.len() == re.captures_len() {
            extracted_names
        } else {
            re.capture_names().map(|n| n.map(str::to_owned)).collect()
        };
        Ok(Self {
            engine: Engine::Fancy(Box::new(re)),
            capture_names,
        })
    }

    pub fn capture_names(&self) -> &[Option<String>] {
        &self.capture_names
    }

    pub fn has_capture(&self, name: &str) -> bool {
        self.capture_names.iter().flatten().any(|n| n == name)
    }

    pub fn is_match(&self, text: &str) -> bool {
        match &self.engine {
            Engine::Fast(re) => re.is_match(text),
            Engine::Fancy(re) => re.is_match(text).unwrap_or(false),
        }
    }

    pub fn search<'t>(&self, text: &'t str) -> Option<RegexMatch<'t>> {
        match &self.engine {
            Engine::Fast(re) => re.captures(text).map(RegexMatch::Fast),
            Engine::Fancy(re) => re.captures(text).ok().flatten().map(RegexMatch::Fancy),
        }
    }

    /// Search `text[..end]` starting at byte offset `start` while preserving lookbehind
    /// context before `start`.
    pub fn search_range<'t>(
        &self,
        text: &'t str,
        start: usize,
        end: usize,
    ) -> Option<RegexMatch<'t>> {
        if start > end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return None;
        }
        let slice = &text[..end];
        match &self.engine {
            Engine::Fast(re) => re.captures_at(slice, start).map(RegexMatch::Fast),
            Engine::Fancy(re) => re
                .captures_from_pos(slice, start)
                .ok()
                .flatten()
                .map(RegexMatch::Fancy),
        }
    }
}

/// Normalize Python `re` syntax quirks into Rust `regex` / `fancy-regex` syntax:
/// - Inside `[...]`: escape unescaped `[`, leading `]`, and set operators `&&`/`--`/`~~`
/// - `\<` and `\>` are literal brackets in Python, word boundaries in Rust
/// - Outside `[...]`:
///   - `\Z` -> `\z`
///   - `{,N}` -> `{0,N}`
///   - `((?flags)...)` and `(?:(?flags)...)` -> `(?flags:...)` (`R_GLOB2LOCFLAGS`)
///   - `(?(name)...)` / `(?(<name>)...)` -> `(?(N)...)` using numeric capture index `N`
pub fn normalize_python_regex(pattern: &str) -> String {
    let mut pass1 = String::with_capacity(pattern.len() + 16);
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut in_class = false;
    let mut class_first = false;
    let mut class_after_caret = false;

    while i < bytes.len() {
        let ch = pattern[i..].chars().next().unwrap_or('\0');
        if ch == '\\' {
            if let Some(next) = pattern[i + 1..].chars().next() {
                if !in_class && next == 'Z' {
                    pass1.push_str(r"\z");
                } else if matches!(next, '<' | '>') {
                    pass1.push(next);
                } else {
                    pass1.push('\\');
                    pass1.push(next);
                }
                i += 1 + next.len_utf8();
                class_first = false;
                class_after_caret = false;
                continue;
            }
            pass1.push('\\');
            i += 1;
            continue;
        }

        if in_class {
            if class_first && ch == '^' && !class_after_caret {
                pass1.push('^');
                class_after_caret = true;
                i += 1;
                continue;
            }
            if ch == '[' {
                pass1.push_str(r"\[");
                class_first = false;
                class_after_caret = false;
                i += 1;
                continue;
            }
            if ch == ']' {
                if class_first {
                    pass1.push_str(r"\]");
                    class_first = false;
                    class_after_caret = false;
                    i += 1;
                    continue;
                }
                in_class = false;
                pass1.push(']');
                i += 1;
                continue;
            }
            if (ch == '&' && bytes.get(i + 1) == Some(&b'&'))
                || (ch == '-' && bytes.get(i + 1) == Some(&b'-'))
                || (ch == '~' && bytes.get(i + 1) == Some(&b'~'))
            {
                pass1.push('\\');
                pass1.push(ch);
                class_first = false;
                class_after_caret = false;
                i += 1;
                continue;
            }
            pass1.push(ch);
            class_first = false;
            class_after_caret = false;
            i += ch.len_utf8();
            continue;
        }

        if ch == '[' {
            in_class = true;
            class_first = true;
            class_after_caret = false;
            pass1.push('[');
            i += 1;
            continue;
        }

        // Convert Python `{,N}` quantifier to `{0,N}`.
        if ch == '{'
            && bytes.get(i + 1) == Some(&b',')
            && let Some((digits, close_rel)) = parse_brace_upper(&pattern[i + 2..])
        {
            pass1.push_str("{0,");
            pass1.push_str(digits);
            pass1.push('}');
            i += 2 + close_rel + 1;
            continue;
        }

        // Convert `((?flags)...)` and `(?:(?flags)...)` -> `(?flags:...)`.
        if ch == '('
            && let Some((flags, consumed)) = parse_glob_to_loc_flags(&pattern[i..])
        {
            pass1.push_str("(?");
            pass1.push_str(flags);
            pass1.push(':');
            i += consumed;
            continue;
        }

        pass1.push(ch);
        i += ch.len_utf8();
    }

    if pass1.contains("(?(") {
        resolve_named_conditionals(&pass1)
    } else {
        pass1
    }
}

/// Pass 2: rewrite Python named conditionals `(?(name)...)` to numeric `(?(N)...)`
/// matching `fancy-regex`'s numbered conditional syntax using exact capture indices.
fn resolve_named_conditionals(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut in_class = false;
    let mut class_first = false;
    let mut class_after_caret = false;
    let mut group_idx = 0usize;
    let mut group_map: BTreeMap<String, usize> = BTreeMap::new();

    while i < bytes.len() {
        let ch = pattern[i..].chars().next().unwrap_or('\0');
        if ch == '\\' {
            out.push('\\');
            if let Some(next) = pattern[i + 1..].chars().next() {
                out.push(next);
                i += 1 + next.len_utf8();
            } else {
                i += 1;
            }
            class_first = false;
            class_after_caret = false;
            continue;
        }

        if in_class {
            if class_first && !class_after_caret && ch == '^' {
                class_after_caret = true;
            } else if class_first && ch == ']' {
                class_first = false;
                class_after_caret = false;
            } else if ch == ']' {
                in_class = false;
            } else {
                class_first = false;
                class_after_caret = false;
            }
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }

        if ch == '[' {
            in_class = true;
            class_first = true;
            class_after_caret = false;
            out.push('[');
            i += 1;
            continue;
        }

        if ch == '(' {
            if pattern[i..].starts_with("(?#")
                && let Some(rel_end) = pattern[i + 3..].find(')')
            {
                let end = i + 3 + rel_end + 1;
                out.push_str(&pattern[i..end]);
                i = end;
                continue;
            }

            if pattern[i..].starts_with("(?(")
                && let Some((name, consumed)) = parse_group_condition(&pattern[i + 3..])
            {
                let end = i + 3 + consumed;
                if let Some(&idx) = group_map.get(name) {
                    out.push_str(&format!("(?({idx})"));
                } else {
                    out.push_str(&pattern[i..end]);
                }
                i = end;
                continue;
            }

            if pattern[i..].starts_with("(?P<")
                && let Some(gt_rel) = pattern[i + 4..].find('>')
            {
                let name = &pattern[i + 4..i + 4 + gt_rel];
                group_idx += 1;
                group_map.insert(name.to_owned(), group_idx);
                let end = i + 4 + gt_rel + 1;
                out.push_str(&pattern[i..end]);
                i = end;
                continue;
            }

            if pattern[i..].starts_with("(?<")
                && !matches!(bytes.get(i + 3), Some(b'=' | b'!'))
                && let Some(gt_rel) = pattern[i + 3..].find('>')
            {
                let name = &pattern[i + 3..i + 3 + gt_rel];
                group_idx += 1;
                group_map.insert(name.to_owned(), group_idx);
                let end = i + 3 + gt_rel + 1;
                out.push_str(&pattern[i..end]);
                i = end;
                continue;
            }

            if bytes.get(i + 1) != Some(&b'?') {
                group_idx += 1;
            }
        }

        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

/// Convert `(?P<name>...)` / `(?<name>...)` to unnamed `(...)` and `(?P=name)` / `\k<name>`
/// to `\N` for `fancy-regex` so numbered conditionals `(?(N)...)` and backrefs work together,
/// returning `(stripped_pattern, capture_names)` with group 0 = `None`.
fn strip_group_names_for_fancy(pattern: &str) -> (String, Vec<Option<String>>) {
    let mut out = String::with_capacity(pattern.len());
    let mut names: Vec<Option<String>> = vec![None];
    let mut name_to_idx: BTreeMap<String, usize> = BTreeMap::new();
    let bytes = pattern.as_bytes();
    let mut i = 0usize;
    let mut in_class = false;
    let mut class_first = false;
    let mut class_after_caret = false;

    while i < bytes.len() {
        let ch = pattern[i..].chars().next().unwrap_or('\0');
        if ch == '\\' {
            if !in_class
                && pattern[i..].starts_with(r"\k<")
                && let Some(gt) = pattern[i + 3..].find('>')
            {
                let name = &pattern[i + 3..i + 3 + gt];
                if let Some(&idx) = name_to_idx.get(name) {
                    out.push('\\');
                    out.push_str(&idx.to_string());
                    i += 3 + gt + 1;
                    continue;
                }
            }
            out.push('\\');
            if let Some(next) = pattern[i + 1..].chars().next() {
                out.push(next);
                i += 1 + next.len_utf8();
            } else {
                i += 1;
            }
            class_first = false;
            class_after_caret = false;
            continue;
        }
        if in_class {
            if class_first && !class_after_caret && ch == '^' {
                class_after_caret = true;
            } else if class_first && ch == ']' {
                class_first = false;
                class_after_caret = false;
            } else if ch == ']' {
                in_class = false;
            } else {
                class_first = false;
                class_after_caret = false;
            }
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        if ch == '[' {
            in_class = true;
            class_first = true;
            class_after_caret = false;
            out.push('[');
            i += 1;
            continue;
        }
        if ch == '(' {
            if pattern[i..].starts_with("(?#")
                && let Some(rel_end) = pattern[i + 3..].find(')')
            {
                let end = i + 3 + rel_end + 1;
                out.push_str(&pattern[i..end]);
                i = end;
                continue;
            }
            if pattern[i..].starts_with("(?(")
                && let Some((_, consumed)) = parse_group_condition(&pattern[i + 3..])
            {
                let end = i + 3 + consumed;
                out.push_str(&pattern[i..end]);
                i = end;
                continue;
            }
            if pattern[i..].starts_with("(?P=")
                && let Some(rel_end) = pattern[i + 4..].find(')')
            {
                let name = &pattern[i + 4..i + 4 + rel_end];
                if let Some(&idx) = name_to_idx.get(name) {
                    out.push('\\');
                    out.push_str(&idx.to_string());
                    i += 4 + rel_end + 1;
                    continue;
                }
            }
            if pattern[i..].starts_with("(?P<")
                && let Some(gt) = pattern[i + 4..].find('>')
            {
                let name = pattern[i + 4..i + 4 + gt].to_owned();
                let idx = names.len();
                name_to_idx.insert(name.clone(), idx);
                names.push(Some(name));
                out.push('(');
                i += 4 + gt + 1;
                continue;
            }
            if pattern[i..].starts_with("(?<")
                && !matches!(bytes.get(i + 3), Some(b'=' | b'!'))
                && let Some(gt) = pattern[i + 3..].find('>')
            {
                let name = pattern[i + 3..i + 3 + gt].to_owned();
                let idx = names.len();
                name_to_idx.insert(name.clone(), idx);
                names.push(Some(name));
                out.push('(');
                i += 3 + gt + 1;
                continue;
            }
            if bytes.get(i + 1) != Some(&b'?') {
                names.push(None);
            }
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    (out, names)
}

fn parse_brace_upper(rest: &str) -> Option<(&str, usize)> {
    let end = rest.bytes().position(|b| !b.is_ascii_digit())?;
    if end == 0 || rest.as_bytes().get(end) != Some(&b'}') {
        return None;
    }
    Some((&rest[..end], end))
}

fn parse_glob_to_loc_flags(rest: &str) -> Option<(&str, usize)> {
    let (prefix_len, after_outer) = if let Some(s) = rest.strip_prefix("(?:(?") {
        (5usize, s)
    } else if let Some(s) = rest.strip_prefix("((?") {
        (3usize, s)
    } else {
        return None;
    };
    let end = after_outer.bytes().position(|b| !b.is_ascii_lowercase())?;
    if end == 0 || after_outer.as_bytes().get(end) != Some(&b')') {
        return None;
    }
    let flags = &after_outer[..end];
    if !flags
        .bytes()
        .all(|b| matches!(b, b'i' | b'm' | b's' | b'u' | b'x'))
    {
        return None;
    }
    Some((flags, prefix_len + end + 1))
}

fn parse_group_condition(rest: &str) -> Option<(&str, usize)> {
    if let Some(inner) = rest.strip_prefix('<') {
        let first = inner.as_bytes().first()?;
        if !(first.is_ascii_alphabetic() || *first == b'_') {
            return None;
        }
        let end = inner
            .bytes()
            .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))?;
        if !inner[end..].starts_with(">)") {
            return None;
        }
        return Some((&inner[..end], 1 + end + 2));
    }
    let first = rest.as_bytes().first()?;
    if !(first.is_ascii_alphanumeric() || *first == b'_') {
        return None;
    }
    let end = rest
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))?;
    if rest.as_bytes().get(end) != Some(&b')') {
        return None;
    }
    Some((&rest[..end], end + 1))
}

fn map_tag_to_opt(tag: &str) -> String {
    let lower = tag.to_ascii_lowercase();
    match lower.as_str() {
        "id" => "fid".to_owned(),
        "port" => "fport".to_owned(),
        _ => lower,
    }
}

fn parse_compl_name(name: &str) -> Option<(&'static str, String)> {
    let (prefix, rest) = if let Some(r) = name.strip_prefix("alt_") {
        ("alt_", r)
    } else if let Some(r) = name.strip_prefix("tuple_") {
        ("tuple_", r)
    } else {
        return None;
    };
    if rest.is_empty() {
        return None;
    }
    let base = if let Some((head, tail)) = rest.rsplit_once('_')
        && !head.is_empty()
        && !tail.is_empty()
        && tail.bytes().all(|b| b.is_ascii_digit())
    {
        head
    } else {
        rest
    };
    Some((prefix, map_tag_to_opt(base)))
}

fn is_valid_ftag_body(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomTagKind {
    Open,
    Close,
    SelfClosing,
}

fn is_custom_f_tag(tn: &str) -> Option<(CustomTagKind, &str)> {
    let (kind, rest) = if let Some(r) = tn.strip_prefix('/') {
        (CustomTagKind::Close, r)
    } else if let Some(r) = tn.strip_suffix('/') {
        (CustomTagKind::SelfClosing, r)
    } else {
        (CustomTagKind::Open, tn)
    };
    let name = rest.strip_prefix("F-")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return None;
    }
    Some((kind, name))
}

/// Fail2Ban `Regex` / `FailRegex` implementation matching `fail2ban/server/failregex.py`.
#[derive(Debug)]
pub struct FailRegex {
    raw_pattern: String,
    effective_regex: String,
    compiled: CompiledRegex,
    multiline: bool,
    alt_values: Vec<(String, String)>,
    tuple_values: Vec<(String, String)>,
    matched: bool,
    last_groups: BTreeMap<String, String>,
    skipped_lines: Vec<String>,
    matched_tuple_lines: Vec<(String, String, String)>,
    unmatched_tuple_lines: Vec<(String, String, String)>,
}

impl FailRegex {
    /// Compile a `failregex` rule, validating that at least one failure-id group
    /// (`fid`, `ip4`, `ip6`, `dns`, `mlfid`) exists in this regex or `pref_regex`.
    pub fn new(
        pattern: &str,
        pref_regex: Option<&FailRegex>,
        multiline: bool,
        use_dns: UseDns,
    ) -> Result<Self> {
        let compiled = Self::compile_filter_regex(pattern, multiline, use_dns)?;
        let has_id = compiled.has_failure_id_group()
            || pref_regex.is_some_and(FailRegex::has_failure_id_group);
        if !has_id {
            let quoted = if compiled.effective_regex.contains('\'')
                && !compiled.effective_regex.contains('"')
            {
                format!("\"{}\"", compiled.effective_regex)
            } else {
                format!("'{}'", compiled.effective_regex.replace('\'', "\\'"))
            };
            return Err(Error::regex(format!("No failure-id group in {quoted}")));
        }
        Ok(compiled)
    }

    /// Compile a filter regex without requiring a failure-id group (used for `prefregex` and `ignoreregex`).
    pub fn compile_filter_regex(pattern: &str, multiline: bool, use_dns: UseDns) -> Result<Self> {
        let resolved = Self::resolve_host_tag(pattern, use_dns);
        if resolved.trim_start().is_empty() {
            return Err(Error::regex("Cannot add empty regex"));
        }
        let compiled = CompiledRegex::compile(&resolved, multiline)?;

        let mut alt_values = Vec::new();
        let mut tuple_values = Vec::new();
        for name in compiled.capture_names().iter().flatten() {
            if name.len() > 4
                && let Some((kind, target)) = parse_compl_name(name)
            {
                if kind == "alt_" {
                    alt_values.push((name.clone(), target));
                } else {
                    tuple_values.push((name.clone(), target));
                }
            }
        }
        alt_values.sort();
        tuple_values.sort();

        Ok(Self {
            raw_pattern: pattern.to_owned(),
            effective_regex: resolved,
            compiled,
            multiline,
            alt_values,
            tuple_values,
            matched: false,
            last_groups: BTreeMap::new(),
            skipped_lines: Vec::new(),
            matched_tuple_lines: Vec::new(),
            unmatched_tuple_lines: Vec::new(),
        })
    }

    /// Expand Fail2Ban `<HOST>`, `<ADDR>`, `<IP4>`, `<IP6>`, `<SUBNET>`, `<CIDR>`,
    /// `<DNS>`, `<F-ID/>`, `<F-PORT/>`, `<SKIPLINES>`, and custom `<F-NAME>...</F-NAME>` tags.
    pub fn resolve_host_tag(regex: &str, use_dns: UseDns) -> String {
        let ri_ipv4 = format!(r"(?:::f{{4,6}}:)?(?P<ip4>{IP_4_RE})");
        let ri_ipv6 = format!(r"(?P<ip6>{IP_6_RE})");
        let ri_dns = r"(?P<dns>[\w\-.^_]*\w)";
        let ri_addr = format!(r"\[?(?:{ri_ipv4}|{ri_ipv6})\]?");
        let ri_host = format!(r"(?:{ri_addr}|{ri_dns})");
        let ri_cidr = r"(?P<cidr>\d+)";
        let ri_subnet = format!(r"\[?(?:{ri_ipv4}|{ri_ipv6})(?:/{ri_cidr})?\]?");

        let mut out = String::with_capacity(regex.len() + 64);
        let mut open_tags: BTreeSet<String> = BTreeSet::new();
        let mut nl_count: usize = 0;
        let bytes = regex.as_bytes();
        let mut i = 0usize;

        while i < bytes.len() {
            if bytes[i] == b'<'
                && let Some(rel_end) = bytes[i + 1..].iter().position(|&b| b == b'>' || b == b'<')
                && bytes[i + 1 + rel_end] == b'>'
            {
                let end = i + 1 + rel_end;
                let tn = &regex[i + 1..end];
                let inner = tn
                    .strip_prefix('/')
                    .unwrap_or(tn)
                    .strip_suffix('/')
                    .unwrap_or_else(|| tn.strip_prefix('/').unwrap_or(tn));
                let valid_shape =
                    !tn.starts_with("//") && !tn.ends_with("//") && is_valid_ftag_body(inner);

                if valid_shape {
                    let full_tag = &regex[i..=end];
                    let replacement: Option<String> = match tn {
                        "HOST" => Some(if use_dns == UseDns::No {
                            ri_addr.clone()
                        } else {
                            ri_host.clone()
                        }),
                        "SKIPLINES" => {
                            let s = format!(r"\n(?P<skiplines{nl_count}>(?:(?:.*\n)*?))");
                            nl_count += 1;
                            Some(s)
                        }
                        "IP4" | "F-IP4/" => Some(ri_ipv4.clone()),
                        "IP6" | "F-IP6/" => Some(ri_ipv6.clone()),
                        "ADDR" | "F-ADDR/" => Some(ri_addr.clone()),
                        "CIDR" | "F-CIDR/" => Some(ri_cidr.to_owned()),
                        "SUBNET" | "F-SUBNET/" => Some(ri_subnet.clone()),
                        "DNS" | "F-DNS/" => Some(ri_dns.to_owned()),
                        "F-ID/" => Some(r"(?P<fid>\S+)".to_owned()),
                        "F-PORT/" => Some(r"(?P<fport>\w+)".to_owned()),
                        _ => match is_custom_f_tag(tn) {
                            Some((CustomTagKind::Close, name)) => {
                                if open_tags.contains(name) {
                                    Some(")".to_owned())
                                } else {
                                    None
                                }
                            }
                            Some((CustomTagKind::Open, name)) => {
                                open_tags.insert(name.to_owned());
                                Some(format!("(?P<{}>", map_tag_to_opt(name)))
                            }
                            Some((CustomTagKind::SelfClosing, name)) => {
                                Some(format!("(?P<{}>)", map_tag_to_opt(name)))
                            }
                            None => None,
                        },
                    };
                    if let Some(repl) = replacement {
                        out.push_str(&repl);
                        i = end + 1;
                        continue;
                    }
                    out.push_str(full_tag);
                    i = end + 1;
                    continue;
                }
            }
            let ch = regex[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    pub fn regex(&self) -> &str {
        &self.effective_regex
    }

    pub fn raw_pattern(&self) -> &str {
        &self.raw_pattern
    }

    pub fn has_capture(&self, name: &str) -> bool {
        self.compiled.has_capture(name)
    }

    pub fn has_failure_id_group(&self) -> bool {
        FAILURE_ID_PRESENTS
            .iter()
            .any(|g| self.compiled.has_capture(g))
    }

    /// Build Fail2Ban's newline-terminated search buffer from `(before_date, date_text, after_date)` tuples.
    pub fn tuple_lines_buf(tuple_lines: &[(String, String, String)]) -> String {
        let mut buf = String::new();
        for (idx, (pre, _, post)) in tuple_lines.iter().enumerate() {
            if idx > 0 {
                buf.push('\n');
            }
            buf.push_str(pre);
            buf.push_str(post);
        }
        buf.push('\n');
        buf
    }

    /// Search `buf` and partition `org_lines` into matched, skipped, and unmatched tuple lines.
    pub fn search(&mut self, buf: &str, org_lines: &[(String, String, String)]) -> bool {
        self.matched = false;
        self.last_groups.clear();
        self.skipped_lines.clear();
        self.matched_tuple_lines.clear();
        self.unmatched_tuple_lines.clear();

        // Python `re` with multiline=False allows `$` to match just before a trailing `\n`.
        // When `multiline == false`, strip the single synthetic trailing `\n` from `_tupleLinesBuf`
        // so Rust's `$` matches identically to Python.
        let search_buf = if !self.multiline {
            buf.strip_suffix('\n').unwrap_or(buf)
        } else {
            buf
        };

        let Some(m) = self.compiled.search(search_buf) else {
            return false;
        };

        let m_start = m.start();
        let m_end = m.end();
        let raw_groups = m.named_groups(self.compiled.capture_names());

        let mut skipped_raw = String::new();
        let mut n = 0usize;
        loop {
            let key = format!("skiplines{n}");
            if !self.compiled.has_capture(&key) {
                break;
            }
            if let Some(val) = raw_groups.get(&key) {
                skipped_raw.push_str(val);
            }
            n += 1;
        }
        self.skipped_lines = skipped_raw.lines().map(str::to_owned).collect();
        self.last_groups =
            merge_alt_and_tuple_groups(raw_groups, &self.alt_values, &self.tuple_values);

        self.matched = true;
        if org_lines.len() <= 1 {
            self.matched_tuple_lines = org_lines.to_vec();
        } else {
            let bytes = search_buf.as_bytes();
            let search_start_end = if bytes.get(m_start) == Some(&b'\n') {
                (m_start + 1).min(bytes.len())
            } else {
                m_start.min(bytes.len())
            };
            let match_line_start =
                memchr::memrchr(b'\n', &bytes[..search_start_end]).map_or(0, |p| p + 1);

            let end_probe = m_end.saturating_sub(1).min(bytes.len());
            let match_line_end = memchr::memchr(b'\n', &bytes[end_probe..])
                .map_or(bytes.len(), |rel| end_probe + rel + 1);

            let line_count1 = bytes[..match_line_start]
                .iter()
                .filter(|&&b| b == b'\n')
                .count();
            let line_count2 = bytes[..match_line_end]
                .iter()
                .filter(|&&b| b == b'\n')
                .count()
                .min(org_lines.len());

            let lc1 = line_count1.min(line_count2);
            self.matched_tuple_lines = org_lines[lc1..line_count2].to_vec();
            self.unmatched_tuple_lines = org_lines[..lc1].to_vec();

            let mut cursor = 0usize;
            for skipped in &self.skipped_lines {
                if let Some(rel) =
                    self.matched_tuple_lines[cursor..]
                        .iter()
                        .position(|(pre, _, post)| {
                            skipped.strip_prefix(pre.as_str()) == Some(post.as_str())
                        })
                {
                    let removed = self.matched_tuple_lines.remove(cursor + rel);
                    self.unmatched_tuple_lines.push(removed);
                    cursor += rel;
                }
            }
            self.unmatched_tuple_lines
                .extend_from_slice(&org_lines[line_count2..]);
        }

        true
    }

    pub fn has_matched(&self) -> bool {
        self.matched
    }

    pub fn groups(&self) -> BTreeMap<String, String> {
        self.last_groups.clone()
    }

    pub fn skipped_lines(&self) -> &[String] {
        &self.skipped_lines
    }

    pub fn matched_tuple_lines(&self) -> &[(String, String, String)] {
        &self.matched_tuple_lines
    }

    pub fn unmatched_tuple_lines(&self) -> &[(String, String, String)] {
        &self.unmatched_tuple_lines
    }

    pub fn matched_lines(&self) -> Vec<String> {
        self.matched_tuple_lines
            .iter()
            .map(|(a, b, c)| format!("{a}{b}{c}"))
            .collect()
    }

    pub fn unmatched_lines(&self) -> Vec<String> {
        self.unmatched_tuple_lines
            .iter()
            .map(|(a, b, c)| format!("{a}{b}{c}"))
            .collect()
    }

    /// Return the first present failure identifier from `groups` (or default `FAILURE_ID_GROUPS`).
    pub fn get_fail_id(&self, groups: Option<&[&str]>) -> Result<String> {
        let search_groups = groups.unwrap_or(FAILURE_ID_GROUPS);
        for grp in search_groups {
            if let Some(val) = self.last_groups.get(*grp) {
                return Ok(val.clone());
            }
        }
        Err(Error::regex(format!(
            "No failure-id group found using {:?}",
            self.effective_regex
        )))
    }
}

fn merge_alt_and_tuple_groups(
    mut groups: BTreeMap<String, String>,
    alt_values: &[(String, String)],
    tuple_values: &[(String, String)],
) -> BTreeMap<String, String> {
    for (k, target) in alt_values {
        if let Some(val) = groups.get(k).cloned()
            && !val.is_empty()
            && groups.get(target).is_none_or(String::is_empty)
        {
            groups.insert(target.clone(), val);
        }
    }

    if !tuple_values.is_empty() {
        let mut by_target: BTreeMap<&str, Vec<Option<String>>> = BTreeMap::new();
        for (k, target) in tuple_values {
            let list = by_target
                .entry(target.as_str())
                .or_insert_with(|| vec![groups.get(target).cloned()]);
            list.push(groups.get(k).cloned());
        }
        for (target, parts) in by_target {
            groups.insert(target.to_owned(), format_python_tuple(&parts));
        }
    }

    groups
}

fn format_python_tuple(parts: &[Option<String>]) -> String {
    let formatted: Vec<String> = parts
        .iter()
        .map(|opt| match opt {
            None => "None".to_owned(),
            Some(s) => {
                let mut q = String::with_capacity(s.len() + 2);
                q.push('\'');
                for ch in s.chars() {
                    match ch {
                        '\\' => q.push_str("\\\\"),
                        '\'' => q.push_str("\\'"),
                        '\n' => q.push_str("\\n"),
                        '\r' => q.push_str("\\r"),
                        '\t' => q.push_str("\\t"),
                        _ => q.push(ch),
                    }
                }
                q.push('\'');
                q
            }
        })
        .collect();
    if formatted.len() == 1 {
        format!("({},)", formatted[0])
    } else {
        format!("({})", formatted.join(", "))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn escaped_angle_brackets_match_literal_text() {
        let regex = CompiledRegex::compile(r"^\<?(?P<peer>\S+?)\>?$", false).unwrap();
        for line in ["<192.0.2.1>", "192.0.2.1"] {
            let captures = regex.search(line).unwrap();
            assert_eq!(captures.name("peer"), Some("192.0.2.1"));
        }
    }

    #[test]
    fn resolves_tags_and_compiles_with_fancy_fallback() {
        let re = FailRegex::new(
            r#"^Failed password for (?:invalid user )?<F-USER>(?P<cond_user>\S+)</F-USER> from <HOST>(?(cond_user): |.*)$"#,
            None,
            false,
            UseDns::Yes,
        )
        .unwrap();
        assert!(re.has_capture("user"));
        assert!(re.has_capture("ip4"));
        assert!(re.has_capture("ip6"));
        assert!(re.has_capture("dns"));

        // Conditional branch when cond_user matched (`: ` required).
        let mut r = re;
        let line = vec![(
            String::new(),
            "Jan  1 00:00:00 ".to_owned(),
            "Failed password for admin from 2001:db8::1: ".to_owned(),
        )];
        let buf = FailRegex::tuple_lines_buf(&line);
        assert!(r.search(&buf, &line));
        let g = r.groups();
        assert_eq!(g.get("user").map(String::as_str), Some("admin"));
        assert_eq!(g.get("ip6").map(String::as_str), Some("2001:db8::1"));

        // Conditional false branch + apache-noscript / sshd style conditional patterns.
        let line_no_colon = vec![(
            String::new(),
            String::new(),
            "Failed password for admin from 2001:db8::1 missing_colon".to_owned(),
        )];
        assert!(!r.search(&FailRegex::tuple_lines_buf(&line_no_colon), &line_no_colon));

        let mut sshd_re = FailRegex::new(
            r"^Failed password for (?P<cond_inv>invalid user )?<F-USER>(?P<cond_user>\S+)|(?(cond_inv)(?:(?! from ).)*?|[^:]+)</F-USER> from <HOST>(?:\s+port \d+)?(?:\s+ssh\d*)?(?(cond_user): |(?:(?:(?! from ).)*)$)",
            None,
            false,
            UseDns::No,
        )
        .unwrap();
        let sshd_inv = vec![(
            String::new(),
            String::new(),
            "Failed password for invalid user bob smith from 192.0.2.5 port 22 ssh2".to_owned(),
        )];
        assert!(sshd_re.search(&FailRegex::tuple_lines_buf(&sshd_inv), &sshd_inv));
        assert_eq!(
            sshd_re.groups().get("user").map(String::as_str),
            Some("bob smith")
        );
    }

    #[test]
    fn normalizes_python_regex_quirks_from_stock_filters() {
        // Unescaped '[' in char class (postfix.conf) + global-to-local flags.
        let p = FailRegex::new(
            r"^[^[]*\[<HOST>\]: SASL ((?i)LOGIN|PLAIN) failed$",
            None,
            false,
            UseDns::No,
        )
        .unwrap();
        let line = vec![(
            String::new(),
            String::new(),
            "foo [192.0.2.1]: SASL login failed".to_owned(),
        )];
        let mut p = p;
        assert!(p.search(&FailRegex::tuple_lines_buf(&line), &line));

        // `{,N}` quantifier (assp.conf / froxlor-auth.conf).
        let q =
            FailRegex::new(r"^errors \(\d{,3}\) from <ADDR>$", None, false, UseDns::No).unwrap();
        let line_q = vec![(
            String::new(),
            String::new(),
            "errors (12) from 198.51.100.7".to_owned(),
        )];
        let mut q = q;
        assert!(q.search(&FailRegex::tuple_lines_buf(&line_q), &line_q));

        // Backref `(?P=CODE)` (stunnel.conf / sendmail-reject.conf).
        let b = FailRegex::new(
            r"^from <HOST> : (?P<CODE>[\dA-F]+): error:(?P=CODE):fail$",
            None,
            false,
            UseDns::No,
        )
        .unwrap();
        let line_b = vec![(
            String::new(),
            String::new(),
            "from 192.0.2.9 : ABC1: error:ABC1:fail".to_owned(),
        )];
        let mut b = b;
        assert!(b.search(&FailRegex::tuple_lines_buf(&line_b), &line_b));
    }

    #[test]
    fn merges_alt_and_tuple_groups_and_skiplines() {
        let mut alt_re = FailRegex::new(
            r"^log=<F-ALT_USER1>\S*</F-ALT_USER1> ruser=<F-USER>\S*</F-USER> host=<ADDR>(?:\s+user=<F-ALT_USER>\S*</F-ALT_USER>)?$",
            None,
            false,
            UseDns::No,
        )
        .unwrap();
        let l1 = vec![(
            String::new(),
            String::new(),
            "log=root ruser= host=192.0.2.2 user=alice".to_owned(),
        )];
        assert!(alt_re.search(&FailRegex::tuple_lines_buf(&l1), &l1));
        assert_eq!(
            alt_re.groups().get("user").map(String::as_str),
            Some("alice")
        );

        let mut tup_re = FailRegex::new(
            r"^\s*<F-TUPLE_ID_1>\S+</F-TUPLE_ID_1> <F-ID><ADDR>:<F-PORT/></F-ID> <F-TUPLE_ID_2>\S+</F-TUPLE_ID_2>$",
            None,
            false,
            UseDns::No,
        )
        .unwrap();
        let l2 = vec![(
            String::new(),
            String::new(),
            "left [192.0.2.4]:12345 right".to_owned(),
        )];
        assert!(tup_re.search(&FailRegex::tuple_lines_buf(&l2), &l2));
        assert_eq!(
            tup_re.groups().get("fid").map(String::as_str),
            Some("('[192.0.2.4]:12345', 'left', 'right')")
        );

        let mut skip_re = FailRegex::new(
            r"^\s+\[conn(?P<__connid>\d+)\] Failed<SKIPLINES>\s+\[conn(?P=__connid)\] end <HOST>$",
            None,
            true,
            UseDns::No,
        )
        .unwrap();
        let multi = vec![
            (String::new(), "t1 ".into(), " [conn1] Failed".into()),
            (String::new(), "t2 ".into(), " noise line".into()),
            (
                String::new(),
                "t3 ".into(),
                " [conn1] end 192.0.2.50".into(),
            ),
        ];
        assert!(skip_re.search(&FailRegex::tuple_lines_buf(&multi), &multi));
        assert_eq!(skip_re.matched_lines().len(), 2);
        assert_eq!(skip_re.unmatched_lines(), vec!["t2  noise line".to_owned()]);
    }
}
