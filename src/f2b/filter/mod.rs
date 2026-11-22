//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/filter.py`.
//!
//! Coordinates [`DateDetector`], [`FailRegex`], [`IgnoreConfig`], `mlfid` multi-line
//! session correlation, and log input [`backend`]s.

pub mod backend;
pub mod file_identity;
pub mod ipdns;
pub mod poll_stamp;
pub mod regex;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::date::DateDetector;
use crate::duration::str2seconds;
use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};
use crate::ticket::{Ticket, TicketId};

use self::ipdns::{IgnoreCache, IgnoreConfig, UseDns, parse_ip_with_cidr, text_to_ip};
use self::regex::FailRegex;

const DEFAULT_MLFID_MAX_COUNT: usize = 100;
const DEFAULT_MLFID_MAX_TIME: Duration = Duration::from_secs(300);

fn remove_regex(regexes: &mut Vec<FailRegex>, hits: &mut Vec<usize>, index: Option<i64>) {
    let Some(index) = index else {
        regexes.clear();
        hits.clear();
        return;
    };
    let offset = if index < 0 {
        usize::try_from(index.unsigned_abs())
            .ok()
            .and_then(|n| regexes.len().checked_sub(n))
    } else {
        usize::try_from(index).ok()
    };
    if let Some(offset) = offset.filter(|&i| i < regexes.len()) {
        regexes.remove(offset);
        if offset < hits.len() {
            hits.remove(offset);
        }
    } else {
        log_msg(
            LogLevel::Error,
            "fail2ban.filter",
            &format!("Cannot remove regular expression. Index {index} is not valid"),
        );
    }
}

const CP1252_HIGH: [char; 32] = [
    '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}', '\u{017D}', '\u{FFFD}',
    '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
];

/// Supported log character encodings matching Fail2Ban's `logencoding` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogEncoding {
    #[default]
    Auto,
    Utf8,
    Latin1,
    Ascii,
    Cp1252,
    Utf16Le,
    Utf16Be,
    Utf16,
}

impl LogEncoding {
    /// Parse a Fail2Ban `logencoding` string (`auto`, `utf-8`, `latin1`, `ascii`, `cp1252`, `utf-16*`).
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Self::Auto),
            "utf-8" | "utf8" | "utf_8" => Ok(Self::Utf8),
            "latin1" | "latin-1" | "latin_1" | "iso-8859-1" | "iso8859-1" | "iso_8859_1" => {
                Ok(Self::Latin1)
            }
            "ascii" | "us-ascii" | "us_ascii" => Ok(Self::Ascii),
            "cp1252" | "windows-1252" | "windows_1252" => Ok(Self::Cp1252),
            "utf-16le" | "utf16le" | "utf_16_le" => Ok(Self::Utf16Le),
            "utf-16be" | "utf16be" | "utf_16_be" => Ok(Self::Utf16Be),
            "utf-16" | "utf16" | "utf_16" => Ok(Self::Utf16),
            _ => Err(Error::config(format!("Unsupported logencoding {raw:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Utf8 => "utf-8",
            Self::Latin1 => "latin1",
            Self::Ascii => "ascii",
            Self::Cp1252 => "cp1252",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Utf16 => "utf-16",
        }
    }

    pub const fn is_utf16(self) -> bool {
        matches!(self, Self::Utf16Le | Self::Utf16Be | Self::Utf16)
    }

    /// Resolve a `Utf16` BOM prefix if present, returning `(resolved_encoding, bom_bytes)`.
    pub fn resolve_bom(self, bytes: &[u8]) -> (Self, usize) {
        if self == Self::Utf16 && bytes.len() >= 2 {
            match (bytes[0], bytes[1]) {
                (0xFE, 0xFF) => (Self::Utf16Be, 2),
                (0xFF, 0xFE) => (Self::Utf16Le, 2),
                _ => (Self::Utf16Le, 0),
            }
        } else {
            (self, 0)
        }
    }

    /// Locate the first line terminator in `buf` without splitting multi-byte code units
    /// containing `0x0A` (e.g. U+020A in UTF-16LE/BE). Returns `(line_end_no_crlf, next_start)`.
    pub fn split_line(self, buf: &[u8]) -> Option<(usize, usize)> {
        match self {
            Self::Auto | Self::Utf8 | Self::Latin1 | Self::Ascii | Self::Cp1252 => {
                let nl = memchr::memchr(b'\n', buf)?;
                let line_end = if nl > 0 && buf[nl - 1] == b'\r' {
                    nl - 1
                } else {
                    nl
                };
                Some((line_end, nl + 1))
            }
            Self::Utf16Le | Self::Utf16 => {
                let mut i = 0usize;
                while i + 1 < buf.len() {
                    if buf[i] == b'\n' && buf[i + 1] == 0 {
                        let line_end = if i >= 2 && buf[i - 2] == b'\r' && buf[i - 1] == 0 {
                            i - 2
                        } else {
                            i
                        };
                        return Some((line_end, i + 2));
                    }
                    i += 2;
                }
                None
            }
            Self::Utf16Be => {
                let mut i = 0usize;
                while i + 1 < buf.len() {
                    if buf[i] == 0 && buf[i + 1] == b'\n' {
                        let line_end = if i >= 2 && buf[i - 2] == 0 && buf[i - 1] == b'\r' {
                            i - 2
                        } else {
                            i
                        };
                        return Some((line_end, i + 2));
                    }
                    i += 2;
                }
                None
            }
        }
    }

    /// Decode raw log bytes into UTF-8 `String` according to this encoding.
    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            Self::Auto | Self::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Self::Latin1 => bytes.iter().map(|&b| char::from(b)).collect(),
            Self::Ascii => bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii() {
                        char::from(b)
                    } else {
                        '\u{FFFD}'
                    }
                })
                .collect(),
            Self::Cp1252 => bytes
                .iter()
                .map(|&b| {
                    if (0x80..=0x9F).contains(&b) {
                        CP1252_HIGH[(b - 0x80) as usize]
                    } else {
                        char::from(b)
                    }
                })
                .collect(),
            Self::Utf16Le => decode_utf16_bytes(bytes, false),
            Self::Utf16Be => decode_utf16_bytes(bytes, true),
            Self::Utf16 => {
                let (resolved, skip) = self.resolve_bom(bytes);
                decode_utf16_bytes(&bytes[skip..], resolved == Self::Utf16Be)
            }
        }
    }
}

fn decode_utf16_bytes(bytes: &[u8], big_endian: bool) -> String {
    let mut units = Vec::with_capacity(bytes.len().div_ceil(2));
    for pair in bytes.chunks_exact(2) {
        units.push(if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        });
    }
    if bytes.len() % 2 == 1 {
        units.push(0xFFFD);
    }
    String::from_utf16_lossy(&units)
}

/// Single failure detection emitted by [`Filter::process_line`].
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    pub regex_idx: usize,
    pub fid: Option<TicketId>,
    pub ip: Option<TicketId>,
    pub time: f64,
    pub matches: Vec<String>,
    pub data: BTreeMap<String, String>,
}

/// Aggregate filter counters (used by `fail2ban-regex` and diagnostics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessLineStats {
    pub total_lines: usize,
    pub matched: usize,
    pub ignored: usize,
    pub missed: usize,
    pub date_matched: usize,
    pub regex_hits: Vec<usize>,
    pub ignoreregex_hits: Vec<usize>,
}

/// Detailed per-line outcome returned by [`Filter::process_line_with_info`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LineProcessResult {
    pub results: Vec<MatchResult>,
    pub(crate) pref_groups: Option<BTreeMap<String, String>>,
    pub date_matched: bool,
    pub date_time: Option<f64>,
    pub ignored_by_regex: Vec<usize>,
    pub ignored_by_ip: bool,
    pub missed: bool,
}

#[derive(Debug, Clone, Default)]
struct MlfIdEntry {
    data: BTreeMap<String, String>,
    users: BTreeSet<String>,
    mlfpending: bool,
    nofail_matches: Vec<String>,
    matches: Vec<String>,
}

#[derive(Debug)]
struct CachedMlfId {
    entry: MlfIdEntry,
    expires_at: Instant,
    seq: u64,
}

#[derive(Debug)]
struct MlfIdCache {
    max_count: usize,
    max_time: Duration,
    entries: BTreeMap<String, CachedMlfId>,
    next_seq: u64,
}

impl MlfIdCache {
    fn new(max_count: usize, max_time: Duration) -> Self {
        Self {
            max_count,
            max_time,
            entries: BTreeMap::new(),
            next_seq: 0,
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        self.entries.retain(|_, v| v.expires_at > now);
    }

    fn take(&mut self, key: &str) -> Option<MlfIdEntry> {
        let now = Instant::now();
        self.prune_expired(now);
        self.entries.remove(key).map(|c| c.entry)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut MlfIdEntry> {
        let now = Instant::now();
        self.prune_expired(now);
        self.entries.get_mut(key).map(|c| &mut c.entry)
    }

    fn insert(&mut self, key: String, entry: MlfIdEntry) {
        let now = Instant::now();
        self.prune_expired(now);
        if self.entries.len() >= self.max_count
            && !self.entries.contains_key(&key)
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.seq)
                .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        self.entries.insert(
            key,
            CachedMlfId {
                entry,
                expires_at: now + self.max_time,
                seq: self.next_seq,
            },
        );
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Fail2Ban 1.1.1 log filter pipeline.
#[derive(Debug)]
pub struct Filter {
    jail_name: String,
    prefregex: Option<FailRegex>,
    failregex: Vec<FailRegex>,
    ignoreregex: Vec<FailRegex>,
    date_detector: DateDetector,
    max_lines: usize,
    use_dns: UseDns,
    log_encoding: LogEncoding,
    log_encoding_name: String,
    log_timezone: Option<String>,
    find_time: f64,
    check_find_time: bool,
    in_operation: bool,
    check_all_regex: bool,
    ignore_pending: bool,
    return_raw_host: bool,
    pub ignore: IgnoreConfig,
    mlfid_cache: MlfIdCache,
    last_date: f64,
    last_time_text: Option<String>,
    line_buffer: Vec<(String, String, String)>,
    stats: ProcessLineStats,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new("default")
    }
}

impl Filter {
    /// Construct a new [`Filter`] for `jail_name` with Fail2Ban 1.1.1 defaults.
    pub fn new(jail_name: impl Into<String>) -> Self {
        Self {
            jail_name: jail_name.into(),
            prefregex: None,
            failregex: Vec::new(),
            ignoreregex: Vec::new(),
            date_detector: DateDetector::with_defaults().unwrap_or_else(|_| DateDetector::empty()),
            max_lines: 1,
            use_dns: UseDns::Warn,
            log_encoding: LogEncoding::Auto,
            log_encoding_name: "UTF-8".to_owned(),
            log_timezone: None,
            find_time: 600.0,
            check_find_time: true,
            in_operation: false,
            check_all_regex: false,
            ignore_pending: true,
            return_raw_host: false,
            ignore: IgnoreConfig::new(),
            mlfid_cache: MlfIdCache::new(DEFAULT_MLFID_MAX_COUNT, DEFAULT_MLFID_MAX_TIME),
            last_date: 0.0,
            last_time_text: None,
            line_buffer: Vec::new(),
            stats: ProcessLineStats::default(),
        }
    }

    pub fn jail_name(&self) -> &str {
        &self.jail_name
    }

    pub fn set_jail_name(&mut self, name: impl Into<String>) {
        self.jail_name = name.into();
    }

    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    /// Set `maxlines` (`>= 1`), recompiling regexes if multiline flag (`maxlines > 1`) changed.
    pub fn set_max_lines(&mut self, max_lines: usize) -> Result<()> {
        let next = max_lines.max(1);
        let prev_ml = self.max_lines > 1;
        let next_ml = next > 1;
        self.max_lines = next;
        if self.line_buffer.len() > next {
            let excess = self.line_buffer.len() - next;
            self.line_buffer.drain(..excess);
        }
        if prev_ml != next_ml {
            self.recompile_all_regexes()?;
        }
        Ok(())
    }

    pub fn use_dns(&self) -> UseDns {
        self.use_dns
    }

    /// Set `usedns` policy, recompiling regexes if `<HOST>` DNS expansion changed.
    pub fn set_use_dns(&mut self, use_dns: UseDns) -> Result<()> {
        let prev = self.use_dns;
        self.use_dns = use_dns;
        if (prev == UseDns::No) != (use_dns == UseDns::No) {
            self.recompile_all_regexes()?;
        }
        Ok(())
    }

    pub fn set_use_dns_str(&mut self, raw: &str) -> Result<UseDns> {
        let parsed = UseDns::parse(raw);
        self.set_use_dns(parsed)?;
        Ok(parsed)
    }

    pub fn log_encoding(&self) -> LogEncoding {
        self.log_encoding
    }

    pub fn log_encoding_name(&self) -> &str {
        &self.log_encoding_name
    }

    pub fn set_log_encoding(&mut self, encoding: LogEncoding) {
        let name = if encoding == LogEncoding::Auto {
            "UTF-8"
        } else {
            encoding.as_str()
        };
        self.log_encoding_name = name.to_owned();
        self.log_encoding = encoding;
    }

    pub fn set_log_encoding_str(&mut self, raw: &str) -> Result<LogEncoding> {
        let enc = LogEncoding::parse(raw)?;
        self.set_log_encoding(enc);
        if enc != LogEncoding::Auto {
            self.log_encoding_name = raw.to_owned();
        }
        Ok(enc)
    }

    pub fn log_timezone(&self) -> Option<&str> {
        self.log_timezone.as_deref()
    }

    pub fn set_log_timezone(&mut self, tz: Option<&str>) -> Result<()> {
        self.date_detector.set_default_tz(tz)?;
        self.log_timezone = tz.map(str::to_owned);
        Ok(())
    }

    pub fn date_pattern(&self) -> Option<(Option<String>, String)> {
        self.date_detector.date_pattern()
    }

    /// Set custom `datepattern` (`None` restores the 31 default templates).
    pub fn set_date_pattern(&mut self, pattern: Option<&str>) -> Result<()> {
        let mut dd = DateDetector::empty();
        if let Some(tz) = self.log_timezone.as_deref() {
            dd.set_default_tz(Some(tz))?;
        }
        match pattern.map(str::trim) {
            None | Some("") => {
                dd.add_default_template()?;
                dd.set_pattern_spec(None);
            }
            Some(pat) => {
                dd.append_template(pat)?;
                dd.set_pattern_spec(Some(pat.to_owned()));
            }
        }
        self.date_detector = dd;
        self.last_time_text = None;
        Ok(())
    }

    pub fn date_detector(&self) -> &DateDetector {
        &self.date_detector
    }

    pub fn date_detector_mut(&mut self) -> &mut DateDetector {
        &mut self.date_detector
    }

    pub fn find_time(&self) -> f64 {
        self.find_time
    }

    pub fn set_find_time(&mut self, secs: f64) {
        self.find_time = secs.max(0.0);
    }

    pub fn set_find_time_str(&mut self, raw: &str) -> Result<f64> {
        let secs = str2seconds(raw)?;
        self.set_find_time(secs);
        Ok(secs)
    }

    pub fn check_find_time(&self) -> bool {
        self.check_find_time
    }

    pub fn set_check_find_time(&mut self, enabled: bool) {
        self.check_find_time = enabled;
    }

    pub fn in_operation(&self) -> bool {
        self.in_operation
    }

    pub fn set_in_operation(&mut self, in_op: bool) {
        self.in_operation = in_op;
    }

    pub fn check_all_regex(&self) -> bool {
        self.check_all_regex
    }

    pub fn set_check_all_regex(&mut self, enabled: bool) {
        self.check_all_regex = enabled;
    }

    pub fn ignore_pending(&self) -> bool {
        self.ignore_pending
    }

    pub fn set_ignore_pending(&mut self, enabled: bool) {
        self.ignore_pending = enabled;
    }

    pub fn return_raw_host(&self) -> bool {
        self.return_raw_host
    }

    pub fn set_return_raw_host(&mut self, enabled: bool) {
        self.return_raw_host = enabled;
    }

    pub fn ignore_self(&self) -> bool {
        self.ignore.ignore_self
    }

    pub fn set_ignore_self(&mut self, enabled: bool) {
        self.ignore.ignore_self = enabled;
    }

    pub fn set_ignore_self_str(&mut self, raw: &str) -> Result<bool> {
        self.ignore.set_ignore_self_str(raw)
    }

    pub fn ignore_ips(&self) -> &[String] {
        &self.ignore.ignore_ips
    }

    pub fn add_ignore_ip(&mut self, raw: &str) {
        self.ignore.add_ignore_ip(raw);
    }

    pub fn del_ignore_ip(&mut self, raw: Option<&str>) -> bool {
        self.ignore.del_ignore_ip(raw)
    }

    pub fn ignore_command(&self) -> Option<&str> {
        self.ignore.ignore_command.as_deref()
    }

    pub fn set_ignore_command(&mut self, cmd: Option<&str>) {
        self.ignore.ignore_command = cmd
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
    }

    pub fn ignore_cache(&self) -> Option<&IgnoreCache> {
        self.ignore.ignore_cache.as_ref()
    }

    pub fn set_ignore_cache(&mut self, raw: Option<&str>) -> Result<()> {
        self.ignore.ignore_cache = match raw {
            Some(spec) => IgnoreCache::parse(spec)?,
            None => None,
        };
        Ok(())
    }

    pub fn ignores_ip(&mut self, id: &TicketId, ticket: Option<&Ticket>) -> bool {
        self.ignore.is_ignored(id, ticket, &self.jail_name)
    }

    pub fn prefregex(&self) -> Option<&str> {
        self.prefregex.as_ref().map(FailRegex::regex)
    }

    pub fn set_prefregex(&mut self, pattern: Option<&str>) -> Result<()> {
        self.prefregex = match pattern {
            Some(pat) if !pat.trim().is_empty() => Some(FailRegex::compile_filter_regex(
                pat,
                self.max_lines > 1,
                self.use_dns,
            )?),
            _ => None,
        };
        Ok(())
    }

    pub fn fail_regexes(&self) -> Vec<String> {
        self.failregex
            .iter()
            .map(|r| r.regex().to_owned())
            .collect()
    }

    pub fn add_fail_regex(&mut self, pattern: &str) -> Result<usize> {
        let rx = FailRegex::new(
            pattern,
            self.prefregex.as_ref(),
            self.max_lines > 1,
            self.use_dns,
        )?;
        self.failregex.push(rx);
        self.stats.regex_hits.push(0);
        Ok(self.failregex.len())
    }

    pub fn del_fail_regex(&mut self, index: Option<i64>) {
        remove_regex(&mut self.failregex, &mut self.stats.regex_hits, index);
    }

    pub fn ignore_regexes(&self) -> Vec<String> {
        self.ignoreregex
            .iter()
            .map(|r| r.regex().to_owned())
            .collect()
    }

    pub fn add_ignore_regex(&mut self, pattern: &str) -> Result<usize> {
        let rx = FailRegex::compile_filter_regex(pattern, self.max_lines > 1, self.use_dns)?;
        self.ignoreregex.push(rx);
        self.stats.ignoreregex_hits.push(0);
        Ok(self.ignoreregex.len())
    }

    pub fn del_ignore_regex(&mut self, index: Option<i64>) {
        remove_regex(
            &mut self.ignoreregex,
            &mut self.stats.ignoreregex_hits,
            index,
        );
    }

    pub fn last_date(&self) -> f64 {
        self.last_date
    }

    pub fn last_time_text(&self) -> Option<&str> {
        self.last_time_text.as_deref()
    }

    pub fn stats(&self) -> &ProcessLineStats {
        &self.stats
    }

    pub fn reset_stats(&mut self) {
        self.stats = ProcessLineStats {
            regex_hits: vec![0; self.failregex.len()],
            ignoreregex_hits: vec![0; self.ignoreregex.len()],
            ..Default::default()
        };
    }

    pub fn clear_line_buffer(&mut self) {
        self.line_buffer.clear();
    }

    pub fn clear_mlfid_cache(&mut self) {
        self.mlfid_cache.clear();
    }

    /// Reset filter patterns, ignore rules, date settings, and DNS caches during
    /// live jail reload (`begin = true`), finalizing on `begin = false`.
    pub fn reload(&mut self, begin: bool) -> Result<()> {
        if begin {
            ipdns::clear_dns_caches();
            self.prefregex = None;
            self.failregex.clear();
            self.ignoreregex.clear();
            self.stats.regex_hits.clear();
            self.stats.ignoreregex_hits.clear();
            self.ignore = IgnoreConfig::new();
            self.log_timezone = None;
            self.set_date_pattern(None)?;
            self.last_time_text = None;
            self.max_lines = 1;
            self.use_dns = UseDns::Warn;
            self.log_encoding = LogEncoding::Auto;
            self.find_time = 600.0;
            self.line_buffer.clear();
        }
        Ok(())
    }

    /// Process a single log line using current wall-clock time for `findtime` checks.
    pub fn process_line(&mut self, line: &str, preset_date: Option<f64>) -> Vec<MatchResult> {
        self.process_line_at(line, preset_date, current_unix_seconds())
            .results
    }

    /// Process a single log line and return detailed match/ignore/date status (`fail2ban-regex`).
    pub fn process_line_with_info(
        &mut self,
        line: &str,
        preset_date: Option<f64>,
    ) -> LineProcessResult {
        self.process_line_at(line, preset_date, current_unix_seconds())
    }

    /// Deterministic entry point parameterized by reference wall-clock `now`.
    pub fn process_line_at(
        &mut self,
        line: &str,
        preset_date: Option<f64>,
        now: f64,
    ) -> LineProcessResult {
        let clean = line.trim_end_matches(['\r', '\n']);
        self.stats.total_lines += 1;

        let mut out = LineProcessResult::default();
        let (time_opt, tuple_line) = self.extract_line_date(clean, preset_date, now, &mut out);

        self.line_buffer.push(tuple_line);
        if self.line_buffer.len() > self.max_lines {
            let excess = self.line_buffer.len() - self.max_lines;
            self.line_buffer.drain(..excess);
        }

        let Some(event_time) = time_opt.or_else(|| (!self.check_find_time).then_some(now)) else {
            // Even without a parsed timestamp, probe failregex for missed-date diagnostics.
            let org_lines = self.line_buffer.clone();
            let buf = FailRegex::tuple_lines_buf(&org_lines);
            if self.would_match_failregex(&buf, &org_lines) {
                log_msg(
                    LogLevel::Warning,
                    "fail2ban.filter",
                    &format!(
                        "[{}] Found a match but no valid date/time found for {:?}",
                        self.jail_name, clean
                    ),
                );
                self.stats.missed += 1;
                out.missed = true;
            }
            return out;
        };

        out.date_time = Some(event_time);

        if self.check_find_time && event_time < now - self.find_time {
            log_msg(
                LogLevel::TraceDebug,
                "fail2ban.filter",
                &format!(
                    "[{}] Ignore line since time {event_time} < {}",
                    self.jail_name,
                    now - self.find_time
                ),
            );
            return out;
        }

        self.run_find_failure(event_time, &mut out);
        out
    }

    fn extract_line_date(
        &mut self,
        clean: &str,
        preset_date: Option<f64>,
        now: f64,
        out: &mut LineProcessResult,
    ) -> (Option<f64>, (String, String, String)) {
        if let Some(ts) = preset_date {
            self.last_date = ts;
            self.stats.date_matched += 1;
            out.date_matched = true;
            return (Some(ts), (String::new(), String::new(), clean.to_owned()));
        }

        match self.date_detector.match_time(clean) {
            Some(tm) => match tm.timestamp {
                Some(ts) => {
                    self.last_date = ts;
                    self.last_time_text = Some(clean[tm.start..tm.end].to_owned());
                    self.stats.date_matched += 1;
                    out.date_matched = true;
                    (
                        Some(ts),
                        (
                            clean[..tm.start].to_owned(),
                            clean[tm.start..tm.end].to_owned(),
                            clean[tm.end..].to_owned(),
                        ),
                    )
                }
                None => {
                    // {NONE} datepattern matched.
                    self.last_date = now;
                    self.stats.date_matched += 1;
                    out.date_matched = true;
                    (Some(now), (String::new(), String::new(), clean.to_owned()))
                }
            },
            None => {
                // Multi-line continuation lines may omit timestamp after an earlier dated line.
                let inherited = if self.max_lines > 1 && self.last_date > 0.0 {
                    Some(self.last_date)
                } else {
                    None
                };
                (inherited, (String::new(), String::new(), clean.to_owned()))
            }
        }
    }

    fn would_match_failregex(&mut self, buf: &str, org_lines: &[(String, String, String)]) -> bool {
        let mut work_buf = buf.to_owned();
        let mut work_lines = org_lines.to_vec();

        if let Some(ref mut pref) = self.prefregex {
            if !pref.search(&work_buf, &work_lines) {
                return false;
            }
            if let Some(content) = pref.groups().get("content") {
                work_lines = content
                    .split('\n')
                    .map(|l| (String::new(), String::new(), l.to_owned()))
                    .collect();
                work_buf = FailRegex::tuple_lines_buf(&work_lines);
            }
        }
        if self
            .ignoreregex
            .iter_mut()
            .any(|rx| rx.search(&work_buf, &work_lines))
        {
            return false;
        }
        self.failregex
            .iter_mut()
            .any(|rx| rx.search(&work_buf, &work_lines))
    }

    fn run_find_failure(&mut self, event_time: f64, out: &mut LineProcessResult) {
        let org_lines = self.line_buffer.clone();
        let orig_buf = FailRegex::tuple_lines_buf(&org_lines);

        let mut work_buf = orig_buf;
        let mut work_lines = org_lines.clone();
        let mut pref_groups = BTreeMap::new();

        if let Some(ref mut pref) = self.prefregex {
            if !pref.search(&work_buf, &work_lines) {
                return;
            }
            pref_groups = pref.groups();
            if !self.check_find_time {
                out.pref_groups = Some(pref_groups.clone());
            }
            if let Some(content) = pref_groups.remove("content") {
                work_lines = if org_lines.len() == 1 && !content.contains('\n') {
                    // Keep the full original line tuple when single-line prefregex strips prefix.
                    org_lines.clone()
                } else {
                    content
                        .split('\n')
                        .map(|l| (String::new(), String::new(), l.to_owned()))
                        .collect()
                };
                work_buf = if work_lines.len() == 1 && org_lines.len() == 1 {
                    format!("{content}\n")
                } else {
                    FailRegex::tuple_lines_buf(&work_lines)
                };
            }
        }

        // Check ignoreregex before failregex (matching upstream filter.py).
        for (idx, ig_rx) in self.ignoreregex.iter_mut().enumerate() {
            if ig_rx.search(&work_buf, &work_lines) {
                if let Some(slot) = self.stats.ignoreregex_hits.get_mut(idx) {
                    *slot += 1;
                }
                out.ignored_by_regex.push(idx);
                if !self.check_all_regex {
                    self.stats.ignored += 1;
                    if org_lines.len() == work_lines.len() {
                        self.line_buffer = ig_rx.unmatched_tuple_lines().to_vec();
                    }
                    return;
                }
            }
        }
        if !out.ignored_by_regex.is_empty() {
            self.stats.ignored += 1;
            return;
        }

        let mut next_line_buffer: Option<Vec<(String, String, String)>> = None;

        for idx in 0..self.failregex.len() {
            if !self.failregex[idx].search(&work_buf, &work_lines) {
                continue;
            }

            let matched_tuples: Vec<(String, String, String)> =
                if org_lines.len() == 1 && work_lines.len() == 1 {
                    org_lines.clone()
                } else {
                    self.failregex[idx].matched_tuple_lines().to_vec()
                };
            let unmatched_tuples = self.failregex[idx].unmatched_tuple_lines().to_vec();

            let mut fail_data = pref_groups.clone();
            for (k, v) in self.failregex[idx].groups() {
                fail_data.insert(k, v);
            }

            let merged = self.merge_failure(&mut fail_data, &matched_tuples);
            let Some(merged_lines) = merged else {
                if !self.check_all_regex {
                    if org_lines.len() == work_lines.len() {
                        next_line_buffer = Some(unmatched_tuples);
                    }
                    break;
                }
                continue;
            };

            let produced =
                self.build_results_from_match(idx, event_time, merged_lines, fail_data, out);

            if produced {
                if let Some(slot) = self.stats.regex_hits.get_mut(idx) {
                    *slot += 1;
                }
                self.stats.matched += 1;
            }

            if next_line_buffer.is_none() && org_lines.len() == work_lines.len() {
                next_line_buffer = Some(unmatched_tuples);
            }

            if !self.check_all_regex {
                break;
            }
        }

        if let Some(rem) = next_line_buffer {
            self.line_buffer = rem;
        }
    }

    /// Fail2Ban 1.1.1 `_mergeFailure` `mlfid` session merger (`filter.py` lines 796-846).
    ///
    /// Returns `Some(lines)` when this match should proceed toward ticket emission
    /// (subject to `fid`/`ip` resolution), or `None` when buffered by `nofail` /
    /// discarded as pending without identifier.
    fn merge_failure(
        &mut self,
        fail: &mut BTreeMap<String, String>,
        matched_tuples: &[(String, String, String)],
    ) -> Option<Vec<String>> {
        let mut line_strs: Vec<String> = matched_tuples
            .iter()
            .map(|(a, b, c)| format!("{a}{b}{c}"))
            .collect();

        let mlfid_key = fail.get("mlfid").cloned();
        if let Some(ref mlfid) = mlfid_key {
            let mut nfflgs: u8 = 0;
            if fail.contains_key("nofail") {
                nfflgs |= 1;
            }
            if let Some(gained) = fail.get("mlfgained").cloned() {
                nfflgs |= 8 | 1;
                fail.entry("nofail".to_owned()).or_insert(gained);
            }
            if fail.remove("mlfforget").is_some() {
                nfflgs |= 2;
            }

            let mut mlfpending = false;
            let mut entry_opt = self.mlfid_cache.take(mlfid);

            if let Some(ref mut entry) = entry_opt {
                if let Some(u) = fail.get("user") {
                    entry.users.insert(u.clone());
                }
                if entry.data.remove("nofail").is_some() || entry.data.remove("mlfgained").is_some()
                {
                    nfflgs |= 4;
                }
                if (nfflgs & 8) != 0 && entry.mlfpending {
                    entry.mlfpending = false;
                    mlfpending = true;
                } else {
                    mlfpending = entry.mlfpending;
                }
                if (nfflgs & 4) == 0 && !mlfpending {
                    entry.matches.clear();
                }
                for (k, v) in fail.iter() {
                    entry.data.insert(k.clone(), v.clone());
                }
                *fail = entry.data.clone();
            } else if (nfflgs & 2) == 0 {
                let mut users = BTreeSet::new();
                if let Some(u) = fail.get("user") {
                    users.insert(u.clone());
                }
                entry_opt = Some(MlfIdEntry {
                    data: fail.clone(),
                    users,
                    mlfpending: false,
                    nofail_matches: Vec::new(),
                    matches: Vec::new(),
                });
            }

            if let Some(ref mut entry) = entry_opt {
                if mlfpending || entry.users.len() > 1 {
                    entry.mlfpending = false;
                    entry.data.remove("nofail");
                    entry.data.remove("mlfgained");
                    fail.remove("nofail");
                    fail.remove("mlfgained");
                    nfflgs &= !(8 | 1);
                }

                if (nfflgs & 1) == 0 {
                    let mut combined = std::mem::take(&mut entry.nofail_matches);
                    combined.extend(std::mem::take(&mut entry.matches));
                    if (nfflgs & 8) == 0 {
                        combined.extend(line_strs);
                    }
                    line_strs = combined;
                } else if (nfflgs & 3) == 1 {
                    entry.nofail_matches.extend(line_strs);
                    line_strs = Vec::new();
                }

                if (nfflgs & 2) == 0 {
                    self.mlfid_cache.insert(mlfid.clone(), entry.clone());
                }
            }
        }

        if fail.contains_key("nofail") && !self.check_all_regex {
            return None;
        }

        Some(line_strs)
    }

    fn build_results_from_match(
        &mut self,
        regex_idx: usize,
        event_time: f64,
        matches: Vec<String>,
        fail_data: BTreeMap<String, String>,
        out: &mut LineProcessResult,
    ) -> bool {
        let explicit_fid = fail_data.get("fid").map(|s| TicketId::parse(s));
        let resolved_ips = resolve_fail_ips(&fail_data, self.use_dns, self.return_raw_host);

        if explicit_fid.is_none() && resolved_ips.is_empty() {
            if let Some(mlfid) = fail_data.get("mlfid")
                && let Some(entry) = self.mlfid_cache.get_mut(mlfid)
            {
                entry.mlfpending = true;
                entry.matches = matches.clone();
            }
            if !self.check_all_regex && self.ignore_pending {
                return false;
            }
            if self.check_all_regex {
                out.results.push(MatchResult {
                    regex_idx,
                    fid: None,
                    ip: None,
                    time: event_time,
                    matches,
                    data: fail_data,
                });
                return true;
            }
            return false;
        }

        let pairs: Vec<(Option<TicketId>, Option<TicketId>)> = if resolved_ips.is_empty() {
            vec![(explicit_fid, None)]
        } else {
            resolved_ips
                .into_iter()
                .map(|ip_id| {
                    let fid = explicit_fid.clone().or_else(|| Some(ip_id.clone()));
                    (fid, Some(ip_id))
                })
                .collect()
        };

        let mut emitted_any = false;
        for (fid, ip) in pairs {
            if let Some(primary) = fid.as_ref().or(ip.as_ref()) {
                let mut tmp = Ticket::new(primary.clone(), event_time);
                tmp.ip = ip.clone();
                tmp.matches = matches.clone();
                tmp.data = fail_data.clone();
                if self.ignore.is_ignored(primary, Some(&tmp), &self.jail_name) {
                    self.stats.ignored += 1;
                    out.ignored_by_ip = true;
                    continue;
                }
            }
            out.results.push(MatchResult {
                regex_idx,
                fid,
                ip,
                time: event_time,
                matches: matches.clone(),
                data: fail_data.clone(),
            });
            emitted_any = true;
        }

        emitted_any
    }

    fn recompile_all_regexes(&mut self) -> Result<()> {
        let multiline = self.max_lines > 1;
        let new_pref = match &self.prefregex {
            Some(pref) => Some(FailRegex::compile_filter_regex(
                pref.raw_pattern(),
                multiline,
                self.use_dns,
            )?),
            None => None,
        };
        let mut new_fail = Vec::with_capacity(self.failregex.len());
        for rx in &self.failregex {
            new_fail.push(FailRegex::new(
                rx.raw_pattern(),
                new_pref.as_ref(),
                multiline,
                self.use_dns,
            )?);
        }
        let mut new_ignore = Vec::with_capacity(self.ignoreregex.len());
        for rx in &self.ignoreregex {
            new_ignore.push(FailRegex::compile_filter_regex(
                rx.raw_pattern(),
                multiline,
                self.use_dns,
            )?);
        }
        self.prefregex = new_pref;
        self.failregex = new_fail;
        self.ignoreregex = new_ignore;
        Ok(())
    }
}

fn resolve_fail_ips(
    fail_data: &BTreeMap<String, String>,
    use_dns: UseDns,
    return_raw_host: bool,
) -> Vec<TicketId> {
    let cidr = fail_data.get("cidr").and_then(|s| s.parse::<u8>().ok());
    if let Some(v4) = fail_data.get("ip4") {
        if return_raw_host {
            return vec![TicketId::Raw(v4.clone())];
        }
        return vec![parse_ip_with_cidr(v4, cidr)];
    }
    if let Some(v6) = fail_data.get("ip6") {
        if return_raw_host {
            return vec![TicketId::Raw(v6.clone())];
        }
        return vec![parse_ip_with_cidr(v6, cidr)];
    }
    if let Some(dns) = fail_data.get("dns") {
        if return_raw_host {
            return vec![TicketId::Raw(dns.clone())];
        }
        return text_to_ip(dns, use_dns);
    }
    Vec::new()
}

fn current_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn basic_filter_matching_ignoreregex_and_ignoreip() {
        let mut f = Filter::new("sshd");
        f.set_check_find_time(false);
        f.set_ignore_self(false);
        f.add_ignore_ip("10.0.0.0/8");
        f.add_ignore_regex(r"for healthcheck from").unwrap();
        f.add_fail_regex(r"Failed password for (?P<user>\S+) from <HOST> port \d+")
            .unwrap();

        let bad = f.process_line(
            "May 14 08:30:15 host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2",
            None,
        );
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].ip, Some(TicketId::parse("203.0.113.5")));
        assert_eq!(bad[0].fid, Some(TicketId::parse("203.0.113.5")));
        assert_eq!(bad[0].data.get("user").map(String::as_str), Some("root"));

        // Ignored by ignoreip CIDR
        let whitelisted = f.process_line(
            "May 14 08:30:16 host sshd[1]: Failed password for root from 10.1.2.3 port 22 ssh2",
            None,
        );
        assert!(whitelisted.is_empty());

        // Ignored by ignoreregex
        let ig_rx = f.process_line(
            "May 14 08:30:17 host sshd[1]: Failed password for healthcheck from 203.0.113.5 port 22",
            None,
        );
        assert!(ig_rx.is_empty());
        assert_eq!(f.stats().matched, 1);
        assert_eq!(f.stats().ignored, 2);
    }

    #[test]
    fn prefregex_and_mlfid_nofail_pending_gained_forget_state_machine() {
        let mut f = Filter::new("sshd");
        f.set_check_find_time(false);
        f.set_ignore_self(false);
        f.set_prefregex(Some(
            r"^\s*\S+ sshd\[<F-MLFID>\d+</F-MLFID>\]: <F-CONTENT>.+</F-CONTENT>$",
        ))
        .unwrap();
        f.add_fail_regex(r"^Connection from <HOST> port \d+<F-NOFAIL/>$")
            .unwrap();
        f.add_fail_regex(r"^Failed password for <F-USER>\S+</F-USER>$")
            .unwrap();
        f.add_fail_regex(r"^Received disconnect from <HOST>.*<F-MLFGAINED/>$")
            .unwrap();
        f.add_fail_regex(r"^Disconnected<F-MLFFORGET/><F-NOFAIL/>$")
            .unwrap();

        // Scenario A: Connection line carries IP with NOFAIL -> buffered silently; Failed line triggers using cached IP.
        let r1 = f.process_line(
            "2024-05-14 08:30:01 h1 sshd[100]: Connection from 198.51.100.10 port 4444",
            None,
        );
        assert!(r1.is_empty());
        let r2 = f.process_line(
            "2024-05-14 08:30:02 h1 sshd[100]: Failed password for alice",
            None,
        );
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].ip, Some(TicketId::parse("198.51.100.10")));
        assert_eq!(r2[0].data.get("user").map(String::as_str), Some("alice"));
        assert_eq!(r2[0].matches.len(), 2);

        // Clean forget discards session so later unrelated same-PID line has no stale IP.
        let r3 = f.process_line("2024-05-14 08:30:03 h1 sshd[100]: Disconnected", None);
        assert!(r3.is_empty());

        // Non-pending mlfgained does not emit a false failure on normal disconnect.
        let benign = f.process_line(
            "2024-05-14 08:30:30 h1 sshd[150]: Received disconnect from 198.51.100.15",
            None,
        );
        assert!(benign.is_empty());

        // Scenario B: Failure arrives BEFORE IP (`mlfpending`), then `mlfgained` supplies IP.
        let p1 = f.process_line(
            "2024-05-14 08:31:01 h1 sshd[200]: Failed password for bob",
            None,
        );
        assert!(p1.is_empty());
        let p2 = f.process_line(
            "2024-05-14 08:31:02 h1 sshd[200]: Received disconnect from 198.51.100.20",
            None,
        );
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].ip, Some(TicketId::parse("198.51.100.20")));
        assert_eq!(p2[0].data.get("user").map(String::as_str), Some("bob"));
        assert_eq!(p2[0].matches.len(), 2);
    }

    #[test]
    fn findtime_filtering_none_datepattern_and_process_line_with_info() {
        let mut f = Filter::new("app");
        f.set_ignore_self(false);
        f.set_find_time(60.0);
        f.set_check_find_time(true);
        f.add_fail_regex(r"^bad login from <HOST>$").unwrap();

        // Line older than findtime is skipped.
        let expired = f.process_line_at(
            "2024-05-14 08:00:00 bad login from 192.0.2.1",
            None,
            1_715_675_000.0,
        );
        assert!(expired.date_matched);
        assert!(expired.results.is_empty());

        // Line with missing date is marked missed.
        let missed = f.process_line_at("bad login from 192.0.2.1", None, 1_715_675_000.0);
        assert!(!missed.date_matched);
        assert!(missed.missed);
        assert!(missed.results.is_empty());

        // {NONE} datepattern matches using reference `now`.
        f.set_date_pattern(Some("{NONE}")).unwrap();
        let none_res = f.process_line_at("bad login from 192.0.2.1", None, 1_715_675_000.0);
        assert!(none_res.date_matched);
        assert_eq!(none_res.results.len(), 1);
        assert!((none_res.results[0].time - 1_715_675_000.0).abs() < 1e-6);
    }

    #[test]
    fn multiline_max_lines_and_check_all_regex_and_encoding() {
        let mut f = Filter::new("multi");
        f.set_check_find_time(false);
        f.set_ignore_self(false);
        f.set_max_lines(2).unwrap();
        f.add_fail_regex(r"user=(?P<user>\S+)\n.*from=<HOST>")
            .unwrap();

        assert!(
            f.process_line("2024-05-14 08:30:00 user=bob", None)
                .is_empty()
        );
        let res = f.process_line("2024-05-14 08:30:00 from=203.0.113.77", None);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].matches.len(), 2);
        assert_eq!(res[0].ip, Some(TicketId::parse("203.0.113.77")));

        // Verify next line doesn't re-trigger the already consumed line.
        assert!(
            f.process_line("2024-05-14 08:30:01 unrelated", None)
                .is_empty()
        );

        assert_eq!(
            LogEncoding::Latin1.decode(&[b'o', b'k', 0xE9]),
            "ok\u{00E9}"
        );
        assert_eq!(LogEncoding::Ascii.decode(&[b'a', 0xFF]), "a\u{FFFD}");
        assert_eq!(LogEncoding::Cp1252.decode(&[0x80, b'5']), "\u{20AC}5");

        // Upstream filtertestcase.py:1867 — U+020A embeds 0x0A byte in both UTF-16BE & UTF-16LE.
        let sample = "Test\u{020A} ok\nLine2\n";
        let be: Vec<u8> = sample.encode_utf16().flat_map(u16::to_be_bytes).collect();
        let (end_be, next_be) = LogEncoding::Utf16Be.split_line(&be).unwrap();
        assert_eq!(
            LogEncoding::Utf16Be.decode(&be[..end_be]),
            "Test\u{020A} ok"
        );
        assert_eq!(LogEncoding::Utf16Be.decode(&be[next_be..]), "Line2\n");

        let le: Vec<u8> = sample.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (end_le, next_le) = LogEncoding::Utf16Le.split_line(&le).unwrap();
        assert_eq!(
            LogEncoding::Utf16Le.decode(&le[..end_le]),
            "Test\u{020A} ok"
        );
        assert_eq!(LogEncoding::Utf16Le.decode(&le[next_le..]), "Line2\n");

        let mut with_bom = vec![0xFE, 0xFF];
        with_bom.extend_from_slice(&be[..end_be]);
        assert_eq!(LogEncoding::Utf16.decode(&with_bom), "Test\u{020A} ok");
    }

    #[test]
    fn sshd_open_close_mlf_tags_and_reload() {
        let mut f = Filter::new("sshd");
        f.set_check_find_time(false);
        f.set_ignore_self(false);
        f.set_prefregex(Some(
            r"^\s*\S+ sshd\[<F-MLFID>\d+</F-MLFID>\]: <F-CONTENT>.+</F-CONTENT>$",
        ))
        .unwrap();
        f.add_fail_regex(r"^<F-NOFAIL>Connection from</F-NOFAIL> <HOST> port \d+$")
            .unwrap();
        f.add_fail_regex(r"^Failed publickey for <F-USER>\S+</F-USER>$")
            .unwrap();
        f.add_fail_regex(r"^<F-MLFFORGET><F-MLFGAINED>Accepted \w+</F-MLFGAINED></F-MLFFORGET> for <F-USER>\S+</F-USER> from <HOST>$")
            .unwrap();

        assert!(
            f.process_line(
                "2024-05-14 09:00:01 h1 sshd[300]: Connection from 198.51.100.30 port 99",
                None
            )
            .is_empty()
        );
        let hits = f.process_line(
            "2024-05-14 09:00:02 h1 sshd[300]: Failed publickey for carol",
            None,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, Some(TicketId::parse("198.51.100.30")));

        // Verify reload(begin=true) clears rules while allowing fresh rules on reload(false).
        f.add_ignore_ip("198.51.100.30");
        f.reload(true).unwrap();
        assert!(f.fail_regexes().is_empty());
        assert!(f.ignore_ips().is_empty());
        assert!(f.prefregex().is_none());
        f.add_fail_regex(r"^Failed from <HOST>$").unwrap();
        f.reload(false).unwrap();
        assert_eq!(f.fail_regexes().len(), 1);
    }
}
