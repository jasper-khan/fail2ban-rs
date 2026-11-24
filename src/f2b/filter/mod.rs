//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/filter.py`.
//!
//! Coordinates [`DateDetector`], [`FailRegex`], [`IgnoreConfig`], `mlfid` multi-line
//! session correlation, and log input [`backend`]s.
#![allow(unsafe_code)]

pub mod backend;
pub mod file_identity;
pub mod ipdns;
pub mod poll_stamp;
pub mod regex;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::date::DateDetector;
use crate::duration::str2seconds;
use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};
use crate::ticket::{Ticket, TicketId};

use self::ipdns::{
    IgnoreCache, IgnoreConfig, IgnoreDecision, PendingIgnoreCommand, UseDns, dns_to_ip_cached,
    parse_ip_with_cidr, parse_ticket_ip_or_net, text_to_ip,
};
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
    Iconv {
        iconv_name: &'static CStr,
        display_name: &'static str,
    },
}

impl LogEncoding {
    /// Parse a Fail2Ban `logencoding` string (`auto`, `utf-8`, `latin1`, `ascii`, `cp1252`, `cp932`, `utf-16*`, etc.).
    pub fn parse(raw: &str) -> Result<Self> {
        let lower = raw.trim().to_ascii_lowercase();
        match lower.as_str() {
            "auto" | "" => Ok(Self::Auto),
            "utf-8" | "utf8" | "utf_8" => Ok(Self::Utf8),
            "latin1" | "latin-1" | "latin_1" | "iso-8859-1" | "iso8859-1" | "iso_8859_1"
            | "iso8859_1" | "cp819" | "l1" => Ok(Self::Latin1),
            "ascii" | "us-ascii" | "us_ascii" | "646" => Ok(Self::Ascii),
            "cp1252" | "windows-1252" | "windows_1252" | "1252" => Ok(Self::Cp1252),
            "utf-16le" | "utf16le" | "utf_16_le" | "utf-16-le" => Ok(Self::Utf16Le),
            "utf-16be" | "utf16be" | "utf_16_be" | "utf-16-be" => Ok(Self::Utf16Be),
            "utf-16" | "utf16" | "utf_16" => Ok(Self::Utf16),
            _ => resolve_iconv_encoding(&lower)
                .ok_or_else(|| Error::config(format!("Unsupported logencoding {raw:?}"))),
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
            Self::Iconv { display_name, .. } => display_name,
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
            Self::Auto
            | Self::Utf8
            | Self::Latin1
            | Self::Ascii
            | Self::Cp1252
            | Self::Iconv { .. } => {
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
            Self::Iconv { iconv_name, .. } => decode_iconv_bytes(iconv_name, bytes),
        }
    }
}

fn resolve_iconv_encoding(lower: &str) -> Option<LogEncoding> {
    let norm = lower.replace(['-', ' '], "_");
    let (iconv_name, display_name) = match norm.as_str() {
        "cp932" | "932" | "ms932" | "mskanji" | "ms_kanji" | "windows_31j" | "csWindows31J" => {
            (c"CP932", "cp932")
        }
        "shift_jis" | "shiftjis" | "sjis" | "s_jis" | "shift_jis_2004" | "shift_jisx0213" => {
            (c"SHIFT_JIS", "shift_jis")
        }
        "euc_jp" | "eucjp" | "ujis" | "u_jis" | "euc_jis_2004" | "euc_jisx0213" => {
            (c"EUC-JP", "euc_jp")
        }
        "gbk" | "936" | "cp936" | "ms936" => (c"GBK", "gbk"),
        "gb2312" | "chinese" | "csiso58gb231280" | "euc_cn" | "euccn" | "hz" => {
            (c"GB2312", "gb2312")
        }
        "gb18030" | "gb18030_2000" => (c"GB18030", "gb18030"),
        "big5" | "big5_tw" | "csbig5" | "cp950" | "950" | "ms950" | "big5hkscs" => {
            (c"BIG5", "big5")
        }
        "euc_kr" | "euckr" | "korean" | "ksc5601" | "ks_c_5601_1987" | "cp949" | "949" | "uhc" => {
            (c"EUC-KR", "euc_kr")
        }
        "koi8_r" | "koi8r" => (c"KOI8-R", "koi8_r"),
        "koi8_u" | "koi8u" => (c"KOI8-U", "koi8_u"),
        "cp1250" | "windows_1250" | "1250" => (c"CP1250", "cp1250"),
        "cp1251" | "windows_1251" | "1251" => (c"CP1251", "cp1251"),
        "cp1253" | "windows_1253" | "1253" => (c"CP1253", "cp1253"),
        "cp1254" | "windows_1254" | "1254" => (c"CP1254", "cp1254"),
        "cp1255" | "windows_1255" | "1255" => (c"CP1255", "cp1255"),
        "cp1256" | "windows_1256" | "1256" => (c"CP1256", "cp1256"),
        "cp1257" | "windows_1257" | "1257" => (c"CP1257", "cp1257"),
        "cp1258" | "windows_1258" | "1258" => (c"CP1258", "cp1258"),
        "cp866" | "866" | "ibm866" => (c"CP866", "cp866"),
        "cp850" | "850" | "ibm850" => (c"CP850", "cp850"),
        "cp437" | "437" | "ibm437" => (c"CP437", "cp437"),
        "iso_8859_2" | "iso8859_2" | "latin2" | "l2" => (c"ISO-8859-2", "iso8859-2"),
        "iso_8859_3" | "iso8859_3" | "latin3" | "l3" => (c"ISO-8859-3", "iso8859-3"),
        "iso_8859_4" | "iso8859_4" | "latin4" | "l4" => (c"ISO-8859-4", "iso8859-4"),
        "iso_8859_5" | "iso8859_5" | "cyrillic" => (c"ISO-8859-5", "iso8859-5"),
        "iso_8859_6" | "iso8859_6" | "arabic" => (c"ISO-8859-6", "iso8859-6"),
        "iso_8859_7" | "iso8859_7" | "greek" => (c"ISO-8859-7", "iso8859-7"),
        "iso_8859_8" | "iso8859_8" | "hebrew" => (c"ISO-8859-8", "iso8859-8"),
        "iso_8859_9" | "iso8859_9" | "latin5" | "l5" => (c"ISO-8859-9", "iso8859-9"),
        "iso_8859_10" | "iso8859_10" | "latin6" | "l6" => (c"ISO-8859-10", "iso8859-10"),
        "iso_8859_13" | "iso8859_13" | "latin7" | "l7" => (c"ISO-8859-13", "iso8859-13"),
        "iso_8859_14" | "iso8859_14" | "latin8" | "l8" => (c"ISO-8859-14", "iso8859-14"),
        "iso_8859_15" | "iso8859_15" | "latin9" | "l9" => (c"ISO-8859-15", "iso8859-15"),
        "iso_8859_16" | "iso8859_16" | "latin10" | "l10" => (c"ISO-8859-16", "iso8859-16"),
        _ => return None,
    };
    Some(LogEncoding::Iconv {
        iconv_name,
        display_name,
    })
}

#[cfg(unix)]
fn decode_iconv_bytes(from_code: &CStr, mut input: &[u8]) -> String {
    use std::ffi::{c_char, c_int, c_void};

    unsafe extern "C" {
        fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> *mut c_void;
        fn iconv(
            cd: *mut c_void,
            inbuf: *mut *mut c_char,
            inbytesleft: *mut usize,
            outbuf: *mut *mut c_char,
            outbytesleft: *mut usize,
        ) -> usize;
        fn iconv_close(cd: *mut c_void) -> c_int;
    }

    let invalid = usize::MAX as *mut c_void;
    // SAFETY: Both `c"UTF-8"` and `from_code` are valid NUL-terminated static C strings.
    let cd = unsafe { iconv_open(c"UTF-8".as_ptr(), from_code.as_ptr()) };
    if cd == invalid || cd.is_null() {
        return String::from_utf8_lossy(input).into_owned();
    }

    let mut out = String::with_capacity(input.len());
    let mut chunk = [0u8; 256];
    while !input.is_empty() {
        let mut in_ptr = input.as_ptr() as *mut c_char;
        let mut in_left = input.len();
        let mut out_ptr = chunk.as_mut_ptr() as *mut c_char;
        let mut out_left = chunk.len();
        // SAFETY: `cd` is a valid open iconv descriptor; `in_ptr`/`in_left` and `out_ptr`/`out_left`
        // point to live slices of exact length `in_left` and `out_left`.
        let res = unsafe { iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left) };
        let written = chunk.len() - out_left;
        if written > 0 {
            out.push_str(&String::from_utf8_lossy(&chunk[..written]));
        }
        let consumed = input.len() - in_left;
        input = &input[consumed..];
        if res == usize::MAX {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == nix::libc::E2BIG {
                continue;
            }
            if !input.is_empty() {
                out.push('\u{FFFD}');
                input = &input[1..];
            }
        }
    }
    // SAFETY: `cd` is a valid open iconv descriptor and is not used after `iconv_close`.
    unsafe {
        iconv_close(cd);
    }
    out
}

#[cfg(not(unix))]
fn decode_iconv_bytes(_from_code: &CStr, input: &[u8]) -> String {
    String::from_utf8_lossy(input).into_owned()
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

/// Saved filter configuration state for rolling back a failed reload.
#[derive(Debug)]
pub struct FilterReloadSnapshot {
    prefregex: Option<FailRegex>,
    failregex: Vec<FailRegex>,
    ignoreregex: Vec<FailRegex>,
    regex_hits: Vec<usize>,
    ignoreregex_hits: Vec<usize>,
    ignore: IgnoreConfig,
    date_detector: DateDetector,
    log_timezone: Option<String>,
    log_encoding: LogEncoding,
    log_encoding_name: String,
    max_lines: usize,
    use_dns: UseDns,
    find_time: f64,
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
    next_sim_by_time_warn: f64,
    line_buffer: Vec<(String, String, String)>,
    stats: ProcessLineStats,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new("default")
    }
}

/// A regex match whose `<HOST>` DNS hostname is not yet cached and must be resolved off-thread.
#[derive(Debug, Clone)]
pub struct PendingDnsMatch {
    pub regex_idx: usize,
    pub event_time: f64,
    pub matches: Vec<String>,
    pub fail_data: BTreeMap<String, String>,
    pub dns_host: String,
}

/// Async external work deferred by [`Filter::process_line_defer_ignore_cmd`] so callers
/// never block Tokio threads or hold jail locks across DNS or `ignorecommand` I/O.
#[derive(Debug, Default)]
pub struct DeferredLineWork {
    pub pending_dns: Vec<PendingDnsMatch>,
    pub pending_ignore: Vec<(MatchResult, PendingIgnoreCommand)>,
}

impl DeferredLineWork {
    pub fn is_empty(&self) -> bool {
        self.pending_dns.is_empty() && self.pending_ignore.is_empty()
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
            next_sim_by_time_warn: 0.0,
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

    /// Return deduplicated hostnames in `ignoreip`/`file:` whose forward DNS entries are
    /// not yet cached, so async callers can resolve them via `spawn_blocking` outside locks.
    pub fn uncached_ignore_hosts(&mut self) -> Vec<String> {
        self.ignore.uncached_ignore_hosts()
    }

    pub fn ignores_ip(&mut self, id: &TicketId, ticket: Option<&Ticket>) -> bool {
        self.ignore.is_ignored(id, ticket, &self.jail_name)
    }

    pub fn check_ignore_static(
        &mut self,
        id: &TicketId,
        ticket: Option<&Ticket>,
    ) -> IgnoreDecision {
        self.ignore.check_ignore_static(id, ticket, &self.jail_name)
    }

    pub fn finish_ignore_command(&mut self, pending: PendingIgnoreCommand, ignored: bool) -> bool {
        self.ignore
            .finish_ignore_command(pending, &self.jail_name, ignored)
    }

    pub fn record_deferred_match_outcome(
        &mut self,
        regex_idx: usize,
        pending: PendingIgnoreCommand,
        ignored: bool,
    ) -> bool {
        let ignored = self
            .ignore
            .finish_ignore_command(pending, &self.jail_name, ignored);
        if ignored {
            self.stats.ignored += 1;
        } else {
            if let Some(slot) = self.stats.regex_hits.get_mut(regex_idx) {
                *slot += 1;
            }
            self.stats.matched += 1;
        }
        ignored
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

    /// Save current regex/ignore rules and clear them at the beginning of a reload.
    pub fn snapshot_and_clear_for_reload(&mut self) -> FilterReloadSnapshot {
        let snap = FilterReloadSnapshot {
            prefregex: self.prefregex.take(),
            failregex: std::mem::take(&mut self.failregex),
            ignoreregex: std::mem::take(&mut self.ignoreregex),
            regex_hits: std::mem::take(&mut self.stats.regex_hits),
            ignoreregex_hits: std::mem::take(&mut self.stats.ignoreregex_hits),
            ignore: std::mem::take(&mut self.ignore),
            date_detector: self.date_detector.clone(),
            log_timezone: self.log_timezone.clone(),
            log_encoding: self.log_encoding,
            log_encoding_name: self.log_encoding_name.clone(),
            max_lines: self.max_lines,
            use_dns: self.use_dns,
            find_time: self.find_time,
        };
        self.ignore = IgnoreConfig::new();
        snap
    }

    /// Restore a saved [`FilterReloadSnapshot`] when a reload stream fails.
    pub fn restore_reload_snapshot(&mut self, snap: FilterReloadSnapshot) {
        self.prefregex = snap.prefregex;
        self.failregex = snap.failregex;
        self.ignoreregex = snap.ignoreregex;
        self.stats.regex_hits = snap.regex_hits;
        self.stats.ignoreregex_hits = snap.ignoreregex_hits;
        self.ignore = snap.ignore;
        self.date_detector = snap.date_detector;
        self.log_timezone = snap.log_timezone;
        self.log_encoding = snap.log_encoding;
        self.log_encoding_name = snap.log_encoding_name;
        self.max_lines = snap.max_lines;
        self.use_dns = snap.use_dns;
        self.find_time = snap.find_time;
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
        self.process_line_inner(line, preset_date, now, None)
    }

    /// Like [`Filter::process_line_at`], but defers uncached forward DNS lookups and external
    /// `ignorecommand` executions so async daemon workers can drop jail locks before I/O.
    pub fn process_line_defer_ignore_cmd(
        &mut self,
        line: &str,
        preset_date: Option<f64>,
        now: f64,
    ) -> (LineProcessResult, DeferredLineWork) {
        let mut deferred = DeferredLineWork::default();
        let res = self.process_line_inner(line, preset_date, now, Some(&mut deferred));
        (res, deferred)
    }

    /// Finalize a [`PendingDnsMatch`] after its hostname has been resolved into the DNS cache
    /// via `spawn_blocking`, returning immediate matches and any deferred `ignorecommand` work.
    pub fn finish_deferred_dns_match(
        &mut self,
        pending: PendingDnsMatch,
    ) -> (Vec<MatchResult>, Vec<(MatchResult, PendingIgnoreCommand)>) {
        let mut out = LineProcessResult::default();
        let mut deferred = DeferredLineWork::default();
        let produced = self.build_results_from_match(
            pending.regex_idx,
            pending.event_time,
            pending.matches,
            pending.fail_data,
            &mut out,
            Some(&mut deferred),
            false,
        );
        if produced {
            if let Some(slot) = self.stats.regex_hits.get_mut(pending.regex_idx) {
                *slot += 1;
            }
            self.stats.matched += 1;
        }
        (out.results, deferred.pending_ignore)
    }

    fn process_line_inner(
        &mut self,
        line: &str,
        preset_date: Option<f64>,
        now: f64,
        deferred: Option<&mut DeferredLineWork>,
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

        let Some(mut event_time) = time_opt.or_else(|| {
            if !self.check_find_time {
                Some(now)
            } else if self.in_operation {
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
                Some(now)
            } else {
                None
            }
        }) else {
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

        if self.check_find_time {
            if self.in_operation {
                let delta = (event_time - now) as i64;
                if delta.abs() > 60 {
                    if now >= self.next_sim_by_time_warn {
                        self.next_sim_by_time_warn = now + 86_400.0;
                        log_msg(
                            LogLevel::Warning,
                            "fail2ban.filter",
                            &format!(
                                "[{}] Detected a log entry {}s {} the current time in operation mode. Treating such entries as if they just happened.",
                                self.jail_name,
                                delta.abs(),
                                if delta < 0 { "before" } else { "after" },
                            ),
                        );
                    }
                    event_time = now;
                    self.last_date = now;
                }
            } else if event_time < now - self.find_time {
                log_msg(
                    LogLevel::TraceDebug,
                    "fail2ban.filter",
                    &format!(
                        "[{}] Ignore line since time {event_time} < {}",
                        self.jail_name,
                        now - self.find_time
                    ),
                );
                out.date_time = Some(event_time);
                return out;
            }
        }

        out.date_time = Some(event_time);
        self.run_find_failure(event_time, &mut out, deferred);
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

    fn run_find_failure(
        &mut self,
        event_time: f64,
        out: &mut LineProcessResult,
        mut deferred: Option<&mut DeferredLineWork>,
    ) {
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

            let produced = self.build_results_from_match(
                idx,
                event_time,
                merged_lines,
                fail_data,
                out,
                deferred.as_deref_mut(),
                true,
            );

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

    #[allow(clippy::too_many_arguments)]
    fn build_results_from_match(
        &mut self,
        regex_idx: usize,
        event_time: f64,
        matches: Vec<String>,
        fail_data: BTreeMap<String, String>,
        out: &mut LineProcessResult,
        mut deferred: Option<&mut DeferredLineWork>,
        defer_uncached_dns: bool,
    ) -> bool {
        if defer_uncached_dns
            && !self.return_raw_host
            && matches!(self.use_dns, UseDns::Yes | UseDns::Warn)
            && !fail_data.contains_key("ip4")
            && !fail_data.contains_key("ip6")
            && let Some(dns_raw) = fail_data.get("dns")
            && parse_ticket_ip_or_net(dns_raw).is_none()
            && !dns_raw.trim().is_empty()
            && dns_to_ip_cached(dns_raw.trim()).is_none()
            && let Some(deferred_out) = deferred.as_deref_mut()
        {
            let dns_host = dns_raw.trim().to_owned();
            deferred_out.pending_dns.push(PendingDnsMatch {
                regex_idx,
                event_time,
                matches,
                fail_data,
                dns_host,
            });
            return false;
        }

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
                if let Some(deferred_out) = deferred.as_deref_mut() {
                    match self
                        .ignore
                        .check_ignore_static(primary, Some(&tmp), &self.jail_name)
                    {
                        IgnoreDecision::Decided(true) => {
                            self.stats.ignored += 1;
                            out.ignored_by_ip = true;
                            continue;
                        }
                        IgnoreDecision::Decided(false) => {}
                        IgnoreDecision::RunCommand(pending) => {
                            deferred_out.pending_ignore.push((
                                MatchResult {
                                    regex_idx,
                                    fid,
                                    ip,
                                    time: event_time,
                                    matches: matches.clone(),
                                    data: fail_data.clone(),
                                },
                                pending,
                            ));
                            continue;
                        }
                    }
                } else if self.ignore.is_ignored(primary, Some(&tmp), &self.jail_name) {
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
    let cidr = match fail_data.get("cidr").map(String::as_str) {
        None | Some("") => None,
        Some(raw) => match raw.parse::<u8>() {
            Ok(p) => Some(p),
            Err(_) => return Vec::new(),
        },
    };
    if let Some(v4) = fail_data.get("ip4") {
        if return_raw_host {
            return vec![TicketId::Raw(v4.clone())];
        }
        return parse_ip_with_cidr(v4, cidr).into_iter().collect();
    }
    if let Some(v6) = fail_data.get("ip6") {
        if return_raw_host {
            return vec![TicketId::Raw(v6.clone())];
        }
        return parse_ip_with_cidr(v6, cidr)
            .filter(|id| crate::filter::ipdns::allow_ipv6() || !id.is_ipv6())
            .into_iter()
            .collect();
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
