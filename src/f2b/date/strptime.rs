//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/strptime.py`.
//!
//! Provides `timeRE` directive expansion, the `TZ_ABBR_OFFS` timezone table,
//! `validate_timezone`, and `re_group_dict_strptime` with midnight/year
//! rollover and `default_tz` support.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};

use chrono::{
    DateTime, Datelike, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta,
    TimeZone,
};

use crate::error::{Error, Result};

/// Alternate baseline year matching `MyTime.alternateNowTime` (`None` -> 2001, `0` -> 1970).
static ALTERNATE_YEAR: AtomicI32 = AtomicI32::new(2001);

/// Set an alternate baseline year for `%ExY` decade generation (e.g. `Some(1970)` in `fail2ban-regex`).
pub fn set_alternate_year(year: Option<i32>) {
    ALTERNATE_YEAR.store(year.unwrap_or(2001).min(2001), Ordering::Relaxed);
}

const TZ_STR: &[(&str, f64)] = &[
    ("Y", -12.0),
    ("X", -11.0),
    ("NUT", -11.0),
    ("SST", -11.0),
    ("W", -10.0),
    ("CKT", -10.0),
    ("HAST", -10.0),
    ("HST", -10.0),
    ("TAHT", -10.0),
    ("TKT", -10.0),
    ("V", -9.0),
    ("AKST", -9.0),
    ("GAMT", -9.0),
    ("GIT", -9.0),
    ("HADT", -9.0),
    ("HNY", -9.0),
    ("U", -8.0),
    ("AKDT", -8.0),
    ("CIST", -8.0),
    ("HAY", -8.0),
    ("HNP", -8.0),
    ("PST", -8.0),
    ("PT", -8.0),
    ("T", -7.0),
    ("HAP", -7.0),
    ("HNR", -7.0),
    ("MST", -7.0),
    ("PDT", -7.0),
    ("S", -6.0),
    ("CST", -6.0),
    ("EAST", -6.0),
    ("GALT", -6.0),
    ("HAR", -6.0),
    ("HNC", -6.0),
    ("MDT", -6.0),
    ("R", -5.0),
    ("CDT", -5.0),
    ("COT", -5.0),
    ("EASST", -5.0),
    ("ECT", -5.0),
    ("EST", -5.0),
    ("ET", -5.0),
    ("HAC", -5.0),
    ("HNE", -5.0),
    ("PET", -5.0),
    ("Q", -4.0),
    ("AST", -4.0),
    ("BOT", -4.0),
    ("CLT", -4.0),
    ("COST", -4.0),
    ("EDT", -4.0),
    ("FKT", -4.0),
    ("GYT", -4.0),
    ("HAE", -4.0),
    ("HNA", -4.0),
    ("PYT", -4.0),
    ("P", -3.0),
    ("ADT", -3.0),
    ("ART", -3.0),
    ("BRT", -3.0),
    ("CLST", -3.0),
    ("FKST", -3.0),
    ("GFT", -3.0),
    ("HAA", -3.0),
    ("PMST", -3.0),
    ("PYST", -3.0),
    ("SRT", -3.0),
    ("UYT", -3.0),
    ("WGT", -3.0),
    ("O", -2.0),
    ("BRST", -2.0),
    ("FNT", -2.0),
    ("PMDT", -2.0),
    ("UYST", -2.0),
    ("WGST", -2.0),
    ("N", -1.0),
    ("AZOT", -1.0),
    ("CVT", -1.0),
    ("EGT", -1.0),
    ("Z", 0.0),
    ("EGST", 0.0),
    ("GMT", 0.0),
    ("UTC", 0.0),
    ("WET", 0.0),
    ("WT", 0.0),
    ("A", 1.0),
    ("CET", 1.0),
    ("DFT", 1.0),
    ("WAT", 1.0),
    ("WEDT", 1.0),
    ("WEST", 1.0),
    ("B", 2.0),
    ("CAT", 2.0),
    ("CEDT", 2.0),
    ("CEST", 2.0),
    ("EET", 2.0),
    ("SAST", 2.0),
    ("WAST", 2.0),
    ("C", 3.0),
    ("EAT", 3.0),
    ("EEDT", 3.0),
    ("EEST", 3.0),
    ("IDT", 3.0),
    ("MSK", 3.0),
    ("D", 4.0),
    ("AMT", 4.0),
    ("AZT", 4.0),
    ("GET", 4.0),
    ("GST", 4.0),
    ("KUYT", 4.0),
    ("MSD", 4.0),
    ("MUT", 4.0),
    ("RET", 4.0),
    ("SAMT", 4.0),
    ("SCT", 4.0),
    ("E", 5.0),
    ("AMST", 5.0),
    ("AQTT", 5.0),
    ("AZST", 5.0),
    ("HMT", 5.0),
    ("MAWT", 5.0),
    ("MVT", 5.0),
    ("PKT", 5.0),
    ("TFT", 5.0),
    ("TJT", 5.0),
    ("TMT", 5.0),
    ("UZT", 5.0),
    ("YEKT", 5.0),
    ("F", 6.0),
    ("ALMT", 6.0),
    ("BIOT", 6.0),
    ("BTT", 6.0),
    ("IOT", 6.0),
    ("KGT", 6.0),
    ("NOVT", 6.0),
    ("OMST", 6.0),
    ("YEKST", 6.0),
    ("G", 7.0),
    ("CXT", 7.0),
    ("DAVT", 7.0),
    ("HOVT", 7.0),
    ("ICT", 7.0),
    ("KRAT", 7.0),
    ("NOVST", 7.0),
    ("OMSST", 7.0),
    ("THA", 7.0),
    ("WIB", 7.0),
    ("H", 8.0),
    ("ACT", 8.0),
    ("AWST", 8.0),
    ("BDT", 8.0),
    ("BNT", 8.0),
    ("CAST", 8.0),
    ("HKT", 8.0),
    ("IRKT", 8.0),
    ("KRAST", 8.0),
    ("MYT", 8.0),
    ("PHT", 8.0),
    ("SGT", 8.0),
    ("ULAT", 8.0),
    ("WITA", 8.0),
    ("WST", 8.0),
    ("I", 9.0),
    ("AWDT", 9.0),
    ("IRKST", 9.0),
    ("JST", 9.0),
    ("KST", 9.0),
    ("PWT", 9.0),
    ("TLT", 9.0),
    ("WDT", 9.0),
    ("WIT", 9.0),
    ("YAKT", 9.0),
    ("K", 10.0),
    ("AEST", 10.0),
    ("ChST", 10.0),
    ("PGT", 10.0),
    ("VLAT", 10.0),
    ("YAKST", 10.0),
    ("YAPT", 10.0),
    ("L", 11.0),
    ("AEDT", 11.0),
    ("LHDT", 11.0),
    ("MAGT", 11.0),
    ("NCT", 11.0),
    ("PONT", 11.0),
    ("SBT", 11.0),
    ("VLAST", 11.0),
    ("VUT", 11.0),
    ("M", 12.0),
    ("ANAST", 12.0),
    ("ANAT", 12.0),
    ("FJT", 12.0),
    ("GILT", 12.0),
    ("MAGST", 12.0),
    ("MHT", 12.0),
    ("NZST", 12.0),
    ("PETST", 12.0),
    ("PETT", 12.0),
    ("TVT", 12.0),
    ("WFT", 12.0),
    ("FJST", 13.0),
    ("NZDT", 13.0),
    ("NFT", 11.5),
    ("ACDT", 10.5),
    ("LHST", 10.5),
    ("ACST", 9.5),
    ("CCT", 6.5),
    ("MMT", 6.5),
    ("NPT", 5.75),
    ("SLT", 5.5),
    ("AFT", 4.5),
    ("IRDT", 4.5),
    ("IRST", 3.5),
    ("HAT", -2.5),
    ("NDT", -2.5),
    ("HNT", -3.5),
    ("NST", -3.5),
    ("NT", -3.5),
    ("HLV", -4.5),
    ("VET", -4.5),
    ("MART", -9.5),
    ("MIT", -9.5),
];

/// Cached map of Fail2Ban timezone abbreviation -> offset in minutes.
pub fn tz_abbr_offs() -> &'static BTreeMap<&'static str, i32> {
    static MAP: OnceLock<BTreeMap<&'static str, i32>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = BTreeMap::new();
        m.insert("", 0);
        for &(abbr, hours) in TZ_STR {
            m.insert(abbr, (hours * 60.0) as i32);
        }
        m
    })
}

/// Validate a Fail2Ban timezone specification and convert to offset in minutes.
///
/// Supports `None`, empty string (`Some(0)`), fixed offsets (`+0200`, `-05:00`,
/// `-04`), and symbolic abbreviations (`UTC`, `GMT`, `Z`, `CET+0100`, `PST`).
pub fn validate_timezone(tz: Option<&str>) -> Result<Option<i32>> {
    let Some(raw) = tz else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(Some(0));
    }

    let (abbr, tzo) = split_fixed_offset_tz(raw)
        .ok_or_else(|| Error::date(format!("Unknown or unsupported time zone: {raw:?}")))?;

    let base = if abbr.is_empty() {
        0
    } else {
        *tz_abbr_offs()
            .get(abbr)
            .ok_or_else(|| Error::date(format!("Unknown or unsupported time zone: {raw:?}")))?
    };

    if tzo.is_empty() {
        return Ok(Some(base));
    }

    let sign = if tzo.starts_with('-') { -1 } else { 1 };
    let rest = &tzo[1..];
    let delta = if rest.len() <= 2 {
        let hh: i32 = rest
            .parse()
            .map_err(|_| Error::date(format!("Unknown or unsupported time zone: {raw:?}")))?;
        sign * hh * 60
    } else {
        let (hh_str, mm_str) = if let Some((h, m)) = rest.split_once(':') {
            (h, m)
        } else if rest.len() == 4 {
            (&rest[..2], &rest[2..])
        } else {
            return Err(Error::date(format!(
                "Unknown or unsupported time zone: {raw:?}"
            )));
        };
        let hh: i32 = hh_str
            .parse()
            .map_err(|_| Error::date(format!("Unknown or unsupported time zone: {raw:?}")))?;
        let mm: i32 = mm_str
            .parse()
            .map_err(|_| Error::date(format!("Unknown or unsupported time zone: {raw:?}")))?;
        sign * (hh * 60 + mm)
    };
    Ok(Some(base + delta))
}

fn split_fixed_offset_tz(raw: &str) -> Option<(&str, &str)> {
    // Matches `^(?P<abbr>[A-Z](?:[A-Za-z]{2,4})?)?(?P<off>[+-][01]\d(?::?\d{2})?)?$`
    let bytes = raw.as_bytes();
    let mut idx = 0usize;
    if let Some(&first) = bytes.first()
        && first.is_ascii_uppercase()
    {
        idx = 1;
        while idx < bytes.len() && bytes[idx].is_ascii_alphabetic() {
            idx += 1;
        }
        if idx != 1 && !(3..=5).contains(&idx) {
            return None;
        }
    }
    let abbr = &raw[..idx];
    let off = &raw[idx..];
    if !off.is_empty() {
        let ob = off.as_bytes();
        if ob.len() < 3
            || !matches!(ob[0], b'+' | b'-')
            || !matches!(ob[1], b'0' | b'1')
            || !ob[2].is_ascii_digit()
        {
            return None;
        }
        let tail = &ob[3..];
        let valid_tail = match tail.len() {
            0 => true,
            2 => tail[0].is_ascii_digit() && tail[1].is_ascii_digit(),
            3 => tail[0] == b':' && tail[1].is_ascii_digit() && tail[2].is_ascii_digit(),
            _ => false,
        };
        if !valid_tail {
            return None;
        }
    }
    Some((abbr, off))
}

const TZ_ABBR_RE: &str = r"[A-Z](?:[A-Za-z]{2,4})?";

/// Build Fail2Ban's `%ExY` century regex matching `strptime.py`'s `_getYearCentRE`.
pub fn build_ex_year_regex(base_year: i32, alt_year: i32) -> String {
    let cent = |y: i32| -> String {
        let s = format!("{y:04}");
        s.chars().take(3).collect()
    };
    let mut set = BTreeSet::new();
    set.insert(cent(base_year - 1));
    set.insert(cent(base_year + 3));
    let mut y = alt_year - 1;
    while y <= base_year {
        set.insert(cent(y));
        y += 3;
    }
    let list: Vec<String> = set.into_iter().collect();
    let grouped = group_prefixes(&list);
    format!(r"(?P<Y>{grouped}\d)")
}

fn group_prefixes(exprset: &[String]) -> String {
    if exprset.is_empty() {
        return String::new();
    }
    if exprset.len() == 1 {
        return exprset[0].clone();
    }
    if exprset.iter().all(|s| s.chars().count() == 1) {
        return format!("[{}]", exprset.join(""));
    }

    let mut buckets: BTreeMap<char, Vec<String>> = BTreeMap::new();
    let mut plain_fallbacks = Vec::new();

    for s in exprset {
        let mut chars = s.chars();
        if let Some(first) = chars.next() {
            let tail: String = chars.collect();
            if tail.is_empty() {
                plain_fallbacks.push(s.clone());
            } else {
                buckets.entry(first).or_default().push(tail);
            }
        }
    }

    if !plain_fallbacks.is_empty() || buckets.is_empty() {
        return format!("(?:{})", exprset.join("|"));
    }

    let mut parts = Vec::with_capacity(buckets.len());
    for (prefix, tails) in buckets {
        let sub = group_prefixes(&tails);
        parts.push(format!("{prefix}{sub}"));
    }
    if parts.len() == 1 {
        parts.into_iter().next().unwrap_or_default()
    } else {
        format!("(?:{})", parts.join("|"))
    }
}

/// Expand a Fail2Ban `strptime` pattern (e.g. `%Y-%m-%d %H:%M:%S`) into
/// `(human_name, regex_pattern)` using the exact `timeRE` directives.
pub fn expand_date_pattern(pattern: &str) -> Result<(String, String)> {
    let mut name_out = String::with_capacity(pattern.len() * 2);
    let mut regex_out = String::with_capacity(pattern.len() * 2);
    let bytes = pattern.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            let ch = pattern[i..]
                .chars()
                .next()
                .ok_or_else(|| Error::date("invalid utf-8 in datepattern"))?;
            name_out.push(ch);
            regex_out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let rest = &pattern[i + 1..];
        let (key, consumed) = match_directive(rest).ok_or_else(|| {
            Error::date(format!(
                "Failed to set datepattern {pattern:?} (invalid or unescaped %)"
            ))
        })?;
        let (disp, rx) = directive_parts(key)?;
        name_out.push_str(&disp);
        regex_out.push_str(&rx);
        i += 1 + consumed;
    }

    Ok((name_out, regex_out))
}

fn match_directive(rest: &str) -> Option<(&'static str, usize)> {
    const LONG_KEYS: &[&str] = &[
        "ExY", "Exy", "Exm", "Exd", "ExH", "Exk", "Exl", "ExM", "ExS", "Exz", "ExZ",
    ];
    for &k in LONG_KEYS {
        if rest.starts_with(k) {
            return Some((k, k.len()));
        }
    }
    const SHORT_KEYS: &[&str] = &[
        "%", "Y", "y", "m", "b", "B", "d", "H", "k", "I", "l", "M", "S", "f", "p", "a", "A", "w",
        "j", "U", "W", "z", "Z", "c", "x", "X",
    ];
    for &k in SHORT_KEYS {
        if rest.starts_with(k) {
            return Some((k, k.len()));
        }
    }
    None
}

fn directive_parts(key: &str) -> Result<(String, String)> {
    let (disp, rx) = match key {
        "%" => ("%".to_owned(), "%".to_owned()),
        "a" => ("DAY".to_owned(), r"(?P<a>mon|tue|wed|thu|fri|sat|sun)".to_owned()),
        "A" => (
            "DAYNAME".to_owned(),
            r"(?P<A>monday|tuesday|wednesday|thursday|friday|saturday|sunday)".to_owned(),
        ),
        "b" => (
            "MON".to_owned(),
            r"(?P<b>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)".to_owned(),
        ),
        "B" => (
            "MONTH".to_owned(),
            r"(?P<B>january|february|march|april|may|june|july|august|september|october|november|december)".to_owned(),
        ),
        "d" => ("Day".to_owned(), r"(?P<d>[1-2]\d|[0 ]?[1-9]|3[0-1])".to_owned()),
        "H" => ("24hour".to_owned(), r"(?P<H>[0-1]?\d|2[0-3])".to_owned()),
        "k" => ("%k".to_owned(), r" ?(?P<H>[0-2]?\d)".to_owned()),
        "I" => ("12hour".to_owned(), r"(?P<I>1[0-2]|0[1-9]|[1-9])".to_owned()),
        "l" => ("%l".to_owned(), r" ?(?P<I>1?\d)".to_owned()),
        "j" => (
            "Yearday".to_owned(),
            r"(?P<j>36[0-6]|3[0-5]\d|[12]\d\d|0[1-9]\d|00[1-9])".to_owned(),
        ),
        "m" => ("Month".to_owned(), r"(?P<m>0?[1-9]|1[0-2])".to_owned()),
        "M" => ("Minute".to_owned(), r"(?P<M>[0-5]?\d)".to_owned()),
        "p" => ("AMPM".to_owned(), r"(?P<p>am|pm)".to_owned()),
        "S" => ("Second".to_owned(), r"(?P<S>[0-5]?\d|6[0-1])".to_owned()),
        "U" => ("Yearweek".to_owned(), r"(?P<U>5[0-3]|[0-4]\d|\d)".to_owned()),
        "W" => ("Yearweek".to_owned(), r"(?P<W>5[0-3]|[0-4]\d|\d)".to_owned()),
        "w" => ("Weekday".to_owned(), r"(?P<w>[0-6])".to_owned()),
        "y" => ("Year2".to_owned(), r"(?P<y>\d\d)".to_owned()),
        "Y" => ("Year".to_owned(), r"(?P<Y>\d{4})".to_owned()),
        "f" => ("Microseconds".to_owned(), r"(?P<f>[0-9]{1,6})".to_owned()),
        "Z" => ("Zone name".to_owned(), r"(?P<Z>Z|[A-Z]{3,5})".to_owned()),
        "z" => (
            "Zone offset".to_owned(),
            r"(?P<z>Z|UTC|GMT|[+-][01]\d(?::?\d{2})?)".to_owned(),
        ),
        "Exd" => ("ExDay".to_owned(), r"(?P<d>[1-2]\d|0[1-9]|3[0-1])".to_owned()),
        "Exm" => ("ExMonth".to_owned(), r"(?P<m>0[1-9]|1[0-2])".to_owned()),
        "ExH" => ("Ex24hour".to_owned(), r"(?P<H>[0-1]\d|2[0-3])".to_owned()),
        "Exk" => ("%Exk".to_owned(), r" ?(?P<H>[0-1]?\d|2[0-3])".to_owned()),
        "Exl" => ("%Exl".to_owned(), r" ?(?P<I>1[0-2]|\d)".to_owned()),
        "ExM" => ("ExMinute".to_owned(), r"(?P<M>[0-5]\d)".to_owned()),
        "ExS" => ("ExSecond".to_owned(), r"(?P<S>[0-5]\d|6[0-1])".to_owned()),
        "Exy" => ("ExYear2".to_owned(), r"(?P<y>\d{2})".to_owned()),
        "ExY" => {
            let base_year = Local::now().year();
            let alt_year = ALTERNATE_YEAR.load(Ordering::Relaxed);
            ("ExYear".to_owned(), build_ex_year_regex(base_year, alt_year))
        }
        "ExZ" => ("ExZone name".to_owned(), format!(r"(?P<Z>{TZ_ABBR_RE})")),
        "Exz" => (
            "ExZone offset".to_owned(),
            format!(r"(?P<z>(?:{TZ_ABBR_RE})?[+-][01]\d(?::?\d{{2}})?|{TZ_ABBR_RE})"),
        ),
        "c" => return expand_date_pattern("%a %b %d %H:%M:%S %Y"),
        "x" => return expand_date_pattern("%m/%d/%y"),
        "X" => return expand_date_pattern("%H:%M:%S"),
        _ => {
            return Err(Error::date(format!("unsupported date directive %{key}")));
        }
    };
    Ok((disp, rx))
}

/// Convert captured `strptime` named groups to a Unix timestamp (`f64`).
///
/// Mirrors `strptime.reGroupDictStrptime` including century (`y <= 2000 -> +2000`),
/// weekday/julian calculation, `default_tz` fallback, midnight rollover, and
/// year-boundary rollover.
pub fn re_group_dict_strptime(
    found: &BTreeMap<String, String>,
    msec: bool,
    default_tz: Option<i32>,
) -> Result<f64> {
    re_group_dict_strptime_at(found, msec, default_tz, Local::now().fixed_offset())
}

/// Deterministic variant of [`re_group_dict_strptime`] parameterized by reference `now`
/// (carrying both local wall clock and UTC offset).
pub(crate) fn re_group_dict_strptime_at(
    found: &BTreeMap<String, String>,
    msec: bool,
    default_tz: Option<i32>,
    now: DateTime<FixedOffset>,
) -> Result<f64> {
    let mut year: Option<i32> = None;
    let mut month: Option<u32> = None;
    let mut day: Option<u32> = None;
    let mut hour: u32 = 0;
    let mut minute: u32 = 0;
    let mut second: u32 = 0;
    let mut fraction: u32 = 0;
    let mut weekday: Option<i32> = None;
    let mut julian: Option<i32> = None;
    let mut week_of_year: Option<i32> = None;
    let mut week_starts_mon = false;
    let mut tzoffset: Option<i32> = None;

    for (key, val) in found {
        match key.as_str() {
            "y" => {
                let mut y: i32 = val
                    .trim()
                    .parse()
                    .map_err(|_| Error::date(format!("invalid year {val:?}")))?;
                if y <= 2000 {
                    y += 2000;
                }
                year = Some(y);
            }
            "Y" => {
                year = Some(
                    val.trim()
                        .parse()
                        .map_err(|_| Error::date(format!("invalid year {val:?}")))?,
                );
            }
            "m" => {
                month = Some(
                    val.trim()
                        .parse()
                        .map_err(|_| Error::date(format!("invalid month {val:?}")))?,
                );
            }
            "B" => {
                month = Some(
                    parse_full_month(val)
                        .ok_or_else(|| Error::date(format!("invalid month name {val:?}")))?,
                );
            }
            "b" => {
                month =
                    Some(parse_abbr_month(val).ok_or_else(|| {
                        Error::date(format!("invalid month abbreviation {val:?}"))
                    })?);
            }
            "d" => {
                day = Some(
                    val.trim()
                        .parse()
                        .map_err(|_| Error::date(format!("invalid day {val:?}")))?,
                );
            }
            "H" => {
                hour = val
                    .trim()
                    .parse()
                    .map_err(|_| Error::date(format!("invalid hour {val:?}")))?;
            }
            "I" => {
                let mut h: u32 = val
                    .trim()
                    .parse()
                    .map_err(|_| Error::date(format!("invalid 12h hour {val:?}")))?;
                let ampm = found.get("p").map(|s| s.trim().to_ascii_lowercase());
                match ampm.as_deref() {
                    None | Some("" | "am") => {
                        if h == 12 {
                            h = 0;
                        }
                    }
                    Some("pm") => {
                        if h != 12 {
                            h += 12;
                        }
                    }
                    Some(_) => {}
                }
                hour = h;
            }
            "M" => {
                minute = val
                    .trim()
                    .parse()
                    .map_err(|_| Error::date(format!("invalid minute {val:?}")))?;
            }
            "S" => {
                second = val
                    .trim()
                    .parse()
                    .map_err(|_| Error::date(format!("invalid second {val:?}")))?;
            }
            "f" => {
                if msec {
                    let mut s = val.trim().to_owned();
                    while s.len() < 6 {
                        s.push('0');
                    }
                    fraction = s[..6]
                        .parse()
                        .map_err(|_| Error::date(format!("invalid microsecond {val:?}")))?;
                }
            }
            "A" => {
                weekday = Some(
                    parse_full_weekday(val)
                        .ok_or_else(|| Error::date(format!("invalid weekday name {val:?}")))?,
                );
            }
            "a" => {
                weekday =
                    Some(parse_abbr_weekday(val).ok_or_else(|| {
                        Error::date(format!("invalid weekday abbreviation {val:?}"))
                    })?);
            }
            "w" => {
                let mut w: i32 = val
                    .trim()
                    .parse()
                    .map_err(|_| Error::date(format!("invalid weekday {val:?}")))?;
                w -= 1;
                if w < 0 {
                    w = 6;
                }
                weekday = Some(w);
            }
            "j" => {
                julian = Some(
                    val.trim()
                        .parse()
                        .map_err(|_| Error::date(format!("invalid julian day {val:?}")))?,
                );
            }
            "U" | "W" => {
                week_of_year = Some(
                    val.trim()
                        .parse()
                        .map_err(|_| Error::date(format!("invalid week {val:?}")))?,
                );
                week_starts_mon = key == "W";
            }
            "z" | "Z" => {
                if matches!(val.as_str(), "Z" | "UTC" | "GMT") {
                    tzoffset = Some(0);
                } else {
                    tzoffset = validate_timezone(Some(val))?;
                }
            }
            _ => {}
        }
    }

    if tzoffset.is_none() {
        tzoffset = default_tz;
    }

    // Align missing year/month/day and rollover comparisons to the log's own timezone
    // (or local wall time when no timezone is specified), avoiding +-24h drift when host
    // timezone differs from log timezone.
    let now_utc = now.naive_utc();
    let ref_now = match tzoffset {
        Some(off) => now_utc + TimeDelta::seconds(i64::from(off) * 60),
        None => now.naive_local(),
    };

    let mut assume_year = false;
    let year_val = match year {
        Some(y) => y,
        None => {
            assume_year = true;
            ref_now.year()
        }
    };
    let mut final_year = year_val;

    if (month.is_none() || day.is_none())
        && julian.is_none()
        && let (Some(woy), Some(wd)) = (week_of_year, weekday)
    {
        julian = Some(calc_julian_from_u_or_w(year_val, woy, wd, week_starts_mon)?);
    }
    if (month.is_none() || day.is_none())
        && let Some(j) = julian
    {
        let jan1 = NaiveDate::from_ymd_opt(year_val, 1, 1)
            .ok_or_else(|| Error::date("invalid year for julian day"))?;
        let d = jan1 + TimeDelta::days(i64::from(j - 1));
        final_year = d.year();
        month = Some(d.month());
        day = Some(d.day());
    }

    let mut assume_today = false;
    if month.is_none() && day.is_none() {
        assume_today = true;
        month = Some(ref_now.month());
        day = Some(ref_now.day());
    }

    let final_month = month.ok_or_else(|| Error::date("missing month in date"))?;
    let final_day = day.ok_or_else(|| Error::date("missing day in date"))?;

    let naive_date = match NaiveDate::from_ymd_opt(final_year, final_month, final_day) {
        Some(d) => d,
        None if assume_year && final_month == 2 && final_day == 29 => {
            final_year -= 1;
            NaiveDate::from_ymd_opt(final_year, 2, 29).ok_or_else(|| {
                Error::date(format!(
                    "invalid date {}-{}-{}",
                    final_year + 1,
                    final_month,
                    final_day
                ))
            })?
        }
        None => {
            return Err(Error::date(format!(
                "invalid date {final_year}-{final_month}-{final_day}"
            )));
        }
    };
    let naive_time = NaiveTime::from_hms_micro_opt(hour, minute, second, fraction)
        .ok_or_else(|| Error::date(format!("invalid time {hour}:{minute}:{second}.{fraction}")))?;
    let mut dt_wall = NaiveDateTime::new(naive_date, naive_time);

    if assume_today && dt_wall > ref_now {
        dt_wall -= TimeDelta::days(1);
    }
    if assume_year && dt_wall > ref_now + TimeDelta::days(1) {
        let prev_date = NaiveDate::from_ymd_opt(final_year - 1, final_month, final_day)
            .ok_or_else(|| {
                Error::date(format!(
                    "invalid rollover date {}-{}-{}",
                    final_year - 1,
                    final_month,
                    final_day
                ))
            })?;
        dt_wall = NaiveDateTime::new(prev_date, naive_time);
    }

    let mut secs = if let Some(off) = tzoffset {
        let dt_utc = dt_wall - TimeDelta::seconds(i64::from(off) * 60);
        dt_utc.and_utc().timestamp() as f64
    } else {
        Local
            .from_local_datetime(&dt_wall)
            .earliest()
            .or_else(|| Local.from_local_datetime(&dt_wall).latest())
            .map_or_else(
                || dt_wall.and_utc().timestamp(),
                |local_dt| local_dt.timestamp(),
            ) as f64
    };
    if msec {
        secs += f64::from(fraction) / 1_000_000.0;
    }
    Ok(secs)
}

fn calc_julian_from_u_or_w(
    year: i32,
    week_of_year: i32,
    mut weekday: i32,
    week_starts_mon: bool,
) -> Result<i32> {
    let jan1 = NaiveDate::from_ymd_opt(year, 1, 1)
        .ok_or_else(|| Error::date(format!("invalid year {year}")))?;
    let mut first_weekday = jan1.weekday().num_days_from_monday() as i32;
    if !week_starts_mon {
        first_weekday = (first_weekday + 1) % 7;
        weekday = (weekday + 1) % 7;
    }
    let week_0_length = (7 - first_weekday) % 7;
    if week_of_year == 0 {
        Ok(1 + weekday - first_weekday)
    } else {
        let days_to_week = week_0_length + (7 * (week_of_year - 1));
        Ok(1 + days_to_week + weekday)
    }
}

fn parse_abbr_month(s: &str) -> Option<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn parse_full_month(s: &str) -> Option<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "january" => Some(1),
        "february" => Some(2),
        "march" => Some(3),
        "april" => Some(4),
        "may" => Some(5),
        "june" => Some(6),
        "july" => Some(7),
        "august" => Some(8),
        "september" => Some(9),
        "october" => Some(10),
        "november" => Some(11),
        "december" => Some(12),
        _ => None,
    }
}

fn parse_abbr_weekday(s: &str) -> Option<i32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "mon" => Some(0),
        "tue" => Some(1),
        "wed" => Some(2),
        "thu" => Some(3),
        "fri" => Some(4),
        "sat" => Some(5),
        "sun" => Some(6),
        _ => None,
    }
}

fn parse_full_weekday(s: &str) -> Option<i32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "monday" => Some(0),
        "tuesday" => Some(1),
        "wednesday" => Some(2),
        "thursday" => Some(3),
        "friday" => Some(4),
        "saturday" => Some(5),
        "sunday" => Some(6),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn validates_timezones_and_abbr_table() {
        assert_eq!(validate_timezone(None).unwrap(), None);
        assert_eq!(validate_timezone(Some("")).unwrap(), Some(0));
        assert_eq!(validate_timezone(Some("Z")).unwrap(), Some(0));
        assert_eq!(validate_timezone(Some("UTC")).unwrap(), Some(0));
        assert_eq!(validate_timezone(Some("UTC+0200")).unwrap(), Some(120));
        assert_eq!(validate_timezone(Some("UTC-04:00")).unwrap(), Some(-240));
        assert_eq!(validate_timezone(Some("CET+0100")).unwrap(), Some(120));
        assert_eq!(validate_timezone(Some("PST")).unwrap(), Some(-480));
        assert_eq!(validate_timezone(Some("NPT")).unwrap(), Some(345));
        assert_eq!(validate_timezone(Some("ChST")).unwrap(), Some(600));
        assert!(validate_timezone(Some("not-a-time-zone")).is_err());
        assert!(validate_timezone(Some("XYZ")).is_err());
    }

    #[test]
    fn expands_directives_and_century_regex() {
        let (name, rx) = expand_date_pattern("%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(name, "Year-Month-Day 24hour:Minute:Second");
        assert!(rx.contains("(?P<Y>\\d{4})"));
        assert!(rx.contains("(?P<S>[0-5]?\\d|6[0-1])"));

        assert_eq!(build_ex_year_regex(2026, 2001), "(?P<Y>20[012]\\d)");
        assert_eq!(
            build_ex_year_regex(2026, 1970),
            "(?P<Y>(?:19[6789]|20[012])\\d)"
        );
        assert!(expand_date_pattern("%Q").is_err());
    }

    #[test]
    fn handles_midnight_and_year_rollover_plus_default_tz() {
        let utc = FixedOffset::east_opt(0).unwrap();
        let now = utc
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(2026, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 5, 0)
                    .unwrap(),
            )
            .unwrap();

        // Time-only pattern after current clock rolls back to Dec 31, 2025.
        let mut f = BTreeMap::new();
        f.insert("H".into(), "23".into());
        f.insert("M".into(), "55".into());
        f.insert("S".into(), "10".into());
        let ts = re_group_dict_strptime_at(&f, false, Some(0), now).unwrap();
        let expected = NaiveDate::from_ymd_opt(2025, 12, 31)
            .unwrap()
            .and_hms_opt(23, 55, 10)
            .unwrap()
            .and_utc()
            .timestamp() as f64;
        assert_eq!(ts, expected);

        // Month/day without year rolls back to previous year when > now + 1 day.
        let mut f2 = BTreeMap::new();
        f2.insert("b".into(), "Dec".into());
        f2.insert("d".into(), "31".into());
        f2.insert("H".into(), "23".into());
        f2.insert("M".into(), "59".into());
        f2.insert("S".into(), "00".into());
        let ts2 = re_group_dict_strptime_at(&f2, false, Some(0), now).unwrap();
        let expected2 = NaiveDate::from_ymd_opt(2025, 12, 31)
            .unwrap()
            .and_hms_opt(23, 59, 0)
            .unwrap()
            .and_utc()
            .timestamp() as f64;
        assert_eq!(ts2, expected2);

        // Two-digit year <= 2000 gets +2000; 12h AM/PM works.
        let mut f3 = BTreeMap::new();
        f3.insert("b".into(), "Apr".into());
        f3.insert("d".into(), "27".into());
        f3.insert("y".into(), "13".into());
        f3.insert("I".into(), "02".into());
        f3.insert("M".into(), "33".into());
        f3.insert("S".into(), "06".into());
        f3.insert("p".into(), "PM".into());
        f3.insert("z".into(), "+0200".into());
        let ts3 = re_group_dict_strptime_at(&f3, false, None, now).unwrap();
        let expected3 = NaiveDate::from_ymd_opt(2013, 4, 27)
            .unwrap()
            .and_hms_opt(12, 33, 6)
            .unwrap()
            .and_utc()
            .timestamp() as f64;
        assert_eq!(ts3, expected3);

        // Cross-timezone rollover (B3): UTC-5 host at 10:00 local (15:00 UTC) reading UTC log 14:59:55.
        let now_minus5 = FixedOffset::west_opt(5 * 3600)
            .unwrap()
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(2026, 5, 14)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
            )
            .unwrap();
        let mut f_utc_time = BTreeMap::new();
        f_utc_time.insert("H".into(), "14".into());
        f_utc_time.insert("M".into(), "59".into());
        f_utc_time.insert("S".into(), "55".into());
        let ts_minus5 = re_group_dict_strptime_at(&f_utc_time, false, Some(0), now_minus5).unwrap();
        assert_eq!(
            ts_minus5,
            NaiveDate::from_ymd_opt(2026, 5, 14)
                .unwrap()
                .and_hms_opt(14, 59, 55)
                .unwrap()
                .and_utc()
                .timestamp() as f64
        );

        // Cross-timezone rollover (B3): UTC+8 host at 01:00 local on May 15 (17:00 UTC May 14) reading UTC 16:59:55.
        let now_plus8 = FixedOffset::east_opt(8 * 3600)
            .unwrap()
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(2026, 5, 15)
                    .unwrap()
                    .and_hms_opt(1, 0, 0)
                    .unwrap(),
            )
            .unwrap();
        let mut f_utc_time2 = BTreeMap::new();
        f_utc_time2.insert("H".into(), "16".into());
        f_utc_time2.insert("M".into(), "59".into());
        f_utc_time2.insert("S".into(), "55".into());
        let ts_plus8 = re_group_dict_strptime_at(&f_utc_time2, false, Some(0), now_plus8).unwrap();
        assert_eq!(
            ts_plus8,
            NaiveDate::from_ymd_opt(2026, 5, 14)
                .unwrap()
                .and_hms_opt(16, 59, 55)
                .unwrap()
                .and_utc()
                .timestamp() as f64
        );

        // Leap-day year rollover (B3): non-leap year 2025 parsing Feb 29 rolls back to 2024-02-29.
        let now_2025 = utc
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(2025, 1, 2)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap(),
            )
            .unwrap();
        let mut f_leap = BTreeMap::new();
        f_leap.insert("b".into(), "Feb".into());
        f_leap.insert("d".into(), "29".into());
        f_leap.insert("H".into(), "23".into());
        f_leap.insert("M".into(), "59".into());
        f_leap.insert("S".into(), "59".into());
        let ts_leap = re_group_dict_strptime_at(&f_leap, false, Some(0), now_2025).unwrap();
        assert_eq!(
            ts_leap,
            NaiveDate::from_ymd_opt(2024, 2, 29)
                .unwrap()
                .and_hms_opt(23, 59, 59)
                .unwrap()
                .and_utc()
                .timestamp() as f64
        );
    }
}
