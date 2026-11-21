//! Select one original Fail2Ban 1.1.1 jail for offline nginx log replay.
//!
//! This is an admission subset, not the original daemon's JailReader. It
//! reads original configuration layers, never opens configured log paths,
//! performs no host discovery, and has no action or command execution path.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::detect::{ignore::IgnoreList, legacy_matcher::LegacyMatcher};
use crate::error::{Error, Result};

use super::{legacy_filter, legacy_filter_spec, legacy_interp, legacy_layers};

#[derive(Debug)]
pub(crate) struct JailPlan {
    pub(crate) name: String,
    pub(crate) max_retry: u64,
    pub(crate) find_time: u64,
    /// -1 is the original permanent duration.
    pub(crate) ban_time_seconds: i64,
    /// Literal path metadata only; the caller supplies offline log records.
    pub(crate) log_paths: Vec<PathBuf>,
    pub(crate) matcher: LegacyMatcher,
    ignore: IgnoreList,
}

impl JailPlan {
    pub(crate) fn ignores(&self, ip: IpAddr) -> bool {
        self.ignore.is_ignored(&ip.to_canonical())
    }
}

const FILTER: &str = "nginx-http-auth";

pub(super) const SUPPORTED_JAIL_KEYS: &[&str] = &[
    "enabled",
    "filter",
    "mode",
    "backend",
    "usedns",
    "ignoreself",
    "ignoreip",
    "ignorecommand",
    "ignorecache",
    "maxretry",
    "findtime",
    "bantime",
    "logpath",
    "action",
    "bantime.increment",
    "skip_if_nologs",
    "systemd_if_nologs",
    "logtimezone",
    "logencoding",
    "maxmatches",
    "port",
    "protocol",
];

pub(super) const UNSUPPORTED_MATCH_OPTIONS: &[&str] = &[
    "failregex",
    "ignoreregex",
    "prefregex",
    "maxlines",
    "datepattern",
    "journalmatch",
];

pub(super) const UNSUPPORTED_BANTIME_OPTIONS: &[&str] = &[
    "bantime.factor",
    "bantime.formula",
    "bantime.multipliers",
    "bantime.maxtime",
    "bantime.rndtime",
    "bantime.overalljails",
];

/// Load and admit the named jail from a caller-selected original config base.
/// This never applies cleanup, opens logs, or initializes an action backend.
pub(crate) fn read(base: &Path, jail: &str) -> Result<JailPlan> {
    if jail == "DEFAULT" || jail == "INCLUDES" || jail.is_empty() || jail.starts_with("KNOWN/") {
        return Err(Error::config("expected a named original replay jail"));
    }

    let config = legacy_layers::read(base, "jail")?
        .ok_or_else(|| Error::config("original jail configuration not found"))?;
    let selected = config
        .sections
        .get(jail)
        .ok_or_else(|| Error::config(format!("unknown original replay jail {jail:?}")))?;

    let raw = |key: &str| selected.get(key).or_else(|| config.defaults.get(key));
    let get = |key: &str| {
        legacy_interp::get_effective(
            jail,
            key,
            &config.defaults,
            |name| config.sections.get(name),
            None,
        )
        .map_err(|err| Error::config(format!("jail {jail:?} option {key}: {err}")))
    };
    let required = |key: &str| -> Result<String> {
        get(key)?.ok_or_else(|| Error::config(format!("jail {jail:?} requires {key}")))
    };
    let matching_override = |key: &str| {
        if raw(key).is_some() {
            Err(Error::config(format!(
                "unsupported original replay option {key}"
            )))
        } else {
            Ok(())
        }
    };
    let reject_active = |key: &str| {
        if raw(key).is_some_and(|value| !value.is_empty()) {
            Err(Error::config(format!(
                "unsupported original replay option {key}"
            )))
        } else {
            Ok(())
        }
    };

    let enabled = get("enabled")?.is_some_and(|s| original_bool(&s) == Some(true));
    if !enabled {
        return Err(Error::config(format!(
            "original replay jail {jail:?} is not enabled"
        )));
    }
    if required("backend")? != "polling" {
        return Err(Error::config(
            "original nginx file replay requires backend=polling",
        ));
    }
    if required("usedns")? != "no" {
        return Err(Error::config(
            "original nginx file replay requires usedns=no",
        ));
    }
    if original_bool(&required("ignoreself")?) != Some(false) {
        return Err(Error::config(
            "original nginx file replay requires ignoreself=false",
        ));
    }

    // Do not resolve or read command/action templates. Require an explicit
    // empty effective action if the ordinary upstream default is nonempty.
    for key in ["action", "ignorecommand", "ignorecache"]
        .into_iter()
        .chain(UNSUPPORTED_BANTIME_OPTIONS.iter().copied())
    {
        reject_active(key)?;
    }
    for key in UNSUPPORTED_MATCH_OPTIONS {
        matching_override(key)?;
    }
    if let Some(key) = selected
        .keys()
        .find(|key| !SUPPORTED_JAIL_KEYS.contains(&key.as_str()))
    {
        return Err(Error::config(format!(
            "unsupported original replay jail option {key}"
        )));
    }
    if get("bantime.increment")?.is_some_and(|s| original_bool(&s) != Some(false)) {
        return Err(Error::config(
            "original nginx file replay does not support incremental bans",
        ));
    }
    if get("skip_if_nologs")?.is_some_and(|s| original_bool(&s) != Some(false)) {
        return Err(Error::config(
            "original nginx file replay does not evaluate skip_if_nologs",
        ));
    }
    if get("logtimezone")?.is_some_and(|s| !matches!(s.as_str(), "" | "UTC")) {
        return Err(Error::config(
            "original nginx file replay uses UTC timestamps only",
        ));
    }
    if get("logencoding")?.is_some_and(|s| !matches!(s.as_str(), "auto" | "utf-8" | "UTF-8")) {
        return Err(Error::config(
            "original nginx file replay accepts UTF-8 input text only",
        ));
    }
    // systemd_if_nologs affects auto only. maxmatches and port/protocol
    // have no role in this decision-only replay without evidence or actions.

    let expression = required("filter")?;
    let spec = legacy_filter_spec::parse(&expression)?;
    if spec.name != FILTER {
        return Err(Error::config(
            "original jail replay supports only the nginx-http-auth filter",
        ));
    }
    for (key, value) in &spec.parameters {
        let supported = match key.as_str() {
            "mode" => matches!(
                value.as_str(),
                "normal" | "auth" | "aggressive" | "fallback"
            ),
            "logtype" => value == "file",
            _ => false,
        };
        if !supported {
            return Err(Error::config(format!(
                "unsupported original nginx filter parameter {key}={value:?}"
            )));
        }
    }

    let max_retry = required("maxretry")?
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::config("original replay maxretry must be a positive integer"))?;
    let find_time = u64::try_from(duration(&required("findtime")?, "findtime")?)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::config("original replay findtime must be positive"))?;
    let ban_time_seconds = duration(&required("bantime")?, "bantime")?;
    if ban_time_seconds < -1 {
        return Err(Error::config(
            "original replay bantime must be nonnegative or -1",
        ));
    }
    let log_paths = log_paths(&required("logpath")?)?;
    let ignore = ignore_list(&get("ignoreip")?.unwrap_or_default())?;

    let filter_config = legacy_filter::read(base, FILTER)?
        .ok_or_else(|| Error::config("original nginx-http-auth filter configuration not found"))?;
    if !spec.parameters.contains_key("logtype")
        && filter_config
            .sections
            .get("Definition")
            .is_some_and(|definition| definition.contains_key("logtype"))
        && legacy_interp::get_effective(
            "Definition",
            "logtype",
            &filter_config.defaults,
            |name| filter_config.sections.get(name),
            None,
        )
        .map_err(|err| Error::config(format!("original nginx filter logtype: {err}")))?
        .is_some_and(|value| value != "file")
    {
        return Err(Error::config(
            "original nginx replay requires filter logtype=file",
        ));
    }
    let mut jail_vars = BTreeMap::from([
        ("filter".to_owned(), expression.clone()),
        ("enabled".to_owned(), "True".to_owned()),
    ]);
    for key in [
        "backend",
        "usedns",
        "maxretry",
        "maxmatches",
        "findtime",
        "bantime",
        "logpath",
        "ignoreip",
        "logtimezone",
        "logencoding",
    ] {
        if let Some(value) = get(key)? {
            jail_vars.insert(key.to_owned(), value);
        }
    }
    let mut filter = legacy_filter::resolve(
        &filter_config,
        &legacy_filter::Parameters {
            backend: "polling",
            jail: &jail_vars,
            call: &spec.parameters,
            all: false,
        },
    )?;
    // Upstream appends the jail's FilterReader options after filter commands.
    // Override usedns here with its explicitly admitted jail setting.
    filter.options.insert("usedns".to_owned(), "no".to_owned());
    let matcher = LegacyMatcher::compile(&filter)?;
    Ok(JailPlan {
        name: jail.to_owned(),
        max_retry,
        find_time,
        ban_time_seconds,
        log_paths,
        matcher,
        ignore,
    })
}

pub(super) fn original_bool(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "1" | "on" | "true" | "yes" => Some(true),
        "0" | "off" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// One integral amount and an original unit. No Python expressions, eval,
/// fractions, compound strings, month/year averaging or rounding.
pub(super) fn duration(raw: &str, key: &str) -> Result<i64> {
    let bad = || {
        Error::config(format!(
            "unsupported original replay {key} duration {raw:?}"
        ))
    };
    let raw = raw.trim();
    if raw == "-1" {
        return Ok(-1);
    }
    let raw = raw.strip_prefix('+').unwrap_or(raw);
    let split = raw
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(raw.len());
    let (digits, suffix) = raw.split_at(split);
    if digits.starts_with('0') && digits.bytes().any(|b| b != b'0') {
        return Err(bad());
    }
    let amount: i64 = digits.parse().map_err(|_| bad())?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "s" | "ss" | "se" | "sec" | "second" | "seconds" => 1,
        "m" | "mm" | "mi" | "min" | "minute" | "minutes" => 60,
        "h" | "hh" | "ho" | "hou" | "hour" | "hours" => 3_600,
        "d" | "dd" | "da" | "day" | "days" => 86_400,
        "w" | "ww" | "we" | "wee" | "week" | "weeks" => 604_800,
        _ => return Err(bad()),
    };
    amount.checked_mul(multiplier).ok_or_else(bad)
}

pub(super) fn log_paths(raw: &str) -> Result<Vec<PathBuf>> {
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for path in raw.split('\n') {
        if path.is_empty()
            || !Path::new(path).is_absolute()
            || path.chars().any(|ch| {
                ch.is_whitespace() || ch.is_control() || matches!(ch, '*' | '?' | '[' | ']')
            })
            || !seen.insert(path)
        {
            return Err(Error::config(
                "original replay logpath requires unique absolute literal paths without flags or globs",
            ));
        }
        paths.push(PathBuf::from(path));
    }
    Ok(paths)
}

fn ignore_list(raw: &str) -> Result<IgnoreList> {
    let entries = raw
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<IpAddr>()
                .map_or_else(|_| part.to_owned(), |ip| ip.to_canonical().to_string())
        })
        .collect::<Vec<_>>();
    // false is mandatory: IgnoreList must never probe network interfaces here.
    IgnoreList::new(&entries, false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "legacy_jail_plan_test.rs"]
mod tests;
