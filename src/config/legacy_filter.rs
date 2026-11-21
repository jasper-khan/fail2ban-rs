//! Original Fail2Ban 1.1.1 FilterReader parameter and template resolution.
//!
//! The result is the config-stage projection of `getOptions` + `getCombined`,
//! before FilterReader.convert, filter runtime tag evaluation, or regex
//! compilation. It does not infer other modes or implement filter behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::error::{Error, Result};

use super::legacy_layers::{self, LayeredConfig};
use super::{legacy_interp, legacy_tags};

pub(super) type Options = BTreeMap<String, String>;

const FILTER_OPTIONS: &[&str] = &[
    "usedns",
    "prefregex",
    "ignoreregex",
    "failregex",
    "maxlines",
    "datepattern",
    "journalmatch",
];

pub(super) struct Parameters<'a> {
    /// Jail backend already selected by the caller; used to infer logtype.
    pub(super) backend: &'a str,
    /// Resolved string jail options sent into this original getOptions phase.
    pub(super) jail: &'a Options,
    /// Explicit bracket parameters with original key spellings.
    pub(super) call: &'a Options,
    /// Request the original all=True expansion (used for jail known options).
    pub(super) all: bool,
}

/// Public because compatibility [`JailConfig`](crate::config::JailConfig)s
/// carry it in an optional field; reading and compiling stay crate-internal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedFilter {
    /// Combined strings, except maxlines. Unknown angle tags are kept literal.
    pub(crate) options: Options,
    /// Integer conversion after all config substitutions. Like upstream, an
    /// absent or malformed integer is unset; outside i64 is also unset here.
    pub(crate) maxlines: Option<i64>,
    /// True when this filter resolved to stock Fail2Ban 1.1.1 `sshd` normal
    /// mode (file logtype, `publickey=nofail`, empty ignoreregex), routed
    /// through the parity-proven `LegacySshSessions` engine.
    pub(crate) ssh_normal: bool,
}

/// Load a FilterReader name, not an explicit file for fail2ban-regex.
pub(super) fn read(base: &Path, name: &str) -> Result<Option<LayeredConfig>> {
    if Path::new(name).is_absolute() || name.starts_with("./") {
        return legacy_layers::read(base, name);
    }
    legacy_layers::read(base, &format!("filter.d/{name}"))
}

/// Read a named original filter and compute effective options for offline replay.
/// Jail-derived options and the full daemon activation phase are not used here.
pub(crate) fn read_resolved(
    base: &Path,
    expression: &str,
    backend: &str,
) -> Result<Option<ResolvedFilter>> {
    let spec = super::legacy_filter_spec::parse(expression)?;
    let Some(config) = read(base, spec.name)? else {
        return Ok(None);
    };
    let params = Parameters {
        backend,
        jail: &Options::new(),
        call: &spec.parameters,
        all: false,
    };
    resolve(&config, &params).map(Some)
}

/// Run a single original FilterReader resolution phase with the supplied inputs.
pub(super) fn resolve(config: &LayeredConfig, params: &Parameters<'_>) -> Result<ResolvedFilter> {
    let mut init = params.call.clone();
    // FilterReader.applyAutoOptions considers explicit init args and
    // Definition's own value (not DEFAULT/Init), before the getOptions pass.
    if init.get("logtype").is_none_or(String::is_empty)
        && config
            .sections
            .get("Definition")
            .is_none_or(|opts| !opts.contains_key("logtype"))
    {
        let logtype = if params.backend.starts_with("systemd") {
            "journal"
        } else {
            "file"
        };
        init.insert("logtype".to_owned(), logtype.to_owned());
    }

    // The percent stage freezes these pre-selections. [Init]'s own defaults
    // are collected later, and do not flow back into these variables.
    let mut preselected = params.jail.clone();
    preselected.extend(init.clone());
    let mut options = Options::new();
    for &key in FILTER_OPTIONS {
        if !preselected.contains_key(key)
            && let Some(value) = get(config, "Definition", key, Some(&preselected))?
        {
            options.insert(key.to_owned(), value);
        }
    }

    if let Some(section) = config.sections.get("Init") {
        for key in section.keys().filter(|key| key.as_str() != "__name__") {
            let mut value = None;
            if !key.starts_with("known/") {
                value = get(config, "Init", key, None)?;
                if let Some(original) = value.as_ref() {
                    init.insert(format!("known/{key}"), original.clone());
                }
            }
            if !init.contains_key(key) {
                if let Some((base, _)) = conditional_option(key) {
                    value = preselected.get(base).cloned().or(value);
                }
                if value.is_none() {
                    value = get(config, "Init", key, None)?;
                }
                if let Some(value) = value {
                    init.insert(key.clone(), value);
                }
            }
        }
    }
    if params.all
        && let Some(definition) = config.sections.get("Definition")
    {
        // In 1.1.1 ConfigReader.options defaults to withDefault=False despite
        // the comment in getOptions. This pass fills only explicit Definition
        // keys and does not pass vars to ConfigParser.get.
        for key in definition.keys() {
            if key != "__name__"
                && !options.contains_key(key)
                && let Some(value) = get(config, "Definition", key, None)?
            {
                options.insert(key.clone(), value);
            }
        }
    }

    options.extend(init);
    let ignored: BTreeSet<&str> = options
        .keys()
        .filter_map(|key| conditional_option(key).map(|(base, _)| base))
        .collect();
    let mut angle_fallbacks = BTreeMap::new();
    let mut final_options = Options::new();
    for (key, raw) in &options {
        if ignored.contains(key.as_str()) {
            final_options.insert(key.clone(), raw.clone());
            continue;
        }
        let mut interpolation_error = None;
        let expanded = legacy_tags::expand(raw, |tag| {
            if interpolation_error.is_some() || ignored.contains(tag) {
                return None;
            }
            if let Some(value) = options.get(tag) {
                return Some(value.clone());
            }
            if let Some(value) = angle_fallbacks.get(tag) {
                return Option::<String>::clone(value);
            }
            let value = legacy_interp::get_extended(
                "Definition",
                tag,
                &config.defaults,
                |name| config.sections.get(name),
                Some(&preselected),
            );
            match value {
                Ok(value) => {
                    angle_fallbacks.insert(tag.to_owned(), value.clone());
                    value
                }
                Err(err) => {
                    interpolation_error = Some(err);
                    None
                }
            }
        });
        if let Some(err) = interpolation_error {
            return Err(Error::config(err.to_string()));
        }
        let value = expanded.map_err(|err| Error::config(format!("filter option {key}: {err}")))?;
        final_options.insert(key.clone(), value);
    }

    let maxlines = final_options
        .remove("maxlines")
        .and_then(|value| parse_maxlines(&value));
    Ok(ResolvedFilter {
        options: final_options,
        maxlines,
        ssh_normal: false,
    })
}

fn get(
    config: &LayeredConfig,
    section: &str,
    key: &str,
    vars: Option<&Options>,
) -> Result<Option<String>> {
    legacy_interp::get_effective(
        section,
        key,
        &config.defaults,
        |name| config.sections.get(name),
        vars,
    )
    .map_err(|err| Error::config(err.to_string()))
}

fn conditional_option(key: &str) -> Option<(&str, &str)> {
    key.split_once('?').filter(|(base, condition)| {
        !base.is_empty()
            && !condition.is_empty()
            && base.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
    })
}

/// Python's int() permits a sign and separators between decimal digits.
/// An i64 is sufficient for the matched-lines option; never saturate.
fn parse_maxlines(value: &str) -> Option<i64> {
    let value = value.trim();
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if !digits
        .split('_')
        .all(|part| !part.is_empty() && part.bytes().all(|ch| ch.is_ascii_digit()))
    {
        return None;
    }
    value.replace('_', "").parse().ok()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
#[path = "legacy_filter_test.rs"]
mod tests;
