//! Load an original Fail2Ban 1.1.1 configuration tree into a daemon `Config`.
//!
//! Stage-one admission subset of the original INI surface, mirroring the
//! offline replay rules: polling backend, `usedns = no`, no incremental ban
//! timing, no per-jail action commands (the decision-recording backend
//! replaces the firewall), and supported single-line file-log filters.
//! Journal-only match metadata does not affect polling; the journal backend
//! itself is not supported. The live state belongs to the recording run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::types::{
    Backend, Config, GlobalConfig, JailConfig, LogBackend, LogEncoding, LoggingConfig,
};
use crate::detect::date::DateFormat;
use crate::error::{Error, Result};

use super::legacy_filter;
use super::legacy_filter_spec;
use super::legacy_interp;
use super::legacy_jail_plan::{
    SUPPORTED_JAIL_KEYS, UNSUPPORTED_BANTIME_OPTIONS, UNSUPPORTED_MATCH_OPTIONS, duration,
    log_paths, original_bool,
};
use super::legacy_layers;

/// The original database is a read-only source for compatibility restore.
const ORIGINAL_DBFILE: &str = "/var/lib/fail2ban/fail2ban.sqlite3";
/// Original builtin timing defaults when neither the section nor [DEFAULT]
/// sets them (fail2ban's own jail defaults).
const ORIGINAL_MAXRETRY: &str = "5";
const ORIGINAL_FINDTIME: &str = "600";
const ORIGINAL_BANTIME: &str = "600";

/// Load the original tree under `base` with a decision-recording action
/// backend writing to `record`.
///
/// Every enabled admitted jail runs on the normal daemon pipeline: existing
/// watchers, failure counting, and the WAL-backed ban store.
pub(crate) fn load(base: &Path, record: &Path) -> Result<Config> {
    let record = safe_record_path(record)?;
    load_inner(base, Some(&record))
}

/// Load the original tree under `base`, resolving each enabled jail's
/// `action.d/<name>.conf` lifecycle commands (`actionstart/ban/unban/stop`).
pub(crate) fn load_with_actions(base: &Path) -> Result<Config> {
    load_inner(base, None)
}

fn load_inner(base: &Path, record: Option<&Path>) -> Result<Config> {
    if !base.is_dir() {
        return Err(Error::config(format!(
            "original configuration directory {} does not exist",
            base.display()
        )));
    }
    let global = if let Some(rec) = record {
        recording_global(rec)?
    } else {
        let dbfile = dbfile_of(base)?;
        recording_global(&dbfile)?
    };
    let tree = legacy_layers::read(base, "jail")?
        .ok_or_else(|| Error::config("original jail configuration not found"))?;
    let mut jails = HashMap::new();
    for section in &tree.section_order {
        if section.starts_with("KNOWN/") || section == "INCLUDES" {
            continue;
        }
        if let Some(jail) = load_jail(base, &tree, section, record)? {
            jails.insert(section.clone(), jail);
        }
    }
    let config = Config {
        global,
        logging: LoggingConfig::default(),
        jail: jails,
    };
    config.validate()?;
    Ok(config)
}

/// The record file is interpolated into shell commands, so only absolute
/// paths without shell metacharacters are accepted.
fn safe_record_path(record: &Path) -> Result<PathBuf> {
    let text = record.to_string_lossy();
    let ok = record.is_absolute()
        && record.file_name().is_some()
        && !text.ends_with('/')
        && !text.ends_with("/.")
        && !record
            .components()
            .any(|part| part == std::path::Component::ParentDir)
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'));
    if ok {
        Ok(record.to_path_buf())
    } else {
        Err(Error::config(format!(
            "decision record path {} must be absolute and contain only \
             alphanumeric characters, slashes, dots, underscores, or hyphens, \
             with a filename and no parent-directory traversal",
            record.display()
        )))
    }
}

/// One option from the layered fail2ban.conf `[Definition]` section.
fn definition_option(base: &Path, key: &str) -> Result<Option<String>> {
    let cfg = legacy_layers::read(base, "fail2ban")?;
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    legacy_interp::get_effective(
        "Definition",
        key,
        &cfg.defaults,
        |name| cfg.sections.get(name),
        None,
    )
    .map_err(|err| Error::config(format!("original fail2ban.conf option {key}: {err}")))
}

/// The original ban database of this tree, resolved exactly like the original
/// daemon: the layered `dbfile` option or the built-in default. This path
/// is independent of the recording daemon's WAL and is opened read-only.
pub fn dbfile_of(base: &Path) -> Result<PathBuf> {
    let dbfile = definition_option(base, "dbfile")?
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from(ORIGINAL_DBFILE), PathBuf::from);
    if !dbfile.is_absolute() {
        return Err(Error::config(format!(
            "original fail2ban.conf dbfile must be an absolute path: {}",
            dbfile.display()
        )));
    }
    Ok(dbfile)
}

/// Each recording gets a sibling runtime directory. Never derive the
/// listener or writable WAL from the original daemon's socket or database.
fn recording_global(record: &Path) -> Result<GlobalConfig> {
    let mut filename = record
        .file_name()
        .ok_or_else(|| Error::config("decision record path must have a filename"))?
        .to_os_string();
    filename.push(".fail2ban-rs");
    let runtime = record.with_file_name(filename);
    Ok(GlobalConfig {
        state_dir: runtime.join("state"),
        socket_path: runtime.join("control.sock"),
        ..GlobalConfig::default()
    })
}

/// Convert one original jail section; `None` when it is not enabled.
fn load_jail(
    base: &Path,
    tree: &legacy_layers::LayeredConfig,
    jail: &str,
    record: Option<&Path>,
) -> Result<Option<JailConfig>> {
    let selected = tree
        .sections
        .get(jail)
        .ok_or_else(|| Error::config(format!("original jail {jail:?} has no merged section")))?;
    let get = |key: &str| -> Result<Option<String>> {
        legacy_interp::get_effective(
            jail,
            key,
            &tree.defaults,
            |name| tree.sections.get(name),
            None,
        )
        .map_err(|err| Error::config(format!("original jail {jail:?} option {key}: {err}")))
    };
    let raw = |key: &str| selected.get(key).or_else(|| tree.defaults.get(key));
    let required = |key: &str| -> Result<String> {
        get(key)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::config(format!("original jail {jail:?} requires {key}")))
    };
    let reject_active = |key: &str| -> Result<()> {
        if raw(key).is_some_and(|value| !value.is_empty()) {
            Err(Error::config(format!(
                "unsupported original jail option {key}"
            )))
        } else {
            Ok(())
        }
    };
    let reject_override = |key: &str| -> Result<()> {
        if raw(key).is_some() {
            Err(Error::config(format!(
                "unsupported original jail option {key}"
            )))
        } else {
            Ok(())
        }
    };

    if get("enabled")?.as_deref().and_then(original_bool) != Some(true) {
        return Ok(None);
    }
    let backend_name = required("backend")?;
    let log_backend = match backend_name.as_str() {
        "polling" => LogBackend::File,
        "systemd" => LogBackend::Systemd,
        _ => {
            return Err(Error::config(
                "the original compat daemon currently requires backend=polling or backend=systemd",
            ));
        }
    };
    if required("usedns")? != "no" {
        return Err(Error::config(
            "the original compat daemon currently requires usedns=no",
        ));
    }
    if original_bool(&required("ignoreself")?) != Some(false) {
        return Err(Error::config(
            "the original compat daemon currently requires ignoreself=false",
        ));
    }
    if record.is_some() {
        reject_active("action")?;
    }
    for key in ["ignorecommand", "ignorecache"] {
        reject_active(key)?;
    }
    for key in UNSUPPORTED_BANTIME_OPTIONS {
        if !matches!(
            *key,
            "bantime.factor" | "bantime.multipliers" | "bantime.maxtime" | "journalmatch"
        ) {
            reject_active(key)?;
        }
    }
    for key in UNSUPPORTED_MATCH_OPTIONS {
        if *key != "journalmatch" {
            reject_override(key)?;
        }
    }
    let bantime_increment = get("bantime.increment")?
        .and_then(|v| original_bool(&v))
        .unwrap_or(false);
    let bantime_factor = get("bantime.factor")?
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            v.trim().parse::<f64>().map_err(|_| {
                Error::config(format!(
                    "original bantime.factor must be numeric, got {v:?}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(1.0);
    let bantime_multipliers = get("bantime.multipliers")?
        .map(|v| {
            v.split_whitespace()
                .map(|tok| {
                    tok.parse::<u32>().map_err(|_| {
                        Error::config(format!(
                            "original bantime.multipliers must be integers, got {tok:?}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let bantime_maxtime = get("bantime.maxtime")?
        .filter(|v| !v.trim().is_empty())
        .map(|v| duration(&v, "bantime.maxtime"))
        .transpose()?
        .unwrap_or(604_800);
    for key in ["skip_if_nologs", "systemd_if_nologs"] {
        if get(key)?.is_some_and(|value| original_bool(&value) != Some(false)) {
            return Err(Error::config(format!(
                "the original compat daemon does not yet support {key}"
            )));
        }
    }
    if let Some(value) = get("logtimezone")?
        && !matches!(value.as_str(), "" | "UTC")
    {
        return Err(Error::config(
            "the original compat daemon uses UTC timestamps only",
        ));
    }
    let log_encoding = match get("logencoding")?.as_deref() {
        None | Some("" | "auto" | "utf-8" | "UTF-8" | "utf8" | "UTF8" | "ascii" | "ASCII") => {
            LogEncoding::Utf8
        }
        Some("latin-1" | "latin1" | "LATIN-1" | "iso-8859-1" | "ISO-8859-1") => LogEncoding::Latin1,
        Some(other) => {
            return Err(Error::config(format!(
                "the original compat daemon does not support logencoding={other:?}"
            )));
        }
    };
    for key in selected.keys() {
        let base_name = key.split_once('?').map_or(key.as_str(), |(base, _)| base);
        let known = base_name.strip_prefix("known/");
        let admitted = SUPPORTED_JAIL_KEYS.contains(&base_name)
            || matches!(
                base_name,
                "bantime.factor" | "bantime.multipliers" | "bantime.maxtime" | "journalmatch"
            )
            || known.is_some_and(|rest| SUPPORTED_JAIL_KEYS.contains(&rest));
        if !admitted {
            return Err(Error::config(format!(
                "unsupported original jail option {key}"
            )));
        }
    }

    let paths = if log_backend == LogBackend::File {
        log_paths(&required("logpath")?)?
    } else {
        Vec::new()
    };
    let max_retry =
        parse_maxretry(&get("maxretry")?.unwrap_or_else(|| ORIGINAL_MAXRETRY.to_owned()))?;
    let find_time = duration(
        &get("findtime")?.unwrap_or_else(|| ORIGINAL_FINDTIME.to_owned()),
        "findtime",
    )?;
    if find_time <= 0 {
        return Err(Error::config("original jail findtime must be positive"));
    }
    let ban_time = duration(
        &get("bantime")?.unwrap_or_else(|| ORIGINAL_BANTIME.to_owned()),
        "bantime",
    )?;
    if ban_time < -1 {
        return Err(Error::config(
            "original jail bantime must be nonnegative or -1",
        ));
    }
    let port = parse_ports(jail, &get("port")?.unwrap_or_default())?;
    let protocol = get("protocol")?.unwrap_or_else(|| "tcp".to_owned());
    if !["tcp", "udp", "sctp", "dccp"].contains(&protocol.as_str()) {
        return Err(Error::config(format!(
            "original jail {jail:?} protocol {protocol:?} is not supported"
        )));
    }
    let expression = required("filter")?;
    let spec = legacy_filter_spec::parse(&expression)?;
    for (key, value) in &spec.parameters {
        let supported = match key.as_str() {
            "mode" => matches!(
                value.as_str(),
                "normal" | "auth" | "aggressive" | "fallback"
            ),
            "logtype" => value == "file",
            "publickey" => spec.name == "sshd" && value == "nofail",
            _ => false,
        };
        if !supported {
            return Err(Error::config(format!(
                "unsupported original filter parameter {key}={value:?}"
            )));
        }
    }
    let resolved = legacy_filter::read_resolved(base, &expression, &backend_name)?
        .ok_or_else(|| Error::config(format!("original filter {expression:?} not found")))?;
    let max_lines = match resolved.maxlines {
        None | Some(1) => 1_usize,
        Some(n) if (2..=100).contains(&n) => n as usize,
        Some(other) => {
            return Err(Error::config(format!(
                "original filter maxlines out of supported range (1..=100): {other}"
            )));
        }
    };
    let journalmatch = if log_backend == LogBackend::Systemd {
        get("journalmatch")?
            .or_else(|| resolved.options.get("journalmatch").cloned())
            .as_deref()
            .map(parse_journalmatch)
            .transpose()?
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    // Fail2Ban applies journalmatch only with the systemd backend; polling
    // ignores this metadata in stock filters such as nginx-http-auth.
    // Prefregex filters run through the original parity-proven engine, which
    // enforces its own subset (file logtype, single line, {^LN-BEG} dates)
    // at compile time with the original error messages. Pattern-list filters
    // without prefregex stay on the native engine, which has no datepattern.
    let has_prefregex = resolved
        .options
        .get("prefregex")
        .is_some_and(|value| !value.is_empty());
    if !has_prefregex
        && resolved
            .options
            .get("datepattern")
            .is_some_and(|value| !value.is_empty())
    {
        return Err(Error::config(
            "the original compat daemon does not yet support filter datepattern",
        ));
    }
    if let Some(value) = resolved.options.get("usedns")
        && value != "no"
    {
        return Err(Error::config(
            "the original compat daemon does not yet support filter usedns",
        ));
    }
    if let Some(value) = resolved.options.get("logtype") {
        let ok = match log_backend {
            LogBackend::File => value == "file",
            LogBackend::Systemd => matches!(value.as_str(), "journal" | "short" | "file"),
        };
        if !ok {
            return Err(Error::config(format!(
                "the original compat daemon does not yet support filter logtype={value:?}"
            )));
        }
    }
    let is_stock_sshd_normal = spec.name == "sshd"
        && spec.parameters.get("mode").map_or("normal", String::as_str) == "normal"
        && resolved
            .options
            .get("ignoreregex")
            .is_none_or(|v| v.trim().is_empty());
    let (failregex, ignoreregex, legacy_filter) = if is_stock_sshd_normal {
        let mut ssh = resolved.clone();
        ssh.ssh_normal = true;
        (Vec::new(), Vec::new(), Some(ssh))
    } else if has_prefregex {
        (Vec::new(), Vec::new(), Some(resolved.clone()))
    } else {
        (
            regex_lines(jail, resolved.options.get("failregex"))?,
            resolved
                .options
                .get("ignoreregex")
                .map(|value| {
                    value
                        .split('\n')
                        .filter(|line| !line.trim().is_empty())
                        .map(|line| line.trim().to_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            None,
        )
    };
    let ignoreip = get("ignoreip")?
        .map(|value| {
            value
                .split(|ch: char| ch.is_whitespace() || ch == ',')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let first = if log_backend == LogBackend::File {
        paths
            .first()
            .cloned()
            .ok_or_else(|| Error::config("original jail logpath produced no paths"))?
    } else {
        PathBuf::new()
    };
    let backend = if let Some(rec) = record {
        Backend::Script {
            ban_cmd: recorder_command("BAN", rec),
            unban_cmd: recorder_command("UNBAN", rec),
        }
    } else {
        let action_expr = required("action")?;
        resolve_legacy_action(base, jail, &action_expr, &port, &protocol, ban_time)?
    };
    Ok(Some(JailConfig {
        enabled: true,
        log_path: first,
        log_paths: paths,
        date_format: DateFormat::Syslog,
        filter: failregex,
        ignoreregex,
        legacy_filter,
        compat_mode: true,
        max_lines,
        log_encoding,
        max_retry,
        find_time,
        ban_time,
        bantime_increment,
        bantime_factor,
        bantime_multipliers,
        bantime_maxtime,
        port,
        protocol,
        log_backend,
        journalmatch,
        backend,
        ignoreip,
        ignoreself: false,
        ..JailConfig::default()
    }))
}

/// Journal disjunctions are separate argv tokens; never strip them or allow
/// unvalidated words to change journalctl options. Quoted/escaped values are
/// not admitted here until matching the original tokenization is supported.
fn parse_journalmatch(value: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut need_match = true;
    for token in value.split_whitespace() {
        if token == "+" {
            if need_match {
                return Err(Error::config(
                    "journalmatch '+' must separate nonempty groups",
                ));
            }
            need_match = true;
        } else {
            let valid = token.split_once('=').is_some_and(|(field, value)| {
                !field.is_empty()
                    && field
                        .bytes()
                        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == b'_')
                    && !value.is_empty()
                    && !value
                        .chars()
                        .any(|ch| ch.is_control() || matches!(u32::from(ch), 0x5c | 0x27 | 0x22))
            });
            if !valid {
                return Err(Error::config(
                    "unsupported journalmatch token; expected literal FIELD=value or '+'",
                ));
            }
            need_match = false;
        }
        out.push(token.to_owned());
    }
    if need_match && !out.is_empty() {
        return Err(Error::config(
            "journalmatch '+' must separate nonempty groups",
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[test]
fn journalmatch_disjunction_passes_as_a_distinct_argument() {
    assert_eq!(
        parse_journalmatch("_SYSTEMD_UNIT=fixture.service + _COMM=fixture")
            .expect("two literal clauses"),
        ["_SYSTEMD_UNIT=fixture.service", "+", "_COMM=fixture"]
    );
    assert!(parse_journalmatch(" + _COMM=fixture").is_err());
    assert!(parse_journalmatch("_COMM=fixture +").is_err());
    assert!(parse_journalmatch("_COMM=fixture unstructured-text").is_err());
}

/// One decision-recording command, executed by the script backend with
/// `<JAIL>`/`<IP>` substituted at ban time.
fn recorder_command(kind: &str, record: &Path) -> String {
    // safe_record_path has already bounded the record path's charset.
    format!("printf '{kind} <JAIL> <IP>\\n' >> {}", record.display())
}

/// Split a multi-line failregex value into per-line patterns.
fn regex_lines(jail: &str, value: Option<&String>) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    if let Some(value) = value {
        for line in value.split('\n') {
            if !line.trim().is_empty() {
                patterns.push(line.trim().to_owned());
            }
        }
    }
    if patterns.is_empty() {
        return Err(Error::config(format!(
            "original jail {jail:?} filter has no failregex patterns"
        )));
    }
    Ok(patterns)
}

/// Parse the original `maxretry` integer (builtin default applied earlier).
fn parse_maxretry(raw: &str) -> Result<u32> {
    let raw = raw.trim();
    let digits = raw.strip_prefix('+').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::config(format!(
            "original maxretry must be a positive integer, got {raw:?}"
        )));
    }
    digits
        .parse::<u32>()
        .map_err(|_| Error::config(format!("original maxretry {raw:?} is out of range")))
}

/// Parse the original `port` shorthand into numeric port strings.
fn parse_ports(jail: &str, raw: &str) -> Result<Vec<String>> {
    let ports = raw
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u16>()
                .ok()
                .filter(|n| (1..=u16::MAX).contains(n))
                .map_or_else(
                    || {
                        Err(Error::config(format!(
                            "the original compat daemon currently requires numeric ports, \
                             got {part:?} in jail {jail:?}"
                        )))
                    },
                    |n| Ok(n.to_string()),
                )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ports)
}

#[cfg(test)]
#[path = "compat_test.rs"]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests;

/// Resolve a jail's `action = <name>[k=v, ...]` against `base/action.d/<name>.conf`.
fn resolve_legacy_action(
    base: &Path,
    jail: &str,
    expression: &str,
    ports: &[String],
    protocol: &str,
    ban_time: i64,
) -> Result<Backend> {
    let mut actions = expression
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let first_line = actions
        .next()
        .ok_or_else(|| Error::config(format!("original jail {jail:?} has empty action")))?;
    if actions.next().is_some() {
        return Err(Error::config(format!(
            "original jail {jail:?} declares multiple live actions; only one is supported"
        )));
    }
    let spec = legacy_filter_spec::parse(first_line)?;
    let action_dir = base.join("action.d");
    let tree = legacy_layers::read(&action_dir, spec.name)?
        .ok_or_else(|| Error::config(format!("original action {:?} not found", spec.name)))?;

    let unsupported = |key: &str| {
        Error::config(format!(
            "original action {:?} uses unsupported live option {key:?}",
            spec.name
        ))
    };
    let controls = [
        "actionstart_on_demand",
        "actionrepair_on_unban",
        "actionflush",
        "actioncheck",
        "actionrepair",
        "actionreban",
        "actionreload",
        "timeout",
        "family",
    ];
    let reject_control = |key: &str, value: &str| -> Result<()> {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains('?')
            || (controls.contains(&normalized.as_str())
                && !value.trim().is_empty()
                && !(normalized == "actionstart_on_demand"
                    && original_bool(value.trim()) == Some(false)))
        {
            return Err(unsupported(key));
        }
        Ok(())
    };
    for values in tree.sections.values() {
        for (key, value) in values {
            reject_control(key, value)?;
        }
    }
    for (key, value) in &tree.defaults {
        reject_control(key, value)?;
    }
    for (key, value) in &spec.parameters {
        reject_control(key, value)?;
    }
    let mut tags: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    if let Some(init) = tree.sections.get("Init") {
        for (k, v) in init {
            tags.insert(k.clone(), v.clone());
        }
    }
    tags.insert("name".to_owned(), jail.to_owned());
    tags.insert("port".to_owned(), ports.join(","));
    tags.insert("protocol".to_owned(), protocol.to_owned());
    tags.insert("bantime".to_owned(), ban_time.to_string());
    for (k, v) in &spec.parameters {
        tags.insert(k.clone(), v.clone());
    }

    let get_cmd = |key: &str| -> Result<Option<String>> {
        let raw = legacy_interp::get_effective(
            "Definition",
            key,
            &tree.defaults,
            |name| tree.sections.get(name),
            None,
        )
        .map_err(|err| Error::config(format!("original action {:?} {key}: {err}", spec.name)))?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let mut expanded = trimmed.to_owned();
        for _ in 0..4 {
            let before = expanded.clone();
            for (tag, value) in &tags {
                expanded = expanded.replace(&format!("<{tag}>"), value);
            }
            if expanded == before {
                break;
            }
        }
        let remaining = if matches!(key, "actionban" | "actionunban") {
            expanded.replace("<ip>", "").replace("<IP>", "")
        } else {
            expanded.clone()
        };
        if remaining.contains('<') || remaining.contains("%(") {
            return Err(unsupported(key));
        }
        Ok(Some(expanded))
    };

    let action_start = get_cmd("actionstart")?;
    let action_ban = get_cmd("actionban")?.ok_or_else(|| {
        Error::config(format!("original action {:?} missing actionban", spec.name))
    })?;
    let action_unban = get_cmd("actionunban")?.ok_or_else(|| {
        Error::config(format!(
            "original action {:?} missing actionunban",
            spec.name
        ))
    })?;
    let action_stop = get_cmd("actionstop")?;

    Ok(Backend::LegacyAction {
        action_start,
        action_ban,
        action_unban,
        action_stop,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod live_action_admission_tests {
    use super::*;

    #[test]
    fn live_action_admission_rejects_unimplemented_forms_before_execution() {
        let temp = tempfile::tempdir().unwrap();
        let actions = temp.path().join("action.d");
        std::fs::create_dir(&actions).unwrap();
        let file = actions.join("audit.conf");
        let resolve =
            |expression| resolve_legacy_action(temp.path(), "fixture", expression, &[], "tcp", 60);
        let base = "[Definition]\nactionban = printf '<ip>'\nactionunban = printf '<ip>'\n";
        std::fs::write(&file, base).unwrap();
        assert!(resolve("audit").is_ok());
        assert!(
            resolve("audit\naudit")
                .unwrap_err()
                .to_string()
                .contains("multiple live actions")
        );
        for option in [
            "actioncheck = printf 'test'",
            "actionflush = printf 'test'",
            "actionrepair = printf 'test'",
            "actionban?family=inet6 = printf 'test'",
            "actionstart_on_demand = true",
            "timeout = 8",
            "actionstart = printf '<unsupported-tag>'",
        ] {
            std::fs::write(&file, format!("{base}{option}\n")).unwrap();
            assert!(resolve("audit").is_err(), "admitted unsupported: {option}");
        }
    }
}
