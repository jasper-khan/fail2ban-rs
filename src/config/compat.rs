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
    Backend, Config, GlobalConfig, JailConfig, LegacyActionFamilyCmds, LegacyActionSpec,
    LogBackend, LogEncoding, LoggingConfig,
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

/// Resolve `dbpurgeage` from `fail2ban.conf` / `fail2ban.local` (default 86400s = 1d).
pub fn dbpurgeage_of(base: &Path) -> Result<i64> {
    match definition_option(base, "dbpurgeage")?
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        None => Ok(86_400),
        Some(raw) => duration(raw, "dbpurgeage"),
    }
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
    let backend_name = get("backend")?.unwrap_or_else(|| "auto".to_owned());
    let log_backend = match backend_name.trim() {
        "polling" | "pyinotify" => LogBackend::File,
        "systemd" => LogBackend::Systemd,
        "auto" | "" => {
            if get("logpath")?.is_some_and(|v| !v.trim().is_empty()) {
                LogBackend::File
            } else {
                LogBackend::Systemd
            }
        }
        _ => {
            return Err(Error::config(
                "the original compat daemon currently requires backend=auto, polling, or systemd",
            ));
        }
    };
    match get("usedns")?.as_deref().map(str::trim) {
        None | Some("" | "no" | "warn" | "raw") => {}
        Some(other) => {
            return Err(Error::config(format!(
                "the original compat daemon does not support usedns={other:?}"
            )));
        }
    }
    let ignoreself = match get("ignoreself")?.as_deref().map(str::trim) {
        None | Some("") => true,
        Some(raw) => original_bool(raw).ok_or_else(|| {
            Error::config(format!(
                "original jail {jail:?} has invalid ignoreself={raw:?}"
            ))
        })?,
    };
    if record.is_some() {
        reject_active("action")?;
    }
    // ignorecache admitted.
    for key in UNSUPPORTED_BANTIME_OPTIONS {
        if !matches!(
            *key,
            "bantime.factor"
                | "bantime.multipliers"
                | "bantime.maxtime"
                | "bantime.rndtime"
                | "bantime.overalljails"
                | "journalmatch"
                | "ignorecommand"
                | "ignorecache"
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
    let bantime_rndtime = get("bantime.rndtime")?
        .filter(|v| !v.trim().is_empty())
        .map(|v| duration(&v, "bantime.rndtime"))
        .transpose()?
        .unwrap_or(0);
    let ignore_command = get("ignorecommand")?
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    let skip_if_nologs = get("skip_if_nologs")?
        .and_then(|v| original_bool(&v))
        .unwrap_or(false);
    let systemd_if_nologs = get("systemd_if_nologs")?
        .and_then(|v| original_bool(&v))
        .unwrap_or(false);
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
                "bantime.factor"
                    | "bantime.multipliers"
                    | "bantime.maxtime"
                    | "bantime.rndtime"
                    | "bantime.overalljails"
                    | "journalmatch"
                    | "ignorecommand"
                    | "ignorecache"
            )
            || known.is_some_and(|rest| SUPPORTED_JAIL_KEYS.contains(&rest));
        if !admitted {
            return Err(Error::config(format!(
                "unsupported original jail option {key}"
            )));
        }
    }

    let mut log_backend = log_backend;
    let paths = if log_backend == LogBackend::File {
        let raw_lp = get("logpath")?.unwrap_or_default();
        if raw_lp.trim().is_empty() {
            if systemd_if_nologs {
                log_backend = LogBackend::Systemd;
                Vec::new()
            } else if skip_if_nologs {
                return Ok(None);
            } else {
                return Err(Error::config(format!(
                    "original jail {jail:?} requires logpath"
                )));
            }
        } else {
            let expanded = log_paths(&raw_lp)?;
            let any_exists = expanded.iter().any(|p| p.exists());
            if !any_exists && systemd_if_nologs {
                log_backend = LogBackend::Systemd;
                Vec::new()
            } else if !any_exists && skip_if_nologs {
                return Ok(None);
            } else {
                expanded
            }
        }
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
    let has_ln_beg_datepattern = resolved.options.get("datepattern").is_some_and(|value| {
        value
            .lines()
            .map(str::trim)
            .any(|l| matches!(l, "{^LN-BEG}" | "^{DATE}"))
    });
    if !has_prefregex
        && !has_ln_beg_datepattern
        && resolved
            .options
            .get("datepattern")
            .is_some_and(|value| !value.is_empty())
    {
        return Err(Error::config(
            "the original compat daemon does not yet support filter datepattern",
        ));
    }
    let has_f_tags = resolved
        .options
        .get("failregex")
        .is_some_and(|v| v.contains("<F-"));
    let use_legacy_matcher =
        has_prefregex || has_ln_beg_datepattern || (has_f_tags && max_lines == 1);
    if let Some(value) = resolved.options.get("usedns")
        && value != "no"
    {
        return Err(Error::config(
            "the original compat daemon does not yet support filter usedns",
        ));
    }
    let mut resolved = resolved;
    if use_legacy_matcher {
        resolved
            .options
            .entry("usedns".to_owned())
            .or_insert_with(|| "no".to_owned());
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
    } else if use_legacy_matcher {
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
        bantime_rndtime,
        ignore_command,
        port,
        protocol,
        log_backend,
        journalmatch,
        backend,
        ignoreip,
        ignoreself,
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

/// Parse the original `port` shorthand into numeric ports, ranges (`lo:hi`),
/// or `/etc/services` service names (matching Fail2Ban 1.1.1).
fn parse_ports(jail: &str, raw: &str) -> Result<Vec<String>> {
    let ports = raw
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|part| !part.is_empty())
        .map(|part| resolve_port_token(jail, part))
        .collect::<Result<Vec<_>>>()?;
    Ok(ports)
}

fn resolve_port_token(jail: &str, token: &str) -> Result<String> {
    if let Ok(n) = token.parse::<u16>()
        && n >= 1
    {
        return Ok(n.to_string());
    }
    if let Some((lo_s, hi_s)) = token.split_once(':')
        && let (Ok(lo), Ok(hi)) = (lo_s.parse::<u16>(), hi_s.parse::<u16>())
        && lo <= hi
    {
        return Ok(format!("{lo}:{hi}"));
    }
    if let Some(port) = lookup_service_port(token) {
        return Ok(port.to_string());
    }
    Err(Error::config(format!(
        "unknown port or service name {token:?} in jail {jail:?}"
    )))
}

fn lookup_service_port(name: &str) -> Option<u16> {
    let needle = name.to_ascii_lowercase();
    if let Ok(contents) = std::fs::read_to_string("/etc/services") {
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(primary) = fields.next() else {
                continue;
            };
            let Some(port_proto) = fields.next() else {
                continue;
            };
            let Some((port_str, _)) = port_proto.split_once('/') else {
                continue;
            };
            let Ok(port) = port_str.parse::<u16>() else {
                continue;
            };
            if primary.eq_ignore_ascii_case(&needle)
                || fields.any(|alias| alias.eq_ignore_ascii_case(&needle))
            {
                return Some(port);
            }
        }
    }
    match needle.as_str() {
        "ftp-data" => Some(20),
        "ftp" => Some(21),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "domain" => Some(53),
        "http" | "www" => Some(80),
        "pop3" => Some(110),
        "imap" | "imap2" => Some(143),
        "ldap" => Some(389),
        "https" => Some(443),
        "smtps" | "submissions" => Some(465),
        "submission" => Some(587),
        "ldaps" => Some(636),
        "imaps" => Some(993),
        "pop3s" => Some(995),
        "mysql" => Some(3306),
        "sieve" => Some(4190),
        "postgresql" => Some(5432),
        "http-alt" => Some(8080),
        _ => None,
    }
}

#[cfg(test)]
#[path = "compat_test.rs"]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests;

/// Resolve a jail's `action = ...` list against `base/action.d/<name>.conf`.
///
/// Supports multiple action lines per jail, dual-stack `?family=inet6`
/// conditional sections and keys, `actionstart_on_demand`,
/// `actionrepair_on_unban`, `actioncheck`, `actionrepair`, `actionflush`,
/// `actionreban`, `actionreload`, `timeout`, nested `<tag>` expansion, and
/// standard Fail2Ban formatting/runtime tags.
fn resolve_legacy_action(
    base: &Path,
    jail: &str,
    expression: &str,
    ports: &[String],
    protocol: &str,
    ban_time: i64,
) -> Result<Backend> {
    let lines: Vec<&str> = expression
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return Err(Error::config(format!(
            "original jail {jail:?} has empty action"
        )));
    }
    let mut resolved_actions = Vec::with_capacity(lines.len());
    for line in lines {
        resolved_actions.push(resolve_single_legacy_action(
            base, jail, line, ports, protocol, ban_time,
        )?);
    }
    Ok(Backend::LegacyAction {
        actions: resolved_actions,
    })
}

fn is_supported_condition(cond: &str) -> bool {
    matches!(
        cond.to_ascii_lowercase().as_str(),
        "family=inet4" | "family=inet6"
    )
}

fn validate_action_conditions(
    action_name: &str,
    tree: &crate::config::legacy_layers::LayeredConfig,
    params: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for (section, values) in &tree.sections {
        if let Some((_, cond)) = section.split_once('?')
            && !is_supported_condition(cond)
        {
            return Err(Error::config(format!(
                "original action {action_name:?} uses unsupported section condition {section:?}"
            )));
        }
        for key in values.keys() {
            if let Some((_, cond)) = key.split_once('?')
                && !is_supported_condition(cond)
            {
                return Err(Error::config(format!(
                    "original action {action_name:?} uses unsupported option condition {key:?}"
                )));
            }
        }
    }
    for key in tree.defaults.keys().chain(params.keys()) {
        if let Some((_, cond)) = key.split_once('?')
            && !is_supported_condition(cond)
        {
            return Err(Error::config(format!(
                "original action {action_name:?} uses unsupported option condition {key:?}"
            )));
        }
    }
    Ok(())
}

fn resolve_single_legacy_action(
    base: &Path,
    jail: &str,
    action_line: &str,
    ports: &[String],
    protocol: &str,
    ban_time: i64,
) -> Result<LegacyActionSpec> {
    let spec = legacy_filter_spec::parse(action_line)?;
    let action_dir = base.join("action.d");
    let tree = legacy_layers::read(&action_dir, spec.name)?
        .ok_or_else(|| Error::config(format!("original action {:?} not found", spec.name)))?;
    validate_action_conditions(spec.name, &tree, &spec.parameters)?;

    let (ipv4, start_on_demand, repair_on_unban, timeout_secs) = resolve_action_family(
        &tree,
        spec.name,
        &spec.parameters,
        jail,
        ports,
        protocol,
        ban_time,
        "inet4",
    )?;
    let (ipv6, _, _, _) = resolve_action_family(
        &tree,
        spec.name,
        &spec.parameters,
        jail,
        ports,
        protocol,
        ban_time,
        "inet6",
    )?;

    Ok(LegacyActionSpec {
        name: spec.name.to_owned(),
        ban_time,
        start_on_demand,
        repair_on_unban,
        timeout_secs,
        ipv4,
        ipv6,
    })
}

fn merge_section_for_family(
    tree: &crate::config::legacy_layers::LayeredConfig,
    base_section: &str,
    family: &str,
) -> std::collections::BTreeMap<String, String> {
    let family_suffix = format!("?family={family}");
    let mut out = std::collections::BTreeMap::new();
    // Base section non-conditional keys first, then conditional keys matching `family`.
    if let Some(sec) = tree.sections.get(base_section) {
        for (k, v) in sec {
            if !k.contains('?') {
                out.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in sec {
            if let Some((base_key, cond)) = k.split_once('?')
                && cond.eq_ignore_ascii_case(&format!("family={family}"))
            {
                out.insert(base_key.to_owned(), v.clone());
            }
        }
    }
    // Conditional section `[Section?family=<family>]` overrides base section.
    for (sec_name, sec) in &tree.sections {
        if let Some((prefix, cond)) = sec_name.split_once('?')
            && prefix == base_section
            && cond.eq_ignore_ascii_case(&format!("family={family}"))
        {
            for (k, v) in sec {
                if !k.contains('?') {
                    out.insert(k.clone(), v.clone());
                } else if let Some(base_key) = k.strip_suffix(&family_suffix) {
                    out.insert(base_key.to_owned(), v.clone());
                }
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn resolve_action_family(
    tree: &crate::config::legacy_layers::LayeredConfig,
    action_name: &str,
    params: &std::collections::BTreeMap<String, String>,
    jail: &str,
    ports: &[String],
    protocol: &str,
    ban_time: i64,
    family: &str,
) -> Result<(LegacyActionFamilyCmds, bool, bool, u64)> {
    let def_sec = merge_section_for_family(tree, "Definition", family);
    let init_sec = merge_section_for_family(tree, "Init", family);

    let mut sections: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, String>,
    > = std::collections::BTreeMap::new();
    sections.insert("Definition".to_owned(), def_sec.clone());
    sections.insert("Init".to_owned(), init_sec.clone());

    let mut defaults = std::collections::BTreeMap::new();
    for (k, v) in &tree.defaults {
        if !k.contains('?') {
            defaults.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in &tree.defaults {
        if let Some((base_key, cond)) = k.split_once('?')
            && cond.eq_ignore_ascii_case(&format!("family={family}"))
        {
            defaults.insert(base_key.to_owned(), v.clone());
        }
    }

    // Build tag map: [Definition] interpolated values < [Init] < built-ins < action[params].
    let mut tags: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    tags.insert("sp".to_owned(), " ".to_owned());
    tags.insert("br".to_owned(), "\n".to_owned());
    tags.insert("newl".to_owned(), "\n".to_owned());
    tags.insert("tb".to_owned(), "\t".to_owned());

    for k in def_sec.keys() {
        if let Ok(Some(val)) = legacy_interp::get_effective(
            "Definition",
            k,
            &defaults,
            |name| sections.get(name),
            None,
        ) {
            tags.insert(k.clone(), val);
        }
    }
    for k in init_sec.keys() {
        if let Ok(Some(val)) =
            legacy_interp::get_effective("Init", k, &defaults, |name| sections.get(name), None)
        {
            tags.insert(k.clone(), val);
        }
    }
    tags.insert("name".to_owned(), jail.to_owned());
    tags.insert("port".to_owned(), ports.join(","));
    tags.insert("protocol".to_owned(), protocol.to_owned());
    tags.insert("bantime".to_owned(), ban_time.to_string());
    tags.insert("family".to_owned(), family.to_owned());

    for (k, v) in params {
        if !k.contains('?') {
            tags.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in params {
        if let Some((base_key, cond)) = k.split_once('?')
            && cond.eq_ignore_ascii_case(&format!("family={family}"))
        {
            tags.insert(base_key.to_owned(), v.clone());
        }
    }

    let start_on_demand = tags
        .get("actionstart_on_demand")
        .and_then(|v| original_bool(v.trim()))
        .unwrap_or(false);
    let repair_on_unban = tags
        .get("actionrepair_on_unban")
        .and_then(|v| original_bool(v.trim()))
        .unwrap_or(false);
    let timeout_secs = match tags
        .get("timeout")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => raw.parse::<u64>().map_err(|_| {
            Error::config(format!(
                "original action {action_name:?} has invalid timeout {raw:?}"
            ))
        })?,
        None => 60,
    };

    let runtime_tags = [
        "<ip>",
        "<IP>",
        "<ip-rev>",
        "<family>",
        "<name>",
        "<JAIL>",
        "<port>",
        "<protocol>",
        "<time>",
        "<bantime>",
        "<failures>",
        "<ipfailures>",
        "<ipjailfailures>",
        "<matches>",
        "<ipmatches>",
        "<ipjailmatches>",
    ];

    let get_cmd = |key: &str, allow_runtime_tags: bool| -> Result<Option<String>> {
        let raw = legacy_interp::get_effective(
            "Definition",
            key,
            &defaults,
            |name| sections.get(name),
            None,
        )
        .map_err(|err| Error::config(format!("original action {action_name:?} {key}: {err}")))?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let mut expanded = trimmed.to_owned();
        for _ in 0..12 {
            let before = expanded.clone();
            for (tag, value) in &tags {
                let needle = format!("<{tag}>");
                if expanded.contains(&needle) {
                    expanded = expanded.replace(&needle, value);
                }
            }
            if expanded == before {
                break;
            }
        }
        let mut check_str = expanded.clone();
        if allow_runtime_tags {
            for rt in runtime_tags {
                check_str = check_str.replace(rt, "");
            }
        }
        if contains_unexpanded_tag(&check_str) || check_str.contains("%(") {
            return Err(Error::config(format!(
                "original action {action_name:?} {key} contains unexpanded tag in {expanded:?}"
            )));
        }
        Ok(Some(expanded))
    };

    let start = get_cmd("actionstart", false)?;
    let stop = get_cmd("actionstop", false)?;
    let flush = get_cmd("actionflush", false)?;
    let check = get_cmd("actioncheck", false)?;
    let repair = get_cmd("actionrepair", false)?;
    let ban = get_cmd("actionban", true)?.ok_or_else(|| {
        Error::config(format!("original action {action_name:?} missing actionban"))
    })?;
    let unban = get_cmd("actionunban", true)?.ok_or_else(|| {
        Error::config(format!(
            "original action {action_name:?} missing actionunban"
        ))
    })?;
    let reban = get_cmd("actionreban", true)?;
    let reload = get_cmd("actionreload", false)?;

    Ok((
        LegacyActionFamilyCmds {
            start,
            stop,
            flush,
            check,
            repair,
            ban,
            unban,
            reban,
            reload,
        },
        start_on_demand,
        repair_on_unban,
        timeout_secs,
    ))
}

/// Detect unexpanded Fail2Ban `<tag>` tokens while allowing shell redirections
/// such as `< /dev/null` or `<<EOF`.
fn contains_unexpanded_tag(s: &str) -> bool {
    for (idx, _) in s.match_indices('<') {
        let start = idx + 1;
        if let Some(rest) = s.get(start..)
            && let Some(rel_end) = rest.find('>')
            && let Some(inner) = rest.get(..rel_end)
            && !inner.is_empty()
            && inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod live_action_admission_tests {
    use super::*;

    #[test]
    fn live_action_supports_multi_action_dual_stack_and_rejects_unknown_tags() {
        let temp = tempfile::tempdir().unwrap();
        let actions = temp.path().join("action.d");
        std::fs::create_dir(&actions).unwrap();
        let file = actions.join("audit.conf");
        let resolve = |expression| {
            resolve_legacy_action(
                temp.path(),
                "fixture",
                expression,
                &["22".into()],
                "tcp",
                60,
            )
        };
        let base = concat!(
            "[Definition]\n",
            "actionstart = printf 'start <addr_set>'\n",
            "actioncheck = printf 'check <addr_set>'\n",
            "actionflush = printf 'flush <addr_set>'\n",
            "actionrepair = printf 'repair <addr_set>'\n",
            "actionban = printf 'ban <addr_set> <ip> <ip-rev>'\n",
            "actionunban = printf 'unban <addr_set> <ip>'\n",
            "actionstart_on_demand = true\n",
            "timeout = 12\n",
            "[Init]\n",
            "addr_set = v4-set-<name>\n",
            "[Init?family=inet6]\n",
            "addr_set = v6-set-<name>\n",
        );
        std::fs::write(&file, base).unwrap();

        let Backend::LegacyAction { actions: resolved } =
            resolve("audit\naudit[addr_set=custom]").unwrap()
        else {
            panic!("expected LegacyAction");
        };
        assert_eq!(resolved.len(), 2);
        assert!(resolved[0].start_on_demand);
        assert_eq!(resolved[0].timeout_secs, 12);
        assert_eq!(
            resolved[0].ipv4.ban,
            "printf 'ban v4-set-fixture <ip> <ip-rev>'"
        );
        assert_eq!(
            resolved[0].ipv6.ban,
            "printf 'ban v6-set-fixture <ip> <ip-rev>'"
        );
        assert_eq!(resolved[1].ipv4.ban, "printf 'ban custom <ip> <ip-rev>'");

        // Unknown tags and unknown section conditions are still rejected before execution.
        std::fs::write(
            &file,
            "[Definition]\nactionstart = printf '<unsupported-tag>'\nactionban = printf '<ip>'\nactionunban = printf '<ip>'\n",
        )
        .unwrap();
        assert!(resolve("audit").is_err());

        std::fs::write(
            &file,
            "[Definition]\nactionban?bogus=1 = printf '<ip>'\nactionban = printf '<ip>'\nactionunban = printf '<ip>'\n",
        )
        .unwrap();
        assert!(resolve("audit").is_err());
    }

    #[test]
    fn parse_ports_resolves_service_names_and_ranges() {
        assert_eq!(parse_ports("sshd", "ssh").unwrap(), vec!["22"]);
        assert_eq!(parse_ports("web", "http,https").unwrap(), vec!["80", "443"]);
        assert_eq!(parse_ports("all", "0:65535").unwrap(), vec!["0:65535"]);
    }

    #[test]
    fn skip_if_nologs_and_systemd_if_nologs_behave_like_fail2ban_111() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("f2b");
        let filter_dir = base.join("filter.d");
        std::fs::create_dir_all(&filter_dir).unwrap();
        std::fs::write(
            base.join("fail2ban.conf"),
            format!(
                "[Definition]\nsocket = {}\ndbfile = {}\n",
                tmp.path().join("s.sock").display(),
                tmp.path().join("db.sqlite3").display()
            ),
        )
        .unwrap();
        std::fs::write(
            filter_dir.join("mini.conf"),
            "[Definition]\nfailregex = fail from <HOST>\nignoreregex =\n",
        )
        .unwrap();
        std::fs::write(
            base.join("jail.conf"),
            "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n\n\
             [skipped]\nenabled = true\nport = 22\nfilter = mini\nlogpath = /nonexistent/does-not-exist.log\nskip_if_nologs = true\nbantime.overalljails = true\n\n\
             [fallback]\nenabled = true\nport = 22\nfilter = mini\nlogpath = /nonexistent/also-missing.log\nsystemd_if_nologs = true\n",
        ).unwrap();
        let cfg = load(&base, &tmp.path().join("rec.log")).unwrap();
        assert!(
            !cfg.jail.contains_key("skipped"),
            "skip_if_nologs should skip missing-log jail"
        );
        let fb = cfg.jail.get("fallback").expect("systemd_if_nologs jail");
        assert_eq!(fb.log_backend, LogBackend::Systemd);
    }
}
