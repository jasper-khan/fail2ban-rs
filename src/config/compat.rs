//! Load an original Fail2Ban 1.1.1 configuration tree into a daemon `Config`.
//!
//! Stage-one admission subset of the original INI surface, mirroring the
//! offline replay rules: polling backend, `usedns = no`, no incremental ban
//! timing, no per-jail action commands (the decision-recording backend
//! replaces the firewall), file-log filters without prefregex/journalmatch/
//! maxlines or custom date patterns. Anything outside that subset fails
//! loudly instead of being silently dropped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::types::{Backend, Config, GlobalConfig, JailConfig, LogBackend, LoggingConfig};
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

/// Original daemon built-in defaults for options absent from fail2ban.conf.
const ORIGINAL_SOCKET: &str = "/var/run/fail2ban/fail2ban.sock";
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
    if !base.is_dir() {
        return Err(Error::config(format!(
            "original configuration directory {} does not exist",
            base.display()
        )));
    }
    let global = load_global(base)?;
    let tree = legacy_layers::read(base, "jail")?
        .ok_or_else(|| Error::config("original jail configuration not found"))?;
    let mut jails = HashMap::new();
    for section in &tree.section_order {
        if section.starts_with("KNOWN/") || section == "INCLUDES" {
            continue;
        }
        if let Some(jail) = load_jail(base, &tree, section, &record)? {
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
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'));
    if ok {
        Ok(record.to_path_buf())
    } else {
        Err(Error::config(format!(
            "decision record path {} must be absolute and contain only \
             alphanumeric characters, slashes, dots, underscores, or hyphens",
            record.display()
        )))
    }
}

/// Read fail2ban.conf layered overlays for the daemon socket and database
/// location. Other original daemon options are left for later stages.
fn load_global(base: &Path) -> Result<GlobalConfig> {
    let mut socket = PathBuf::from(ORIGINAL_SOCKET);
    let mut dbfile = PathBuf::from(ORIGINAL_DBFILE);
    if let Some(cfg) = legacy_layers::read(base, "fail2ban")? {
        let option = |key: &str| -> Result<Option<String>> {
            legacy_interp::get_effective(
                "Definition",
                key,
                &cfg.defaults,
                |name| cfg.sections.get(name),
                None,
            )
            .map_err(|err| Error::config(format!("original fail2ban.conf option {key}: {err}")))
        };
        if let Some(value) = option("socket")?.filter(|value| !value.is_empty()) {
            socket = PathBuf::from(value);
        }
        if let Some(value) = option("dbfile")?.filter(|value| !value.is_empty()) {
            dbfile = PathBuf::from(value);
        }
    }
    for (what, path) in [("socket", &socket), ("dbfile", &dbfile)] {
        if !path.is_absolute() {
            return Err(Error::config(format!(
                "original fail2ban.conf {what} must be an absolute path: {}",
                path.display()
            )));
        }
    }
    let state_dir = dbfile
        .parent()
        .ok_or_else(|| Error::config("original fail2ban.conf dbfile has no directory"))?
        .to_path_buf();
    Ok(GlobalConfig {
        state_dir,
        socket_path: socket,
        ..GlobalConfig::default()
    })
}

/// Convert one original jail section; `None` when it is not enabled.
fn load_jail(
    base: &Path,
    tree: &legacy_layers::LayeredConfig,
    jail: &str,
    record: &Path,
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
    if required("backend")? != "polling" {
        return Err(Error::config(
            "the original compat daemon currently requires backend=polling",
        ));
    }
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
    for key in ["action", "ignorecommand", "ignorecache"]
        .into_iter()
        .chain(UNSUPPORTED_BANTIME_OPTIONS.iter().copied())
    {
        reject_active(key)?;
    }
    for key in UNSUPPORTED_MATCH_OPTIONS {
        reject_override(key)?;
    }
    for key in ["bantime.increment", "skip_if_nologs", "systemd_if_nologs"] {
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
    if let Some(value) = get("logencoding")?
        && !matches!(value.as_str(), "auto" | "utf-8" | "UTF-8")
    {
        return Err(Error::config(
            "the original compat daemon accepts UTF-8 input text only",
        ));
    }
    for key in selected.keys() {
        let base_name = key.split_once('?').map_or(key.as_str(), |(base, _)| base);
        let known = base_name.strip_prefix("known/");
        let admitted = SUPPORTED_JAIL_KEYS.contains(&base_name)
            || known.is_some_and(|rest| SUPPORTED_JAIL_KEYS.contains(&rest));
        if !admitted {
            return Err(Error::config(format!(
                "unsupported original jail option {key}"
            )));
        }
    }

    let paths = log_paths(&required("logpath")?)?;
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
            _ => false,
        };
        if !supported {
            return Err(Error::config(format!(
                "unsupported original filter parameter {key}={value:?}"
            )));
        }
    }
    let resolved = legacy_filter::read_resolved(base, &expression, "polling")?
        .ok_or_else(|| Error::config(format!("original filter {expression:?} not found")))?;
    if let Some(maxlines) = resolved.maxlines
        && maxlines > 1
    {
        return Err(Error::config(
            "the original compat daemon does not yet support multi-line filters",
        ));
    }
    for key in ["prefregex", "journalmatch", "datepattern"] {
        if resolved
            .options
            .get(key)
            .is_some_and(|value| !value.is_empty())
        {
            return Err(Error::config(format!(
                "the original compat daemon does not yet support filter {key}"
            )));
        }
    }
    for key in ["logtype", "usedns"] {
        if resolved
            .options
            .get(key)
            .is_some_and(|value| value != "file" && value != "no")
        {
            return Err(Error::config(format!(
                "the original compat daemon does not yet support filter {key}"
            )));
        }
    }
    let failregex = regex_lines(jail, resolved.options.get("failregex"))?;
    let ignoreregex = resolved
        .options
        .get("ignoreregex")
        .map(|value| {
            value
                .split('\n')
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let ignoreip = get("ignoreip")?
        .map(|value| {
            value
                .split(|ch: char| ch.is_whitespace() || ch == ',')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let Some(first) = paths.first() else {
        return Err(Error::config("original jail logpath produced no paths"));
    };
    Ok(Some(JailConfig {
        enabled: true,
        log_path: first.clone(),
        log_paths: paths,
        date_format: DateFormat::Syslog,
        filter: failregex,
        ignoreregex,
        max_retry,
        find_time,
        ban_time,
        port,
        protocol,
        log_backend: LogBackend::File,
        backend: Backend::Script {
            ban_cmd: recorder_command("BAN", record),
            unban_cmd: recorder_command("UNBAN", record),
        },
        ignoreip,
        ignoreself: false,
        ..JailConfig::default()
    }))
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
