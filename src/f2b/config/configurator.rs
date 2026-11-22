//! Fail2Ban 1.1.1 `Fail2banReader`, `FilterReader`, `ActionReader`, `JailReader`,
//! `JailsReader`, and `Configurator`.
//!
//! Reads `/etc/fail2ban` INI trees (`fail2ban.conf`, `jail.conf`, `filter.d/*`,
//! `action.d/*`, `paths-*.conf`, `.local`, `.d/*.conf`, `[INCLUDES]`) and produces
//! the exact Fail2Ban 1.1.1 protocol command stream (`Vec<PickleValue>`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::duration::parse_bool;
use crate::error::{Error, Result};
use crate::logging::LogLevel;
use crate::protocol::PickleValue;

use super::interp;
use super::layers::{self, LayeredConfig};
use super::spec;
use super::tags;

pub type Options = BTreeMap<String, String>;

const FAIL2BAN_VERSION: &str = "1.1.1";

const FILTER_OPTIONS: &[&str] = &[
    "usedns",
    "prefregex",
    "ignoreregex",
    "failregex",
    "maxlines",
    "datepattern",
    "journalmatch",
];

const ACTION_CONFIG_OPTS: &[&str] = &[
    "actionstart",
    "actionstart_on_demand",
    "actionstop",
    "actionflush",
    "actionreload",
    "actioncheck",
    "actionrepair",
    "actionrepair_on_unban",
    "actionban",
    "actionprolong",
    "actionreban",
    "actionunban",
    "norestored",
];

const ACTION_ESCAPED_TAGS: &[&str] = &[
    "matches",
    "ipmatches",
    "ipjailmatches",
    "timeout",
    "bantime",
];

/// Early server bootstrap options from `fail2ban.conf` `[Definition]` / `[DEFAULT]`.
#[derive(Debug, Clone)]
pub struct EarlyOptions {
    pub socket: String,
    pub pidfile: String,
    pub loglevel: String,
    pub logtarget: String,
    pub syslogsocket: String,
}

impl Default for EarlyOptions {
    fn default() -> Self {
        Self {
            socket: "/var/run/fail2ban/fail2ban.sock".to_owned(),
            pidfile: "/var/run/fail2ban/fail2ban.pid".to_owned(),
            loglevel: "INFO".to_owned(),
            logtarget: "/var/log/fail2ban.log".to_owned(),
            syslogsocket: "auto".to_owned(),
        }
    }
}

/// Reader for `fail2ban.conf` / `fail2ban.local` / `fail2ban.d/*.conf`.
#[derive(Debug)]
pub struct Fail2banReader {
    base: PathBuf,
    config: Option<LayeredConfig>,
    opts: Options,
    thread_stacksize: Option<i64>,
}

impl Fail2banReader {
    pub fn new(base: impl AsRef<Path>) -> Self {
        Self {
            base: base.as_ref().to_path_buf(),
            config: None,
            opts: Options::new(),
            thread_stacksize: None,
        }
    }

    pub fn read(&mut self) -> Result<bool> {
        self.config = layers::read(&self.base, "fail2ban")?;
        Ok(self.config.is_some())
    }

    pub fn get_early_options(&self) -> Result<EarlyOptions> {
        let mut out = EarlyOptions::default();
        let Some(cfg) = self.config.as_ref() else {
            return Ok(out);
        };
        if let Some(v) = get_opt(cfg, "Definition", "socket", None)? {
            out.socket = v;
        }
        if let Some(v) = get_opt(cfg, "Definition", "pidfile", None)? {
            out.pidfile = v;
        }
        if let Some(v) = get_opt(cfg, "Definition", "loglevel", None)? {
            out.loglevel = v;
        }
        if let Some(v) = get_opt(cfg, "Definition", "logtarget", None)? {
            out.logtarget = v;
        }
        if let Some(v) = get_opt(cfg, "Definition", "syslogsocket", None)? {
            out.syslogsocket = v;
        }
        Ok(out)
    }

    pub fn get_options(&mut self, overrides: Option<&Options>) -> Result<()> {
        let defaults: &[(&str, Option<&str>)] = &[
            ("loglevel", Some("INFO")),
            ("logtarget", Some("STDERR")),
            ("syslogsocket", Some("auto")),
            ("allowipv6", Some("auto")),
            ("dbfile", Some("/var/lib/fail2ban/fail2ban.sqlite3")),
            ("dbmaxmatches", None),
            ("dbpurgeage", Some("1d")),
        ];
        self.opts.clear();
        self.thread_stacksize = None;
        if let Some(cfg) = self.config.as_ref() {
            for &(key, def) in defaults {
                if let Some(val) = get_opt(cfg, "Definition", key, None)? {
                    self.opts.insert(key.to_owned(), val);
                } else if let Some(d) = def {
                    self.opts.insert(key.to_owned(), d.to_owned());
                }
            }
            if cfg.sections.contains_key("Thread")
                && let Some(val) = get_opt(cfg, "Thread", "stacksize", None)?
                && let Ok(n) = val.trim().parse::<i64>()
            {
                self.thread_stacksize = Some(n);
            }
        } else {
            for &(key, def) in defaults {
                if let Some(d) = def {
                    self.opts.insert(key.to_owned(), d.to_owned());
                }
            }
        }
        if let Some(ov) = overrides {
            for (k, v) in ov {
                self.opts.insert(k.clone(), v.clone());
            }
        }
        if let Some(lvl) = self.opts.get("loglevel") {
            let _ = LogLevel::parse(lvl)?;
        }
        Ok(())
    }

    pub fn convert(&self) -> Vec<PickleValue> {
        let mut ordered: Vec<(u8, PickleValue)> = Vec::new();
        if let Some(sz) = self.thread_stacksize {
            ordered.push((
                0,
                PickleValue::List(vec![
                    PickleValue::Str("set".to_owned()),
                    PickleValue::Str("thread".to_owned()),
                    PickleValue::Dict(vec![(
                        PickleValue::Str("stacksize".to_owned()),
                        PickleValue::Int(sz),
                    )]),
                ]),
            ));
        }
        let order: &[(&str, u8)] = &[
            ("syslogsocket", 11),
            ("loglevel", 12),
            ("logtarget", 13),
            ("allowipv6", 14),
            ("dbfile", 50),
            ("dbmaxmatches", 51),
            ("dbpurgeage", 52),
        ];
        for &(key, rank) in order {
            if let Some(val) = self.opts.get(key) {
                let pval = if key == "dbmaxmatches" {
                    match val.trim().parse::<i64>() {
                        Ok(n) => PickleValue::Int(n),
                        Err(_) => continue,
                    }
                } else {
                    PickleValue::Str(val.clone())
                };
                ordered.push((
                    rank,
                    PickleValue::List(vec![
                        PickleValue::Str("set".to_owned()),
                        PickleValue::Str(key.to_owned()),
                        pval,
                    ]),
                ));
            }
        }
        ordered.sort_by_key(|(rank, _)| *rank);
        ordered.into_iter().map(|(_, cmd)| cmd).collect()
    }
}

/// Resolved filter options matching `FilterReader.getCombined()`.
#[derive(Debug, Clone, Default)]
pub struct ResolvedFilter {
    pub options: Options,
    pub maxlines: Option<i64>,
}

/// Reader for `filter.d/<name>.conf`.
#[derive(Debug)]
pub struct FilterReader {
    base: PathBuf,
    file: String,
    jail_name: String,
    init_opts: Options,
    config: Option<LayeredConfig>,
    resolved: ResolvedFilter,
}

impl FilterReader {
    pub fn new(base: impl AsRef<Path>, file: &str, jail_name: &str, init_opts: Options) -> Self {
        Self {
            base: base.as_ref().to_path_buf(),
            file: file.to_owned(),
            jail_name: jail_name.to_owned(),
            init_opts,
            config: None,
            resolved: ResolvedFilter::default(),
        }
    }

    pub fn read(&mut self) -> Result<bool> {
        let name = if Path::new(&self.file).is_absolute() || self.file.starts_with("./") {
            self.file.clone()
        } else {
            format!("filter.d/{}", self.file)
        };
        self.config = layers::read(&self.base, &name)?;
        Ok(self.config.is_some())
    }

    /// Read directly from a specific file path (used by `fail2ban-regex`).
    pub fn read_path(&mut self, path: &Path) -> Result<bool> {
        let lossy = path.to_string_lossy();
        let no_ext = lossy
            .strip_suffix(".conf")
            .or_else(|| lossy.strip_suffix(".local"))
            .unwrap_or(&lossy);
        self.config = layers::read(&self.base, no_ext)?;
        Ok(self.config.is_some())
    }

    pub fn apply_auto_options(&mut self, backend: &str) {
        let Some(cfg) = self.config.as_ref() else {
            return;
        };
        if self.init_opts.get("logtype").is_none_or(String::is_empty)
            && cfg
                .sections
                .get("Definition")
                .is_none_or(|opts| !opts.contains_key("logtype"))
        {
            let logtype = if backend.starts_with("systemd") {
                "journal"
            } else {
                "file"
            };
            self.init_opts
                .insert("logtype".to_owned(), logtype.to_owned());
        }
    }

    pub fn get_options(&mut self, jail_opts: &Options, all: bool) -> Result<()> {
        let Some(cfg) = self.config.as_ref() else {
            return Err(Error::config(format!(
                "filter {:?} was not read",
                self.file
            )));
        };
        self.resolved =
            resolve_definition_init(cfg, FILTER_OPTIONS, jail_opts, &self.init_opts, all, &[])?;
        Ok(())
    }

    pub fn combined(&self) -> &Options {
        &self.resolved.options
    }

    pub fn maxlines(&self) -> Option<i64> {
        self.resolved.maxlines
    }

    pub fn convert(&self) -> Vec<PickleValue> {
        let mut stream = Vec::new();
        fill_filter_stream(
            &mut stream,
            &self.resolved.options,
            self.resolved.maxlines,
            &self.jail_name,
        );
        stream
    }
}

/// Resolved action properties matching `ActionReader.getCombined()`.
#[derive(Debug, Clone, Default)]
pub struct ResolvedAction {
    pub name: String,
    pub combined: Options,
    pub init_opts: Options,
}

/// Reader for `action.d/<name>.conf`.
#[derive(Debug)]
pub struct ActionReader {
    base: PathBuf,
    file: String,
    jail_name: String,
    act_name: String,
    init_opts: Options,
    config: Option<LayeredConfig>,
    resolved: ResolvedAction,
}

impl ActionReader {
    pub fn new(
        base: impl AsRef<Path>,
        file: &str,
        jail_name: &str,
        mut init_opts: Options,
    ) -> Self {
        let n = init_opts
            .entry("name".to_owned())
            .or_insert_with(|| jail_name.to_owned())
            .clone();
        let act_name = if let Some(a) = init_opts.get("actname").cloned() {
            a
        } else {
            let mut a = file.to_owned();
            if n != jail_name {
                if let Some(rest) = n.strip_prefix(jail_name) {
                    a.push_str(rest);
                } else {
                    a.push('-');
                    a.push_str(&n);
                }
            }
            init_opts.insert("actname".to_owned(), a.clone());
            a
        };
        Self {
            base: base.as_ref().to_path_buf(),
            file: file.to_owned(),
            jail_name: jail_name.to_owned(),
            act_name,
            init_opts,
            config: None,
            resolved: ResolvedAction::default(),
        }
    }

    pub fn read(&mut self) -> Result<bool> {
        let name = if Path::new(&self.file).is_absolute() || self.file.starts_with("./") {
            self.file.clone()
        } else {
            format!("action.d/{}", self.file)
        };
        self.config = layers::read(&self.base, &name)?;
        Ok(self.config.is_some())
    }

    pub fn get_options(&mut self, jail_opts: &Options) -> Result<()> {
        let Some(cfg) = self.config.as_ref() else {
            return Err(Error::config(format!(
                "action {:?} was not read",
                self.file
            )));
        };
        let mut init = self.init_opts.clone();
        // Collect [Init] defaults & conditional sections (like [Init?family=inet6]).
        // Merge conditional [Definition?family=inet6] keys as `key?family=inet6` too.
        let mut merged_cfg = cfg.clone();
        flatten_conditional_sections(&mut merged_cfg);

        // Include action conditional keys in the list of Definition keys to extract.
        let mut def_keys: Vec<String> =
            ACTION_CONFIG_OPTS.iter().map(|s| (*s).to_owned()).collect();
        if let Some(def) = merged_cfg.sections.get("Definition") {
            for k in def.keys() {
                if k != "__name__" && !def_keys.contains(k) {
                    def_keys.push(k.clone());
                }
            }
        }
        let def_refs: Vec<&str> = def_keys.iter().map(String::as_str).collect();

        // Populate init defaults from [Init] (matching DefinitionInitConfigReader.getOptions).
        if let Some(init_sec) = merged_cfg.sections.get("Init") {
            for key in init_sec.keys().filter(|k| k.as_str() != "__name__") {
                if !key.starts_with("known/")
                    && let Some(orig) = get_opt(&merged_cfg, "Init", key, None)?
                {
                    init.insert(format!("known/{key}"), orig.clone());
                    if !init.contains_key(key) {
                        init.insert(key.clone(), orig);
                    }
                } else if !init.contains_key(key)
                    && let Some(v) = get_opt(&merged_cfg, "Init", key, None)?
                {
                    init.insert(key.clone(), v);
                }
            }
        }

        let res = resolve_definition_init(
            &merged_cfg,
            &def_refs,
            jail_opts,
            &init,
            false,
            ACTION_ESCAPED_TAGS,
        )?;
        self.resolved = ResolvedAction {
            name: self.act_name.clone(),
            combined: res.options,
            init_opts: init,
        };
        Ok(())
    }

    pub fn convert(&self) -> Vec<PickleValue> {
        let mut stream = Vec::new();
        stream.push(PickleValue::str_list([
            "set",
            &self.jail_name,
            "addaction",
            &self.act_name,
        ]));
        let mut multi: Vec<PickleValue> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (opt, val) in &self.resolved.combined {
            if opt.starts_with("known/") {
                continue;
            }
            let base = opt.split_once('?').map_or(opt.as_str(), |(b, _)| b);
            if ACTION_CONFIG_OPTS.contains(&base) {
                seen.insert(opt.clone());
                multi.push(PickleValue::List(vec![
                    PickleValue::Str(opt.clone()),
                    action_opt_value(base, val),
                ]));
            }
        }
        for (opt, val) in &self.resolved.init_opts {
            if opt.starts_with("known/") || seen.contains(opt) {
                continue;
            }
            let base = opt.split_once('?').map_or(opt.as_str(), |(b, _)| b);
            if !ACTION_CONFIG_OPTS.contains(&base) {
                multi.push(PickleValue::List(vec![
                    PickleValue::Str(opt.clone()),
                    PickleValue::Str(val.clone()),
                ]));
            }
        }
        if multi.len() > 1 {
            stream.push(PickleValue::List(vec![
                PickleValue::Str("multi-set".to_owned()),
                PickleValue::Str(self.jail_name.clone()),
                PickleValue::Str("action".to_owned()),
                PickleValue::Str(self.act_name.clone()),
                PickleValue::List(multi),
            ]));
        } else if let Some(PickleValue::List(mut pair)) = multi.into_iter().next() {
            let mut cmd = vec![
                PickleValue::Str("set".to_owned()),
                PickleValue::Str(self.jail_name.clone()),
                PickleValue::Str("action".to_owned()),
                PickleValue::Str(self.act_name.clone()),
            ];
            cmd.append(&mut pair);
            stream.push(PickleValue::List(cmd));
        }
        stream
    }
}

fn action_opt_value(base: &str, raw: &str) -> PickleValue {
    if matches!(
        base,
        "actionstart_on_demand" | "actionrepair_on_unban" | "norestored"
    ) && let Ok(b) = parse_bool(raw)
    {
        return PickleValue::Bool(b);
    }
    PickleValue::Str(raw.to_owned())
}

#[derive(Debug)]
enum JailAction {
    Conf(Box<ActionReader>),
    Python {
        act_name: String,
        path: String,
        init_json: String,
    },
}

/// Reader for a single jail section inside `jail.conf` / `jail.local` / `jail.d/*`.
#[derive(Debug)]
pub struct JailReader {
    base: PathBuf,
    name: String,
    force_enable: bool,
    filter: Option<FilterReader>,
    actions: Vec<JailAction>,
    opts: Options,
    config_error: Option<String>,
    runtime_error: Option<String>,
}

const JAIL_IGNORE_STREAM_OPTS: &[&str] = &[
    "action",
    "filter",
    "enabled",
    "backend",
    "skip_if_nologs",
    "systemd_if_nologs",
    "usedns",
    "prefregex",
    "ignoreregex",
    "failregex",
    "maxlines",
    "datepattern",
    "journalmatch",
];

const JAIL_ALL_OPTS: &[&str] = &[
    "enabled",
    "backend",
    "maxretry",
    "maxmatches",
    "findtime",
    "bantime",
    "bantime.increment",
    "bantime.factor",
    "bantime.formula",
    "bantime.multipliers",
    "bantime.maxtime",
    "bantime.rndtime",
    "bantime.overalljails",
    "ignorecommand",
    "ignoreself",
    "ignoreip",
    "ignorecache",
    "filter",
    "logtimezone",
    "logencoding",
    "logpath",
    "skip_if_nologs",
    "systemd_if_nologs",
    "action",
    "usedns",
    "prefregex",
    "ignoreregex",
    "failregex",
    "maxlines",
    "datepattern",
    "journalmatch",
];

impl JailReader {
    pub fn new(base: impl AsRef<Path>, name: &str, force_enable: bool) -> Self {
        Self {
            base: base.as_ref().to_path_buf(),
            name: name.to_owned(),
            force_enable,
            filter: None,
            actions: Vec::new(),
            opts: Options::new(),
            config_error: None,
            runtime_error: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_enabled(&self) -> bool {
        self.force_enable
            || self
                .opts
                .get("enabled")
                .is_some_and(|v| parse_bool(v).unwrap_or(false))
    }

    pub fn has_error(&self) -> bool {
        self.config_error.is_some() || self.runtime_error.is_some()
    }

    pub fn get_options(
        &mut self,
        shared_config: &LayeredConfig,
        add_opts: Option<&Options>,
    ) -> bool {
        let mut cfg = shared_config.clone();
        cfg.defaults
            .insert("fail2ban_version".to_owned(), FAIL2BAN_VERSION.to_owned());
        cfg.defaults.insert(
            "fail2ban_confpath".to_owned(),
            self.base.to_string_lossy().into_owned(),
        );

        match self.load_options_inner(&mut cfg, add_opts) {
            Ok(()) => true,
            Err(e) => {
                self.config_error = Some(e.to_string());
                false
            }
        }
    }

    fn load_options_inner(
        &mut self,
        cfg: &mut LayeredConfig,
        add_opts: Option<&Options>,
    ) -> Result<()> {
        if !cfg.sections.contains_key(&self.name) {
            return Err(Error::config(format!(
                "Jail {:?} was not found among available",
                self.name
            )));
        }

        // First pass: enabled, backend, filter
        let enabled =
            get_opt(cfg, &self.name, "enabled", None)?.unwrap_or_else(|| "false".to_owned());
        let backend =
            get_opt(cfg, &self.name, "backend", None)?.unwrap_or_else(|| "auto".to_owned());
        let filter_expr = get_opt(cfg, &self.name, "filter", None)?.unwrap_or_default();
        self.opts.insert("enabled".to_owned(), enabled);
        self.opts.insert("backend".to_owned(), backend);
        self.opts.insert("filter".to_owned(), filter_expr);
        if let Some(add) = add_opts {
            for (k, v) in add {
                self.opts.insert(k.clone(), v.clone());
            }
        }

        if !self.is_enabled() {
            return Ok(());
        }

        // Load filter and merge its options as known/... into the jail section
        let flt_expr = self.opts.get("filter").cloned().unwrap_or_default();
        if !flt_expr.trim().is_empty() {
            let parsed = spec::parse(flt_expr.trim())?;
            let mut filter_opt = parsed.parameters;
            if let Some(add) = add_opts {
                for (k, v) in add {
                    filter_opt.insert(k.clone(), v.clone());
                }
            }
            let mut reader = FilterReader::new(&self.base, parsed.name, &self.name, filter_opt);
            if !reader.read()? {
                return Err(Error::config(format!(
                    "Unable to read the filter {:?}",
                    parsed.name
                )));
            }
            let backend_val = self
                .opts
                .get("backend")
                .cloned()
                .unwrap_or_else(|| "auto".to_owned());
            reader.apply_auto_options(&backend_val);
            reader.get_options(&self.opts, true)?;
            // Merge filter combined options as `known/<k>` into jail section
            let sec = cfg.sections.entry(self.name.clone()).or_default();
            for (k, v) in reader.combined() {
                if !k.starts_with("known/") {
                    sec.insert(format!("known/{k}"), v.clone());
                }
            }
            self.filter = Some(reader);
        }

        // Second pass: read all jail options with known/... available
        self.opts.clear();
        for &key in JAIL_ALL_OPTS {
            if let Some(val) = get_opt(cfg, &self.name, key, None)? {
                self.opts.insert(key.to_owned(), val);
            }
        }
        self.opts
            .entry("enabled".to_owned())
            .or_insert_with(|| "false".to_owned());
        self.opts
            .entry("backend".to_owned())
            .or_insert_with(|| "auto".to_owned());
        self.opts.entry("filter".to_owned()).or_default();
        self.opts.entry("action".to_owned()).or_default();
        if let Some(add) = add_opts {
            for (k, v) in add {
                self.opts.insert(k.clone(), v.clone());
            }
        }

        // Recompute filter options honoring jail overrides
        if let Some(reader) = self.filter.as_mut() {
            reader.get_options(&self.opts, false)?;
        }

        // Parse and load actions
        let action_str = self.opts.get("action").cloned().unwrap_or_default();
        for raw_act in split_with_options(&action_str) {
            let act = raw_act.trim();
            if act.is_empty() {
                continue;
            }
            let parsed = spec::parse(act)?;
            let mut act_opt = parsed.parameters;
            if parsed.name.ends_with(".py") {
                let act_name = act_opt.remove("actname").unwrap_or_else(|| {
                    parsed
                        .name
                        .strip_suffix(".py")
                        .unwrap_or(parsed.name)
                        .to_owned()
                });
                let full_path = self.base.join("action.d").join(parsed.name);
                let json_opts = serde_json::to_string(&act_opt)
                    .map_err(|e| Error::config(format!("serializing action options: {e}")))?;
                self.actions.push(JailAction::Python {
                    act_name,
                    path: full_path.to_string_lossy().into_owned(),
                    init_json: json_opts,
                });
            } else {
                let mut reader = ActionReader::new(&self.base, parsed.name, &self.name, act_opt);
                if !reader.read()? {
                    return Err(Error::config(format!(
                        "Unable to read action {:?}",
                        parsed.name
                    )));
                }
                reader.get_options(&self.opts)?;
                self.actions.push(JailAction::Conf(Box::new(reader)));
            }
        }

        Ok(())
    }

    pub fn convert(
        &mut self,
        allow_no_files: bool,
        systemd_if_nologs: bool,
    ) -> Result<Vec<PickleValue>> {
        if let Some(err) = &self.config_error {
            return Ok(vec![PickleValue::str_list([
                "config-error",
                &format!(
                    "Jail '{}' skipped, because of wrong configuration: {err}",
                    self.name
                ),
            ])]);
        }

        let mut stream: Vec<PickleValue> = Vec::new();
        let mut stream_late: Vec<PickleValue> = Vec::new();

        if let Some(flt) = &self.filter {
            stream.extend(flt.convert());
        }
        let jail_maxlines = self
            .opts
            .get("maxlines")
            .and_then(|v| v.trim().parse::<i64>().ok());
        fill_filter_stream(&mut stream, &self.opts, jail_maxlines, &self.name);

        let mut backend = self
            .opts
            .get("backend")
            .cloned()
            .unwrap_or_else(|| "auto".to_owned());

        let has_journalmatch = self.opts.contains_key("journalmatch")
            || self
                .filter
                .as_ref()
                .is_some_and(|f| f.combined().contains_key("journalmatch"));

        for (opt, value) in &self.opts {
            if opt == "logpath" {
                if backend.starts_with("systemd") {
                    continue;
                }
                let mut found_files = 0usize;
                for raw_line in value.lines() {
                    let trimmed = raw_line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let (pattern, tail) = match trimmed.rsplit_once(' ') {
                        Some((p, t)) if matches!(t, "head" | "tail") => (p.trim(), t),
                        _ => (trimmed, "head"),
                    };
                    for matched_path in glob_existing(pattern) {
                        found_files += 1;
                        stream_late.push(PickleValue::str_list([
                            "set",
                            &self.name,
                            "addlogpath",
                            &matched_path,
                            tail,
                        ]));
                    }
                }
                if found_files == 0 {
                    let skip_if_nologs = self
                        .opts
                        .get("skip_if_nologs")
                        .and_then(|v| parse_bool(v).ok())
                        .unwrap_or(false);
                    let jail_systemd_if_nologs = self
                        .opts
                        .get("systemd_if_nologs")
                        .and_then(|v| parse_bool(v).ok())
                        .unwrap_or(true);
                    if backend.starts_with("auto")
                        && systemd_if_nologs
                        && jail_systemd_if_nologs
                        && has_journalmatch
                    {
                        backend = "systemd".to_owned();
                    } else if !allow_no_files && !skip_if_nologs {
                        return Err(Error::config(format!(
                            "Have not found any log file for '{}' jail.",
                            self.name
                        )));
                    } else if skip_if_nologs {
                        let msg = format!(
                            "Jail '{}' skipped, because of missing log files.",
                            self.name
                        );
                        self.runtime_error = Some(msg.clone());
                        return Ok(vec![PickleValue::str_list(["config-error", &msg])]);
                    }
                }
            } else if opt == "ignoreip" {
                let words = split_words(value);
                if !words.is_empty() {
                    let mut cmd = vec![
                        PickleValue::Str("set".to_owned()),
                        PickleValue::Str(self.name.clone()),
                        PickleValue::Str("addignoreip".to_owned()),
                    ];
                    cmd.extend(words.into_iter().map(PickleValue::Str));
                    stream.push(PickleValue::List(cmd));
                }
            } else if !JAIL_IGNORE_STREAM_OPTS.contains(&opt.as_str()) {
                let pval = jail_opt_value(opt, value)?;
                stream.push(PickleValue::List(vec![
                    PickleValue::Str("set".to_owned()),
                    PickleValue::Str(self.name.clone()),
                    PickleValue::Str(opt.clone()),
                    pval,
                ]));
            }
        }

        stream.extend(stream_late);

        for act in &self.actions {
            match act {
                JailAction::Conf(reader) => stream.extend(reader.convert()),
                JailAction::Python {
                    act_name,
                    path,
                    init_json,
                } => {
                    stream.push(PickleValue::str_list([
                        "set",
                        &self.name,
                        "addaction",
                        act_name,
                        path,
                        init_json,
                    ]));
                }
            }
        }

        stream.insert(0, PickleValue::str_list(["add", &self.name, &backend]));
        Ok(stream)
    }
}

fn jail_opt_value(opt: &str, raw: &str) -> Result<PickleValue> {
    match opt {
        "maxretry" | "maxmatches" => {
            let n: i64 = raw
                .trim()
                .parse()
                .map_err(|_| Error::config(format!("invalid integer for {opt}: {raw:?}")))?;
            Ok(PickleValue::Int(n))
        }
        "ignoreself" | "bantime.increment" | "bantime.overalljails" => {
            Ok(PickleValue::Bool(parse_bool(raw)?))
        }
        _ => Ok(PickleValue::Str(raw.to_owned())),
    }
}

/// Reader for all jails in `jail.conf` / `jail.local` / `jail.d/*`.
#[derive(Debug)]
pub struct JailsReader {
    base: PathBuf,
    force_enable: bool,
    config: Option<LayeredConfig>,
    jails: Vec<JailReader>,
}

impl JailsReader {
    pub fn new(base: impl AsRef<Path>, force_enable: bool) -> Self {
        Self {
            base: base.as_ref().to_path_buf(),
            force_enable,
            config: None,
            jails: Vec::new(),
        }
    }

    pub fn read(&mut self) -> Result<bool> {
        self.jails.clear();
        self.config = layers::read(&self.base, "jail")?;
        Ok(self.config.is_some())
    }

    pub fn get_options(&mut self, section: Option<&str>, ignore_wrong: bool) -> Result<bool> {
        let Some(cfg) = self.config.as_ref() else {
            return Ok(false);
        };
        let sections: Vec<String> = match section {
            Some(s) => vec![s.to_owned()],
            None => cfg
                .section_order
                .iter()
                .filter(|s| s.as_str() != "INCLUDES" && !s.starts_with("KNOWN/"))
                .cloned()
                .collect(),
        };
        let mut ok_any = false;
        let mut err_any = false;
        self.jails.clear();
        for sec in sections {
            let mut jail = JailReader::new(&self.base, &sec, self.force_enable);
            if jail.get_options(cfg, None) {
                if jail.is_enabled() {
                    ok_any = true;
                    self.jails.push(jail);
                }
            } else {
                err_any = true;
                self.jails.push(jail);
            }
        }
        Ok((ignore_wrong && ok_any) || !err_any)
    }

    pub fn convert(
        &mut self,
        allow_no_files: bool,
        systemd_if_nologs: bool,
    ) -> Result<Vec<PickleValue>> {
        let mut stream = Vec::new();
        for jail in &mut self.jails {
            stream.extend(jail.convert(allow_no_files, systemd_if_nologs)?);
        }
        for jail in &self.jails {
            if !jail.has_error() {
                stream.push(PickleValue::str_list(["start", jail.name()]));
            }
        }
        Ok(stream)
    }
}

/// Top-level Fail2Ban 1.1.1 configurator (`fail2ban/client/configurator.py`).
#[derive(Debug)]
pub struct Configurator {
    base: PathBuf,
    fail2ban: Fail2banReader,
    jails: JailsReader,
    general_stream: Vec<PickleValue>,
    jails_stream: Vec<PickleValue>,
}

impl Configurator {
    pub fn new(base: impl AsRef<Path>, force_enable: bool) -> Self {
        let base = base.as_ref().to_path_buf();
        Self {
            fail2ban: Fail2banReader::new(&base),
            jails: JailsReader::new(&base, force_enable),
            base,
            general_stream: Vec::new(),
            jails_stream: Vec::new(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base
    }

    pub fn read_early(&mut self) -> Result<()> {
        if !self.fail2ban.read()? {
            return Err(Error::config(format!(
                "Read fail2ban configuration failed in {}",
                self.base.display()
            )));
        }
        Ok(())
    }

    pub fn read_all(&mut self) -> Result<()> {
        self.read_early()?;
        if !self.jails.read()? {
            return Err(Error::config(format!(
                "Read jails configuration failed in {}",
                self.base.display()
            )));
        }
        Ok(())
    }

    pub fn get_early_options(&self) -> Result<EarlyOptions> {
        self.fail2ban.get_early_options()
    }

    pub fn get_options(
        &mut self,
        jail: Option<&str>,
        update_main: Option<&Options>,
        ignore_wrong: bool,
    ) -> Result<bool> {
        self.fail2ban.get_options(update_main)?;
        self.jails.get_options(jail, ignore_wrong)
    }

    pub fn convert_to_protocol(&mut self, allow_no_files: bool) -> Result<()> {
        self.general_stream = self.fail2ban.convert();
        self.jails_stream = self.jails.convert(allow_no_files, true)?;
        Ok(())
    }

    pub fn get_config_stream(&self) -> Vec<PickleValue> {
        let mut out = Vec::with_capacity(self.general_stream.len() + self.jails_stream.len());
        out.extend(self.general_stream.iter().cloned());
        out.extend(self.jails_stream.iter().cloned());
        out
    }

    pub fn get_jails_stream(&self) -> Vec<PickleValue> {
        self.jails_stream.clone()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers shared by FilterReader, ActionReader, JailReader
// ---------------------------------------------------------------------------

fn get_opt(
    config: &LayeredConfig,
    section: &str,
    key: &str,
    vars: Option<&Options>,
) -> Result<Option<String>> {
    interp::get_effective(
        section,
        key,
        &config.defaults,
        |name| config.sections.get(name),
        vars,
    )
    .map_err(|e| Error::config(e.to_string()))
}

fn conditional_option(key: &str) -> Option<(&str, &str)> {
    key.split_once('?').filter(|(base, cond)| {
        !base.is_empty()
            && !cond.is_empty()
            && base.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
    })
}

/// Merge conditional sections such as `[Init?family=inet6]` or `[Definition?family=inet6]`
/// into `[Init]` / `[Definition]` as `opt?family=inet6`, matching upstream `ConfigReader`.
fn flatten_conditional_sections(cfg: &mut LayeredConfig) {
    let cond_sections: Vec<(String, String, String, Options)> = cfg
        .sections
        .iter()
        .filter_map(|(name, opts)| {
            let (base, cond) = name.split_once('?')?;
            if base == "Definition" || base == "Init" {
                Some((name.clone(), base.to_owned(), cond.to_owned(), opts.clone()))
            } else {
                None
            }
        })
        .collect();
    for (_, base, cond, opts) in cond_sections {
        let target = cfg.sections.entry(base).or_default();
        for (k, v) in opts {
            target.insert(format!("{k}?{cond}"), v);
        }
    }
}

fn resolve_definition_init(
    config: &LayeredConfig,
    definition_keys: &[&str],
    jail_opts: &Options,
    call_opts: &Options,
    all: bool,
    ignore_tags: &[&str],
) -> Result<ResolvedFilter> {
    let mut init = call_opts.clone();
    let mut preselected = jail_opts.clone();
    preselected.extend(init.clone());

    let mut options = Options::new();
    for &key in definition_keys {
        if !preselected.contains_key(key)
            && let Some(value) = get_opt(config, "Definition", key, Some(&preselected))?
        {
            options.insert(key.to_owned(), value);
        }
    }

    if let Some(section) = config.sections.get("Init") {
        for key in section.keys().filter(|k| k.as_str() != "__name__") {
            let mut value = None;
            if !key.starts_with("known/") {
                value = get_opt(config, "Init", key, None)?;
                if let Some(original) = value.as_ref() {
                    init.insert(format!("known/{key}"), original.clone());
                }
            }
            if !init.contains_key(key) {
                if let Some((base, _)) = conditional_option(key) {
                    value = preselected.get(base).cloned().or(value);
                }
                if value.is_none() {
                    value = get_opt(config, "Init", key, None)?;
                }
                if let Some(v) = value {
                    init.insert(key.clone(), v);
                }
            }
        }
    }

    if all && let Some(definition) = config.sections.get("Definition") {
        for key in definition.keys() {
            if key != "__name__"
                && !options.contains_key(key)
                && let Some(value) = get_opt(config, "Definition", key, None)?
            {
                options.insert(key.clone(), value);
            }
        }
    }

    options.extend(init);

    let mut ignored: BTreeSet<&str> = options
        .keys()
        .filter_map(|k| conditional_option(k).map(|(base, _)| base))
        .collect();
    for &t in ignore_tags {
        ignored.insert(t);
    }

    let mut angle_fallbacks: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut final_options = Options::new();
    for (key, raw) in &options {
        if ignored.contains(key.as_str()) {
            final_options.insert(key.clone(), raw.clone());
            continue;
        }
        let mut interp_err = None;
        let expanded = tags::expand(raw, |tag| {
            if interp_err.is_some() || ignored.contains(tag) {
                return None;
            }
            if let Some(v) = options.get(tag) {
                return Some(v.clone());
            }
            if let Some(v) = angle_fallbacks.get(tag) {
                return v.clone();
            }
            match interp::get_extended(
                "Definition",
                tag,
                &config.defaults,
                |name| config.sections.get(name),
                Some(&preselected),
            ) {
                Ok(v) => {
                    angle_fallbacks.insert(tag.to_owned(), v.clone());
                    v
                }
                Err(e) => {
                    interp_err = Some(e);
                    None
                }
            }
        });
        if let Some(err) = interp_err {
            return Err(Error::config(err.to_string()));
        }
        let val = expanded.map_err(|e| Error::config(format!("option {key}: {e}")))?;
        final_options.insert(key.clone(), val);
    }

    let maxlines = final_options
        .remove("maxlines")
        .and_then(|v| v.trim().replace('_', "").parse::<i64>().ok());

    Ok(ResolvedFilter {
        options: final_options,
        maxlines,
    })
}

fn fill_filter_stream(
    stream: &mut Vec<PickleValue>,
    opts: &Options,
    maxlines: Option<i64>,
    jail_name: &str,
) {
    let mut prio0_idx = 0usize;
    if let Some(ml) = maxlines {
        stream.insert(
            prio0_idx,
            PickleValue::List(vec![
                PickleValue::Str("set".to_owned()),
                PickleValue::Str(jail_name.to_owned()),
                PickleValue::Str("maxlines".to_owned()),
                PickleValue::Int(ml),
            ]),
        );
        prio0_idx += 1;
    }
    for &key in FILTER_OPTIONS {
        if key == "maxlines" {
            continue;
        }
        let Some(value) = opts.get(key) else {
            continue;
        };
        match key {
            "failregex" | "ignoreregex" => {
                let multi: Vec<PickleValue> = value
                    .split('\n')
                    .filter(|l| !l.is_empty())
                    .map(|l| PickleValue::Str(l.to_owned()))
                    .collect();
                let cmd_name = format!("add{key}");
                if multi.len() > 1 {
                    stream.push(PickleValue::List(vec![
                        PickleValue::Str("multi-set".to_owned()),
                        PickleValue::Str(jail_name.to_owned()),
                        PickleValue::Str(cmd_name),
                        PickleValue::List(multi),
                    ]));
                } else if let Some(single) = multi.into_iter().next() {
                    stream.push(PickleValue::List(vec![
                        PickleValue::Str("set".to_owned()),
                        PickleValue::Str(jail_name.to_owned()),
                        PickleValue::Str(cmd_name),
                        single,
                    ]));
                }
            }
            "usedns" | "prefregex" => {
                let idx = if key == "usedns" { 0 } else { prio0_idx };
                stream.insert(idx, PickleValue::str_list(["set", jail_name, key, value]));
                prio0_idx += 1;
            }
            "datepattern" => {
                if !value.is_empty() {
                    stream.push(PickleValue::str_list(["set", jail_name, key, value]));
                }
            }
            "journalmatch" => {
                for line in value.split('\n') {
                    if line.is_empty() {
                        continue;
                    }
                    let mut cmd = vec![
                        PickleValue::Str("set".to_owned()),
                        PickleValue::Str(jail_name.to_owned()),
                        PickleValue::Str("addjournalmatch".to_owned()),
                    ];
                    cmd.extend(shlex_split(line).into_iter().map(PickleValue::Str));
                    stream.push(PickleValue::List(cmd));
                }
            }
            _ => {}
        }
    }
}

/// Split words on whitespace or commas (`fail2ban.helpers.splitwords`).
pub fn split_words(input: &str) -> Vec<String> {
    input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Split multi-line action definitions respecting `[...]` option brackets (`splitWithOptions`).
pub fn split_with_options(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut bracket_depth: usize = 0;
    let mut quote: Option<char> = None;

    for ch in input.chars() {
        match quote {
            Some(q) => {
                cur.push(ch);
                if ch == q {
                    quote = None;
                }
            }
            None => match ch {
                '\'' | '"' if bracket_depth > 0 => {
                    quote = Some(ch);
                    cur.push(ch);
                }
                '[' => {
                    bracket_depth += 1;
                    cur.push(ch);
                }
                ']' => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                    cur.push(ch);
                }
                '\n' if bracket_depth == 0 => {
                    let trimmed = cur.trim();
                    if !trimmed.is_empty() {
                        out.push(trimmed.to_owned());
                    }
                    cur.clear();
                }
                _ => cur.push(ch),
            },
        }
    }
    let trimmed = cur.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_owned());
    }
    out
}

/// Minimal POSIX `shlex.split` for `journalmatch` tokens.
pub fn shlex_split(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            Some('"') => {
                if ch == '"' {
                    quote = None;
                } else if ch == '\\' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else {
                    cur.push(ch);
                }
            }
            Some(_) => unreachable!(),
            None => match ch {
                c if c.is_whitespace() => {
                    if in_token {
                        out.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                }
                '\'' | '"' => {
                    quote = Some(ch);
                    in_token = true;
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                        in_token = true;
                    }
                }
                _ => {
                    cur.push(ch);
                    in_token = true;
                }
            },
        }
    }
    if in_token {
        out.push(cur);
    }
    out
}

/// Pure-Rust filesystem glob matching `JailReader._glob` (skips dangling symlinks).
pub(crate) fn glob_existing(pattern: &str) -> Vec<String> {
    if !pattern.contains(['*', '?', '[']) {
        let p = Path::new(pattern);
        return if p.exists() {
            vec![pattern.to_owned()]
        } else {
            Vec::new()
        };
    }

    let is_abs = pattern.starts_with('/');
    let parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut current: Vec<PathBuf> = vec![if is_abs {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    }];

    for part in parts {
        let mut next = Vec::new();
        let has_wild = part.contains(['*', '?', '[']);
        for base in current {
            if !has_wild {
                let cand = base.join(part);
                if cand.exists() {
                    next.push(cand);
                }
            } else if let Ok(entries) = fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.') && !part.starts_with('.') {
                        continue;
                    }
                    if glob_match(part, &name_str) {
                        let cand = entry.path();
                        if cand.exists() {
                            next.push(cand);
                        }
                    }
                }
            }
        }
        current = next;
    }

    let mut res: Vec<String> = current
        .into_iter()
        .map(|p| {
            let s = p.to_string_lossy().into_owned();
            if !is_abs {
                s.strip_prefix("./").unwrap_or(&s).to_owned()
            } else {
                s
            }
        })
        .collect();
    res.sort();
    res
}

fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_slice(&p, &t)
}

fn glob_match_slice(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        '*' => {
            if glob_match_slice(&p[1..], t) {
                return true;
            }
            !t.is_empty() && glob_match_slice(p, &t[1..])
        }
        '?' => !t.is_empty() && glob_match_slice(&p[1..], &t[1..]),
        '[' => {
            if t.is_empty() {
                return false;
            }
            if let Some(end) = p[1..].iter().position(|&c| c == ']') {
                let class = &p[1..1 + end];
                let (neg, body) = match class.first() {
                    Some('!' | '^') => (true, &class[1..]),
                    _ => (false, class),
                };
                let ch = t[0];
                let mut matched = false;
                let mut i = 0;
                while i < body.len() {
                    if i + 2 < body.len() && body[i + 1] == '-' {
                        if ch >= body[i] && ch <= body[i + 2] {
                            matched = true;
                        }
                        i += 3;
                    } else {
                        if ch == body[i] {
                            matched = true;
                        }
                        i += 1;
                    }
                }
                if matched != neg {
                    return glob_match_slice(&p[2 + end..], &t[1..]);
                }
                return false;
            }
            t[0] == '[' && glob_match_slice(&p[1..], &t[1..])
        }
        c => !t.is_empty() && t[0] == c && glob_match_slice(&p[1..], &t[1..]),
    }
}
