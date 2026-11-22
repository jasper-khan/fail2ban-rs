//! Fail2Ban 1.1.1 regex testing tool (`fail2ban/client/fail2banregex.py`).

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use chrono::{Local, TimeZone};

use crate::VERSION;
use crate::config::{FilterReader, JailReader, layers, shlex_split, spec};
use crate::date::strptime::set_alternate_year;
use crate::error::{Error, Result};
use crate::filter::backend::systemd::{build_journalctl_args, format_journal_entry};
use crate::filter::backend::{JournalConfig, expand_journal_files};
use crate::filter::ipdns::UseDns;
use crate::filter::regex::FailRegex;
use crate::filter::{Filter, LogEncoding, MatchResult};
use crate::logging::{LogLevel, set_level};
use crate::protocol::PickleValue;

const DEFAULT_CONFIG_DIR: &str = "/etc/fail2ban";
const DEFAULT_DISPLAY_MAXLINES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexCliOptions {
    pub config: PathBuf,
    pub datepattern: Option<String>,
    pub timezone: Option<String>,
    pub encoding: String,
    pub raw: bool,
    pub usedns: Option<String>,
    pub maxlines: usize,
    pub journalmatch: Option<String>,
    pub log_level: String,
    pub verbose: i32,
    pub verbose_date: bool,
    pub debuggex: bool,
    pub check_all_regex: bool,
    pub out: Option<String>,
    pub invert: bool,
    pub print_no_missed: bool,
    pub print_no_ignored: bool,
    pub print_all_matched: bool,
    pub print_all_missed: bool,
    pub print_all_ignored: bool,
    pub log_traceback: bool,
    pub full_traceback: bool,
}

impl Default for RegexCliOptions {
    fn default() -> Self {
        Self {
            config: PathBuf::from(DEFAULT_CONFIG_DIR),
            datepattern: None,
            timezone: None,
            encoding: "auto".to_owned(),
            raw: false,
            usedns: None,
            maxlines: 0,
            journalmatch: None,
            log_level: "critical".to_owned(),
            verbose: 0,
            verbose_date: false,
            debuggex: false,
            check_all_regex: true,
            out: None,
            invert: false,
            print_no_missed: false,
            print_no_ignored: false,
            print_all_matched: false,
            print_all_missed: false,
            print_all_ignored: false,
            log_traceback: false,
            full_traceback: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexCliAction {
    Help,
    Version {
        short: bool,
    },
    Run {
        opts: Box<RegexCliOptions>,
        log: String,
        regex: String,
        ignore_regex: Option<String>,
    },
}

/// Parse `fail2ban-regex` command-line flags and positional `<LOG> <REGEX> [IGNOREREGEX]`.
pub fn parse_cli(args: &[String]) -> Result<RegexCliAction> {
    let mut opts = RegexCliOptions::default();
    let mut positional = Vec::new();
    let mut idx = 0usize;
    let mut after_double_dash = false;

    while idx < args.len() {
        let arg = &args[idx];
        if !after_double_dash && arg == "--" {
            after_double_dash = true;
            idx += 1;
            continue;
        }
        if !after_double_dash && arg.starts_with("--") {
            let body = &arg[2..];
            let (name, inline_val) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (body, None),
            };
            match name {
                "help" => return Ok(RegexCliAction::Help),
                "version" => return Ok(RegexCliAction::Version { short: false }),
                "raw" => opts.raw = true,
                "verbose" => opts.verbose = opts.verbose.saturating_add(1),
                "verbose-date" | "VD" => opts.verbose_date = true,
                "debuggex" => opts.debuggex = true,
                "no-check-all" => opts.check_all_regex = false,
                "invert" => opts.invert = true,
                "print-no-missed" => opts.print_no_missed = true,
                "print-no-ignored" => opts.print_no_ignored = true,
                "print-all-matched" => opts.print_all_matched = true,
                "print-all-missed" => opts.print_all_missed = true,
                "print-all-ignored" => opts.print_all_ignored = true,
                "log-traceback" => opts.log_traceback = true,
                "full-traceback" => opts.full_traceback = true,
                "config" => {
                    opts.config = PathBuf::from(take_long_val(name, inline_val, args, &mut idx)?);
                }
                "datepattern" => {
                    opts.datepattern = Some(take_long_val(name, inline_val, args, &mut idx)?);
                }
                "timezone" | "TZ" => {
                    opts.timezone = Some(take_long_val(name, inline_val, args, &mut idx)?);
                }
                "encoding" => {
                    opts.encoding = take_long_val(name, inline_val, args, &mut idx)?;
                }
                "usedns" => {
                    opts.usedns = Some(take_long_val(name, inline_val, args, &mut idx)?);
                }
                "maxlines" => {
                    let raw = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.maxlines = raw.trim().parse::<usize>().map_err(|_| {
                        Error::Value(format!("option --maxlines: invalid integer value: {raw:?}"))
                    })?;
                }
                "journalmatch" => {
                    opts.journalmatch = Some(take_long_val(name, inline_val, args, &mut idx)?);
                }
                "log-level" => {
                    opts.log_level = take_long_val(name, inline_val, args, &mut idx)?;
                }
                "verbosity" => {
                    let raw = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.verbose = raw.trim().parse::<i32>().map_err(|_| {
                        Error::Value(format!(
                            "option --verbosity: invalid integer value: {raw:?}"
                        ))
                    })?;
                }
                "out" => {
                    opts.out = Some(take_long_val(name, inline_val, args, &mut idx)?);
                }
                _ => {
                    return Err(Error::Value(format!("no such option: --{name}")));
                }
            }
            idx += 1;
            continue;
        }

        if !after_double_dash && arg.starts_with('-') && arg != "-" {
            let rest = &arg[1..];
            for (byte_off, ch) in rest.char_indices() {
                match ch {
                    'h' => return Ok(RegexCliAction::Help),
                    'V' => return Ok(RegexCliAction::Version { short: true }),
                    'r' => opts.raw = true,
                    'v' => opts.verbose = opts.verbose.saturating_add(1),
                    'D' => opts.debuggex = true,
                    'i' => opts.invert = true,
                    't' => opts.log_traceback = true,
                    'c' | 'd' | 'e' | 'L' | 'm' | 'l' | 'o' => {
                        let after = &rest[byte_off + ch.len_utf8()..];
                        let val = if !after.is_empty() {
                            after.to_owned()
                        } else {
                            idx += 1;
                            args.get(idx).cloned().ok_or_else(|| {
                                Error::Value(format!("-{ch} option requires 1 argument"))
                            })?
                        };
                        match ch {
                            'c' => opts.config = PathBuf::from(val),
                            'd' => opts.datepattern = Some(val),
                            'e' => opts.encoding = val,
                            'L' => {
                                opts.maxlines = val.trim().parse::<usize>().map_err(|_| {
                                    Error::Value(format!(
                                        "option -L: invalid integer value: {val:?}"
                                    ))
                                })?;
                            }
                            'm' => opts.journalmatch = Some(val),
                            'l' => opts.log_level = val,
                            'o' => opts.out = Some(val),
                            _ => {}
                        }
                        break;
                    }
                    _ => {
                        return Err(Error::Value(format!("no such option: -{ch}")));
                    }
                }
            }
            idx += 1;
            continue;
        }

        positional.push(arg.clone());
        idx += 1;
    }

    let mut errors = Vec::new();
    if opts.print_no_missed && opts.print_all_missed {
        errors.push("ERROR: --print-no-missed and --print-all-missed are mutually exclusive.");
    }
    if opts.print_no_ignored && opts.print_all_ignored {
        errors.push("ERROR: --print-no-ignored and --print-all-ignored are mutually exclusive.");
    }
    if positional.len() != 2 && positional.len() != 3 {
        errors.push("ERROR: provide both <LOG> and <REGEX>.");
    }
    if !errors.is_empty() {
        return Err(Error::invalid_command(errors.join("\n")));
    }

    let log = positional.remove(0);
    let regex = positional.remove(0);
    let ignore_regex = positional.into_iter().next();

    Ok(RegexCliAction::Run {
        opts: Box::new(opts),
        log,
        regex,
        ignore_regex,
    })
}

fn take_long_val(
    name: &str,
    inline_val: Option<&str>,
    args: &[String],
    idx: &mut usize,
) -> Result<String> {
    if let Some(v) = inline_val {
        return Ok(v.to_owned());
    }
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| Error::Value(format!("--{name} option requires 1 argument")))
}

#[derive(Debug, Clone)]
pub struct RegexStat {
    pub pattern: String,
    pub hits: usize,
    pub matches: Vec<(String, f64, bool)>,
}

impl RegexStat {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            hits: 0,
            matches: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LineStats {
    pub tested: usize,
    pub matched: usize,
    pub ignored: usize,
    pub missed: usize,
    pub matched_lines: Vec<String>,
    pub ignored_lines: Vec<String>,
    pub missed_lines: Vec<String>,
    pub matched_lines_debuggex: Vec<String>,
    pub ignored_lines_debuggex: Vec<String>,
    pub missed_lines_debuggex: Vec<String>,
}

/// Stateful runner mirroring `fail2ban.client.fail2banregex.Fail2banRegex`.
pub struct Fail2banRegex {
    opts: RegexCliOptions,
    filter: Filter,
    pref_matched: usize,
    pref_groups: Vec<BTreeMap<String, String>>,
    fail_stats: Vec<RegexStat>,
    ignore_stats: Vec<RegexStat>,
    line_stats: LineStats,
    journal_matches: Vec<Vec<String>>,
    backend: String,
    encoding: LogEncoding,
    display_maxlines: usize,
    maxlines_set: bool,
    datepattern_set: bool,
    elapsed_secs: Option<f64>,
    header_lines: Vec<String>,
}

impl Fail2banRegex {
    pub fn new(opts: RegexCliOptions) -> Result<Self> {
        // Upstream calls MyTime.setAlternateNow(0) so %ExY/%Exy match historical log dates.
        set_alternate_year(Some(1970));

        let file_enc = LogEncoding::parse(&opts.encoding)?;
        let mut filter = Filter::new("fail2ban-regex");
        filter.set_check_find_time(false);
        filter.set_ignore_self(false);
        filter.set_return_raw_host(opts.raw);
        filter.set_check_all_regex(opts.check_all_regex && opts.out.is_none());
        filter.set_ignore_pending(opts.out.is_some());
        filter.set_log_encoding(file_enc);

        if let Some(ref tz) = opts.timezone {
            filter.set_log_timezone(Some(tz))?;
        }
        if let Some(ref ud) = opts.usedns {
            let _ = filter.set_use_dns_str(ud)?;
        }

        let mut header_lines = Vec::new();
        let mut maxlines_set = false;
        let display_maxlines = if opts.maxlines > 0 {
            filter.set_max_lines(opts.maxlines)?;
            maxlines_set = true;
            if opts.out.is_none() {
                header_lines.push(format!("Use         maxlines : {}", filter.max_lines()));
            }
            opts.maxlines
        } else {
            DEFAULT_DISPLAY_MAXLINES
        };

        let mut datepattern_set = false;
        if let Some(ref dp) = opts.datepattern {
            filter
                .set_date_pattern(Some(dp))
                .map_err(|e| Error::config(format!("Failed to set datepattern: {e}")))?;
            datepattern_set = true;
            if opts.out.is_none() {
                let desc = filter.date_pattern().map_or_else(String::new, |(_, d)| d);
                header_lines.push(format!("Use      datepattern : {dp} : {desc}"));
            }
        }

        let journal_matches = match &opts.journalmatch {
            Some(jm) => parse_journal_groups(&shlex_split(jm)),
            None => Vec::new(),
        };

        Ok(Self {
            opts,
            filter,
            pref_matched: 0,
            pref_groups: Vec::new(),
            fail_stats: Vec::new(),
            ignore_stats: Vec::new(),
            line_stats: LineStats::default(),
            journal_matches,
            backend: "auto".to_owned(),
            encoding: file_enc,
            display_maxlines,
            maxlines_set,
            datepattern_set,
            elapsed_secs: None,
            header_lines,
        })
    }

    pub fn set_backend(&mut self, backend: &str) {
        self.backend = backend.to_owned();
    }

    pub fn stats(&self) -> &LineStats {
        &self.line_stats
    }

    pub fn fail_stats(&self) -> &[RegexStat] {
        &self.fail_stats
    }

    pub fn ignore_stats(&self) -> &[RegexStat] {
        &self.ignore_stats
    }

    fn push_header(&mut self, line: String) {
        if self.opts.out.is_none() {
            self.header_lines.push(line);
        }
    }

    fn set_stream_datepattern(&mut self, pat: &str) -> Result<()> {
        if !self.datepattern_set {
            self.filter
                .set_date_pattern(Some(pat))
                .map_err(|e| Error::config(format!("Failed to set datepattern: {e}")))?;
            self.datepattern_set = true;
            let desc = self
                .filter
                .date_pattern()
                .map_or_else(String::new, |(_, d)| d);
            self.push_header(format!("Use      datepattern : {pat} : {desc}"));
        }
        Ok(())
    }

    fn set_stream_maxlines(&mut self, maxlines: usize) -> Result<()> {
        if !self.maxlines_set {
            self.filter.set_max_lines(maxlines)?;
            self.maxlines_set = true;
            self.push_header(format!(
                "Use         maxlines : {}",
                self.filter.max_lines()
            ));
        }
        Ok(())
    }

    /// Load a failregex / jail / filter spec, or an optional ignoreregex line.
    pub fn read_regex(&mut self, value: &str, is_fail: bool) -> Result<()> {
        let mut reader_cmds: Option<Vec<PickleValue>> = None;

        if is_fail && looks_like_filter_spec(value) {
            let parsed = spec::parse(value).map_err(|e| {
                Error::config(format!(
                    "Wrong filter name or options: {e}\n       while parsing: {value}"
                ))
            })?;
            let flt_name = parsed.name;
            let mut flt_opt = parsed.parameters;

            let is_jail_candidate = !flt_name.contains('/')
                && !flt_name.ends_with(".conf")
                && !flt_name.ends_with(".local");
            let mut loaded_jail = false;

            if is_jail_candidate
                && let Ok(Some(cfg)) = layers::read(&self.opts.config, "jail")
                && cfg.sections.contains_key(flt_name)
                && flt_name != "INCLUDES"
                && !flt_name.starts_with("KNOWN/")
            {
                loaded_jail = true;
                self.push_header(format!("Use {:>11} jail : {flt_name}", ""));
                if !flt_opt.is_empty() {
                    self.push_header(format!("Use jail/flt options : {flt_opt:?}"));
                }
                flt_opt.insert("backend".to_owned(), self.backend.clone());
                let mut jail = JailReader::new(&self.opts.config, flt_name, true);
                if !jail.get_options(&cfg, Some(&flt_opt)) {
                    return Err(Error::config(format!("Failed to get jail for {value:?}")));
                }
                reader_cmds = Some(jail.convert(true, true)?);
            }

            if !loaded_jail && let Some(flt_file) = resolve_filter_file(&self.opts.config, flt_name)
            {
                let (base_dir, stem, inside_conf) =
                    classify_filter_file(&self.opts.config, flt_name, &flt_file);
                if inside_conf {
                    self.push_header(format!(
                        "Use {:>11} file : {stem}, basedir: {}",
                        "filter",
                        base_dir.display()
                    ));
                } else {
                    self.push_header(format!("Use {:>11} file : {flt_name}", "filter"));
                }
                if !flt_opt.is_empty() {
                    self.push_header(format!("Use   filter options : {flt_opt:?}"));
                }
                let mut reader = if inside_conf {
                    let mut r = FilterReader::new(&base_dir, &stem, "fail2ban-regex-jail", flt_opt);
                    if !r.read()? {
                        return Err(Error::config(format!("failed to load filter {value}")));
                    }
                    r
                } else {
                    let parent = flt_file.parent().unwrap_or_else(|| Path::new("."));
                    let abs_file = if flt_file.is_absolute() {
                        flt_file.clone()
                    } else {
                        std::env::current_dir()
                            .map(|d| d.join(&flt_file))
                            .unwrap_or_else(|_| flt_file.clone())
                    };
                    let mut r = FilterReader::new(parent, &stem, "fail2ban-regex-jail", flt_opt);
                    if !r.read_path(&abs_file)? {
                        return Err(Error::config(format!("failed to load filter {value}")));
                    }
                    r
                };
                reader.apply_auto_options(&self.backend);
                reader.get_options(&BTreeMap::new(), false)?;
                reader_cmds = Some(reader.convert());
            }
        } else if !is_fail && !self.ignore_stats.is_empty() {
            self.filter.del_ignore_regex(None);
            self.ignore_stats.clear();
        }

        if let Some(cmds) = reader_cmds {
            let mut fail_patterns = Vec::new();
            let mut ignore_patterns = Vec::new();
            let mut jm_tokens = Vec::new();

            for cmd in cmds {
                let Some(parts) = cmd.as_list() else {
                    continue;
                };
                let op = parts.first().and_then(PickleValue::as_str).unwrap_or("");
                let key = parts.get(2).and_then(PickleValue::as_str).unwrap_or("");
                let vals: Vec<&PickleValue> = match op {
                    "multi-set" => parts
                        .get(3)
                        .and_then(PickleValue::as_list)
                        .map_or_else(Vec::new, |s| s.iter().collect()),
                    "set" => parts.get(3..).map_or_else(Vec::new, |s| s.iter().collect()),
                    _ => Vec::new(),
                };
                match key {
                    "prefregex" => {
                        for v in vals {
                            if let Some(pat) = v.as_str() {
                                self.filter.set_prefregex(Some(pat))?;
                            }
                        }
                    }
                    "addfailregex" => {
                        for v in vals {
                            if let Some(pat) = v.as_str() {
                                fail_patterns.push(pat.to_owned());
                            }
                        }
                    }
                    "addignoreregex" => {
                        for v in vals {
                            if let Some(pat) = v.as_str() {
                                ignore_patterns.push(pat.to_owned());
                            }
                        }
                    }
                    "maxlines" => {
                        for v in vals {
                            if let Some(n) = v.as_i64()
                                && n > 0
                            {
                                self.set_stream_maxlines(n as usize)?;
                            }
                        }
                    }
                    "datepattern" => {
                        for v in vals {
                            if let Some(pat) = v.as_str() {
                                self.set_stream_datepattern(pat)?;
                            }
                        }
                    }
                    "addjournalmatch" => {
                        if self.opts.journalmatch.is_none() {
                            let group: Vec<String> = vals
                                .iter()
                                .filter_map(|v| v.as_str().map(str::to_owned))
                                .collect();
                            if !group.is_empty() {
                                jm_tokens.push(group);
                            }
                        }
                    }
                    _ => {}
                }
            }

            if !jm_tokens.is_empty() && self.opts.journalmatch.is_none() {
                self.journal_matches = jm_tokens;
            }
            for pat in fail_patterns {
                self.filter.add_fail_regex(&pat)?;
                self.fail_stats.push(RegexStat::new(pat));
            }
            for pat in ignore_patterns {
                self.filter.add_ignore_regex(&pat)?;
                self.ignore_stats.push(RegexStat::new(pat));
            }
        } else {
            let kind = if is_fail { "failregex" } else { "ignoreregex" };
            self.push_header(format!("Use {:>11} line : {}", kind, shortstr(value, 53)));
            if is_fail {
                self.filter.add_fail_regex(value)?;
                self.fail_stats.push(RegexStat::new(value));
            } else {
                self.filter.add_ignore_regex(value)?;
                self.ignore_stats.push(RegexStat::new(value));
            }
        }

        Ok(())
    }

    /// Process a sequence of `(line, optional_preset_date)` entries.
    pub fn process_entries<I>(&mut self, entries: I, emit: &mut dyn FnMut(&str))
    where
        I: IntoIterator<Item = (String, Option<f64>)>,
    {
        let start = Instant::now();
        let is_out = self.opts.out.is_some();
        let max_lines = self.filter.max_lines();
        let mut recent_missed: VecDeque<(String, String)> = VecDeque::with_capacity(max_lines + 1);

        for (raw_line, preset_date) in entries {
            let line = if preset_date.is_none() {
                let clean = raw_line.trim_end_matches(['\r', '\n']);
                if clean.is_empty() || clean.starts_with('#') {
                    continue;
                }
                clean.to_owned()
            } else {
                raw_line
            };

            let res = self.filter.process_line_with_info(&line, preset_date);
            if !is_out && let Some(groups) = res.pref_groups {
                self.pref_matched += 1;
                if self.opts.verbose > 0 && self.pref_groups.len() < self.display_maxlines {
                    self.pref_groups.push(groups);
                }
            }

            if is_out {
                let ignored = !res.ignored_by_regex.is_empty() || res.ignored_by_ip;
                let active: Vec<MatchResult> = res
                    .results
                    .into_iter()
                    .filter(|m| !m.data.contains_key("nofail"))
                    .collect();

                if !active.is_empty() && !ignored {
                    if !self.opts.invert {
                        self.emit_out_results(&active, emit);
                    }
                } else if self.opts.invert {
                    let mut data = BTreeMap::new();
                    data.insert("fid".to_owned(), String::new());
                    let synth = MatchResult {
                        regex_idx: usize::MAX,
                        fid: None,
                        ip: None,
                        time: self.filter.last_date(),
                        matches: vec![line],
                        data,
                    };
                    self.emit_out_results(&[synth], emit);
                }
                continue;
            }

            let dbg_line = if self.opts.debuggex {
                if max_lines > 1
                    && res.date_matched
                    && let Some(dt) = self.filter.last_time_text()
                    && let Some(pos) = line.find(dt)
                {
                    format!("{}{}", &line[..pos], &line[pos + dt.len()..])
                } else {
                    line.clone()
                }
            } else {
                String::new()
            };

            let mut is_ignored = res.ignored_by_ip;
            for &ig_idx in &res.ignored_by_regex {
                is_ignored = true;
                if let Some(st) = self.ignore_stats.get_mut(ig_idx) {
                    st.hits += 1;
                }
            }

            let multi = res.results.len() > 1;
            let mut matched_non_nofail = false;
            let mut matched_prior_lines: Vec<String> = Vec::new();
            for m in &res.results {
                if let Some(st) = self.fail_stats.get_mut(m.regex_idx) {
                    st.hits += 1;
                    let id_str = m
                        .fid
                        .as_ref()
                        .or(m.ip.as_ref())
                        .map_or_else(String::new, ToString::to_string);
                    st.matches.push((id_str, m.time, multi));
                }
                if m.data.contains_key("nofail") {
                    is_ignored = true;
                } else {
                    matched_non_nofail = true;
                    if max_lines > 1 && m.matches.len() > 1 {
                        for prev in &m.matches[..m.matches.len() - 1] {
                            matched_prior_lines.push(prev.clone());
                        }
                    }
                }
            }

            if is_ignored {
                self.line_stats.ignored += 1;
                if !self.opts.print_no_ignored
                    && (self.opts.print_all_ignored
                        || self.line_stats.ignored <= self.display_maxlines + 1)
                {
                    self.line_stats.ignored_lines.push(line);
                    if self.opts.debuggex {
                        self.line_stats.ignored_lines_debuggex.push(dbg_line);
                    }
                }
            } else if matched_non_nofail {
                let mut dbg_multiline_parts = Vec::new();
                for prev in matched_prior_lines {
                    if let Some(pos) = recent_missed.iter().position(|(r, _)| r == &prev)
                        && let Some((prev_raw, prev_dbg)) = recent_missed.remove(pos)
                    {
                        self.line_stats.missed = self.line_stats.missed.saturating_sub(1);
                        self.line_stats.matched += 1;
                        if let Some(mpos) = self
                            .line_stats
                            .missed_lines
                            .iter()
                            .position(|s| s == &prev_raw)
                        {
                            self.line_stats.missed_lines.remove(mpos);
                        }
                        if self.opts.debuggex
                            && let Some(dpos) = self
                                .line_stats
                                .missed_lines_debuggex
                                .iter()
                                .position(|s| s == &prev_dbg)
                        {
                            self.line_stats.missed_lines_debuggex.remove(dpos);
                        }
                        if self.opts.print_all_matched {
                            if self.opts.debuggex {
                                dbg_multiline_parts.push(prev_dbg);
                            } else {
                                self.line_stats.matched_lines.push(prev_raw);
                            }
                        }
                    }
                }
                self.line_stats.matched += 1;
                if self.opts.print_all_matched {
                    if self.opts.debuggex {
                        dbg_multiline_parts.push(dbg_line);
                        self.line_stats
                            .matched_lines_debuggex
                            .push(dbg_multiline_parts.join("\n"));
                    } else {
                        self.line_stats.matched_lines.push(line);
                    }
                }
            } else {
                self.line_stats.missed += 1;
                if max_lines > 1 {
                    if recent_missed.len() >= max_lines {
                        recent_missed.pop_front();
                    }
                    recent_missed.push_back((line.clone(), dbg_line.clone()));
                }
                if !self.opts.print_no_missed
                    && (self.opts.print_all_missed
                        || self.line_stats.missed <= self.display_maxlines + 1)
                {
                    self.line_stats.missed_lines.push(line);
                    if self.opts.debuggex {
                        self.line_stats.missed_lines_debuggex.push(dbg_line);
                    }
                }
            }
            self.line_stats.tested += 1;
        }

        self.elapsed_secs = Some(start.elapsed().as_secs_f64());
    }

    fn emit_out_results(&self, results: &[MatchResult], emit: &mut dyn FnMut(&str)) {
        let Some(ofmt) = self.opts.out.as_deref() else {
            return;
        };
        for m in results {
            match ofmt {
                "id" | "fid" => {
                    let s = m
                        .fid
                        .as_ref()
                        .map(ToString::to_string)
                        .or_else(|| m.data.get("fid").cloned())
                        .or_else(|| m.ip.as_ref().map(ToString::to_string))
                        .unwrap_or_default();
                    emit(&s);
                }
                "ip" => {
                    let s =
                        m.ip.as_ref()
                            .or(m.fid.as_ref())
                            .map(ToString::to_string)
                            .or_else(|| m.data.get("ip4").cloned())
                            .or_else(|| m.data.get("ip6").cloned())
                            .unwrap_or_default();
                    emit(&s);
                }
                "msg" => {
                    for line in &m.matches {
                        emit(line);
                    }
                }
                "row" => {
                    let id_str = m
                        .fid
                        .as_ref()
                        .or(m.ip.as_ref())
                        .map(ToString::to_string)
                        .unwrap_or_default();
                    let dict_entries: Vec<(PickleValue, PickleValue)> = m
                        .data
                        .iter()
                        .filter(|(k, _)| k.as_str() != "matches")
                        .map(|(k, v)| (PickleValue::Str(k.clone()), PickleValue::Str(v.clone())))
                        .collect();
                    let row = format!(
                        "[{},\t{},\t{}],",
                        crate::client::beautifier::py_repr(&PickleValue::Str(id_str)),
                        crate::client::beautifier::py_repr(&PickleValue::Float(m.time)),
                        crate::client::beautifier::py_repr(&PickleValue::Dict(dict_entries)),
                    );
                    emit(&row);
                }
                _ if ofmt.contains('<') => {
                    for line in format_out_tags(ofmt, m) {
                        emit(&line);
                    }
                }
                other => {
                    let val = if other == "matches" {
                        m.matches.join("\n")
                    } else {
                        m.data
                            .get(other)
                            .cloned()
                            .unwrap_or_else(|| "None".to_owned())
                    };
                    emit(&val);
                }
            }
        }
    }

    /// Render the complete `Running tests` + `Results` report (empty in `--out` mode).
    pub fn render_report(&self) -> String {
        if self.opts.out.is_some() {
            return String::new();
        }
        let mut lines = vec![
            String::new(),
            "Running tests".to_owned(),
            "=============".to_owned(),
            String::new(),
        ];
        lines.extend(self.header_lines.iter().cloned());
        lines.push(String::new());

        lines.push(String::new());
        lines.push("Results".to_owned());
        lines.push("=======".to_owned());

        if let Some(pref_pat) = self.filter.prefregex() {
            lines.push(String::new());
            lines.push(format!("Prefregex: {} total", self.pref_matched));
            let mut body = vec![pref_pat.to_owned()];
            if self.opts.verbose > 0 {
                for grp in &self.pref_groups {
                    body.push(format!("    {grp:?}"));
                }
            }
            append_pprint_list(&body, None, &mut lines);
        }

        render_regex_section("Failregex", &self.fail_stats, self.opts.verbose, &mut lines);
        render_regex_section(
            "Ignoreregex",
            &self.ignore_stats,
            self.opts.verbose,
            &mut lines,
        );

        let templates = self.filter.date_detector().templates_info();
        lines.push(String::new());
        lines.push("Date template hits:".to_owned());
        let mut date_rows = Vec::new();
        for tmpl in &templates {
            if self.opts.verbose > 0 || tmpl.hits > 0 {
                date_rows.push(format!("[{}] {}", tmpl.hits, tmpl.name));
                if self.opts.verbose_date {
                    let pat = tmpl.pattern.as_deref().unwrap_or("");
                    date_rows.push(format!(
                        "    # weight: {:.3} ({:.3}), pattern: {pat}",
                        tmpl.weight, tmpl.weight
                    ));
                    date_rows.push(format!("    # regex:   {}", tmpl.regex));
                }
            }
        }
        append_pprint_list(&date_rows, Some("[# of hits] date format"), &mut lines);

        lines.push(String::new());
        lines.push(format!(
            "Lines: {} lines, {} ignored, {} matched, {} missed",
            self.line_stats.tested,
            self.line_stats.ignored,
            self.line_stats.matched,
            self.line_stats.missed
        ));
        if let Some(secs) = self.elapsed_secs {
            lines.push(format!("[processed in {secs:.2} sec]"));
        }
        lines.push(String::new());

        if self.opts.print_all_matched {
            let stored = if self.opts.debuggex {
                &self.line_stats.matched_lines_debuggex
            } else {
                &self.line_stats.matched_lines
            };
            self.append_lines_section(
                "Matched",
                "matched",
                self.line_stats.matched,
                stored,
                true,
                true,
                &mut lines,
            );
        }
        if !self.opts.print_no_ignored {
            let stored = if self.opts.debuggex {
                &self.line_stats.ignored_lines_debuggex
            } else {
                &self.line_stats.ignored_lines
            };
            self.append_lines_section(
                "Ignored",
                "ignored",
                self.line_stats.ignored,
                stored,
                self.opts.print_all_ignored,
                false,
                &mut lines,
            );
        }
        if !self.opts.print_no_missed {
            let stored = if self.opts.debuggex {
                &self.line_stats.missed_lines_debuggex
            } else {
                &self.line_stats.missed_lines
            };
            self.append_lines_section(
                "Missed",
                "missed",
                self.line_stats.missed,
                stored,
                self.opts.print_all_missed,
                true,
                &mut lines,
            );
        }

        lines.join("\n")
    }

    #[allow(clippy::too_many_arguments)]
    fn append_lines_section(
        &self,
        cap: &str,
        ltype: &str,
        count: usize,
        stored: &[String],
        print_all: bool,
        use_fail_regexes: bool,
        out: &mut Vec<String>,
    ) {
        if count == 0 {
            return;
        }
        let header = format!("{cap} line(s):");
        if count < self.display_maxlines || print_all {
            if self.opts.debuggex {
                let regexes = if use_fail_regexes {
                    &self.fail_stats
                } else {
                    &self.ignore_stats
                };
                let multiline = self.filter.max_lines() > 1;
                let use_dns = self.filter.use_dns();
                let mut formatted = Vec::new();
                for line in stored {
                    for rx in regexes {
                        let url = debuggex_url(line, &rx.pattern, multiline, use_dns);
                        formatted.push(format!("{} | {} |  {url}", line.trim_end(), rx.pattern));
                    }
                }
                append_pprint_list(&formatted, Some(&header), out);
            } else {
                let trimmed: Vec<String> = stored.iter().map(|s| s.trim_end().to_owned()).collect();
                append_pprint_list(&trimmed, Some(&header), out);
            }
        } else {
            out.push(format!(
                "{header} too many to print.  Use --print-all-{ltype} to print all {count} lines"
            ));
        }
    }

    /// Execute the full `fail2ban-regex` run against `<LOG>`, `<REGEX>`, and optional `[IGNOREREGEX]`.
    pub fn run(&mut self, log_arg: &str, regex_arg: &str, ignore_arg: Option<&str>) -> Result<()> {
        if log_arg.starts_with("systemd-journal") {
            self.set_backend("systemd");
        }

        self.read_regex(regex_arg, true)?;
        if let Some(ig) = ignore_arg {
            self.read_regex(ig, false)?;
        }

        let entries: Vec<(String, Option<f64>)> = if Path::new(log_arg).is_file() {
            self.push_header(format!("Use         log file : {log_arg}"));
            self.push_header(format!(
                "Use         encoding : {}",
                self.filter.log_encoding_name()
            ));
            read_log_file_lines(Path::new(log_arg), self.encoding)?
                .into_iter()
                .map(|l| (l, None))
                .collect()
        } else if log_arg.starts_with("systemd-journal") {
            if self.opts.datepattern.is_none() {
                self.filter.date_detector_mut().clear();
            }
            self.push_header("Use         systemd journal".to_owned());
            self.push_header(format!(
                "Use         encoding : {}",
                self.filter.log_encoding_name()
            ));
            let jcfg = build_journal_config(log_arg, &self.journal_matches)?;
            if !jcfg.matches.is_empty() {
                let joined = jcfg
                    .matches
                    .iter()
                    .map(|g| g.join(" "))
                    .collect::<Vec<_>>()
                    .join(" + ");
                self.push_header(format!("Use    journal match : {joined}"));
            }
            read_journal_entries(&jcfg, self.encoding)?
        } else if self.filter.max_lines() <= 1 && !log_arg.contains('\n') {
            self.push_header(format!(
                "Use      single line : {}",
                shortstr(&log_arg.replace('\n', r"\n"), 53)
            ));
            vec![(log_arg.to_owned(), None)]
        } else {
            let split: Vec<String> = log_arg.split('\n').map(str::to_owned).collect();
            self.push_header(format!("Use      multi line : {} line(s)", split.len()));
            for (i, l) in split.iter().enumerate() {
                if i >= 5 {
                    self.push_header("| ...".to_owned());
                    break;
                }
                self.push_header(format!("| {:>2}: {}", i + 1, shortstr(l, 53)));
            }
            self.push_header("`-".to_owned());
            split.into_iter().map(|l| (l, None)).collect()
        };

        self.process_entries(entries, &mut |line| output(line));

        if self.opts.out.is_none() {
            let report = self.render_report();
            if !report.is_empty() {
                output(&report);
            }
        }
        Ok(())
    }
}

/// Entrypoint called by `src/bin/fail2ban-regex.rs` (returns exit code `0`, `2`, or `255`).
pub fn run_cli(args: Vec<String>) -> i32 {
    let action = match parse_cli(&args) {
        Ok(a) => a,
        Err(Error::Value(e)) => {
            let _ = writeln!(
                io::stderr(),
                "Usage: fail2ban-regex [OPTIONS] <LOG> <REGEX> [IGNOREREGEX]\n\nfail2ban-regex: error: {e}"
            );
            return 2;
        }
        Err(e) => {
            disp_help();
            let _ = writeln!(io::stderr(), "\n{e}");
            return 255;
        }
    };

    match action {
        RegexCliAction::Help => {
            disp_help();
            0
        }
        RegexCliAction::Version { short } => {
            if short {
                output(&norm_version());
            } else {
                output(&format!("fail2ban-regex {VERSION}"));
            }
            0
        }
        RegexCliAction::Run {
            opts,
            log,
            regex,
            ignore_regex,
        } => {
            if let Ok(lvl) = LogLevel::parse(&opts.log_level) {
                set_level(lvl);
            }
            let mut runner = match Fail2banRegex::new(*opts) {
                Ok(r) => r,
                Err(e) => {
                    output(&format!("ERROR: {e}"));
                    return 255;
                }
            };
            if let Err(e) = runner.run(&log, &regex, ignore_regex.as_deref()) {
                if runner.opts.out.is_none() && !runner.header_lines.is_empty() {
                    output("\nRunning tests\n=============\n");
                    for line in &runner.header_lines {
                        output(line);
                    }
                }
                output(&format!("ERROR: {e}"));
                return 255;
            }
            0
        }
    }
}

/// Build a debuggex.com URL matching `fail2banregex.debuggexURL`.
pub fn debuggex_url(sample: &str, regex: &str, multiline: bool, use_dns: UseDns) -> String {
    let resolved = FailRegex::resolve_host_tag(regex, use_dns);
    let mut url = format!(
        "https://www.debuggex.com/?re={}&str={}&flavor=python",
        url_encode(&resolved),
        url_encode(sample),
    );
    if multiline {
        url.push_str("&flags=m");
    }
    url
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else if b == b' ' {
            out.push('+');
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn shortstr(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_owned();
    }
    let prefix: String = s.chars().take(max_chars.saturating_sub(3)).collect();
    format!("{prefix}...")
}

fn looks_like_filter_spec(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let head = value.split('[').next().unwrap_or(value);
    if head.is_empty() {
        return false;
    }
    if value.contains('[') && !value.trim_end().ends_with(']') {
        return false;
    }
    let without_slashes = head
        .strip_prefix("///")
        .or_else(|| head.strip_prefix("//"))
        .or_else(|| head.strip_prefix('/'))
        .unwrap_or(head);
    !without_slashes.is_empty()
        && without_slashes
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
}

fn resolve_filter_file(config_dir: &Path, flt_name: &str) -> Option<PathBuf> {
    let has_ext = flt_name.chars().rev().take(6).any(|c| c == '.');
    let candidates: Vec<String> = if has_ext {
        vec![flt_name.to_owned()]
    } else {
        vec![
            flt_name.to_owned(),
            format!("{flt_name}.conf"),
            format!("{flt_name}.local"),
        ]
    };

    for cand in candidates {
        let p = Path::new(&cand);
        let full = if p.parent().is_some_and(|par| par == Path::new("filter.d")) {
            config_dir.join(p)
        } else if !cand.contains('/') {
            if config_dir.file_name().is_some_and(|n| n == "filter.d") {
                config_dir.join(&cand)
            } else {
                config_dir.join("filter.d").join(&cand)
            }
        } else {
            PathBuf::from(&cand)
        };
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn classify_filter_file(
    config_dir: &Path,
    flt_name: &str,
    flt_file: &Path,
) -> (PathBuf, String, bool) {
    let is_filter_d = config_dir.file_name().is_some_and(|n| n == "filter.d");
    let no_slash_short =
        !flt_name.contains('/') && !flt_name.ends_with(".conf") && !flt_name.ends_with(".local");
    let under_filter_d = flt_file
        .parent()
        .is_some_and(|p| p == config_dir.join("filter.d") || (is_filter_d && p == config_dir));

    if under_filter_d || is_filter_d || no_slash_short {
        let base = if is_filter_d {
            config_dir.parent().unwrap_or(config_dir).to_path_buf()
        } else {
            config_dir.to_path_buf()
        };
        let stem = Path::new(flt_name)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| flt_name.to_owned());
        (base, stem, true)
    } else {
        let stem = flt_file
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| flt_name.to_owned());
        (
            flt_file
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            stem,
            false,
        )
    }
}

fn parse_journal_groups(tokens: &[String]) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    for tok in tokens {
        if tok == "+" {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
        } else if !tok.is_empty() {
            current.push(tok.clone());
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

fn build_journal_config(log_arg: &str, matches: &[Vec<String>]) -> Result<JournalConfig> {
    let mut cfg = JournalConfig {
        matches: matches.to_vec(),
        flags: None,
        path: None,
        files: Vec::new(),
        namespace: None,
    };
    if log_arg.contains('[') {
        let parsed = spec::parse(log_arg)?;
        if let Some(flags_str) = parsed.parameters.get("journalflags") {
            cfg.flags = flags_str.trim().parse::<u32>().ok();
        }
        if let Some(path_str) = parsed.parameters.get("journalpath") {
            cfg.path = Some(PathBuf::from(path_str));
        }
        if let Some(files_str) = parsed.parameters.get("journalfiles") {
            cfg.files = expand_journal_files(files_str);
        }
        if let Some(ns_str) = parsed.parameters.get("namespace") {
            let ns = ns_str.trim();
            if !ns.is_empty() {
                cfg.namespace = Some(ns.to_owned());
            }
        }
        if cfg.matches.is_empty()
            && let Some(jm) = parsed.parameters.get("journalmatch")
        {
            cfg.matches = parse_journal_groups(&shlex_split(jm));
        }
    }
    Ok(cfg)
}

fn read_journal_entries(
    cfg: &JournalConfig,
    encoding: LogEncoding,
) -> Result<Vec<(String, Option<f64>)>> {
    let mut args = build_journalctl_args(cfg, None, false);
    args.retain(|a| a != "--follow");
    let out = Command::new("journalctl")
        .args(&args)
        .output()
        .map_err(|e| Error::io("executing journalctl", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::io(
            format!("journalctl exited with {}: {}", out.status, stderr.trim()),
            io::Error::other("journalctl failed"),
        ));
    }
    let mut entries = Vec::new();
    for raw_line in out.stdout.split(|&b| b == b'\n') {
        if raw_line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(raw_line)
            && let Some(entry) = format_journal_entry(&val, encoding)
        {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn read_log_file_lines(path: &Path, encoding: LogEncoding) -> Result<Vec<String>> {
    let mut file =
        File::open(path).map_err(|e| Error::io(format!("opening {}", path.display()), e))?;
    if !encoding.is_utf16() {
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        let mut lines = Vec::new();
        loop {
            buf.clear();
            let n = reader
                .read_until(b'\n', &mut buf)
                .map_err(|e| Error::io(format!("reading {}", path.display()), e))?;
            if n == 0 {
                break;
            }
            if buf.ends_with(b"\n") {
                buf.pop();
            }
            if buf.ends_with(b"\r") {
                buf.pop();
            }
            lines.push(encoding.decode(&buf));
        }
        Ok(lines)
    } else {
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .map_err(|e| Error::io(format!("reading {}", path.display()), e))?;
        let text = encoding.decode(&raw);
        Ok(text
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).to_owned())
            .collect())
    }
}

fn format_out_tags(template: &str, m: &MatchResult) -> Vec<String> {
    let mut has_msg_multiline = false;
    let rendered = substitute_tags(template, m, &mut has_msg_multiline);
    if has_msg_multiline && !m.matches.is_empty() {
        m.matches
            .iter()
            .map(|line| rendered.replace("\0msg\0", line))
            .collect()
    } else {
        vec![rendered]
    }
}

fn substitute_tags(template: &str, m: &MatchResult, has_msg_multiline: &mut bool) -> String {
    let mut out = String::with_capacity(template.len());
    let mut lit_start = 0usize;
    let mut tag_start: Option<usize> = None;

    for (idx, ch) in template.char_indices() {
        match ch {
            '<' => tag_start = Some(idx),
            ' ' => tag_start = None,
            '>' => {
                let Some(open) = tag_start.take() else {
                    continue;
                };
                let Some(name) = template.get(open + 1..idx).filter(|s| !s.is_empty()) else {
                    continue;
                };
                if let Some(repl) = resolve_out_tag(name, m, has_msg_multiline) {
                    if let Some(lit) = template.get(lit_start..open) {
                        out.push_str(lit);
                    }
                    out.push_str(&repl);
                    lit_start = idx + 1;
                }
            }
            _ => {}
        }
    }
    if let Some(tail) = template.get(lit_start..) {
        out.push_str(tail);
    }
    out
}

fn resolve_out_tag(name: &str, m: &MatchResult, has_msg_multiline: &mut bool) -> Option<String> {
    let target = m.ip.as_ref().or(m.fid.as_ref());
    match name {
        "ip" | "IP" => Some(target.map_or_else(String::new, ToString::to_string)),
        "fid" => Some(
            m.fid
                .as_ref()
                .map(ToString::to_string)
                .or_else(|| m.data.get("fid").cloned())
                .unwrap_or_default(),
        ),
        "family" => Some(target.map_or("", |t| t.family()).to_owned()),
        "ip-rev" => Some(target.map_or_else(String::new, |t| t.ip_rev())),
        "cidr" => Some(
            target
                .and_then(|t| t.prefix_len())
                .map_or_else(String::new, |p| p.to_string()),
        ),
        "mask" => Some(target.map_or_else(String::new, |t| t.netmask())),
        "time" => Some(crate::client::beautifier::py_repr(&PickleValue::Float(
            m.time,
        ))),
        "matches" => Some(m.matches.join("\n").replace('\0', r"\x00")),
        "msg" => {
            if m.matches.len() <= 1 {
                Some(m.matches.first().cloned().unwrap_or_default())
            } else {
                *has_msg_multiline = true;
                Some("\0msg\0".to_owned())
            }
        }
        "br" => Some("\n".to_owned()),
        "sp" => Some(" ".to_owned()),
        _ => {
            let suffix = name.strip_prefix("F-")?;
            if suffix.is_empty()
                || !suffix.bytes().all(|b| {
                    b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')
                })
            {
                return None;
            }
            let lower = suffix.to_ascii_lowercase();
            let mapped = match lower.as_str() {
                "id" => "fid",
                "port" => "fport",
                other => other,
            };
            let val = m
                .data
                .get(mapped)
                .or_else(|| m.data.get(&lower))
                .map(|s| s.replace('\0', r"\x00"))
                .unwrap_or_default();
            Some(val)
        }
    }
}

fn render_regex_section(title: &str, stats: &[RegexStat], verbose: i32, out: &mut Vec<String>) {
    let mut total = 0usize;
    let mut items = Vec::new();
    for (idx, st) in stats.iter().enumerate() {
        total += st.hits;
        if st.hits > 0 || verbose > 0 {
            items.push(format!("{:>2}) [{}] {}", idx + 1, st.hits, st.pattern));
        }
        if verbose > 0 {
            for (id, ts, multi) in &st.matches {
                let ts_str = format_ctime(*ts);
                let suffix = if *multi {
                    " (multiple regex matched)"
                } else {
                    ""
                };
                items.push(format!("    {id}  {ts_str}{suffix}"));
            }
        }
    }
    out.push(String::new());
    out.push(format!("{title}: {total} total"));
    append_pprint_list(&items, Some(" #) [# of hits] regular expression"), out);
}

fn append_pprint_list(items: &[String], header: Option<&str>, out: &mut Vec<String>) {
    if items.is_empty() {
        return;
    }
    if let Some(h) = header {
        out.push(format!("|- {h}"));
    }
    for item in items {
        out.push(format!("|  {item}"));
    }
    out.push("`-".to_owned());
}

fn format_ctime(unix_secs: f64) -> String {
    let secs = unix_secs.floor() as i64;
    match Local.timestamp_opt(secs, 0).single() {
        Some(dt) => dt.format("%a %b %d %H:%M:%S %Y").to_string(),
        None => "Thu Jan 01 00:00:00 1970".to_owned(),
    }
}

fn norm_version() -> String {
    VERSION.replace(".fix", "").replace(".dev", ".")
}

fn output(s: &str) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{s}");
    let _ = stdout.flush();
}

fn disp_help() {
    output("Usage: fail2ban-regex [OPTIONS] <LOG> <REGEX> [IGNOREREGEX]");
    output("");
    output("Fail2Ban reads log file that contains password failure report");
    output("and bans the corresponding IP addresses using firewall rules.");
    output("");
    output("This tools can test regular expressions for \"fail2ban\".");
    output("");
    output("LOG:");
    output("  string                a string representing a log line");
    output("  filename              path to a log file (/var/log/auth.log)");
    output("  systemd-journal       search systemd journal, optionally with backend parameters");
    output("                        (systemd-journal[journalflags=1]).");
    output("");
    output("REGEX:");
    output("  string                a string representing a 'failregex'");
    output(
        "  filter                name of jail or filter, optionally with options (sshd[mode=aggressive])",
    );
    output("  filename              path to a filter file (filter.d/sshd.conf)");
    output("");
    output("IGNOREREGEX:");
    output("  string                a string representing an 'ignoreregex'");
    output("");
    output("Options:");
    output("  --version             show program's version number and exit");
    output("  -h, --help            show this help message and exit");
    output("  -c CONFIG, --config=CONFIG");
    output("                        set alternate config directory");
    output("  -d DATEPATTERN, --datepattern=DATEPATTERN");
    output("                        set custom pattern used to match date/times");
    output("  --timezone=TIMEZONE, --TZ=TIMEZONE");
    output("                        set time-zone used by convert time format");
    output("  -e ENCODING, --encoding=ENCODING");
    output("                        File encoding. Default: system locale");
    output("  -r, --raw             Raw hosts, don't resolve dns");
    output("  --usedns=USEDNS       DNS specified replacement of tags <HOST> in regexp");
    output("                        ('yes' - matches all form of hosts, 'no' - IP addresses only)");
    output("  -L MAXLINES, --maxlines=MAXLINES");
    output("                        maxlines for multi-line regex.");
    output("  -m JOURNALMATCH, --journalmatch=JOURNALMATCH");
    output("                        journalctl style matches overriding filter file.");
    output("  -l LOG_LEVEL, --log-level=LOG_LEVEL");
    output("                        Log level for the Fail2Ban logger to use");
    output("  -V                    get version in machine-readable short format");
    output("  -v, --verbose         Increase verbosity");
    output("  --verbosity=VERBOSE   Set numerical level of verbosity (0..4)");
    output("  --verbose-date, --VD  Verbose date patterns/regex in output");
    output("  -D, --debuggex        Produce debuggex.com urls for debugging there");
    output("  --no-check-all        Disable check for all regex's");
    output(
        "  -o OUT, --out=OUT     Set token to print failure information only (row, id, ip, msg, host, ip4, ip6, dns, matches, ...)",
    );
    output("  -i, --invert          Invert the sense of matching, to output non-matching lines.");
    output("  --print-no-missed     Do not print any missed lines");
    output("  --print-no-ignored    Do not print any ignored lines");
    output("  --print-all-matched   Print all matched lines");
    output("  --print-all-missed    Print all missed lines, no matter how many");
    output("  --print-all-ignored   Print all ignored lines, no matter how many");
    output("  -t, --log-traceback   Enrich log-messages with compressed tracebacks");
    output(
        "  --full-traceback      Either to make the tracebacks full, not compressed (as by default)",
    );
    output("");
    output("Report bugs to https://github.com/fail2ban/fail2ban/issues");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parse_cli_options_and_mutual_exclusions() {
        let act = parse_cli(&argv(&[
            "-c",
            "/tmp/f2b",
            "-d",
            "EPOCH",
            "--TZ=UTC",
            "-e",
            "latin1",
            "-rD",
            "--usedns=no",
            "-L",
            "3",
            "--no-check-all",
            "--print-all-matched",
            "-o",
            "ip",
            "-vv",
            "line",
            "sshd[mode=aggressive]",
            "ignore",
        ]))
        .unwrap();
        let RegexCliAction::Run {
            opts,
            log,
            regex,
            ignore_regex,
        } = act
        else {
            panic!("expected Run");
        };
        assert_eq!(opts.config, PathBuf::from("/tmp/f2b"));
        assert_eq!(opts.datepattern.as_deref(), Some("EPOCH"));
        assert_eq!(opts.timezone.as_deref(), Some("UTC"));
        assert_eq!(opts.encoding, "latin1");
        assert!(opts.raw);
        assert!(opts.debuggex);
        assert_eq!(opts.usedns.as_deref(), Some("no"));
        assert_eq!(opts.maxlines, 3);
        assert!(!opts.check_all_regex);
        assert!(opts.print_all_matched);
        assert_eq!(opts.out.as_deref(), Some("ip"));
        assert_eq!(opts.verbose, 2);
        assert_eq!(log, "line");
        assert_eq!(regex, "sshd[mode=aggressive]");
        assert_eq!(ignore_regex.as_deref(), Some("ignore"));

        assert_eq!(
            parse_cli(&argv(&["-V"])).unwrap(),
            RegexCliAction::Version { short: true }
        );
        assert!(
            parse_cli(&argv(&[
                "--print-no-missed",
                "--print-all-missed",
                "a",
                "b"
            ]))
            .is_err()
        );
        assert!(parse_cli(&argv(&["only-one"])).is_err());
    }

    #[test]
    fn inline_regex_stats_ignore_and_report() {
        let opts = RegexCliOptions {
            datepattern: Some(r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?".to_owned()),
            print_all_matched: true,
            print_all_ignored: true,
            ..RegexCliOptions::default()
        };

        let mut runner = Fail2banRegex::new(opts).unwrap();
        let logs = concat!(
            "Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.10\n",
            "Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for health from 192.0.2.11\n",
            "Dec 31 11:59:59 [sshd] accepted login for admin from 192.0.2.12\n",
        );
        runner
            .run(
                logs,
                r"Authentication failure for .*? from <HOST>$",
                Some(r"for health from"),
            )
            .unwrap();

        assert_eq!(runner.stats().tested, 3);
        assert_eq!(runner.stats().matched, 1);
        assert_eq!(runner.stats().ignored, 1);
        assert_eq!(runner.stats().missed, 1);

        let report = runner.render_report();
        assert!(report.contains("Running tests\n============="));
        assert!(report.contains("Results\n======="));
        assert!(report.contains("Failregex: 1 total"));
        assert!(report.contains("Ignoreregex: 1 total"));
        assert!(report.contains("Date template hits:"));
        assert!(report.contains("Lines: 3 lines, 1 ignored, 1 matched, 1 missed"));
        assert!(report.contains("Matched line(s):"));
        assert!(report.contains("Ignored line(s):"));
        assert!(report.contains("Missed line(s):"));
    }

    #[test]
    fn out_modes_tags_row_unknown_and_invert() {
        let opts = RegexCliOptions {
            out: Some("<ip>, <F-USER>, <family>".to_owned()),
            ..RegexCliOptions::default()
        };
        let mut runner = Fail2banRegex::new(opts).unwrap();
        runner
            .read_regex(
                r"Authentication failure for <F-USER>.*?</F-USER> from <ADDR>$",
                true,
            )
            .unwrap();

        let mut emitted = Vec::new();
        runner.process_entries(
            vec![
                ("Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.0".to_owned(), None),
                ("Dec 31 12:00:00 [sshd] ok line".to_owned(), None),
            ],
            &mut |s| emitted.push(s.to_owned()),
        );
        assert_eq!(emitted, vec!["192.0.2.0, kevin, inet4"]);

        let inv_opts = RegexCliOptions {
            out: Some("msg".to_owned()),
            invert: true,
            ..RegexCliOptions::default()
        };
        let mut inv_runner = Fail2banRegex::new(inv_opts).unwrap();
        inv_runner
            .read_regex(
                r"Authentication failure for <F-USER>.*?</F-USER> from <ADDR>$",
                true,
            )
            .unwrap();
        let mut inv_out = Vec::new();
        inv_runner.process_entries(
            vec![
                ("Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.0".to_owned(), None),
                ("Dec 31 12:00:00 [sshd] ok line".to_owned(), None),
            ],
            &mut |s| inv_out.push(s.to_owned()),
        );
        assert_eq!(inv_out, vec!["Dec 31 12:00:00 [sshd] ok line"]);

        // Upstream 1.1.1 has no special `--out=json` branch; unknown keys print `None`.
        let json_opts = RegexCliOptions {
            out: Some("json".to_owned()),
            ..RegexCliOptions::default()
        };
        let mut json_runner = Fail2banRegex::new(json_opts).unwrap();
        json_runner.read_regex(r"from <HOST>$", true).unwrap();
        let mut json_out = Vec::new();
        json_runner.process_entries(
            vec![("Dec 31 11:59:59 bad from 192.0.2.5".to_owned(), None)],
            &mut |s| json_out.push(s.to_owned()),
        );
        assert_eq!(json_out, vec!["None"]);
    }

    #[test]
    fn load_filter_file_with_options_and_debuggex_url() {
        let dir = tempfile::tempdir().unwrap();
        let filter_d = dir.path().join("filter.d");
        std::fs::create_dir_all(&filter_d).unwrap();
        std::fs::write(
            filter_d.join("demo.conf"),
            "[Definition]\nmode = normal\nprefregex = ^\\s*<F-CONTENT>bad .+</F-CONTENT>$\nfailregex = ^\\s*bad <mode> from <HOST>$\nignoreregex = ^\\s*bad .* from 192\\.0\\.2\\.99$\n",
        )
        .unwrap();

        let opts = RegexCliOptions {
            config: dir.path().to_path_buf(),
            datepattern: Some("EPOCH".to_owned()),
            debuggex: true,
            print_all_matched: true,
            ..RegexCliOptions::default()
        };

        let log_path = dir.path().join("demo.log");
        std::fs::write(
            &log_path,
            "1700000000 bad strict from 192.0.2.1\n1700000001 bad strict from 192.0.2.99\n1700000002 benign\nbad strict from 192.0.2.2\n",
        )
        .unwrap();

        let mut runner = Fail2banRegex::new(opts).unwrap();
        runner
            .run(log_path.to_str().unwrap(), "demo[mode=strict]", None)
            .unwrap();

        assert_eq!(runner.stats().tested, 4);
        assert_eq!(runner.stats().matched, 2);
        assert_eq!(runner.stats().ignored, 1);
        assert_eq!(runner.stats().missed, 1);
        assert!(runner.render_report().contains("Prefregex: 3 total"));

        let url = debuggex_url(
            "bad strict from 192.0.2.1",
            "^bad strict from <HOST>$",
            false,
            UseDns::No,
        );
        assert!(url.starts_with("https://www.debuggex.com/?re="));
        assert!(url.contains("&flavor=python"));
        assert!(
            runner
                .render_report()
                .contains("https://www.debuggex.com/?")
        );
    }

    #[test]
    fn multiline_skiplines_backcredits_missed_and_out_row_formats() {
        let dp = Some(r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?".to_owned());
        let rx =
            r"\[sshd\] step1 user=<F-USER>\S+</F-USER><SKIPLINES>\s*\[sshd\] step2 from <HOST>$";
        let logs = concat!(
            "Dec 31 11:59:59 [sshd] step1 user=bob\n",
            "Dec 31 11:59:59 [sshd] noise in middle\n",
            "Dec 31 11:59:59 [sshd] another noise line\n",
            "Dec 31 11:59:59 [sshd] step2 from 192.0.2.55\n",
        );

        let opts = RegexCliOptions {
            datepattern: dp.clone(),
            maxlines: 5,
            debuggex: true,
            print_all_matched: true,
            ..RegexCliOptions::default()
        };

        let mut runner = Fail2banRegex::new(opts).unwrap();
        runner.run(logs, rx, None).unwrap();

        assert_eq!(runner.stats().tested, 4);
        assert_eq!(runner.stats().matched, 2);
        assert_eq!(runner.stats().ignored, 0);
        assert_eq!(runner.stats().missed, 2);

        let report = runner.render_report();
        assert!(report.contains("&flags=m"));
        assert!(report.contains("[sshd] step1 user=bob"));
        assert!(report.contains("[sshd] step2 from 192.0.2.55"));

        let row_opts = RegexCliOptions {
            datepattern: dp,
            maxlines: 5,
            out: Some("row".to_owned()),
            ..RegexCliOptions::default()
        };

        let mut row_runner = Fail2banRegex::new(row_opts).unwrap();
        row_runner.read_regex(rx, true).unwrap();
        let entries: Vec<(String, Option<f64>)> =
            logs.lines().map(|l| (l.to_owned(), None)).collect();
        let mut emitted = Vec::new();
        row_runner.process_entries(entries, &mut |s| emitted.push(s.to_owned()));

        assert_eq!(emitted.len(), 1);
        assert!(emitted[0].starts_with("['192.0.2.55',"));
        assert!(emitted[0].contains("'user': 'bob'"));
        assert!(emitted[0].ends_with("],"));
    }
}
