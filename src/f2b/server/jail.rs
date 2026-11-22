//! Fail2Ban 1.1.1 per-jail runtime (`JailState` and async `Jail` controller).
//!
//! Coordinates [`Filter`], [`FailManager`], [`BanManager`], [`BanTimeExtra`],
//! [`ActionKind`]s, SQLite [`Fail2BanDb`] persistence, and log input backends
//! (`FilterPoll`, `FilterPyinotify`, `FilterSystemd`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;

use crate::action::ActionKind;
use crate::banmanager::{AddBanOutcome, BanManager};
use crate::config::spec;
use crate::db::Fail2BanDb;
use crate::duration::{parse_bool, time2str};
use crate::error::{Error, Result};
use crate::f2b_log;
use crate::failmanager::FailManager;
use crate::filter::Filter;
use crate::filter::LogEncoding;
use crate::filter::backend::inotify::FilterPyinotify;
use crate::filter::backend::polling::FilterPoll;
use crate::filter::backend::systemd::FilterSystemd;
use crate::filter::backend::{BackendKind, FileLogConfig, JournalConfig, LogEvent};
use crate::filter::file_identity::file_first_line_sha1;
use crate::filter::ipdns::allow_ipv6;
use crate::logging::LogLevel;
use crate::observer::{self, BanTimeExtra};
use crate::protocol::PickleValue;
use crate::ticket::{ActionContext, Ticket, TicketId};

const EVENT_CHANNEL_CAPACITY: usize = 1024;
const PERIODIC_CHECK_INTERVAL_SECS: f64 = 30.0;
const CONSISTENCY_THROTTLE_SECS: f64 = 3.0;

/// Current Unix timestamp in seconds.
pub(crate) fn current_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Resolved concrete backend and optional backend bracket parameters.
#[derive(Debug, Clone)]
struct ParsedBackend {
    real_backend: BackendKind,
    journal_flags: Option<u32>,
    journal_path: Option<PathBuf>,
    journal_tail: bool,
}

fn parse_backend_spec(raw: &str) -> Result<ParsedBackend> {
    let kind = BackendKind::parse(raw)?;
    let real_backend = match kind {
        BackendKind::Auto => {
            if cfg!(target_os = "linux") {
                BackendKind::Pyinotify
            } else {
                BackendKind::Polling
            }
        }
        concrete => concrete,
    };

    let mut journal_flags = None;
    let mut journal_path = None;
    let mut journal_tail = false;

    let trimmed = raw.trim();
    if trimmed.contains('[') {
        let parsed = spec::parse(trimmed)?;
        if let Some(v) = parsed.parameters.get("journalflags") {
            let flags = v.trim().parse::<u32>().map_err(|_| {
                Error::invalid_command(format!("invalid journalflags value {v:?}"))
            })?;
            journal_flags = Some(flags);
        }
        if let Some(v) = parsed.parameters.get("journalpath") {
            let p = v.trim();
            if !p.is_empty() {
                journal_path = Some(PathBuf::from(p));
            }
        }
        if let Some(v) = parsed.parameters.get("tail") {
            journal_tail = parse_bool(v)?;
        }
    }

    Ok(ParsedBackend {
        real_backend,
        journal_flags,
        journal_path,
        journal_tail,
    })
}

/// Snapshot of state saved during `reload_begin` to detect whether the log backend needs restart.
#[derive(Debug, Clone)]
struct ReloadSnapshot {
    log_paths: Vec<(PathBuf, bool)>,
    journal_matches: Vec<Vec<String>>,
    encoding: LogEncoding,
}

/// Complete per-jail Fail2Ban state machine.
pub struct JailState {
    pub name: String,
    pub backend_spec: String,
    pub real_backend: BackendKind,
    pub alive: bool,
    pub idle: bool,
    pub filter: Filter,
    pub fail_manager: FailManager,
    pub ban_manager: BanManager,
    pub ban_extra: BanTimeExtra,
    pub actions: Vec<(String, ActionKind)>,
    pub log_paths: Vec<(PathBuf, bool)>,
    pub journal_matches: Vec<Vec<String>>,
    pub journal_flags: Option<u32>,
    pub journal_path: Option<PathBuf>,
    pub journal_tail: bool,
    pub db: Option<Arc<std::sync::Mutex<Fail2BanDb>>>,
    ban_epoch: u64,
    last_consistency_check: f64,
    last_periodic_check: f64,
    file_checkpoints: BTreeMap<PathBuf, (String, u64)>,
    last_journal_ts: Option<f64>,
    reloading: bool,
    reload_logs: Option<BTreeSet<PathBuf>>,
    reload_actions: Option<BTreeMap<String, Option<String>>>,
    reload_snapshot: Option<ReloadSnapshot>,
}

impl std::fmt::Debug for JailState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailState")
            .field("name", &self.name)
            .field("backend_spec", &self.backend_spec)
            .field("real_backend", &self.real_backend)
            .field("alive", &self.alive)
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}

impl JailState {
    /// Construct a new [`JailState`] with Fail2Ban 1.1.1 defaults.
    pub fn new(
        name: impl Into<String>,
        backend_spec: impl Into<String>,
        db: Option<Arc<std::sync::Mutex<Fail2BanDb>>>,
    ) -> Result<Self> {
        let name = name.into();
        let backend_spec = backend_spec.into();
        if name.len() >= 26 {
            f2b_log!(
                LogLevel::Warning,
                "fail2ban.jail",
                "Jail name {:?} might be too long and some commands might not function correctly. Please shorten",
                name
            );
        }
        let parsed = parse_backend_spec(&backend_spec)?;
        f2b_log!(
            LogLevel::Info,
            "fail2ban.jail",
            "Creating new jail '{}'",
            name
        );
        f2b_log!(
            LogLevel::Info,
            "fail2ban.jail",
            "Initiated '{}' backend",
            parsed.real_backend.as_str()
        );
        let filter = Filter::new(&name);
        Ok(Self {
            name,
            backend_spec,
            real_backend: parsed.real_backend,
            alive: false,
            idle: false,
            filter,
            fail_manager: FailManager::new(),
            ban_manager: BanManager::new(),
            ban_extra: BanTimeExtra::new(),
            actions: Vec::new(),
            log_paths: Vec::new(),
            journal_matches: Vec::new(),
            journal_flags: parsed.journal_flags,
            journal_path: parsed.journal_path,
            journal_tail: parsed.journal_tail,
            db,
            ban_epoch: 0,
            last_consistency_check: 0.0,
            last_periodic_check: current_unix_seconds(),
            file_checkpoints: BTreeMap::new(),
            last_journal_ts: None,
            reloading: false,
            reload_logs: None,
            reload_actions: None,
            reload_snapshot: None,
        })
    }

    pub fn backend_display_name(&self) -> &'static str {
        self.real_backend.as_str()
    }

    pub fn is_reloading(&self) -> bool {
        self.reloading
    }

    /// Add a log file path to monitor (`FileFilter.addLogPath` semantics).
    pub fn add_log_path(&mut self, path: PathBuf, tail: bool) {
        if self.real_backend == BackendKind::Systemd {
            return;
        }
        if let Some(ref mut reload_set) = self.reload_logs
            && reload_set.remove(&path)
        {
            return;
        }
        if self.log_paths.iter().any(|(p, _)| p == &path) {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.filter",
                "{} already exists",
                path.display()
            );
            return;
        }
        self.log_paths.push((path, tail));
    }

    /// Remove a monitored log file path (`FileFilter.delLogPath` semantics).
    pub fn del_log_path(&mut self, path: &Path) {
        if self.real_backend == BackendKind::Systemd {
            return;
        }
        self.log_paths.retain(|(p, _)| p != path);
        self.file_checkpoints.remove(path);
        if let Some(ref mut reload_set) = self.reload_logs {
            reload_set.remove(path);
        }
    }

    pub fn get_log_paths(&self) -> Vec<String> {
        if self.real_backend == BackendKind::Systemd {
            return Vec::new();
        }
        self.log_paths
            .iter()
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect()
    }

    /// Add systemd journal match tokens (splitting on `+` into OR-groups).
    pub fn add_journal_match(&mut self, tokens: &[String]) {
        if self.real_backend != BackendKind::Systemd || tokens.is_empty() {
            return;
        }
        let mut groups: Vec<Vec<String>> = vec![Vec::new()];
        for tok in tokens {
            if tok == "+" {
                groups.push(Vec::new());
            } else {
                if let Some(last) = groups.last_mut() {
                    last.push(tok.clone());
                }
            }
        }
        for grp in groups {
            if !grp.is_empty() {
                self.journal_matches.push(grp);
            }
        }
    }

    /// Remove a systemd journal match group (or all groups if `tokens` is empty).
    pub fn del_journal_match(&mut self, tokens: &[String]) -> Result<()> {
        if self.real_backend != BackendKind::Systemd {
            return Ok(());
        }
        if tokens.is_empty() {
            self.journal_matches.clear();
            return Ok(());
        }
        if let Some(pos) = self.journal_matches.iter().position(|g| g == tokens) {
            self.journal_matches.remove(pos);
            Ok(())
        } else {
            Err(Error::invalid_command(format!(
                "Match {tokens:?} not found"
            )))
        }
    }

    /// Add or reload an action (`CommandAction` or built-in `smtp.py` Python action).
    pub fn add_action(
        &mut self,
        act_name: &str,
        python_path: Option<&str>,
        init_json: Option<&str>,
    ) -> Result<()> {
        let init_str = init_json.unwrap_or("{}");
        if let Some(pos) = self.actions.iter().position(|(n, _)| n == act_name) {
            if !self.reloading {
                return Err(Error::invalid_command(format!(
                    "Action {act_name} already exists"
                )));
            }
            let same_kind = match (&self.actions[pos].1, python_path) {
                (ActionKind::Command(_), None) => true,
                (ActionKind::Smtp(_), Some(p)) => {
                    p.rsplit(['/', '\\']).next().unwrap_or(p) == "smtp.py"
                }
                _ => false,
            };
            if same_kind {
                self.actions[pos].1.clear_all_params();
                if let ActionKind::Smtp(ref mut smtp) = self.actions[pos].1
                    && let Some(raw) = init_json
                {
                    *smtp = crate::action::SmtpAction::from_json(
                        self.name.clone(),
                        act_name.to_owned(),
                        raw,
                    )?;
                }
            } else {
                let replacement = build_action(&self.name, act_name, python_path, init_str)?;
                self.actions[pos].1 = replacement;
            }
            if let Some(ref mut kept) = self.reload_actions {
                kept.insert(act_name.to_owned(), init_json.map(str::to_owned));
            }
            return Ok(());
        }

        let action = build_action(&self.name, act_name, python_path, init_str)?;
        self.actions.push((act_name.to_owned(), action));
        if self.reloading
            && let Some(ref mut kept) = self.reload_actions
        {
            kept.insert(act_name.to_owned(), init_json.map(str::to_owned));
        }
        Ok(())
    }

    /// Remove an action by name (`delaction`).
    pub fn del_action(&mut self, act_name: &str) -> Result<()> {
        let Some(pos) = self.actions.iter().position(|(n, _)| n == act_name) else {
            return Err(Error::invalid_command(format!(
                "Invalid Action name: {act_name}"
            )));
        };
        self.actions.remove(pos);
        Ok(())
    }

    /// Look up mutable reference to an action by name.
    pub fn get_action_mut(&mut self, act_name: &str) -> Option<&mut ActionKind> {
        self.actions
            .iter_mut()
            .find(|(n, _)| n == act_name)
            .map(|(_, a)| a)
    }

    /// Look up shared reference to an action by name.
    pub fn get_action(&self, act_name: &str) -> Option<&ActionKind> {
        self.actions
            .iter()
            .find(|(n, _)| n == act_name)
            .map(|(_, a)| a)
    }

    /// Begin reload phase: pause processing, clear regex/ignore/journal lists, and snapshot logs/actions.
    pub fn reload_begin(&mut self) {
        self.idle = true;
        self.reloading = true;
        self.reload_snapshot = Some(ReloadSnapshot {
            log_paths: self.log_paths.clone(),
            journal_matches: self.journal_matches.clone(),
            encoding: self.filter.log_encoding(),
        });
        let _ = self.filter.del_fail_regex(None);
        let _ = self.filter.del_ignore_regex(None);
        let _ = self.filter.del_ignore_ip(None);
        let _ = self.filter.set_prefregex(None);
        self.journal_matches.clear();

        let existing_logs: BTreeSet<PathBuf> =
            self.log_paths.iter().map(|(p, _)| p.clone()).collect();
        self.reload_logs = Some(existing_logs);
        self.reload_actions = Some(BTreeMap::new());
    }

    /// Finalize reload phase: remove obsolete logs & actions, reload kept actions.
    ///
    /// Returns `true` if the log backend configuration changed and needs restart.
    pub async fn reload_commit(&mut self) -> Result<bool> {
        if let Some(obsolete_logs) = self.reload_logs.take() {
            for path in obsolete_logs {
                self.del_log_path(&path);
            }
        }

        if let Some(kept_actions) = self.reload_actions.take() {
            let mut removed = Vec::new();
            let mut kept_indices = Vec::new();
            for (idx, (act_name, _)) in self.actions.iter().enumerate() {
                if kept_actions.contains_key(act_name) {
                    kept_indices.push(idx);
                } else {
                    removed.push(act_name.clone());
                }
            }

            for idx in kept_indices {
                if let Err(err) = self.actions[idx].1.reload().await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Failed to reload jail '{}' action '{}': {err}",
                        self.name,
                        self.actions[idx].0
                    );
                }
            }

            if !removed.is_empty() {
                let active_tickets: Vec<Ticket> = self
                    .ban_manager
                    .get_ban_list(false)
                    .into_iter()
                    .filter_map(|id| self.ban_manager.get_ticket_by_id(&id).cloned())
                    .collect();

                for act_name in &removed {
                    if let Some(pos) = self.actions.iter().position(|(n, _)| n == act_name) {
                        let (_, mut act) = self.actions.remove(pos);
                        if act.supports_flush() {
                            if let Err(err) = act.flush().await {
                                f2b_log!(
                                    LogLevel::Error,
                                    "fail2ban.actions",
                                    "Failed to flush removed action '{act_name}' in '{}': {err}",
                                    self.name
                                );
                            }
                        } else {
                            for ticket in &active_tickets {
                                let ctx = self.build_action_context(ticket, false);
                                if let Err(err) = act.unban(&ctx).await {
                                    f2b_log!(
                                        LogLevel::Error,
                                        "fail2ban.actions",
                                        "Failed to unban {} on removed action '{act_name}': {err}",
                                        ticket.fid
                                    );
                                }
                            }
                        }
                        if let Err(err) = act.stop().await {
                            f2b_log!(
                                LogLevel::Error,
                                "fail2ban.actions",
                                "Failed to stop removed action '{act_name}' in '{}': {err}",
                                self.name
                            );
                        }
                    }
                }
            }
        }

        self.reloading = false;
        let backend_changed = match self.reload_snapshot.take() {
            Some(prev) => {
                prev.log_paths != self.log_paths
                    || prev.journal_matches != self.journal_matches
                    || prev.encoding != self.filter.log_encoding()
            }
            None => false,
        };
        Ok(backend_changed)
    }

    /// Process one [`LogEvent`] from the log backend task.
    pub async fn handle_log_event(&mut self, ev: LogEvent, now: f64) {
        match ev {
            LogEvent::Checkpoint {
                path,
                fingerprint,
                offset,
            } => {
                self.file_checkpoints
                    .insert(PathBuf::from(&path), (fingerprint.clone(), offset));
                self.db_update_log(&path, &fingerprint, offset);
            }
            LogEvent::Line {
                line,
                preset_date,
                log_path: _,
            } => {
                if let Some(ts) = preset_date {
                    self.last_journal_ts = Some(ts);
                }
                let processed = self.filter.process_line_at(&line, preset_date, now);
                for m in processed.results {
                    let Some(fid) = m.fid.or_else(|| m.ip.clone()) else {
                        continue;
                    };
                    let event_time = if self.filter.check_find_time() && m.time > now {
                        now
                    } else {
                        m.time
                    };
                    let mut ticket = Ticket::new(fid.clone(), event_time);
                    ticket.ip = m.ip;
                    ticket.matches = m.matches;
                    ticket.data = m.data;

                    f2b_log!(
                        LogLevel::Info,
                        "fail2ban.filter",
                        "[{}] Found {} - {}",
                        self.name,
                        ticket.target_ip(),
                        time2str(event_time)
                    );

                    let mut attempts = self.fail_manager.add_failure(ticket.clone(), 1, false);
                    if self.ban_extra.increment {
                        let boost = self.db_failure_found_boost(&mut ticket);
                        if boost > 0 {
                            attempts = self.fail_manager.add_failure(ticket, boost, true);
                        }
                    }

                    if attempts >= self.fail_manager.max_retry()
                        && let Some(to_ban) = self.fail_manager.to_ban(Some(&fid))
                    {
                        self.ban_ticket(to_ban, now).await;
                    }
                }
            }
        }
    }

    /// Periodic 1-second maintenance tick: expire bans, clean stale failures, and periodically check action consistency.
    pub async fn periodic_tick(&mut self, now: f64) {
        let expired = self.ban_manager.unban(now);
        for ticket in expired {
            self.unban_ticket_actions(&ticket, true).await;
            self.db_del_ban(Some(&ticket.fid));
        }
        self.fail_manager.cleanup(now);

        if now >= self.last_periodic_check + PERIODIC_CHECK_INTERVAL_SECS {
            self.last_periodic_check = now;
            self.run_consistency_checks(now).await;
        }
    }

    /// Execute the full ban pipeline for a single [`Ticket`].
    pub async fn ban_ticket(&mut self, mut ticket: Ticket, now: f64) {
        let already_banned = self.ban_manager.in_ban_list(&ticket.fid);
        let mut incremented_in_observer = false;

        if !ticket.restored && self.ban_extra.increment {
            let pre_cnt = ticket.ban_count;
            let db_guard = self.db.as_ref().and_then(|d| d.lock().ok());
            observer::incr_ban_time(
                &self.ban_extra,
                db_guard.as_deref(),
                &self.name,
                self.ban_manager.ban_time(),
                &mut ticket,
            );
            drop(db_guard);
            if ticket.ban_count > pre_cnt {
                incremented_in_observer = true;
            }
        }

        // Prevent double-incrementing `ban_count` when inserting a new ticket into `BanManager`,
        // since `BanManager::add_ban_ticket` increments `ban_count` by 1 on `Entry::Vacant`.
        if !already_banned && (incremented_in_observer || ticket.restored) && ticket.ban_count > 0
        {
            ticket.ban_count = ticket.ban_count.saturating_sub(1);
        }

        let outcome = self.ban_manager.add_ban_ticket(ticket.clone(), now);
        match outcome {
            AddBanOutcome::Added => {
                let stored = self
                    .ban_manager
                    .get_ticket_by_id(&ticket.fid)
                    .cloned()
                    .unwrap_or(ticket);
                let ctx = self.build_action_context(&stored, !stored.restored);
                let prefix = if stored.restored { "Restore " } else { "" };
                f2b_log!(
                    LogLevel::Notice,
                    "fail2ban.actions",
                    "[{}] {}Ban {}",
                    self.name,
                    prefix,
                    stored.fid
                );
                for (act_name, act) in &mut self.actions {
                    if stored.restored && act.norestored() {
                        continue;
                    }
                    if let Err(err) = act.ban(&ctx).await {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to execute ban jail '{}' action '{}' for {}: {err}",
                            self.name,
                            act_name,
                            stored.fid
                        );
                    }
                }
                if !stored.restored {
                    self.db_add_ban(&stored);
                }
            }
            AddBanOutcome::Prolonged(prolonged) => {
                let ctx = self.build_action_context(&prolonged, false);
                for (act_name, act) in &mut self.actions {
                    if !act.prolongable() || (prolonged.restored && act.norestored()) {
                        continue;
                    }
                    if let Err(err) = act.prolong(&ctx).await {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to execute prolong jail '{}' action '{}' for {}: {err}",
                            self.name,
                            act_name,
                            prolonged.fid
                        );
                    }
                }
                if !prolonged.restored {
                    self.db_add_ban(&prolonged);
                }
            }
            AddBanOutcome::Duplicate => {
                let existing_time = self
                    .ban_manager
                    .get_ticket_by_id(&ticket.fid)
                    .map_or(ticket.time, |t| t.time);
                let diftm = ticket.time - existing_time;
                let lvl = if diftm < 3.0 {
                    LogLevel::Debug
                } else if diftm < 60.0 {
                    LogLevel::Notice
                } else {
                    LogLevel::Warning
                };
                f2b_log!(
                    lvl,
                    "fail2ban.actions",
                    "[{}] {} already banned",
                    self.name,
                    ticket.fid
                );
                if diftm > CONSISTENCY_THROTTLE_SECS
                    && now > self.last_consistency_check + CONSISTENCY_THROTTLE_SECS
                {
                    self.last_consistency_check = now;
                    self.run_consistency_checks(now).await;
                }
            }
            AddBanOutcome::Expired => {
                f2b_log!(
                    LogLevel::Info,
                    "fail2ban.actions",
                    "[{}] Ignore {}, expired bantime",
                    self.name,
                    ticket.fid
                );
            }
        }
    }

    async fn run_consistency_checks(&mut self, _now: f64) {
        let mut reban_indices = Vec::new();
        for (idx, (act_name, act)) in self.actions.iter_mut().enumerate() {
            let before_epoch = act.ban_epoch();
            match act.consistency_check().await {
                Ok(true) => {
                    if act.ban_epoch() > before_epoch || act.ban_epoch() > self.ban_epoch {
                        reban_indices.push(idx);
                    }
                }
                Ok(false) => {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Consistency check failed for jail '{}' action '{act_name}'",
                        self.name
                    );
                }
                Err(err) => {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Consistency check error for jail '{}' action '{act_name}': {err}",
                        self.name
                    );
                }
            }
        }
        if !reban_indices.is_empty() {
            let active_tickets: Vec<Ticket> = self
                .ban_manager
                .get_ban_list(false)
                .into_iter()
                .filter_map(|id| self.ban_manager.get_ticket_by_id(&id).cloned())
                .collect();
            let mut max_epoch = self.ban_epoch;
            for &idx in &reban_indices {
                max_epoch = max_epoch.max(self.actions[idx].1.ban_epoch());
            }
            self.ban_epoch = max_epoch;

            for ticket in &active_tickets {
                let ctx = self.build_action_context(ticket, false);
                for &idx in &reban_indices {
                    let act_name = self.actions[idx].0.clone();
                    f2b_log!(
                        LogLevel::Notice,
                        "fail2ban.actions",
                        "[{}] Reban {}, action '{}'",
                        self.name,
                        ticket.fid,
                        act_name
                    );
                    if let Err(err) = self.actions[idx].1.reban(&ctx).await {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to execute reban jail '{}' action '{act_name}' for {}: {err}",
                            self.name,
                            ticket.fid
                        );
                    }
                }
            }
        }
    }

    /// Manually ban one or more IPs/CIDRs/IDs (`set <jail> banip ...`).
    pub async fn ban_ip(&mut self, ips: &[String]) -> Result<usize> {
        let now = current_unix_seconds();
        let before = self.ban_manager.total_bans();
        for raw in ips {
            let id = TicketId::parse(raw);
            let ticket = Ticket::new(id, now);
            self.ban_ticket(ticket, now).await;
        }
        Ok((self.ban_manager.total_bans().saturating_sub(before)) as usize)
    }

    /// Manually unban specific IPs (or flush all if `ips` is `None`).
    pub async fn unban_ip(&mut self, ips: Option<&[String]>, ifexists: bool) -> Result<usize> {
        match ips {
            None => Ok(self.flush_bans(true, false).await),
            Some(targets) => {
                let mut cnt = 0usize;
                let mut missed = Vec::new();
                for raw in targets {
                    let target = TicketId::parse(raw);
                    self.db_del_ban(Some(&target));
                    if let Some(ticket) = self.ban_manager.remove_by_id(&target) {
                        self.unban_ticket_actions(&ticket, true).await;
                        cnt += 1;
                    } else {
                        let matched = self.ban_manager.remove_matching(&target);
                        if !matched.is_empty() {
                            for ticket in matched {
                                self.db_del_ban(Some(&ticket.fid));
                                self.unban_ticket_actions(&ticket, true).await;
                                cnt += 1;
                            }
                        } else {
                            f2b_log!(LogLevel::Notice, "fail2ban.actions", "{target} is not banned");
                            if !ifexists {
                                missed.push(raw.clone());
                            }
                        }
                    }
                }
                if !missed.is_empty() {
                    return Err(Error::invalid_command(format!("not banned: {missed:?}")));
                }
                Ok(cnt)
            }
        }
    }

    /// Manually feed an attempt (`set <jail> attempt <ip> [<match>...]`).
    pub async fn add_attempt(&mut self, ip: &str, matches: &[String]) -> Result<i64> {
        let id = TicketId::parse(ip);
        let now = current_unix_seconds();
        let mut ticket = Ticket::new(id.clone(), now);
        ticket.matches = matches.to_vec();

        if self.filter.ignores_ip(&id, Some(&ticket)) {
            return Ok(0);
        }

        f2b_log!(
            LogLevel::Info,
            "fail2ban.filter",
            "[{}] Attempt {} - {}",
            self.name,
            id,
            time2str(now)
        );
        let count = u64::try_from(matches.len().max(1)).unwrap_or(1);
        let mut attempts = self.fail_manager.add_failure(ticket.clone(), count, false);
        if self.ban_extra.increment {
            let boost = self.db_failure_found_boost(&mut ticket);
            if boost > 0 {
                attempts = self.fail_manager.add_failure(ticket, boost, true);
            }
        }
        if attempts >= self.fail_manager.max_retry()
            && let Some(to_ban) = self.fail_manager.to_ban(Some(&id))
        {
            self.ban_ticket(to_ban, now).await;
        }
        Ok(1)
    }

    /// Check whether IDs are currently banned (`get <jail> banned` / `banned`).
    pub fn get_banned(&self, ids: &[String]) -> PickleValue {
        if ids.is_empty() {
            return PickleValue::str_list(
                self.ban_manager
                    .get_ban_list(false)
                    .into_iter()
                    .map(|id| id.to_string()),
            );
        }
        if ids.len() == 1 {
            let target = TicketId::parse(&ids[0]);
            return PickleValue::Int(i64::from(self.ban_manager.in_ban_list(&target)));
        }
        PickleValue::List(
            ids.iter()
                .map(|raw| {
                    let target = TicketId::parse(raw);
                    PickleValue::Int(i64::from(self.ban_manager.in_ban_list(&target)))
                })
                .collect(),
        )
    }

    /// List banned IPs ordered by end-of-ban time (`get <jail> banip [--with-time]`).
    pub fn get_ban_list(&self, with_time: bool) -> Vec<String> {
        if !with_time {
            return self
                .ban_manager
                .get_ban_list(true)
                .into_iter()
                .map(|id| id.to_string())
                .collect();
        }
        let default_bt = self.ban_manager.ban_time();
        self.ban_manager
            .get_ban_list_extended(true)
            .into_iter()
            .map(|(id, start, end_opt)| {
                let btm = self
                    .ban_manager
                    .get_ticket_by_id(&id)
                    .map_or(default_bt, |t| t.effective_ban_time(default_bt));
                let end_str = match end_opt {
                    Some(e) => time2str(e),
                    None => "9999-12-31 23:59:59".to_owned(),
                };
                format!("{id} \t{} + {btm} = {end_str}", time2str(start))
            })
            .collect()
    }

    /// Return status formatted for `Transmitter::status` (`"basic"`, `"short"`, `"capi"`, `"cymru"`, `"stats"`).
    pub fn status(&self, flavor: &str) -> PickleValue {
        let fm_cur = self.fail_manager.size() as i64;
        let fm_tot = self.fail_manager.total_failures() as i64;
        let bm_cur = self.ban_manager.size() as i64;
        let bm_tot = self.ban_manager.total_bans() as i64;

        if flavor == "stats" {
            return PickleValue::List(vec![
                PickleValue::Str(self.backend_display_name().to_owned()),
                PickleValue::Tuple(vec![PickleValue::Int(fm_cur), PickleValue::Int(fm_tot)]),
                PickleValue::Tuple(vec![PickleValue::Int(bm_cur), PickleValue::Int(bm_tot)]),
            ]);
        }

        let mut filter_items = vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Currently failed".to_owned()),
                PickleValue::Int(fm_cur),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Total failed".to_owned()),
                PickleValue::Int(fm_tot),
            ]),
        ];
        if self.real_backend == BackendKind::Systemd {
            let matches: Vec<String> = self
                .journal_matches
                .iter()
                .map(|grp| grp.join(" "))
                .collect();
            filter_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Journal matches".to_owned()),
                PickleValue::str_list(matches),
            ]));
        } else {
            filter_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("File list".to_owned()),
                PickleValue::str_list(self.get_log_paths()),
            ]));
        }

        let mut action_items = vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Currently banned".to_owned()),
                PickleValue::Int(bm_cur),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Total banned".to_owned()),
                PickleValue::Int(bm_tot),
            ]),
        ];
        if flavor != "short" {
            let banned: Vec<String> = self
                .ban_manager
                .get_ban_list(false)
                .into_iter()
                .map(|id| id.to_string())
                .collect();
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned IP list".to_owned()),
                PickleValue::str_list(banned),
            ]));
        }
        if flavor == "cymru" {
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned ASN list".to_owned()),
                PickleValue::List(Vec::new()),
            ]));
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned Country list".to_owned()),
                PickleValue::List(Vec::new()),
            ]));
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned RIR list".to_owned()),
                PickleValue::List(Vec::new()),
            ]));
        }

        PickleValue::List(vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Filter".to_owned()),
                PickleValue::List(filter_items),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Actions".to_owned()),
                PickleValue::List(action_items),
            ]),
        ])
    }

    async fn flush_bans(&mut self, clear_db: bool, on_stop: bool) -> usize {
        let tickets = self.ban_manager.flush_ban_list();
        let mut flushed_actions: BTreeSet<String> = BTreeSet::new();
        for (act_name, act) in &mut self.actions {
            if act.supports_flush() {
                f2b_log!(
                    LogLevel::Notice,
                    "fail2ban.actions",
                    "[{}] Flush ticket(s) with {}",
                    self.name,
                    act_name
                );
                match act.flush().await {
                    Ok(()) => {
                        flushed_actions.insert(act_name.clone());
                    }
                    Err(err) => {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to flush bans in jail '{}' action '{act_name}': {err}",
                            self.name
                        );
                    }
                }
            }
        }
        if clear_db {
            self.db_del_ban(None);
        }
        let log_prefix = if on_stop { "Repeal Ban" } else { "Unban" };
        let count = tickets.len();
        for ticket in tickets {
            f2b_log!(
                LogLevel::Notice,
                "fail2ban.actions",
                "[{}] {} {}",
                self.name,
                log_prefix,
                ticket.fid
            );
            let ctx = self.build_action_context(&ticket, false);
            for (act_name, act) in self.actions.iter_mut().rev() {
                if flushed_actions.contains(act_name) {
                    continue;
                }
                if let Err(err) = act.unban(&ctx).await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Failed to execute unban jail '{}' action '{act_name}' for {}: {err}",
                        self.name,
                        ticket.fid
                    );
                }
            }
        }
        count
    }

    async fn unban_ticket_actions(&mut self, ticket: &Ticket, log_notice: bool) {
        if log_notice {
            f2b_log!(
                LogLevel::Notice,
                "fail2ban.actions",
                "[{}] Unban {}",
                self.name,
                ticket.fid
            );
        }
        let ctx = self.build_action_context(ticket, false);
        for (act_name, act) in self.actions.iter_mut().rev() {
            if let Err(err) = act.unban(&ctx).await {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.actions",
                    "Failed to execute unban jail '{}' action '{act_name}' for {}: {err}",
                    self.name,
                    ticket.fid
                );
            }
        }
    }

    fn build_action_context(&self, ticket: &Ticket, include_current: bool) -> ActionContext {
        let (db_all_cnt, db_all_matches, db_jail_cnt, db_jail_matches) =
            self.db_get_bans_merged(&ticket.fid);

        let (ip_failures, ip_matches) = if include_current {
            let mut m = db_all_matches;
            m.extend(ticket.matches.iter().cloned());
            (db_all_cnt.saturating_add(ticket.attempts), m)
        } else if db_all_cnt > 0 || !db_all_matches.is_empty() {
            (db_all_cnt.max(ticket.attempts), db_all_matches)
        } else {
            (ticket.attempts, ticket.matches.clone())
        };

        let (ip_jail_failures, ip_jail_matches) = if include_current {
            let mut m = db_jail_matches;
            m.extend(ticket.matches.iter().cloned());
            (db_jail_cnt.saturating_add(ticket.attempts), m)
        } else if db_jail_cnt > 0 || !db_jail_matches.is_empty() {
            (db_jail_cnt.max(ticket.attempts), db_jail_matches)
        } else {
            (ticket.attempts, ticket.matches.clone())
        };

        ActionContext {
            jail_name: self.name.clone(),
            ticket: ticket.clone(),
            default_ban_time: self.ban_manager.ban_time(),
            ip_failures,
            ip_jail_failures,
            ip_matches,
            ip_jail_matches,
        }
    }

    fn build_file_log_configs(&self) -> Vec<FileLogConfig> {
        let mut out = Vec::with_capacity(self.log_paths.len());
        for (path, tail) in &self.log_paths {
            if let Some((fp, off)) = self.file_checkpoints.get(path) {
                out.push(FileLogConfig {
                    path: path.clone(),
                    tail: *tail,
                    resume_fingerprint: Some(fp.clone()),
                    resume_offset: *off,
                });
                continue;
            }
            let (resume_fingerprint, resume_offset) = if !*tail {
                self.db_add_log_offset(path)
            } else {
                (None, 0)
            };
            out.push(FileLogConfig {
                path: path.clone(),
                tail: *tail,
                resume_fingerprint,
                resume_offset,
            });
        }
        out
    }

    fn restore_tickets_from_db(&mut self, now: f64) -> Vec<Ticket> {
        let Some(ref db_arc) = self.db else {
            return Vec::new();
        };
        let (forbantime, correct_ban_time) = if self.ban_extra.increment {
            (
                None,
                Some(self.ban_extra.max_ban_time(self.ban_manager.ban_time())),
            )
        } else {
            (Some(self.ban_manager.ban_time()), None)
        };
        let tickets = {
            let Ok(guard) = db_arc.lock() else {
                return Vec::new();
            };
            match guard.get_current_bans(
                Some(&self.name),
                forbantime,
                correct_ban_time,
                now.floor() as i64,
            ) {
                Ok(t) => t,
                Err(err) => {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.jail",
                        "Restore bans failed for '{}': {err}",
                        self.name
                    );
                    return Vec::new();
                }
            }
        };
        tickets
            .into_iter()
            .filter(|t| !self.filter.ignores_ip(&t.fid, Some(t)))
            .collect()
    }

    fn db_add_jail(&self) {
        if let Some(ref db_arc) = self.db
            && let Ok(guard) = db_arc.lock()
            && let Err(err) = guard.add_jail(&self.name)
        {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.jail",
                "Failed to register jail '{}' in database: {err}",
                self.name
            );
        }
    }

    fn db_add_log_offset(&self, path: &Path) -> (Option<String>, u64) {
        let Some(ref db_arc) = self.db else {
            return (None, 0);
        };
        let fp = File::open(path)
            .and_then(|mut f| {
                let len = f.metadata()?.len();
                file_first_line_sha1(&mut f, len)
            })
            .unwrap_or_default();
        let path_str = path.to_string_lossy();
        let Ok(guard) = db_arc.lock() else {
            return (None, 0);
        };
        match guard.add_log(&self.name, &path_str, &fp) {
            Ok(Some(pos)) if !fp.is_empty() => (Some(fp), pos),
            _ => (None, 0),
        }
    }

    fn db_update_log(&self, path: &str, fingerprint: &str, offset: u64) {
        if let Some(ref db_arc) = self.db
            && let Ok(guard) = db_arc.lock()
            && let Err(err) = guard.update_log(&self.name, path, fingerprint, offset)
        {
            f2b_log!(
                LogLevel::Warning,
                "fail2ban.jail",
                "Failed to update log checkpoint for '{}' ({path}): {err}",
                self.name
            );
        }
    }

    fn db_add_ban(&self, ticket: &Ticket) {
        if let Some(ref db_arc) = self.db
            && let Ok(guard) = db_arc.lock()
            && let Err(err) = guard.add_ban(&self.name, ticket, self.ban_manager.ban_time())
        {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.jail",
                "Failed to persist ban for '{}' ({}): {err}",
                self.name,
                ticket.fid
            );
        }
    }

    fn db_del_ban(&self, id: Option<&TicketId>) {
        if let Some(ref db_arc) = self.db
            && let Ok(guard) = db_arc.lock()
            && let Err(err) = guard.del_ban(&self.name, id)
        {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.jail",
                "Failed to delete active ban in '{}' from database: {err}",
                self.name
            );
        }
    }

    fn db_failure_found_boost(&self, ticket: &mut Ticket) -> u64 {
        let Some(ref db_arc) = self.db else {
            return 0;
        };
        let Ok(guard) = db_arc.lock() else {
            return 0;
        };
        observer::failure_found_boost(
            &self.ban_extra,
            Some(&*guard),
            &self.name,
            ticket,
            self.fail_manager.max_retry(),
        )
    }

    fn db_get_bans_merged(&self, id: &TicketId) -> (u64, Vec<String>, u64, Vec<String>) {
        let Some(ref db_arc) = self.db else {
            return (0, Vec::new(), 0, Vec::new());
        };
        let Ok(guard) = db_arc.lock() else {
            return (0, Vec::new(), 0, Vec::new());
        };
        let (all_cnt, all_matches) = guard.get_bans_merged(id, None).unwrap_or_default();
        let (jail_cnt, jail_matches) = guard
            .get_bans_merged(id, Some(&self.name))
            .unwrap_or_default();
        (all_cnt, all_matches, jail_cnt, jail_matches)
    }
}

fn build_action(
    jail_name: &str,
    act_name: &str,
    python_path: Option<&str>,
    init_json: &str,
) -> Result<ActionKind> {
    match python_path {
        Some(path) => ActionKind::from_python_spec(jail_name, act_name, path, init_json),
        None => Ok(ActionKind::command(
            jail_name.to_owned(),
            act_name.to_owned(),
        )),
    }
}

struct JailTasks {
    backend_shut_tx: watch::Sender<bool>,
    worker_shut_tx: watch::Sender<bool>,
    idle_tx: watch::Sender<bool>,
    backend_handle: Option<JoinHandle<()>>,
    worker_handle: Option<JoinHandle<()>>,
    event_tx: mpsc::Sender<LogEvent>,
}

/// Async thread-safe handle to a single Fail2Ban jail and its background tasks.
pub struct Jail {
    pub state: Arc<Mutex<JailState>>,
    tasks: Mutex<Option<JailTasks>>,
}

impl std::fmt::Debug for Jail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jail").finish_non_exhaustive()
    }
}

impl Jail {
    /// Create a new [`Jail`].
    pub fn new(
        name: impl Into<String>,
        backend_spec: impl Into<String>,
        db: Option<Arc<std::sync::Mutex<Fail2BanDb>>>,
    ) -> Result<Self> {
        let state = JailState::new(name, backend_spec, db)?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            tasks: Mutex::new(None),
        })
    }

    /// Start actions, restore active DB bans, and launch backend + worker tasks.
    pub async fn start(&self) -> Result<()> {
        let mut st = self.state.lock().await;
        if st.alive {
            st.idle = false;
            drop(st);
            self.sync_idle_signal(false).await;
            return Ok(());
        }

        let jail_name = st.name.clone();
        f2b_log!(LogLevel::Debug, "fail2ban.jail", "Starting jail '{}'", jail_name);
        st.db_add_jail();

        let ipv6_allowed = allow_ipv6();
        for (act_name, act) in &mut st.actions {
            if let Err(err) = act.start(ipv6_allowed).await {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.actions",
                    "Failed to start jail '{}' action '{act_name}': {err}",
                    jail_name
                );
            }
        }

        let now = current_unix_seconds();
        let restored = st.restore_tickets_from_db(now);
        for ticket in restored {
            st.ban_ticket(ticket, now).await;
        }

        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (worker_shut_tx, worker_shut_rx) = watch::channel(false);
        let (idle_tx, idle_rx) = watch::channel(false);
        let (backend_shut_tx, backend_shut_rx) = watch::channel(false);

        let backend_handle = spawn_backend_task(&st, event_tx.clone(), backend_shut_rx);
        let worker_handle = spawn_worker_task(
            Arc::clone(&self.state),
            event_rx,
            worker_shut_rx,
            idle_rx,
        );

        st.alive = true;
        st.idle = false;
        drop(st);

        *self.tasks.lock().await = Some(JailTasks {
            backend_shut_tx,
            worker_shut_tx,
            idle_tx,
            backend_handle,
            worker_handle,
            event_tx,
        });

        f2b_log!(LogLevel::Info, "fail2ban.jail", "Jail '{}' started", jail_name);
        Ok(())
    }

    /// Stop background tasks, flush/unban active bans, and stop actions in reverse order.
    pub async fn stop(&self) -> Result<()> {
        let taken = self.tasks.lock().await.take();
        if let Some(mut runtime) = taken {
            let _ = runtime.backend_shut_tx.send(true);
            let _ = runtime.worker_shut_tx.send(true);
            if let Some(bh) = runtime.backend_handle.take() {
                let _ = bh.await;
            }
            if let Some(wh) = runtime.worker_handle.take() {
                let _ = wh.await;
            }
        }

        let mut st = self.state.lock().await;
        if st.alive || !st.ban_manager.get_ban_list(false).is_empty() || !st.actions.is_empty() {
            let _ = st.flush_bans(false, true).await;
        }
        let jail_name = st.name.clone();
        for (act_name, act) in st.actions.iter_mut().rev() {
            if let Err(err) = act.stop().await {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.actions",
                    "Failed to stop jail '{jail_name}' action '{act_name}': {err}"
                );
            }
        }
        st.alive = false;
        f2b_log!(LogLevel::Info, "fail2ban.jail", "Jail '{}' stopped", jail_name);
        Ok(())
    }

    /// Restart only the log backend task when monitored paths/encoding/matches change at runtime.
    pub async fn restart_backend_if_alive(&self) {
        let mut tasks_guard = self.tasks.lock().await;
        let Some(ref mut runtime) = *tasks_guard else {
            return;
        };
        let _ = runtime.backend_shut_tx.send(true);
        let old_handle = runtime.backend_handle.take();
        let event_tx = runtime.event_tx.clone();
        drop(tasks_guard);

        if let Some(h) = old_handle {
            let _ = h.await;
        }

        let st = self.state.lock().await;
        if !st.alive {
            return;
        }
        let (new_shut_tx, new_shut_rx) = watch::channel(false);
        let new_handle = spawn_backend_task(&st, event_tx, new_shut_rx);
        drop(st);

        let mut tasks_guard = self.tasks.lock().await;
        if let Some(ref mut runtime) = *tasks_guard {
            runtime.backend_shut_tx = new_shut_tx;
            runtime.backend_handle = new_handle;
        }
    }

    pub async fn set_idle(&self, idle: bool) {
        {
            let mut st = self.state.lock().await;
            st.idle = idle;
        }
        self.sync_idle_signal(idle).await;
    }

    pub async fn is_idle(&self) -> bool {
        self.state.lock().await.idle
    }

    pub async fn is_alive(&self) -> bool {
        self.state.lock().await.alive
    }

    pub async fn reload_begin(&self) {
        {
            let mut st = self.state.lock().await;
            st.reload_begin();
        }
        self.sync_idle_signal(true).await;
    }

    pub async fn reload_commit(&self) -> Result<()> {
        let (changed, idle) = {
            let mut st = self.state.lock().await;
            let changed = st.reload_commit().await?;
            (changed, st.idle)
        };
        self.sync_idle_signal(idle).await;
        if changed {
            self.restart_backend_if_alive().await;
        }
        Ok(())
    }

    async fn sync_idle_signal(&self, idle: bool) {
        let tasks_guard = self.tasks.lock().await;
        if let Some(ref runtime) = *tasks_guard {
            let _ = runtime.idle_tx.send(idle);
        }
    }
}

fn spawn_backend_task(
    st: &JailState,
    event_tx: mpsc::Sender<LogEvent>,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let jail_name = st.name.clone();
    let encoding = st.filter.log_encoding();
    let allow_poll_fallback = st.backend_spec.trim().eq_ignore_ascii_case("auto");

    match st.real_backend {
        BackendKind::Polling => {
            if st.log_paths.is_empty() {
                return None;
            }
            let configs = st.build_file_log_configs();
            let poller = FilterPoll::new(configs, encoding);
            Some(tokio::spawn(async move {
                if let Err(err) = poller.run(event_tx, shutdown_rx).await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.filter",
                        "Polling backend error in jail '{jail_name}': {err}"
                    );
                }
            }))
        }
        BackendKind::Pyinotify => {
            if st.log_paths.is_empty() {
                return None;
            }
            let configs = st.build_file_log_configs();
            let configs_fallback = if allow_poll_fallback {
                Some(configs.clone())
            } else {
                None
            };
            let watcher = FilterPyinotify::new(configs, encoding);
            Some(tokio::spawn(async move {
                let shut_fb = shutdown_rx.clone();
                let tx_fb = event_tx.clone();
                if let Err(err) = watcher.run(event_tx, shutdown_rx).await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.filter",
                        "Pyinotify backend error in jail '{jail_name}': {err}"
                    );
                    if let Some(cfgs) = configs_fallback {
                        f2b_log!(
                            LogLevel::Warning,
                            "fail2ban.filter",
                            "Falling back to polling backend for jail '{jail_name}'"
                        );
                        let poller = FilterPoll::new(cfgs, encoding);
                        let _ = poller.run(tx_fb, shut_fb).await;
                    }
                }
            }))
        }
        BackendKind::Systemd => {
            let jcfg = JournalConfig {
                matches: st.journal_matches.clone(),
                flags: st.journal_flags,
                path: st.journal_path.clone(),
            };
            let reader = FilterSystemd::new(jcfg, encoding, st.journal_tail)
                .with_since(st.last_journal_ts);
            Some(tokio::spawn(async move {
                if let Err(err) = reader.run(event_tx, shutdown_rx).await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.filter",
                        "Systemd backend error in jail '{jail_name}': {err}"
                    );
                }
            }))
        }
        BackendKind::Auto => None,
    }
}

fn spawn_worker_task(
    state: Arc<Mutex<JailState>>,
    mut event_rx: mpsc::Receiver<LogEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut idle_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut rx_closed = false;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            let is_idle = *idle_rx.borrow();
            tokio::select! {
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = idle_rx.changed() => {}
                maybe_ev = event_rx.recv(), if !is_idle && !rx_closed => {
                    match maybe_ev {
                        Some(ev) => {
                            let now = current_unix_seconds();
                            let mut st = state.lock().await;
                            st.handle_log_event(ev, now).await;
                        }
                        None => {
                            rx_closed = true;
                        }
                    }
                }
                _ = tick.tick(), if !is_idle => {
                    let now = current_unix_seconds();
                    let mut st = state.lock().await;
                    st.periodic_tick(now).await;
                }
            }
        }
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn jail_log_to_fail_to_ban_sqlite_and_unban_lifecycle() {
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("auth.log");
        let ban_log = dir.path().join("ban.log");
        let db_path = dir.path().join("f2b.sqlite3");

        std::fs::write(&log_file, "").unwrap();
        let db = Arc::new(std::sync::Mutex::new(
            Fail2BanDb::open(&db_path.to_string_lossy(), 86_400, 10).unwrap(),
        ));

        let jail = Jail::new("sshd", "polling", Some(Arc::clone(&db))).unwrap();
        {
            let mut st = jail.state.lock().await;
            st.filter.set_ignore_self(false);
            st.filter.set_check_find_time(false);
            st.filter
                .add_fail_regex(r"Failed password for \S+ from <HOST> port \d+")
                .unwrap();
            st.fail_manager.set_max_retry(2);
            st.ban_manager.set_ban_time(1);
            st.add_log_path(log_file.clone(), false);
            st.add_action("rec", None, None).unwrap();
            let act = st.get_action_mut("rec").unwrap();
            act.set_property("actionban", &format!("echo ban:<ip> >> '{}'", ban_log.display()))
                .unwrap();
            act.set_property(
                "actionunban",
                &format!("echo unban:<ip> >> '{}'", ban_log.display()),
            )
            .unwrap();
        }

        jail.start().await.unwrap();

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_file)
                .unwrap();
            writeln!(
                f,
                "May 14 08:30:01 host sshd[10]: Failed password for root from 203.0.113.42 port 22"
            )
            .unwrap();
            writeln!(
                f,
                "May 14 08:30:02 host sshd[11]: Failed password for root from 203.0.113.42 port 22"
            )
            .unwrap();
        }

        // Wait up to 4s for polling -> ban -> DB persistence -> 1s expiry -> unban.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut saw_ban_and_unban = false;
        while tokio::time::Instant::now() < deadline {
            if let Ok(contents) = std::fs::read_to_string(&ban_log)
                && contents.contains("ban:203.0.113.42")
                && contents.contains("unban:203.0.113.42")
            {
                saw_ban_and_unban = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            saw_ban_and_unban,
            "ban_log={:?}",
            std::fs::read_to_string(&ban_log)
        );

        // Verify SQLite bans history retained the ban while active bips was cleared on unban.
        {
            let guard = db.lock().unwrap();
            let (cnt, matches) = guard
                .get_bans_merged(&TicketId::parse("203.0.113.42"), Some("sshd"))
                .unwrap();
            assert_eq!(cnt, 2);
            assert_eq!(matches.len(), 2);
            let cur = guard
                .get_current_bans(Some("sshd"), None, None, current_unix_seconds() as i64)
                .unwrap();
            assert!(cur.is_empty());
        }

        jail.stop().await.unwrap();
    }

    #[tokio::test]
    async fn jail_restore_bans_respects_norestored_and_increment() {
        let dir = TempDir::new().unwrap();
        let ban_log = dir.path().join("actions.log");
        let db = Arc::new(std::sync::Mutex::new(
            Fail2BanDb::open(":memory:", 86_400, 10).unwrap(),
        ));

        let now = current_unix_seconds();
        {
            let guard = db.lock().unwrap();
            guard.add_jail("sshd").unwrap();
            let mut t = Ticket::new(TicketId::parse("198.51.100.7"), now);
            t.ban_count = 2;
            t.ban_time = Some(600);
            t.matches = vec!["prior match".to_owned()];
            guard.add_ban("sshd", &t, 600).unwrap();
        }

        let jail = Jail::new("sshd", "polling", Some(Arc::clone(&db))).unwrap();
        {
            let mut st = jail.state.lock().await;
            st.filter.set_ignore_self(false);
            st.ban_extra.set_opt("increment", Some("true")).unwrap();

            st.add_action("fw", None, None).unwrap();
            st.get_action_mut("fw")
                .unwrap()
                .set_property("actionban", &format!("echo fw:<ip> >> '{}'", ban_log.display()))
                .unwrap();

            st.add_action("notify", None, None).unwrap();
            let notify = st.get_action_mut("notify").unwrap();
            notify.set_property("norestored", "true").unwrap();
            notify
                .set_property(
                    "actionban",
                    &format!("echo notify:<ip> >> '{}'", ban_log.display()),
                )
                .unwrap();
        }

        jail.start().await.unwrap();
        {
            let st = jail.state.lock().await;
            assert!(st.ban_manager.in_ban_list(&TicketId::parse("198.51.100.7")));
            let restored = st
                .ban_manager
                .get_ticket_by_id(&TicketId::parse("198.51.100.7"))
                .unwrap();
            assert_eq!(restored.ban_count, 2);
            assert!(restored.restored);
        }

        let logged = std::fs::read_to_string(&ban_log).unwrap();
        assert!(logged.contains("fw:198.51.100.7"));
        assert!(!logged.contains("notify:198.51.100.7"));

        jail.stop().await.unwrap();
    }

    #[tokio::test]
    async fn jail_status_and_ban_list_formats_match_upstream() {
        let jail = Jail::new("sshd", "polling", None).unwrap();
        {
            let mut st = jail.state.lock().await;
            st.add_log_path(PathBuf::from("/var/log/auth.log"), false);
            st.ban_manager.set_ban_time(600);
            let mut t = Ticket::new(TicketId::parse("192.0.2.9"), 1_700_000_000.0);
            t.ban_time = Some(-1);
            assert_eq!(
                st.ban_manager.add_ban_ticket(t, 1_700_000_000.0),
                AddBanOutcome::Added
            );

            let basic = st.status("basic");
            let sections = basic.as_list().unwrap();
            assert_eq!(sections.len(), 2);

            let stats = st.status("stats");
            let parts = stats.as_list().unwrap();
            assert_eq!(parts[0].as_str(), Some("polling"));

            let list_wt = st.get_ban_list(true);
            assert_eq!(list_wt.len(), 1);
            assert!(list_wt[0].contains("192.0.2.9 \t"));
            assert!(list_wt[0].contains("+ -1 = 9999-12-31 23:59:59"));
        }
    }
}
