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

use crate::action::{ActionKind, CommandAction, SmtpAction};
use crate::banmanager::{AddBanOutcome, BanManager, PendingActions};
use crate::config::spec;
use crate::db::Fail2BanDb;
use crate::duration::time2str;
use crate::error::{Error, Result};
use crate::f2b_log;
use crate::failmanager::FailManager;
use crate::filter::backend::inotify::FilterPyinotify;
use crate::filter::backend::polling::FilterPoll;
use crate::filter::backend::systemd::{
    FilterSystemd, parse_systemd_journal_options, validate_journal_config,
    validate_journal_match_tokens,
};
use crate::filter::backend::{AutoSeekConfig, BackendKind, FileLogConfig, JournalConfig, LogEvent};
use crate::filter::file_identity::file_first_line_sha1;
use crate::filter::ipdns::{
    CymruInfo, IgnoreDecision, PendingIgnoreCommand, allow_ipv6, dns_to_ip,
    run_ignore_command_async,
};
use crate::filter::{DeferredLineWork, Filter, FilterReloadSnapshot, LogEncoding, MatchResult};
use crate::logging::LogLevel;
use crate::observer::{self, BanTimeExtra};
use crate::protocol::PickleValue;
use crate::ticket::{ActionContext, ActionJailStats, Ticket, TicketId};

const EVENT_CHANNEL_CAPACITY: usize = 1024;
const PERIODIC_CHECK_INTERVAL_SECS: f64 = 30.0;
const CONSISTENCY_THROTTLE_SECS: f64 = 3.0;

/// Current Unix timestamp in seconds.
pub fn current_unix_seconds() -> f64 {
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
    journal_files: Vec<PathBuf>,
    journal_namespace: Option<String>,
    journal_rotated: bool,
    use_dns: Option<String>,
}

pub(crate) fn validate_backend_spec(raw: &str) -> Result<()> {
    parse_backend_spec(raw).map(|_| ())
}

fn parse_backend_spec(raw: &str) -> Result<ParsedBackend> {
    let trimmed = raw.trim();
    let parsed = spec::parse(trimmed)?;
    let kind = BackendKind::parse(parsed.name).map_err(|_| {
        let msg = format!(
            "Unknown backend {}. Must be among ['pyinotify', 'polling', 'systemd'] or 'auto'",
            parsed.name
        );
        f2b_log!(LogLevel::Error, "fail2ban.jail", "{msg}");
        Error::invalid_command(msg)
    })?;
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

    if real_backend != BackendKind::Systemd {
        if !parsed.parameters.is_empty() {
            return Err(Error::invalid_command(format!(
                "Backend {:?} got unexpected keyword arguments: {:?}",
                parsed.name,
                parsed.parameters.keys().collect::<Vec<_>>()
            )));
        }
        return Ok(ParsedBackend {
            real_backend,
            journal_flags: None,
            journal_path: None,
            journal_files: Vec::new(),
            journal_namespace: None,
            journal_rotated: false,
            use_dns: None,
        });
    }

    let jopts = parse_systemd_journal_options(&parsed.parameters, Vec::new())?;
    Ok(ParsedBackend {
        real_backend,
        journal_flags: jopts.config.flags,
        journal_path: jopts.config.path,
        journal_files: jopts.config.files,
        journal_namespace: jopts.config.namespace,
        journal_rotated: jopts.config.rotated,
        use_dns: jopts.use_dns,
    })
}

/// Snapshot of state saved during `reload_begin` to detect whether the log backend needs restart
/// or to roll back when a reload stream fails.
#[derive(Debug)]
struct ReloadSnapshot {
    was_idle: bool,
    log_paths: Vec<(PathBuf, bool)>,
    journal_matches: Vec<Vec<String>>,
    encoding: LogEncoding,
    filter: FilterReloadSnapshot,
    fail_max_retry: u64,
    fail_max_time: f64,
    fail_max_matches: usize,
    ban_time: i64,
    ban_extra: BanTimeExtra,
    file_checkpoints: BTreeMap<PathBuf, (String, u64)>,
    dirty_file_checkpoints: BTreeSet<PathBuf>,
}

/// Per-jail action registry and reload bookkeeping, protected by its own mutex so slow
/// action I/O (shell commands, SMTP) never blocks `JailState` reads (`status`, `banned`, `get`).
///
/// Lock hierarchy invariant: `Jail.actions` -> `Jail.state` (never reversed); `Jail.state` is
/// never held across `.await`.
pub struct JailActions {
    pub entries: Vec<(String, ActionKind)>,
    action_ban_epochs: BTreeMap<String, u64>,
    reload_actions: Option<Vec<(String, Option<String>)>>,
    reload_added_actions: Vec<String>,
    replaced_actions: Vec<(String, ActionKind)>,
    saved_command_actions: BTreeMap<String, CommandAction>,
    saved_smtp_actions: BTreeMap<String, SmtpAction>,
}

impl std::fmt::Debug for JailActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailActions")
            .field("count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl JailActions {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            action_ban_epochs: BTreeMap::new(),
            reload_actions: None,
            reload_added_actions: Vec::new(),
            replaced_actions: Vec::new(),
            saved_command_actions: BTreeMap::new(),
            saved_smtp_actions: BTreeMap::new(),
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|(n, _)| n.clone()).collect()
    }

    pub fn get_mut(&mut self, act_name: &str) -> Option<&mut ActionKind> {
        self.entries
            .iter_mut()
            .find(|(n, _)| n == act_name)
            .map(|(_, a)| a)
    }

    pub fn del_action(&mut self, act_name: &str) -> Result<()> {
        let Some(pos) = self.entries.iter().position(|(n, _)| n == act_name) else {
            return Err(Error::invalid_command(format!(
                "Invalid Action name: {act_name}"
            )));
        };
        self.entries.remove(pos);
        self.action_ban_epochs.remove(act_name);
        Ok(())
    }

    fn reload_begin(&mut self) {
        self.saved_command_actions.clear();
        self.saved_smtp_actions.clear();
        for (name, act) in &self.entries {
            match act {
                ActionKind::Command(cmd) => {
                    self.saved_command_actions.insert(name.clone(), cmd.clone());
                }
                ActionKind::Smtp(smtp) => {
                    self.saved_smtp_actions.insert(name.clone(), smtp.clone());
                }
            }
        }
        self.reload_actions = Some(Vec::new());
        self.reload_added_actions.clear();
        self.replaced_actions.clear();
    }

    fn reload_abort(&mut self) {
        self.reload_actions = None;
        for name in self.reload_added_actions.drain(..).rev() {
            if let Some(pos) = self.entries.iter().position(|(n, _)| n == &name) {
                self.entries.remove(pos);
                self.action_ban_epochs.remove(&name);
            }
        }
        for (name, old_act) in self.replaced_actions.drain(..).rev() {
            if let Some(pos) = self.entries.iter().position(|(n, _)| n == &name) {
                self.action_ban_epochs
                    .insert(name.clone(), old_act.ban_epoch());
                self.entries[pos].1 = old_act;
            }
        }
        for (name, act) in &mut self.entries {
            if let Some(orig) = self.saved_command_actions.get(name) {
                *act = ActionKind::Command(orig.clone());
            } else if let Some(orig) = self.saved_smtp_actions.get(name) {
                *act = ActionKind::Smtp(orig.clone());
            }
        }
        self.saved_command_actions.clear();
        self.saved_smtp_actions.clear();
    }
}

/// Synchronous per-jail Fail2Ban state machine (never held across async I/O).
pub struct JailState {
    pending_unbans: BTreeMap<TicketId, PendingUnban>,
    dirty_bans: BTreeMap<TicketId, Ticket>,
    pub name: String,
    pub backend_spec: String,
    pub real_backend: BackendKind,
    pub alive: bool,
    pub idle: bool,
    pub filter: Filter,
    pub fail_manager: FailManager,
    pub ban_manager: BanManager,
    pub ban_extra: BanTimeExtra,
    pub log_paths: Vec<(PathBuf, bool)>,
    pub journal_matches: Vec<Vec<String>>,
    pub journal_flags: Option<u32>,
    pub journal_path: Option<PathBuf>,
    pub journal_files: Vec<PathBuf>,
    pub journal_namespace: Option<String>,
    pub journal_rotated: bool,
    pub db: Option<Arc<std::sync::Mutex<Fail2BanDb>>>,
    last_consistency_check: f64,
    last_periodic_check: f64,
    file_checkpoints: BTreeMap<PathBuf, (String, u64)>,
    dirty_file_checkpoints: BTreeSet<PathBuf>,
    last_journal_ts: Option<f64>,
    last_journal_cursor: Option<String>,
    journal_dirty: bool,
    journal_events_since_sync: u64,
    last_journal_db_sync: f64,
    journalctl_bin: String,
    backend_error: Arc<std::sync::Mutex<Option<String>>>,
    reloading: bool,
    reload_logs: Option<BTreeSet<PathBuf>>,
    reload_snapshot: Option<ReloadSnapshot>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnbanReason {
    Explicit,
    Automatic,
    Stop,
}

#[derive(Default)]
struct PendingUnban {
    forget_history: bool,
    completed: BTreeSet<String>,
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
        let mut filter = Filter::new(&name);
        if let Some(ref dns) = parsed.use_dns {
            filter.set_use_dns_str(dns)?;
        }
        Ok(Self {
            name,
            backend_spec,
            real_backend: parsed.real_backend,
            alive: false,
            idle: false,
            filter,
            fail_manager: FailManager::new(),
            ban_manager: BanManager::new(),
            pending_unbans: BTreeMap::new(),
            dirty_bans: BTreeMap::new(),
            ban_extra: BanTimeExtra::new(),
            log_paths: Vec::new(),
            journal_matches: Vec::new(),
            journal_flags: parsed.journal_flags,
            journal_path: parsed.journal_path,
            journal_files: parsed.journal_files,
            journal_namespace: parsed.journal_namespace,
            journal_rotated: parsed.journal_rotated,
            db,
            last_consistency_check: 0.0,
            last_periodic_check: current_unix_seconds(),
            file_checkpoints: BTreeMap::new(),
            dirty_file_checkpoints: BTreeSet::new(),
            last_journal_ts: None,
            last_journal_cursor: None,
            journal_dirty: false,
            journal_events_since_sync: 0,
            last_journal_db_sync: 0.0,
            journalctl_bin: "journalctl".to_owned(),
            backend_error: Arc::new(std::sync::Mutex::new(None)),
            reloading: false,
            reload_logs: None,
            reload_snapshot: None,
        })
    }

    pub fn backend_display_name(&self) -> &'static str {
        self.real_backend.as_str()
    }

    pub fn is_reloading(&self) -> bool {
        self.reloading
    }

    pub fn set_journalctl_bin(&mut self, bin: impl Into<String>) {
        self.journalctl_bin = bin.into();
    }

    pub fn backend_error(&self) -> Option<String> {
        self.backend_error.lock().ok().and_then(|g| g.clone())
    }

    fn set_backend_error(&self, err: Option<String>) {
        if let Ok(mut guard) = self.backend_error.lock() {
            *guard = err;
        }
    }

    fn journal_config(&self) -> JournalConfig {
        JournalConfig {
            matches: self.journal_matches.clone(),
            flags: self.journal_flags,
            path: self.journal_path.clone(),
            files: self.journal_files.clone(),
            namespace: self.journal_namespace.clone(),
            rotated: self.journal_rotated,
        }
    }

    fn systemd_validation_target(&self) -> Option<(JournalConfig, String)> {
        (self.real_backend == BackendKind::Systemd)
            .then(|| (self.journal_config(), self.journalctl_bin.clone()))
    }

    /// Add a log file path to monitor (`FileFilter.addLogPath` semantics).
    pub fn add_log_path(&mut self, path: PathBuf, tail: bool) -> Result<()> {
        if self.real_backend == BackendKind::Systemd {
            return Ok(());
        }
        if let Some(ref mut reload_set) = self.reload_logs
            && reload_set.remove(&path)
        {
            return Ok(());
        }
        if self.log_paths.iter().any(|(p, _)| p == &path) {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.filter",
                "{} already exists",
                path.display()
            );
            return Ok(());
        }
        let check_file = || {
            let file = std::fs::File::open(&path)?;
            if file.metadata()?.is_dir() {
                return Err(std::io::Error::from_raw_os_error(nix::libc::EISDIR));
            }
            Ok(())
        };
        check_file().map_err(|source| Error::LogPath {
            path: path.clone(),
            source,
        })?;
        self.log_paths.push((path, tail));
        Ok(())
    }

    /// Remove a monitored log file path (`FileFilter.delLogPath` semantics).
    pub fn del_log_path(&mut self, path: &Path) {
        if self.real_backend == BackendKind::Systemd {
            return;
        }
        self.log_paths.retain(|(p, _)| p != path);
        self.file_checkpoints.remove(path);
        self.dirty_file_checkpoints.remove(path);
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

    /// Begin reload phase on state: pause processing, clear regex/ignore/journal lists, and snapshot logs.
    fn reload_begin_state(&mut self) {
        let was_idle = self.idle;
        self.idle = true;
        self.reloading = true;
        let encoding = self.filter.log_encoding();
        let filter_snap = self.filter.snapshot_and_clear_for_reload();
        self.reload_snapshot = Some(ReloadSnapshot {
            was_idle,
            log_paths: self.log_paths.clone(),
            journal_matches: std::mem::take(&mut self.journal_matches),
            encoding,
            filter: filter_snap,
            fail_max_retry: self.fail_manager.max_retry(),
            fail_max_time: self.fail_manager.max_time(),
            fail_max_matches: self.fail_manager.max_matches(),
            ban_time: self.ban_manager.ban_time(),
            ban_extra: self.ban_extra.clone(),
            file_checkpoints: self.file_checkpoints.clone(),
            dirty_file_checkpoints: self.dirty_file_checkpoints.clone(),
        });

        let existing_logs: BTreeSet<PathBuf> =
            self.log_paths.iter().map(|(p, _)| p.clone()).collect();
        self.reload_logs = Some(existing_logs);
    }

    /// Roll back state portion of an in-progress reload.
    fn reload_abort_state(&mut self) -> bool {
        self.reload_logs = None;
        if let Some(snap) = self.reload_snapshot.take() {
            self.idle = snap.was_idle;
            self.log_paths = snap.log_paths;
            self.journal_matches = snap.journal_matches;
            self.filter.restore_reload_snapshot(snap.filter);
            self.fail_manager.set_max_retry(snap.fail_max_retry);
            self.fail_manager.set_max_time(snap.fail_max_time);
            self.fail_manager.set_max_matches(snap.fail_max_matches);
            self.ban_manager.set_ban_time(snap.ban_time);
            self.ban_extra = snap.ban_extra;
            self.file_checkpoints = snap.file_checkpoints;
            self.dirty_file_checkpoints = snap.dirty_file_checkpoints;
        } else {
            self.idle = false;
        }
        self.reloading = false;
        self.idle
    }

    fn reload_commit_state(&mut self) -> (bool, bool) {
        if let Some(obsolete_logs) = self.reload_logs.take() {
            for path in obsolete_logs {
                self.del_log_path(&path);
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
        (backend_changed, self.idle)
    }

    fn handle_log_event_phase1_sync(
        &mut self,
        ev: LogEvent,
        now: f64,
    ) -> (Vec<Ticket>, Option<DeferredLogLine>) {
        match ev {
            LogEvent::Checkpoint {
                path,
                fingerprint,
                offset,
            } => {
                let pb = PathBuf::from(&path);
                self.file_checkpoints
                    .insert(pb.clone(), (fingerprint.clone(), offset));
                if self.db_update_log(&path, &fingerprint, offset) {
                    self.dirty_file_checkpoints.remove(&pb);
                } else {
                    self.dirty_file_checkpoints.insert(pb);
                }
                (Vec::new(), None)
            }
            LogEvent::Line {
                line,
                preset_date,
                log_path,
                in_operation,
                checkpoint,
                journal_cursor,
            } => {
                self.filter.set_in_operation(in_operation);
                let (processed, deferred) =
                    self.filter
                        .process_line_defer_ignore_cmd(&line, preset_date, now);
                let mut bans = Vec::new();
                for m in processed.results {
                    if let Some(ticket) = self.apply_match_result_sync(m, now) {
                        bans.push(ticket);
                    }
                }
                let deferred_line = Some(DeferredLogLine {
                    work: deferred,
                    log_path,
                    checkpoint,
                    journal_cursor,
                    preset_date,
                });
                (bans, deferred_line)
            }
        }
    }

    fn apply_match_result_sync(&mut self, m: MatchResult, now: f64) -> Option<Ticket> {
        let fid = m.fid.or_else(|| m.ip.clone())?;
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
        if self.ban_extra.increment() {
            let boost = self.db_failure_found_boost(&mut ticket);
            if boost > 0 {
                attempts = self.fail_manager.add_failure(ticket, boost, true);
            }
        }

        if attempts >= self.fail_manager.max_retry() {
            return self.fail_manager.to_ban(Some(&fid));
        }
        None
    }

    fn advance_line_checkpoints(
        &mut self,
        log_path: Option<String>,
        checkpoint: Option<(String, u64)>,
        journal_cursor: Option<String>,
        preset_date: Option<f64>,
        now: f64,
    ) {
        // Advance offsets only after the line and any resulting ban writes have completed;
        // SQLite persistence happens in batches on LogEvent::Checkpoint, periodic_tick, or shutdown.
        if let (Some(path), Some((fp, offset))) = (log_path, checkpoint) {
            let pb = PathBuf::from(path);
            self.file_checkpoints.insert(pb.clone(), (fp, offset));
            self.dirty_file_checkpoints.insert(pb);
        }
        if let Some(cursor) = journal_cursor {
            self.last_journal_cursor = Some(cursor);
        }
        if let Some(ts) = preset_date {
            self.last_journal_ts = Some(ts);
            if self.real_backend == BackendKind::Systemd {
                self.journal_dirty = true;
                self.journal_events_since_sync += 1;
                if self.journal_events_since_sync >= 100 || now >= self.last_journal_db_sync + 5.0 {
                    self.flush_journal_pos_to_db(now);
                }
            }
        }
    }

    /// Synchronous state step for the 1-second maintenance tick: expire bans, clean stale failures,
    /// flush batched checkpoints, and report whether periodic action consistency checks are due.
    fn prepare_periodic_tick(&mut self, now: f64) -> (String, Vec<TicketId>, bool) {
        self.fail_manager.cleanup(now);
        self.flush_file_checkpoints_to_db();

        if self.journal_dirty && now >= self.last_journal_db_sync + 5.0 {
            self.flush_journal_pos_to_db(now);
        }

        let due_check = if now >= self.last_periodic_check + PERIODIC_CHECK_INTERVAL_SECS {
            self.last_periodic_check = now;
            true
        } else {
            false
        };
        let mut due = self.ban_manager.expired_ids(now);
        due.retain(|id| !self.pending_unbans.contains_key(id));
        if due_check {
            due.extend(self.pending_unbans.keys().cloned());
            self.retry_ban_writes();
        }
        (self.name.clone(), due, due_check)
    }

    /// Synchronous state transition for banning a ticket; returns the action work to run unlocked.
    fn prepare_ban_ticket(&mut self, mut ticket: Ticket, now: f64) -> PreparedBan {
        let already_banned = self.ban_manager.in_ban_list(&ticket.fid);
        let mut incremented_in_observer = false;

        if !ticket.restored && self.ban_extra.increment() {
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
        if !already_banned && (incremented_in_observer || ticket.restored) && ticket.ban_count > 0 {
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
                PreparedBan::Added {
                    jail_name: self.name.clone(),
                    ticket: stored,
                    ctx,
                }
            }
            AddBanOutcome::Prolonged(prolonged) => {
                let ctx = self.build_action_context(&prolonged, false);
                PreparedBan::Prolonged {
                    jail_name: self.name.clone(),
                    ticket: prolonged,
                    ctx,
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
                let run_check = if diftm > CONSISTENCY_THROTTLE_SECS
                    && now > self.last_consistency_check + CONSISTENCY_THROTTLE_SECS
                {
                    self.last_consistency_check = now;
                    true
                } else {
                    false
                };
                PreparedBan::Duplicate {
                    jail_name: self.name.clone(),
                    run_check,
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
                PreparedBan::Expired
            }
        }
    }

    fn active_ticket_contexts(
        &self,
        skip_fid: Option<&TicketId>,
    ) -> Vec<(TicketId, ActionContext)> {
        self.ban_manager
            .get_ban_list(false)
            .into_iter()
            .filter_map(|id| self.ban_manager.get_ticket_by_id(&id))
            .chain(self.ban_manager.pending_tickets())
            .filter(|ticket| {
                skip_fid != Some(&ticket.fid) && !self.pending_unbans.contains_key(&ticket.fid)
            })
            .map(|t| {
                let ctx = self.build_action_context(t, false);
                (t.fid.clone(), ctx)
            })
            .collect()
    }

    fn record_attempt_failure(
        &mut self,
        id: TicketId,
        mut ticket: Ticket,
        count: u64,
        now: f64,
    ) -> Option<Ticket> {
        f2b_log!(
            LogLevel::Info,
            "fail2ban.filter",
            "[{}] Attempt {} - {}",
            self.name,
            id,
            time2str(now)
        );
        let mut attempts = self.fail_manager.add_failure(ticket.clone(), count, false);
        if self.ban_extra.increment() {
            let boost = self.db_failure_found_boost(&mut ticket);
            if boost > 0 {
                attempts = self.fail_manager.add_failure(ticket, boost, true);
            }
        }
        if attempts >= self.fail_manager.max_retry() {
            return self.fail_manager.to_ban(Some(&id));
        }
        None
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
        let backend_err = self.backend_error();

        if flavor == "stats" {
            let backend_label = match backend_err {
                Some(_) => format!("{} (error)", self.backend_display_name()),
                None => self.backend_display_name().to_owned(),
            };
            return PickleValue::List(vec![
                PickleValue::Str(backend_label),
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
        if let Some(err) = backend_err {
            filter_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Backend error".to_owned()),
                PickleValue::Str(err),
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
            let banned_ids = self.ban_manager.get_ban_list(false);
            let cymru = crate::filter::ipdns::lookup_cymru_info(&banned_ids);
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned ASN list".to_owned()),
                PickleValue::str_list(cymru.asns),
            ]));
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned Country list".to_owned()),
                PickleValue::str_list(cymru.countries),
            ]));
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned RIR list".to_owned()),
                PickleValue::str_list(cymru.rirs),
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

    /// Snapshot basic status + banned IDs under lock so Cymru DNS lookups run without holding locks.
    pub fn status_snapshot_for_cymru(&self) -> (PickleValue, Vec<TicketId>) {
        (self.status("basic"), self.ban_manager.get_ban_list(false))
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
            jail_stats: ActionJailStats {
                banned: self.ban_manager.size(),
                banned_total: self.ban_manager.total_bans(),
                found: self.fail_manager.size(),
                found_total: self.fail_manager.total_failures(),
            },
        }
    }

    fn build_file_log_configs(&mut self) -> Vec<FileLogConfig> {
        let mut out = Vec::with_capacity(self.log_paths.len());
        let seek_cutoff = if self.filter.check_find_time() {
            Some(current_unix_seconds() - self.filter.find_time())
        } else {
            None
        };
        for (path, tail) in &self.log_paths {
            let auto_seek = if !*tail {
                seek_cutoff.map(|start_time| AutoSeekConfig {
                    start_time,
                    date_detector: self.filter.date_detector().clone(),
                })
            } else {
                None
            };
            if let Some((fp, off)) = self.file_checkpoints.get(path) {
                out.push(FileLogConfig {
                    path: path.clone(),
                    tail: *tail,
                    resume_fingerprint: Some(fp.clone()),
                    resume_offset: *off,
                    auto_seek: None,
                });
                continue;
            }
            if *tail {
                if let Ok(mut f) = File::open(path)
                    && let Ok(meta) = f.metadata()
                {
                    let len = meta.len();
                    let fp = file_first_line_sha1(&mut f, len).unwrap_or_default();
                    self.file_checkpoints
                        .insert(path.clone(), (fp.clone(), len));
                    out.push(FileLogConfig {
                        path: path.clone(),
                        tail: true,
                        resume_fingerprint: Some(fp),
                        resume_offset: len,
                        auto_seek: None,
                    });
                    continue;
                }
                out.push(FileLogConfig {
                    path: path.clone(),
                    tail: true,
                    resume_fingerprint: None,
                    resume_offset: 0,
                    auto_seek: None,
                });
                continue;
            }
            let (resume_fingerprint, resume_offset) = self.db_add_log_offset(path);
            out.push(FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint,
                resume_offset,
                auto_seek,
            });
        }
        out
    }

    fn flush_file_checkpoints_to_db(&mut self) {
        if self.dirty_file_checkpoints.is_empty() {
            return;
        }
        for path in std::mem::take(&mut self.dirty_file_checkpoints) {
            if let Some((fp, off)) = self.file_checkpoints.get(&path) {
                let path_str = path.to_string_lossy();
                if !self.db_update_log(&path_str, fp, *off) {
                    self.dirty_file_checkpoints.insert(path);
                }
            }
        }
    }

    fn restore_tickets_from_db(&mut self, now: f64) -> Vec<Ticket> {
        let Some(ref db_arc) = self.db else {
            return Vec::new();
        };
        let base_ban_time = self.ban_manager.ban_time();
        let forbantime = (!self.ban_extra.increment()).then_some(base_ban_time);
        let correct_ban_time = Some(self.ban_extra.max_ban_time(base_ban_time));
        let Ok(guard) = db_arc.lock() else {
            return Vec::new();
        };
        match guard.get_current_bans_with_base(
            Some(&self.name),
            forbantime,
            correct_ban_time,
            Some(base_ban_time),
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
                Vec::new()
            }
        }
    }

    fn split_restored_tickets_for_ignore(
        &mut self,
        tickets: Vec<Ticket>,
    ) -> (Vec<Ticket>, Vec<(Ticket, PendingIgnoreCommand)>) {
        let mut kept = Vec::new();
        let mut pending = Vec::new();
        for t in tickets {
            match self.filter.check_ignore_static(&t.fid, Some(&t)) {
                IgnoreDecision::Decided(true) => {}
                IgnoreDecision::Decided(false) => kept.push(t),
                IgnoreDecision::RunCommand(cmd) => pending.push((t, cmd)),
            }
        }
        (kept, pending)
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

    fn db_update_log(&self, path: &str, fingerprint: &str, offset: u64) -> bool {
        let Some(db) = &self.db else {
            return true;
        };
        let Ok(guard) = db.lock() else {
            return false;
        };
        if let Err(err) = guard.update_log(&self.name, path, fingerprint, offset) {
            f2b_log!(
                LogLevel::Warning,
                "fail2ban.jail",
                "Failed to update log checkpoint for '{}' ({path}): {err}",
                self.name
            );
            return false;
        }
        true
    }

    fn db_get_journal_pos(&self) -> Option<f64> {
        let db_arc = self.db.as_ref()?;
        let guard = db_arc.lock().ok()?;
        guard
            .get_journal_pos(&self.name, "systemd-journal")
            .ok()
            .flatten()
    }

    fn flush_journal_pos_to_db(&mut self, now: f64) {
        if !self.journal_dirty {
            return;
        }
        let Some(ts) = self.last_journal_ts else {
            self.journal_dirty = false;
            return;
        };
        self.last_journal_db_sync = now;
        self.journal_events_since_sync = 0;
        if let Some(ref db_arc) = self.db {
            let Ok(guard) = db_arc.lock() else {
                return;
            };
            let iso = format!("{} ", time2str(ts));
            if let Err(err) = guard.update_journal(&self.name, "systemd-journal", ts, &iso) {
                f2b_log!(
                    LogLevel::Warning,
                    "fail2ban.jail",
                    "Failed to update systemd-journal checkpoint for '{}': {err}",
                    self.name
                );
                return;
            }
        }
        self.journal_dirty = false;
    }

    fn write_ban(&self, ticket: &Ticket) -> Result<()> {
        if let Some(db) = &self.db {
            db.lock()
                .map_err(|_| Error::database("database lock poisoned"))?
                .add_ban(&self.name, ticket, self.ban_manager.ban_time())?;
        }
        Ok(())
    }

    fn db_add_ban(&mut self, ticket: &Ticket) {
        if let Err(err) = self.write_ban(ticket) {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.jail",
                "Failed to persist ban for '{}' ({}), will retry: {err}",
                self.name,
                ticket.fid
            );
            let mut pending = ticket.clone();
            pending.ban_time = Some(ticket.effective_ban_time(self.ban_manager.ban_time()));
            self.dirty_bans.insert(ticket.fid.clone(), pending);
        } else {
            self.dirty_bans.remove(&ticket.fid);
        }
    }

    fn retry_ban_writes(&mut self) {
        // A locked/full database affects the whole batch. Wait until the next tick
        // after one failed write instead of waiting out the busy timeout for every IP.
        while let Some(entry) = self.dirty_bans.first_key_value() {
            if let Err(err) = self.write_ban(entry.1) {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.jail",
                    "Ban persistence still pending for '{}' ({}): {err}",
                    self.name,
                    entry.0
                );
                break;
            }
            self.dirty_bans.pop_first();
        }
    }

    fn db_del_ban(&self, id: Option<&TicketId>) -> Result<()> {
        if let Some(ref db_arc) = self.db {
            let guard = db_arc
                .lock()
                .map_err(|_| Error::database("database lock poisoned"))?;
            if let Err(err) = guard.del_ban(&self.name, id) {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.jail",
                    "Failed to delete active ban in '{}' from database: {err}",
                    self.name
                );
                return Err(err);
            }
        }
        Ok(())
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

struct FlushPassResult {
    skip_unban: BTreeSet<String>,
    first_error: Option<Error>,
}

/// Run `flush()` across `actions` following upstream `Actions.__flushBan` (`actions.py:652-676`),
/// invoking `consistencyCheck` on flush errors when available.
async fn flush_actions_or_check(
    jail_name: &str,
    actions: &mut [(String, ActionKind)],
    on_stop: bool,
    continue_on_error: bool,
) -> FlushPassResult {
    let mut skip_unban = BTreeSet::new();
    let mut first_error = None;
    for (act_name, act) in actions {
        if !act.supports_flush() {
            continue;
        }
        f2b_log!(
            LogLevel::Notice,
            "fail2ban.actions",
            "[{jail_name}] Flush ticket(s) with {act_name}"
        );
        match act.flush().await {
            Ok(true) => {
                skip_unban.insert(act_name.clone());
            }
            Ok(false) => {}
            Err(err) => {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.actions",
                    "Failed to flush bans in jail '{jail_name}' action '{act_name}': {err}"
                );
                f2b_log!(
                    LogLevel::Info,
                    "fail2ban.actions",
                    "No flush occurred, do consistency check"
                );
                if act.has_consistency_check() {
                    if let Err(chk_err) = act.consistency_check_on_flush(on_stop).await {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Consistency check error for jail '{jail_name}' action '{act_name}': {chk_err}"
                        );
                        if first_error.is_none() {
                            first_error = Some(chk_err);
                        }
                        if !continue_on_error {
                            break;
                        }
                        continue;
                    }
                    if on_stop && !continue_on_error {
                        skip_unban.insert(act_name.clone());
                    }
                }
            }
        }
    }
    FlushPassResult {
        skip_unban,
        first_error,
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

enum PreparedBan {
    Added {
        jail_name: String,
        ticket: Ticket,
        ctx: ActionContext,
    },
    Prolonged {
        jail_name: String,
        ticket: Ticket,
        ctx: ActionContext,
    },
    Duplicate {
        jail_name: String,
        run_check: bool,
    },
    Expired,
}

struct JailTasks {
    backend_shut_tx: watch::Sender<bool>,
    worker_shut_tx: watch::Sender<bool>,
    idle_tx: watch::Sender<bool>,
    replace_rx_tx: mpsc::UnboundedSender<mpsc::Receiver<LogEvent>>,
    backend_handle: Option<JoinHandle<()>>,
    worker_handle: Option<JoinHandle<()>>,
}

/// Async thread-safe handle to a single Fail2Ban jail and its background tasks.
#[derive(Clone)]
pub struct Jail {
    pub state: Arc<Mutex<JailState>>,
    pub actions: Arc<Mutex<JailActions>>,
    tasks: Arc<Mutex<Option<JailTasks>>>,
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
            actions: Arc::new(Mutex::new(JailActions::new())),
            tasks: Arc::new(Mutex::new(None)),
        })
    }

    /// Validate that the configured backend reader can start cleanly without holding `state` across I/O.
    pub async fn validate_backend(&self) -> Result<()> {
        let target = self.state.lock().await.systemd_validation_target();
        if let Some((cfg, bin)) = target {
            validate_journal_config(&cfg, &bin).await?;
        }
        Ok(())
    }

    /// Validate and add systemd journal match tokens (splitting on `+` into OR-groups).
    pub async fn add_journal_match(&self, tokens: &[String]) -> Result<()> {
        if tokens.is_empty() {
            return Ok(());
        }
        let (proposed_cfg, bin, new_groups) = {
            let st = self.state.lock().await;
            if st.real_backend != BackendKind::Systemd {
                return Ok(());
            }
            let new_groups = validate_journal_match_tokens(tokens)?;
            let mut proposed = st.journal_config();
            proposed.matches.extend(new_groups.iter().cloned());
            (proposed, st.journalctl_bin.clone(), new_groups)
        };
        validate_journal_config(&proposed_cfg, &bin).await?;
        self.state.lock().await.journal_matches.extend(new_groups);
        Ok(())
    }

    /// Remove a systemd journal match group (or all groups if `tokens` is empty) after validating the remaining reader.
    pub async fn del_journal_match(&self, tokens: &[String]) -> Result<()> {
        let (proposed_cfg, bin, proposed) = {
            let st = self.state.lock().await;
            if st.real_backend != BackendKind::Systemd {
                return Ok(());
            }
            let mut proposed = st.journal_matches.clone();
            if tokens.is_empty() {
                proposed.clear();
            } else if let Some(pos) = proposed.iter().position(|g| g == tokens) {
                proposed.remove(pos);
            } else {
                return Err(Error::invalid_command(format!(
                    "Match {tokens:?} not found"
                )));
            }
            let mut proposed_cfg = st.journal_config();
            proposed_cfg.matches = proposed.clone();
            (proposed_cfg, st.journalctl_bin.clone(), proposed)
        };
        validate_journal_config(&proposed_cfg, &bin).await?;
        self.state.lock().await.journal_matches = proposed;
        Ok(())
    }

    /// Add or reload an action, matching upstream `Actions.add` (`fail2ban/server/actions.py:131-150`).
    pub async fn add_action(
        &self,
        act_name: &str,
        python_path: Option<&str>,
        init_json: Option<&str>,
    ) -> Result<()> {
        let mut acts = self.actions.lock().await;
        let (jail_name, reloading) = {
            let st = self.state.lock().await;
            (st.name.clone(), st.reloading)
        };
        let init_str = init_json.unwrap_or("{}");
        if let Some(pos) = acts.entries.iter().position(|(n, _)| n == act_name) {
            if !reloading {
                return Err(Error::invalid_command(format!(
                    "Action {act_name} already exists"
                )));
            }
            if acts.entries[pos].1.has_reload() {
                if acts.entries[pos].1.has_clear_all_params() {
                    acts.entries[pos].1.clear_all_params().await?;
                    if let Some(ref mut reload_acts) = acts.reload_actions {
                        if let Some((_, existing_opts)) =
                            reload_acts.iter_mut().find(|(n, _)| n == act_name)
                        {
                            *existing_opts = init_json.map(str::to_owned);
                        } else {
                            reload_acts.push((act_name.to_owned(), init_json.map(str::to_owned)));
                        }
                    }
                }
                return Ok(());
            }
            let replacement = build_action(&jail_name, act_name, python_path, init_str)?;
            let repl_epoch = replacement.ban_epoch();
            let old = std::mem::replace(&mut acts.entries[pos].1, replacement);
            acts.replaced_actions.push((act_name.to_owned(), old));
            acts.action_ban_epochs
                .insert(act_name.to_owned(), repl_epoch);
            return Ok(());
        }

        let action = build_action(&jail_name, act_name, python_path, init_str)?;
        acts.action_ban_epochs
            .insert(act_name.to_owned(), action.ban_epoch());
        acts.entries.push((act_name.to_owned(), action));
        if reloading {
            acts.reload_added_actions.push(act_name.to_owned());
        }
        Ok(())
    }

    /// Remove an action by name (`delaction`).
    pub async fn del_action(&self, act_name: &str) -> Result<()> {
        self.actions.lock().await.del_action(act_name)
    }

    /// Execute the full ban pipeline for a single [`Ticket`] without holding `state` across action I/O.
    pub async fn ban_ticket(&self, ticket: Ticket, now: f64) {
        let mut acts = self.actions.lock().await;
        let _ = self.ban_ticket_locked(&mut acts, ticket, now).await;
    }

    async fn ban_ticket_locked(
        &self,
        acts: &mut JailActions,
        ticket: Ticket,
        now: f64,
    ) -> Result<()> {
        let mut st = self.state.lock().await;
        if st.pending_unbans.contains_key(&ticket.fid) {
            let id = ticket.fid.clone();
            drop(st);
            self.unban_one_locked(acts, &id, UnbanReason::Automatic)
                .await?;
            st = self.state.lock().await;
        }
        let (prepared, actions) =
            if let Some((stored, pending)) = st.ban_manager.pending_ban(&ticket.fid) {
                let actions = pending.clone();
                let stored = stored.clone();
                if stored
                    .end_of_ban(st.ban_manager.ban_time())
                    .is_some_and(|end| end < now)
                {
                    // Expire the old actions before accepting a fresh ban for this ID.
                    drop(st);
                    self.unban_one_locked(acts, &stored.fid, UnbanReason::Automatic)
                        .await?;
                    st = self.state.lock().await;
                    (st.prepare_ban_ticket(ticket, now), None)
                } else {
                    let mut ctx = st.build_action_context(&stored, !stored.restored);
                    ctx.jail_stats.banned += 1;
                    if !actions.previously_banned {
                        ctx.jail_stats.banned_total = ctx.jail_stats.banned_total.saturating_add(1);
                    }
                    (
                        PreparedBan::Added {
                            jail_name: st.name.clone(),
                            ticket: stored,
                            ctx,
                        },
                        Some(actions),
                    )
                }
            } else {
                (st.prepare_ban_ticket(ticket, now), None)
            };
        if let PreparedBan::Added { ticket: stored, .. } = &prepared
            && actions.is_none()
        {
            st.ban_manager.begin_actions(&stored.fid);
        }
        drop(st);
        match prepared {
            PreparedBan::Added {
                jail_name,
                ticket: stored,
                ctx,
            } => {
                let mut failed = PendingActions {
                    previously_banned: actions.as_ref().is_some_and(|p| p.previously_banned),
                    ..Default::default()
                };
                let mut repaired_indices = Vec::new();
                for (idx, (act_name, act)) in acts.entries.iter_mut().enumerate() {
                    let reban = actions.as_ref().is_some_and(|p| p.reban.contains(act_name));
                    if !reban
                        && ((stored.restored && act.norestored())
                            || actions.as_ref().is_some_and(|p| !p.ban.contains(act_name)))
                    {
                        continue;
                    }
                    let synced = acts.action_ban_epochs.get(act_name).copied().unwrap_or(0);
                    let applied = if reban {
                        act.reban(&ctx).await
                    } else {
                        act.ban(&ctx).await
                    };
                    if let Err(err) = applied {
                        if reban {
                            failed.reban.push(act_name.clone());
                        } else {
                            failed.ban.push(act_name.clone());
                        }
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to execute ban jail '{jail_name}' action '{act_name}' for {}: {err}",
                            stored.fid
                        );
                    } else if act.ban_epoch() > synced {
                        repaired_indices.push(idx);
                    }
                }
                if !repaired_indices.is_empty() {
                    self.reban_actions_for_active_tickets_locked(
                        acts,
                        &jail_name,
                        &repaired_indices,
                        Some(&stored.fid),
                    )
                    .await;
                }
                let names: Vec<_> = failed
                    .ban
                    .iter()
                    .chain(&failed.reban)
                    .map(String::as_str)
                    .collect();
                let err = (!names.is_empty()).then(|| {
                    Error::action(format!(
                        "[{jail_name}] Ban {} failed for action(s): {}",
                        stored.fid,
                        names.join(", ")
                    ))
                });
                let mut st = self.state.lock().await;
                let first = st.ban_manager.finish_actions(&stored.fid, failed);
                if let Some(err) = err {
                    return Err(err);
                }
                if !first {
                    return Ok(());
                }
                let prefix = if stored.restored { "Restore " } else { "" };
                f2b_log!(
                    LogLevel::Notice,
                    "fail2ban.actions",
                    "[{jail_name}] {prefix}Ban {}",
                    stored.fid
                );
                if !stored.restored {
                    st.db_add_ban(&stored);
                }
            }
            PreparedBan::Prolonged {
                jail_name,
                ticket: prolonged,
                ctx,
            } => {
                for (act_name, act) in &mut acts.entries {
                    if !act.prolongable() || (prolonged.restored && act.norestored()) {
                        continue;
                    }
                    if let Err(err) = act.prolong(&ctx).await {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to execute prolong jail '{jail_name}' action '{act_name}' for {}: {err}",
                            prolonged.fid
                        );
                    }
                }
                if !prolonged.restored {
                    self.state.lock().await.db_add_ban(&prolonged);
                }
            }
            PreparedBan::Duplicate {
                jail_name,
                run_check,
            } => {
                if run_check {
                    self.run_consistency_checks_locked(acts, &jail_name).await;
                }
            }
            PreparedBan::Expired => {}
        }
        Ok(())
    }

    async fn run_consistency_checks_locked(&self, acts: &mut JailActions, jail_name: &str) {
        let mut reban_indices = Vec::new();
        for (idx, (act_name, act)) in acts.entries.iter_mut().enumerate() {
            let synced_epoch = acts.action_ban_epochs.get(act_name).copied().unwrap_or(0);
            match act.consistency_check().await {
                Ok(true) => {
                    if act.ban_epoch() > synced_epoch {
                        reban_indices.push(idx);
                    }
                }
                Ok(false) => {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Consistency check failed for jail '{jail_name}' action '{act_name}'"
                    );
                }
                Err(err) => {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Consistency check error for jail '{jail_name}' action '{act_name}': {err}"
                    );
                }
            }
        }
        if !reban_indices.is_empty() {
            self.reban_actions_for_active_tickets_locked(acts, jail_name, &reban_indices, None)
                .await;
        }
    }

    async fn reban_actions_for_active_tickets_locked(
        &self,
        acts: &mut JailActions,
        jail_name: &str,
        reban_indices: &[usize],
        skip_fid: Option<&TicketId>,
    ) {
        let active = self.state.lock().await.active_ticket_contexts(skip_fid);
        for (fid, ctx) in &active {
            let pending = self
                .state
                .lock()
                .await
                .ban_manager
                .pending_ban(fid)
                .map(|(_, p)| p.clone());
            for &idx in reban_indices {
                let act_name = acts.entries[idx].0.clone();
                if pending
                    .as_ref()
                    .is_some_and(|p| p.ban.contains(&act_name) || p.reban.contains(&act_name))
                {
                    continue;
                }
                f2b_log!(
                    LogLevel::Notice,
                    "fail2ban.actions",
                    "[{jail_name}] Reban {fid}, action '{act_name}'"
                );
                if let Err(err) = acts.entries[idx].1.reban(ctx).await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Failed to execute reban jail '{jail_name}' action '{act_name}' for {fid}: {err}"
                    );
                    self.state
                        .lock()
                        .await
                        .ban_manager
                        .failed_reban(fid, act_name);
                }
            }
        }
        for &idx in reban_indices {
            let (ref act_name, ref act) = acts.entries[idx];
            acts.action_ban_epochs
                .insert(act_name.clone(), act.ban_epoch());
        }
    }

    // Keep the ticket and its durable record until every required action succeeds.
    // Remember successful actions: deleting an nftables element a second time can fail.
    async fn unban_one_locked(
        &self,
        acts: &mut JailActions,
        id: &TicketId,
        reason: UnbanReason,
    ) -> Result<()> {
        let (ctx, jail_name, completed, forget_history) = {
            let mut st = self.state.lock().await;
            let Some(ticket) = st.ban_manager.get_ticket_by_id(id) else {
                return Ok(());
            };
            let ctx = st.build_action_context(ticket, false);
            let jail_name = st.name.clone();
            let pending = st.pending_unbans.entry(id.clone()).or_default();
            pending.forget_history |= reason == UnbanReason::Explicit;
            (
                ctx,
                jail_name,
                pending.completed.clone(),
                pending.forget_history,
            )
        };
        let mut failure = None;
        for (name, act) in &mut acts.entries {
            if completed.contains(name) {
                continue;
            }
            match act.unban(&ctx).await {
                Ok(()) => {
                    let mut st = self.state.lock().await;
                    st.pending_unbans
                        .entry(id.clone())
                        .or_default()
                        .completed
                        .insert(name.clone());
                }
                Err(err) => {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "[{jail_name}] Unban {id} failed for action '{name}', will retry: {err}"
                    );
                    failure.get_or_insert(err);
                }
            }
        }
        if let Some(err) = failure {
            return Err(err);
        }
        let mut st = self.state.lock().await;
        if forget_history {
            st.db_del_ban(Some(id))?;
            st.dirty_bans.remove(id);
        }
        st.pending_unbans.remove(id);
        st.ban_manager.remove_by_id_deferred(id);
        let operation = if reason == UnbanReason::Stop && !forget_history {
            "Repeal Ban"
        } else {
            "Unban"
        };
        f2b_log!(
            LogLevel::Notice,
            "fail2ban.actions",
            "[{jail_name}] {operation} {id}"
        );
        Ok(())
    }

    async fn flush_bans_locked(
        &self,
        acts: &mut JailActions,
        jail_name: &str,
        on_stop: bool,
    ) -> Result<usize> {
        let clear_db = !on_stop;
        let reason = if on_stop {
            UnbanReason::Stop
        } else {
            UnbanReason::Explicit
        };
        let pass = flush_actions_or_check(jail_name, &mut acts.entries, on_stop, on_stop).await;
        let ids = {
            let mut st = self.state.lock().await;
            let ids = st.ban_manager.ordered_ids(|_| true);
            if clear_db || !pass.skip_unban.is_empty() {
                // A flush applies to the entire jail, even if a later SQLite delete fails.
                for id in &ids {
                    let pending = st.pending_unbans.entry(id.clone()).or_default();
                    pending.forget_history |= clear_db;
                    pending.completed.extend(pass.skip_unban.iter().cloned());
                }
            }
            ids
        };
        if !on_stop && let Some(err) = pass.first_error {
            return Err(err);
        }
        for (act_name, act) in &acts.entries {
            acts.action_ban_epochs
                .insert(act_name.clone(), act.ban_epoch());
        }
        let mut failure = None;
        for id in &ids {
            if let Err(err) = self.unban_one_locked(acts, id, reason).await {
                let db_failed = matches!(err, Error::Database(_));
                failure.get_or_insert(err);
                if db_failed && !on_stop {
                    break;
                }
            }
        }
        let mut st = self.state.lock().await;
        st.ban_manager.recompute_next_unban();
        if let Some(err) = failure {
            return Err(err);
        }
        if clear_db {
            st.db_del_ban(None)?;
            st.dirty_bans.clear();
        }
        Ok(ids.len())
    }

    /// Manually ban one or more IPs/CIDRs/IDs (`set <jail> banip ...`).
    pub async fn ban_ip(&self, ips: &[String]) -> Result<usize> {
        let now = current_unix_seconds();
        let mut acts = self.actions.lock().await;
        let before = self.state.lock().await.ban_manager.total_bans();
        let mut result = Ok(());
        for raw in ips {
            let id = TicketId::parse(raw);
            let mut ticket = Ticket::new(id, now);
            ticket.attempts = 0;
            result = result.and(self.ban_ticket_locked(&mut acts, ticket, now).await);
        }
        result?;
        let after = self.state.lock().await.ban_manager.total_bans();
        Ok((after.saturating_sub(before)) as usize)
    }

    /// Manually unban specific IPs (or flush all if `ips` is `None`), matching upstream
    /// `Actions.removeBannedIP` (`fail2ban/server/actions.py:245-300`).
    pub async fn unban_ip(&self, ips: Option<&[String]>, ifexists: bool) -> Result<usize> {
        let mut acts = self.actions.lock().await;
        match ips {
            None => {
                let jail_name = self.state.lock().await.name.clone();
                self.flush_bans_locked(&mut acts, &jail_name, false).await
            }
            Some(targets) => {
                let mut cnt = 0usize;
                let mut missed = Vec::new();
                let mut failure = None;
                'targets: for raw in targets {
                    let target = TicketId::parse(raw);
                    let ids = {
                        let mut st = self.state.lock().await;
                        if st.ban_manager.get_ticket_by_id(&target).is_some() {
                            vec![target]
                        } else {
                            // A target may have expired history but no active ticket.
                            if let Err(err) = st.db_del_ban(Some(&target)) {
                                failure = Some(err);
                                break;
                            }
                            st.dirty_bans.remove(&target);
                            st.ban_manager.matching_ids(&target)
                        }
                    };
                    if ids.is_empty() && !ifexists {
                        missed.push(raw.clone());
                    }
                    for id in ids {
                        match self
                            .unban_one_locked(&mut acts, &id, UnbanReason::Explicit)
                            .await
                        {
                            Ok(()) => cnt += 1,
                            Err(err) => {
                                let db_failed = matches!(err, Error::Database(_));
                                failure.get_or_insert(err);
                                if db_failed {
                                    break 'targets;
                                }
                            }
                        }
                    }
                }
                self.state.lock().await.ban_manager.recompute_next_unban();
                if let Some(err) = failure {
                    return Err(err);
                }
                if !missed.is_empty() {
                    let rendered =
                        crate::client::beautifier::py_repr(&PickleValue::str_list(missed));
                    return Err(Error::Value(format!("not banned: {rendered}")));
                }
                Ok(cnt)
            }
        }
    }

    /// Manually feed an attempt (`set <jail> attempt <ip> [<match>...]`).
    pub async fn add_attempt(&self, ip: &str, matches: &[String]) -> Result<i64> {
        self.prefetch_uncached_ignore_hosts().await;
        let id = TicketId::parse(ip);
        let now = current_unix_seconds();
        let mut ticket = Ticket::new(id.clone(), now);
        ticket.matches = matches.to_vec();

        let decision = self
            .state
            .lock()
            .await
            .filter
            .check_ignore_static(&id, Some(&ticket));
        let ignored = match decision {
            IgnoreDecision::Decided(ignored) => ignored,
            IgnoreDecision::RunCommand(pending) => {
                let res = run_ignore_command_async(&pending.cmd).await;
                self.state
                    .lock()
                    .await
                    .filter
                    .finish_ignore_command(pending, res)
            }
        };
        if ignored {
            return Ok(0);
        }

        let count = u64::try_from(matches.len().max(1)).unwrap_or(1);
        let maybe_ban = self
            .state
            .lock()
            .await
            .record_attempt_failure(id, ticket, count, now);
        if let Some(to_ban) = maybe_ban {
            let mut acts = self.actions.lock().await;
            self.ban_ticket_locked(&mut acts, to_ban, now).await?;
        }
        Ok(1)
    }

    /// Periodic 1-second maintenance tick: expire bans, clean stale failures, flush batched checkpoints,
    /// and periodically check action consistency without holding `state` across action I/O.
    pub async fn periodic_tick(&self, now: f64) {
        let mut acts = self.actions.lock().await;
        let (jail_name, expired, due_check) = self.state.lock().await.prepare_periodic_tick(now);
        if !expired.is_empty() {
            for id in expired {
                if let Err(Error::Database(_)) = self
                    .unban_one_locked(&mut acts, &id, UnbanReason::Automatic)
                    .await
                {
                    break;
                }
            }
            self.state.lock().await.ban_manager.recompute_next_unban();
        }
        if due_check {
            let pending: Vec<_> = {
                let st = self.state.lock().await;
                st.ban_manager
                    .pending_tickets()
                    .filter(|t| !st.pending_unbans.contains_key(&t.fid))
                    .cloned()
                    .collect()
            };
            for ticket in pending {
                let _ = self.ban_ticket_locked(&mut acts, ticket, now).await;
            }
            self.run_consistency_checks_locked(&mut acts, &jail_name)
                .await;
        }
    }

    /// Process one [`LogEvent`] without holding `state` across DNS, `ignorecommand`, or action I/O.
    pub async fn handle_log_event(&self, ev: LogEvent, now: f64) {
        let _ = self.handle_log_event_with_shutdown(ev, now, None).await;
    }

    async fn prefetch_uncached_ignore_hosts(&self) {
        let hosts = self.state.lock().await.filter.uncached_ignore_hosts();
        if !hosts.is_empty() {
            let _ = tokio::task::spawn_blocking(move || {
                for host in hosts {
                    let _ = dns_to_ip(&host);
                }
            })
            .await;
        }
    }

    /// Returns `true` if aborted early by `shutdown_rx`.
    async fn handle_log_event_with_shutdown(
        &self,
        ev: LogEvent,
        now: f64,
        mut shutdown_rx: Option<&mut watch::Receiver<bool>>,
    ) -> bool {
        if matches!(ev, LogEvent::Line { .. }) {
            let hosts = self.state.lock().await.filter.uncached_ignore_hosts();
            if !hosts.is_empty() {
                let prefetch = tokio::task::spawn_blocking(move || {
                    for host in hosts {
                        let _ = dns_to_ip(&host);
                    }
                });
                if let Some(shut) = shutdown_rx.as_deref_mut() {
                    tokio::select! {
                        biased;
                        res = shut.changed() => {
                            if res.is_err() || *shut.borrow() {
                                return true;
                            }
                        }
                        _ = prefetch => {}
                    }
                } else {
                    let _ = prefetch.await;
                }
            }
        }

        let (immediate_bans, deferred) = {
            let mut st = self.state.lock().await;
            st.handle_log_event_phase1_sync(ev, now)
        };
        for to_ban in immediate_bans {
            self.ban_ticket(to_ban, now).await;
        }

        let Some(mut deferred) = deferred else {
            return false;
        };

        let mut pending_ignore = std::mem::take(&mut deferred.work.pending_ignore);
        if !deferred.work.pending_dns.is_empty() {
            let mut unique_hosts = Vec::new();
            let mut seen = BTreeSet::new();
            for item in &deferred.work.pending_dns {
                if seen.insert(item.dns_host.clone()) {
                    unique_hosts.push(item.dns_host.clone());
                }
            }
            let dns_task = tokio::task::spawn_blocking(move || {
                for host in unique_hosts {
                    let _ = dns_to_ip(&host);
                }
            });
            if let Some(shut) = shutdown_rx.as_deref_mut() {
                tokio::select! {
                    biased;
                    res = shut.changed() => {
                        if res.is_err() || *shut.borrow() {
                            return true;
                        }
                    }
                    _ = dns_task => {}
                }
            } else {
                let _ = dns_task.await;
            }

            let dns_bans = {
                let mut st = self.state.lock().await;
                let mut bans = Vec::new();
                for item in deferred.work.pending_dns {
                    let (matches, extra_ignore) = st.filter.finish_deferred_dns_match(item);
                    pending_ignore.extend(extra_ignore);
                    for m in matches {
                        if let Some(ticket) = st.apply_match_result_sync(m, now) {
                            bans.push(ticket);
                        }
                    }
                }
                bans
            };
            for to_ban in dns_bans {
                self.ban_ticket(to_ban, now).await;
            }
        }

        if !pending_ignore.is_empty() {
            let mut resolved = Vec::with_capacity(pending_ignore.len());
            for (m, p) in pending_ignore {
                let ignored = if let Some(shut) = shutdown_rx.as_deref_mut() {
                    tokio::select! {
                        biased;
                        res = shut.changed() => {
                            if res.is_err() || *shut.borrow() {
                                return true;
                            }
                            run_ignore_command_async(&p.cmd).await
                        }
                        res = run_ignore_command_async(&p.cmd) => res,
                    }
                } else {
                    run_ignore_command_async(&p.cmd).await
                };
                resolved.push((m, p, ignored));
            }

            let ignore_bans = {
                let mut st = self.state.lock().await;
                let mut bans = Vec::new();
                for (m, p, ignored) in resolved {
                    if !st
                        .filter
                        .record_deferred_match_outcome(m.regex_idx, p, ignored)
                        && let Some(ticket) = st.apply_match_result_sync(m, now)
                    {
                        bans.push(ticket);
                    }
                }
                bans
            };
            for to_ban in ignore_bans {
                self.ban_ticket(to_ban, now).await;
            }
        }

        self.state.lock().await.advance_line_checkpoints(
            deferred.log_path,
            deferred.checkpoint,
            deferred.journal_cursor,
            deferred.preset_date,
            now,
        );
        false
    }

    /// Start actions, restore active DB bans, and launch backend + worker tasks.
    pub async fn start(&self) -> Result<()> {
        {
            let mut st = self.state.lock().await;
            if st.alive {
                st.idle = false;
                let sync = !st.reloading;
                drop(st);
                if sync {
                    self.sync_idle_signal(false).await;
                }
                return Ok(());
            }
        }
        self.validate_backend().await?;
        self.state.lock().await.db_add_jail();
        self.start_validated().await;
        Ok(())
    }

    pub(super) async fn start_validated(&self) {
        let jail_name = {
            let st = self.state.lock().await;
            st.set_backend_error(None);
            st.name.clone()
        };
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.jail",
            "Starting jail '{}'",
            jail_name
        );
        let ipv6_allowed = allow_ipv6();
        {
            let mut acts = self.actions.lock().await;
            for (act_name, act) in &mut acts.entries {
                if let Err(err) = act.start(ipv6_allowed).await {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Failed to start jail '{}' action '{act_name}': {err}",
                        jail_name
                    );
                }
            }
        }

        let now = current_unix_seconds();
        self.prefetch_uncached_ignore_hosts().await;
        let (mut restored, pending_ignores) = {
            let mut st = self.state.lock().await;
            let raw_restored = st.restore_tickets_from_db(now);
            st.split_restored_tickets_for_ignore(raw_restored)
        };
        if !pending_ignores.is_empty() {
            let mut checked = Vec::with_capacity(pending_ignores.len());
            for (ticket, pending) in pending_ignores {
                let ignored = run_ignore_command_async(&pending.cmd).await;
                checked.push((ticket, pending, ignored));
            }
            let mut st = self.state.lock().await;
            for (ticket, pending, ignored) in checked {
                if !st.filter.finish_ignore_command(pending, ignored) {
                    restored.push(ticket);
                }
            }
        }
        for ticket in restored {
            self.ban_ticket(ticket, now).await;
        }

        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (replace_rx_tx, replace_rx_rx) = mpsc::unbounded_channel();
        let (worker_shut_tx, worker_shut_rx) = watch::channel(false);
        let (idle_tx, idle_rx) = watch::channel(false);
        let (backend_shut_tx, backend_shut_rx) = watch::channel(false);

        let backend_handle = {
            let mut st = self.state.lock().await;
            let handle = spawn_backend_task(&mut st, event_tx, backend_shut_rx);
            st.alive = true;
            st.idle = false;
            handle
        };
        let worker_handle = spawn_worker_task(
            self.clone(),
            event_rx,
            replace_rx_rx,
            worker_shut_rx,
            idle_rx,
        );

        *self.tasks.lock().await = Some(JailTasks {
            backend_shut_tx,
            worker_shut_tx,
            idle_tx,
            replace_rx_tx,
            backend_handle,
            worker_handle,
        });

        f2b_log!(
            LogLevel::Info,
            "fail2ban.jail",
            "Jail '{}' started",
            jail_name
        );
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

        let mut acts = self.actions.lock().await;
        let (jail_name, should_flush) = {
            let mut st = self.state.lock().await;
            st.flush_file_checkpoints_to_db();
            st.flush_journal_pos_to_db(current_unix_seconds());
            st.retry_ban_writes();
            let should_flush = st.alive
                || !st.ban_manager.get_ban_list(false).is_empty()
                || !acts.entries.is_empty();
            (st.name.clone(), should_flush)
        };
        if should_flush && let Err(err) = self.flush_bans_locked(&mut acts, &jail_name, true).await
        {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.actions",
                "Failed to flush bans while stopping jail '{jail_name}': {err}"
            );
        }
        for (act_name, act) in acts.entries.iter_mut().rev() {
            if let Err(err) = act.stop().await {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.actions",
                    "Failed to stop jail '{jail_name}' action '{act_name}': {err}"
                );
            }
        }
        self.state.lock().await.alive = false;
        f2b_log!(
            LogLevel::Info,
            "fail2ban.jail",
            "Jail '{}' stopped",
            jail_name
        );
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
        let replace_rx_tx = runtime.replace_rx_tx.clone();
        drop(tasks_guard);

        if let Some(h) = old_handle {
            let _ = h.await;
        }

        let mut st = self.state.lock().await;
        if !st.alive {
            return;
        }
        st.flush_file_checkpoints_to_db();
        st.set_backend_error(None);
        let (new_event_tx, new_event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let _ = replace_rx_tx.send(new_event_rx);
        let (new_shut_tx, new_shut_rx) = watch::channel(false);
        let new_handle = spawn_backend_task(&mut st, new_event_tx, new_shut_rx);
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

    pub async fn reload_begin(&self) {
        {
            let mut acts = self.actions.lock().await;
            acts.reload_begin();
            let mut st = self.state.lock().await;
            st.reload_begin_state();
        }
        self.sync_idle_signal(true).await;
    }

    pub async fn reload_abort(&self) {
        let idle = {
            let mut acts = self.actions.lock().await;
            acts.reload_abort();
            let mut st = self.state.lock().await;
            st.reload_abort_state()
        };
        self.sync_idle_signal(idle).await;
    }

    /// Finalize reload phase matching upstream `Actions.reload(begin=False)`
    /// (`fail2ban/server/actions.py:157-170`): reload retained actions, then flush/unban,
    /// stop, and remove actions absent from `_reload_actions`, and retire obsolete logs.
    pub async fn reload_commit(&self) -> Result<()> {
        let mut acts = self.actions.lock().await;
        let (jail_name, alive, systemd_check) = {
            let st = self.state.lock().await;
            let check = (st.real_backend == BackendKind::Systemd
                && st
                    .reload_snapshot
                    .as_ref()
                    .is_some_and(|prev| prev.journal_matches != st.journal_matches))
            .then(|| (st.journal_config(), st.journalctl_bin.clone()));
            (st.name.clone(), st.alive, check)
        };

        if let Some((cfg, bin)) = systemd_check
            && let Err(err) = validate_journal_config(&cfg, &bin).await
        {
            acts.reload_abort();
            let idle = self.state.lock().await.reload_abort_state();
            drop(acts);
            self.sync_idle_signal(idle).await;
            return Err(err);
        }

        let pending: Vec<_> = self
            .state
            .lock()
            .await
            .pending_unbans
            .keys()
            .cloned()
            .collect();
        for id in &pending {
            if let Err(err) = self
                .unban_one_locked(&mut acts, id, UnbanReason::Automatic)
                .await
            {
                acts.reload_abort();
                let idle = self.state.lock().await.reload_abort_state();
                drop(acts);
                self.sync_idle_signal(idle).await;
                return Err(err);
            }
        }
        if !pending.is_empty() {
            self.state.lock().await.ban_manager.recompute_next_unban();
        }
        if let Some(reload_acts) = acts.reload_actions.take() {
            for (act_name, options) in &reload_acts {
                if let Some(act) = acts.get_mut(act_name)
                    && let Err(err) = act.reload(options.as_deref()).await
                {
                    f2b_log!(
                        LogLevel::Error,
                        "fail2ban.actions",
                        "Failed to reload jail '{jail_name}' action '{act_name}': {err}"
                    );
                    acts.reload_abort();
                    let idle = self.state.lock().await.reload_abort_state();
                    drop(acts);
                    self.sync_idle_signal(idle).await;
                    return Err(err);
                }
            }

            // Match upstream Actions.add/reload (fail2ban/server/actions.py:131-170):
            // only actions entered into `_reload_actions` survive plain reload; new or
            // non-reloadable actions require `reload --restart`.
            let kept_names: BTreeSet<&str> = reload_acts.iter().map(|(n, _)| n.as_str()).collect();
            let mut delacts_with_idx: Vec<(usize, (String, ActionKind))> = Vec::new();
            let mut idx = 0usize;
            let mut orig_idx = 0usize;
            while idx < acts.entries.len() {
                if kept_names.contains(acts.entries[idx].0.as_str()) {
                    idx += 1;
                } else {
                    delacts_with_idx.push((orig_idx, acts.entries.remove(idx)));
                }
                orig_idx += 1;
            }
            let (orig_indices, mut delacts): (Vec<usize>, Vec<(String, ActionKind)>) =
                delacts_with_idx.into_iter().unzip();

            if !delacts.is_empty() && alive {
                let pass = flush_actions_or_check(&jail_name, &mut delacts, true, false).await;
                if let Some(err) = pass.first_error {
                    for (pos, entry) in orig_indices.into_iter().zip(delacts) {
                        acts.entries.insert(pos, entry);
                    }
                    acts.reload_abort();
                    let idle = self.state.lock().await.reload_abort_state();
                    drop(acts);
                    self.sync_idle_signal(idle).await;
                    return Err(err);
                }
                let active_ctxs = self.state.lock().await.active_ticket_contexts(None);
                for (fid, ctx) in &active_ctxs {
                    for (act_name, act) in &mut delacts {
                        if pass.skip_unban.contains(act_name) {
                            continue;
                        }
                        if let Err(err) = act.unban(ctx).await {
                            f2b_log!(
                                LogLevel::Error,
                                "fail2ban.actions",
                                "Failed to execute unban jail '{jail_name}' action '{act_name}' for {fid}: {err}"
                            );
                        }
                    }
                }
                for (act_name, mut act) in delacts.into_iter().rev() {
                    acts.action_ban_epochs.remove(&act_name);
                    if let Err(err) = act.stop().await {
                        f2b_log!(
                            LogLevel::Error,
                            "fail2ban.actions",
                            "Failed to stop jail '{jail_name}' action '{act_name}': {err}"
                        );
                    }
                }
            } else {
                for (act_name, _) in &delacts {
                    acts.action_ban_epochs.remove(act_name);
                }
            }
            acts.reload_added_actions.clear();
            acts.replaced_actions.clear();
            acts.saved_command_actions.clear();
            acts.saved_smtp_actions.clear();
        }

        let (backend_changed, idle) = self.state.lock().await.reload_commit_state();
        drop(acts);
        self.sync_idle_signal(idle).await;
        if backend_changed {
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
    st: &mut JailState,
    event_tx: mpsc::Sender<LogEvent>,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let jail_name = st.name.clone();
    let encoding = st.filter.log_encoding();
    let allow_poll_fallback = st.backend_spec.trim().eq_ignore_ascii_case("auto");
    let health = Arc::clone(&st.backend_error);

    match st.real_backend {
        BackendKind::Polling => {
            if st.log_paths.is_empty() {
                return None;
            }
            let configs = st.build_file_log_configs();
            let poller = FilterPoll::new(configs, encoding);
            Some(tokio::spawn(async move {
                if let Err(err) = poller.run(event_tx, shutdown_rx).await {
                    if let Ok(mut guard) = health.lock() {
                        *guard = Some(err.to_string());
                    }
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
                        if let Err(fb_err) = poller.run(tx_fb, shut_fb).await
                            && let Ok(mut guard) = health.lock()
                        {
                            *guard = Some(fb_err.to_string());
                        }
                    } else if let Ok(mut guard) = health.lock() {
                        *guard = Some(err.to_string());
                    }
                }
            }))
        }
        BackendKind::Systemd => {
            let jcfg = st.journal_config();
            let after_cursor = st.last_journal_cursor.clone();
            let since_epoch = if after_cursor.is_some() {
                None
            } else {
                let saved_ts = st.last_journal_ts.or_else(|| st.db_get_journal_pos());
                if let Some(ts) = saved_ts {
                    let floor = if st.filter.check_find_time() {
                        current_unix_seconds() - st.filter.find_time()
                    } else {
                        0.0
                    };
                    Some(ts.max(floor))
                } else if st.filter.check_find_time() {
                    Some(current_unix_seconds() - st.filter.find_time())
                } else {
                    None
                }
            };
            let reader = FilterSystemd::new(jcfg, encoding, false)
                .with_since(since_epoch)
                .with_after_cursor(after_cursor)
                .with_journalctl_bin(st.journalctl_bin.clone())
                .with_health_sink(health);
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

struct DeferredLogLine {
    work: DeferredLineWork,
    log_path: Option<String>,
    checkpoint: Option<(String, u64)>,
    journal_cursor: Option<String>,
    preset_date: Option<f64>,
}

/// Append Team Cymru ASN/Country/RIR tuples to a `status("basic")` response value.
pub fn attach_cymru_to_status(status: &mut PickleValue, cymru: CymruInfo) {
    let PickleValue::List(ref mut sections) = *status else {
        return;
    };
    for section in sections {
        let PickleValue::Tuple(ref mut pair) = *section else {
            continue;
        };
        if pair.first().and_then(PickleValue::as_str) != Some("Actions") {
            continue;
        }
        if let Some(PickleValue::List(action_items)) = pair.get_mut(1) {
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned ASN list".to_owned()),
                PickleValue::str_list(cymru.asns),
            ]));
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned Country list".to_owned()),
                PickleValue::str_list(cymru.countries),
            ]));
            action_items.push(PickleValue::Tuple(vec![
                PickleValue::Str("Banned RIR list".to_owned()),
                PickleValue::str_list(cymru.rirs),
            ]));
            return;
        }
    }
}

fn spawn_worker_task(
    jail: Jail,
    mut event_rx: mpsc::Receiver<LogEvent>,
    mut replace_rx_rx: mpsc::UnboundedReceiver<mpsc::Receiver<LogEvent>>,
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
                biased;
                res = shutdown_rx.changed() => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some(new_rx) = replace_rx_rx.recv() => {
                    event_rx = new_rx;
                    rx_closed = false;
                }
                _ = idle_rx.changed() => {}
                _ = tick.tick(), if !is_idle => {
                    let now = current_unix_seconds();
                    jail.periodic_tick(now).await;
                }
                maybe_ev = event_rx.recv(), if !is_idle && !rx_closed => {
                    match maybe_ev {
                        Some(ev) => {
                            let now = current_unix_seconds();
                            if jail
                                .handle_log_event_with_shutdown(ev, now, Some(&mut shutdown_rx))
                                .await
                            {
                                break;
                            }
                        }
                        None => {
                            rx_closed = true;
                        }
                    }
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
    async fn failed_ban_retries_only_failed_actions_and_serializes_expiry() {
        let dir = TempDir::new().unwrap();
        let calls = dir.path().join("calls");
        let ready = dir.path().join("ready");
        let jail = Jail::new("test", "polling", None).unwrap();
        for (name, command) in [
            ("first", format!("echo ok >> '{}'", calls.display())),
            ("second", format!("test -f '{}'", ready.display())),
        ] {
            jail.add_action(name, None, None).await.unwrap();
            jail.actions
                .lock()
                .await
                .get_mut(name)
                .unwrap()
                .set_property("actionban", &command)
                .await
                .unwrap();
        }
        let ips = ["192.0.2.6".to_owned()];
        let id = TicketId::parse(&ips[0]);
        assert!(jail.ban_ip(&ips).await.is_err());
        {
            let st = jail.state.lock().await;
            assert!(!st.ban_manager.in_ban_list(&id));
            assert_eq!(st.ban_manager.size(), 0);
            assert_eq!(st.ban_manager.total_bans(), 0);
            assert!(st.get_ban_list(true).is_empty());
        }
        std::fs::write(ready, "").unwrap();
        let now = current_unix_seconds();
        jail.periodic_tick(now + PERIODIC_CHECK_INTERVAL_SECS + 1.0)
            .await;
        assert_eq!(std::fs::read_to_string(calls).unwrap(), "ok\n");
        assert_eq!(jail.state.lock().await.ban_manager.total_bans(), 1);
        {
            let mut acts = jail.actions.lock().await;
            let second = acts.get_mut("second").unwrap();
            second.set_property("actionreban", "false").await.unwrap();
            jail.reban_actions_for_active_tickets_locked(&mut acts, "test", &[1], None)
                .await;
            assert!(!jail.state.lock().await.ban_manager.in_ban_list(&id));
            assert!(
                jail.ban_ticket_locked(&mut acts, Ticket::new(id.clone(), now), now)
                    .await
                    .is_err()
            );
            acts.get_mut("second")
                .unwrap()
                .set_property("actionreban", "true")
                .await
                .unwrap();
        }
        assert_eq!(jail.ban_ip(&ips).await.unwrap(), 0);
        assert_eq!(jail.state.lock().await.ban_manager.total_bans(), 1);
        let guard = jail.actions.lock().await;
        let tick = jail.periodic_tick(now + 1000.0);
        tokio::pin!(tick);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut tick)
                .await
                .is_err()
        );
        assert!(jail.state.lock().await.ban_manager.in_ban_list(&id));
        drop(guard);
        tick.await;
        assert!(!jail.state.lock().await.ban_manager.in_ban_list(&id));
    }

    #[tokio::test]
    async fn retries_failed_ban_writes_with_original_deadline_and_skips_unbanned_ips() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("bans.sqlite");
        let db = Arc::new(std::sync::Mutex::new(
            Fail2BanDb::open(file.to_str().unwrap(), 86400, 10).unwrap(),
        ));
        let jail = Jail::new("test", "polling", Some(db)).unwrap();
        let control = rusqlite::Connection::open(file).unwrap();
        control.execute_batch("CREATE TRIGGER offline BEFORE INSERT ON bips BEGIN SELECT RAISE(FAIL, 'offline'); END;").unwrap();
        let ips = ["192.0.2.6".to_owned(), "192.0.2.7".to_owned()];
        jail.ban_ip(&ips).await.unwrap();
        jail.unban_ip(Some(&ips[1..]), false).await.unwrap();
        let (start, duration) = {
            let mut st = jail.state.lock().await;
            let t = st
                .ban_manager
                .get_ticket_by_id(&TicketId::parse(&ips[0]))
                .unwrap();
            let original = (
                t.time.round_ties_even() as i64,
                t.effective_ban_time(st.ban_manager.ban_time()),
            );
            st.ban_manager.set_ban_time(12345);
            original
        };
        control.execute_batch("DROP TRIGGER offline").unwrap();
        jail.periodic_tick(current_unix_seconds()).await;
        jail.periodic_tick(current_unix_seconds() + PERIODIC_CHECK_INTERVAL_SECS + 1.0)
            .await;
        let row: (String, i64, i64, i64) = control
            .query_row(
                "SELECT ip, timeofban, bantime, (SELECT count(*) FROM bans) FROM bips",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, (ips[0].clone(), start, duration, 1));
    }

    #[tokio::test]
    async fn expiry_retries_failed_unban_after_action_recovers() {
        let dir = TempDir::new().unwrap();
        let ready = dir.path().join("ready");
        let jail = Jail::new("test", "polling", None).unwrap();
        jail.add_action("fw", None, None).await.unwrap();
        jail.actions
            .lock()
            .await
            .get_mut("fw")
            .unwrap()
            .set_property("actionunban", &format!("test -f '{}'", ready.display()))
            .await
            .unwrap();
        let ips = ["192.0.2.6".to_owned()];
        jail.ban_ip(&ips).await.unwrap();
        let now = current_unix_seconds() + 1000.0;
        jail.periodic_tick(now).await;
        assert_eq!(jail.state.lock().await.ban_manager.size(), 1);
        std::fs::write(ready, "").unwrap();
        jail.periodic_tick(now + PERIODIC_CHECK_INTERVAL_SECS + 1.0)
            .await;
        assert_eq!(jail.state.lock().await.ban_manager.size(), 0);
    }

    #[tokio::test]
    async fn retries_file_and_journal_positions_after_sqlite_recovers() {
        let dir = TempDir::new().unwrap();
        let filename = dir.path().join("checkpoint.sqlite");
        let db = Arc::new(std::sync::Mutex::new(
            Fail2BanDb::open(filename.to_str().unwrap(), 86400, 10).unwrap(),
        ));
        let control = rusqlite::Connection::open(&filename).unwrap();
        control.execute_batch("CREATE TRIGGER unavailable BEFORE INSERT ON logs BEGIN SELECT RAISE(FAIL, 'offline'); END;").unwrap();
        let jail = Jail::new("test", "systemd", Some(db.clone())).unwrap();
        let mut st = jail.state.lock().await;
        st.handle_log_event_phase1_sync(
            LogEvent::Checkpoint {
                path: "test.log".into(),
                fingerprint: "fp".into(),
                offset: 42,
            },
            100.0,
        );
        st.advance_line_checkpoints(None, None, None, Some(99.0), 100.0);
        st.prepare_periodic_tick(106.0);
        assert!(st.dirty_file_checkpoints.contains(Path::new("test.log")) && st.journal_dirty);
        control.execute_batch("DROP TRIGGER unavailable").unwrap();
        st.prepare_periodic_tick(112.0);
        assert!(st.dirty_file_checkpoints.is_empty() && !st.journal_dirty);
        assert_eq!(st.db_get_journal_pos(), Some(99.0));
        assert_eq!(
            db.lock()
                .unwrap()
                .add_log("test", "test.log", "fp")
                .unwrap(),
            Some(42)
        );
    }

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
            st.filter
                .add_fail_regex(r"Failed password for \S+ from <HOST> port \d+")
                .unwrap();
            st.fail_manager.set_max_retry(2);
            st.ban_manager.set_ban_time(3);
            st.add_log_path(log_file.clone(), false).unwrap();
        }
        jail.add_action("rec", None, None).await.unwrap();
        {
            let mut acts = jail.actions.lock().await;
            let act = acts.get_mut("rec").unwrap();
            act.set_property(
                "actionban",
                &format!("echo ban:<ip> >> '{}'", ban_log.display()),
            )
            .await
            .unwrap();
            act.set_property(
                "actionunban",
                &format!("echo unban:<ip> >> '{}'", ban_log.display()),
            )
            .await
            .unwrap();
        }

        jail.start().await.unwrap();

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_file)
                .unwrap();
            let date = chrono::Local::now().format("%b %e %H:%M:%S%.3f");
            writeln!(
                f,
                "{date} host sshd[10]: Failed password for root from 203.0.113.42 port 22"
            )
            .unwrap();
            writeln!(
                f,
                "{date} host sshd[11]: Failed password for root from 203.0.113.42 port 22"
            )
            .unwrap();
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
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

        // Verify natural expiry keeps `bans` & `bips` history (for `bantime.increment`)
        // while `get_current_bans` no longer reports the expired ticket as active.
        {
            let guard = db.lock().unwrap();
            let ip = TicketId::parse("203.0.113.42");
            let (cnt, matches) = guard.get_bans_merged(&ip, Some("sshd")).unwrap();
            assert_eq!(cnt, 2);
            assert_eq!(matches.len(), 2);
            assert!(guard.get_ban(&ip, Some("sshd"), false).unwrap().is_some());
            let cur = guard
                .get_current_bans(
                    Some("sshd"),
                    None,
                    None,
                    current_unix_seconds().ceil() as i64,
                )
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
        }
        jail.add_action("fw", None, None).await.unwrap();
        jail.add_action("notify", None, None).await.unwrap();
        {
            let mut acts = jail.actions.lock().await;
            acts.get_mut("fw")
                .unwrap()
                .set_property(
                    "actionban",
                    &format!("echo fw:<ip> >> '{}'", ban_log.display()),
                )
                .await
                .unwrap();
            let notify = acts.get_mut("notify").unwrap();
            notify.set_property("norestored", "true").await.unwrap();
            notify
                .set_property(
                    "actionban",
                    &format!("echo notify:<ip> >> '{}'", ban_log.display()),
                )
                .await
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
        let log = tempfile::NamedTempFile::new().unwrap();
        let jail = Jail::new("sshd", "polling", None).unwrap();
        {
            let mut st = jail.state.lock().await;
            st.add_log_path(log.path().to_owned(), false).unwrap();
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

    #[tokio::test]
    async fn systemd_backend_parses_journalfiles_namespace_and_persists_journal_pos() {
        let dir = TempDir::new().unwrap();
        let jf1 = dir.path().join("system.journal");
        let jf2 = dir.path().join("user.journal");
        std::fs::write(&jf1, b"").unwrap();
        std::fs::write(&jf2, b"").unwrap();

        let glob_pat = format!("{}/*.journal", dir.path().display());
        let spec = format!("systemd[journalfiles=\"{glob_pat}\", namespace=customns, rotated=1]");
        let db = Arc::new(std::sync::Mutex::new(
            Fail2BanDb::open(":memory:", 86_400, 10).unwrap(),
        ));

        let jail = Jail::new("sshd-j", spec, Some(Arc::clone(&db))).unwrap();
        {
            let st = jail.state.lock().await;
            assert_eq!(st.real_backend, BackendKind::Systemd);
            assert_eq!(st.journal_files, vec![jf1.clone(), jf2.clone()]);
            assert_eq!(st.journal_namespace.as_deref(), Some("customns"));
            assert_eq!(st.db_get_journal_pos(), None);
        }
        jail.handle_log_event(
            LogEvent::Line {
                line: "srv sshd[1]: benign".to_owned(),
                preset_date: Some(1_715_675_415.75),
                log_path: None,
                in_operation: true,
                checkpoint: None,
                journal_cursor: None,
            },
            1_715_675_416.0,
        )
        .await;
        jail.state
            .lock()
            .await
            .flush_journal_pos_to_db(1_715_675_416.0);

        // A newly constructed jail backed by the same SQLite DB resumes from stored timestamp.
        let jail2 = Jail::new("sshd-j", "systemd", Some(Arc::clone(&db))).unwrap();
        let st2 = jail2.state.lock().await;
        let resumed = st2.db_get_journal_pos().unwrap();
        assert!((resumed - 1_715_675_415.75).abs() < 1e-6);
    }
}
