//! Log watcher lifecycle — plan compilation, spawning, and gap-free stop.
//!
//! Every spawned watcher's [`JoinHandle`] is kept alongside the shared
//! cancellation token. Stopping cancels the token and awaits each handle
//! (bounded by [`STOP_TIMEOUT`]) to collect the [`ResumePoint`] it reached,
//! so a replacement watcher continues exactly where the old one stopped and
//! no log line is skipped or read twice across a reload.
//!
//! One jail may watch several log files (original Fail2Ban multi-`logpath`
//! jails). Each (jail, path) pair is its own watcher task and resume point;
//! all of them report failures under the same jail id, so failures merge
//! into one threshold exactly like the original.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::error::Elapsed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::config::{Config, JailConfig, LogBackend};
use crate::detect::ResumePoint;
use crate::detect::date::DateParser;
use crate::detect::ignore::IgnoreList;
use crate::detect::line_matcher::LineMatcher;
use crate::detect::watcher::Failure;

/// Upper bound on waiting for all old watchers to report their position.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle to one running watcher task, keyed by its resume key.
pub(super) type WatcherHandle = (String, JoinHandle<Option<ResumePoint>>);

/// Which stream one watcher plan reads.
pub(super) enum PlanSource {
    /// One log file of the jail.
    File(PathBuf),
    /// The jail's systemd journal matches.
    Journal(Vec<String>),
}

/// Pre-compiled watcher plan for one jail log source.
pub(super) struct WatcherPlan {
    /// Resume-map identity: jail plus the source it tails.
    pub(super) key: String,
    /// Jail id failures are reported under.
    pub(super) jail: String,
    pub(super) source: PlanSource,
    pub(super) matcher: LineMatcher,
    pub(super) date_parser: DateParser,
    pub(super) ignore_list: IgnoreList,
}

/// Stable resume-map identity of one (jail, source) watcher.
fn watcher_key(jail: &str, key_suffix: &str) -> String {
    format!("{jail}\u{1}{key_suffix}")
}

/// The log files one jail watches: `log_paths` when set, else the single
/// `log_path`, deduplicated in first-seen order.
fn jail_paths(jail: &JailConfig) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for path in jail.log_paths.iter().chain([&jail.log_path]) {
        if !path.as_os_str().is_empty() && seen.insert(path.clone()) {
            paths.push(path.clone());
        }
    }
    paths
}

/// Build one watcher plan per enabled jail source.
pub(super) fn build_watcher_plan(config: &Config) -> crate::error::Result<Vec<WatcherPlan>> {
    let mut plans = Vec::new();
    for (name, jail) in config.enabled_jails() {
        match jail.log_backend {
            LogBackend::Systemd => {
                plans.push(planned_source(
                    name,
                    PlanSource::Journal(jail.journalmatch.clone()),
                    jail,
                )?);
            }
            LogBackend::File => {
                if jail_paths(jail).is_empty() {
                    return Err(crate::error::Error::config(format!(
                        "jail '{name}': no log file to watch"
                    )));
                }
                for path in jail_paths(jail) {
                    plans.push(planned_source(name, PlanSource::File(path), jail)?);
                }
            }
        }
    }
    Ok(plans)
}

/// Compile the matcher set for one plan from the jail's patterns.
fn planned_source(
    name: &str,
    source: PlanSource,
    jail: &JailConfig,
) -> crate::error::Result<WatcherPlan> {
    let matcher = match &jail.legacy_filter {
        Some(legacy) => LineMatcher::legacy(legacy)?,
        None => LineMatcher::modern(&jail.filter, &jail.ignoreregex)?,
    };
    let key_suffix = match &source {
        PlanSource::File(path) => path.display().to_string(),
        PlanSource::Journal(_) => "(journal)".to_owned(),
    };
    Ok(WatcherPlan {
        key: watcher_key(name, &key_suffix),
        jail: name.to_string(),
        source,
        matcher,
        date_parser: DateParser::new(jail.date_format)?,
        ignore_list: IgnoreList::new(&jail.ignoreip, jail.ignoreself)?,
    })
}

/// Spawn one watcher task per plan under child tokens of `cancel`.
///
/// Each key found in `resume` starts from its recorded position; the rest
/// start from their default (end of file / journal tail).
pub(super) fn spawn_watchers(
    watcher_plan: Vec<WatcherPlan>,
    failure_tx: &mpsc::Sender<Failure>,
    cancel: &CancellationToken,
    phase: &'static str,
    mut resume: HashMap<String, ResumePoint>,
    handoff: &Arc<AtomicBool>,
) -> Vec<WatcherHandle> {
    watcher_plan
        .into_iter()
        .map(|plan| {
            let start = resume.remove(&plan.key);
            let key = plan.key.clone();
            let handle = spawn_one(
                plan,
                failure_tx.clone(),
                cancel.child_token(),
                phase,
                start,
                handoff.clone(),
            );
            (key, handle)
        })
        .collect()
}

/// Spawn the file or journal watcher for a single plan.
fn spawn_one(
    plan: WatcherPlan,
    tx: mpsc::Sender<Failure>,
    cancel: CancellationToken,
    phase: &'static str,
    start: Option<ResumePoint>,
    handoff: Arc<AtomicBool>,
) -> JoinHandle<Option<ResumePoint>> {
    let WatcherPlan {
        key: _,
        jail,
        source,
        matcher,
        date_parser,
        ignore_list,
    } = plan;
    match source {
        PlanSource::File(path) => tokio::spawn(crate::detect::watcher::run_supervised_from(
            jail,
            path,
            matcher,
            date_parser,
            ignore_list,
            tx,
            cancel,
            phase,
            start,
            handoff,
        )),
        PlanSource::Journal(journalmatch) => {
            // The journal source speaks the native engine only; legacy
            // filters never reach it (compat rejects journalmatch up front).
            let LineMatcher::Modern(matcher) = matcher else {
                unreachable!("legacy filters are not admitted on the journal backend");
            };
            tokio::spawn(crate::detect::journal::run_supervised_from(
                jail,
                journalmatch,
                matcher,
                date_parser,
                ignore_list,
                tx,
                cancel,
                phase,
                start,
                handoff,
            ))
        }
    }
}

/// The running watcher set: a shared cancellation token plus every task's
/// join handle.
#[derive(Default)]
pub(super) struct Watchers {
    cancel: CancellationToken,
    handles: Vec<WatcherHandle>,
    handoff: Arc<AtomicBool>,
}

impl Watchers {
    /// Spawn watchers for `plan` under a fresh token.
    pub(super) fn spawn(
        plan: Vec<WatcherPlan>,
        failure_tx: &mpsc::Sender<Failure>,
        phase: &'static str,
        resume: HashMap<String, ResumePoint>,
    ) -> Self {
        let cancel = CancellationToken::new();
        let handoff = Arc::new(AtomicBool::new(false));
        let handles = spawn_watchers(plan, failure_tx, &cancel, phase, resume, &handoff);
        Self {
            cancel,
            handles,
            handoff,
        }
    }

    /// Reload must wait for every watcher to deliver queued failures and
    /// report its position; timing out would restart it at EOF.
    pub(super) async fn stop_for_reload(&mut self) -> HashMap<String, ResumePoint> {
        self.handoff.store(true, Ordering::Release);
        self.cancel.cancel();
        let mut points = HashMap::new();
        for (key, handle) in self.handles.drain(..) {
            if let Some(point) = resume_point(&key, Ok(handle.await)) {
                points.insert(key, point);
            }
        }
        points
    }

    /// Cancel every watcher and collect the positions they stopped at.
    ///
    /// All handles share one [`STOP_TIMEOUT`] deadline. A watcher that times
    /// out, panics, or reports no position is logged and omitted, so its
    /// replacement starts from the default position.
    pub(super) async fn stop(&mut self) -> HashMap<String, ResumePoint> {
        self.cancel.cancel();
        let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
        let mut points = HashMap::new();
        for (key, handle) in self.handles.drain(..) {
            let outcome = tokio::time::timeout_at(deadline, handle).await;
            if let Some(point) = resume_point(&key, outcome) {
                points.insert(key, point);
            }
        }
        points
    }
}

/// Unpack a watcher's stop outcome, logging why no position is available.
fn resume_point(
    key: &str,
    outcome: Result<Result<Option<ResumePoint>, JoinError>, Elapsed>,
) -> Option<ResumePoint> {
    let jail = key.split('\u{1}').next().unwrap_or(key);
    match outcome {
        Ok(Ok(Some(point))) => Some(point),
        Ok(Ok(None)) => {
            debug!(jail, "watcher stopped without a resume point");
            None
        }
        Ok(Err(e)) => {
            warn!(jail, error = %e, "watcher task failed; jail restarts from default position");
            None
        }
        Err(_) => {
            warn!(
                jail,
                "watcher stop timed out; jail restarts from default position"
            );
            None
        }
    }
}

impl Drop for Watchers {
    /// Never leak running watchers: dropping the set cancels them (a no-op
    /// if [`Watchers::stop`] already ran).
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "watchers_test.rs"]
mod watchers_test;
