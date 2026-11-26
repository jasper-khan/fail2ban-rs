//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/filterpoll.py`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::error::Result;
use crate::logging::{LogLevel, log_msg};

use super::super::LogEncoding;
use super::super::poll_stamp::{PollOutcome, Selections};
use super::{FileLogConfig, LogEvent, WatchedFile, send_events};

/// Default polling sleep interval matching Fail2Ban `FilterPoll.sleeptime`.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Polling log file reader using [`Selections`] and [`WatchedFile`].
#[derive(Debug)]
pub struct FilterPoll {
    selections: Selections,
    watched: BTreeMap<PathBuf, WatchedFile>,
    pending_configs: BTreeMap<PathBuf, FileLogConfig>,
    late_paths: BTreeSet<PathBuf>,
    dirty_queue: VecDeque<PathBuf>,
    dirty_set: BTreeSet<PathBuf>,
    encoding: LogEncoding,
    poll_interval: Duration,
    startup_done: bool,
}

impl FilterPoll {
    /// Create a new [`FilterPoll`] monitoring `configs` with default 1s interval.
    pub fn new(configs: Vec<FileLogConfig>, encoding: LogEncoding) -> Self {
        Self::with_interval(configs, encoding, DEFAULT_POLL_INTERVAL)
    }

    /// Create a new [`FilterPoll`] with an explicit poll interval.
    pub fn with_interval(
        configs: Vec<FileLogConfig>,
        encoding: LogEncoding,
        poll_interval: Duration,
    ) -> Self {
        let mut selections = Selections::new();
        let mut pending_configs = BTreeMap::new();
        for cfg in configs {
            selections.add_path(&cfg.path);
            pending_configs.insert(cfg.path.clone(), cfg);
        }
        Self {
            selections,
            watched: BTreeMap::new(),
            pending_configs,
            late_paths: BTreeSet::new(),
            dirty_queue: VecDeque::new(),
            dirty_set: BTreeSet::new(),
            encoding,
            poll_interval,
            startup_done: false,
        }
    }

    fn enqueue_dirty(&mut self, path: PathBuf) {
        if self.dirty_set.insert(path.clone()) {
            self.dirty_queue.push_back(path);
        }
    }

    fn pop_dirty(&mut self) -> Option<PathBuf> {
        let path = self.dirty_queue.pop_front()?;
        self.dirty_set.remove(&path);
        Some(path)
    }

    /// Dynamically add a file path to monitor.
    pub fn add_file(&mut self, cfg: FileLogConfig) -> bool {
        if self.selections.add_path(&cfg.path) {
            if self.startup_done {
                self.late_paths.insert(cfg.path.clone());
            }
            self.pending_configs.insert(cfg.path.clone(), cfg);
            true
        } else {
            false
        }
    }

    /// Dynamically stop monitoring `path`.
    pub fn remove_file(&mut self, path: &Path) -> bool {
        let removed_sel = self.selections.remove_path(path);
        let removed_watch = self.watched.remove(path).is_some();
        let removed_pend = self.pending_configs.remove(path).is_some();
        self.late_paths.remove(path);
        if self.dirty_set.remove(path) {
            self.dirty_queue.retain(|p| p != path);
        }
        removed_sel || removed_watch || removed_pend
    }

    /// Return currently tracked paths (excluding paths evicted after ENOENT threshold).
    pub fn active_paths(&self) -> Vec<PathBuf> {
        self.selections.paths().map(Path::to_path_buf).collect()
    }

    fn discover_changed_paths(&mut self) {
        let outcomes = self.selections.poll_all();

        for outcome in outcomes {
            match outcome {
                PollOutcome::Changed { path, .. } => {
                    if self.watched.contains_key(&path) {
                        self.enqueue_dirty(path);
                    } else if let Some(cfg) = self.pending_configs.remove(&path) {
                        let tail_override = if self.late_paths.remove(&path) {
                            Some(false)
                        } else {
                            None
                        };
                        match WatchedFile::open(cfg.clone(), self.encoding, tail_override) {
                            Ok(wf) => {
                                self.watched.insert(path.clone(), wf);
                                self.enqueue_dirty(path);
                            }
                            Err(err) => {
                                log_msg(
                                    LogLevel::Warning,
                                    "fail2ban.filter",
                                    &format!("Unable to open {:?}: {err}", cfg.path),
                                );
                                self.pending_configs.insert(path, cfg);
                            }
                        }
                    }
                }
                PollOutcome::Evicted { path } => {
                    self.watched.remove(&path);
                    self.pending_configs.remove(&path);
                    self.late_paths.remove(&path);
                    if self.dirty_set.remove(&path) {
                        self.dirty_queue.retain(|p| p != &path);
                    }
                    log_msg(
                        LogLevel::Warning,
                        "fail2ban.filter",
                        &format!("Removed nonexistent log path {:?}", path),
                    );
                }
                PollOutcome::Error { path, error } => {
                    log_msg(
                        LogLevel::Warning,
                        "fail2ban.filter",
                        &format!("Poll stat error on {:?}: {error:?}", path),
                    );
                }
            }
        }

        if !self.startup_done {
            for path in self.pending_configs.keys() {
                self.late_paths.insert(path.clone());
            }
            self.startup_done = true;
        }
    }

    fn collect_path_batch(&mut self, path: &Path, out: &mut Vec<LogEvent>) -> bool {
        if let Some(wf) = self.watched.get_mut(path) {
            return wf.collect_events_batch(out);
        }
        false
    }

    /// Execute one synchronous poll cycle across all monitored files and return
    /// any newly read lines and offset checkpoints.
    pub fn poll_once(&mut self) -> Vec<LogEvent> {
        self.discover_changed_paths();
        let mut events = Vec::new();
        while let Some(path) = self.pop_dirty() {
            let has_more = self.collect_path_batch(&path, &mut events);
            if has_more {
                self.enqueue_dirty(path);
            }
        }
        events
    }

    /// Run the asynchronous polling loop until `shutdown` signals `true` or `tx` closes.
    ///
    /// Drains each changed file in bounded batches, awaiting channel capacity between batches
    /// before sleeping for `poll_interval`.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<LogEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        loop {
            if *shutdown.borrow() {
                break;
            }
            self.discover_changed_paths();
            while let Some(path) = self.pop_dirty() {
                if *shutdown.borrow() {
                    return Ok(());
                }
                let mut batch = Vec::new();
                let has_more = self.collect_path_batch(&path, &mut batch);
                if has_more {
                    self.enqueue_dirty(path);
                }
                if !batch.is_empty() && !send_events(&tx, &mut shutdown, batch).await {
                    return Ok(());
                }
            }
            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                () = tokio::time::sleep(self.poll_interval) => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::super::poll_stamp::REMOVE_AFTER;

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "f2b_poll_be_{name}_{}_{nanos}.log",
            std::process::id()
        ))
    }

    #[test]
    fn polling_handles_partial_append_rotate_truncate_and_resume() {
        let path = unique_temp_path("main");
        let old = unique_temp_path("main_old");
        fs::write(&path, b"first\npartial").unwrap();

        let cfg = FileLogConfig {
            path: path.clone(),
            tail: false,
            resume_fingerprint: None,
            resume_offset: 0,
            auto_seek: None,
        };
        let mut poller = FilterPoll::new(vec![cfg], LogEncoding::Utf8);

        // First poll emits only complete "first" line and checkpoints at offset 6.
        let ev1 = poller.poll_once();
        assert_eq!(ev1.len(), 2);
        match &ev1[0] {
            LogEvent::Line { line, .. } => assert_eq!(line, "first"),
            other => panic!("unexpected event {other:?}"),
        }
        let saved_fp = match &ev1[1] {
            LogEvent::Checkpoint {
                fingerprint,
                offset,
                ..
            } => {
                assert_eq!(*offset, 6);
                fingerprint.clone()
            }
            other => panic!("unexpected event {other:?}"),
        };

        // Finish partial line.
        {
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"_done\n").unwrap();
        }
        let ev2 = poller.poll_once();
        assert!(matches!(
            &ev2[0],
            LogEvent::Line { line, .. } if line == "partial_done"
        ));

        // Resume new poller from checkpoint -> skips already-processed 19 bytes.
        {
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"third\n").unwrap();
        }
        let mut resumed = FilterPoll::new(
            vec![FileLogConfig {
                path: path.clone(),
                tail: true,
                resume_fingerprint: Some(saved_fp),
                resume_offset: 19,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
        );
        let ev_res = resumed.poll_once();
        assert!(matches!(
            &ev_res[0],
            LogEvent::Line { line, .. } if line == "third"
        ));

        // Truncate in-place.
        fs::write(&path, b"trunc1\n").unwrap();
        let ev_tr = poller.poll_once();
        assert!(
            ev_tr
                .iter()
                .any(|e| matches!(e, LogEvent::Line { line, .. } if line == "trunc1"))
        );

        // Atomic rotate: move old -> create new.
        fs::rename(&path, &old).unwrap();
        fs::write(&path, b"rotated1\n").unwrap();
        let ev_rot = poller.poll_once();
        assert!(
            ev_rot
                .iter()
                .any(|e| matches!(e, LogEvent::Line { line, .. } if line == "rotated1"))
        );

        // Remove path and verify eviction after REMOVE_AFTER checks.
        fs::remove_file(&path).unwrap();
        for _ in 0..REMOVE_AFTER {
            let _ = poller.poll_once();
        }
        assert!(poller.active_paths().is_empty());

        let _ = fs::remove_file(&old);
    }

    #[tokio::test]
    async fn polling_async_tail_and_late_file_creation_and_shutdown() {
        let missing = unique_temp_path("late");
        let existing = unique_temp_path("tail");
        fs::write(&existing, b"ignored_old\n").unwrap();

        let poller = FilterPoll::with_interval(
            vec![
                FileLogConfig {
                    path: existing.clone(),
                    tail: true,
                    resume_fingerprint: None,
                    resume_offset: 0,
                    auto_seek: None,
                },
                FileLogConfig {
                    path: missing.clone(),
                    tail: true,
                    resume_fingerprint: None,
                    resume_offset: 0,
                    auto_seek: None,
                },
            ],
            LogEncoding::Utf8,
            Duration::from_millis(20),
        );

        let (tx, mut rx) = mpsc::channel(32);
        let (shut_tx, shut_rx) = watch::channel(false);
        let handle = tokio::spawn(async move { poller.run(tx, shut_rx).await });

        tokio::time::sleep(Duration::from_millis(60)).await;
        // Write to both after startup: tail file gets new line, late-created file reads from 0.
        {
            let mut f = fs::OpenOptions::new().append(true).open(&existing).unwrap();
            f.write_all(b"new_tail_line\n").unwrap();
        }
        fs::write(&missing, b"late_line1\n").unwrap();

        let mut lines = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while lines.len() < 2 && tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
                && let LogEvent::Line { line, .. } = ev
            {
                lines.push(line);
            }
        }
        let _ = shut_tx.send(true);
        handle.await.unwrap().unwrap();

        assert!(lines.contains(&"new_tail_line".to_owned()));
        assert!(lines.contains(&"late_line1".to_owned()));
        assert!(!lines.contains(&"ignored_old".to_owned()));

        let _ = fs::remove_file(&existing);
        let _ = fs::remove_file(&missing);
    }

    #[tokio::test]
    async fn polling_bounds_multi_batch_append_under_slow_consumer_and_resumes_from_checkpoint() {
        let path = unique_temp_path("backpressure");
        fs::write(&path, b"").unwrap();

        let total_lines = 2000usize;
        let expected: Vec<String> = (0..total_lines)
            .map(|i| {
                format!(
                    "1700000200 poll-{i:04}-padding-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
                )
            })
            .collect();
        let mut payload = String::new();
        for line in &expected {
            payload.push_str(line);
            payload.push('\n');
        }

        // 1. Single multi-batch append drained across multiple bounded batches in one poll cycle.
        let poller = FilterPoll::with_interval(
            vec![FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint: None,
                resume_offset: 0,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
            Duration::from_secs(60), // Long poll interval proves multi-batch drain does not wait for next poll.
        );
        let (tx, mut rx) = mpsc::channel(4);
        let (shut_tx, shut_rx) = watch::channel(false);

        // Append before starting so the very first poll cycle must drain all 2,000 lines without sleeping 60s.
        fs::write(&path, payload.as_bytes()).unwrap();
        let handle = tokio::spawn(poller.run(tx, shut_rx));

        let mut received = Vec::with_capacity(total_lines);
        let mut eof_checkpoints = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while received.len() < total_lines && tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
            {
                match ev {
                    LogEvent::Line {
                        line, in_operation, ..
                    } => {
                        assert!(
                            !in_operation,
                            "cold-start multi-batch drain must keep in_operation=false before EOF"
                        );
                        received.push(line);
                        if received.len() == 1 || received.len() % 500 == 0 {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    LogEvent::Checkpoint { .. } => eof_checkpoints += 1,
                }
            }
        }
        if let Ok(Some(LogEvent::Checkpoint { .. })) =
            tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
        {
            eof_checkpoints += 1;
        }
        let _ = shut_tx.send(true);
        handle.await.unwrap().unwrap();

        assert_eq!(received, expected);
        assert_eq!(
            eof_checkpoints, 1,
            "multi-batch drain must emit exactly one EOF checkpoint"
        );

        // 2. Shutdown mid-backlog under slow consumer, then resume from last consumed line checkpoint.
        let poller2 = FilterPoll::with_interval(
            vec![FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint: None,
                resume_offset: 0,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
            Duration::from_secs(60),
        );
        let (tx2, mut rx2) = mpsc::channel(2);
        let (shut_tx2, shut_rx2) = watch::channel(false);
        let handle2 = tokio::spawn(poller2.run(tx2, shut_rx2));

        let stop_after = 600usize;
        let mut first_part = Vec::with_capacity(stop_after);
        let mut last_cp: Option<(String, u64)> = None;
        while first_part.len() < stop_after {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
                .await
                .unwrap()
                .unwrap();
            if let LogEvent::Line {
                line, checkpoint, ..
            } = ev
            {
                first_part.push(line);
                last_cp = checkpoint;
            }
        }
        let _ = shut_tx2.send(true);
        tokio::time::timeout(Duration::from_secs(2), handle2)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let (resume_fp, resume_off) = last_cp.unwrap();
        let poller3 = FilterPoll::with_interval(
            vec![FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint: Some(resume_fp),
                resume_offset: resume_off,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
            Duration::from_secs(60),
        );
        let (tx3, mut rx3) = mpsc::channel(4);
        let (shut_tx3, shut_rx3) = watch::channel(false);
        let handle3 = tokio::spawn(poller3.run(tx3, shut_rx3));

        let mut remainder = Vec::with_capacity(total_lines - stop_after);
        while remainder.len() < total_lines - stop_after {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx3.recv())
                .await
                .unwrap()
                .unwrap();
            if let LogEvent::Line { line, .. } = ev {
                remainder.push(line);
            }
        }
        let _ = shut_tx3.send(true);
        handle3.await.unwrap().unwrap();

        assert_eq!(first_part, expected[..stop_after]);
        assert_eq!(remainder, expected[stop_after..]);

        let _ = fs::remove_file(&path);
    }
}
