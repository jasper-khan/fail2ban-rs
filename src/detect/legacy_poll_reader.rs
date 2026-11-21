//! Fail2Ban 1.1.1 parity-backed polling file reader for compatibility jails.
//!
//! Replaces the forked native `reader.rs` on the `--legacy-dir` path by
//! driving the already parity-verified `PollSelection` (mtime/inode/size stat
//! gating + 51-ENOENT eviction) and `FileIdentityState` (inode + truncation +
//! 30-second periodic SHA-1 re-hash rotation detection) in the real daemon.
//!
//! Failures and checkpoints travel on the same FIFO `ReaderEvent` channel so a
//! checkpoint can never overtake an earlier failure before the tracker drains
//! and flushes the WAL.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use memchr::memchr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::LogEncoding;
use crate::detect::date::DateParser;
use crate::detect::identity::FileIdentity;
use crate::detect::ignore::IgnoreList;
use crate::detect::legacy_file_identity::FileIdentityState;
use crate::detect::legacy_poll_stamp::{PollSelection, PollStamp};
use crate::detect::line_matcher::{FileTiming, LineMatcher};
use crate::detect::reader::ReaderEvent;
use crate::detect::resume::{FilePosition, FileStart, PersistedFilePosition, open_log_from_with};
use crate::detect::watcher::{Failure, MAX_LINE_LEN};
use crate::text::lossy;

/// Poll interval between stat passes.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

struct ReadCtx {
    jail_id: String,
    matcher: LineMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    file_timing: Option<FileTiming>,
    tx: mpsc::Sender<ReaderEvent>,
    max_lines: usize,
    log_encoding: LogEncoding,
    window: VecDeque<String>,
}

impl ReadCtx {
    fn decode_bytes(&self, buf: &[u8]) -> String {
        match self.log_encoding {
            LogEncoding::Utf8 => lossy(buf).into_owned(),
            LogEncoding::Latin1 => buf.iter().map(|&b| char::from(b)).collect(),
        }
    }

    fn handle_line(&mut self, line: &str) -> bool {
        let matched = if self.max_lines <= 1 {
            self.matcher
                .try_match(line, &self.date_parser, self.file_timing.as_mut(), || {
                    chrono::Utc::now().timestamp()
                })
        } else {
            if self.window.len() >= self.max_lines {
                self.window.pop_front();
            }
            self.window.push_back(line.to_owned());
            let joined = self.window.iter().cloned().collect::<Vec<_>>().join(
                "
",
            );
            let hit = self.matcher.try_match(
                &joined,
                &self.date_parser,
                self.file_timing.as_mut(),
                || chrono::Utc::now().timestamp(),
            );
            if hit.is_some() {
                self.window.clear();
            }
            hit
        };
        let Some(m) = matched else {
            return true;
        };
        if self.ignore_list.is_ignored(&m.ip) {
            debug!(
                ip = %m.ip,
                jail = %self.jail_id,
                reason = "allowlist",
                "failure ignored"
            );
            return true;
        }
        let failure = Failure {
            ip: m.ip,
            jail_id: self.jail_id.clone(),
            timestamp: m.timestamp,
        };
        debug!(
            ip = %failure.ip,
            jail = %failure.jail_id,
            timestamp = failure.timestamp,
            "failure delivered"
        );
        self.tx.blocking_send(ReaderEvent::Failure(failure)).is_ok()
    }
}

/// Blocking Fail2Ban 1.1.1 polling read loop for one compatibility log path.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub(crate) fn read_loop(
    jail_id: String,
    log_path: PathBuf,
    matcher: LineMatcher,
    date_parser: DateParser,
    ignore_list: IgnoreList,
    tx: mpsc::Sender<ReaderEvent>,
    cancel: CancellationToken,
    resume: Option<FileStart>,
    emit_checkpoints: bool,
    max_lines: usize,
    log_encoding: LogEncoding,
) -> Option<(FilePosition, Option<PersistedFilePosition>)> {
    let Some(mut initial) =
        open_log_from_with(&jail_id, &log_path, resume.as_ref(), &cancel, open_regular)
    else {
        let absent = PersistedFilePosition::absent(log_path.clone());
        return Some((FilePosition::absent(log_path), Some(absent)));
    };
    let acknowledged = initial.stream_position().unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    let mut active = ActiveFile::new(initial, acknowledged, now);

    let mut ctx = ReadCtx {
        file_timing: matcher.file_timing(),
        jail_id,
        matcher,
        date_parser,
        ignore_list,
        tx,
        max_lines: max_lines.max(1),
        log_encoding,
        window: VecDeque::new(),
    };
    let mut selection = PollSelection::new(1);
    let mut missing_logged = false;
    let mut retry_read = false;
    let mut last_saved: Option<PersistedFilePosition> = None;

    if emit_checkpoints && !active.emit(&log_path, &ctx.tx, &mut last_saved) {
        return None;
    }

    loop {
        if cancel.is_cancelled() {
            // Checked against a file-size snapshot, rather than draining an
            // unbounded live append stream during reload/shutdown.
            let now = chrono::Utc::now().timestamp();
            return match active.poll(&log_path, &mut ctx, now) {
                Ok(true) => Some(active.position(log_path)),
                Ok(false) | Err(_) => None,
            };
        }

        let sample = match stat_stamp(&log_path) {
            Ok(Some(stamp)) => {
                missing_logged = false;
                Some(stamp)
            }
            Ok(None) => {
                if !missing_logged {
                    warn!(
                        jail = %ctx.jail_id,
                        path = %log_path.display(),
                        "log file missing during poll; waiting for reappearance"
                    );
                    missing_logged = true;
                }
                None
            }
            Err(err) => {
                warn!(
                    jail = %ctx.jail_id,
                    path = %log_path.display(),
                    error = %err,
                    "log stat failed during poll"
                );
                None
            }
        };

        let selections = match selection.select_sampled_with_errors(&[(0, sample)], |_| {}) {
            Ok(sel) => sel,
            Err(err) => {
                warn!(
                    jail = %ctx.jail_id,
                    path = %log_path.display(),
                    error = %err,
                    "poll selection reset"
                );
                selection = PollSelection::new(1);
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
        };

        if !selections.removed.is_empty() {
            warn!(
                jail = %ctx.jail_id,
                path = %log_path.display(),
                "log file absent for 51 consecutive polls; resetting poll slot"
            );
            selection = PollSelection::new(1);
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }

        if retry_read || !selections.changed.is_empty() || sample.is_none() {
            let now = chrono::Utc::now().timestamp();
            match active.poll(&log_path, &mut ctx, now) {
                Ok(true) => retry_read = false,
                Ok(false) => return None,
                Err(err) => {
                    if !retry_read {
                        warn!(jail = %ctx.jail_id, path = %log_path.display(), error = %err,
                            "legacy log poll failed; will retry existing cursor");
                    }
                    retry_read = true;
                }
            }
            if emit_checkpoints && !active.emit(&log_path, &ctx.tx, &mut last_saved) {
                return None;
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

fn stat_stamp(path: &Path) -> std::io::Result<Option<PollStamp>> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            let mtime = meta.mtime() as f64 + meta.mtime_nsec() as f64 / 1_000_000_000.0;
            Ok(Some(PollStamp {
                mtime,
                inode: meta.ino(),
                size: meta.len(),
            }))
        }
        Ok(_) => Ok(None),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Open without blocking on a named pipe accidentally supplied in place
/// of a log, then verify the descriptor rather than trusting a prior stat.
fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "log requires a regular file",
        ));
    }
    Ok(file)
}

struct ActiveFile {
    reader: BufReader<File>,
    acknowledged: u64,
    identity: Option<FileIdentityState>,
    live: Option<FileIdentity>,
}

impl ActiveFile {
    fn new(reader: BufReader<File>, acknowledged: u64, now: i64) -> Self {
        let file = reader.get_ref();
        // The original SHA-1 identifies restarts when available. Its
        // bounded-read failure (e.g. oversized first line) must not stop
        // monitoring: the open descriptor and bounded native fingerprint
        // still identify the in-process source.
        let identity = FileIdentityState::initialize(file, now, MAX_LINE_LEN + 1).ok();
        let live = FileIdentity::from_handle(file);
        Self {
            reader,
            acknowledged,
            identity,
            live,
        }
    }

    fn position(&self, path: PathBuf) -> (FilePosition, Option<PersistedFilePosition>) {
        let persisted = PersistedFilePosition::from_handle(
            path.clone(),
            self.reader.get_ref(),
            self.acknowledged,
        );
        (
            FilePosition {
                path,
                identity: self.live.clone(),
                offset: self.acknowledged,
            },
            persisted,
        )
    }

    fn emit(
        &self,
        path: &Path,
        tx: &mpsc::Sender<ReaderEvent>,
        last_sent: &mut Option<PersistedFilePosition>,
    ) -> bool {
        let Some(current) = PersistedFilePosition::from_handle(
            path.to_path_buf(),
            self.reader.get_ref(),
            self.acknowledged,
        ) else {
            return true;
        };
        if last_sent.as_ref() == Some(&current) {
            return true;
        }
        if tx
            .blocking_send(ReaderEvent::Checkpoint(current.clone()))
            .is_err()
        {
            return false;
        }
        *last_sent = Some(current);
        true
    }

    fn poll(&mut self, path: &Path, ctx: &mut ReadCtx, now: i64) -> io::Result<bool> {
        let current = self.reader.get_ref().metadata()?;
        let candidate = match open_regular(path) {
            Ok(candidate) => candidate,
            Err(e) => {
                // The old file remains usable even while the target path is
                // temporarily missing. Never discard complete lines written to
                // that handle during rename or an open error.
                if !self.drain(self.reader.get_ref().metadata()?.len(), ctx)? {
                    return Ok(false);
                }
                return if e.kind() == ErrorKind::NotFound {
                    Ok(true)
                } else {
                    Err(e)
                };
            }
        };
        let candidate_meta = candidate.metadata()?;
        if (current.dev(), current.ino()) != (candidate_meta.dev(), candidate_meta.ino()) {
            if !self.drain(self.reader.get_ref().metadata()?.len(), ctx)? {
                return Ok(false);
            }
            info!(jail = %ctx.jail_id, "reopening rotated log");
            ctx.window.clear();
            *self = Self::new(BufReader::new(candidate), 0, now);
            return self.drain(candidate_meta.len(), ctx);
        }
        let live = FileIdentity::from_handle(&candidate);
        let rotation = self
            .identity
            .as_mut()
            .and_then(|identity| identity.reopen(&candidate, self.acknowledged, now).ok());
        let fallback = || {
            self.live
                .as_ref()
                .zip(live.as_ref())
                .is_some_and(|(a, b)| a.is_rotated(b))
        };
        if candidate_meta.len() < self.acknowledged
            || rotation.map_or_else(fallback, |state| state.rotated)
        {
            info!(jail = %ctx.jail_id, "reopening truncated log");
            self.acknowledged = 0;
            ctx.window.clear();
        }
        self.live = live;
        self.drain(candidate_meta.len(), ctx)
    }

    /// Drain complete records as far as the sampled EOF. Keep an incomplete
    /// line unconsumed, even when oversized. This prevents its appended suffix
    /// being treated as a separate record in a later poll.
    fn drain(&mut self, end: u64, ctx: &mut ReadCtx) -> io::Result<bool> {
        self.reader.seek(SeekFrom::Start(self.acknowledged))?;
        let mut reader = (&mut self.reader).take(end.saturating_sub(self.acknowledged));
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let read = reader
                .by_ref()
                .take(MAX_LINE_LEN as u64 + 1)
                .read_until(b'\n', &mut buf)?;
            if read == 0 {
                break;
            }
            if buf.last() == Some(&b'\n') {
                let text = ctx.decode_bytes(&buf);
                if !ctx.handle_line(text.trim_end()) {
                    return Ok(false);
                }
                self.acknowledged = self.acknowledged.saturating_add(read as u64);
            } else if buf.len() > MAX_LINE_LEN {
                let Some(drained) = drain_until_newline(&mut reader)? else {
                    break;
                };
                warn!(jail = %ctx.jail_id, limit = MAX_LINE_LEN, reason = "oversized", "log line skipped");
                self.acknowledged = self
                    .acknowledged
                    .saturating_add(read as u64)
                    .saturating_add(drained);
            } else {
                break;
            }
        }
        if let Some(timing) = ctx.file_timing.as_mut() {
            timing.reached_eof();
        }
        Ok(true)
    }
}

fn drain_until_newline(reader: &mut impl BufRead) -> io::Result<Option<u64>> {
    let mut total = 0_u64;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(None);
        }
        if let Some(pos) = memchr(b'\n', available) {
            let take = pos + 1;
            reader.consume(take);
            return Ok(Some(total.saturating_add(take as u64)));
        }
        let len = available.len();
        reader.consume(len);
        total = total.saturating_add(len as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn context() -> (ReadCtx, mpsc::Receiver<ReaderEvent>) {
        let (tx, rx) = mpsc::channel(8);
        let matcher = LineMatcher::modern(&[r"^fixture rejected <HOST>$".to_owned()], &[])
            .expect("compile inert fixture matcher");
        let ctx = ReadCtx {
            jail_id: "fixture".to_owned(),
            matcher,
            date_parser: DateParser::new(crate::detect::date::DateFormat::Syslog)
                .expect("date parser"),
            ignore_list: IgnoreList::new(&[], false).expect("empty allowlist"),
            file_timing: None,
            tx,
            max_lines: 1,
            log_encoding: LogEncoding::Utf8,
            window: VecDeque::new(),
        };
        (ctx, rx)
    }

    fn received(rx: &mut mpsc::Receiver<ReaderEvent>) -> Vec<std::net::IpAddr> {
        let mut ips = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ReaderEvent::Failure(f) = ev {
                ips.push(f.ip);
            }
        }
        ips
    }

    fn ip(value: &str) -> std::net::IpAddr {
        value.parse().expect("documentation address")
    }

    #[test]
    fn drains_old_inode_in_order_even_when_target_is_temporarily_missing() {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("access.log");
        let old_path = dir.path().join("access.old");
        std::fs::write(&path, b"header\n").expect("seed first record");
        let mut writer = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append old");
        let mut active = ActiveFile::new(BufReader::new(open_regular(&path).expect("old")), 7, 100);
        let (mut ctx, mut rx) = context();
        std::fs::rename(&path, &old_path).expect("rotate scratch log");
        writeln!(writer, "fixture rejected 192.0.2.10").expect("late old record");
        assert!(
            active
                .poll(&path, &mut ctx, 101)
                .expect("missing-target poll")
        );
        assert_eq!(received(&mut rx), vec![ip("192.0.2.10")]);
        writeln!(writer, "fixture rejected 192.0.2.11").expect("another old record");
        std::fs::write(&path, b"fixture rejected 192.0.2.12\n").expect("create new log");
        assert!(active.poll(&path, &mut ctx, 102).expect("replacement poll"));
        assert_eq!(received(&mut rx), vec![ip("192.0.2.11"), ip("192.0.2.12")]);
        let (live, persisted) = active.position(path.clone());
        assert_eq!(
            live.offset,
            std::fs::metadata(path).expect("live length").len()
        );
        assert_eq!(persisted.expect("checkpoint").offset, Some(live.offset));
    }

    #[test]
    fn oversized_first_record_and_fragment_do_not_disable_later_complete_records() {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("access.log");
        let oversize = vec![b'x'; MAX_LINE_LEN + 8];
        std::fs::write(&path, &oversize).expect("long partial");
        let mut active =
            ActiveFile::new(BufReader::new(open_regular(&path).expect("active")), 0, 100);
        let (mut ctx, mut rx) = context();
        assert!(active.identity.is_none());
        assert!(active.poll(&path, &mut ctx, 101).expect("partial poll"));
        assert_eq!(active.acknowledged, 0, "can't checkpoint a partial record");
        let mut writer = OpenOptions::new().append(true).open(&path).expect("append");
        writer
            .write_all(b"fixture rejected 192.0.2.13\nfixture rejected 192.0.2.14\n")
            .expect("finish long record and write independent record");
        assert!(active.poll(&path, &mut ctx, 102).expect("complete records"));
        assert_eq!(received(&mut rx), vec![ip("192.0.2.14")]);
        let (live, persisted) = active.position(path.clone());
        assert_eq!(
            live.offset,
            std::fs::metadata(path).expect("live length").len()
        );
        assert!(persisted.expect("candidate").first_line_sha1.is_none());
    }
}
