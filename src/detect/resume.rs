//! Watcher resume points — gap-free handoff between old and new watchers.
//!
//! When a watcher stops it reports where it got to: a file identity plus
//! byte offset for file watchers, or a journal cursor for journal watchers.
//! A replacement watcher started from that [`ResumePoint`] continues exactly
//! where the old one stopped instead of jumping to the end of the log.

use std::io::{BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::detect::backoff::{Backoff, blocking_sleep};
use crate::detect::identity::FileIdentity;
use crate::detect::watcher::MAX_LINE_LEN;

/// Opaque position a watcher reached when it stopped.
///
/// Returned by [`watcher::run`](crate::detect::watcher::run) and
/// [`journal::run`](crate::detect::journal::run); pass it to the matching
/// `run_from` of the replacement watcher. A resume point of the wrong kind
/// (file vs journal) or for a different log path is ignored, and the new
/// watcher falls back to its default start position.
#[derive(Debug, Clone)]
pub struct ResumePoint(Kind);

#[derive(Debug, Clone)]
enum Kind {
    File {
        live: FilePosition,
        persisted: Option<PersistedFilePosition>,
    },
    PersistedFile(PersistedFilePosition),
    Journal(String),
}

/// Where a file reader stopped (in-process handoff).
#[derive(Debug, Clone)]
pub(crate) struct FilePosition {
    /// Log path the reader was tailing.
    pub(crate) path: PathBuf,
    /// Fingerprint of the handle the reader held; `None` if the file was
    /// never opened (it did not exist).
    pub(crate) identity: Option<FileIdentity>,
    /// Byte offset of the first unprocessed byte.
    pub(crate) offset: u64,
}

/// Serializable checkpoint for a log file, used across daemon restarts and
/// for one-time migration from original Fail2Ban 1.1.1 SQLite `logs` rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PersistedFilePosition {
    /// Log path the checkpoint belongs to.
    pub(crate) path: PathBuf,
    /// File inode recorded by Rust (absent for checkpoints migrated from
    /// original Fail2Ban SQLite, which stores only first-line hash + offset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inode: Option<u64>,
    /// Fail2Ban 1.1.1 first-line SHA-1 hex fingerprint (`""` while empty or
    /// first line is incomplete; `None` if missing/NULL in legacy DB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) first_line_sha1: Option<String>,
    /// Byte offset of the first unprocessed byte (`None` if legacy DB held an
    /// invalid, negative, or non-integer position).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) offset: Option<u64>,
}

impl PersistedFilePosition {
    /// Marker for a file that did not exist when the checkpoint was captured.
    pub(crate) fn absent(path: PathBuf) -> Self {
        Self {
            path,
            inode: None,
            first_line_sha1: None,
            offset: Some(0),
        }
    }

    /// Capture a durable checkpoint from an already-open file handle without
    /// moving its seek position.
    #[cfg(unix)]
    pub(crate) fn from_handle(path: PathBuf, file: &std::fs::File, offset: u64) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().ok()?;
        if !meta.is_file() {
            return None;
        }
        let first_line_sha1 =
            crate::detect::legacy_file_identity::file_first_line_sha1(file, MAX_LINE_LEN + 1).ok();
        Some(Self {
            path,
            inode: Some(meta.ino()),
            first_line_sha1,
            offset: Some(offset),
        })
    }

    /// Non-unix fallback: handle checkpointing is unsupported.
    #[cfg(not(unix))]
    pub(crate) fn from_handle(_path: PathBuf, _file: &std::fs::File, _offset: u64) -> Option<Self> {
        None
    }
}

/// Start instruction for a file reader: either an in-process live handoff or a
/// persisted/migrated checkpoint.
#[derive(Debug, Clone)]
pub(crate) enum FileStart {
    Live(FilePosition),
    Persisted(PersistedFilePosition),
}

impl FilePosition {
    /// Marker for "the file did not exist": a successor reads it from the
    /// start once it appears.
    pub(crate) fn absent(path: PathBuf) -> Self {
        Self {
            path,
            identity: None,
            offset: 0,
        }
    }
}

impl ResumePoint {
    /// Wrap a file reader position.
    #[cfg(test)]
    pub(crate) fn file(pos: FilePosition) -> Self {
        Self(Kind::File {
            live: pos,
            persisted: None,
        })
    }

    /// Wrap a file reader position together with its durable persisted form.
    pub(crate) fn file_with_persisted(
        live: FilePosition,
        persisted: Option<PersistedFilePosition>,
    ) -> Self {
        Self(Kind::File { live, persisted })
    }

    /// Wrap a persisted or migrated file checkpoint.
    pub(crate) fn persisted_file(pos: PersistedFilePosition) -> Self {
        Self(Kind::PersistedFile(pos))
    }

    /// Wrap a journal cursor.
    pub(crate) fn journal(cursor: String) -> Self {
        Self(Kind::Journal(cursor))
    }

    /// The live file position, if this is an in-process file resume point.
    #[cfg(test)]
    pub(crate) fn into_file(self) -> Option<FilePosition> {
        match self.0 {
            Kind::File { live, .. } => Some(live),
            Kind::PersistedFile(_) | Kind::Journal(_) => None,
        }
    }

    /// The file start position, whether live (reload) or persisted (restart).
    pub(crate) fn into_file_start(self) -> Option<FileStart> {
        match self.0 {
            Kind::File { live, .. } => Some(FileStart::Live(live)),
            Kind::PersistedFile(pos) => Some(FileStart::Persisted(pos)),
            Kind::Journal(_) => None,
        }
    }

    /// The durable file checkpoint carried by this resume point, if any.
    pub(crate) fn persisted_file_position(&self) -> Option<&PersistedFilePosition> {
        match &self.0 {
            Kind::File { persisted, .. } => persisted.as_ref(),
            Kind::PersistedFile(pos) => Some(pos),
            Kind::Journal(_) => None,
        }
    }

    /// The journal cursor, if this is a journal resume point.
    pub(crate) fn into_journal_cursor(self) -> Option<String> {
        match self.0 {
            Kind::Journal(c) => Some(c),
            Kind::File { .. } | Kind::PersistedFile(_) => None,
        }
    }
}

/// Where a freshly opened file should start reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartAt {
    /// Skip existing content (default, no resume point).
    End,
    /// Read the whole file (new file, or rotated/truncated/invalid checkpoint).
    Start,
    /// Continue at a byte offset in the same file.
    Offset(u64),
}

/// Decide the start position for `file` at `path` given an optional live resume.
pub(crate) fn start_for(
    path: &Path,
    resume: Option<&FilePosition>,
    file: &std::fs::File,
) -> StartAt {
    let Some(pos) = resume.filter(|p| p.path == path) else {
        return StartAt::End;
    };
    let Some(old) = pos.identity.as_ref() else {
        return StartAt::Start; // file was absent at handoff — it is new
    };
    match FileIdentity::from_handle(file) {
        Some(cur) if old.can_resume(&cur, pos.offset) => StartAt::Offset(pos.offset),
        _ => StartAt::Start, // replaced/truncated during handoff
    }
}

/// Decide the start position for `file` at `path` given a persisted or migrated
/// checkpoint, following Fail2Ban 1.1.1's `FileContainer` + `_addLog` rules:
///
/// - Same file (matching first-line SHA-1, matching inode if recorded) and
///   `0 < offset <= file_size` → resume at `StartAt::Offset(offset)`.
/// - Rotated, truncated (`file_size < offset`), or invalid checkpoint (`None`,
///   `0`, empty/mismatched hash) → fall back to `StartAt::Start` (offset 0).
pub(crate) fn start_for_persisted(
    path: &Path,
    pos: &PersistedFilePosition,
    file: &std::fs::File,
) -> StartAt {
    if pos.path != path {
        return StartAt::End;
    }
    let Some(offset) = pos.offset.filter(|&off| off > 0) else {
        return StartAt::Start;
    };
    let Some(stored_hash) = pos.first_line_sha1.as_deref().filter(|h| !h.is_empty()) else {
        return StartAt::Start;
    };
    let Ok(meta) = file.metadata() else {
        return StartAt::Start;
    };
    if !meta.is_file() || meta.len() < offset {
        return StartAt::Start;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(saved_ino) = pos.inode
            && saved_ino != meta.ino()
        {
            return StartAt::Start;
        }
        match crate::detect::legacy_file_identity::file_first_line_sha1(file, MAX_LINE_LEN + 1) {
            Ok(current_hash) if current_hash == stored_hash => StartAt::Offset(offset),
            _ => StartAt::Start,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (offset, stored_hash);
        StartAt::Start
    }
}

/// Decide the start position for `file` given either a live or persisted start.
fn start_for_any(path: &Path, start: Option<&FileStart>, file: &std::fs::File) -> StartAt {
    match start {
        None => StartAt::End,
        Some(FileStart::Live(pos)) => start_for(path, Some(pos), file),
        Some(FileStart::Persisted(pos)) => start_for_persisted(path, pos, file),
    }
}

/// Open the log at `path`, retrying with capped backoff while it is missing.
///
/// Returns `None` only if `cancel` fires first. A file that only appears
/// after one or more retries is read from the start, since it is new.
#[cfg(test)]
pub(crate) fn open_log(
    jail_id: &str,
    path: &Path,
    resume: Option<&FilePosition>,
    cancel: &CancellationToken,
) -> Option<BufReader<std::fs::File>> {
    let start = resume.cloned().map(FileStart::Live);
    open_log_from(jail_id, path, start.as_ref(), cancel)
}

/// Open the log at `path` using either a live or persisted resume point.
pub(crate) fn open_log_from(
    jail_id: &str,
    path: &Path,
    resume: Option<&FileStart>,
    cancel: &CancellationToken,
) -> Option<BufReader<std::fs::File>> {
    open_log_from_with(jail_id, path, resume, cancel, |path| {
        std::fs::File::open(path)
    })
}

pub(super) fn open_log_from_with(
    jail_id: &str,
    path: &Path,
    resume: Option<&FileStart>,
    cancel: &CancellationToken,
    open: impl Fn(&Path) -> std::io::Result<std::fs::File>,
) -> Option<BufReader<std::fs::File>> {
    let mut backoff = Backoff::new();
    let mut retried = false;
    loop {
        match open(path).and_then(|file| position_file(path, file, resume, retried)) {
            Ok(reader) => {
                if retried {
                    info!(jail = %jail_id, path = %path.display(), "log file opened after retry");
                }
                return Some(reader);
            }
            Err(e) => {
                let delay = backoff.next_delay();
                log_open_failure(jail_id, path, &e, &backoff, delay);
                if !blocking_sleep(delay, cancel) {
                    return None;
                }
                retried = true;
            }
        }
    }
}

fn position_file(
    path: &Path,
    mut file: std::fs::File,
    resume: Option<&FileStart>,
    force_start: bool,
) -> std::io::Result<BufReader<std::fs::File>> {
    let start = if force_start {
        StartAt::Start
    } else {
        start_for_any(path, resume, &file)
    };
    match start {
        StartAt::End => file.seek(SeekFrom::End(0))?,
        StartAt::Start => 0,
        StartAt::Offset(off) => file.seek(SeekFrom::Start(off))?,
    };
    Ok(BufReader::new(file))
}

fn log_open_failure(
    jail_id: &str,
    path: &Path,
    err: &std::io::Error,
    backoff: &Backoff,
    delay: std::time::Duration,
) {
    let retry_secs = delay.as_secs();
    if backoff.is_first_failure() {
        warn!(jail = %jail_id, path = %path.display(), error = %err, retry_secs, "log open failed, retrying");
    } else {
        debug!(jail = %jail_id, path = %path.display(), error = %err, retry_secs, "log open retry failed");
    }
}

#[cfg(test)]
#[path = "resume_test.rs"]
mod resume_test;
