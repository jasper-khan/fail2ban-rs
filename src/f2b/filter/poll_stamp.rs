//! File modification snapshot tracking and missing-file eviction for `FilterPoll`,
//! matching Fail2Ban 1.1.1 `fail2ban/server/filterpoll.py`.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Remove missing log path from active polling after this many consecutive `ENOENT` polls
/// (matching `FilterPoll.getModified` removing after `absent >= 50` / 60s).
pub const REMOVE_AFTER: usize = 50;

/// Metadata snapshot of a watched log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollStamp {
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub size: u64,
    pub ino: u64,
    pub dev: u64,
}

impl PollStamp {
    /// Stat `path` and extract high-resolution modification/inode metadata.
    pub fn from_path(path: &Path) -> std::result::Result<Self, SnapshotError> {
        let meta = fs::metadata(path).map_err(SnapshotError::from_io)?;
        Ok(Self {
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            ctime_ns: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
            size: meta.size(),
            ino: meta.ino(),
            dev: meta.dev(),
        })
    }
}

/// Errors encountered when snapping metadata for a polled file.
#[derive(Debug)]
pub enum SnapshotError {
    NotFound,
    PermissionDenied,
    Other(io::Error),
}

impl SnapshotError {
    pub fn from_io(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Other(err),
        }
    }
}

/// Single-file change detection status returned by [`PollSelection::check`].
#[derive(Debug)]
pub enum PollCheck {
    Changed(PollStamp),
    Unchanged,
    Missing { consecutive: usize, evict: bool },
    Error(SnapshotError),
}

/// Per-file polling selection tracking last observed [`PollStamp`] and absent counter.
#[derive(Debug, Clone)]
pub struct PollSelection {
    path: PathBuf,
    last_stamp: Option<PollStamp>,
    absent_count: usize,
}

impl PollSelection {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last_stamp: None,
            absent_count: 0,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_stamp(&self) -> Option<PollStamp> {
        self.last_stamp
    }

    pub fn absent_count(&self) -> usize {
        self.absent_count
    }

    /// Check `self.path` metadata against the last recorded snapshot.
    pub fn check(&mut self) -> PollCheck {
        match PollStamp::from_path(&self.path) {
            Ok(stamp) => {
                self.absent_count = 0;
                if self.last_stamp == Some(stamp) {
                    PollCheck::Unchanged
                } else {
                    self.last_stamp = Some(stamp);
                    PollCheck::Changed(stamp)
                }
            }
            Err(SnapshotError::NotFound) => {
                self.absent_count += 1;
                let evict = self.absent_count >= REMOVE_AFTER;
                PollCheck::Missing {
                    consecutive: self.absent_count,
                    evict,
                }
            }
            Err(err) => PollCheck::Error(err),
        }
    }
}

/// Outcome yielded by [`Selections::poll_all`] for one monitored path.
#[derive(Debug)]
pub enum PollOutcome {
    Changed { path: PathBuf, stamp: PollStamp },
    Evicted { path: PathBuf },
    Error { path: PathBuf, error: SnapshotError },
}

/// Collection of monitored file paths managed by `FilterPoll`.
#[derive(Debug, Default)]
pub struct Selections {
    entries: BTreeMap<PathBuf, PollSelection>,
}

impl Selections {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_path(&mut self, path: impl Into<PathBuf>) -> bool {
        let pb = path.into();
        if self.entries.contains_key(&pb) {
            return false;
        }
        self.entries.insert(pb.clone(), PollSelection::new(pb));
        true
    }

    pub fn remove_path(&mut self, path: &Path) -> bool {
        self.entries.remove(path).is_some()
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.entries.contains_key(path)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.entries.keys().map(PathBuf::as_path)
    }

    /// Poll every tracked file once, returning changed paths, evicted paths
    /// (after [`REMOVE_AFTER`] consecutive `NotFound` results), and stat errors.
    pub fn poll_all(&mut self) -> Vec<PollOutcome> {
        let mut outcomes = Vec::new();
        let mut to_evict = Vec::new();

        for (path, sel) in &mut self.entries {
            match sel.check() {
                PollCheck::Changed(stamp) => outcomes.push(PollOutcome::Changed {
                    path: path.clone(),
                    stamp,
                }),
                PollCheck::Unchanged | PollCheck::Missing { evict: false, .. } => {}
                PollCheck::Missing { evict: true, .. } => {
                    to_evict.push(path.clone());
                }
                PollCheck::Error(error) => outcomes.push(PollOutcome::Error {
                    path: path.clone(),
                    error,
                }),
            }
        }

        for path in to_evict {
            self.entries.remove(&path);
            outcomes.push(PollOutcome::Evicted { path });
        }

        outcomes
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "f2b_poll_{name}_{}_{nanos}.log",
            std::process::id()
        ))
    }

    #[test]
    fn poll_selection_detects_changes_and_evicts_after_threshold() {
        let path = unique_temp_path("sel");
        fs::write(&path, b"hello\n").unwrap();

        let mut selections = Selections::new();
        assert!(selections.add_path(&path));
        assert!(!selections.add_path(&path));

        // First poll reports Changed.
        let first = selections.poll_all();
        assert!(matches!(first.as_slice(), [PollOutcome::Changed { .. }]));

        // Second poll with no change reports empty outcomes.
        assert!(selections.poll_all().is_empty());

        // Appending triggers Changed.
        fs::write(&path, b"hello\nworld\n").unwrap();
        let updated = selections.poll_all();
        assert!(matches!(updated.as_slice(), [PollOutcome::Changed { .. }]));

        // Removing triggers eviction at exactly REMOVE_AFTER polls.
        fs::remove_file(&path).unwrap();
        for _ in 1..REMOVE_AFTER {
            assert!(selections.poll_all().is_empty());
            assert!(selections.contains(&path));
        }
        let evicted = selections.poll_all();
        assert!(matches!(evicted.as_slice(), [PollOutcome::Evicted { .. }]));
        assert!(!selections.contains(&path));
    }
}
