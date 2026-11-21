//! Durable Rust-owned log-position store for compatibility-mode restarts.
//!
//! Legacy Fail2Ban SQLite databases are opened read-only and imported at most
//! once; afterwards this store (inside the isolated recording state directory)
//! is authoritative. Updates are written atomically via temp-file + fsync +
//! rename so an interruption before or after a checkpoint save leaves either
//! the previous intact state or the new intact state — never a torn file.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::detect::resume::{PersistedFilePosition, ResumePoint};
use crate::error::{Error, Result};

const LOG_POSITIONS_FILENAME: &str = "log_positions.json";
const STORE_VERSION: u32 = 1;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredLogPositions {
    version: u32,
    positions: BTreeMap<String, PersistedFilePosition>,
}

/// Thread-safe, atomically persisted map of watcher keys to log checkpoints.
pub(crate) struct LogPositionStore {
    state_dir: PathBuf,
    path: PathBuf,
    positions: Mutex<BTreeMap<String, PersistedFilePosition>>,
    sqlite_mirror: Option<crate::track::SqliteMirror>,
}

impl LogPositionStore {
    /// Open or initialize the log-position store inside `state_dir`.
    ///
    /// A missing file starts empty. A corrupted or unsupported file logs a
    /// warning and starts empty rather than blocking daemon startup.
    #[cfg(test)]
    pub(crate) fn open(state_dir: &Path) -> Self {
        Self::open_with_sqlite(state_dir, None)
    }

    pub(crate) fn open_with_sqlite(
        state_dir: &Path,
        sqlite_mirror: Option<crate::track::SqliteMirror>,
    ) -> Self {
        let path = state_dir.join(LOG_POSITIONS_FILENAME);
        let positions = load_from_disk(&path);
        Self {
            state_dir: state_dir.to_path_buf(),
            path,
            positions: Mutex::new(positions),
            sqlite_mirror,
        }
    }

    pub(super) fn sqlite_mirror(&self) -> Option<crate::track::SqliteMirror> {
        self.sqlite_mirror.clone()
    }

    fn mirror_sqlite(&self, key: &str, pos: &PersistedFilePosition) -> Result<()> {
        let Some(db) = &self.sqlite_mirror else {
            return Ok(());
        };
        let (jail, _) = key.split_once('\u{1}').ok_or_else(|| {
            Error::persistence("invalid watcher key for legacy SQLite checkpoint")
        })?;
        let hash = pos.first_line_sha1.as_deref().unwrap_or("");
        let offset = pos.offset.unwrap_or(0);
        let guard = db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.upsert_log(jail, &pos.path.to_string_lossy(), hash, offset)
    }

    /// Snapshot all persisted checkpoints as `ResumePoint`s for watcher startup.
    pub(crate) fn snapshot_resume_points(&self) -> HashMap<String, ResumePoint> {
        let guard = self.lock_positions();
        guard
            .iter()
            .map(|(k, v)| (k.clone(), ResumePoint::persisted_file(v.clone())))
            .collect()
    }

    /// Insert any entries whose key is not yet present and flush durably.
    ///
    /// Existing keys are preserved so an earlier Rust-saved checkpoint is never
    /// overwritten by a legacy SQLite row (even if a previous migration crashed
    /// between saving `log_positions.json` and committing the WAL marker).
    pub(crate) fn seed_missing(
        &self,
        entries: impl IntoIterator<Item = (String, PersistedFilePosition)>,
    ) -> Result<usize> {
        let mut guard = self.lock_positions();
        let mut next = guard.clone();
        let mut added = 0usize;
        for (key, pos) in entries {
            if let std::collections::btree_map::Entry::Vacant(entry) = next.entry(key) {
                entry.insert(pos);
                added += 1;
            }
        }
        if added > 0 {
            self.write_durable_locked(&next)?;
            *guard = next;
        }
        Ok(added)
    }

    /// Update one watcher's checkpoint if it changed and flush durably.
    pub(crate) fn update_one(&self, key: &str, pos: PersistedFilePosition) -> Result<()> {
        let mut guard = self.lock_positions();
        if guard.get(key) == Some(&pos) {
            return Ok(());
        }
        // Both sinks must acknowledge before publishing the new position in
        // memory. If the JSON write fails after SQLite commits, retry the
        // idempotent mirror write with the same offset.
        self.mirror_sqlite(key, &pos)?;
        let mut next = guard.clone();
        next.insert(key.to_owned(), pos);
        self.write_durable_locked(&next)?;
        *guard = next;
        Ok(())
    }

    /// Update a batch of watcher checkpoints (e.g. on reload or shutdown) and
    /// flush durably if anything changed.
    pub(crate) fn update_batch(&self, points: &HashMap<String, ResumePoint>) -> Result<()> {
        let mut guard = self.lock_positions();
        let mut next = guard.clone();
        let mut changed = false;
        for (key, point) in points {
            let Some(pos) = point.persisted_file_position() else {
                continue;
            };
            if guard.get(key) != Some(pos) {
                self.mirror_sqlite(key, pos)?;
                next.insert(key.clone(), pos.clone());
                changed = true;
            }
        }
        if changed {
            self.write_durable_locked(&next)?;
            *guard = next;
        }
        Ok(())
    }

    fn lock_positions(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, PersistedFilePosition>> {
        self.positions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_durable_locked(
        &self,
        positions: &BTreeMap<String, PersistedFilePosition>,
    ) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir).map_err(|err| {
            Error::persistence(format!(
                "creating state directory {} for log positions: {err}",
                self.state_dir.display()
            ))
        })?;
        let payload = StoredLogPositions {
            version: STORE_VERSION,
            positions: positions.clone(),
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|err| Error::persistence(format!("serializing log positions: {err}")))?;
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!("{LOG_POSITIONS_FILENAME}.tmp.{}.{seq}", std::process::id());
        let tmp_path = self.state_dir.join(tmp_name);
        let write_result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp_path, &self.path)?;
            sync_dir(&self.state_dir)
        })();
        if let Err(err) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::persistence(format!(
                "persisting log positions to {}: {err}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

fn load_from_disk(path: &Path) -> BTreeMap<String, PersistedFilePosition> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return BTreeMap::new(),
        Err(err) => {
            warn!(
                phase = "startup",
                path = %path.display(),
                error = %err,
                "failed to read persisted log positions; starting without them"
            );
            return BTreeMap::new();
        }
    };
    match serde_json::from_slice::<StoredLogPositions>(&bytes) {
        Ok(stored) if stored.version == STORE_VERSION => stored.positions,
        Ok(stored) => {
            warn!(
                phase = "startup",
                path = %path.display(),
                version = stored.version,
                "unsupported log positions version; ignoring file"
            );
            BTreeMap::new()
        }
        Err(err) => {
            warn!(
                phase = "startup",
                path = %path.display(),
                error = %err,
                "corrupt persisted log positions; ignoring file"
            );
            BTreeMap::new()
        }
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
#[path = "log_positions_test.rs"]
mod tests;
