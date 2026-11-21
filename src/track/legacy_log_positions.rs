//! Pure read-side projection of original Fail2Ban 1.1.1 log positions.
//!
//! The caller supplies typed row snapshots. No database, file or journal is
//! accessed, and the original _addLog registration writes are not performed.

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum StoredLogPosition {
    Integer(i64),
    Real(f64),
}

/// One row from the original logs schema; keys must be unique by jail/path.
#[derive(Clone, Copy, Debug)]
pub(super) struct LogRow<'a> {
    pub(super) jail: &'a str,
    pub(super) path: &'a str,
    /// Literal stored fingerprint; journal rows use this column for ISO text.
    pub(super) first_line_md5: Option<&'a str>,
    pub(super) last_file_pos: Option<StoredLogPosition>,
}

/// Return the old value as selected by _addLog (also called by getJournalPos).
///
/// Omitting a fingerprint disables the check. A provided empty fingerprint
/// is not the same as an omitted one. No new row is registered on a miss.
pub(super) fn stored_position(
    rows: &[LogRow<'_>],
    jail: &str,
    path: &str,
    fingerprint: Option<&str>,
) -> Option<StoredLogPosition> {
    let row = rows
        .iter()
        .find(|row| row.jail == jail && row.path == path)?;
    if fingerprint.is_some() && fingerprint != row.first_line_md5 {
        return None;
    }
    row.last_file_pos
}

/// Stored byte offset to apply to a new FileContainer, if not tailing.
/// A zero offset is intentionally equivalent to no override.
pub(super) fn file_resume_offset(
    rows: &[LogRow<'_>],
    jail: &str,
    path: &str,
    fingerprint: Option<&str>,
    tail: bool,
) -> Option<u64> {
    if tail {
        return None;
    }
    match stored_position(rows, jail, path, fingerprint)? {
        StoredLogPosition::Integer(offset) if offset > 0 => u64::try_from(offset).ok(),
        _ => None,
    }
}

/// Initial seek time for a journal with a known tail entry (the nonempty
/// startup branch). The original uses the numeric lastfilepos, not an ISO
/// marker or journal cursor. Inputs are finite epoch seconds, and find_time
/// is already in whole seconds as in Python's int(getFindTime()).
pub(super) fn journal_resume_time(
    saved: Option<StoredLogPosition>,
    now: f64,
    find_time: i64,
) -> f64 {
    let saved = match saved {
        Some(StoredLogPosition::Integer(seconds)) => seconds as f64,
        Some(StoredLogPosition::Real(seconds)) => seconds,
        None => 0.0,
    };
    saved.max(now - find_time as f64)
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
#[path = "legacy_log_positions_test.rs"]
mod tests;
