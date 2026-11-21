//! Detection pipeline — read logs, find attackers.
//!
//! Tails log files (or the systemd journal), matches lines against
//! per-jail filter patterns, and emits [`watcher::Failure`] events.

/// Log line timestamp parsing.
pub mod date;
/// Built-in filter templates for common services.
pub mod filters;
/// IP allowlist and local-address detection.
pub mod ignore;
/// Systemd journal log source.
pub mod journal;
/// Per-line matching engine: native patterns or parity-proven original.
pub mod line_matcher;
/// Two-phase log matching engine.
pub mod matcher;
/// Pattern compilation and `<HOST>` expansion.
pub mod pattern;
/// Log file tailer with rotation detection.
pub mod watcher;

/// Capped exponential backoff for unavailable log sources.
mod backoff;
/// IP extraction from regex match spans (internal to the matcher).
mod extract;
/// Log file identity and rotation detection (internal to the reader).
mod identity;
/// Journal JSON entry decoding (internal to the journal watcher).
mod journal_entry;
/// Bounded `journalctl` JSON line reader (internal to the journal watcher).
mod journal_line;
/// `journalctl` stderr/exit-status capture (internal to the journal watcher).
mod journal_proc;
// Original-filter replay is intentionally separate from the deployed matcher.
#[allow(dead_code)]
pub(crate) mod legacy_date;
#[allow(dead_code)]
pub(crate) mod legacy_file_cursor;
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) mod legacy_file_identity;
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) mod legacy_file_seek;
#[allow(dead_code)]
pub mod legacy_matcher;
#[cfg(test)]
mod legacy_matcher_parity_test;
#[allow(dead_code)]
pub(crate) mod legacy_observation_time;
#[allow(dead_code)]
pub(crate) mod legacy_poll_stamp;
#[allow(dead_code)]
mod legacy_regex;
#[allow(dead_code)]
mod legacy_ssh_events;
#[allow(dead_code)]
mod legacy_ssh_log;
#[cfg(test)]
mod legacy_ssh_session_parity_test;
#[allow(dead_code)]
mod legacy_ssh_sessions;
/// Blocking log-file read loop (internal to the watcher).
mod reader;
/// Watcher resume points for gap-free reload handoff.
mod resume;

pub use resume::ResumePoint;
