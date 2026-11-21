//! Read original Fail2Ban 1.1.1 ban state directly from its SQLite database.
//!
//! Startup-only migration slice: the database is opened read-only and only
//! the `bips` table (bans in progress) is decoded. Fail2Ban keeps this
//! database continuously updated; writing it back is a later stage, so the
//! WAL remains the daemon's live store after the upgrade seed.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::Value;
use tracing::{info, warn};

use crate::config::{Config, LogBackend};
use crate::detect::ignore::IgnoreList;
use crate::error::{Error, Result};
use crate::track::legacy_log_positions::{LogRow, StoredLogPosition, file_resume_offset};
use crate::track::legacy_restore::{self, LegacyBanRow, RestoreRequest, RestoredBan};
use crate::track::state::BanRecord;

/// Restored bans for all compat jails from the original SQLite database.
///
/// Called only for compatibility-tree startups. The database is never created
/// or modified; a missing file or missing `bips` table seeds nothing and only
/// logs.
pub(crate) fn restore_bans(dbfile: &Path, config: &Config) -> Result<Vec<BanRecord>> {
    restore_bans_at(dbfile, config, chrono::Utc::now().timestamp() as f64)
}

fn restore_bans_at(dbfile: &Path, config: &Config, now: f64) -> Result<Vec<BanRecord>> {
    if !original_db_exists(dbfile)? {
        return Ok(Vec::new());
    }
    let mut connection = open_readonly(dbfile)?;
    let snapshot = connection
        .transaction()
        .map_err(|err| db_error(dbfile, "opening a read snapshot of", &err))?;
    if !has_bips(&snapshot).map_err(|err| db_error(dbfile, "checking bips in", &err))? {
        info!(
            phase = "startup",
            dbfile = %dbfile.display(),
            "original ban database has no bips table"
        );
        return Ok(Vec::new());
    }

    let mut restored = Vec::new();
    for (name, jail) in config.enabled_jails() {
        let request = RestoreRequest {
            jail: name,
            now,
            // Original restoreCurrentBans without increment uses the jail's
            // ban time as the search window. A permanent jail disables it.
            age_window: (jail.ban_time >= 0).then_some(jail.ban_time as f64),
            base_ban_time: jail.ban_time as f64,
            max_ban_time: (jail.ban_time >= 0).then_some(jail.ban_time as f64),
            // Match history inside the metadata is not reseeded in live counters.
            max_matches: 0,
        };
        let rows = read_bips(&snapshot, &request).map_err(|err| {
            db_error(
                dbfile,
                &format!("reading bips for jail {name:?} from"),
                &err,
            )
        })?;
        let ignore = IgnoreList::new(&jail.ignoreip, false)?;
        for ban in legacy_restore::restore_current(&rows, &request).map_err(|err| {
            Error::config(format!(
                "original ban database {} for jail {name:?}: {err}",
                dbfile.display()
            ))
        })? {
            if let Some(record) = ban_record(name, &ban) {
                if !ignore.is_ignored(&record.ip) {
                    restored.push(record);
                }
            } else {
                warn!(
                    phase = "startup",
                    jail = %name,
                    identifier = %ban.ip,
                    "original ban with a non-address identifier was not restored"
                );
            }
        }
    }
    snapshot
        .commit()
        .map_err(|err| db_error(dbfile, "closing the read snapshot of", &err))?;
    info!(
        phase = "startup",
        bans = restored.len(),
        "bans loaded from the original Fail2Ban database"
    );
    Ok(restored)
}

fn original_db_exists(dbfile: &Path) -> Result<bool> {
    match dbfile.metadata() {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(Error::config(format!(
            "original ban database is not a regular file: {}",
            dbfile.display()
        ))),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            info!(
                phase = "startup",
                dbfile = %dbfile.display(),
                "no original ban database to restore"
            );
            Ok(false)
        }
        Err(err) => Err(Error::io(
            format!("checking original ban database {}", dbfile.display()),
            err,
        )),
    }
}

fn open_readonly(dbfile: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        dbfile,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| db_error(dbfile, "opening", &err))
}

fn db_error(dbfile: &Path, operation: &str, err: &rusqlite::Error) -> Error {
    Error::config(format!(
        "{operation} original ban database {}: {err}",
        dbfile.display()
    ))
}

fn has_bips(connection: &Connection) -> rusqlite::Result<bool> {
    has_table(connection, "bips")
}

fn has_table(connection: &Connection, table: &str) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1 COLLATE NOCASE)",
        params![table],
        |row| row.get(0),
    )
}

/// One log checkpoint imported from the original Fail2Ban 1.1.1 `logs` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyLogCheckpoint {
    pub(crate) jail: String,
    pub(crate) path: PathBuf,
    pub(crate) first_line_sha1: Option<String>,
    pub(crate) offset: Option<u64>,
}

/// Read original Fail2Ban 1.1.1 log positions for all enabled file-backend
/// jails from the read-only SQLite `logs` table.
///
/// A missing database or missing `logs` table returns an empty list without
/// error. A `(jail, path)` pair with no row in `logs` is omitted so the daemon
/// keeps its default tail-from-EOF behavior for untracked files; a pair with a
/// row (even an invalid or zero-offset row) is returned so the reader applies
/// Fail2Ban 1.1.1 fallback rules.
pub(crate) fn restore_log_positions(
    dbfile: &Path,
    config: &Config,
) -> Result<Vec<LegacyLogCheckpoint>> {
    if !original_db_exists(dbfile)? {
        return Ok(Vec::new());
    }
    let mut connection = open_readonly(dbfile)?;
    let snapshot = connection
        .transaction()
        .map_err(|err| db_error(dbfile, "opening a read snapshot of", &err))?;
    if !has_table(&snapshot, "logs").map_err(|err| db_error(dbfile, "checking logs in", &err))? {
        info!(
            phase = "startup",
            dbfile = %dbfile.display(),
            "original ban database has no logs table"
        );
        return Ok(Vec::new());
    }

    let mut checkpoints = Vec::new();
    for (name, jail) in config.enabled_jails() {
        if jail.log_backend != LogBackend::File {
            continue;
        }
        let mut seen = BTreeSet::new();
        for path in jail.log_paths.iter().chain([&jail.log_path]) {
            if path.as_os_str().is_empty() || !seen.insert(path) {
                continue;
            }
            let path_text = path.to_string_lossy();
            let row = read_log_row(&snapshot, name, &path_text).map_err(|err| {
                db_error(
                    dbfile,
                    &format!("reading logs for jail {name:?} path {path_text:?} from"),
                    &err,
                )
            })?;
            if let Some((first_line_sha1, pos)) = row {
                let rows = [LogRow {
                    jail: name,
                    path: &path_text,
                    first_line_md5: first_line_sha1.as_deref(),
                    last_file_pos: pos,
                }];
                let offset = file_resume_offset(&rows, name, &path_text, None, false);
                checkpoints.push(LegacyLogCheckpoint {
                    jail: name.to_owned(),
                    path: path.clone(),
                    first_line_sha1,
                    offset,
                });
            }
        }
    }
    snapshot
        .commit()
        .map_err(|err| db_error(dbfile, "closing the read snapshot of", &err))?;
    info!(
        phase = "startup",
        log_positions = checkpoints.len(),
        "log positions loaded from the original Fail2Ban database"
    );
    Ok(checkpoints)
}

fn read_log_row(
    connection: &Connection,
    jail: &str,
    path: &str,
) -> rusqlite::Result<Option<(Option<String>, Option<StoredLogPosition>)>> {
    let mut statement = connection
        .prepare("SELECT firstlinemd5, lastfilepos FROM logs WHERE jail = ?1 AND path = ?2")?;
    let mut rows = statement.query(params![jail, path])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let first_line_sha1 = match row.get_ref(0)? {
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        _ => None,
    };
    let last_file_pos = match row.get_ref(1)? {
        ValueRef::Integer(value) => Some(StoredLogPosition::Integer(value)),
        ValueRef::Real(value) => Some(StoredLogPosition::Real(value)),
        _ => None,
    };
    Ok(Some((first_line_sha1, last_file_pos)))
}

/// Apply the original selection window before decoding a row, so another
/// jail's (or an expired row's) data does not affect this restore.
fn read_bips(
    connection: &Connection,
    request: &RestoreRequest<'_>,
) -> rusqlite::Result<Vec<LegacyBanRow>> {
    let oldest = request
        .age_window
        .filter(|window| *window >= 0.0)
        .map(|window| request.now - window);
    let mut statement = connection.prepare(
        "SELECT ip, timeofban, bantime, bancount, data FROM bips
         WHERE jail = ?1 AND ip IS NOT NULL AND ip <> ''
         AND (?2 IS NULL OR timeofban > ?2)
         AND (timeofban + bantime > ?3 OR bantime <= -1)
         ORDER BY ip",
    )?;
    let queried = statement.query_map(params![request.jail, oldest, request.now], |row| {
        let ip: String = row.get(0)?;
        Ok(LegacyBanRow {
            jail: request.jail.to_owned(),
            time_of_ban: row.get(1)?,
            ban_time: row.get(2)?,
            ban_count: row.get(3)?,
            data: ticket_data(row.get_ref(4)?, request.jail, &ip),
            ip,
        })
    })?;
    queried.collect()
}

/// Fail2Ban's adapter writes UTF-8 JSON bytes (a SQLite BLOB), and its
/// converter uses replacement decoding and falls back to empty metadata on
/// invalid JSON. Accept TEXT and NULL as well, without logging log contents.
fn ticket_data(value: ValueRef<'_>, jail: &str, ip: &str) -> Option<Value> {
    let parsed = match value {
        ValueRef::Null => return None,
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            serde_json::from_str(&String::from_utf8_lossy(bytes)).ok()
        }
        _ => None,
    };
    if matches!(parsed, Some(Value::Object(_) | Value::Null)) {
        parsed
    } else {
        warn!(
            phase = "startup",
            jail, ip, "invalid original ban ticket data; restoring without metadata"
        );
        None
    }
}

/// One restored original ban as a live [`BanRecord`]; `None` drops an
/// identifier that is not parseable as an address.
fn ban_record(jail: &str, ban: &RestoredBan) -> Option<BanRecord> {
    let ip: IpAddr = ban.ip.parse().ok()?;
    let expires_at = (ban.ban_time >= 0.0).then_some((ban.time_of_ban + ban.ban_time) as i64);
    Some(BanRecord {
        ip,
        jail_id: jail.to_owned(),
        banned_at: ban.time_of_ban as i64,
        expires_at,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::float_cmp,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
#[path = "legacy_sqlite_test.rs"]
mod tests;
