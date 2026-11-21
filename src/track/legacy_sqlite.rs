//! Read original Fail2Ban 1.1.1 ban state directly from its SQLite database.
//!
//! Startup-only migration slice: the database is opened read-only and only
//! the `bips` table (bans in progress) is decoded. Fail2Ban keeps this
//! database continuously updated; writing it back is a later stage, so the
//! WAL remains the daemon's live store after the upgrade seed.

use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::Value;
use tracing::{info, warn};

use crate::config::Config;
use crate::detect::ignore::IgnoreList;
use crate::error::{Error, Result};
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
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'bips' COLLATE NOCASE)",
        [],
        |row| row.get(0),
    )
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
