//! Read original Fail2Ban 1.1.1 ban state directly from its SQLite database.
//!
//! Startup-only migration slice: the database is opened read-only and only
//! the `bips` table (bans in progress) is decoded. Fail2Ban keeps this
//! database continuously updated; writing it back is a later stage, so the
//! WAL remains the daemon's live store after the upgrade seed.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use tracing::{info, warn};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::track::legacy_restore::{self, LegacyBanRow, RestoreRequest, RestoredBan};
use crate::track::state::BanRecord;

/// Restored bans for all compat jails from the original SQLite database.
///
/// Called only for compatibility-tree startups. The database is never created
/// or modified; a missing file or missing `bips` table seeds nothing and only
/// logs.
pub(crate) fn restore_bans(dbfile: &Path, config: &Config) -> Result<Vec<BanRecord>> {
    if !dbfile.is_file() {
        info!(
            phase = "startup",
            dbfile = %dbfile.display(),
            "no original ban database to restore"
        );
        return Ok(Vec::new());
    }
    let rows = read_bips(dbfile)?;
    if rows.is_empty() {
        info!(
            phase = "startup",
            "original ban database has no current bans"
        );
        return Ok(Vec::new());
    }
    let now = chrono::Utc::now().timestamp() as f64;
    let mut restored = Vec::new();
    for (name, jail) in config.enabled_jails() {
        let request = RestoreRequest {
            jail: name,
            now,
            // Original restoreCurrentBans without increment uses the jail's
            // ban time as the search window; the -1 permanent sentinel and
            // the -2 unknown legacy sentinel disable it.
            age_window: (jail.ban_time >= 0).then_some(jail.ban_time as f64),
            base_ban_time: jail.ban_time as f64,
            max_ban_time: (jail.ban_time >= 0).then_some(jail.ban_time as f64),
            // The failure-match history inside ticket data is decoded but
            // not re-seeded into the live counters yet.
            max_matches: 0,
        };
        for ban in legacy_restore::restore_current(&rows, &request).map_err(|err| {
            Error::config(format!("original ban database for jail {name:?}: {err}"))
        })? {
            if let Some(record) = ban_record(name, &ban) {
                restored.push(record);
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
    info!(
        phase = "startup",
        bans = restored.len(),
        "bans restored from the original Fail2Ban database"
    );
    Ok(restored)
}

/// Every `bips` row, decoded; the JSON ticket data is left as raw text here.
fn read_bips(dbfile: &Path) -> Result<Vec<LegacyBanRow>> {
    let connection = Connection::open_with_flags(
        dbfile,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| {
        Error::config(format!(
            "opening original ban database {}: {err}",
            dbfile.display()
        ))
    })?;
    let mut statement = match connection.prepare(
        "SELECT ip, jail, CAST(timeofban AS REAL), CAST(bantime AS REAL), \
         bancount, data FROM bips",
    ) {
        Ok(statement) => statement,
        Err(err) if is_missing_table(&err) => {
            info!(phase = "startup", "original ban database has no bips table");
            return Ok(Vec::new());
        }
        Err(err) => {
            return Err(Error::config(format!(
                "reading bips from {}: {err}",
                dbfile.display()
            )));
        }
    };
    let mut rows: Vec<(String, String, f64, f64, i64, Option<String>)> = Vec::new();
    let queried = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })
        .map_err(|err| Error::config(format!("reading bips from {}: {err}", dbfile.display())))?;
    for row in queried {
        rows.push(row.map_err(|err| {
            Error::config(format!(
                "decoding a bips row from {}: {err}",
                dbfile.display()
            ))
        })?);
    }
    rows.into_iter()
        .map(|(ip, jail, time_of_ban, ban_time, ban_count, data)| {
            let data = data
                .map(|text| serde_json::from_str(&text))
                .transpose()
                .map_err(|err| Error::config(format!("bips ticket data of {ip:?}: {err}")))?;
            Ok(LegacyBanRow {
                jail,
                ip,
                time_of_ban,
                ban_time,
                ban_count,
                data,
            })
        })
        .collect()
}

/// The SQLite message for an absent table.
fn is_missing_table(err: &rusqlite::Error) -> bool {
    err.to_string().contains("no such table:") && err.to_string().contains("bips")
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

/// Compatibility startups merge original-database bans into the WAL state.
///
/// The WAL is authoritative for a pair already in it (a later restart of this
/// daemon refreshes the original row otherwise); original rows for jails the
/// compat config does not enable are ignored upstream, exactly like the
/// original restore pass.
pub(crate) fn merge_with_wal(restored: Vec<BanRecord>, extra: Vec<BanRecord>) -> Vec<BanRecord> {
    let wal_keys: HashSet<(IpAddr, String)> = restored
        .iter()
        .map(|record| (record.ip, record.jail_id.clone()))
        .collect();
    restored
        .into_iter()
        .chain(
            extra
                .into_iter()
                .filter(|record| !wal_keys.contains(&(record.ip, record.jail_id.clone()))),
        )
        .collect()
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
