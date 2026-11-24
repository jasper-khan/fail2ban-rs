//! Fail2Ban 1.1.1 SQLite v4 persistent database (`Fail2BanDb`).
//!
//! Mirrors `fail2ban/server/database.py`, including v1-v3 -> v4 schema
//! migration, log position checkpoints, active `bips`, historical `bans`,
//! merged IP failure/match queries, and periodic purging.

use std::collections::VecDeque;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
};

use crate::error::{Error, Result};
use crate::protocol::PickleValue;
use crate::ticket::{Ticket, TicketId};

/// Default purge age in seconds (24 hours), matching upstream Fail2Ban 1.1.1.
pub const DEFAULT_PURGE_AGE: i64 = 86_400;
/// Default maximum matched log lines stored per ticket in SQLite `data` JSON.
pub const DEFAULT_MAX_MATCHES: usize = 10;
const OUTDATED_FACTOR: i64 = 3;

const SCHEMA_V4_DDL: &str = concat!(
    "CREATE TABLE IF NOT EXISTS fail2banDb(version INTEGER);",
    "CREATE TABLE IF NOT EXISTS jails(",
    "name TEXT NOT NULL UNIQUE, ",
    "enabled INTEGER NOT NULL DEFAULT 1",
    ");",
    "CREATE INDEX IF NOT EXISTS jails_name ON jails(name);",
    "CREATE TABLE IF NOT EXISTS logs(",
    "jail TEXT NOT NULL, ",
    "path TEXT, ",
    "firstlinemd5 TEXT, ",
    "lastfilepos INTEGER DEFAULT 0, ",
    "FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE, ",
    "UNIQUE(jail, path), ",
    "UNIQUE(jail, path, firstlinemd5)",
    ");",
    "CREATE INDEX IF NOT EXISTS logs_path ON logs(path);",
    "CREATE INDEX IF NOT EXISTS logs_jail_path ON logs(jail, path);",
    "CREATE TABLE IF NOT EXISTS bans(",
    "jail TEXT NOT NULL, ",
    "ip TEXT, ",
    "timeofban INTEGER NOT NULL, ",
    "bantime INTEGER NOT NULL, ",
    "bancount INTEGER NOT NULL default 1, ",
    "data JSON, ",
    "FOREIGN KEY(jail) REFERENCES jails(name)",
    ");",
    "CREATE INDEX IF NOT EXISTS bans_jail_timeofban_ip ON bans(jail, timeofban);",
    "CREATE INDEX IF NOT EXISTS bans_jail_ip ON bans(jail, ip);",
    "CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip);",
    "CREATE TABLE IF NOT EXISTS bips(",
    "ip TEXT NOT NULL, ",
    "jail TEXT NOT NULL, ",
    "timeofban INTEGER NOT NULL, ",
    "bantime INTEGER NOT NULL, ",
    "bancount INTEGER NOT NULL default 1, ",
    "data JSON, ",
    "PRIMARY KEY(ip, jail), ",
    "FOREIGN KEY(jail) REFERENCES jails(name)",
    ");",
    "CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);",
    "CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);",
);

const UPSERT_JAIL: &str = "INSERT INTO jails(name, enabled) VALUES(?1, 1)
    ON CONFLICT(name) DO UPDATE SET enabled = 1";
const ENSURE_JAIL: &str = "INSERT OR IGNORE INTO jails(name, enabled) VALUES(?1, 1)";
const UPSERT_LOG: &str = "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos)
    VALUES(?1, ?2, ?3, ?4)
    ON CONFLICT(jail, path) DO UPDATE SET
        firstlinemd5 = excluded.firstlinemd5,
        lastfilepos = excluded.lastfilepos";
const UPSERT_BIP: &str = "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data)
    VALUES(?1, ?2, ?3, ?4, ?5, ?6)
    ON CONFLICT(ip, jail) DO UPDATE SET
        timeofban = excluded.timeofban,
        bantime = excluded.bantime,
        bancount = excluded.bancount,
        data = excluded.data";
const INSERT_BAN: &str =
    "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, ?5, ?6)";

/// Result of executing one bridged SQLite statement for a `:memory:` Python action database.
pub(crate) struct BridgeSqlResult {
    pub(crate) rows: Vec<Vec<PickleValue>>,
    pub(crate) json_cols: Vec<bool>,
    pub(crate) rowcount: i64,
}

/// Lock-free view of mutable database settings (`purge_age`, `max_matches`) so
/// Python action lifecycle commands never block on an active `:memory:` transaction.
#[derive(Debug)]
pub(crate) struct DbMetadata {
    purge_age: AtomicI64,
    max_matches: AtomicUsize,
}

impl DbMetadata {
    fn new(purge_age: i64, max_matches: usize) -> Self {
        Self {
            purge_age: AtomicI64::new(purge_age),
            max_matches: AtomicUsize::new(max_matches),
        }
    }

    pub(crate) fn purge_age(&self) -> i64 {
        self.purge_age.load(Ordering::Relaxed)
    }

    pub(crate) fn max_matches(&self) -> usize {
        self.max_matches.load(Ordering::Relaxed)
    }
}

/// Thread-safe handle to Fail2Ban 1.1.1's v4 SQLite persistent database.
pub struct Fail2BanDb {
    filename: String,
    purge_age: i64,
    max_matches: usize,
    meta: Arc<DbMetadata>,
    conn: Mutex<Connection>,
}

impl fmt::Debug for Fail2BanDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fail2BanDb")
            .field("filename", &self.filename)
            .field("purge_age", &self.purge_age)
            .field("max_matches", &self.max_matches)
            .finish_non_exhaustive()
    }
}

impl Fail2BanDb {
    /// Open or create a Fail2Ban v4 SQLite database, returning `Ok(None)` when `path` is `"None"`.
    pub fn open_optional(path: &str, purge_age: i64, max_matches: usize) -> Result<Option<Self>> {
        if path.trim().eq_ignore_ascii_case("none") {
            return Ok(None);
        }
        Self::open(path, purge_age, max_matches).map(Some)
    }

    /// Open or create a Fail2Ban v4 SQLite database (`":memory:"` or filesystem path).
    pub fn open(path: &str, purge_age: i64, max_matches: usize) -> Result<Self> {
        let trimmed = path.trim();
        if trimmed.eq_ignore_ascii_case("none") {
            return Err(Error::database("database is disabled (dbfile = None)"));
        }

        let mut conn = if trimmed == ":memory:" {
            Connection::open_in_memory()
                .map_err(|e| sql_error("opening in-memory Fail2Ban SQLite", &e))?
        } else {
            let fs_path = Path::new(trimmed);
            if let Some(parent) = fs_path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::io(
                        format!("creating parent directory for {}", fs_path.display()),
                        e,
                    )
                })?;
            }
            Connection::open(fs_path)
                .map_err(|e| sql_error(&format!("opening Fail2Ban SQLite {trimmed}"), &e))?
        };

        conn.busy_timeout(Duration::from_millis(5000))
            .map_err(|e| sql_error("setting busy_timeout", &e))?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(|e| sql_error("enabling foreign keys", &e))?;

        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| sql_error("beginning schema initialization", &e))?;
            let has_objects: bool = tx
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*')",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| sql_error("inspecting schema", &e))?;
            if !has_objects {
                tx.execute_batch(SCHEMA_V4_DDL)
                    .map_err(|e| sql_error("creating v4 schema", &e))?;
                tx.execute("INSERT INTO fail2banDb(version) VALUES(4)", [])
                    .map_err(|e| sql_error("inserting schema version", &e))?;
            } else {
                upgrade_legacy_schema_to_v4(&tx, trimmed)?;
            }
            validate_v4(&tx)?;
            tx.commit()
                .map_err(|e| sql_error("committing schema transaction", &e))?;
        }

        Ok(Self {
            filename: trimmed.to_owned(),
            purge_age,
            max_matches,
            meta: Arc::new(DbMetadata::new(purge_age, max_matches)),
            conn: Mutex::new(conn),
        })
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn purge_age(&self) -> i64 {
        self.purge_age
    }

    pub fn set_purge_age(&mut self, secs: i64) {
        self.purge_age = secs;
        self.meta.purge_age.store(secs, Ordering::Relaxed);
    }

    pub fn max_matches(&self) -> usize {
        self.max_matches
    }

    pub fn set_max_matches(&mut self, n: usize) {
        self.max_matches = n;
        self.meta.max_matches.store(n, Ordering::Relaxed);
    }

    pub(crate) fn metadata(&self) -> Arc<DbMetadata> {
        Arc::clone(&self.meta)
    }

    /// Register or re-enable a jail in the `jails` table.
    pub fn add_jail(&self, jail: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(UPSERT_JAIL, params![jail])
            .map_err(|e| sql_error("adding jail", &e))?;
        Ok(())
    }

    /// Mark a jail disabled (`enabled = 0`), matching upstream `Fail2BanDb.delJail`.
    pub fn del_jail(&self, jail: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE jails SET enabled = 0 WHERE name = ?1",
            params![jail],
        )
        .map_err(|e| sql_error("disabling jail", &e))?;
        Ok(())
    }

    /// Mark all jails disabled (`enabled = 0`), matching upstream `Fail2BanDb.delAllJails`.
    pub fn del_all_jails(&self) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("UPDATE jails SET enabled = 0", [])
            .map_err(|e| sql_error("disabling all jails", &e))?;
        Ok(())
    }

    /// Return jail names optionally filtered by `enabled` status.
    pub fn get_jail_names(&self, enabled: Option<bool>) -> Result<Vec<String>> {
        let conn = self.lock_conn()?;
        let mut names = Vec::new();
        match enabled {
            None => {
                let mut stmt = conn
                    .prepare("SELECT name FROM jails ORDER BY name")
                    .map_err(|e| sql_error("preparing get_jail_names", &e))?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| sql_error("querying jail names", &e))?;
                for row in rows {
                    names.push(row.map_err(|e| sql_error("reading jail name", &e))?);
                }
            }
            Some(en) => {
                let mut stmt = conn
                    .prepare("SELECT name FROM jails WHERE enabled = ?1 ORDER BY name")
                    .map_err(|e| sql_error("preparing get_jail_names", &e))?;
                let rows = stmt
                    .query_map(params![i64::from(en)], |row| row.get::<_, String>(0))
                    .map_err(|e| sql_error("querying jail names", &e))?;
                for row in rows {
                    names.push(row.map_err(|e| sql_error("reading jail name", &e))?);
                }
            }
        }
        Ok(names)
    }

    /// Register or check a log file checkpoint.
    ///
    /// Returns `Some(lastfilepos)` if `(jail, path)` exists and `first_line_hash` matches
    /// the stored `firstlinemd5`. Otherwise inserts/updates the row with offset 0 and returns `None`.
    pub fn add_log(&self, jail: &str, path: &str, first_line_hash: &str) -> Result<Option<u64>> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning add_log transaction", &e))?;
        tx.execute(ENSURE_JAIL, params![jail])
            .map_err(|e| sql_error("ensuring jail for log", &e))?;

        let existing: Option<(Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT firstlinemd5, lastfilepos FROM logs WHERE jail = ?1 AND path = ?2",
                params![jail, path],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| sql_error("reading log checkpoint", &e))?;

        if let Some((stored_hash, stored_pos)) = existing
            && stored_hash.as_deref() == Some(first_line_hash)
        {
            tx.commit()
                .map_err(|e| sql_error("committing add_log read", &e))?;
            return Ok(stored_pos.and_then(|pos| u64::try_from(pos).ok()));
        }

        tx.execute(UPSERT_LOG, params![jail, path, first_line_hash, 0_i64])
            .map_err(|e| sql_error("upserting log checkpoint", &e))?;
        tx.commit()
            .map_err(|e| sql_error("committing add_log", &e))?;
        Ok(None)
    }

    /// Update the stored `firstlinemd5` and `lastfilepos` for `(jail, path)`.
    pub fn update_log(
        &self,
        jail: &str,
        path: &str,
        first_line_hash: &str,
        offset: u64,
    ) -> Result<()> {
        let offset_i64 = i64::try_from(offset)
            .map_err(|_| Error::database("log offset exceeds signed 64-bit range"))?;
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning update_log transaction", &e))?;
        tx.execute(ENSURE_JAIL, params![jail])
            .map_err(|e| sql_error("ensuring jail for log update", &e))?;
        tx.execute(UPSERT_LOG, params![jail, path, first_line_hash, offset_i64])
            .map_err(|e| sql_error("updating log checkpoint", &e))?;
        tx.commit()
            .map_err(|e| sql_error("committing update_log", &e))?;
        Ok(())
    }

    /// Read the stored systemd journal timestamp from `logs` (`database.py:getJournalPos`).
    pub fn get_journal_pos(&self, jail: &str, name: &str) -> Result<Option<f64>> {
        let conn = self.lock_conn()?;
        let row: Option<Option<f64>> = conn
            .query_row(
                "SELECT lastfilepos FROM logs WHERE jail = ?1 AND path = ?2",
                params![jail, name],
                |r| {
                    let v = match r.get_ref(0)? {
                        ValueRef::Real(f) => Some(f),
                        ValueRef::Integer(i) => Some(i as f64),
                        _ => None,
                    };
                    Ok(v)
                },
            )
            .optional()
            .map_err(|e| sql_error("reading journal position", &e))?;
        Ok(row.flatten())
    }

    /// Persist the latest systemd journal timestamp and ISO label in `logs` (`database.py:updateJournal`).
    pub fn update_journal(&self, jail: &str, name: &str, ts: f64, iso: &str) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning update_journal transaction", &e))?;
        tx.execute(ENSURE_JAIL, params![jail])
            .map_err(|e| sql_error("ensuring jail for journal update", &e))?;
        tx.execute(UPSERT_LOG, params![jail, name, iso, ts])
            .map_err(|e| sql_error("updating journal position", &e))?;
        tx.commit()
            .map_err(|e| sql_error("committing update_journal", &e))?;
        Ok(())
    }

    /// Return `(path, firstlinemd5, lastfilepos)` checkpoints recorded for `jail`.
    pub fn get_logs(&self, jail: &str) -> Result<Vec<(String, String, u64)>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT path, COALESCE(firstlinemd5, ''), COALESCE(lastfilepos, 0)
                 FROM logs
                 WHERE jail = ?1 AND path IS NOT NULL
                 ORDER BY path",
            )
            .map_err(|e| sql_error("preparing get_logs", &e))?;
        let rows = stmt
            .query_map(params![jail], |row| {
                let path: String = row.get(0)?;
                let hash: String = row.get(1)?;
                let pos = match row.get_ref(2)? {
                    ValueRef::Integer(i) => u64::try_from(i).unwrap_or(0),
                    ValueRef::Real(f) if f >= 0.0 => f as u64,
                    _ => 0,
                };
                Ok((path, hash, pos))
            })
            .map_err(|e| sql_error("querying logs", &e))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| sql_error("reading log row", &e))?);
        }
        Ok(out)
    }

    /// Record a ban in both `bans` (history) and `bips` (active/bad IPs).
    pub fn add_ban(&self, jail: &str, ticket: &Ticket, default_ban_time: i64) -> Result<()> {
        let ip = ticket.fid.to_string();
        let timeofban = ticket.time.round_ties_even() as i64;
        let bantime = ticket.effective_ban_time(default_ban_time);
        let bancount = i64::try_from(ticket.ban_count).unwrap_or(i64::MAX);
        let data = ticket.to_db_json(self.max_matches);

        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning add_ban transaction", &e))?;
        tx.execute(ENSURE_JAIL, params![jail])
            .map_err(|e| sql_error("ensuring jail for add_ban", &e))?;
        tx.execute(
            INSERT_BAN,
            params![jail, &ip, timeofban, bantime, bancount, data.as_slice()],
        )
        .map_err(|e| sql_error("inserting ban history", &e))?;
        tx.execute(
            UPSERT_BIP,
            params![&ip, jail, timeofban, bantime, bancount, data.as_slice()],
        )
        .map_err(|e| sql_error("upserting active bip", &e))?;
        tx.commit()
            .map_err(|e| sql_error("committing add_ban", &e))?;
        Ok(())
    }

    /// Remove ban entries (or all entries for `jail`) from both `bips` and `bans`,
    /// matching upstream `Fail2BanDb.delBan`.
    pub fn del_ban(&self, jail: &str, id: Option<&TicketId>) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning del_ban transaction", &e))?;
        match id {
            Some(tid) => {
                let ip = tid.to_string();
                tx.execute(
                    "DELETE FROM bips WHERE jail = ?1 AND ip = ?2",
                    params![jail, &ip],
                )
                .map_err(|e| sql_error("deleting active ban", &e))?;
                tx.execute(
                    "DELETE FROM bans WHERE jail = ?1 AND ip = ?2",
                    params![jail, &ip],
                )
                .map_err(|e| sql_error("deleting ban history", &e))?;
            }
            None => {
                tx.execute("DELETE FROM bips WHERE jail = ?1", params![jail])
                    .map_err(|e| sql_error("deleting all active bans for jail", &e))?;
                tx.execute("DELETE FROM bans WHERE jail = ?1", params![jail])
                    .map_err(|e| sql_error("deleting all ban history for jail", &e))?;
            }
        }
        tx.commit()
            .map_err(|e| sql_error("committing del_ban", &e))?;
        Ok(())
    }

    /// Query `(bancount, timeofban, bantime)` from `bips` for `bantime.increment` and `failureFound`.
    pub fn get_ban(
        &self,
        id: &TicketId,
        jail: Option<&str>,
        overall_jails: bool,
    ) -> Result<Option<(u64, i64, i64)>> {
        let ip = id.to_string();
        let conn = self.lock_conn()?;
        let row: Option<(i64, i64, i64)> = if overall_jails {
            conn.query_row(
                "SELECT sum(bancount), max(timeofban), sum(bantime)
                 FROM bips
                 WHERE ip = ?1
                 GROUP BY ip",
                params![ip],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| sql_error("querying overall_jails ban", &e))?
        } else if let Some(j) = jail {
            conn.query_row(
                "SELECT bancount, timeofban, bantime
                 FROM bips
                 WHERE ip = ?1 AND jail = ?2",
                params![ip, j],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| sql_error("querying jail ban", &e))?
        } else {
            conn.query_row(
                "SELECT bancount, timeofban, bantime
                 FROM bips
                 WHERE ip = ?1
                 ORDER BY timeofban DESC
                 LIMIT 1",
                params![ip],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| sql_error("querying latest ban", &e))?
        };
        Ok(row.map(|(cnt, tob, bt)| (u64::try_from(cnt).unwrap_or(0), tob, bt)))
    }

    /// Restore currently active or permanent bans from `bips`.
    pub fn get_current_bans(
        &self,
        jail: Option<&str>,
        forbantime: Option<i64>,
        correct_ban_time: Option<i64>,
        now: i64,
    ) -> Result<Vec<Ticket>> {
        self.get_current_bans_with_base(jail, forbantime, correct_ban_time, forbantime, now)
    }

    /// Restore currently active or permanent bans from `bips`, passing the jail's
    /// base `bantime` (for legacy `bantime = -2` rows) and `correct_ban_time` cap independently.
    pub fn get_current_bans_with_base(
        &self,
        jail: Option<&str>,
        forbantime: Option<i64>,
        correct_ban_time: Option<i64>,
        base_ban_time: Option<i64>,
        now: i64,
    ) -> Result<Vec<Ticket>> {
        let min_timeofban = forbantime
            .filter(|&fb| fb != -1)
            .map(|fb| now.saturating_sub(fb));
        let cap = correct_ban_time.filter(|&c| c >= 0);

        let conn = self.lock_conn()?;
        let sql = if jail.is_some() {
            "SELECT ip, timeofban, bantime, bancount, data
             FROM bips
             WHERE jail = ?1
               AND ip IS NOT NULL AND ip <> ''
               AND (timeofban + bantime > ?2 OR bantime <= -1)
               AND (?3 IS NULL OR timeofban > ?3)
             ORDER BY ip, timeofban DESC"
        } else {
            "SELECT ip, max(timeofban), bantime, bancount, data
             FROM bips
             WHERE ip IS NOT NULL AND ip <> ''
               AND (timeofban + bantime > ?1 OR bantime <= -1)
               AND (?2 IS NULL OR timeofban > ?2)
             GROUP BY ip
             ORDER BY ip, timeofban DESC"
        };

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| sql_error("preparing get_current_bans", &e))?;

        let mut tickets = Vec::new();
        type BanRow = (String, i64, i64, i64, Option<Vec<u8>>);
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<BanRow> {
            let ip: String = row.get(0)?;
            let timeofban: i64 = row.get(1)?;
            let bantime: i64 = row.get(2)?;
            let bancount: i64 = row.get(3)?;
            let data = match row.get_ref(4)? {
                ValueRef::Blob(b) | ValueRef::Text(b) => Some(b.to_vec()),
                _ => None,
            };
            Ok((ip, timeofban, bantime, bancount, data))
        };

        let rows = if let Some(j) = jail {
            stmt.query_map(params![j, now, min_timeofban], mapper)
        } else {
            stmt.query_map(params![now, min_timeofban], mapper)
        }
        .map_err(|e| sql_error("querying current bans", &e))?;

        for row_res in rows {
            let (ip_str, timeofban, raw_bantime, bancount, data_bytes) =
                row_res.map_err(|e| sql_error("reading current ban row", &e))?;
            if ip_str.is_empty() {
                continue;
            }
            let bantime = if raw_bantime == -2 {
                base_ban_time.or(cap).unwrap_or(600)
            } else if let Some(max_bt) = cap
                && (raw_bantime == -1 || raw_bantime > max_bt)
            {
                max_bt
            } else {
                raw_bantime
            };
            if bantime != -1 && timeofban.saturating_add(bantime) <= now {
                continue;
            }

            let mut ticket = Ticket::new(TicketId::parse(&ip_str), timeofban as f64);
            ticket.restored = true;
            ticket.ban_time = Some(bantime);
            ticket.ban_count = u64::try_from(bancount).unwrap_or(0);
            ticket.attempts = 0;
            if let Some(bytes) = data_bytes.as_deref() {
                ticket.apply_db_json(bytes);
                apply_nested_matches_fallback(&mut ticket, bytes);
            }
            if self.max_matches == 0 {
                ticket.matches.clear();
            } else if ticket.matches.len() > self.max_matches {
                let excess = ticket.matches.len() - self.max_matches;
                ticket.matches.drain(..excess);
            }
            tickets.push(ticket);
        }

        Ok(tickets)
    }

    /// Aggregate total historical failure count and recent matched lines from `bans`
    /// for `<ipfailures>`, `<ipmatches>`, `<ipjailfailures>`, and `<ipjailmatches>`.
    pub fn get_bans_merged(&self, id: &TicketId, jail: Option<&str>) -> Result<(u64, Vec<String>)> {
        let ip = id.to_string();
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT data FROM bans
                 WHERE ip = ?1 AND (?2 IS NULL OR jail = ?2)
                 ORDER BY timeofban DESC, rowid DESC",
            )
            .map_err(|e| sql_error("preparing get_bans_merged", &e))?;

        let rows = stmt
            .query_map(params![ip, jail], |row| {
                Ok(match row.get_ref(0)? {
                    ValueRef::Blob(b) | ValueRef::Text(b) => Some(b.to_vec()),
                    _ => None,
                })
            })
            .map_err(|e| sql_error("querying merged bans", &e))?;

        let mut total_failures: u64 = 0;
        let mut matches_rev = VecDeque::new();

        for row_res in rows {
            let data_bytes = row_res.map_err(|e| sql_error("reading merged ban row", &e))?;
            let (failures, row_matches) = parse_ban_data_summary(data_bytes.as_deref());
            total_failures = total_failures.saturating_add(failures);

            let remaining = self.max_matches.saturating_sub(matches_rev.len());
            if remaining > 0 && !row_matches.is_empty() {
                let start = row_matches.len().saturating_sub(remaining);
                for line in row_matches[start..].iter().rev() {
                    matches_rev.push_front(line.clone());
                }
            }
        }

        Ok((total_failures, matches_rev.into()))
    }

    /// Purge expired rows older than `now - purge_age` from `bans` and `bips`,
    /// preserving active/permanent `-1` rows in `bips`, and remove orphaned disabled jails.
    pub fn purge(&self, now: i64) -> Result<usize> {
        let cutoff = now.saturating_sub(self.purge_age);
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning purge transaction", &e))?;
        let del_bans = tx
            .execute("DELETE FROM bans WHERE timeofban < ?1", params![cutoff])
            .map_err(|e| sql_error("purging bans", &e))?;
        let del_bips = tx
            .execute(
                "DELETE FROM bips
                 WHERE timeofban < ?1
                   AND bantime != -1
                   AND (timeofban + (bantime * ?2)) < ?1",
                params![cutoff, OUTDATED_FACTOR],
            )
            .map_err(|e| sql_error("purging bips", &e))?;
        tx.execute(
            "DELETE FROM jails
             WHERE enabled = 0
               AND NOT EXISTS(SELECT 1 FROM bans WHERE jail = jails.name)
               AND NOT EXISTS(SELECT 1 FROM bips WHERE jail = jails.name)",
            [],
        )
        .map_err(|e| sql_error("cleaning disabled jails", &e))?;
        tx.commit().map_err(|e| sql_error("committing purge", &e))?;
        Ok(del_bans + del_bips)
    }

    /// Run a Python `:memory:` bridge transaction under the SQLite connection lock.
    /// Commits iff `f` returns `true`; otherwise drops the transaction to roll back.
    pub(crate) fn with_bridge_transaction<F>(&self, f: F) -> std::result::Result<(), String>
    where
        F: FnOnce(&Transaction<'_>) -> bool,
    {
        let mut conn = self.lock_conn().map_err(|e| e.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        if f(&tx) {
            tx.commit().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn execute_bridge_sql(
        &self,
        sql: &str,
        params: &[PickleValue],
    ) -> std::result::Result<BridgeSqlResult, String> {
        let conn = self.lock_conn().map_err(|e| e.to_string())?;
        Self::execute_bridge_sql_on(&conn, sql, params)
    }

    pub(crate) fn execute_bridge_sql_on(
        conn: &Connection,
        sql: &str,
        params: &[PickleValue],
    ) -> std::result::Result<BridgeSqlResult, String> {
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let bound: Vec<SqlValue> = params
            .iter()
            .map(|v| match v {
                PickleValue::None => SqlValue::Null,
                PickleValue::Bool(b) => SqlValue::Integer(i64::from(*b)),
                PickleValue::Int(i) => SqlValue::Integer(*i),
                PickleValue::Float(f) => SqlValue::Real(*f),
                PickleValue::Str(s) => SqlValue::Text(s.clone()),
                PickleValue::Bytes(b) => SqlValue::Blob(b.clone()),
                other => SqlValue::Text(other.to_string_lossy()),
            })
            .collect();
        let col_count = stmt.column_count();
        if col_count == 0 {
            let changed = stmt
                .execute(params_from_iter(bound))
                .map_err(|e| e.to_string())?;
            return Ok(BridgeSqlResult {
                rows: Vec::new(),
                json_cols: Vec::new(),
                rowcount: changed as i64,
            });
        }
        // Fail2Ban v4 schema uses column name `data` for every JSON column (`bans.data`, `bips.data`).
        let json_cols: Vec<bool> = (0..col_count)
            .map(|i| stmt.column_name(i) == Ok("data"))
            .collect();
        let mut rows_out = Vec::new();
        let mut rows = stmt
            .query(params_from_iter(bound))
            .map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let mut vals = Vec::with_capacity(col_count);
            for idx in 0..col_count {
                let cell = match row.get_ref(idx).map_err(|e| e.to_string())? {
                    ValueRef::Null => PickleValue::None,
                    ValueRef::Integer(i) => PickleValue::Int(i),
                    ValueRef::Real(f) => PickleValue::Float(f),
                    ValueRef::Text(b) => PickleValue::Str(String::from_utf8_lossy(b).into_owned()),
                    ValueRef::Blob(b) => PickleValue::Bytes(b.to_vec()),
                };
                vals.push(cell);
            }
            rows_out.push(vals);
        }
        Ok(BridgeSqlResult {
            rows: rows_out,
            json_cols,
            rowcount: -1,
        })
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::database("SQLite connection mutex poisoned"))
    }
}

fn apply_nested_matches_fallback(ticket: &mut Ticket, raw: &[u8]) {
    if !ticket.matches.is_empty() {
        return;
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(raw)
    else {
        return;
    };
    if let Some(serde_json::Value::Array(arr)) = map.get("matches") {
        ticket.matches = extract_match_lines(arr);
    }
}

fn parse_ban_data_summary(raw: Option<&[u8]>) -> (u64, Vec<String>) {
    let Some(bytes) = raw else {
        return (1, Vec::new());
    };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(bytes)
    else {
        return (1, Vec::new());
    };
    let failures = map
        .get("failures")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let matches = map
        .get("matches")
        .and_then(serde_json::Value::as_array)
        .map(|arr| extract_match_lines(arr))
        .unwrap_or_default();
    (failures, matches)
}

fn extract_match_lines(arr: &[serde_json::Value]) -> Vec<String> {
    arr.iter()
        .filter_map(|item| match item {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(parts) => {
                let mut joined = String::new();
                for part in parts {
                    joined.push_str(part.as_str()?);
                }
                Some(joined)
            }
            _ => None,
        })
        .collect()
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get(0),
    )
    .map_err(|e| sql_error("checking table existence", &e))
}

fn upgrade_legacy_schema_to_v4(conn: &Connection, db_path: &str) -> Result<()> {
    if !table_exists(conn, "fail2banDb")?
        || !table_exists(conn, "jails")?
        || !table_exists(conn, "logs")?
        || !table_exists(conn, "bans")?
    {
        return Ok(());
    }
    let version: Option<i64> = conn
        .query_row("SELECT version FROM fail2banDb LIMIT 1", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| sql_error("reading fail2banDb version", &e))?;
    let Some(version) = version else {
        return Ok(());
    };
    if version > 4 {
        return Err(Error::database(format!(
            "unsupported Fail2Ban SQLite schema version {version} (expected <= 4)"
        )));
    }
    if version == 4 {
        return Ok(());
    }
    if version < 1 {
        return Err(Error::database(format!(
            "invalid Fail2Ban SQLite schema version {version}"
        )));
    }

    if db_path != ":memory:" {
        let p = Path::new(db_path);
        let backup = p.with_extension("sqlite3.bak");
        if p.is_file() && !backup.exists() {
            let _ = std::fs::copy(p, &backup);
        }
    }

    if version < 2 {
        conn.execute_batch(concat!(
            "CREATE TEMPORARY TABLE logs_temp AS SELECT * FROM logs;",
            "DROP TABLE logs;",
            "CREATE TABLE logs(",
            "jail TEXT NOT NULL, ",
            "path TEXT, ",
            "firstlinemd5 TEXT, ",
            "lastfilepos INTEGER DEFAULT 0, ",
            "FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE, ",
            "UNIQUE(jail, path), ",
            "UNIQUE(jail, path, firstlinemd5)",
            ");",
            "CREATE INDEX IF NOT EXISTS logs_path ON logs(path);",
            "CREATE INDEX IF NOT EXISTS logs_jail_path ON logs(jail, path);",
            "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) ",
            "SELECT jail, path, firstlinemd5, lastfilepos FROM logs_temp;",
            "DROP TABLE logs_temp;",
            "UPDATE fail2banDb SET version = 2;",
        ))
        .map_err(|e| sql_error("migrating Fail2Ban SQLite v1 -> v2", &e))?;
    }

    if version < 3 {
        conn.execute_batch(concat!(
            "CREATE TEMPORARY TABLE bans_temp AS ",
            "SELECT jail, ip, timeofban, -2 AS bantime, 1 AS bancount, data FROM bans;",
            "DROP TABLE bans;",
            "CREATE TABLE bans(",
            "jail TEXT NOT NULL, ",
            "ip TEXT, ",
            "timeofban INTEGER NOT NULL, ",
            "bantime INTEGER NOT NULL, ",
            "bancount INTEGER NOT NULL default 1, ",
            "data JSON, ",
            "FOREIGN KEY(jail) REFERENCES jails(name)",
            ");",
            "CREATE INDEX IF NOT EXISTS bans_jail_timeofban_ip ON bans(jail, timeofban);",
            "CREATE INDEX IF NOT EXISTS bans_jail_ip ON bans(jail, ip);",
            "CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip);",
            "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) ",
            "SELECT jail, ip, timeofban, bantime, bancount, data FROM bans_temp;",
            "DROP TABLE bans_temp;",
        ))
        .map_err(|e| sql_error("migrating Fail2Ban SQLite v2 -> v3", &e))?;
    }

    if !table_exists(conn, "bips")? {
        conn.execute_batch(concat!(
            "CREATE TABLE bips(",
            "ip TEXT NOT NULL, ",
            "jail TEXT NOT NULL, ",
            "timeofban INTEGER NOT NULL, ",
            "bantime INTEGER NOT NULL, ",
            "bancount INTEGER NOT NULL default 1, ",
            "data JSON, ",
            "PRIMARY KEY(ip, jail), ",
            "FOREIGN KEY(jail) REFERENCES jails(name)",
            ");",
            "CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);",
            "CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);",
        ))
        .map_err(|e| sql_error("creating bips during v4 migration", &e))?;
        conn.execute(
            "INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data)
             SELECT ip, jail, timeofban, bantime, bancount, data
             FROM bans
             WHERE ip IS NOT NULL AND jail IS NOT NULL
             ORDER BY timeofban",
            [],
        )
        .map_err(|e| sql_error("backfilling bips during v4 migration", &e))?;
    }

    conn.execute("UPDATE fail2banDb SET version = 4", [])
        .map_err(|e| sql_error("updating fail2banDb version to 4", &e))?;
    conn.execute_batch(SCHEMA_V4_DDL)
        .map_err(|e| sql_error("finalizing v4 schema", &e))?;
    Ok(())
}

fn validate_v4(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT version FROM fail2banDb LIMIT 2")
        .map_err(|e| sql_error("checking schema version", &e))?;
    let versions: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|e| sql_error("reading schema version", &e))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| sql_error("reading schema version", &e))?;
    if versions.as_slice() != [4] {
        return Err(Error::database(
            "Fail2Ban SQLite database must contain schema version 4",
        ));
    }
    for (table, probe) in [
        ("fail2banDb", "SELECT version FROM fail2banDb"),
        ("jails", UPSERT_JAIL),
        ("logs", UPSERT_LOG),
        ("bips", UPSERT_BIP),
        ("bans", INSERT_BAN),
    ] {
        if !table_exists(conn, table)? {
            return Err(Error::database(format!(
                "Fail2Ban SQLite v4 requires table {table:?}"
            )));
        }
        conn.prepare(probe)
            .map_err(|e| sql_error(&format!("validating table {table}"), &e))?;
    }
    Ok(())
}

fn sql_error(operation: &str, err: &rusqlite::Error) -> Error {
    Error::database(format!("{operation}: {err}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn id(s: &str) -> TicketId {
        TicketId::parse(s)
    }

    #[test]
    fn opens_in_memory_and_rejects_none() {
        assert!(Fail2BanDb::open("None", DEFAULT_PURGE_AGE, DEFAULT_MAX_MATCHES).is_err());
        assert!(
            Fail2BanDb::open_optional("none", DEFAULT_PURGE_AGE, DEFAULT_MAX_MATCHES)
                .unwrap()
                .is_none()
        );
        let mut db = Fail2BanDb::open(":memory:", DEFAULT_PURGE_AGE, DEFAULT_MAX_MATCHES).unwrap();
        assert_eq!(db.filename(), ":memory:");
        assert_eq!(db.purge_age(), 86_400);
        assert_eq!(db.max_matches(), 10);
        db.set_purge_age(3600);
        db.set_max_matches(25);
        assert_eq!(db.purge_age(), 3600);
        assert_eq!(db.max_matches(), 25);
    }

    #[test]
    fn jail_and_log_checkpoints_roundtrip_and_handle_rotation() {
        let db = Fail2BanDb::open(":memory:", 86_400, 10).unwrap();
        db.add_jail("sshd").unwrap();
        assert_eq!(db.get_jail_names(Some(true)).unwrap(), vec!["sshd"]);

        assert_eq!(
            db.add_log("sshd", "/var/log/auth.log", "hash1").unwrap(),
            None
        );
        db.update_log("sshd", "/var/log/auth.log", "hash1", 1024)
            .unwrap();
        assert_eq!(
            db.add_log("sshd", "/var/log/auth.log", "hash1").unwrap(),
            Some(1024)
        );
        // Hash mismatch indicates rotation: resets offset and returns None.
        assert_eq!(
            db.add_log("sshd", "/var/log/auth.log", "hash2").unwrap(),
            None
        );
        assert_eq!(
            db.get_logs("sshd").unwrap(),
            vec![("/var/log/auth.log".to_owned(), "hash2".to_owned(), 0)]
        );

        db.del_jail("sshd").unwrap();
        assert!(db.get_jail_names(Some(true)).unwrap().is_empty());
        assert_eq!(db.get_jail_names(Some(false)).unwrap(), vec!["sshd"]);
    }

    #[test]
    fn add_ban_del_ban_get_ban_and_get_bans_merged() {
        let mut db = Fail2BanDb::open(":memory:", 86_400, 2).unwrap();
        db.add_jail("sshd").unwrap();
        db.add_jail("nginx").unwrap();

        let ip = id("198.51.100.10");

        let mut t1 = Ticket::new(ip.clone(), 1000.0);
        t1.ban_count = 1;
        t1.attempts = 3;
        t1.matches = vec!["m1".into(), "m2".into()];
        t1.data.insert("user".into(), "alice".into());
        db.add_ban("sshd", &t1, 600).unwrap();

        let mut t2 = Ticket::new(ip.clone(), 2000.0);
        t2.ban_count = 2;
        t2.ban_time = Some(1200);
        t2.attempts = 4;
        t2.matches = vec!["m3".into()];
        db.add_ban("sshd", &t2, 600).unwrap();

        let mut t3 = Ticket::new(ip.clone(), 2500.0);
        t3.ban_count = 1;
        t3.ban_time = Some(900);
        t3.attempts = 5;
        t3.matches = vec!["m4".into()];
        db.add_ban("nginx", &t3, 600).unwrap();

        assert_eq!(
            db.get_ban(&ip, Some("sshd"), false).unwrap(),
            Some((2, 2000, 1200))
        );
        assert_eq!(
            db.get_ban(&ip, Some("nginx"), false).unwrap(),
            Some((1, 2500, 900))
        );
        assert_eq!(db.get_ban(&ip, None, true).unwrap(), Some((3, 2500, 2100)));

        let (all_failures, all_matches) = db.get_bans_merged(&ip, None).unwrap();
        assert_eq!(all_failures, 12);
        assert_eq!(all_matches, vec!["m3", "m4"]);

        let (sshd_failures, sshd_matches) = db.get_bans_merged(&ip, Some("sshd")).unwrap();
        assert_eq!(sshd_failures, 7);
        assert_eq!(sshd_matches, vec!["m2", "m3"]);

        db.set_max_matches(10);
        let (all_failures_10, all_matches_10) = db.get_bans_merged(&ip, None).unwrap();
        assert_eq!(all_failures_10, 12);
        assert_eq!(all_matches_10, vec!["m1", "m2", "m3", "m4"]);

        // del_ban removes from both bips and bans for the target jail while preserving other jails.
        db.del_ban("sshd", Some(&ip)).unwrap();
        assert_eq!(db.get_ban(&ip, Some("sshd"), false).unwrap(), None);
        assert_eq!(db.get_bans_merged(&ip, Some("sshd")).unwrap().0, 0);
        assert_eq!(db.get_bans_merged(&ip, Some("nginx")).unwrap().0, 5);
    }

    #[test]
    fn get_current_bans_and_purge_respect_permanent_and_caps() {
        let db = Fail2BanDb::open(":memory:", 86_400, 10).unwrap();
        db.add_jail("sshd").unwrap();

        let expired_ip = id("192.0.2.1");
        let active_ip = id("192.0.2.2");
        let perm_ip = id("192.0.2.3");

        let mut old = Ticket::new(expired_ip, 1000.0);
        old.ban_count = 1;
        old.ban_time = Some(600);
        db.add_ban("sshd", &old, 600).unwrap();

        let mut active = Ticket::new(active_ip.clone(), 100_000.0);
        active.ban_count = 2;
        active.ban_time = Some(3600);
        active.attempts = 4;
        active.matches = vec!["bad".into()];
        db.add_ban("sshd", &active, 600).unwrap();

        let mut perm = Ticket::new(perm_ip.clone(), 1000.0);
        perm.ban_count = 5;
        perm.ban_time = Some(-1);
        db.add_ban("sshd", &perm, 600).unwrap();

        // With cap=1800, permanent row from t=1000 expires at 2800 <= 100_500.
        let capped = db
            .get_current_bans(Some("sshd"), None, Some(1800), 100_500)
            .unwrap();
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].fid, active_ip);
        assert!(capped[0].restored);
        assert_eq!(capped[0].ban_time, Some(1800));
        assert_eq!(capped[0].ban_count, 2);
        assert_eq!(capped[0].attempts, 4);
        assert_eq!(capped[0].matches, vec!["bad"]);

        // Without cap (None), permanent row remains active.
        let uncapped = db
            .get_current_bans(Some("sshd"), None, None, 100_500)
            .unwrap();
        assert_eq!(uncapped.len(), 2);
        assert_eq!(uncapped[0].fid, active_ip);
        assert_eq!(uncapped[0].ban_time, Some(3600));
        assert_eq!(uncapped[1].fid, perm_ip);
        assert_eq!(uncapped[1].ban_time, Some(-1));

        // Purge at 100_500 with purge_age=86_400 (cutoff=14_100):
        // old row removed from bans & bips; perm removed from bans (old) but preserved in bips!
        let purged = db.purge(100_500).unwrap();
        assert!(purged >= 2);
        let after_purge = db
            .get_current_bans(Some("sshd"), None, None, 100_500)
            .unwrap();
        assert_eq!(after_purge.len(), 2);
        assert_eq!(after_purge[1].fid, perm_ip);

        // Disabled jail stays while bips still has active/permanent entry, then gets cleaned once unbanned.
        db.del_jail("sshd").unwrap();
        db.purge(100_500).unwrap();
        assert_eq!(db.get_jail_names(None).unwrap(), vec!["sshd"]);

        db.del_ban("sshd", None).unwrap();
        db.purge(200_000).unwrap();
        assert!(db.get_jail_names(None).unwrap().is_empty());
    }

    #[test]
    fn upgrades_v1_v2_v3_to_v4_and_rejects_unrelated_dbs() {
        let dir = tempfile::tempdir().unwrap();

        // 1. Unrelated DB is left untouched and rejected.
        let unrelated = dir.path().join("unrelated.sqlite3");
        {
            let conn = Connection::open(&unrelated).unwrap();
            conn.execute_batch("CREATE TABLE notes(body TEXT);")
                .unwrap();
        }
        assert!(Fail2BanDb::open(unrelated.to_str().unwrap(), 86_400, 10).is_err());

        // 2. v1 database upgrade -> v4 (creates .sqlite3.bak, upgrades logs + bans + bips).
        let v1_path = dir.path().join("v1.sqlite3");
        {
            let conn = Connection::open(&v1_path).unwrap();
            conn.execute_batch(concat!(
                "CREATE TABLE fail2banDb(version INTEGER);",
                "INSERT INTO fail2banDb(version) VALUES(1);",
                "CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);",
                "INSERT INTO jails(name, enabled) VALUES('sshd', 1);",
                "CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0);",
                "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('sshd', '/var/log/auth.log', 'h1', 42);",
                "CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, data JSON);",
                "INSERT INTO bans(jail, ip, timeofban, data) VALUES('sshd', '198.51.100.7', 1700000000, '{\"matches\":[\"bad\"]}');",
            ))
            .unwrap();
        }
        let db1 = Fail2BanDb::open(v1_path.to_str().unwrap(), 86_400, 10).unwrap();
        assert!(v1_path.with_extension("sqlite3.bak").is_file());
        assert_eq!(
            db1.add_log("sshd", "/var/log/auth.log", "h1").unwrap(),
            Some(42)
        );
        let restored = db1
            .get_current_bans(Some("sshd"), None, Some(600), 1_700_000_100)
            .unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].fid, id("198.51.100.7"));
        assert_eq!(restored[0].ban_time, Some(600));
        assert_eq!(restored[0].matches, vec!["bad"]);

        // 3. v3 database upgrade -> v4 (preserves bantime & bancount, backfills bips).
        let v3_path = dir.path().join("v3.sqlite3");
        {
            let conn = Connection::open(&v3_path).unwrap();
            conn.execute_batch(concat!(
                "CREATE TABLE fail2banDb(version INTEGER);",
                "INSERT INTO fail2banDb(version) VALUES(3);",
                "CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);",
                "INSERT INTO jails(name, enabled) VALUES('sshd', 1);",
                "CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0, UNIQUE(jail, path));",
                "CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, bancount INTEGER NOT NULL default 1, data JSON);",
                "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES('sshd', '192.0.2.55', 1700000000, 900, 3, '{\"failures\":4}');",
            ))
            .unwrap();
        }
        let db3 = Fail2BanDb::open(v3_path.to_str().unwrap(), 86_400, 10).unwrap();
        assert_eq!(
            db3.get_ban(&id("192.0.2.55"), Some("sshd"), false).unwrap(),
            Some((3, 1_700_000_000, 900))
        );

        // 4. systemd-journal position persistence matches Fail2BanDb.getJournalPos/updateJournal.
        assert_eq!(
            db3.get_journal_pos("sshd", "systemd-journal").unwrap(),
            None
        );
        db3.update_journal(
            "sshd",
            "systemd-journal",
            1_715_675_415.5,
            "2024-05-14T08:30:15.500000+00:00 ",
        )
        .unwrap();
        let jpos = db3
            .get_journal_pos("sshd", "systemd-journal")
            .unwrap()
            .unwrap();
        assert!((jpos - 1_715_675_415.5).abs() < 1e-6);
        assert!(
            db3.get_logs("sshd")
                .unwrap()
                .iter()
                .any(|(p, _, _)| p == "systemd-journal")
        );
    }
}
