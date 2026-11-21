//! Direct read-write persistence to Fail2Ban 1.1.1's v4 SQLite schema.
//!
//! Creates and updates the exact tables (`fail2banDb`, `jails`, `logs`, `bans`,
//! `bips`) used by upstream Fail2Ban 1.1.1 `database.py`, enabling bidirectional
//! upgrade and rollback verification with upstream `Fail2BanDb`.

use std::net::IpAddr;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::{Error, Result};
use crate::track::state::BanRecord;

/// Exact Fail2Ban 1.1.1 v4 schema (from `fail2ban/server/database.py`).
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

/// Writable handle to a Fail2Ban 1.1.1 v4 SQLite database.
pub struct LegacySqliteDb {
    conn: Connection,
}

impl LegacySqliteDb {
    /// Open a structurally compatible v4 database, or initialize an empty one.
    /// Do not stamp an unrelated/older database as v4.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            Error::persistence(format!("opening Fail2Ban SQLite {}: {e}", path.display()))
        })?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(|e| sql_error("enabling foreign key checks", &e))?;
        let tx = TransactionBehavior::Immediate;
        let snapshot = rusqlite::Transaction::new_unchecked(&conn, tx)
            .map_err(|e| sql_error("opening schema transaction", &e))?;
        let objects: bool = snapshot
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| sql_error("checking schema", &e))?;
        if !objects {
            snapshot
                .execute_batch(SCHEMA_V4_DDL)
                .map_err(|e| sql_error("initializing v4 schema", &e))?;
            snapshot
                .execute("INSERT INTO fail2banDb(version) VALUES(4)", [])
                .map_err(|e| sql_error("writing schema version", &e))?;
        }
        if objects {
            upgrade_legacy_schema_to_v4(&snapshot, path)?;
        }
        validate_v4(&snapshot)?;
        snapshot
            .commit()
            .map_err(|e| sql_error("committing schema transaction", &e))?;
        Ok(Self { conn })
    }

    /// Ensure a jail is registered/enabled without replacing its parent row.
    pub fn ensure_jail(&self, jail: &str) -> Result<()> {
        ensure_jail(&self.conn, jail)
    }

    /// Persist a log checkpoint and its jail in one SQLite transaction.
    pub fn upsert_log(
        &self,
        jail: &str,
        path: &str,
        first_line_sha1: &str,
        offset: u64,
    ) -> Result<()> {
        let offset = i64::try_from(offset)
            .map_err(|_| Error::persistence("Fail2Ban SQLite log offset exceeds signed range"))?;
        let tx = self.begin()?;
        ensure_jail(&tx, jail)?;
        tx.execute(UPSERT_LOG, params![jail, path, first_line_sha1, offset])
            .map_err(|e| sql_error("writing log checkpoint", &e))?;
        tx.commit()
            .map_err(|e| sql_error("committing log checkpoint", &e))
    }

    /// Encode Fail2Ban 1.1.1 ticket `data` JSON BLOB (`{"matches":[...]}`),
    /// bounding entries (max 50 lines, 4 KiB each) for safe SQLite persistence.
    pub fn encode_ticket_data(matches: &[String]) -> Vec<u8> {
        let bounded: Vec<&str> = matches
            .iter()
            .take(50)
            .map(|line| {
                let mut end = line.len().min(4096);
                while !line.is_char_boundary(end) {
                    end -= 1;
                }
                line.get(..end).unwrap_or("")
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({ "matches": bounded }))
            .unwrap_or_else(|_| EMPTY_DATA.to_vec())
    }

    /// Write the active row and history atomically with matched log lines stored
    /// in the `data` JSON BLOB (`{"matches":[...]}`), matching Fail2Ban 1.1.1.
    pub fn upsert_ban_with_matches(
        &self,
        ban: &BanRecord,
        ban_count: i64,
        matches: &[String],
    ) -> Result<()> {
        let data = Self::encode_ticket_data(matches);
        let tx = self.begin()?;
        ensure_jail(&tx, &ban.jail_id)?;
        let ip = ban.ip.to_string();
        tx.execute(
            "INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ip,
                ban.jail_id,
                ban.banned_at,
                duration(ban),
                ban_count,
                data.as_slice()
            ],
        )
        .map_err(|e| sql_error("writing active ban with matches", &e))?;
        tx.execute(
            INSERT_HISTORY,
            params![
                ban.jail_id,
                ip,
                ban.banned_at,
                duration(ban),
                ban_count,
                data.as_slice()
            ],
        )
        .map_err(|e| sql_error("writing ban history with matches", &e))?;
        tx.commit().map_err(|e| sql_error("committing ban", &e))
    }

    /// Write the active row and history atomically. Ticket data matches the
    /// original writer's SQLite JSON BLOB representation.
    pub fn upsert_ban(&self, ban: &BanRecord, ban_count: i64) -> Result<()> {
        self.upsert_ban_then(ban, ban_count, || Ok(()))
    }

    /// Stage both SQLite writes before committing the caller's WAL update.
    /// On staging or callback failure SQLite rolls back; the caller must
    /// compensate if the WAL write succeeds but SQLite commit fails.
    pub(super) fn upsert_ban_then(
        &self,
        ban: &BanRecord,
        ban_count: i64,
        commit_wal: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let tx = self.begin()?;
        write_active(&tx, ban, ban_count)?;
        let ip = ban.ip.to_string();
        tx.execute(
            INSERT_HISTORY,
            params![
                ban.jail_id,
                ip,
                ban.banned_at,
                duration(ban),
                ban_count,
                EMPTY_DATA
            ],
        )
        .map_err(|e| sql_error("writing ban history", &e))?;
        commit_wal()?;
        tx.commit().map_err(|e| sql_error("committing ban", &e))
    }

    /// Update an active ticket without appending a second ban-history event.
    pub(super) fn prolong_ban_then(
        &self,
        ban: &BanRecord,
        commit_wal: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let tx = self.begin()?;
        let changed = tx
            .execute(
                "UPDATE bips SET timeofban = ?3, bantime = ?4 WHERE jail = ?1 AND ip = ?2",
                params![
                    ban.jail_id,
                    ban.ip.to_string(),
                    ban.banned_at,
                    duration(ban)
                ],
            )
            .map_err(|e| sql_error("extending active ban", &e))?;
        if changed == 0 {
            return Err(Error::persistence(
                "active ban missing from Fail2Ban SQLite during prolongation",
            ));
        }
        commit_wal()?;
        tx.commit()
            .map_err(|e| sql_error("committing active ban extension", &e))
    }

    /// Purge expired ban history rows older than `purge_age_secs` from `bans`,
    /// matching upstream Fail2Ban 1.1.1 `Fail2BanDb.purge()`.
    pub fn purge(&self, now_secs: i64, purge_age_secs: i64) -> Result<usize> {
        if purge_age_secs <= 0 {
            return Ok(0);
        }
        let cutoff = now_secs.saturating_sub(purge_age_secs);
        let deleted = self
            .conn
            .execute(
                "DELETE FROM bans WHERE bantime >= 0 AND (timeofban + bantime) < ?1",
                params![cutoff],
            )
            .map_err(|e| Error::persistence(format!("purging Fail2Ban SQLite bans: {e}")))?;
        Ok(deleted)
    }

    /// Remove the active row while retaining ban history.
    pub fn delete_ban(&self, jail: &str, ip: IpAddr) -> Result<()> {
        self.delete_ban_then(jail, ip, || Ok(()))
    }

    /// Stage the SQLite deletion before committing the caller's WAL update.
    pub(super) fn delete_ban_then(
        &self,
        jail: &str,
        ip: IpAddr,
        commit_wal: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let tx = self.begin()?;
        tx.execute(
            "DELETE FROM bips WHERE jail = ?1 AND ip = ?2",
            params![jail, ip.to_string()],
        )
        .map_err(|e| sql_error("deleting active ban", &e))?;
        commit_wal()?;
        tx.commit()
            .map_err(|e| sql_error("committing active ban removal", &e))
    }

    fn begin(&self) -> Result<rusqlite::Transaction<'_>> {
        rusqlite::Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .map_err(|e| sql_error("beginning write", &e))
    }
}

const UPSERT_JAIL: &str = "INSERT INTO jails(name, enabled) VALUES(?1, 1)
                            ON CONFLICT(name) DO UPDATE SET enabled = 1";
const UPSERT_LOG: &str = "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos)
                         VALUES(?1, ?2, ?3, ?4)
                         ON CONFLICT(jail, path) DO UPDATE SET
                         firstlinemd5 = excluded.firstlinemd5, lastfilepos = excluded.lastfilepos";
const UPSERT_BIP: &str = "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(ip, jail) DO UPDATE SET timeofban = excluded.timeofban,
                         bantime = excluded.bantime, bancount = excluded.bancount, data = excluded.data";
const INSERT_HISTORY: &str = "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data)
                            VALUES(?1, ?2, ?3, ?4, ?5, ?6)";
const EMPTY_DATA: &[u8] = br#"{"matches":[]}"#;

fn ensure_jail(connection: &Connection, jail: &str) -> Result<()> {
    connection
        .execute(UPSERT_JAIL, params![jail])
        .map_err(|e| sql_error("upserting jail", &e))?;
    Ok(())
}

fn duration(ban: &BanRecord) -> i64 {
    ban.expires_at
        .map_or(-1, |exp| exp.saturating_sub(ban.banned_at))
}

fn write_active(connection: &Connection, ban: &BanRecord, ban_count: i64) -> Result<()> {
    ensure_jail(connection, &ban.jail_id)?;
    connection
        .execute(
            UPSERT_BIP,
            params![
                ban.ip.to_string(),
                ban.jail_id,
                ban.banned_at,
                duration(ban),
                ban_count,
                EMPTY_DATA
            ],
        )
        .map_err(|e| sql_error("writing active ban", &e))?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        params![table],
        |r| r.get(0),
    )
    .map_err(|e| sql_error("checking table existence", &e))
}

/// Automatically upgrade Fail2Ban SQLite schema v1, v2, or v3 to v4, matching
/// upstream `Fail2BanDb.updateDb()` (and creating a pre-upgrade `.bak` copy).
/// Unrelated databases without `fail2banDb` are left untouched so `validate_v4`
/// rejects them safely.
fn upgrade_legacy_schema_to_v4(conn: &Connection, db_path: &Path) -> Result<()> {
    if !table_exists(conn, "fail2banDb")?
        || !table_exists(conn, "jails")?
        || !table_exists(conn, "logs")?
        || !table_exists(conn, "bans")?
    {
        return Ok(());
    }
    let version: Option<i64> = conn
        .query_row("SELECT version FROM fail2banDb LIMIT 1", [], |r| r.get(0))
        .optional()
        .map_err(|e| sql_error("reading fail2banDb version", &e))?;
    let Some(version) = version else {
        return Ok(());
    };
    if !(1..4).contains(&version) {
        return Ok(());
    }
    let backup = db_path.with_extension("sqlite3.bak");
    if db_path.is_file() && !backup.exists() {
        let _ = std::fs::copy(db_path, &backup);
    }
    if version < 2 && table_exists(conn, "logs")? {
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
            "INSERT INTO logs SELECT * FROM logs_temp;",
            "DROP TABLE logs_temp;",
            "UPDATE fail2banDb SET version = 2;",
        ))
        .map_err(|e| sql_error("migrating Fail2Ban SQLite v1 -> v2", &e))?;
    }
    if version < 3 && table_exists(conn, "bans")? {
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
            "FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE",
            ");",
            "CREATE INDEX IF NOT EXISTS bans_jail_timeofban_ip ON bans(jail, timeofban);",
            "CREATE INDEX IF NOT EXISTS bans_jail_ip ON bans(jail, ip);",
            "CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip);",
            "INSERT INTO bans SELECT * FROM bans_temp;",
            "DROP TABLE bans_temp;",
        ))
        .map_err(|e| sql_error("migrating Fail2Ban SQLite v2 -> v3", &e))?;
    }
    if version < 4 && !table_exists(conn, "bips")? {
        conn.execute_batch(concat!(
            "CREATE TABLE bips(",
            "ip TEXT NOT NULL, ",
            "jail TEXT NOT NULL, ",
            "timeofban INTEGER NOT NULL, ",
            "bantime INTEGER NOT NULL, ",
            "bancount INTEGER NOT NULL default 1, ",
            "data JSON, ",
            "PRIMARY KEY(ip, jail)",
            ");",
            "CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);",
            "CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);",
            "UPDATE fail2banDb SET version = 4;",
        ))
        .map_err(|e| sql_error("migrating Fail2Ban SQLite v3 -> v4", &e))?;
        if table_exists(conn, "bans")? {
            conn.execute(
                "INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data) \
                 SELECT ip, jail, timeofban, bantime, bancount, data FROM bans ORDER BY timeofban",
                [],
            )
            .map_err(|e| sql_error("backfilling bips during v4 migration", &e))?;
        }
    }
    conn.execute_batch(SCHEMA_V4_DDL)
        .map_err(|e| sql_error("finalizing v4 schema", &e))?;
    Ok(())
}

fn validate_v4(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT version FROM fail2banDb LIMIT 2")
        .map_err(|e| sql_error("checking schema version", &e))?;
    let version_rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|e| sql_error("reading schema version", &e))?;
    let versions = version_rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| sql_error("reading schema version", &e))?;
    if versions.as_slice() != [4] {
        return Err(Error::persistence(
            "Fail2Ban SQLite must have exactly one v4 schema version",
        ));
    }
    for (table, query) in [
        ("fail2banDb", "SELECT version FROM fail2banDb"),
        ("jails", UPSERT_JAIL),
        ("logs", UPSERT_LOG),
        ("bips", UPSERT_BIP),
        ("bans", INSERT_HISTORY),
    ] {
        let is_table = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?1 AND type = 'table')",
                [table],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|e| sql_error("checking required table", &e))?;
        if !is_table {
            return Err(Error::persistence(format!(
                "Fail2Ban SQLite v4 requires table {table:?}"
            )));
        }
        conn.prepare(query)
            .map_err(|e| sql_error("checking required v4 columns and keys", &e))?;
    }
    Ok(())
}

fn sql_error(operation: &str, error: &rusqlite::Error) -> Error {
    Error::persistence(format!("{operation} in Fail2Ban SQLite: {error}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::process::Command;

    fn fixture_ban(address: [u8; 4]) -> BanRecord {
        BanRecord {
            ip: IpAddr::from(address),
            jail_id: "sshd".to_owned(),
            banned_at: 1_800_000_000,
            expires_at: Some(1_800_000_600),
        }
    }

    fn count(db: &LegacySqliteDb, sql: &str) -> i64 {
        db.conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn sqlite_jail_updates_keep_peer_checkpoints_and_history() {
        let dir = tempfile::tempdir().unwrap();
        let db = LegacySqliteDb::open_or_create(&dir.path().join("legacy.sqlite3")).unwrap();
        let first = fixture_ban([192, 0, 2, 4]);
        let second = fixture_ban([192, 0, 2, 5]);
        db.upsert_log("sshd", "fixture-a.log", "hash-a", 5).unwrap();
        db.upsert_log("sshd", "fixture-b.log", "hash-b", 7).unwrap();
        db.upsert_ban(&first, 1).unwrap();
        db.upsert_ban(&second, 1).unwrap();
        db.upsert_log("sshd", "fixture-a.log", "hash-a", 11)
            .unwrap();
        assert_eq!(count(&db, "SELECT count(*) FROM logs"), 2);
        assert_eq!(count(&db, "SELECT sum(lastfilepos) FROM logs"), 18);
        assert_eq!(count(&db, "SELECT count(*) FROM bans"), 2);
        assert_eq!(count(&db, "SELECT count(*) FROM bips"), 2);
    }

    #[test]
    fn sqlite_late_statement_failure_and_wal_failure_rollback_all_sql() {
        let dir = tempfile::tempdir().unwrap();
        let db = LegacySqliteDb::open_or_create(&dir.path().join("legacy.sqlite3")).unwrap();
        let first = fixture_ban([192, 0, 2, 4]);
        db.conn
            .execute_batch(
                "CREATE TRIGGER simulate_write_failure BEFORE INSERT ON bans BEGIN
              SELECT RAISE(ABORT, 'test history write failure'); END;",
            )
            .unwrap();
        let mut wal_called = false;
        assert!(
            db.upsert_ban_then(&first, 1, || {
                wal_called = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!wal_called);
        assert_eq!(count(&db, "SELECT count(*) FROM bips"), 0);
        assert_eq!(count(&db, "SELECT count(*) FROM jails"), 0);
        db.conn
            .execute_batch("DROP TRIGGER simulate_write_failure")
            .unwrap();
        assert!(
            db.upsert_ban_then(&first, 1, || Err(Error::persistence("test WAL failure")))
                .is_err()
        );
        assert_eq!(count(&db, "SELECT count(*) FROM jails"), 0);
        assert_eq!(count(&db, "SELECT count(*) FROM bips"), 0);
        assert_eq!(count(&db, "SELECT count(*) FROM bans"), 0);
    }

    #[test]
    fn prolong_and_unban_only_modify_active_table_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let db = LegacySqliteDb::open_or_create(&dir.path().join("legacy.sqlite3")).unwrap();
        let mut ban = fixture_ban([192, 0, 2, 4]);
        db.upsert_ban(&ban, 5).unwrap();
        ban.expires_at = Some(ban.banned_at + 900);
        db.prolong_ban_then(&ban, || Ok(())).unwrap();
        assert_eq!(count(&db, "SELECT bantime FROM bips"), 900);
        assert_eq!(count(&db, "SELECT bantime FROM bans"), 600);
        assert!(
            db.delete_ban_then(&ban.jail_id, ban.ip, || Err(Error::persistence(
                "test WAL failure"
            )))
            .is_err()
        );
        assert_eq!(count(&db, "SELECT count(*) FROM bips"), 1);
        db.delete_ban(&ban.jail_id, ban.ip).unwrap();
        assert_eq!(count(&db, "SELECT count(*) FROM bips"), 0);
        assert_eq!(count(&db, "SELECT count(*) FROM bans"), 1);
    }

    #[test]
    fn sqlite_does_not_stamp_a_nonempty_unrelated_or_old_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-v4.sqlite3");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE notes(title TEXT);")
            .unwrap();
        assert!(LegacySqliteDb::open_or_create(&path).is_err());
        let objects: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(objects, 1);
        conn.execute_batch(
            "CREATE TABLE fail2banDb(version INTEGER); INSERT INTO fail2banDb VALUES(3);",
        )
        .unwrap();
        assert!(LegacySqliteDb::open_or_create(&path).is_err());
        let version: i64 = conn
            .query_row("SELECT version FROM fail2banDb", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn rust_written_sqlite_roundtrips_with_legacy_reader() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("fail2ban.sqlite3");
        let db = LegacySqliteDb::open_or_create(&db_path).unwrap();
        let now = chrono::Utc::now().timestamp();
        let ip: IpAddr = "198.51.100.77".parse().unwrap();
        db.upsert_ban(
            &BanRecord {
                ip,
                jail_id: "sshd".to_owned(),
                banned_at: now - 5,
                expires_at: Some(now + 600),
            },
            2,
        )
        .unwrap();
        db.upsert_log("sshd", "/var/log/auth.log", "deadbeef", 1234)
            .unwrap();
        drop(db);

        let mut cfg = crate::config::Config {
            global: crate::config::GlobalConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            jail: std::collections::HashMap::new(),
        };
        cfg.jail.insert(
            "sshd".to_owned(),
            crate::config::JailConfig {
                enabled: true,
                log_path: std::path::PathBuf::from("/var/log/auth.log"),
                ban_time: 600,
                ..crate::config::JailConfig::default()
            },
        );
        let bans = crate::track::legacy_sqlite::restore_bans(&db_path, &cfg).unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, ip);
        let logs = crate::track::legacy_sqlite::restore_log_positions(&db_path, &cfg).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].offset, Some(1234));
    }

    #[test]
    #[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
    fn upstream_fail2ban_111_reads_sqlite_written_by_rust() {
        let source = std::fs::canonicalize(
            std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
        )
        .expect("locate Fail2Ban 1.1.1 source");
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("fail2ban.sqlite3");
        let db = LegacySqliteDb::open_or_create(&db_path).unwrap();
        let now = chrono::Utc::now().timestamp();
        let ip1: IpAddr = "198.51.100.81".parse().unwrap();
        let ip2: IpAddr = "198.51.100.82".parse().unwrap();
        db.upsert_ban(
            &BanRecord {
                ip: ip1,
                jail_id: "sshd".to_owned(),
                banned_at: now - 2,
                expires_at: Some(now + 600),
            },
            1,
        )
        .unwrap();
        db.upsert_ban(
            &BanRecord {
                ip: ip2,
                jail_id: "sshd".to_owned(),
                banned_at: now - 2,
                expires_at: Some(now + 600),
            },
            1,
        )
        .unwrap();
        db.delete_ban("sshd", ip2).unwrap();
        db.upsert_log("sshd", "/var/log/auth.log", "cafebabe", 2048)
            .unwrap();
        drop(db);

        let py = r"
import json, sys
from fail2ban.server.database import Fail2BanDb

from types import SimpleNamespace
class Jail:
    name = 'sshd'
    actions = SimpleNamespace(getBanTime=lambda: 600)
    getMaxBanTime = staticmethod(lambda: 600)

db = Fail2BanDb(sys.argv[1])
bans = [str(t.getIP()) for t in db.getCurrentBans(jail=Jail())]
paths = sorted(db.getLogPaths(jail=Jail()))
db.close()
print(json.dumps({'bans': bans, 'paths': paths}))
";
        let out = Command::new("python3")
            .args(["-S", "-c", py])
            .arg(&db_path)
            .env("PYTHONPATH", &source)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("run upstream Fail2BanDb rollback check");
        assert!(
            out.status.success(),
            "upstream Fail2BanDb failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(parsed["bans"], serde_json::json!(["198.51.100.81"]));
        assert_eq!(parsed["paths"], serde_json::json!(["/var/log/auth.log"]));
    }

    #[test]
    fn purge_removes_expired_history_older_than_purge_age() {
        let dir = tempfile::tempdir().expect("scratch");
        let db_path = dir.path().join("fail2ban.sqlite3");
        let db = LegacySqliteDb::open_or_create(&db_path).expect("open");
        let old_ban = BanRecord {
            ip: "198.51.100.1".parse().expect("ip"),
            jail_id: "sshd".to_owned(),
            banned_at: 1_000,
            expires_at: Some(1_600),
        };
        let recent_ban = BanRecord {
            ip: "198.51.100.2".parse().expect("ip"),
            jail_id: "sshd".to_owned(),
            banned_at: 100_000,
            expires_at: Some(100_600),
        };
        let perm_ban = BanRecord {
            ip: "198.51.100.3".parse().expect("ip"),
            jail_id: "sshd".to_owned(),
            banned_at: 1_000,
            expires_at: None,
        };
        db.upsert_ban(&old_ban, 1).expect("old");
        db.upsert_ban(&recent_ban, 1).expect("recent");
        db.upsert_ban(&perm_ban, 1).expect("perm");

        let deleted = db.purge(100_500, 86_400).expect("purge");
        assert_eq!(deleted, 1);

        let remaining: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM bans", [], |r| r.get(0))
            .expect("count");
        assert_eq!(remaining, 2);
    }

    #[test]
    fn migrates_legacy_v2_schema_to_v4_preserving_jails_logs_and_bans() {
        let dir = tempfile::tempdir().expect("scratch");
        let db_path = dir.path().join("fail2ban.sqlite3");
        {
            let conn = Connection::open(&db_path).expect("seed v2");
            conn.execute_batch(concat!(
                "CREATE TABLE fail2banDb(version INTEGER);",
                "INSERT INTO fail2banDb(version) VALUES(2);",
                "CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);",
                "INSERT INTO jails(name, enabled) VALUES('sshd', 1);",
                "CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0, UNIQUE(jail, path));",
                "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('sshd', '/var/log/auth.log', 'abc', 128);",
                "CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, data JSON);",
                "INSERT INTO bans(jail, ip, timeofban, data) VALUES('sshd', '198.51.100.7', 1700000000, X'7b7d');",
            ))
            .expect("v2 schema");
        }
        let db = LegacySqliteDb::open_or_create(&db_path).expect("migrate v2 -> v4");
        assert!(db_path.with_extension("sqlite3.bak").is_file());
        let ver: i64 = db
            .conn
            .query_row("SELECT version FROM fail2banDb LIMIT 1", [], |r| r.get(0))
            .expect("ver");
        assert_eq!(ver, 4);
        let bip_ip: String = db
            .conn
            .query_row("SELECT ip FROM bips WHERE jail = 'sshd'", [], |r| r.get(0))
            .expect("backfilled bip");
        assert_eq!(bip_ip, "198.51.100.7");
    }

    #[test]
    fn upsert_ban_with_matches_persists_upstream_json_blob() {
        let dir = tempfile::tempdir().expect("scratch");
        let db_path = dir.path().join("fail2ban.sqlite3");
        let db = LegacySqliteDb::open_or_create(&db_path).expect("open");
        let ban = BanRecord {
            ip: "198.51.100.44".parse().expect("ip"),
            jail_id: "sshd".to_owned(),
            banned_at: 1_700_000_123,
            expires_at: Some(1_700_000_723),
        };
        let lines =
            vec!["Nov 21 12:00:00 srv sshd[1]: Failed password from 198.51.100.44".to_owned()];
        db.upsert_ban_with_matches(&ban, 1, &lines).expect("upsert");
        let blob: Vec<u8> = db
            .conn
            .query_row(
                "SELECT data FROM bips WHERE ip = '198.51.100.44'",
                [],
                |r| r.get(0),
            )
            .expect("read data");
        let val: serde_json::Value = serde_json::from_slice(&blob).expect("json");
        assert_eq!(val.get("matches"), Some(&serde_json::json!(lines)));
    }
}
