//! Unit tests for the original-database ban restore slice.

use std::path::Path;

use rusqlite::Connection;
use tempfile::tempdir;

use crate::track::legacy_restore::RestoredBan;

use super::{ban_record, merge_with_wal, read_bips, restore_bans};

/// The original `bips` schema, copied from Fail2Ban 1.1.1 database.py.
const BIPS_DDL: &str = concat!(
    "CREATE TABLE IF NOT EXISTS bips(",
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
);

fn write_bips(path: &Path, rows: &[(&str, f64, f64, i64, Option<&str>)]) {
    let connection = Connection::open(path).expect("create original database");
    connection.execute_batch(BIPS_DDL).expect("original DDL");
    for (ip, time_of_ban, ban_time, ban_count, data) in rows {
        let data = data
            .map(|text| format!("'{text}'"))
            .unwrap_or("NULL".to_owned());
        connection
            .execute(
                &format!(
                    "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data) \
                     VALUES('{ip}', 'chain-jail', {time_of_ban}, {ban_time}, {ban_count}, {data})"
                ),
                [],
            )
            .expect("insert original row");
    }
}

/// One row of a different jail, proving per-jail selection.
fn write_other_jail_row(path: &Path, ip: &str) {
    let connection = Connection::open(path).expect("reopen db");
    let now = chrono::Utc::now().timestamp() as f64;
    connection
        .execute(
            &format!(
                "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data) \
                 VALUES('{ip}', 'other-jail', {now}, 4, 1, NULL)"
            ),
            [],
        )
        .expect("insert other-jail row");
}

fn restore_config() -> crate::config::Config {
    let dir = tempdir().expect("scratch state dir");
    let jail = crate::config::JailConfig {
        enabled: true,
        filter: vec!["failed login from <HOST>".to_owned()],
        log_path: dir.path().join("web1.log"),
        ban_time: 4,
        ..crate::config::JailConfig::default()
    };
    let mut map = std::collections::HashMap::new();
    map.insert("chain-jail".to_owned(), jail);
    crate::config::Config {
        global: crate::config::GlobalConfig {
            state_dir: dir.path().to_path_buf(),
            ..crate::config::GlobalConfig::default()
        },
        logging: crate::config::LoggingConfig::default(),
        jail: map,
    }
}

#[test]
fn read_bips_decodes_the_original_row_shape() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    write_bips(
        &db,
        &[
            ("203.0.113.7", 1_800_000_000.25, 600.0, 3, None),
            (
                "2001:db8::12",
                1_800_000_100.5,
                -1.0,
                1,
                Some(r#"{"matches": ["line one"]}"#),
            ),
        ],
    );
    let rows = read_bips(&db).expect("rows decode");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].jail, "chain-jail");
    assert_eq!(rows[0].ip, "203.0.113.7");
    assert_eq!(rows[0].time_of_ban, 1_800_000_000.25);
    assert_eq!(rows[0].ban_time, 600.0);
    assert_eq!(rows[0].ban_count, 3);
    assert!(rows[0].data.is_none());
    assert_eq!(rows[1].ip, "2001:db8::12");
    assert_eq!(
        rows[1].data.as_ref().expect("json data")["matches"][0],
        "line one"
    );
}

#[test]
fn read_bips_accepts_an_empty_database_file_without_the_table() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    Connection::open(&db).expect("create empty database");
    assert!(read_bips(&db).expect("no table is not an error").is_empty());
}

#[test]
fn restore_bans_applies_the_original_selection_window() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    let now = chrono::Utc::now().timestamp() as f64;
    write_bips(
        &db,
        &[
            // Fresh: restored, expiring about three seconds from now.
            ("203.0.113.7", now - 1.0, 4.0, 2, None),
            // Already expired inside the search window: dropped.
            ("203.0.113.8", now - 10.0, 4.0, 1, None),
            // Much older than the window: dropped.
            ("203.0.113.9", now - 600.0, 3600.0, 1, None),
            // Permanent inside the window: restored without expiry.
            ("203.0.113.10", now - 1.0, -1.0, 1, None),
            // Permanent outside the window: the original SQL prunes it too.
            ("203.0.113.14", now - 3_600.0, -1.0, 1, None),
            // Legacy unknown duration: the jail ban time substitutes.
            ("203.0.113.11", now - 1.0, -2.0, 1, None),
        ],
    );
    write_other_jail_row(&db, "198.51.100.2");
    let config = restore_config();
    let restored = restore_bans(&db, &config).expect("selection succeeds");
    let expected: Vec<std::net::IpAddr> = [
        // The original orders bips rows by the stored IP text.
        "203.0.113.10",
        "203.0.113.11",
        "203.0.113.7",
    ]
    .into_iter()
    .map(|ip| ip.parse().expect("ip"))
    .collect();
    let ips: Vec<std::net::IpAddr> = restored.iter().map(|record| record.ip).collect();
    assert_eq!(ips, expected, "only this jail's live bans are restored");
    let fresh = restored[2].clone();
    let permanent = restored[0].clone();
    let unknown = restored[1].clone();
    assert!(fresh.expires_at.unwrap() >= (now + 2.0) as i64);
    // The original caps a restored persistent ban at the jail's current ban
    // time (correctBanTime); only bantime = -1 jails keep it permanent.
    assert!(permanent.expires_at.unwrap() >= (now + 2.0) as i64);
    assert!(unknown.expires_at.unwrap() >= (now + 2.0) as i64);
}

#[test]
fn restore_bans_missing_database_seeds_nothing() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("absent.sqlite3");
    let config = restore_config();
    assert!(
        restore_bans(&db, &config)
            .expect("missing file is not an error")
            .is_empty()
    );
}

#[test]
fn ban_record_drops_non_address_identifiers() {
    let ban = legacy_restored("not-an-ip", 4.0);
    assert!(ban_record("chain-jail", &ban).is_none());
    let ban = legacy_restored("203.0.113.13", 4.0);
    let record = ban_record("chain-jail", &ban).expect("parseable");
    assert_eq!(record.jail_id, "chain-jail");
    assert!(record.expires_at.is_some());
    let ban = legacy_restored("203.0.113.13", -1.0);
    assert_eq!(
        ban_record("chain-jail", &ban)
            .expect("permanent")
            .expires_at,
        None
    );
}

fn legacy_restored(ip: &str, ban_time: f64) -> RestoredBan {
    RestoredBan {
        ip: ip.to_owned(),
        time_of_ban: 1_800_000_000.0,
        ban_time,
        ban_count: 1,
        data: serde_json::Map::default(),
    }
}

#[test]
fn merge_with_wal_prefers_the_wal_for_the_same_pair() {
    let wal = vec![record("203.0.113.7", 1_000)];
    let extra = vec![record("203.0.113.7", 2_000), record("203.0.113.8", 3_000)];
    let merged = merge_with_wal(wal, extra);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].banned_at, 1_000);
    assert_eq!(merged[1].ip.to_string(), "203.0.113.8");
}

fn record(ip: &str, banned_at: i64) -> crate::track::state::BanRecord {
    crate::track::state::BanRecord {
        ip: ip.parse().expect("ip"),
        jail_id: "chain-jail".to_owned(),
        banned_at,
        expires_at: None,
    }
}
