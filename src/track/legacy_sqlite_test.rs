//! Unit tests for the original-database ban restore slice.

use std::path::Path;
use std::process::Command;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, params};
use tempfile::tempdir;

use crate::track::legacy_restore::{RestoreRequest, RestoredBan};

use super::{ban_record, read_bips, restore_bans, restore_bans_at};

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

const NOW: f64 = 1_800_000_500.0;

fn write_bips(path: &Path, rows: &[(&str, f64, f64, i64, Option<&str>)]) {
    let connection = Connection::open(path).expect("create original database");
    connection.execute_batch(BIPS_DDL).expect("original DDL");
    for (ip, time_of_ban, ban_time, ban_count, data) in rows {
        connection
            .execute(
                "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data)
                 VALUES(?1, 'chain-jail', ?2, ?3, ?4, ?5)",
                params![ip, time_of_ban, ban_time, ban_count, data],
            )
            .expect("insert original row");
    }
}

fn read_for_test(db: &Path) -> Vec<super::LegacyBanRow> {
    let connection = super::open_readonly(db).expect("open original file");
    read_bips(
        &connection,
        &RestoreRequest {
            jail: "chain-jail",
            now: NOW,
            age_window: None,
            base_ban_time: -1.0,
            max_ban_time: None,
            max_matches: 0,
        },
    )
    .expect("read eligible original rows")
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
    let rows = read_for_test(&db);
    assert_eq!(rows.len(), 2);
    let ipv4 = rows
        .iter()
        .find(|row| row.ip == "203.0.113.7")
        .expect("IPv4 row");
    let ipv6 = rows
        .iter()
        .find(|row| row.ip == "2001:db8::12")
        .expect("IPv6 row");
    assert_eq!(ipv4.jail, "chain-jail");
    assert_eq!(ipv4.time_of_ban, 1_800_000_000.25);
    assert_eq!(ipv4.ban_time, 600.0);
    assert_eq!(ipv4.ban_count, 3);
    assert!(ipv4.data.is_none());
    assert_eq!(
        ipv6.data.as_ref().expect("json data")["matches"][0],
        "line one"
    );
}

#[test]
fn read_bips_accepts_an_empty_database_file_without_the_table() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    Connection::open(&db).expect("create empty database");
    assert!(
        restore_bans_at(&db, &restore_config(), NOW)
            .expect("no table is not an error")
            .is_empty()
    );
}

#[test]
fn restore_bans_applies_the_original_selection_window() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    let now = NOW;
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
    let config = restore_config();
    let restored = restore_bans_at(&db, &config, now).expect("selection succeeds");
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
fn restore_skips_ignored_ips_and_bad_optional_or_irrelevant_fields() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    let connection = Connection::open(&db).expect("create");
    connection.execute_batch(BIPS_DDL).expect("schema");
    let rows = [
        (
            "192.0.2.3",
            "chain-jail",
            NOW,
            SqlValue::Integer(1),
            SqlValue::Blob(br#"{"matches":["example"]}"#.to_vec()),
        ),
        (
            "192.0.2.4",
            "chain-jail",
            NOW,
            SqlValue::Integer(1),
            SqlValue::Blob(b"invalid metadata".to_vec()),
        ),
        (
            "192.0.2.5",
            "chain-jail",
            NOW,
            SqlValue::Integer(1),
            SqlValue::Text("[1,2]".to_owned()),
        ),
        (
            "192.0.2.6",
            "chain-jail",
            NOW,
            SqlValue::Integer(1),
            SqlValue::Blob(b"{\"note\":\"invalid \xff utf8\"}".to_vec()),
        ),
        (
            "192.0.2.200",
            "chain-jail",
            NOW,
            SqlValue::Integer(1),
            SqlValue::Null,
        ),
        (
            "198.51.100.23",
            "other-jail",
            NOW,
            SqlValue::Text("not a count".to_owned()),
            SqlValue::Null,
        ),
        (
            "198.51.100.24",
            "chain-jail",
            NOW - 100.0,
            SqlValue::Text("not a count".to_owned()),
            SqlValue::Null,
        ),
    ];
    for (ip, jail, start, count, data) in rows {
        connection
            .execute(
                "INSERT INTO bips(ip,jail,timeofban,bantime,bancount,data) VALUES(?1,?2,?3,4,?4,?5)",
                params![ip, jail, start, count, data],
            )
            .expect("insert test ticket");
    }
    let mut config = restore_config();
    config.jail.get_mut("chain-jail").expect("fixture").ignoreip =
        vec!["192.0.2.128/25".to_owned()];
    let restored = restore_bans_at(&db, &config, NOW)
        .expect("irrelevant bad rows and optional invalid JSON are not fatal");
    assert_eq!(
        restored
            .iter()
            .map(|ban| ban.ip.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"]
    );
    let decoded = read_bips(
        &connection,
        &RestoreRequest {
            jail: "chain-jail",
            now: NOW,
            age_window: Some(4.0),
            base_ban_time: 4.0,
            max_ban_time: Some(4.0),
            max_matches: 0,
        },
    )
    .expect("decode selected metadata");
    let data = |ip| {
        decoded
            .iter()
            .find(|row| row.ip == ip)
            .expect("fixture row")
            .data
            .as_ref()
    };
    assert_eq!(
        data("192.0.2.3").expect("valid blob")["matches"][0],
        "example"
    );
    assert!(data("192.0.2.4").is_none() && data("192.0.2.5").is_none());
    assert_eq!(
        data("192.0.2.6").expect("replacement UTF-8")["note"],
        "invalid \u{fffd} utf8"
    );
}

#[test]
fn malformed_database_and_non_regular_file_are_not_reported_as_missing() {
    let dir = tempdir().expect("scratch");
    let config = restore_config();
    let error = restore_bans_at(dir.path(), &config, NOW).expect_err("directory is not a database");
    assert!(error.to_string().contains("not a regular file"));
    let db = dir.path().join("broken.sqlite3");
    let bytes = b"this is a broken SQLite file";
    std::fs::write(&db, bytes).expect("write scratch malformed database");
    let error = restore_bans_at(&db, &config, NOW).expect_err("corruption must be surfaced");
    assert!(error.to_string().contains("checking bips"));
    assert_eq!(std::fs::read(&db).expect("file is untouched"), bytes);
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn read_blob_written_by_pinned_fail2ban() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate pinned Fail2Ban source");
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&source)
        .output()
        .expect("verify upstream revision");
    assert!(head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "f60978618a101427b06924fc932b44350fec2b63"
    );
    let dir = tempdir().expect("disposable original database");
    let db = dir.path().join("fail2ban.sqlite3");
    let python = Command::new("python3")
        .args(["-I", "-B", "-c", PINNED_FIXTURE])
        .arg(source)
        .arg(&db)
        .arg(NOW.to_string())
        .current_dir(dir.path())
        .output()
        .expect("run upstream database fixture only");
    assert!(python.status.success(), "{python:?}");
    let result = restore_bans_at(&db, &restore_config(), NOW).expect("real blob restores");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].ip.to_string(), "192.0.2.3");
    assert_eq!(result[0].expires_at, Some(NOW as i64 + 3));
    assert_eq!(
        read_for_test(&db)[0].data.as_ref().expect("real metadata")["matches"][0],
        "ordinary fixture line"
    );
}

const PINNED_FIXTURE: &str = r#"
import sqlite3
import sys

def guard(event, _args):
    if event.startswith("socket.") or event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
        raise RuntimeError("fixture may not launch an action, process or socket")
sys.addaudithook(guard)
sys.path.insert(0, sys.argv[1])
from fail2ban.server.database import Fail2BanDb
from fail2ban.server.ticket import FailTicket
from fail2ban.version import version
assert version == "1.1.1"

class Fixture:
    name = "chain-jail"

filename, now = sys.argv[2], int(float(sys.argv[3]))
jail = Fixture()
jail.actions = type("FixtureActions", (), {"getBanTime": lambda self: 4})()
db = Fail2BanDb(filename)
db.addJail(jail)
ticket = FailTicket("192.0.2.3", now - 1, data={"matches": ["ordinary fixture line"]})
ticket.setBanTime(4)
db.addBan(jail, ticket)
with sqlite3.connect(filename) as conn:
    assert conn.execute("SELECT typeof(data) FROM bips").fetchone() == ("blob",)
expected = db.getCurrentBans(jail=jail, fromtime=now, forbantime=4, correctBanTime=4)
assert [str(t.getID()) for t in expected] == ["192.0.2.3"]
"#;

const LOGS_DDL: &str = concat!(
    "CREATE TABLE IF NOT EXISTS logs(",
    "jail TEXT NOT NULL, ",
    "path TEXT, ",
    "firstlinemd5 TEXT, ",
    "lastfilepos INTEGER DEFAULT 0, ",
    "UNIQUE(jail, path)",
    ");"
);

#[test]
fn restore_log_positions_decodes_valid_and_invalid_rows_readonly() {
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    let valid_log = dir.path().join("valid.log");
    let invalid_log = dir.path().join("invalid.log");
    let untracked_log = dir.path().join("untracked.log");

    let conn = Connection::open(&db).expect("create db");
    conn.execute_batch(LOGS_DDL).expect("logs ddl");
    conn.execute(
        "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES(?1, ?2, ?3, ?4)",
        params!["chain-jail", valid_log.to_string_lossy().as_ref(), "abc123", 4096_i64],
    )
    .expect("insert valid");
    conn.execute(
        "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES(?1, ?2, NULL, -5)",
        params!["chain-jail", invalid_log.to_string_lossy().as_ref()],
    )
    .expect("insert invalid");
    drop(conn);

    let before = std::fs::read(&db).expect("before bytes");
    let mut cfg = restore_config();
    let jail = cfg.jail.get_mut("chain-jail").expect("jail");
    jail.log_path = valid_log.clone();
    jail.log_paths = vec![valid_log.clone(), invalid_log.clone(), untracked_log.clone()];

    let checkpoints = super::restore_log_positions(&db, &cfg).expect("restore log positions");
    assert_eq!(checkpoints.len(), 2, "untracked path must be omitted");
    assert_eq!(checkpoints[0].path, valid_log);
    assert_eq!(checkpoints[0].first_line_sha1.as_deref(), Some("abc123"));
    assert_eq!(checkpoints[0].offset, Some(4096));
    assert_eq!(checkpoints[1].path, invalid_log);
    assert_eq!(checkpoints[1].first_line_sha1, None);
    assert_eq!(checkpoints[1].offset, None);

    assert_eq!(std::fs::read(&db).expect("after bytes"), before);
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn restore_log_positions_written_by_pinned_fail2ban_111() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");
    let dir = tempdir().expect("scratch");
    let db = dir.path().join("fail2ban.sqlite3");
    let same_log = dir.path().join("same.log");
    let rotated_log = dir.path().join("rotated.log");
    let truncated_log = dir.path().join("truncated.log");

    std::fs::write(&same_log, "line1 first\nline2 second\n").expect("same_log");
    std::fs::write(&rotated_log, "old first\nold second\n").expect("rotated_log");
    std::fs::write(&truncated_log, "trunc first\ntrunc second\ntrunc third\n")
        .expect("truncated_log");

    // Generate the real Fail2Ban 1.1.1 SQLite DB using upstream Fail2BanDb + FileContainer.
    let script = r"
import sys
from types import SimpleNamespace
from fail2ban.server.database import Fail2BanDb
from fail2ban.server.filter import FileContainer

db_path, same_path, rot_path, trunc_path = sys.argv[1:5]
db = Fail2BanDb(db_path)
jail = SimpleNamespace(name='chain-jail')
db.addJail(jail)

for path, pos in [(same_path, 12), (rot_path, 10), (trunc_path, 30)]:
    fc = FileContainer(path, 'utf-8', tail=False)
    fc.setPos(pos)
    db.addLog(jail, fc)
    db.updateLog(jail, fc)
db.close()
";
    let out = Command::new("python3")
        .args(["-S", "-c", script])
        .arg(&db)
        .arg(&same_log)
        .arg(&rotated_log)
        .arg(&truncated_log)
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run Fail2Ban 1.1.1 oracle");
    assert!(
        out.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Mutate rotated_log (new first line) and truncated_log (shorter than 30 bytes).
    std::fs::write(&rotated_log, "new rotated first\nnew second\n").expect("rotate");
    std::fs::write(&truncated_log, "trunc first\n").expect("truncate");
    // Append to same_log after the recorded offset 12.
    std::fs::write(&same_log, "line1 first\nline2 second\nline3 appended\n").expect("append");

    let before_db = std::fs::read(&db).expect("db bytes before");
    let mut cfg = restore_config();
    let jail = cfg.jail.get_mut("chain-jail").expect("jail");
    jail.log_path = same_log.clone();
    jail.log_paths = vec![same_log.clone(), rotated_log.clone(), truncated_log.clone()];

    let checkpoints = super::restore_log_positions(&db, &cfg).expect("read real 1.1.1 logs");
    assert_eq!(checkpoints.len(), 3);

    let check = |cp: &super::LegacyLogCheckpoint| {
        let f = std::fs::File::open(&cp.path).expect("open log");
        let persisted = crate::detect::resume::PersistedFilePosition {
            path: cp.path.clone(),
            inode: None,
            first_line_sha1: cp.first_line_sha1.clone(),
            offset: cp.offset,
        };
        crate::detect::resume::start_for_persisted(&cp.path, &persisted, &f)
    };
    assert_eq!(
        check(&checkpoints[0]),
        crate::detect::resume::StartAt::Offset(12),
        "same file must resume at exact 1.1.1 offset"
    );
    assert_eq!(
        check(&checkpoints[1]),
        crate::detect::resume::StartAt::Start,
        "rotated file must fall back to offset 0"
    );
    assert_eq!(
        check(&checkpoints[2]),
        crate::detect::resume::StartAt::Start,
        "truncated file must fall back to offset 0"
    );

    // Original DB remains strictly read-only.
    assert_eq!(std::fs::read(&db).expect("db bytes after"), before_db);
}
