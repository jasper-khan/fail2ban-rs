//! Read-only logical projection from synthetic and stock copied databases.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::{Map, Value};
use tempfile::tempdir;

use super::legacy_restore::{LegacyBanRow, RestoreRequest, restore_current};

type Fixture = (
    &'static str,
    &'static str,
    f64,
    Option<f64>,
    f64,
    Option<f64>,
    usize,
);

const V1_JAIL: &str = "DummyJail #29162448 with 0 tickets";
const FIXTURES: &[Fixture] = &[
    ("v4", "sshd", 100.0, None, 20.0, None, 2),
    ("v4", "sshd", 100.0, None, 20.0, Some(10.0), 0),
    ("v4", "sshd", 100.0, Some(4.25), 20.0, Some(5.0), 1),
    ("v4", "sshd", 100.75, None, 20.0, None, 10),
    ("v4", "other", 100.125, None, 20.0, None, 10),
    ("v1", V1_JAIL, 1_388_009_242.5, None, 600.0, Some(5.0), 2),
    ("v1", V1_JAIL, 1_388_009_242.5, None, -1.0, Some(5.0), 0),
    (
        "v2",
        "pam-generic",
        1_417_595_494.0,
        None,
        600.0,
        Some(5.0),
        2,
    ),
    (
        "v2",
        "pam-generic",
        1_417_595_494.0,
        None,
        -1.0,
        Some(5.0),
        0,
    ),
];

#[derive(Deserialize)]
struct Reference {
    rows: Vec<LegacyBanRow>,
    restored: Vec<ReferenceTicket>,
}

type ReferenceTicket = (String, f64, f64, i64, Map<String, Value>);

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_per_jail_restore_agrees_with_fail2ban_111() {
    let source = pinned_source();
    let original = oracle(&source);
    assert_eq!(original.len(), FIXTURES.len());
    for (&(file, jail, now, age_window, base_ban_time, max_ban_time, max_matches), snapshot) in
        FIXTURES.iter().zip(original)
    {
        let request = RestoreRequest {
            jail,
            now,
            age_window,
            base_ban_time,
            max_ban_time,
            max_matches,
        };
        let native = restore_current(&snapshot.rows, &request).expect("valid migration projection");
        let native = native
            .into_iter()
            .map(|row| {
                (
                    row.ip,
                    row.time_of_ban,
                    row.ban_time,
                    row.ban_count,
                    row.data,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            native, snapshot.restored,
            "{file} jail={jail:?} now={now} age={age_window:?} base={base_ban_time} max={max_ban_time:?} matches={max_matches}"
        );
    }
}

fn pinned_source() -> PathBuf {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate original Fail2Ban");
    assert_eq!(
        git(&source, &["rev-parse", "HEAD"]).trim(),
        "f60978618a101427b06924fc932b44350fec2b63"
    );
    let status = git(
        &source,
        &[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored=matching",
            "--",
            "fail2ban",
        ],
    );
    assert!(
        status
            .lines()
            .all(|line| line.starts_with("!! fail2ban/") && line.ends_with("/__pycache__/")),
        "use unmodified Python source and original test databases: {status}"
    );
    source
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("git UTF-8")
}

fn oracle(source: &Path) -> Vec<Reference> {
    const ORACLE: &str = r#"
import json
from pathlib import Path
import shutil
import sqlite3
import sys
from types import SimpleNamespace

source, directory, checks = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.server.database import Fail2BanDb
from fail2ban.version import version
assert version == "1.1.1", version

def version_of(connection):
    return connection.execute("SELECT version FROM fail2banDb").fetchone()[0]

def readonly(path):
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True,
                           detect_types=sqlite3.PARSE_DECLTYPES)

root = Path(directory)
databases = {}
for generation in (1, 2):
    source_db = Path(source) / "fail2ban" / "tests" / "files" / f"database_v{generation}.db"
    path = root / f"copied-v{generation}.sqlite"
    shutil.copyfile(source_db, path)
    initial = readonly(path)
    assert version_of(initial) == generation
    initial.close()
    databases[f"v{generation}"] = Fail2BanDb(str(path))
    migrated = readonly(path)
    assert version_of(migrated) == 4
    assert migrated.execute("SELECT DISTINCT bantime FROM bips").fetchall() == [(-2,)]
    migrated.close()

path = root / "fresh-v4.sqlite"
db = Fail2BanDb(str(path))
databases["v4"] = db
# Write directly to the synthetic SQLite table so fractional storage is
# covered. The ordinary addBan path rounds incoming timestamps to integers.
with sqlite3.connect(path) as writer:
    assert version_of(writer) == 4
    writer.executemany("INSERT INTO jails(name) VALUES (?)", [("sshd",), ("other",)])
    writer.executemany("""
        INSERT INTO bips (jail, ip, timeofban, bantime, bancount, data)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [
        ("sshd", "192.0.2.10", 90.25, 10.5, 2,
         {"matches": ["first", ["two", "\n"], "third"], "failures": 3, "extra": None, "tag": "kept"}),
        ("sshd", "192.0.2.20", 95.75, 4.25, 1, None),
        ("sshd", "192.0.2.30", 89.75, -1, 9, {"matches": ["preserved"]}),
        ("sshd", "192.0.2.40", 88.125, -2, 4, {"matches": ["old"]}),
        ("sshd", "192.0.2.50", 95.75, 999, 0, None),
        ("sshd", "2001:0db8::10", 99.5, 2.25, 1, {"matches": [["not", " flattened"]]}),
        ("other", "192.0.2.10", 100.125, -1, 22, {"tag": "other jail"}),
    ])

def source_rows(db):
    # A separate SQLite connection extracts only the normalized bips shape.
    # The native restore projection, not a DB upgrader, consumes those rows.
    conn = readonly(Path(db.filename))
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute("""
            SELECT jail, ip, timeofban AS time_of_ban,
                   bantime AS ban_time, bancount AS ban_count, data
            FROM bips
            ORDER BY jail DESC, ip DESC
        """)]
    finally:
        conn.close()

answers = []
for file, jail_name, now, age, base, maximum, match_limit in json.loads(checks):
    db = databases[file]
    jail = SimpleNamespace(
        name=jail_name,
        actions=SimpleNamespace(getBanTime=lambda: base),
        getMaxBanTime=lambda: -1 if maximum is None else maximum,
    )
    original = db.getCurrentBans(jail=jail, fromtime=now, forbantime=age, maxmatches=match_limit)
    answers.append({
        "rows": source_rows(db),
        "restored": [[str(ticket.getID()), ticket.getTime(), ticket.getBanTime(),
                      ticket.getBanCount(), ticket.getData()] for ticket in original],
    })
for database in databases.values():
    database.close()
print(json.dumps(answers))
"#;
    let scratch = tempdir().expect("isolated temporary DB workspace");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(scratch.path())
        .arg(serde_json::to_string(FIXTURES).expect("fixtures serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original offline restore query");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
