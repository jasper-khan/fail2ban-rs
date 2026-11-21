use super::*;

const FILE: &str = "/var/log/example-auth.log";
const JOURNAL: &str = "systemd-journal";
const ROWS: &[LogRow<'_>] = &[
    LogRow {
        jail: "ssh",
        path: FILE,
        first_line_md5: Some("record-id-A"),
        last_file_pos: Some(StoredLogPosition::Integer(9_007_199_254_740_993)),
    },
    LogRow {
        jail: "other",
        path: FILE,
        first_line_md5: None,
        last_file_pos: Some(StoredLogPosition::Integer(27)),
    },
    LogRow {
        jail: "ssh",
        path: "/sample/empty",
        first_line_md5: Some(""),
        last_file_pos: Some(StoredLogPosition::Integer(0)),
    },
    LogRow {
        jail: "ssh",
        path: JOURNAL,
        first_line_md5: Some("2026-01-07T03:04:05.250000"),
        last_file_pos: Some(StoredLogPosition::Real(1_767_755_045.25)),
    },
];

#[test]
fn lookup_uses_both_keys_and_exact_optional_fingerprint() {
    let original = Some(StoredLogPosition::Integer(9_007_199_254_740_993));
    assert_eq!(
        stored_position(ROWS, "ssh", FILE, Some("record-id-A")),
        original
    );
    assert_eq!(stored_position(ROWS, "ssh", FILE, None), original);
    assert_eq!(
        stored_position(ROWS, "ssh", FILE, Some("record-id-B")),
        None
    );
    assert_eq!(stored_position(ROWS, "missing", FILE, None), None);
    assert_eq!(stored_position(ROWS, "ssh", "/var/log/absent", None), None);
    assert_eq!(stored_position(ROWS, "other", FILE, Some("")), None);
    assert_eq!(
        stored_position(ROWS, "other", FILE, None),
        Some(StoredLogPosition::Integer(27))
    );
    assert_eq!(
        stored_position(ROWS, "ssh", "/sample/empty", Some("")),
        Some(StoredLogPosition::Integer(0))
    );
}

#[test]
fn file_resume_preserves_integer_bytes_and_does_not_override_tail_or_zero() {
    assert_eq!(
        file_resume_offset(ROWS, "ssh", FILE, Some("record-id-A"), false),
        Some(9_007_199_254_740_993)
    );
    assert_eq!(
        file_resume_offset(ROWS, "ssh", FILE, Some("record-id-A"), true),
        None
    );
    assert_eq!(
        file_resume_offset(ROWS, "ssh", "/sample/empty", None, false),
        None
    );
}

#[test]
fn journal_resume_preserves_fraction_and_uses_the_nonempty_tail_clamp() {
    let saved = stored_position(ROWS, "ssh", JOURNAL, None);
    assert_eq!(saved, Some(StoredLogPosition::Real(1_767_755_045.25)));
    assert_eq!(
        journal_resume_time(saved, 1_767_755_100.0, 60),
        1_767_755_045.25
    );
    assert_eq!(
        journal_resume_time(saved, 1_767_755_110.5, 60),
        1_767_755_050.5
    );
    assert_eq!(journal_resume_time(None, 100.25, 60), 40.25);
    assert_eq!(journal_resume_time(None, 42.0, 60), 0.0);
}

#[test]
#[ignore = "requires unchanged local Fail2Ban 1.1.1 source and Python; no database is opened"]
fn original_return_values_and_journal_clamp_match() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate original source");
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&source)
            .output()
            .unwrap()
    };
    let revision = git(&["rev-parse", "HEAD"]);
    assert!(revision.status.success());
    assert_eq!(
        String::from_utf8_lossy(&revision.stdout).trim(),
        "f60978618a101427b06924fc932b44350fec2b63"
    );
    let status = git(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        "fail2ban",
    ]);
    assert!(status.status.success() && status.stdout.is_empty());

    // Use the original methods with synthetic cursor rows, and evaluate only
    // the selected max(...) assignment from the original nonempty branch.
    // No SQLite instance, systemd/journal, or daemon is created.
    let oracle = r"
import ast, json, pathlib, sys
from types import SimpleNamespace
from fail2ban.server.database import Fail2BanDb
rows = {
    ('ssh', '/var/log/example-auth.log'): ('record-id-A', 9007199254740993),
    ('other', '/var/log/example-auth.log'): (None, 27),
    ('ssh', '/sample/empty'): ('', 0),
    ('ssh', 'systemd-journal'): ('2026-01-07T03:04:05.250000', 1767755045.25),
}
class SyntheticCursor:
    def execute(self, query, params):
        if query.startswith('SELECT '):
            self.row = rows.get(params)
        else:
            assert query.startswith('INSERT OR REPLACE '), query
    def fetchone(self):
        return self.row
db = SimpleNamespace()
cursor = SyntheticCursor()
db._addLog = lambda *a: Fail2BanDb._addLog(db, *a)
def read(jail, path, fingerprint):
    return db._addLog(cursor, SimpleNamespace(name=jail), path, 0, fingerprint)
saved = Fail2BanDb.getJournalPos.__wrapped__(db, cursor, SimpleNamespace(name='ssh'), 'systemd-journal')
tree = ast.parse((pathlib.Path(sys.argv[1]) / 'fail2ban/server/filtersystemd.py').read_text())
assignment, = [
    node for node in ast.walk(tree) if isinstance(node, ast.Assign)
    and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
    and node.targets[0].id == 'startTime'
    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
    and node.value.func.id == 'max'
]
code = compile(ast.Module(body=[assignment], type_ignores=[]), '<isolated-original-assignment>', 'exec')
def resume(position, now, window):
    env = dict(startTime=position or 0, MyTime=SimpleNamespace(time=lambda: now), self=SimpleNamespace(getFindTime=lambda: window))
    exec(code, env)
    return env['startTime']
path = '/var/log/example-auth.log'
print(json.dumps([
    read('ssh',path,'record-id-A'), read('ssh',path,'record-id-B'),
    read('ssh',path,None), read('other',path,None), read('other',path,''), read('missing',path,None),
    saved, resume(saved,1767755100.,60), resume(saved,1767755110.5,60), resume(None,42.,60),
]))
";
    let scratch = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("python3")
        .args(["-S", "-c", oracle])
        .arg(&source)
        .current_dir(scratch.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let selected = |jail, path, md5| match stored_position(ROWS, jail, path, md5) {
        Some(StoredLogPosition::Integer(value)) => serde_json::json!(value),
        Some(StoredLogPosition::Real(value)) => serde_json::json!(value),
        None => serde_json::Value::Null,
    };
    let saved = stored_position(ROWS, "ssh", JOURNAL, None);
    let ours = vec![
        selected("ssh", FILE, Some("record-id-A")),
        selected("ssh", FILE, Some("record-id-B")),
        selected("ssh", FILE, None),
        selected("other", FILE, None),
        selected("other", FILE, Some("")),
        selected("missing", FILE, None),
        selected("ssh", JOURNAL, None),
        serde_json::json!(journal_resume_time(saved, 1_767_755_100.0, 60)),
        serde_json::json!(journal_resume_time(saved, 1_767_755_110.5, 60)),
        serde_json::json!(journal_resume_time(None, 42.0, 60) as i64),
    ];
    assert_eq!(ours, expected);
}
