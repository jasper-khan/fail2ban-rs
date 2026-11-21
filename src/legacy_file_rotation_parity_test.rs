//! Pinned original FileContainer decisions on scratch fixture files only.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::detect::legacy_file_cursor::{LegacyFileCursor, StartAt};
use crate::detect::legacy_file_identity::FileIdentityState;

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const LIMIT: usize = 1_024;
const STORED_OFFSET: u64 = 7;

fn pinned_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate pinned original");
    let git = |args: &[&str]| {
        let result = Command::new("git")
            .args(args)
            .current_dir(&source)
            .output()
            .expect("git");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).expect("git output")
    };
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), ORIGINAL_REV);
    let status = git(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        "fail2ban",
    ]);
    assert!(
        status.is_empty(),
        "unmodified original source required: {status}"
    );
    source
}

fn append(path: &Path, data: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open fixture for append")
        .write_all(data)
        .expect("append to fixture");
}

fn native_scan(
    results: &mut Vec<Value>,
    label: &str,
    path: &Path,
    observed: i64,
    identity: &mut FileIdentityState,
    committed: &mut u64,
) {
    let file = File::open(path).expect("reopen fixture");
    let reopened = identity
        .reopen(&file, *committed, observed)
        .expect("inspect reopened fixture");
    let mut rows = Vec::new();
    let previous = *committed;
    *committed = reopened.offset;
    if reopened.has_content {
        let mut cursor = LegacyFileCursor::open(file, StartAt::Resume(reopened.offset), LIMIT)
            .expect("resume scoped UTF-8 fixture");
        while let Some(line) = cursor.next_record().expect("read fixture record") {
            let end = line.end_offset;
            rows.push(json!([line.text, end]));
            cursor
                .acknowledge(end)
                .expect("commit complete fixture record");
        }
        *committed = cursor.acknowledged_offset();
    }
    // All reset scenarios here have a positive prior offset, letting the
    // original's raw getPos expose the same reset signal without patching it.
    assert_eq!(
        reopened.rotated,
        previous > 0 && reopened.offset == 0,
        "{label}"
    );
    results.push(json!([
        label,
        reopened.offset,
        reopened.has_content,
        identity.fingerprint(),
        rows,
        committed
    ]));
}

fn native(base: &Path) -> Vec<Value> {
    let mut results = Vec::new();
    let live = base.join("active.log");
    fs::write(&live, b"marker\r\none\n").expect("seed fixture generation");
    let mut identity =
        FileIdentityState::initialize(&File::open(&live).expect("open fixture"), 100, LIMIT)
            .expect("initialize fixture identity");
    let mut committed = 0;
    native_scan(
        &mut results,
        "initial",
        &live,
        100,
        &mut identity,
        &mut committed,
    );
    append(&live, b"partial");
    native_scan(
        &mut results,
        "incomplete-append",
        &live,
        101,
        &mut identity,
        &mut committed,
    );
    append(&live, b"\n");
    native_scan(
        &mut results,
        "completed-append",
        &live,
        102,
        &mut identity,
        &mut committed,
    );
    fs::rename(&live, base.join("previous.log")).expect("rotate fixture by inode replacement");
    fs::write(&live, b"marker\r\ntwo\n").expect("same first record in replacement fixture");
    native_scan(
        &mut results,
        "replacement-same-fingerprint",
        &live,
        103,
        &mut identity,
        &mut committed,
    );
    fs::write(&live, b"marker\r\n").expect("truncate same fixture inode");
    native_scan(
        &mut results,
        "copytruncate-same-fingerprint",
        &live,
        104,
        &mut identity,
        &mut committed,
    );
    fs::write(&live, b"new-id\r\nreplacement-body\n").expect("regrow scratch file in place");
    native_scan(
        &mut results,
        "fingerprint-cache-at-boundary",
        &live,
        134,
        &mut identity,
        &mut committed,
    );
    native_scan(
        &mut results,
        "fingerprint-refresh-after-boundary",
        &live,
        135,
        &mut identity,
        &mut committed,
    );

    let first = base.join("first.log");
    fs::write(&first, b"").expect("seed empty fixture");
    let mut identity =
        FileIdentityState::initialize(&File::open(&first).expect("open empty fixture"), 200, LIMIT)
            .expect("initialize empty identity");
    committed = 0;
    native_scan(
        &mut results,
        "first-empty",
        &first,
        200,
        &mut identity,
        &mut committed,
    );
    append(&first, b"begin");
    native_scan(
        &mut results,
        "first-partial",
        &first,
        201,
        &mut identity,
        &mut committed,
    );
    append(&first, b"\r\n");
    native_scan(
        &mut results,
        "first-complete",
        &first,
        202,
        &mut identity,
        &mut committed,
    );
    native_scan(
        &mut results,
        "first-eof",
        &first,
        203,
        &mut identity,
        &mut committed,
    );

    let path = base.join("resume.log");
    fs::write(&path, b"begin\r\nresume-here\n").expect("seed resume fixture");
    let mut identity =
        FileIdentityState::initialize(&File::open(&path).expect("open resume fixture"), 301, LIMIT)
            .expect("initialize resume fingerprint");
    let stored = identity.fingerprint().to_owned();
    committed = identity
        .resume_offset(&stored, STORED_OFFSET, false)
        .unwrap_or(0);
    native_scan(
        &mut results,
        "persist-equal",
        &path,
        301,
        &mut identity,
        &mut committed,
    );

    let mut tail_identity =
        FileIdentityState::initialize(&File::open(&path).expect("open tail fixture"), 302, LIMIT)
            .expect("initialize tail fingerprint");
    assert_eq!(
        tail_identity.resume_offset(&stored, STORED_OFFSET, true),
        None
    );
    committed = fs::metadata(&path).expect("synthetic tail metadata").len();
    native_scan(
        &mut results,
        "persist-tail",
        &path,
        302,
        &mut tail_identity,
        &mut committed,
    );

    fs::write(&path, b"other\r\nnew-data\n").expect("replace fingerprint before restart");
    let mut changed = FileIdentityState::initialize(
        &File::open(&path).expect("open changed fixture"),
        303,
        LIMIT,
    )
    .expect("initialize changed fingerprint");
    committed = changed
        .resume_offset(&stored, STORED_OFFSET, false)
        .unwrap_or(0);
    native_scan(
        &mut results,
        "persist-fingerprint-mismatch",
        &path,
        303,
        &mut changed,
        &mut committed,
    );
    results
}

const ORACLE: &str = r"
import hashlib
import json
import logging
import os
import pathlib
import sys
from types import SimpleNamespace

def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'):
        raise AssertionError('unexpected external operation: ' + event)
sys.addaudithook(audit)

from fail2ban.server.database import Fail2BanDb
from fail2ban.server import filter as f
from fail2ban.version import version
assert version == '1.1.1'
assert f.md5sum is hashlib.sha1, 'expected pinned Python 3 FileContainer SHA-1 choice'
logging.disable(logging.CRITICAL)
base = pathlib.Path(sys.argv[1])
clock = 100
f.time = SimpleNamespace(time=lambda: clock)
results = []
def scan(label, obj, observed):
    global clock
    clock = observed
    has_content = obj.open()
    offset = obj.getPos()
    rows = []
    if has_content:
        while True:
            line = obj.readline()
            if line is None:
                break
            rows.append([line, obj.tell()])
        obj.close()
    results.append([label, offset, has_content, obj.getHash(), rows, obj.getPos()])
def append(path, data):
    with path.open('ab') as output:
        output.write(data)

live = base / 'active.log'
live.write_bytes(b'marker\r\none\n')
obj = f.FileContainer(str(live), 'utf-8')
scan('initial', obj, 100)
append(live, b'partial')
scan('incomplete-append', obj, 101)
append(live, b'\n')
scan('completed-append', obj, 102)
live.rename(base / 'previous.log')
live.write_bytes(b'marker\r\ntwo\n')
scan('replacement-same-fingerprint', obj, 103)
live.write_bytes(b'marker\r\n')
scan('copytruncate-same-fingerprint', obj, 104)
live.write_bytes(b'new-id\r\nreplacement-body\n')
scan('fingerprint-cache-at-boundary', obj, 134)
scan('fingerprint-refresh-after-boundary', obj, 135)

first = base / 'first.log'
first.write_bytes(b'')
clock = 200
obj = f.FileContainer(str(first), 'utf-8')
scan('first-empty', obj, 200)
append(first, b'begin')
scan('first-partial', obj, 201)
append(first, b'\r\n')
scan('first-complete', obj, 202)
scan('first-eof', obj, 203)

path = base / 'resume.log'
path.write_bytes(b'begin\r\nresume-here\n')
clock = 300
stored = f.FileContainer(str(path), 'utf-8').getHash()
class Cursor:
    def execute(self, query, params):
        assert query.startswith('SELECT ') and params == ('fixture-jail', str(path))
    def fetchone(self):
        return (stored, 7)
class Database:
    def addLog(self, jail, container):
        return Fail2BanDb.addLog.__wrapped__(self, Cursor(), jail, container)
    def _addLog(self, *args):
        return Fail2BanDb._addLog(self, *args)
class FixtureFilter(f.FileFilter):
    def _addLogPath(self, _):
        pass
def start(label, observed, tail=False):
    global clock
    clock = observed
    reader = FixtureFilter(SimpleNamespace(name='fixture-jail', database=Database()), useDns='no')
    reader.addLogPath(str(path), tail=tail, autoSeek=False)
    scan(label, reader.getLog(str(path)), observed)
start('persist-equal', 301)
start('persist-tail', 302, tail=True)
path.write_bytes(b'other\r\nnew-data\n')
start('persist-fingerprint-mismatch', 303)
print(json.dumps(results))
";

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_file_rotation_and_resume_match_original_scratch_oracle() {
    let source = pinned_source();
    let original_files = tempfile::tempdir().expect("original scratch files");
    let native_files = tempfile::tempdir().expect("native scratch files");
    let result = Command::new("python3")
        .args(["-S", "-c", ORACLE])
        .arg(original_files.path())
        .current_dir(original_files.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run pinned Python with synthetic files");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> =
        serde_json::from_slice(&result.stdout).expect("pinned original output");
    let observed = native(native_files.path());
    assert_eq!(observed.len(), 14);
    assert_eq!(observed, original);
}
