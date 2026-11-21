//! Pinned FilterPoll stamp equality and registration-order selection only.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

use crate::detect::legacy_poll_stamp::{PollSelection, PollStamp};

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
// Registration order intentionally differs from both lexical path order
// and the caller's snapshot item order.
const LABELS: [&str; 3] = ["zeta.log", "alpha.log", "middle.log"];

type InputStamp = (usize, f64, u64, u64);
type Step = (&'static str, [InputStamp; 3], &'static [usize]);

const STEPS: &[Step] = &[
    (
        "first-registration-of-empty-fixtures",
        [(2, 0.0, 13, 0), (0, 0.0, 11, 0), (1, 0.0, 12, 0)],
        &[0, 1, 2],
    ),
    (
        "equal-tuples-positive-and-negative-zero",
        [(1, -0.0, 12, 0), (2, 0.0, 13, 0), (0, 0.0, 11, 0)],
        &[],
    ),
    (
        "mtime-component-alone",
        [(2, 0.0, 13, 0), (1, 1.25, 12, 0), (0, 0.0, 11, 0)],
        &[1],
    ),
    (
        "inode-and-size-on-separate-sources",
        [(2, 0.0, 13, 10), (1, 1.25, 12, 0), (0, 0.0, 14, 0)],
        &[0, 2],
    ),
    (
        "decreasing-size-and-mtime",
        [(2, 0.0, 13, 1), (0, 0.0, 14, 0), (1, 0.75, 12, 0)],
        &[1, 2],
    ),
    (
        "selection-has-already-recorded-stamps",
        [(2, 0.0, 13, 1), (1, 0.75, 12, 0), (0, 0.0, 14, 0)],
        &[],
    ),
    (
        "each-different-component-selects-in-attachment-order",
        [(1, 0.75, 15, 0), (2, 0.0, 13, 2), (0, 2.5, 14, 0)],
        &[0, 1, 2],
    ),
    (
        "final-equal-all-unchanged",
        [(1, 0.75, 15, 0), (0, 2.5, 14, 0), (2, 0.0, 13, 2)],
        &[],
    ),
];

fn compare() -> Vec<Value> {
    let mut selection = PollSelection::new(LABELS.len());
    STEPS
        .iter()
        .map(|(label, stamp, expected)| {
            let stamp =
                stamp.map(|(slot, mtime, inode, size)| (slot, PollStamp { mtime, inode, size }));
            let changed = selection
                .select(&stamp)
                .expect("select complete synthetic stamps");
            assert_eq!(&changed, expected, "native {label}");
            json!([label, changed])
        })
        .collect()
}

fn pinned_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate original source");
    let git = |args: &[&str]| {
        let result = Command::new("git")
            .args(args)
            .current_dir(&source)
            .output()
            .expect("run git");
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
    assert!(status.is_empty(), "unchanged original required: {status}");
    source
}

const ORACLE: &str = r"
import json
import logging
from pathlib import Path
import sys
from types import SimpleNamespace

def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'):
        raise AssertionError('unexpected system activity: ' + event)
sys.addaudithook(audit)

from fail2ban.server import filterpoll
from fail2ban.version import version
assert version == '1.1.1'
logging.disable(logging.CRITICAL)

labels, cases = json.loads(sys.argv[1])
paths = [str(Path.cwd() / label) for label in labels]
poll = filterpoll.FilterPoll(SimpleNamespace(name='offline-stamps', database=None))
for path in paths:
    Path(path).write_bytes(b'')
    poll.addLogPath(path, tail=False, autoSeek=False)
assert poll.getLogPaths() == paths

out = []
original_os = filterpoll.os
for label, step in cases:
    snapshot = {paths[index]: SimpleNamespace(st_mtime=mtime, st_ino=inode, st_size=size)
                for index, mtime, inode, size in step}
    calls = []
    def stat(path):
        calls.append(path)
        return snapshot[path]
    # Only this module has a fake os binding. The Python process's real
    # os.stat and the FileContainer module are never patched.
    filterpoll.os = SimpleNamespace(stat=stat)
    try:
        modified = []
        assert poll.getModified(modified) is modified
    finally:
        filterpoll.os = original_os
    assert calls == paths, calls
    out.append([label, [paths.index(path) for path in modified]])

print(json.dumps(out))
";

#[test]
#[ignore = "requires clean original Fail2Ban 1.1.1 source via FAIL2BAN_111_SOURCE and Python 3"]
fn original_poll_stamp_equality_and_attachment_order_match() {
    let source = pinned_source();
    let scratch = tempfile::tempdir().expect("isolated synthetic registration paths");
    let inputs = STEPS
        .iter()
        .map(|(label, stamps, _)| json!([label, stamps]))
        .collect::<Vec<_>>();
    let result = Command::new("python3")
        .args(["-S", "-c", ORACLE, &json!([LABELS, inputs]).to_string()])
        .current_dir(scratch.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run original stamp-only oracle");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> = serde_json::from_slice(&result.stdout).expect("oracle results");
    assert_eq!(original, compare());
}
