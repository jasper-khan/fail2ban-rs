//! Byte-offset replay parity over private named UTF-8 fixtures only.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;

use crate::detect::legacy_file_cursor::{LegacyFileCursor, StartAt};

const ORIGINAL: &str = "alpha\nβeta\r\n\npending";

#[derive(Clone, Copy)]
enum Op {
    Read(Option<&'static str>, u64),
    Append(&'static str),
}

use Op::{Append, Read};

struct Scenario {
    name: &'static str,
    start: StartAt,
    initial: &'static str,
    initial_offset: u64,
    operations: &'static [Op],
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "head: CRLF, blank line, and two postponed records",
        start: StartAt::Head,
        initial: ORIGINAL,
        initial_offset: 0,
        operations: &[
            Read(Some("alpha"), 6),
            Read(Some("βeta"), 13),
            Read(Some(""), 14),
            Read(None, 14),
            Read(None, 14),
            Append("-end\nlast\n"),
            Read(Some("pending-end"), 26),
            Read(Some("last"), 31),
            Read(None, 31),
            Append("part"),
            Read(None, 31),
            Append("ial\r\n"),
            Read(Some("partial"), 40),
            Read(None, 40),
        ],
    },
    Scenario {
        name: "resume: supplied byte position is not tail or next line",
        start: StartAt::Resume(6),
        initial: ORIGINAL,
        initial_offset: 6,
        operations: &[
            Read(Some("βeta"), 13),
            Read(Some(""), 14),
            Read(None, 14),
            Append("-end\nlast\n"),
            Read(Some("pending-end"), 26),
            Read(Some("last"), 31),
            Read(None, 31),
        ],
    },
    Scenario {
        name: "tail: preexisting partial bytes are outside the read span",
        start: StartAt::Tail,
        initial: ORIGINAL,
        initial_offset: 21,
        operations: &[
            Read(None, 21),
            Append("-end\nlast\n"),
            Read(Some("-end"), 26),
            Read(Some("last"), 31),
            Read(None, 31),
            Append("part"),
            Read(None, 31),
            Append("ial\r\n"),
            Read(Some("partial"), 40),
            Read(None, 40),
        ],
    },
    Scenario {
        name: "tail: empty begins at zero",
        start: StartAt::Tail,
        initial: "",
        initial_offset: 0,
        operations: &[
            Read(None, 0),
            Append("alpha\n"),
            Read(Some("alpha"), 6),
            Read(None, 6),
        ],
    },
    Scenario {
        name: "tail: a sole partial record still starts at EOF",
        start: StartAt::Tail,
        initial: "raw",
        initial_offset: 3,
        operations: &[
            Read(None, 3),
            Append("-end\n"),
            Read(Some("-end"), 8),
            Read(None, 8),
        ],
    },
];

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Snapshot(u64, Vec<(Option<String>, u64)>);

fn native(scenario: &Scenario) -> Snapshot {
    let scratch = tempdir().expect("private temporary log directory");
    let path = scratch.path().join("fixture.log");
    fs::write(&path, scenario.initial).expect("write original fixture bytes");
    let fd = File::open(&path).expect("open only fixture log");
    let mut cursor = LegacyFileCursor::open(fd, scenario.start, 256).expect("fixture cursor");
    let start = cursor.acknowledged_offset();
    let mut results = Vec::new();
    for &op in scenario.operations {
        match op {
            Append(new) => OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open temporary file for append")
                .write_all(new.as_bytes())
                .expect("append fixture bytes"),
            Read(_, _) => {
                let before = cursor.acknowledged_offset();
                let line = cursor
                    .next_record()
                    .expect("read complete fixture record")
                    .map(|record| (record.text.to_owned(), record.end_offset));
                assert_eq!(cursor.acknowledged_offset(), before, "read is not an ack");
                let text = line.map(|(text, offset)| {
                    cursor.acknowledge(offset).expect("ack fixture record");
                    text
                });
                results.push((text, cursor.acknowledged_offset()));
            }
        }
    }
    Snapshot(start, results)
}

fn golden(scenario: &Scenario) -> Snapshot {
    let observations = scenario
        .operations
        .iter()
        .filter_map(|&op| match op {
            Read(text, offset) => Some((text.map(str::to_owned), offset)),
            Append(_) => None,
        })
        .collect();
    Snapshot(scenario.initial_offset, observations)
}

#[test]
fn file_container_offsets_match_golden() {
    for scenario in SCENARIOS {
        assert_eq!(native(scenario), golden(scenario), "{}", scenario.name);
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn file_container_offsets_agree_with_fail2ban_111() {
    let source = pinned_source();
    let reference = oracle(&source);
    assert_eq!(reference.len(), SCENARIOS.len());
    for (scenario, original) in SCENARIOS.iter().zip(reference) {
        assert_eq!(original, golden(scenario), "original: {}", scenario.name);
        assert_eq!(native(scenario), original, "Rust: {}", scenario.name);
    }
}

fn pinned_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
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
        "use unmodified Python source: {status}"
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

fn oracle(source: &Path) -> Vec<Snapshot> {
    const ORACLE: &str = r"
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

def blocked(*args, **kwargs):
    raise AssertionError('unexpected non-file I/O or execution')
def audit(event, args):
    if event.startswith('socket.') or event in (
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'
    ):
        blocked()
sys.addaudithook(audit)
subprocess.Popen = blocked
os.system = blocked
socket.socket = blocked

source, scenarios = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.server.filter import FileContainer
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version
Utils.executeCmd = blocked
answers = []
for index, (mode, resume, content, operations) in enumerate(json.loads(scenarios)):
    path = Path.cwd() / f'fixture-{index}.log'
    path.write_bytes(content.encode('utf-8'))
    cursor = FileContainer(str(path), 'UTF-8', tail=mode == 'tail')
    if mode == 'resume':
        cursor.setPos(resume)
    start = cursor.getPos()
    records = []
    for op, text in operations:
        if op == 'append':
            with path.open('ab') as writer:
                writer.write(text.encode('utf-8'))
            continue
        assert op == 'read'
        line = None
        if cursor.open():
            try:
                line = cursor.readline()
                end = cursor.tell()
            finally:
                cursor.close()
            assert cursor.getPos() == end
        records.append([line, cursor.getPos()])
    answers.append([start, records])
print(json.dumps(answers))
";
    let input = SCENARIOS
        .iter()
        .map(|s| {
            let (mode, offset) = match s.start {
                StartAt::Head => ("head", None),
                StartAt::Tail => ("tail", None),
                StartAt::Resume(offset) => ("resume", Some(offset)),
            };
            let steps = s.operations.iter().map(|op| match op {
                Append(text) => ("append", Some(text)),
                Read(_, _) => ("read", None),
            });
            json!([mode, offset, s.initial, steps.collect::<Vec<_>>()])
        })
        .collect::<Vec<_>>();
    let scratch = tempdir().expect("temporary oracle directory");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(serde_json::to_string(&input).expect("fixtures serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original FileContainer oracle");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
