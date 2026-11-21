//! Original FileFilter parity across two synthetic logs of one logical jail.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::legacy_jail_plan;
use crate::detect::legacy_file_cursor::StartAt;
use crate::detect::legacy_observation_time::FilePhase;
use crate::legacy_jail_replay::ReplayDecision;
use crate::legacy_queued_file::QueuedFiles;

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const START: i64 = 1_752_537_600;
const JAIL: &str = "multi-fixture";
const LABELS: [&str; 2] = ["/offline/left.log", "/offline/right.log"];
const IP: &str = "192.0.2.20";
const CONFIG: &str = concat!(
    "[multi-fixture]\n",
    "enabled=true\nbackend=polling\nusedns=no\nignoreself=false\nlogtimezone=UTC\n",
    "logpath=/offline/left.log\n        /offline/right.log\n",
    "filter=nginx-http-auth\nmaxretry=2\nfindtime=10s\nbantime=5s\naction=\n",
);

#[derive(Clone, Copy)]
enum Source {
    Left,
    Right,
}

impl Source {
    fn index(self) -> usize {
        usize::from(matches!(self, Self::Right))
    }

    fn label(self) -> &'static Path {
        Path::new(match self {
            Self::Left => LABELS[0],
            Self::Right => LABELS[1],
        })
    }
}

enum Operation {
    Observe {
        label: &'static str,
        source: Source,
        append: String,
        at: i64,
    },
    Tick {
        label: &'static str,
        at: i64,
    },
}

fn failure(second: u8) -> String {
    format!(
        "2025/07/15 00:00:{second:02} [error] 123#123: *4 user \"example\": password mismatch, client: {IP}"
    )
}

fn fixture_steps() -> (String, Vec<Operation>) {
    let first_left = format!("{}\r\n", failure(0));
    let at = |delta| START + delta;
    let observe = |label, source, append, delta| Operation::Observe {
        label,
        source,
        append,
        at: at(delta),
    };
    let tick = |label, delta| Operation::Tick {
        label,
        at: at(delta),
    };
    (
        first_left,
        vec![
            observe("empty-right", Source::Right, String::new(), 0),
            observe("first-left", Source::Left, String::new(), 0),
            observe("partial-right", Source::Right, failure(1), 1),
            observe("complete-right", Source::Right, "\n".to_owned(), 1),
            tick("shared-threshold-ban", 1),
            observe(
                "qualifying-duplicate-left",
                Source::Left,
                format!("{0}\n{0}\n", failure(1)),
                2,
            ),
            tick("no-second-ban", 2),
            tick("at-ban-end", 6),
            tick("strict-expiry", 7),
        ],
    )
}

fn phase(phase: FilePhase) -> &'static str {
    match phase {
        FilePhase::Initial => "initial",
        FilePhase::Live => "live",
    }
}

fn render_decision(decision: ReplayDecision) -> Value {
    match decision {
        ReplayDecision::Ban { ip, at } => json!(["ban", ip.to_string(), at]),
        ReplayDecision::Unban { ip, at } => json!(["unban", ip.to_string(), at]),
    }
}

fn native(config: &Path, scratch: &Path, first: &str, steps: &[Operation]) -> Vec<Value> {
    let files = [scratch.join("left.log"), scratch.join("right.log")];
    fs::write(&files[0], first).expect("write synthetic left input");
    fs::write(&files[1], []).expect("write empty synthetic right input");
    let plan = legacy_jail_plan::read(config, JAIL).expect("read admitted two-file plan");
    let mut replay = QueuedFiles::new(plan).expect("create one shared queued jail");
    for (label, file) in LABELS.into_iter().zip(&files) {
        replay
            .attach(
                Path::new(label),
                File::open(file).expect("open only synthetic file"),
                StartAt::Head,
            )
            .expect("attach selected fixture to its configured label");
    }

    steps
        .iter()
        .map(|step| {
            let mut lines = Vec::new();
            let mut decisions = Vec::new();
            let label = match step {
                Operation::Observe {
                    label,
                    source,
                    append,
                    at,
                } => {
                    if !append.is_empty() {
                        let path = files
                            .get(source.index())
                            .expect("selected synthetic file name");
                        OpenOptions::new()
                            .append(true)
                            .open(path)
                            .expect("open synthetic append")
                            .write_all(append.as_bytes())
                            .expect("append synthetic data");
                    }
                    while let Some(entry) = replay
                        .poll_one(source.label(), *at)
                        .expect("read next complete fixture line")
                    {
                        lines.push(json!([
                            source.index(),
                            entry.end_offset,
                            phase(entry.phase),
                            entry.queued
                        ]));
                    }
                    label
                }
                Operation::Tick { label, at } => {
                    decisions.extend(
                        replay
                            .tick(*at)
                            .expect("advance shared action recorder")
                            .into_iter()
                            .map(render_decision),
                    );
                    label
                }
            };
            let snapshots = LABELS.map(|label| {
                let label = Path::new(label);
                json!([
                    replay.acknowledged_offset(label).expect("source offset"),
                    phase(replay.phase(label).expect("source phase"))
                ])
            });
            json!([label, snapshots, lines, decisions])
        })
        .collect()
}

fn golden(first: &str) -> Vec<Value> {
    let left_pos = first.len();
    let right_pos = failure(1).len() + 1;
    let left_second = left_pos + right_pos;
    let left_final = left_second + right_pos;
    vec![
        json!(["empty-right", [[0, "initial"], [0, "initial"]], [], []]),
        json!([
            "first-left",
            [[left_pos, "live"], [0, "initial"]],
            [[0, left_pos, "initial", false]],
            []
        ]),
        json!(["partial-right", [[left_pos, "live"], [0, "live"]], [], []]),
        json!([
            "complete-right",
            [[left_pos, "live"], [right_pos, "live"]],
            [[1, right_pos, "live", true]],
            []
        ]),
        json!([
            "shared-threshold-ban",
            [[left_pos, "live"], [right_pos, "live"]],
            [],
            [["ban", IP, START + 1]]
        ]),
        json!([
            "qualifying-duplicate-left",
            [[left_final, "live"], [right_pos, "live"]],
            [
                [0, left_second, "live", false],
                [0, left_final, "live", true]
            ],
            []
        ]),
        json!([
            "no-second-ban",
            [[left_final, "live"], [right_pos, "live"]],
            [],
            []
        ]),
        json!([
            "at-ban-end",
            [[left_final, "live"], [right_pos, "live"]],
            [],
            []
        ]),
        json!([
            "strict-expiry",
            [[left_final, "live"], [right_pos, "live"]],
            [],
            [["unban", IP, START + 7]]
        ]),
    ]
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
    let changes = git(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        "config",
        "fail2ban",
    ]);
    assert!(
        changes.is_empty(),
        "unchanged original checkout required: {changes}"
    );
    source
}

fn config(source: &Path) -> TempDir {
    let directory = tempfile::tempdir().expect("separate synthetic configuration");
    fs::write(directory.path().join("jail.conf"), CONFIG).expect("write synthetic jail");
    let filters = directory.path().join("filter.d");
    fs::create_dir(&filters).expect("fixture filter directory");
    for name in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config/filter.d").join(name),
            filters.join(name),
        )
        .expect("copy pinned stock filter into the synthetic configuration");
    }
    directory
}

const ORACLE: &str = r"
from collections import deque
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

violations = []
def blocked(*args, **kwargs):
    violations.append('unexpected process, thread, socket or service')
    raise AssertionError(violations[-1])
def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'):
        blocked()
sys.addaudithook(audit)

from fail2ban.client.jailreader import JailReader
from fail2ban.server.actions import Actions
from fail2ban.server.filter import FileFilter, Observers
from fail2ban.server.jail import Jail
from fail2ban.server.mytime import MyTime
from fail2ban.server.server import Server
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1'
subprocess.Popen = os.system = socket.socket = Utils.executeCmd = blocked
threading.Thread.start = Server.start = Jail.start = Actions.start = blocked
Observers.Main = None
logging.disable(logging.CRITICAL)

base, jail_name, supplied = sys.argv[1:]
first, operations = json.loads(supplied)
reader = JailReader(jail_name, basedir=base)
assert reader.read() and reader.getOptions() and reader.isEnabled()
settings = reader.options
assert settings['action'] == '' and not settings.get('ignorecommand')
assert settings['ignoreself'] is False and settings['usedns'] == 'no'
assert settings['logpath'].splitlines() == ['/offline/left.log', '/offline/right.log']
options = reader.filter.getCombined()

class FixtureJail:
    name = 'offline-test'
    database = None
    def __init__(self):
        self.queue = deque()
        self.produced = 0
    def putFailTicket(self, ticket):
        self.queue.append(ticket)
        self.produced += 1
    def getFailTicket(self):
        return self.queue.popleft() if self.queue else False

jail = FixtureJail()
filt = FileFilter(jail, useDns=settings['usedns'])
filt.active = True
filt.ignoreSelf = settings['ignoreself']
filt.setLogEncoding('UTF-8')
filt.setLogTimeZone(settings['logtimezone'])
filt.setFindTime(settings['findtime'])
filt.setMaxRetry(settings['maxretry'])
filt.prefRegex = options['prefregex']
filt.setDatePattern(options['datepattern'])
for rule in (options.get('failregex') or '').splitlines():
    if rule:
        filt.addFailRegex(rule)
for rule in (options.get('ignoreregex') or '').splitlines():
    if rule:
        filt.addIgnoreRegex(rule)

left = Path.cwd() / 'left.log'
right = Path.cwd() / 'right.log'
left.write_bytes(first.encode('utf-8'))
right.write_bytes(b'')
paths = [left, right]
for path in paths:
    filt.addLogPath(str(path), tail=False, autoSeek=False)
containers = [filt.getLog(str(path)) for path in paths]

events = []
class RecordingSink:
    def ban(self, info):
        events.append(['ban', str(info['ip']), MyTime.time()])
    def unban(self, info):
        events.append(['unban', str(info['ip']), MyTime.time()])

actions = Actions(jail)
actions.banManager.setBanTime(MyTime.str2seconds(settings['bantime']))
actions._actions['record-only'] = RecordingSink()
since = 0
out = []
process = filt.processLineAndAdd

for label, kind, index, append, at in operations:
    MyTime.setTime(at)
    lines = []
    before_event = len(events)
    if kind == 'scan':
        if append:
            with paths[index].open('ab') as writer:
                writer.write(append.encode('utf-8'))
        def trace(line):
            prior = jail.produced
            process(line)
            assert 0 <= jail.produced - prior <= 1
            lines.append([index, containers[index].tell(),
                          'live' if filt.inOperation else 'initial', jail.produced > prior])
        filt.processLineAndAdd = trace
        assert filt.getFailures(str(paths[index])) is True
        assert len(events) == before_event, 'filter must not call actions'
    else:
        added = actions._Actions__checkBan() if jail.queue else 0
        since += added
        if not added or since >= actions.banPrecedence:
            n = added * 2
            limit = n if n and n < actions.unbanMaxCount else actions.unbanMaxCount
            actions._Actions__checkUnBan(limit)
            since = 0
    snapshots = [[container.getPos(), 'live' if container.inOperation else 'initial']
                 for container in containers]
    out.append([label, snapshots, lines, events[before_event:]])

assert not violations, violations
print(json.dumps(out))
";

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python"]
fn original_multi_log_jail_combines_threshold_but_keeps_file_positions_independent() {
    let source = pinned_source();
    let settings = config(&source);
    let python_dir = tempfile::tempdir().expect("isolated Python scratch files");
    let native_dir = tempfile::tempdir().expect("isolated native scratch files");
    let (first, operations) = fixture_steps();
    let encoded = operations
        .iter()
        .map(|step| match step {
            Operation::Observe {
                label,
                source,
                append,
                at,
            } => {
                json!([label, "scan", source.index(), append, at])
            }
            Operation::Tick { label, at } => json!([label, "tick", null, null, at]),
        })
        .collect::<Vec<_>>();
    let arguments = json!([first, encoded]).to_string();
    let result = Command::new("python3")
        .args(["-S", "-c", ORACLE])
        .arg(settings.path())
        .arg(JAIL)
        .arg(arguments)
        .current_dir(python_dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run original on synthetic paths only");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> =
        serde_json::from_slice(&result.stdout).expect("original oracle rows");
    let golden = golden(&first);
    let actual = native(settings.path(), native_dir.path(), &first, &operations);
    assert_eq!(original, golden, "original fixture");
    assert_eq!(actual, original, "multi-log Rust replay");
}
