//! Ordered FilterPoll scans and caller-scheduled action ticks on scratch only.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::legacy_jail_plan;
use crate::detect::legacy_observation_time::FilePhase;
use crate::detect::legacy_poll_stamp::PollStamp;
use crate::legacy_jail_replay::ReplayDecision;
use crate::legacy_poll_cycle::{PollCycle, PollInput};

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const START: i64 = 1_752_537_600;
const PORTION_NAMES: [&str; 2] = ["zeta.log", "alpha.log"];
const JAIL: &str = "poll-fixture";
const CONFIG: &str = concat!(
    "[poll-fixture]\n",
    "enabled=true\nbackend=polling\nusedns=no\nignoreself=false\nlogtimezone=UTC\n",
    "logpath=/offline/zeta.log\n        /offline/alpha.log\n",
    "filter=nginx-http-auth\nmaxretry=2\nfindtime=10s\nbantime=5s\naction=\n",
);

struct Cycle {
    label: &'static str,
    now: i64,
    append: [String; 2],
    mtimes: [f64; 2],
}

fn failure(host: u8) -> String {
    format!(
        "2025/07/15 00:00:00 [error] 123#123: *4 user \"example\": password mismatch, client: 192.0.2.{host}"
    )
}

fn fixture() -> ([String; 2], Vec<Cycle>) {
    let paired = |host| format!("{0}\n{0}\n", failure(host));
    let mut zeta = (10..15).map(paired).collect::<String>();
    use std::fmt::Write;
    writeln!(zeta, "{}", failure(20)).expect("make synthetic zeta data");
    let mut alpha = format!("{}\n", failure(20));
    alpha.extend((30..=35).map(paired));
    let no_change = || [String::new(), String::new()];
    (
        [zeta, alpha],
        vec![
            Cycle {
                label: "initial-both",
                now: START,
                append: no_change(),
                mtimes: [10.5, 20.5],
            },
            Cycle {
                label: "unchanged-drains-fifo-remainder",
                now: START + 1,
                append: no_change(),
                mtimes: [10.5, 20.5],
            },
            Cycle {
                label: "partial-alpha",
                now: START + 2,
                append: [String::new(), failure(10)],
                mtimes: [10.5, 20.5],
            },
            Cycle {
                label: "duplicate-and-mtime-only-zeta",
                now: START + 3,
                append: [String::new(), format!("\n{}\n", failure(10))],
                mtimes: [11.5, 20.5],
            },
            Cycle {
                label: "unchanged-at-ban-end",
                now: START + 5,
                append: no_change(),
                mtimes: [11.5, 20.5],
            },
            Cycle {
                label: "unchanged-past-ban-end",
                now: START + 6,
                append: no_change(),
                mtimes: [11.5, 20.5],
            },
        ],
    )
}

fn phase(phase: FilePhase) -> &'static str {
    match phase {
        FilePhase::Initial => "initial",
        FilePhase::Live => "live",
    }
}

fn decision(decision: ReplayDecision) -> Value {
    match decision {
        ReplayDecision::Ban { ip, at } => json!(["ban", ip.to_string(), at]),
        ReplayDecision::Unban { ip, at } => json!(["unban", ip.to_string(), at]),
    }
}

fn native(config: &Path, directory: &Path, initial: &[String; 2], cycles: &[Cycle]) -> Vec<Value> {
    let paths = PORTION_NAMES.map(|name| directory.join(name));
    let plan = legacy_jail_plan::read(config, JAIL).expect("admitted polling fixture");
    let mut driver = PollCycle::new(plan).expect("one polling fixture jail");
    for (slot, (path, text)) in paths.iter().zip(initial).enumerate() {
        fs::write(path, text).expect("write initial synthetic file");
        driver
            .attach(
                slot,
                File::open(path).expect("open the synthetic file"),
                false,
                None,
                START,
                None,
            )
            .expect("attach configured source in registration order");
    }

    cycles
        .iter()
        .map(|cycle| {
            for (path, text) in paths.iter().zip(&cycle.append) {
                if !text.is_empty() {
                    OpenOptions::new()
                        .append(true)
                        .open(path)
                        .expect("append only to synthetic file")
                        .write_all(text.as_bytes())
                        .expect("write synthetic bytes");
                }
            }
            // The adapter sees caller descriptors in reverse registration order.
            // The physical inode/size are from the same descriptor; mtime is an
            // explicit synthetic observation to avoid clock/FS races.
            let snapshot = paths
                .iter()
                .zip(cycle.mtimes)
                .enumerate()
                .rev()
                .map(|(slot, (path, mtime))| {
                    let file = File::open(path).expect("open selected synthetic handle");
                    let stat = file.metadata().expect("bound synthetic-file metadata");
                    PollInput {
                        slot,
                        stamp: PollStamp {
                            mtime,
                            inode: stat.ino(),
                            size: stat.len(),
                        },
                        file,
                    }
                })
                .collect::<Vec<_>>();
            let drains = driver
                .poll(snapshot, cycle.now)
                .expect("poll synthetic sources in order");
            let rows = drains
                .into_iter()
                .map(|drain| {
                    let lines = drain
                        .lines
                        .into_iter()
                        .map(|entry| json!([entry.end_offset, phase(entry.phase), entry.queued]))
                        .collect::<Vec<_>>();
                    json!([drain.slot, drain.offset, phase(drain.phase), lines])
                })
                .collect::<Vec<_>>();
            let effects = driver
                .tick(cycle.now)
                .expect("one independent worker tick")
                .into_iter()
                .map(decision)
                .collect::<Vec<_>>();
            json!([cycle.label, rows, effects])
        })
        .collect()
}

fn configure(source: &Path) -> TempDir {
    let scratch = tempfile::tempdir().expect("isolated config");
    fs::write(scratch.path().join("jail.conf"), CONFIG).expect("write admitted fixture config");
    let filter_dir = scratch.path().join("filter.d");
    fs::create_dir(&filter_dir).expect("create separate fixture filter directory");
    for name in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config/filter.d").join(name),
            filter_dir.join(name),
        )
        .expect("copy pinned stock filter");
    }
    scratch
}

fn source() -> PathBuf {
    let original =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate original source");
    let git = |args: &[&str]| {
        let result = Command::new("git")
            .args(args)
            .current_dir(&original)
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
        "config",
        "fail2ban",
    ]);
    assert!(
        status.is_empty(),
        "unchanged original checkout needed: {status}"
    );
    original
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
from types import SimpleNamespace

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
from fail2ban.server import filterpoll
from fail2ban.server.filter import Observers
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

base, name, payload = sys.argv[1:]
names, initial, cycles = json.loads(payload)
reader = JailReader(name, basedir=base)
assert reader.read() and reader.getOptions() and reader.isEnabled()
settings = reader.options
assert settings['backend'] == 'polling'
assert settings['action'] == '' and not settings.get('ignorecommand')
assert settings['ignoreself'] is False and settings['usedns'] == 'no'
assert settings['logpath'].splitlines() == ['/offline/' + n for n in names]
rules = reader.filter.getCombined()

class QueueJail:
    name = 'offline-poll'
    database = None
    def __init__(self):
        self.queue = deque()
        self.produced = 0
    def putFailTicket(self, ticket):
        self.queue.append(ticket)
        self.produced += 1
    def getFailTicket(self):
        return self.queue.popleft() if self.queue else False

jail = QueueJail()
poll = filterpoll.FilterPoll(jail)
poll.active = True
poll.ignoreSelf = settings['ignoreself']
poll.setUseDns(settings['usedns'])
poll.setLogEncoding('UTF-8')
poll.setLogTimeZone(settings['logtimezone'])
poll.setFindTime(settings['findtime'])
poll.setMaxRetry(settings['maxretry'])
poll.prefRegex = rules['prefregex']
poll.setDatePattern(rules['datepattern'])
for rule in (rules.get('failregex') or '').splitlines():
    if rule:
        poll.addFailRegex(rule)
for rule in (rules.get('ignoreregex') or '').splitlines():
    if rule:
        poll.addIgnoreRegex(rule)

paths = [Path.cwd() / name for name in names]
for path, text in zip(paths, initial):
    path.write_bytes(text.encode('utf-8'))
    poll.addLogPath(str(path), tail=False, autoSeek=False)
assert poll.getLogPaths() == [str(path) for path in paths]

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
answers = []
process = poll.processLineAndAdd
real_os = filterpoll.os
for label, now, add, mtimes in cycles:
    for path, text in zip(paths, add):
        if text:
            with path.open('ab') as writer:
                writer.write(text.encode('utf-8'))
    stamps = {}
    for path, mtime in zip(paths, mtimes):
        metadata = path.stat()
        stamps[str(path)] = SimpleNamespace(st_ino=metadata.st_ino, st_size=metadata.st_size, st_mtime=mtime)
    MyTime.setTime(now)
    before = len(events)
    filterpoll.os = SimpleNamespace(stat=lambda path: stamps[path])
    try:
        changed = poll.getModified([])
    finally:
        filterpoll.os = real_os

    drains = []
    for path in changed:
        container = poll.getLog(path)
        lines = []
        def trace(line):
            prior = jail.produced
            process(line)
            assert 0 <= jail.produced - prior <= 1
            lines.append([container.tell(), 'live' if poll.inOperation else 'initial',
                          jail.produced > prior])
        poll.processLineAndAdd = trace
        assert poll.getFailures(path) is True
        drains.append([[str(p) for p in paths].index(path), container.getPos(),
                       'live' if container.inOperation else 'initial', lines])
    assert len(events) == before, 'polling does not itself call actions'

    added = actions._Actions__checkBan() if jail.queue else 0
    since += added
    if not added or since >= actions.banPrecedence:
        n = added * 2
        limit = n if n and n < actions.unbanMaxCount else actions.unbanMaxCount
        actions._Actions__checkUnBan(limit)
        since = 0

    answers.append([label, drains, events[before:]])
assert not violations, violations
print(json.dumps(answers))
";

fn require_behavior(observed: &[Value]) {
    let row = |i: usize| observed.get(i).expect("recorded cycle row");
    let events = |i: usize| row(i).get(2).expect("recorded action projection");
    let action = |name: &str, now: i64, hosts: &[u8]| {
        Value::Array(
            hosts
                .iter()
                .map(|host| json!([name, format!("192.0.2.{host}"), now]))
                .collect(),
        )
    };
    let slots = |i: usize| {
        row(i)
            .get(1)
            .and_then(Value::as_array)
            .expect("drained sources")
            .iter()
            .map(|entry| entry.get(0).and_then(Value::as_u64).expect("source index"))
            .collect::<Vec<_>>()
    };
    let first = [10, 11, 12, 13, 14, 20, 30, 31, 32, 33];
    assert_eq!(
        slots(0),
        [0, 1],
        "must not sort log labels lexical or input order"
    );
    assert_eq!(
        events(0),
        &action("ban", START, &first),
        "only one default 10-ticket action pass"
    );
    assert!(
        slots(1).is_empty(),
        "metadata equality skips scanning both files"
    );
    assert_eq!(
        events(1),
        &action("ban", START + 1, &[34, 35]),
        "unchanged files still allow an action tick"
    );
    assert_eq!(slots(2), [1], "only source 1 grew");
    assert_eq!(
        row(2).pointer("/1/0/3"),
        Some(&json!([])),
        "partial record is not an observed line"
    );
    assert_eq!(
        slots(3),
        [0, 1],
        "mtime-only change and completed append are both visited"
    );
    assert_eq!(
        row(3).pointer("/1/1/3/1/2"),
        Some(&json!(true)),
        "duplicate qualifies and is queued first"
    );
    assert_eq!(
        events(3),
        &json!([]),
        "qualifying duplicate produces no second action"
    );
    assert_eq!(events(4), &json!([]), "ban expiry is strict");
    assert_eq!(
        events(5),
        &action(
            "unban",
            START + 6,
            &[10, 11, 12, 13, 14, 20, 30, 31, 32, 33, 34, 35]
        )
    );
}

#[test]
#[ignore = "requires clean Fail2Ban 1.1.1 source via FAIL2BAN_111_SOURCE and Python 3"]
fn original_full_poll_registration_order_and_independent_action_drain_match() {
    let source = source();
    let config = configure(&source);
    let py_files = tempfile::tempdir().expect("synthetic original inputs");
    let rust_files = tempfile::tempdir().expect("synthetic Rust inputs");
    let (initial, cycles) = fixture();
    let operations = cycles
        .iter()
        .map(|c| json!([c.label, c.now, c.append, c.mtimes]))
        .collect::<Vec<_>>();
    let args = json!([PORTION_NAMES, initial, operations]).to_string();
    let result = Command::new("python3")
        .args(["-S", "-c", ORACLE])
        .arg(config.path())
        .arg(JAIL)
        .arg(args)
        .current_dir(py_files.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run pinned original scratch-only poll oracle");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> = serde_json::from_slice(&result.stdout).expect("oracle rows");
    assert_eq!(original.len(), cycles.len());
    require_behavior(&original);
    assert_eq!(
        native(config.path(), rust_files.path(), &initial, &cycles),
        original
    );
}
