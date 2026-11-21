//! Original FilterPoll transient stat ENOENT and recovery on scratch files only.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::legacy_jail_plan;
use crate::detect::legacy_observation_time::FilePhase;
use crate::detect::legacy_poll_stamp::PollStamp;
use crate::legacy_jail_replay::ReplayDecision;
use crate::legacy_poll_cycle::{PollCycle, PollSlot};

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const START: i64 = 1_752_537_600;
const JAIL: &str = "missing-fixture";
const LABELS: [&str; 2] = ["zeta.log", "alpha.log"];
const CONFIG: &str = concat!(
    "[missing-fixture]\n",
    "enabled=true\nbackend=polling\nusedns=no\nignoreself=false\nlogtimezone=UTC\n",
    "logpath=/offline/zeta.log\n        /offline/alpha.log\n",
    "filter=nginx-http-auth\nmaxretry=2\nfindtime=10s\nbantime=30s\naction=\n",
);
const FIRST: u8 = 20;
const SECOND: u8 = 21;
const REPLACEMENT: u8 = 22;

enum Update {
    Stable,
    Away,
    Restore,
    New(String),
}

struct Step {
    label: &'static str,
    at: i64,
    left: Update,
    append_right: String,
    worker: bool,
}

fn failure(seconds: u8, host: u8) -> String {
    format!(
        "2025/07/15 00:00:{seconds:02} [error] 123#123: *4 user \"example\": password mismatch, client: 192.0.2.{host}\n"
    )
}

fn steps(first_record: &str) -> Vec<Step> {
    let poll = |label, seconds, left, append_right| Step {
        label,
        at: START + seconds,
        left,
        append_right,
        worker: false,
    };
    let tick = |label, seconds| Step {
        label,
        at: START + seconds,
        left: Update::Stable,
        append_right: String::new(),
        worker: true,
    };
    vec![
        poll("initial", 0, Update::Stable, String::new()),
        poll(
            "missing-but-right-qualifies",
            1,
            Update::Away,
            failure(1, FIRST),
        ),
        tick("first-recording-tick", 1),
        poll("still-missing", 2, Update::Stable, String::new()),
        poll(
            "same-inode-restore-no-redo",
            3,
            Update::Restore,
            failure(3, SECOND),
        ),
        poll(
            "second-missing-and-right-progresses",
            4,
            Update::Away,
            failure(4, SECOND),
        ),
        tick("second-recording-tick", 4),
        poll(
            "new-inode-restarts-at-head",
            5,
            Update::New(first_record.to_owned() + &failure(5, REPLACEMENT).repeat(2)),
            String::new(),
        ),
        tick("replacement-recording-tick", 5),
        poll("replacement-unchanged", 6, Update::Stable, String::new()),
    ]
}

fn phase(phase: FilePhase) -> &'static str {
    match phase {
        FilePhase::Initial => "initial",
        FilePhase::Live => "live",
    }
}

fn effect(decision: ReplayDecision) -> Value {
    match decision {
        ReplayDecision::Ban { ip, at } => json!(["ban", ip.to_string(), at]),
        ReplayDecision::Unban { ip, at } => json!(["unban", ip.to_string(), at]),
    }
}

fn native(config: &Path, root: &Path, first: &str, steps: &[Step]) -> Vec<Value> {
    let [left, right] = LABELS.map(|name| root.join(name));
    let stash = root.join("pending-rotation.log");
    fs::write(&left, first).expect("write first source");
    fs::write(&right, b"").expect("write empty second source");
    let plan = legacy_jail_plan::read(config, JAIL).expect("admit isolated two-log jail");
    let mut driver = PollCycle::new(plan).expect("isolated polling fixture");
    for (slot, path) in [&left, &right].into_iter().enumerate() {
        driver
            .attach(
                slot,
                File::open(path).expect("open fixture"),
                false,
                None,
                START,
                None,
            )
            .expect("attach only scratch");
    }
    steps
        .iter()
        .map(|step| {
            let mut missing = Vec::new();
            let mut drains = Vec::new();
            let mut effects = Vec::new();
            if step.worker {
                effects.extend(
                    driver
                        .tick(step.at)
                        .expect("record-only worker tick")
                        .into_iter()
                        .map(effect),
                );
            } else {
                match &step.left {
                    Update::Stable => {}
                    Update::Away => fs::rename(&left, &stash).expect("rename scratch source away"),
                    Update::Restore => {
                        fs::rename(&stash, &left).expect("restore same scratch inode");
                    }
                    Update::New(contents) => {
                        fs::write(&left, contents).expect("create replacement scratch source");
                    }
                }
                if !step.append_right.is_empty() {
                    OpenOptions::new()
                        .append(true)
                        .open(&right)
                        .expect("open second fixture for append")
                        .write_all(step.append_right.as_bytes())
                        .expect("append scratch input");
                }
                let samples = [&left, &right]
                    .into_iter()
                    .enumerate()
                    .rev()
                    .map(|(slot, path)| {
                        let sample = match File::open(path) {
                            Ok(file) => {
                                let stat = file.metadata().expect("bound fixture metadata");
                                Some((
                                    PollStamp {
                                        mtime: 1.0,
                                        inode: stat.ino(),
                                        size: stat.len(),
                                    },
                                    file,
                                ))
                            }
                            Err(err) => {
                                assert_eq!(
                                    err.kind(),
                                    ErrorKind::NotFound,
                                    "scratch absence must be ENOENT"
                                );
                                missing.push(slot);
                                None
                            }
                        };
                        PollSlot { slot, sample }
                    })
                    .collect();
                drains.extend(
                    driver
                        .poll_sampled(samples, step.at)
                        .expect("active sampled poll")
                        .into_iter()
                        .map(|entry| {
                            let lines = entry
                                .lines
                                .into_iter()
                                .map(|line| {
                                    json!([line.end_offset, phase(line.phase), line.queued,])
                                })
                                .collect::<Vec<_>>();
                            json!([entry.slot, entry.offset, phase(entry.phase), lines])
                        }),
                );
            }
            let snapshots = [0, 1].map(|slot| {
                json!([
                    driver
                        .acknowledged_offset(slot)
                        .expect("attached source offset"),
                    phase(driver.phase(slot).expect("attached source phase")),
                ])
            });
            json!([step.label, missing, drains, snapshots, effects])
        })
        .collect()
}

fn original_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate original checkout");
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
        String::from_utf8(result.stdout).expect("read git output")
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
        "clean original source required: {status}"
    );
    source
}

fn settings(source: &Path) -> TempDir {
    let dir = tempfile::tempdir().expect("independent private fixture config");
    fs::write(dir.path().join("jail.conf"), CONFIG).expect("write synthetic settings");
    let filters = dir.path().join("filter.d");
    fs::create_dir(&filters).expect("create fixture-only filter directory");
    for name in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config/filter.d").join(name),
            filters.join(name),
        )
        .expect("copy original stock filter text");
    }
    dir
}

const ORACLE: &str = r"
from collections import deque
import errno
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
from fail2ban.server import filter as filter_module, filterpoll
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
labels, first, start, steps = json.loads(payload)
reader = JailReader(name, basedir=base)
assert reader.read() and reader.getOptions() and reader.isEnabled()
settings = reader.options
assert settings['backend'] == 'polling'
assert settings['action'] == '' and not settings.get('ignorecommand')
assert settings['usedns'] == 'no' and settings['ignoreself'] is False
assert settings['logpath'].splitlines() == ['/offline/' + label for label in labels]
rules = reader.filter.getCombined()

class QueueJail:
    name = 'offline-missing'
    database = None
    def __init__(self):
        self.queue = deque()
        self.produced = 0
    def putFailTicket(self, ticket):
        self.queue.append(ticket)
        self.produced += 1
    def getFailTicket(self):
        return self.queue.popleft() if self.queue else False

MyTime.setTime(start)
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

root = Path.cwd()
left, right = paths = [root / label for label in labels]
stash = root / 'pending-rotation.log'
left.write_bytes(first.encode('utf-8'))
right.write_bytes(b'')
initial_inode = left.stat().st_ino
waiting = []
original_time = filter_module.time
# Only Filter's own sleep hook is inert. It still executes commonError,
# setting its actual private counters; other modules' time remain intact.
filter_module.time = SimpleNamespace(time=MyTime.time, sleep=waiting.append)
for path in paths:
    poll.addLogPath(str(path), tail=False, autoSeek=False)
names = [str(path) for path in paths]
pinned_hash = poll.getLog(names[0]).getHash()

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
process_line = poll.processLineAndAdd
real_os = filterpoll.os
for label, now, update, replacement, append_right, worker in steps:
    MyTime.setTime(now)
    waits_before = len(waiting)
    before = len(events)
    missing = []
    drains = []
    if worker:
        added = actions._Actions__checkBan() if jail.queue else 0
        since += added
        if not added or since >= actions.banPrecedence:
            n = added * 2
            limit = n if n and n < actions.unbanMaxCount else actions.unbanMaxCount
            actions._Actions__checkUnBan(limit)
            since = 0
    else:
        if update == 'away':
            left.rename(stash)
        elif update == 'restore':
            stash.rename(left)
            assert left.stat().st_ino == initial_inode
        elif update == 'new':
            left.write_bytes(replacement.encode('utf-8'))
            assert left.stat().st_ino != initial_inode and stash.stat().st_ino == initial_inode
        if append_right:
            with right.open('ab') as writer:
                writer.write(append_right.encode('utf-8'))
        def sampled_stat(path):
            assert path in names
            try:
                actual = real_os.stat(path)
            except FileNotFoundError as error:
                assert error.errno == errno.ENOENT
                missing.append(names.index(path))
                raise
            return SimpleNamespace(st_mtime=1.0, st_ino=actual.st_ino, st_size=actual.st_size)
        # Delegate to a real stat on our scratch paths; mask mtime only.
        filterpoll.os = SimpleNamespace(stat=sampled_stat)
        try:
            changed = poll.getModified([])
        finally:
            filterpoll.os = real_os
        for path in changed:
            slot = names.index(path)
            container = poll.getLog(path)
            rows = []
            def record(line):
                prior = jail.produced
                process_line(line)
                assert 0 <= jail.produced - prior <= 1
                rows.append([container.tell(), 'live' if poll.inOperation else 'initial',
                             jail.produced > prior])
            poll.processLineAndAdd = record
            assert poll.getFailures(path) is True
            drains.append([slot, container.getPos(), 'live' if container.inOperation else 'initial', rows])
        poll.ticks += 1
        if poll.ticks % 10 == 0:
            poll.performSvc()
        assert len(events) == before
        assert len(waiting) - waits_before == len(missing), 'only genuine scratch ENOENT reaches commonError'
        counts = poll._FilterPoll__file404Cnt
        expected = {
            'missing-but-right-qualifies': 1,
            'still-missing': 2,
            'second-missing-and-right-progresses': 1,
        }.get(label, 0)
        assert counts[names[0]] == expected and counts[names[1]] == 0
        if update == 'restore':
            assert names[0] not in changed, 'same inode + identical stamp must not be reread'
        if update == 'new':
            assert names[0] in changed and poll.getLog(names[0]).getHash() == pinned_hash
    assert poll.active and not poll.idle and poll.getLogPaths() == names
    snapshots = [[poll.getLog(path).getPos(), 'live' if poll.getLog(path).inOperation else 'initial']
                 for path in names]
    answers.append([label, missing, drains, snapshots, events[before:]])
filter_module.time = original_time
assert not violations, violations
print(json.dumps(answers))
";

fn require_reference(rows: &[Value], first_bytes: usize) {
    let at = |idx: usize| rows.get(idx).expect("known fixture step");
    let ban = |host: u8, seconds| json!([["ban", format!("192.0.2.{host}"), START + seconds]]);
    let left_position = |step: usize| at(step).pointer("/3/0/0").expect("left checkpoint");
    let initial = json!(first_bytes);
    for step in [0, 1, 2, 3, 4, 5, 6] {
        assert_eq!(left_position(step), &initial);
    }
    assert_eq!(at(1).get(1), Some(&json!([0])));
    assert_eq!(
        at(1).pointer("/2/0/0"),
        Some(&json!(1)),
        "right source still drains"
    );
    assert_eq!(at(1).pointer("/2/0/3/0/2"), Some(&json!(true)));
    assert_eq!(at(2).get(4), Some(&ban(FIRST, 1)));
    assert_eq!(at(3).get(2), Some(&json!([])));
    assert_eq!(at(4).get(1), Some(&json!([])));
    assert_eq!(
        at(4).pointer("/2/0/0"),
        Some(&json!(1)),
        "restoring identical source left untouched"
    );
    assert_eq!(at(5).get(1), Some(&json!([0])));
    assert_eq!(at(6).get(4), Some(&ban(SECOND, 4)));
    assert_eq!(at(7).pointer("/2/0/0"), Some(&json!(0)));
    assert_eq!(
        at(7).pointer("/2/0/3/0/0"),
        Some(&initial),
        "same first line read from new inode head"
    );
    assert_eq!(
        at(7).pointer("/2/0/3/2/2"),
        Some(&json!(true)),
        "replacement's own lines qualify"
    );
    assert_eq!(at(8).get(4), Some(&ban(REPLACEMENT, 5)));
    assert_eq!(at(9).get(2), Some(&json!([])));
}

#[test]
#[ignore = "requires a clean Fail2Ban 1.1.1 source via FAIL2BAN_111_SOURCE and Python 3"]
fn original_transient_enoent_and_both_recovery_paths_match() {
    let source = original_source();
    let config = settings(&source);
    let py_root = tempfile::tempdir().expect("scratch-only original files");
    let rust_root = tempfile::tempdir().expect("scratch-only native files");
    let first = failure(0, FIRST);
    let scenario = steps(&first);
    let encoded = scenario
        .iter()
        .map(|step| {
            let (op, text) = match &step.left {
                Update::Stable => ("stable", ""),
                Update::Away => ("away", ""),
                Update::Restore => ("restore", ""),
                Update::New(text) => ("new", text.as_str()),
            };
            json!([
                step.label,
                step.at,
                op,
                text,
                step.append_right,
                step.worker
            ])
        })
        .collect::<Vec<_>>();
    let result = Command::new("python3")
        .args(["-S", "-c", ORACLE])
        .arg(config.path())
        .arg(JAIL)
        .arg(json!([LABELS, first, START, encoded]).to_string())
        .current_dir(py_root.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run original using only authenticated scratch fixtures");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> =
        serde_json::from_slice(&result.stdout).expect("original parity timeline");
    assert_eq!(original.len(), scenario.len());
    require_reference(&original, first.len());
    assert_eq!(
        native(config.path(), rust_root.path(), &first, &scenario),
        original
    );
}
