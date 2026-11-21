//! Original 1.1.1 polling eviction at 51 consecutive ENOENTs on scratch files.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::legacy_jail_plan;
use crate::detect::legacy_poll_stamp::PollStamp;
use crate::legacy_jail_replay::ReplayDecision;
use crate::legacy_poll_cycle::{PollCycle, PollSlot};

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const START: i64 = 1_752_537_600;
const JAIL: &str = "eviction-fixture";
const FILES: [&str; 2] = ["zeta.log", "alpha.log"];
const FIRST: &str = "2025/07/15 00:00:00 [notice] ordinary fixture record\n";
const HEALTHY: &str = "2025/07/15 00:00:52 [notice] healthy source catch-up\n";
const FAILURE: &str = concat!(
    "2025/07/15 00:01:45 [error] 123#123: *4 user ",
    "\"example\": password mismatch, client: 192.0.2.28\n",
);
const CONFIG: &str = concat!(
    "[eviction-fixture]\n",
    "enabled=true\nbackend=polling\nusedns=no\nignoreself=false\nlogtimezone=UTC\n",
    "logpath=/offline/zeta.log\n        /offline/alpha.log\n",
    "filter=nginx-http-auth\nmaxretry=1\nfindtime=10s\nbantime=30s\naction=\n",
);

fn append(path: &Path, bytes: &str) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open named scratch file")
        .write_all(bytes.as_bytes())
        .expect("append only to scratch file");
}

fn sample(slot: usize, path: &Path) -> PollSlot {
    let sample = match File::open(path) {
        Ok(file) => {
            let stat = file.metadata().expect("bound scratch file metadata");
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
            assert_eq!(err.kind(), ErrorKind::NotFound);
            None
        }
    };
    PollSlot { slot, sample }
}

fn native(config: &Path, scratch: &Path) -> Vec<Value> {
    let paths = FILES.map(|file| scratch.join(file));
    let [left, right] = &paths;
    let stash = scratch.join("held.log");
    fs::write(left, FIRST).expect("write left scratch fixture");
    fs::write(right, b"").expect("create empty right fixture");
    let inode = fs::metadata(left).expect("read left fixture inode").ino();
    let plan = legacy_jail_plan::read(config, JAIL).expect("admit synthetic two-file settings");
    let mut driver = PollCycle::new(plan).expect("construct fixture polling driver");
    for (slot, file) in paths.iter().enumerate() {
        driver
            .attach(
                slot,
                File::open(file).expect("open fixture descriptor"),
                false,
                None,
                START,
                None,
            )
            .expect("attach scratch source");
    }
    (0_i64..=105)
        .map(|i| {
            match i {
                1 | 53 => fs::rename(left, &stash).expect("rename left fixture away"),
                51 | 104 => {
                    fs::rename(&stash, left).expect("restore left fixture");
                    assert_eq!(
                        fs::metadata(left)
                            .expect("read restored fixture inode")
                            .ino(),
                        inode
                    );
                }
                52 => append(right, HEALTHY),
                105 => {
                    append(left, FIRST);
                    append(right, FAILURE);
                }
                _ => {}
            }
            let now = START + i;
            let mut snapshots = Vec::new();
            let mut attempted = Vec::new();
            // Reverse arrival order. The traced sample set is sorted into
            // registration order independently of the observed drain order.
            for (slot, path) in paths.iter().enumerate().rev() {
                if driver
                    .is_registered(slot)
                    .expect("inspect configured fixture slot")
                {
                    snapshots.push(sample(slot, path));
                    attempted.push(slot);
                }
            }
            attempted.reverse();
            if i == 104 {
                assert!(
                    driver
                        .poll_sampled(vec![sample(0, left), sample(1, right)], now)
                        .is_err(),
                    "explicitly supplied evicted sample must not reattach"
                );
                assert!(driver.phase(0).is_err());
                assert!(driver.acknowledged_offset(0).is_err());
                assert!(driver.checkpoint(0).is_err());
            }
            let drains = driver
                .poll_sampled(snapshots, now)
                .expect("poll valid scratch snapshot")
                .into_iter()
                .map(|drain| {
                    json!([
                        drain.slot,
                        drain.offset,
                        drain
                            .lines
                            .iter()
                            .map(|line| (line.end_offset, line.queued))
                            .collect::<Vec<_>>()
                    ])
                })
                .collect::<Vec<_>>();
            let registry = [0, 1].map(|slot| {
                driver
                    .is_registered(slot)
                    .expect("inspect registry for fixture slot")
                    .then(|| {
                        json!([
                            driver
                                .missing_streak(slot)
                                .expect("inspect fixture miss streak")
                                .expect("registered slot has a streak"),
                            driver
                                .acknowledged_offset(slot)
                                .expect("get registered source offset")
                        ])
                    })
            });
            let effects = driver
                .tick(now)
                .expect("tick recording-only actions")
                .into_iter()
                .map(|effect| match effect {
                    ReplayDecision::Ban { ip, at } => json!(["ban", ip.to_string(), at]),
                    ReplayDecision::Unban { ip, at } => json!(["unban", ip.to_string(), at]),
                })
                .collect::<Vec<_>>();
            if i >= 103 {
                assert_eq!(
                    fs::metadata(if i == 103 { &stash } else { left })
                        .expect("eviction preserves the scratch inode")
                        .ino(),
                    inode,
                    "eviction is registry removal, not a file mutation"
                );
                assert!(
                    driver
                        .missing_streak(0)
                        .expect("inspect evicted configured slot")
                        .is_none()
                );
            }
            json!([i, attempted, drains, registry, effects])
        })
        .collect()
}

fn pinned_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate original checkout");
    let git = |args: &[&str]| {
        let result = Command::new("git")
            .args(args)
            .current_dir(&source)
            .output()
            .expect("run pinned source git identity check");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).expect("decode git stdout")
    };
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), ORIGINAL_REV);
    assert!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "config",
            "fail2ban"
        ])
        .is_empty(),
        "run only the pinned clean original"
    );
    source
}

fn settings(source: &Path) -> TempDir {
    let config = tempfile::tempdir().expect("create private fixture configuration");
    fs::write(config.path().join("jail.conf"), CONFIG).expect("write scratch jail config");
    let filters = config.path().join("filter.d");
    fs::create_dir(&filters).expect("create private filter directory");
    for name in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config/filter.d").join(name),
            filters.join(name),
        )
        .expect("copy pinned stock filter");
    }
    config
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
from fail2ban.server import filter as filter_module, filterpoll
from fail2ban.server.actions import Actions
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

start, labels, first, healthy, failure = json.loads(sys.argv[3])
reader = JailReader(sys.argv[2], basedir=sys.argv[1])
assert reader.read() and reader.getOptions() and reader.isEnabled()
settings = reader.options
assert settings['backend'] == 'polling' and settings['action'] == ''
assert settings['usedns'] == 'no' and settings['ignoreself'] is False and not settings.get('ignorecommand')
assert settings['logpath'].splitlines() == ['/offline/' + label for label in labels]
rules = reader.filter.getCombined()

class QueueJail:
    name = 'offline-eviction'
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
poll.ignoreSelf = False
poll.setUseDns('no')
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
stash = root / 'held.log'
left.write_bytes(first.encode())
right.write_bytes(b'')
inode = left.stat().st_ino
names = list(map(str, paths))
for name in names:
    poll.addLogPath(name, tail=False, autoSeek=False)

events = []
class RecordingSink:
    def ban(self, info):
        events.append(['ban', str(info['ip']), MyTime.time()])
    def unban(self, info):
        events.append(['unban', str(info['ip']), MyTime.time()])
actions = Actions(jail)
actions.banManager.setBanTime(MyTime.str2seconds(settings['bantime']))
actions._actions['record-only'] = RecordingSink()

def append(path, text):
    with path.open('ab') as f:
        f.write(text.encode())

orig_time = filter_module.time
real_os = filterpoll.os
waits = []
# Keep original commonError accounting but never sleep.
filter_module.time = SimpleNamespace(time=MyTime.time, sleep=waits.append)
process_line = poll.processLineAndAdd
since = 0
result = []
for i in range(106):
    MyTime.setTime(start + i)
    if i in (1, 53):
        left.rename(stash)
    elif i in (51, 104):
        stash.rename(left)
        assert left.stat().st_ino == inode
    elif i == 52:
        append(right, healthy)
    elif i == 105:
        append(left, first)
        append(right, failure)
    attempted = []
    def stamp(path):
        assert path in names
        attempted.append(names.index(path))
        try:
            actual = real_os.stat(path)
        except FileNotFoundError as err:
            assert path == names[0] and err.errno == errno.ENOENT
            raise
        return SimpleNamespace(st_mtime=1.0, st_ino=actual.st_ino, st_size=actual.st_size)
    filterpoll.os = SimpleNamespace(stat=stamp)
    try:
        changed = poll.getModified([])
    finally:
        filterpoll.os = real_os
    drains = []
    for path in changed:
        holder = poll.getLog(path)
        trace = []
        def traced(line):
            old = jail.produced
            process_line(line)
            trace.append([holder.tell(), old != jail.produced])
        poll.processLineAndAdd = traced
        assert poll.getFailures(path) is True
        drains.append([names.index(path), holder.getPos(), trace])
    poll.ticks += 1
    if poll.ticks % 10 == 0:
        poll.performSvc()
    before = len(events)
    added = actions._Actions__checkBan() if jail.queue else 0
    since += added
    if not added or since >= actions.banPrecedence:
        n = added * 2
        actions._Actions__checkUnBan(n if n and n < actions.unbanMaxCount else actions.unbanMaxCount)
        since = 0
    state = poll._FilterPoll__file404Cnt
    registry = [([state[name], poll.getLog(name).getPos()] if name in state else None)
                for name in names]
    assert poll.active and not poll.idle
    assert (names[0] in poll.getLogPaths()) == (i < 103)
    assert names[1] in poll.getLogPaths()
    if i in (50, 51, 52, 102, 103, 104, 105):
        assert poll._errors == {50: 50, 51: 50, 52: 25, 102: 75, 103: 76, 104: 76, 105: 38}[i]
    if i >= 103:
        assert (stash if i == 103 else left).stat().st_ino == inode
        assert names[0] not in poll._FilterPoll__prevStats and names[0] not in poll.getPendingPaths()
    result.append([i, attempted, drains, registry, events[before:]])
filter_module.time = orig_time
assert len(waits) == 101 and not violations, violations
print(json.dumps(result))
";

fn require_oracle(rows: &[Value]) {
    let empty = json!([]);
    assert_eq!(rows.len(), 106);
    let cell = |row: usize, column: usize| {
        rows.get(row)
            .and_then(|entry| entry.get(column))
            .expect("known oracle timeline field")
            .clone()
    };
    let left = |row| cell(row, 3).get(0).expect("left registry field").clone();
    assert_eq!(left(50), json!([50, FIRST.len()]));
    assert_eq!(left(51), json!([0, FIRST.len()]));
    assert_eq!(
        cell(51, 2),
        empty,
        "same inode/stamp resets count without reread"
    );
    assert_eq!(
        cell(52, 2),
        json!([[1, HEALTHY.len(), [[HEALTHY.len(), false]]]])
    );
    assert_eq!(left(53), json!([1, FIRST.len()]));
    assert_eq!(left(102), json!([50, FIRST.len()]));
    assert_eq!(
        cell(103, 1),
        json!([0, 1]),
        "51st miss includes its original slot"
    );
    assert_eq!(left(103), Value::Null, "51st miss evicts");
    assert_eq!(cell(104, 1), json!([1]), "restored source is not sampled");
    assert_eq!(cell(104, 2), empty);
    assert_eq!(
        cell(105, 1),
        json!([1]),
        "modified evicted file is not sampled"
    );
    let final_right = HEALTHY.len() + FAILURE.len();
    assert_eq!(
        cell(105, 2),
        json!([[1, final_right, [[final_right, true]]]])
    );
    assert_eq!(cell(105, 4), json!([["ban", "192.0.2.28", START + 105]]));
}

#[test]
#[ignore = "requires a clean Fail2Ban 1.1.1 source via FAIL2BAN_111_SOURCE and Python 3"]
fn original_poll_51st_enoent_evicts_and_unchanged_stat_resets_streak() {
    let source = pinned_source();
    let config = settings(&source);
    let py_scratch = tempfile::tempdir().expect("create temporary Python scratch directory");
    let rs_scratch = tempfile::tempdir().expect("create temporary Rust scratch directory");
    let original = Command::new("python3")
        .args(["-S", "-c", ORACLE])
        .arg(config.path())
        .arg(JAIL)
        .arg(json!([START, FILES, FIRST, HEALTHY, FAILURE]).to_string())
        .current_dir(py_scratch.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .env("PYTHONPATH", source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run original in Python scratch directory");
    assert!(
        original.status.success(),
        "{}",
        String::from_utf8_lossy(&original.stderr)
    );
    let original: Vec<Value> =
        serde_json::from_slice(&original.stdout).expect("decode original eviction timeline");
    require_oracle(&original);
    let rewritten = native(config.path(), rs_scratch.path());
    for (idx, (actual, expected)) in rewritten.iter().zip(&original).enumerate() {
        assert_eq!(actual, expected, "pinned timeline row {idx}");
    }
    assert_eq!(rewritten.len(), original.len());
}
