//! Pinned FilterPoll.run idle transitions, with one scripted stat pass per wait.

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

const REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const START: i64 = 1_752_537_600;
const JAIL: &str = "idle-fixture";
const FILES: [&str; 4] = ["charlie.log", "alpha.log", "bravo.log", "delta.log"];
const FIRST: &str = "2025/07/15 00:00:00 [notice] baseline record\n";
const CONFIG: &str = concat!(
    "[idle-fixture]\n",
    "enabled=true\nbackend=polling\nusedns=no\nignoreself=false\nlogtimezone=UTC\n",
    "logpath=/offline/charlie.log\n        /offline/alpha.log\n",
    "        /offline/bravo.log\n        /offline/delta.log\n",
    "filter=nginx-http-auth\nmaxretry=2\nfindtime=10s\nbantime=30s\naction=\n",
);

fn scenario(extra_pad: usize) -> Vec<&'static str> {
    let mut steps = vec!["baseline"];
    steps.extend(std::iter::repeat_n("steady", 7 + extra_pad));
    steps.push("both-away");
    steps.extend(std::iter::repeat_n("both-missing", 48));
    steps.extend([
        "restore-bravo",
        "flip",
        "idle-timeout",
        "resume",
        "restore-alpha",
        "catch-charlie",
        "steady",
        "catch-delta",
    ]);
    steps
}

fn record(elapsed: usize, fail: bool) -> String {
    let msg = if fail {
        "[error] 123#123: *4 user \"example\": password mismatch, client: 192.0.2.41"
    } else {
        "[notice] ordinary record"
    };
    format!(
        "2025/07/15 00:{:02}:{:02} {msg}\n",
        elapsed / 60,
        elapsed % 60
    )
}

fn append(path: &Path, contents: &str) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open scratch source for append")
        .write_all(contents.as_bytes())
        .expect("write scratch records");
}

fn sample(slot: usize, path: &Path) -> PollSlot {
    let sample = match File::open(path) {
        Ok(file) => {
            let stat = file.metadata().expect("read scratch descriptor metadata");
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

fn native(config: &Path, scratch: &Path, steps: &[&str]) -> Vec<Value> {
    let paths = FILES.map(|name| scratch.join(name));
    let [charlie, alpha, bravo, delta] = &paths;
    let stash_a = scratch.join("held-a.log");
    let stash_b = scratch.join("held-b.log");
    let plan = legacy_jail_plan::read(config, JAIL).expect("admit scratch-only config");
    let mut driver = PollCycle::new(plan).expect("create polling fixture");
    for (slot, path) in paths.iter().enumerate() {
        fs::write(path, FIRST).expect("write baseline physical record");
        driver
            .attach(
                slot,
                File::open(path).expect("open scratch descriptor"),
                false,
                None,
                START,
                None,
            )
            .expect("attach to offline poll cycle");
    }
    steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let at = START + i64::try_from(i).expect("scenario index fits timestamp");
            match *step {
                "both-away" => {
                    fs::rename(alpha, &stash_a).expect("temporarily hide alpha scratch source");
                    fs::rename(bravo, &stash_b).expect("temporarily hide bravo scratch source");
                }
                "restore-bravo" => {
                    fs::rename(&stash_b, bravo).expect("restore bravo scratch inode");
                }
                "flip" => {
                    append(charlie, &record(i, true));
                    append(delta, &record(i, false));
                }
                "restore-alpha" => {
                    fs::rename(&stash_a, alpha).expect("restore evicted alpha scratch inode");
                }
                "catch-charlie" => append(charlie, &record(i, true)),
                "catch-delta" => append(delta, &record(i, false)),
                _ => {}
            }
            let (selected, skipped, removed, drains) = match *step {
                "idle-timeout" => {
                    driver.idle_timeout(at).expect("scripted idle timeout");
                    (vec![], vec![], vec![], vec![])
                }
                "resume" => {
                    driver.resume_filter();
                    (vec![], vec![], vec![], vec![])
                }
                _ => {
                    let snapshot = paths
                        .iter()
                        .enumerate()
                        .rev()
                        .filter(|(slot, _)| {
                            driver.is_registered(*slot).expect("known configured slot")
                        })
                        .map(|(slot, path)| sample(slot, path))
                        .collect();
                    let trace = driver
                        .poll_sampled_trace(snapshot, at)
                        .expect("run one active stat pass");
                    let drains = trace
                        .drained
                        .into_iter()
                        .map(|drain| {
                            json!([
                                drain.slot,
                                drain.offset,
                                drain
                                    .lines
                                    .iter()
                                    .map(|line| (line.end_offset, line.queued))
                                    .collect::<Vec<_>>(),
                            ])
                        })
                        .collect::<Vec<_>>();
                    (trace.selected, trace.skipped, trace.removed, drains)
                }
            };
            let registry = [0, 1, 2, 3].map(|slot| {
                driver.is_registered(slot).expect("known slot").then(|| {
                    json!([
                        driver
                            .missing_streak(slot)
                            .expect("known slot")
                            .expect("registered streak"),
                        driver
                            .acknowledged_offset(slot)
                            .expect("registered byte offset"),
                        match driver.phase(slot).expect("registered phase") {
                            FilePhase::Initial => "initial",
                            FilePhase::Live => "live",
                        },
                    ])
                })
            });
            let effects = driver
                .tick(at)
                .expect("independent recording-only action phase")
                .into_iter()
                .map(|effect| match effect {
                    ReplayDecision::Ban { ip, at } => json!(["ban", ip.to_string(), at]),
                    ReplayDecision::Unban { ip, at } => json!(["unban", ip.to_string(), at]),
                })
                .collect::<Vec<_>>();
            json!([
                step,
                selected,
                skipped,
                removed,
                drains,
                registry,
                driver.filter_errors(),
                driver.filter_idle(),
                driver.maintenance_counts(),
                driver
                    .maintenance_trace()
                    .iter()
                    .map(|(at, _)| at)
                    .collect::<Vec<_>>(),
                effects,
            ])
        })
        .collect()
}

fn original_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate pinned Python checkout");
    let git = |args: &[&str]| {
        let res = Command::new("git")
            .args(args)
            .current_dir(&source)
            .output()
            .expect("check original revision");
        assert!(
            res.status.success(),
            "{}",
            String::from_utf8_lossy(&res.stderr)
        );
        String::from_utf8(res.stdout).expect("decode pinned git output")
    };
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), REV);
    assert!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "config",
            "fail2ban"
        ])
        .is_empty()
    );
    source
}

fn settings(source: &Path) -> TempDir {
    let config = tempfile::tempdir().expect("create private fixture config");
    let filters = config.path().join("filter.d");
    fs::write(config.path().join("jail.conf"), CONFIG).expect("write fixture jail config");
    fs::create_dir(&filters).expect("create fixture filter folder");
    for name in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config/filter.d").join(name),
            filters.join(name),
        )
        .expect("copy pinned filter");
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

start, labels, first, steps = json.loads(sys.argv[3])
reader = JailReader(sys.argv[2], basedir=sys.argv[1])
assert reader.read() and reader.getOptions() and reader.isEnabled()
settings = reader.options
assert settings['backend'] == 'polling' and settings['action'] == ''
assert settings['usedns'] == 'no' and settings['ignoreself'] is False and not settings.get('ignorecommand')
assert settings['logpath'].splitlines() == ['/offline/' + label for label in labels]
rules = reader.filter.getCombined()

class QueueJail:
    name = 'offline-idle'
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
charlie, alpha, bravo, delta = paths = [root / label for label in labels]
names = list(map(str, paths))
held_a, held_b = root / 'held-a.log', root / 'held-b.log'
for path in paths:
    path.write_bytes(first.encode())
    poll.addLogPath(str(path), tail=False, autoSeek=False)
inode_a, inode_b = alpha.stat().st_ino, bravo.stat().st_ino

def append(path, time_index, fail):
    msg = ('[error] 123#123: *4 user \x22example\x22: password mismatch, client: 192.0.2.41'
           if fail else '[notice] ordinary record')
    with path.open('ab') as writer:
        record = '2025/07/15 00:%02d:%02d %s\n' % (time_index // 60, time_index % 60, msg)
        writer.write(record.encode())

actions = Actions(jail)
actions.banManager.setBanTime(MyTime.str2seconds(settings['bantime']))
effects = []
class RecordingSink:
    def ban(self, info):
        effects.append(['ban', str(info['ip']), MyTime.time()])
    def unban(self, info):
        effects.append(['unban', str(info['ip']), MyTime.time()])
actions._actions['record-only'] = RecordingSink()

trace = []
recording = None
next_step = 0
since = 0
service = []
service_requests = []
sleeps = []
real_time = filter_module.time
real_os = filterpoll.os
original_wait = Utils.wait_for
original_modified = poll.getModified
original_read = poll.getFailures
original_process = poll.processLineAndAdd
original_service = poll.performSvc
original_delete = poll.delLogPath

def stat(path):
    assert path in names, path
    try:
        actual = real_os.stat(path)
    except FileNotFoundError as err:
        assert path in (names[1], names[2]) and err.errno == errno.ENOENT
        raise
    return SimpleNamespace(st_mtime=1.0, st_ino=actual.st_ino, st_size=actual.st_size)

def observe_modified(modlst):
    assert recording[0] not in ('idle-timeout', 'resume')
    assert not modlst
    filterpoll.os = SimpleNamespace(stat=stat)
    try:
        selected = original_modified(modlst)
    finally:
        filterpoll.os = real_os
    recording[1].extend(names.index(path) for path in selected)
    return selected

def observe_delete(path):
    assert path in names
    recording[3].append(names.index(path))
    return original_delete(path)

def observe_read(path):
    holder = poll.getLog(path)
    read_trace = []
    def observe_process(line):
        previous = jail.produced
        original_process(line)
        read_trace.append([holder.tell(), previous != jail.produced])
    poll.processLineAndAdd = observe_process
    try:
        drained = original_read(path)
    finally:
        poll.processLineAndAdd = original_process
    if drained:
        recording[4].append([names.index(path), holder.getPos(), read_trace])
    else:
        assert poll.idle and not read_trace
        recording[2].append(names.index(path))
    return drained

def observe_service():
    service_requests.append(poll.ticks)
    before = poll._Filter__nextSvcTime
    original_service()
    if poll._Filter__nextSvcTime != before:
        service.append(MyTime.time())

def finalize():
    global since
    if recording is None:
        return
    before = len(effects)
    assert not actions.idle
    added = actions._Actions__checkBan() if jail.queue else 0
    since += added
    if not added or since >= actions.banPrecedence:
        n = added * 2
        actions._Actions__checkUnBan(n if n and n < actions.unbanMaxCount else actions.unbanMaxCount)
        since = 0
    registry = []
    counts = poll._FilterPoll__file404Cnt
    for name in names:
        holder = poll.getLog(name)
        registry.append([counts[name], holder.getPos(), 'live' if holder.inOperation else 'initial']
                        if holder else None)
    trace.append(recording + [registry, poll._errors, poll.idle,
                               [poll.procLines % 100, poll.ticks % 10],
                               list(service), effects[before:]])

def wait(predicate, timeout, *args, **kwargs):
    global next_step, recording
    assert poll.active
    finalize()
    if next_step == len(steps):
        assert not poll.idle
        poll.active = False
        return predicate()
    i = next_step
    next_step += 1
    step = steps[i]
    recording = [step, [], [], [], []]
    MyTime.setTime(start + i)
    idle_wait = step in ('idle-timeout', 'resume')
    assert (timeout == poll.sleeptime * 10 and poll.idle) if idle_wait else (timeout == poll.sleeptime and not poll.idle)
    if step == 'idle-timeout':
        assert not predicate()
        return False
    if step == 'resume':
        poll.idle = False
        assert predicate()
        return True
    if step == 'both-away':
        alpha.rename(held_a)
        bravo.rename(held_b)
    elif step == 'restore-bravo':
        held_b.rename(bravo)
        assert bravo.stat().st_ino == inode_b
    elif step == 'flip':
        append(charlie, i, True)
        append(delta, i, False)
    elif step == 'restore-alpha':
        held_a.rename(alpha)
        assert alpha.stat().st_ino == inode_a
    elif step == 'catch-charlie':
        append(charlie, i, True)
    elif step == 'catch-delta':
        append(delta, i, False)
    # Exactly one stat pass in this supported active wait.
    return predicate()

filter_module.time = SimpleNamespace(time=MyTime.time, sleep=sleeps.append)
poll.getModified = observe_modified
poll.getFailures = observe_read
poll.performSvc = observe_service
poll.delLogPath = observe_delete
Utils.wait_for = staticmethod(wait)
try:
    assert filterpoll.FilterPoll.run(poll)
finally:
    filter_module.time = real_time
    Utils.wait_for = staticmethod(original_wait)
assert next_step == len(steps) and len(trace) == next_step
assert len(sleeps) == 100 and not violations, violations
periodic = [10, 20, 30, 40, 50, 60] if steps.index('flip') == 59 else [10, 20, 30, 40, 50]
assert service_requests == periodic + [steps.index('catch-charlie') - 1], service_requests
print(json.dumps(trace))
";

fn checked(value: &Value, idx: usize) -> &Value {
    value.get(idx).expect("known row field")
}

fn require_reference(rows: &[Value], steps: &[&str]) {
    let find = |step| {
        rows.get(
            steps
                .iter()
                .position(|candidate| *candidate == step)
                .expect("scenario step"),
        )
        .expect("known scenario row")
    };
    let flip = find("flip");
    let previous = find("restore-bravo");
    assert_eq!(checked(previous, 6), &json!(99));
    assert_eq!(
        checked(checked(previous, 5), 1),
        &json!([50, FIRST.len(), "live"])
    );
    assert_eq!(checked(flip, 1), &json!([0, 3]));
    assert_eq!(checked(flip, 2), &json!([0, 3]));
    assert_eq!(checked(flip, 3), &json!([1]));
    assert_eq!(checked(flip, 4), &json!([]));
    assert_eq!(checked(checked(flip, 5), 1), &Value::Null);
    assert_eq!(
        checked(checked(flip, 5), 0),
        &json!([0, FIRST.len(), "live"])
    );
    assert_eq!(
        checked(checked(flip, 5), 3),
        &json!([0, FIRST.len(), "live"])
    );
    assert_eq!(checked(flip, 6), &json!(50));
    assert_eq!(checked(flip, 7), &json!(true));
    let idle = find("idle-timeout");
    let resume = find("resume");
    assert_eq!(checked(idle, 6), &json!(50));
    assert_eq!(checked(idle, 7), &json!(true));
    assert_eq!(
        checked(idle, 9),
        checked(flip, 9),
        "idle timeout cannot run service"
    );
    assert_eq!(
        checked(resume, 8),
        checked(idle, 8),
        "resume does not advance ticks"
    );
    assert_eq!(checked(resume, 6), &json!(50));
    assert_eq!(checked(resume, 7), &json!(false));
    let restored = find("restore-alpha");
    assert_eq!(
        checked(restored, 1),
        &json!([]),
        "retained successful stamps and no implicit reattach"
    );
    assert_eq!(checked(restored, 6), &json!(50));
    let recovered = find("catch-charlie");
    let prefix = FIRST.len() + record(0, true).len();
    let end = prefix + record(0, true).len();
    assert_eq!(
        checked(recovered, 4),
        &json!([[0, end, [[prefix, false], [end, true]]]])
    );
    assert_eq!(checked(recovered, 6), &json!(12));
    assert_eq!(
        checked(checked(recovered, 5), 3),
        &json!([0, FIRST.len(), "live"])
    );
    let effects = checked(recovered, 10).as_array().expect("recorded effects");
    let effect = effects.first().expect("one recording-only ban");
    assert_eq!(checked(effect, 1), &json!("192.0.2.41"));
    assert_eq!(effects.len(), 1);
    let delta = find("catch-delta");
    let prefix = FIRST.len() + record(0, false).len();
    let end = prefix + record(0, false).len();
    assert_eq!(
        checked(delta, 4),
        &json!([[3, end, [[prefix, false], [end, false]]]])
    );
    assert_eq!(checked(delta, 6), &json!(3));
    assert_eq!(checked(delta, 10), &json!([]));
}

#[test]
#[ignore = "requires a clean Fail2Ban 1.1.1 source via FAIL2BAN_111_SOURCE and Python 3"]
fn original_active_to_idle_poll_skips_then_resumes_without_reset() {
    let source = original_source();
    let config = settings(&source);
    for pad in [0, 1] {
        let steps = scenario(pad);
        let py_scratch = tempfile::tempdir().expect("private original scratch logs");
        let rust_scratch = tempfile::tempdir().expect("private rewritten scratch logs");
        let result = Command::new("python3")
            .args(["-S", "-c", ORACLE])
            .arg(config.path())
            .arg(JAIL)
            .arg(json!([START, FILES, FIRST, steps]).to_string())
            .current_dir(py_scratch.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TZ", "UTC")
            .env("PYTHONPATH", &source)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("run pinned Python with scratch files only");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let original: Vec<Value> =
            serde_json::from_slice(&result.stdout).expect("decode pinned timeline");
        require_reference(&original, &steps);
        let rewritten = native(config.path(), rust_scratch.path(), &steps);
        assert_eq!(rewritten.len(), original.len());
        for (i, (actual, expected)) in rewritten.iter().zip(&original).enumerate() {
            assert_eq!(actual, expected, "timeline row {i}, extra pad {pad}");
        }
    }
}
