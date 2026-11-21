//! Pinned synchronous FilePoll failure-maintenance boundaries on scratch only.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::config::legacy_jail_plan;
use crate::detect::legacy_poll_stamp::PollStamp;
use crate::legacy_jail_replay::ReplayDecision;
use crate::legacy_poll_cycle::{PollCycle, PollInput};

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const MIDNIGHT: i64 = 1_752_537_600;
const JAIL: &str = "maintenance-fixture";
const LABELS: [&str; 2] = ["zeta.log", "alpha.log"];
const WATCHED: [&str; 2] = ["192.0.2.40", "192.0.2.41"]; // E, K
const GATE_IP: &str = "192.0.2.42";
const IGNORED_IP: &str = "198.51.100.77";
const CONFIG: &str = concat!(
    "[maintenance-fixture]\n",
    "enabled=true\nbackend=polling\nusedns=no\nignoreself=false\nlogtimezone=UTC\n",
    "logpath=/offline/zeta.log\n        /offline/alpha.log\n",
    "filter=nginx-http-auth\nmaxretry=2\nfindtime=10s\nbantime=30s\n",
    "ignoreip=198.51.100.77\naction=\n",
);

struct Step {
    name: &'static str,
    at: i64,
    append: [String; 2],
    worker: bool,
}

fn finding(seconds: u8, user: &str, address: &str) -> String {
    format!(
        "2025/07/15 00:{:02}:{:02} [error] 123#123: *4 user \"{user}\": password mismatch, client: {address}\n",
        seconds / 60,
        seconds % 60
    )
}

fn no_change() -> [String; 2] {
    [String::new(), String::new()]
}

fn step(name: &'static str, seconds: u8, append: [String; 2]) -> Step {
    Step {
        name,
        at: MIDNIGHT + i64::from(seconds),
        append,
        worker: false,
    }
}

fn scenarios() -> Vec<(&'static str, Vec<Step>)> {
    let empty = String::new();
    let [e, k] = WATCHED;
    let mut bulk = (20..=110)
        .map(|host| finding(106, "example", &format!("203.0.113.{host}")))
        .collect::<String>();
    bulk += "unrelated fixture notice\n";
    bulk += &finding(106, "skip-this", "198.51.100.78"); // regex ignore
    bulk += &finding(106, "example", IGNORED_IP); // IP ignore
    let mut main = vec![
        step(
            "stale-and-E",
            99,
            [
                finding(88, "example", e) + &finding(99, "example", e),
                empty.clone(),
            ],
        ),
        step("hold-K", 100, [empty.clone(), finding(100, "example", k)]),
        step(
            "threshold-service",
            105,
            [finding(105, "example", GATE_IP).repeat(2), empty.clone()],
        ),
        step("fill-to-99-processed", 106, [empty.clone(), bulk]),
        step("unchanged-5", 107, no_change()),
        step("unchanged-6", 107, no_change()),
        step("unchanged-7", 108, no_change()),
        step("unchanged-8", 108, no_change()),
        step("unchanged-9", 109, no_change()),
        step("tenth-poll-suppressed", 109, no_change()),
        step(
            "nonfinding-100-runs-service",
            110,
            [
                empty.clone(),
                "another unrelated fixture notice\n".to_owned(),
            ],
        ),
        step(
            "first-retry-for-K",
            110,
            [finding(110, "example", k), empty.clone()],
        ),
        step(
            "second-retry-for-K-enqueues",
            110,
            [empty.clone(), finding(110, "example", k)],
        ),
        Step {
            name: "worker-drains-in-FIFO-order",
            at: MIDNIGHT + 110,
            append: no_change(),
            worker: true,
        },
    ];
    for (name, at) in [
        ("unchanged-14", 111),
        ("unchanged-15", 112),
        ("unchanged-16", 113),
        ("unchanged-17", 114),
        ("unchanged-18", 115),
        ("unchanged-19", 116),
        ("twentieth-poll-runs-service", 117),
    ] {
        main.push(step(name, at, no_change()));
    }
    let both_on_100 = vec![
        step(
            "held-at-99-processed",
            99,
            [
                finding(90, "example", GATE_IP) + &"ordinary ignored fixture note\n".repeat(98),
                empty.clone(),
            ],
        ),
        step(
            "threshold-at-100-before-cleanup",
            100,
            [empty, finding(90, "example", GATE_IP)],
        ),
        Step {
            name: "worker-records-qualifying-ticket",
            at: MIDNIGHT + 100,
            append: no_change(),
            worker: true,
        },
    ];
    let idle_enough = (0..10)
        .map(|at| step("empty-active-poll", at, no_change()))
        .collect();
    vec![
        ("shared-maintenance-gate", main),
        ("threshold-and-line-cadence-same-record", both_on_100),
        ("first-tenth-poll-on-empty-fixtures", idle_enough),
    ]
}

fn effect(decision: ReplayDecision) -> Value {
    match decision {
        ReplayDecision::Ban { ip, at } => json!(["ban", ip.to_string(), at]),
        ReplayDecision::Unban { ip, at } => json!(["unban", ip.to_string(), at]),
    }
}

fn native(config: &Path, scenario: &str, steps: &[Step]) -> Value {
    let scratch = tempfile::tempdir().expect("isolated native scratch logs");
    let log_paths = LABELS.map(|name| scratch.path().join(name));
    let plan = legacy_jail_plan::read(config, JAIL).expect("admit scratch jail");
    let mut driver = PollCycle::new(plan).expect("one scratch polling jail");
    for (slot, path) in log_paths.iter().enumerate() {
        fs::write(path, b"").expect("create empty synthetic fixture");
        driver
            .attach(
                slot,
                File::open(path).expect("open synthetic file"),
                false,
                None,
                MIDNIGHT,
                None,
            )
            .expect("attach scratch file");
    }
    let watched = WATCHED.map(|text| text.parse::<IpAddr>().expect("example IP address"));
    let rows = steps
        .iter()
        .map(|step| {
            let mut queue_signals = Vec::new();
            let mut effects = Vec::new();
            if step.worker {
                effects.extend(
                    driver
                        .tick(step.at)
                        .expect("run a recording worker tick")
                        .into_iter()
                        .map(effect),
                );
            } else {
                for (path, bytes) in log_paths.iter().zip(&step.append) {
                    if !bytes.is_empty() {
                        OpenOptions::new()
                            .append(true)
                            .open(path)
                            .expect("append synthetic input")
                            .write_all(bytes.as_bytes())
                            .expect("write only scratch");
                    }
                }
                let snapshot = log_paths
                    .iter()
                    .enumerate()
                    .rev()
                    .map(|(slot, path)| {
                        let file = File::open(path).expect("open only a synthetic fixture");
                        let stat = file.metadata().expect("scratch metadata");
                        PollInput {
                            slot,
                            stamp: PollStamp {
                                mtime: 1.0,
                                inode: stat.ino(),
                                size: stat.len(),
                            },
                            file,
                        }
                    })
                    .collect::<Vec<_>>();
                for selected in driver
                    .poll(snapshot, step.at)
                    .expect("drain synthetic filter scan")
                {
                    queue_signals.extend(
                        selected
                            .lines
                            .into_iter()
                            .filter(|line| line.queued)
                            .map(|line| json!([selected.slot, line.end_offset])),
                    );
                }
            }
            json!([
                step.name,
                driver.maintenance_counts(),
                driver.maintenance_trace(),
                watched.map(|ip| driver.failure_retry(ip)),
                queue_signals,
                effects,
            ])
        })
        .collect::<Vec<_>>();
    json!([scenario, rows])
}

fn source() -> PathBuf {
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
        "config",
        "fail2ban",
    ]);
    assert!(
        status.is_empty(),
        "unchanged original checkout required: {status}"
    );
    source
}

fn config(source: &Path) -> TempDir {
    let result = tempfile::tempdir().expect("private scratch configuration");
    fs::write(result.path().join("jail.conf"), CONFIG).expect("write scratch jail settings");
    let filter = result.path().join("filter.d");
    fs::create_dir(&filter).expect("scratch filters");
    for name in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(source.join("config/filter.d").join(name), filter.join(name))
            .expect("copy pinned stock filter");
    }
    fs::write(
        filter.join("nginx-http-auth.local"),
        "[Definition]\nignoreregex=^user \"skip-this\": password mismatch$\n",
    )
    .expect("scenario's synthetic ignore rule");
    result
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
from fail2ban.server.ipdns import IPAddr
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

base, name, supplied = sys.argv[1:]
labels, watched, scenarios = json.loads(supplied)
reader = JailReader(name, basedir=base)
assert reader.read() and reader.getOptions() and reader.isEnabled()
settings = reader.options
assert settings['backend'] == 'polling'
assert settings['action'] == '' and not settings.get('ignorecommand')
assert settings['ignoreself'] is False and settings['usedns'] == 'no'
assert settings['logpath'].splitlines() == ['/offline/' + n for n in labels]
rules = reader.filter.getCombined()

class ScratchJail:
    name = 'offline-maintenance'
    database = None
    def __init__(self):
        self.queue = deque()
        self.produced = 0
    def putFailTicket(self, ticket):
        self.queue.append(ticket)
        self.produced += 1
    def getFailTicket(self):
        return self.queue.popleft() if self.queue else False

out = []
for scenario, steps in scenarios:
    paths = [Path.cwd() / (scenario + '-' + label) for label in labels]
    jail = ScratchJail()
    poll = filterpoll.FilterPoll(jail)
    poll.active = True
    poll.ignoreSelf = settings['ignoreself']
    poll.setUseDns(settings['usedns'])
    poll.setLogEncoding('UTF-8')
    poll.setLogTimeZone(settings['logtimezone'])
    poll.setFindTime(settings['findtime'])
    poll.setMaxRetry(settings['maxretry'])
    poll.addIgnoreIP(settings['ignoreip'])
    poll.prefRegex = rules['prefregex']
    poll.setDatePattern(rules['datepattern'])
    for rule in (rules.get('failregex') or '').splitlines():
        if rule:
            poll.addFailRegex(rule)
    for rule in (rules.get('ignoreregex') or '').splitlines():
        if rule:
            poll.addIgnoreRegex(rule)
    for path in paths:
        path.write_bytes(b'')
        poll.addLogPath(str(path), tail=False, autoSeek=False)
    by_path = {str(path): slot for slot, path in enumerate(paths)}

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
    cleanup_tape = []
    original_cleanup = poll.failManager.cleanup
    def cleanup(now):
        before = poll.failManager.size()
        original_cleanup(now)
        cleanup_tape.append([now, before - poll.failManager.size()])
    poll.failManager.cleanup = cleanup

    process = poll.processLineAndAdd
    rows = []
    for label, now, appends, worker in steps:
        MyTime.setTime(now)
        queue_signals = []
        before_events = len(events)
        if worker:
            added = actions._Actions__checkBan() if jail.queue else 0
            since += added
            if not added or since >= actions.banPrecedence:
                n = added * 2
                limit = n if n and n < actions.unbanMaxCount else actions.unbanMaxCount
                actions._Actions__checkUnBan(limit)
                since = 0
        else:
            for path, text in zip(paths, appends):
                if text:
                    with path.open('ab') as writer:
                        writer.write(text.encode('utf-8'))
            stamps = {}
            for path in paths:
                metadata = path.stat()
                stamps[str(path)] = SimpleNamespace(st_ino=metadata.st_ino, st_size=metadata.st_size, st_mtime=1.0)
            original_os = filterpoll.os
            filterpoll.os = SimpleNamespace(stat=lambda path: stamps[path])
            try:
                changed = poll.getModified([])
            finally:
                filterpoll.os = original_os
            for filename in changed:
                slot = by_path[filename]
                container = poll.getLog(filename)
                def trace(line):
                    prior = jail.produced
                    process(line)
                    assert 0 <= jail.produced - prior <= 1
                    if jail.produced != prior:
                        queue_signals.append([slot, container.tell()])
                poll.processLineAndAdd = trace
                assert poll.getFailures(filename) is True
            # Extracted directly from FilterPoll.run. This is the successful
            # active/non-idle branch, with no wait or thread start.
            poll.ticks += 1
            if poll.ticks % 10 == 0:
                poll.performSvc()
            assert len(events) == before_events

        active = poll.failManager._FailManager__failList
        retries = [active[IPAddr(ip)].getRetry() if IPAddr(ip) in active else None for ip in watched]
        if label == 'fill-to-99-processed':
            assert poll.procLines == 99 and poll.failManager.getFailTotal() == 95
        if label == 'nonfinding-100-runs-service':
            assert poll.procLines == 100 and poll.failManager.getFailTotal() == 95
        rows.append([label, [poll.procLines % 100, poll.ticks % 10], cleanup_tape.copy(),
                     retries, queue_signals, events[before_events:]])
    out.append([scenario, rows])
assert not violations, violations
print(json.dumps(out))
";

fn claim_reference(main: &Value, same_record: &Value) {
    let locate = |scenario: &Value, name: &str| {
        scenario
            .get(1)
            .and_then(Value::as_array)
            .expect("scenario rows")
            .iter()
            .find(|row| row.get(0).and_then(Value::as_str) == Some(name))
            .expect("specific scenario row")
            .clone()
    };
    let tape_105 = json!([[MIDNIGHT + 105, 0]]);
    let tape_110 = json!([[MIDNIGHT + 105, 0], [MIDNIGHT + 110, 2]]);
    let tenth = locate(main, "tenth-poll-suppressed");
    assert_eq!(tenth.get(1), Some(&json!([99, 0])));
    assert_eq!(tenth.get(2), Some(&tape_105));
    assert_eq!(tenth.get(3), Some(&json!([1, 1])));
    let nonfinding = locate(main, "nonfinding-100-runs-service");
    assert_eq!(nonfinding.get(1), Some(&json!([0, 1])));
    assert_eq!(nonfinding.get(2), Some(&tape_110));
    assert_eq!(nonfinding.get(3), Some(&json!([null, null])));
    assert_eq!(nonfinding.get(4), Some(&json!([])));
    let first_k = locate(main, "first-retry-for-K");
    assert_eq!(first_k.get(3), Some(&json!([null, 1])));
    assert_eq!(first_k.get(4), Some(&json!([])));
    let second_k = locate(main, "second-retry-for-K-enqueues");
    assert_eq!(
        second_k.get(4).and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    assert_eq!(second_k.get(5), Some(&json!([])));
    let worker = locate(main, "worker-drains-in-FIFO-order");
    assert_eq!(worker.get(2), Some(&tape_110));
    assert_eq!(
        worker.get(5),
        Some(&json!([
            ["ban", GATE_IP, MIDNIGHT + 110],
            ["ban", WATCHED[1], MIDNIGHT + 110]
        ]))
    );
    let twentieth = locate(main, "twentieth-poll-runs-service");
    assert_eq!(twentieth.get(1), Some(&json!([2, 0])));
    assert_eq!(
        twentieth.get(2),
        Some(&json!([
            [MIDNIGHT + 105, 0],
            [MIDNIGHT + 110, 2],
            [MIDNIGHT + 117, 91]
        ]))
    );

    let same_line = locate(same_record, "threshold-at-100-before-cleanup");
    assert_eq!(same_line.get(1), Some(&json!([0, 2])));
    assert_eq!(same_line.get(2), Some(&json!([[MIDNIGHT + 100, 0]])));
    assert_eq!(
        same_line.get(4).and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    let final_tick = locate(same_record, "worker-records-qualifying-ticket");
    assert_eq!(
        final_tick.get(5),
        Some(&json!([["ban", GATE_IP, MIDNIGHT + 100]]))
    );
}

#[test]
#[ignore = "requires clean Fail2Ban 1.1.1 source via FAIL2BAN_111_SOURCE and Python 3"]
fn original_file_maintenance_shared_clock_and_decisions_match() {
    let source = source();
    let settings = config(&source);
    let python_scratch = tempfile::tempdir().expect("synthetic original logs");
    let fixtures = scenarios();
    let payload = fixtures
        .iter()
        .map(|(name, steps)| {
            let steps = steps
                .iter()
                .map(|step| json!([step.name, step.at, step.append, step.worker]))
                .collect::<Vec<_>>();
            json!([name, steps])
        })
        .collect::<Vec<_>>();
    let result = Command::new("python3")
        .args(["-S", "-c", ORACLE])
        .arg(settings.path())
        .arg(JAIL)
        .arg(json!([LABELS, WATCHED, payload]).to_string())
        .current_dir(python_scratch.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run pinned original on synthetic files only");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> =
        serde_json::from_slice(&result.stdout).expect("original comparison rows");
    assert_eq!(original.len(), 3, "independent oracle scenarios");
    claim_reference(
        original.first().expect("main scenario"),
        original.get(1).expect("same-record scenario"),
    );
    let empty = original
        .get(2)
        .and_then(|item| item.get(1))
        .and_then(Value::as_array)
        .expect("empty-poll trace");
    assert_eq!(empty.len(), 10);
    for row in empty.iter().take(9) {
        assert_eq!(row.get(2), Some(&json!([])));
    }
    let tenth = empty.last().expect("the tenth empty poll");
    assert_eq!(tenth.get(1), Some(&json!([0, 0])));
    assert_eq!(tenth.get(2), Some(&json!([[MIDNIGHT + 9, 0]])));
    assert_eq!(tenth.get(5), Some(&json!([])));
    let ours = fixtures
        .iter()
        .map(|(name, steps)| native(settings.path(), name, steps))
        .collect::<Vec<_>>();
    assert_eq!(ours, original);
}
