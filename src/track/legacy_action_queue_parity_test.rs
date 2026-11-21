//! Original Actions.run scheduling with a synchronous fake wait and inert recorder.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::tempdir;

use super::legacy_action_queue::{LegacyActionQueue, Ticket};
use super::legacy_ban_manager::{AddResult, Duration};

const BASE_DURATION: i64 = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct Input(u8, i64, Option<i64>);

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Trace {
    attempted: Vec<(String, i64, String)>,
    expired: Vec<String>,
    sweep_limit: Option<usize>,
    events: Vec<(String, String)>,
}

fn added(range: std::ops::RangeInclusive<u8>, time: i64) -> Vec<(u8, i64, &'static str)> {
    range.map(|id| (id, time, "added")).collect()
}

fn inputs(range: std::ops::RangeInclusive<u8>, time: i64, duration: Option<i64>) -> Vec<Input> {
    range.map(|id| Input(id, time, duration)).collect()
}

fn address(id: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, id))
}

fn events(attempted: &[(String, i64, String)], expired: &[String]) -> Vec<(String, String)> {
    attempted
        .iter()
        .filter(|(_, _, disposition)| disposition == "added")
        .map(|(ip, _, _)| ("ban".to_owned(), ip.clone()))
        .chain(expired.iter().map(|ip| ("unban".to_owned(), ip.clone())))
        .collect()
}

fn expectation(
    attempts: Vec<(u8, i64, &'static str)>,
    limit: Option<usize>,
    expired: &[u8],
) -> Trace {
    let attempted = attempts
        .into_iter()
        .map(|(id, time, disposition)| (address(id).to_string(), time, disposition.to_owned()))
        .collect::<Vec<_>>();
    let expired = expired
        .iter()
        .map(|&id| address(id).to_string())
        .collect::<Vec<_>>();
    Trace {
        events: events(&attempted, &expired),
        attempted,
        expired,
        sweep_limit: limit,
    }
}

struct Frame(i64, Vec<Input>, Trace);
struct Scenario(&'static str, Vec<Frame>);

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario(
            "FIFO batches of ten, strict expiry",
            vec![
                Frame(
                    100,
                    inputs(1..=12, 100, Some(10)),
                    expectation(added(1..=10, 100), Some(20), &[]),
                ),
                Frame(101, vec![], expectation(added(11..=12, 100), None, &[])),
                Frame(110, vec![], expectation(vec![], Some(20), &[])),
                Frame(
                    111,
                    vec![],
                    expectation(vec![], Some(20), &(1..=12).collect::<Vec<_>>()),
                ),
            ],
        ),
        Scenario(
            "successful counts carry across ticks; sweep limit uses last batch only",
            vec![
                Frame(
                    100,
                    inputs(1..=6, 100, Some(5)),
                    expectation(added(1..=6, 100), None, &[]),
                ),
                Frame(104, vec![], expectation(vec![], Some(20), &[])),
                Frame(
                    110,
                    [
                        inputs(20..=25, 110, None),
                        vec![Input(70, 100, Some(2)), Input(20, 110, None)],
                    ]
                    .concat(),
                    expectation(
                        [
                            added(20..=25, 110),
                            vec![(70, 100, "expired"), (20, 110, "duplicate")],
                        ]
                        .concat(),
                        None,
                        &[],
                    ),
                ),
                Frame(
                    111,
                    [inputs(30..=32, 111, None), vec![Input(71, 101, Some(2))]].concat(),
                    expectation(
                        [added(30..=32, 111), vec![(71, 101, "expired")]].concat(),
                        None,
                        &[],
                    ),
                ),
                Frame(
                    112,
                    inputs(40..=41, 112, None),
                    expectation(added(40..=41, 112), Some(4), &[1, 2, 3, 4]),
                ),
                Frame(113, vec![], expectation(vec![], Some(20), &[5, 6])),
            ],
        ),
        Scenario(
            "still-present expired ticket prolongs before a zero-insertion sweep",
            vec![
                Frame(
                    100,
                    inputs(1..=2, 100, Some(4)),
                    expectation(added(1..=2, 100), None, &[]),
                ),
                Frame(
                    106,
                    vec![
                        Input(1, 106, Some(10)),
                        Input(3, 101, Some(4)),
                        Input(1, 106, Some(3)),
                    ],
                    expectation(
                        vec![
                            (1, 106, "prolonged"),
                            (3, 101, "expired"),
                            (1, 106, "duplicate"),
                        ],
                        Some(20),
                        &[2],
                    ),
                ),
                Frame(
                    107,
                    vec![Input(4, 107, Some(-1))],
                    expectation(added(4..=4, 107), None, &[]),
                ),
                Frame(116, vec![], expectation(vec![], Some(20), &[])),
                Frame(117, vec![], expectation(vec![], Some(20), &[1])),
            ],
        ),
        Scenario(
            "idle expiry cap; expiration order uses registration not deadlines",
            vec![
                Frame(
                    100,
                    (1..=23)
                        .map(|id| Input(id, 100, Some(24 - i64::from(id))))
                        .collect(),
                    expectation(added(1..=10, 100), Some(20), &[]),
                ),
                Frame(100, vec![], expectation(added(11..=20, 100), Some(20), &[])),
                Frame(100, vec![], expectation(added(21..=23, 100), None, &[])),
                Frame(
                    124,
                    vec![],
                    expectation(vec![], Some(20), &(1..=20).collect::<Vec<_>>()),
                ),
                Frame(124, vec![], expectation(vec![], Some(20), &[21, 22, 23])),
            ],
        ),
    ]
}

fn native(scenario: &Scenario) -> Vec<Trace> {
    let mut queue = LegacyActionQueue::new(Duration::from_seconds(BASE_DURATION));
    scenario
        .1
        .iter()
        .map(|Frame(now, extra, _)| {
            for &Input(id, time, duration) in extra {
                queue.enqueue(Ticket {
                    ip: address(id),
                    time,
                    duration: duration.map(Duration::from_seconds),
                });
            }
            let result = queue.tick(*now);
            let attempted = result
                .attempted
                .into_iter()
                .map(|(ticket, outcome)| {
                    let disposition = match outcome {
                        AddResult::Added => "added",
                        AddResult::Duplicate => "duplicate",
                        AddResult::Prolonged => "prolonged",
                        AddResult::Expired => "expired",
                    };
                    (ticket.ip.to_string(), ticket.time, disposition.to_owned())
                })
                .collect::<Vec<_>>();
            let expired = result
                .expired
                .into_iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>();
            Trace {
                events: events(&attempted, &expired),
                attempted,
                expired,
                sweep_limit: result.sweep_limit,
            }
        })
        .collect()
}

#[test]
fn legacy_action_queue_ticks_match_golden() {
    for scenario in &scenarios() {
        let mut actual = native(scenario).into_iter();
        for (index, Frame(_, _, trace)) in scenario.1.iter().enumerate() {
            assert_eq!(
                actual.next().as_ref(),
                Some(trace),
                "{} #{index}",
                scenario.0
            );
        }
        assert!(actual.next().is_none());
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_action_queue_ticks_agree_with_fail2ban_111() {
    let scenarios = scenarios();
    let source = pinned_source();
    let original = oracle(&source, &scenarios);
    assert_eq!(original.len(), scenarios.len());
    for (scenario, original) in scenarios.iter().zip(original) {
        assert_eq!(original.len(), scenario.1.len());
        for (index, (trace, Frame(_, _, expected))) in original.iter().zip(&scenario.1).enumerate()
        {
            assert_eq!(trace, expected, "original {} #{index}", scenario.0);
        }
        assert_eq!(native(scenario), original, "Rust {}", scenario.0);
    }
}

fn pinned_source() -> PathBuf {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
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

fn oracle(source: &Path, scenarios: &[Scenario]) -> Vec<Vec<Trace>> {
    const ORACLE: &str = r"
import json
import os
import socket
import subprocess
import sys
import threading
from collections import deque

violations = []
def blocked(*args, **kwargs):
    violations.append('unexpected process, network or service')
    raise AssertionError(violations[-1])
def audit(event, args):
    if event.startswith('socket.') or event in (
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'
    ):
        blocked()
sys.addaudithook(audit)

source, base_duration, scenario_data = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.server.actions import Actions, Observers
from fail2ban.server.ipdns import IPAddr
from fail2ban.server.mytime import MyTime
from fail2ban.server.ticket import FailTicket
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version

Utils.executeCmd = blocked
subprocess.Popen = blocked
os.system = blocked
socket.socket = blocked
threading.Thread.start = blocked
Observers.Main = None

class Queue:
    name = 'offline-fifo'
    database = None
    def __init__(self):
        self.items = deque()
    @property
    def hasFailTickets(self):
        return bool(self.items)
    def getFailTicket(self):
        return self.items.popleft() if self.items else False

class Recorder:
    def __init__(self, logs):
        self.logs = logs
    def start(self):
        pass
    def stop(self):
        pass
    def ban(self, info):
        self.logs[-1]['events'].append(['ban', str(info['ip'])])
    def unban(self, info):
        address = str(info['ip'])
        self.logs[-1]['events'].append(['unban', address])
        self.logs[-1]['expired'].append(address)

answers = []
for frames in json.loads(scenario_data):
    traces = []
    fifo = Queue()
    worker = Actions(fifo)
    worker.active = True
    worker._actions['record-only'] = Recorder(traces)
    worker.banManager.setBanTime(int(base_duration))
    original_add = worker.banManager.addBanTicket
    original_sweep = worker._Actions__checkUnBan

    def recorded_add(ticket, reason):
        accepted = original_add(ticket, reason)
        if accepted:
            disposition = 'added'
        elif reason.get('expired'):
            disposition = 'expired'
        elif reason.get('prolong'):
            disposition = 'prolonged'
        else:
            assert 'ticket' in reason
            disposition = 'duplicate'
        traces[-1]['attempted'].append([str(ticket.getID()), ticket.getTime(), disposition])
        return accepted

    def recorded_sweep(limit):
        traces[-1]['sweep_limit'] = limit
        return original_sweep(limit)

    def skip_shutdown_flush(*, stop):
        # The replay observes active iterations, not process shutdown.
        assert stop and not worker.active

    def fake_wait(condition, timeout):
        if not frames:
            worker.active = False
            return False
        now, extra = frames.pop(0)
        MyTime.setTime(now)
        traces.append({'attempted': [], 'expired': [], 'sweep_limit': None, 'events': []})
        for ident, event_time, duration in extra:
            ticket = FailTicket(IPAddr(f'192.0.2.{ident}'), event_time)
            if duration is not None:
                ticket.setBanTime(duration)
            fifo.items.append(ticket)
        return condition()

    worker.banManager.addBanTicket = recorded_add
    worker._Actions__checkUnBan = recorded_sweep
    worker._Actions__flushBan = skip_shutdown_flush
    Utils.wait_for = fake_wait
    assert Actions.run(worker) is True
    assert not violations, violations
    assert not fifo.items
    answers.append(traces)
print(json.dumps(answers))
";
    let input = scenarios
        .iter()
        .map(|scenario| {
            scenario
                .1
                .iter()
                .map(|Frame(now, extra, _)| json!([now, extra]))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let scratch = tempdir().expect("temporary oracle directory");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(BASE_DURATION.to_string())
        .arg(serde_json::to_string(&input).expect("fixture serialization"))
        .current_dir(scratch.path())
        .output()
        .expect("run original synchronous action iteration oracle");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
