//! Original CommandAction lifecycle verified only with a recording executor.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;

use super::legacy_action_lifecycle::{Family, Lifecycle, Step, StepKind};

type Call = (
    &'static str,
    Option<u8>,
    &'static [&'static str],
    bool,
    &'static [&'static str],
);

struct Scenario {
    name: &'static str,
    start_on_demand: bool,
    explicit_repair: bool,
    repair_on_unban: bool,
    calls: &'static [Call],
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "eager order, and successful flush clears items",
        start_on_demand: false,
        explicit_repair: true,
        repair_on_unban: false,
        calls: &[
            ("start", None, &[], true, &["start4", "start6"]),
            ("unban", Some(4), &[], true, &[]),
            ("ban", Some(6), &[], true, &["ban6"]),
            ("ban", Some(4), &[], true, &["ban4"]),
            ("unban", Some(4), &[], true, &["unban4"]),
            ("flush", None, &[], true, &["flush4", "flush6"]),
            ("unban", Some(4), &[], true, &[]),
            ("stop", None, &[], true, &["stop4", "stop6"]),
        ],
    },
    Scenario {
        name: "on-demand order follows first successful start",
        start_on_demand: true,
        explicit_repair: true,
        repair_on_unban: false,
        calls: &[
            ("start", None, &[], true, &[]),
            ("ban", Some(6), &[], true, &["start6", "ban6"]),
            ("ban", Some(6), &[], true, &["ban6"]),
            ("ban", Some(4), &[], true, &["start4", "ban4"]),
            ("unban", Some(6), &[], true, &["unban6"]),
            ("flush", None, &[], true, &["flush6", "flush4"]),
            ("stop", None, &[], true, &["stop6", "stop4"]),
        ],
    },
    Scenario {
        name: "start retries, ban checks after failure, default unban does not repair",
        start_on_demand: true,
        explicit_repair: true,
        repair_on_unban: false,
        calls: &[
            ("ban", Some(6), &["start6"], false, &["start6"]),
            (
                "ban",
                Some(6),
                &["ban6", "check6"],
                true,
                &["start6", "ban6", "check6", "repair6", "check6", "ban6"],
            ),
            (
                "unban",
                Some(6),
                &["unban6", "check6"],
                false,
                &["unban6", "check6"],
            ),
            (
                "ban",
                Some(4),
                &["ban4"],
                true,
                &["start4", "ban4", "check4", "ban4"],
            ),
            ("stop", None, &[], true, &["stop6", "stop4"]),
        ],
    },
    Scenario {
        name: "opt-in unban repair clears items; failed repair clears start",
        start_on_demand: true,
        explicit_repair: true,
        repair_on_unban: true,
        calls: &[
            ("ban", Some(4), &[], true, &["start4", "ban4"]),
            (
                "unban",
                Some(4),
                &["unban4", "check4"],
                true,
                &["unban4", "check4", "repair4", "check4", "unban4"],
            ),
            ("unban", Some(4), &[], true, &[]),
            (
                "ban",
                Some(4),
                &["ban4", "check4", "repair4"],
                false,
                &["ban4", "check4", "repair4"],
            ),
            ("ban", Some(4), &[], true, &["start4", "ban4"]),
            ("stop", None, &[], true, &["stop4"]),
        ],
    },
    Scenario {
        name: "fallback restart tolerates stop failure",
        start_on_demand: true,
        explicit_repair: false,
        repair_on_unban: false,
        calls: &[
            ("ban", Some(4), &[], true, &["start4", "ban4"]),
            (
                "ban",
                Some(4),
                &["ban4", "check4", "stop4"],
                true,
                &["ban4", "check4", "stop4", "start4", "check4", "ban4"],
            ),
            ("flush", None, &[], true, &["flush4"]),
            ("stop", None, &[], true, &["stop4"]),
        ],
    },
    Scenario {
        name: "failed second check leaves started; failed flush retains; stop forgets",
        start_on_demand: true,
        explicit_repair: true,
        repair_on_unban: false,
        calls: &[
            (
                "ban",
                Some(4),
                &["ban4", "check4", "check4"],
                false,
                &["start4", "ban4", "check4", "repair4", "check4"],
            ),
            ("ban", Some(4), &[], true, &["ban4"]),
            ("unban", Some(4), &[], true, &["unban4"]),
            ("flush", None, &["flush4"], false, &["flush4"]),
            ("unban", Some(4), &[], true, &["unban4"]),
            ("stop", None, &["stop4"], false, &["stop4"]),
            ("stop", None, &[], true, &[]),
            ("ban", Some(4), &[], true, &["start4", "ban4"]),
        ],
    },
    Scenario {
        name: "eager start continues after failure; eager ban does not auto-start",
        start_on_demand: false,
        explicit_repair: true,
        repair_on_unban: false,
        calls: &[
            ("start", None, &["start4"], false, &["start4", "start6"]),
            ("unban", Some(4), &[], true, &[]),
            ("ban", Some(4), &[], true, &["ban4"]),
            ("flush", None, &[], true, &["flush4"]),
            ("stop", None, &[], true, &["stop6", "stop4"]),
        ],
    },
    Scenario {
        name: "flush and stop each continue across families after failure",
        start_on_demand: true,
        explicit_repair: true,
        repair_on_unban: false,
        calls: &[
            ("ban", Some(4), &[], true, &["start4", "ban4"]),
            ("ban", Some(6), &[], true, &["start6", "ban6"]),
            ("flush", None, &["flush4"], false, &["flush4", "flush6"]),
            ("unban", Some(4), &[], true, &["unban4"]),
            ("unban", Some(6), &[], true, &[]),
            ("stop", None, &["stop4"], false, &["stop4", "stop6"]),
            ("stop", None, &[], true, &[]),
        ],
    },
];

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Trace(bool, Vec<String>);

fn native(scenario: &Scenario) -> Vec<Trace> {
    let mut action = Lifecycle::new(
        scenario.start_on_demand,
        vec![Family::Ipv4, Family::Ipv6],
        true,
        scenario.repair_on_unban,
    );
    scenario
        .calls
        .iter()
        .map(|&(operation, family, injected_failures, _, _)| {
            let mut failed = injected_failures.iter().peekable();
            let mut commands = Vec::new();
            let mut executor = |step: Step| {
                let name = match step.kind {
                    StepKind::Start => "start",
                    StepKind::Ban => "ban",
                    StepKind::Unban => "unban",
                    StepKind::Check => "check",
                    StepKind::Repair if !scenario.explicit_repair => return None,
                    StepKind::Repair => "repair",
                    StepKind::Flush => "flush",
                    StepKind::Stop => "stop",
                };
                let suffix = match step.family {
                    Family::Ipv4 => "4",
                    Family::Ipv6 => "6",
                    Family::Common => "common",
                };
                let command = format!("{name}{suffix}");
                let fail = failed.peek().is_some_and(|wanted| **wanted == command);
                if fail {
                    failed.next();
                }
                commands.push(command);
                Some(!fail)
            };
            let family = family.map(|family| {
                if family == 4 {
                    Family::Ipv4
                } else {
                    Family::Ipv6
                }
            });
            assert!(matches!(
                (operation, family),
                ("ban" | "unban", Some(_)) | ("start" | "flush" | "stop", None)
            ));
            let ok = match (operation, family) {
                ("ban", Some(family)) => action.ban(family, &mut executor),
                ("unban", Some(family)) => action.unban(family, &mut executor),
                ("start", _) => action.start(&mut executor),
                ("flush", _) => action.flush(&mut executor),
                ("stop", _) => action.stop(&mut executor),
                _ => false,
            };
            assert!(
                failed.next().is_none(),
                "unreached failure in {}",
                scenario.name
            );
            Trace(ok, commands)
        })
        .collect()
}

fn golden(scenario: &Scenario) -> Vec<Trace> {
    scenario
        .calls
        .iter()
        .map(|&(_, _, _, ok, commands)| {
            Trace(ok, commands.iter().map(|s| (*s).to_owned()).collect())
        })
        .collect()
}

#[test]
fn legacy_action_lifecycle_matches_golden() {
    for scenario in SCENARIOS {
        assert_eq!(native(scenario), golden(scenario), "{}", scenario.name);
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_action_lifecycle_agrees_with_fail2ban_111() {
    let source = pinned_source();
    let original = oracle(&source);
    assert_eq!(original.len(), SCENARIOS.len());
    for (scenario, original) in SCENARIOS.iter().zip(original) {
        assert_eq!(original, golden(scenario), "oracle: {}", scenario.name);
        assert_eq!(native(scenario), original, "Rust: {}", scenario.name);
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

fn oracle(source: &Path) -> Vec<Vec<Trace>> {
    const ORACLE: &str = r"
import json
import os
import subprocess
import sys

def reject_exec(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn',
                 'socket.connect', 'socket.sendto', 'socket.getaddrinfo'):
        raise AssertionError('test attempted actual process or network activity: ' + event)
sys.addaudithook(reject_exec)

source, scenarios = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.server.action import CommandAction
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version

def blocked(*args, **kwargs):
    raise AssertionError('unexpected original execution path')
Utils.executeCmd = blocked
subprocess.Popen = blocked
os.system = blocked

commands = ('start', 'ban', 'unban', 'check', 'repair', 'flush', 'stop')
known = {cmd + suffix for cmd in commands for suffix in ('4', '6')}
ips = {4: '192.0.2.1', 6: '2001:db8::1'}
results = []
for on_demand, repair, repair_on_unban, calls in json.loads(scenarios):
    action = CommandAction(None, 'offline-lifecycle-fixture')
    action.families = ['inet4', 'inet6']
    action.actionstart_on_demand = on_demand
    action.actionrepair_on_unban = repair_on_unban
    for cmd in commands:
        if cmd == 'repair' and not repair:
            continue
        setattr(action, 'action' + cmd, cmd + '4')
        setattr(action, 'action' + cmd + '?family=inet6', cmd + '6')
    entries = []
    for operation, family, failures in calls:
        emitted = []
        def record(token, timeout, **kwargs):
            assert token in known, 'not a fixture-only command token: ' + token
            emitted.append(token)
            if failures and failures[0] == token:
                failures.pop(0)
                return False
            return True
        action.executeCmd = record
        try:
            if family is None:
                result = getattr(action, operation)()
            else:
                result = getattr(action, operation)({'family': f'inet{family}', 'ip': ips[family]})
            ok = result is not False
        except RuntimeError:
            ok = False
        assert not failures, ('unreached injected failure', operation, failures)
        entries.append([ok, emitted])
    results.append(entries)
print(json.dumps(results))
";
    let scenarios = SCENARIOS
        .iter()
        .map(|s| {
            json!([
                s.start_on_demand,
                s.explicit_repair,
                s.repair_on_unban,
                s.calls
                    .iter()
                    .map(|&(op, family, fail, _, _)| (op, family, fail))
                    .collect::<Vec<_>>()
            ])
        })
        .collect::<Vec<_>>();
    let scratch = tempdir().expect("temporary oracle directory");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(serde_json::to_string(&scenarios).expect("fixtures serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original in-memory recording action");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
