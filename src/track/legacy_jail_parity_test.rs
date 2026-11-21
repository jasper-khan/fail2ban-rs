//! Offline FailManager/BanManager differential. No jail actions or transport.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::tempdir;

use super::legacy_ban_manager::{AddResult, Duration};
use super::legacy_jail::LegacyJail;

const A: &str = "192.0.2.10";
const B: &str = "2001:db8::12";

#[derive(Clone, Copy)]
enum Step {
    // IP, event clock, observation clock, retry count, ban decision.
    Record(&'static str, i64, i64, u64, Option<&'static str>),
    Cleanup(i64, usize),
    Expire(i64, &'static [&'static str]),
    Counts(&'static str, Option<u64>, u64, u64),
}

use Step::{Cleanup, Counts, Expire, Record};

struct Scenario {
    name: &'static str,
    max_retry: u64,
    find_time: u64,
    ban_time: i64,
    steps: &'static [Step],
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "maxretry and inclusive findtime but strict timer expiry",
        max_retry: 3,
        find_time: 10,
        ban_time: 10,
        steps: &[
            Record(A, 100, 100, 1, None),
            Record(B, 104, 104, 1, None),
            Record(A, 105, 105, 2, None),
            Counts(A, Some(2), 3, 0),
            Record(A, 110, 110, 3, Some("added")),
            Counts(A, None, 4, 1),
            Record(B, 114, 114, 2, None),
            Counts(B, Some(2), 5, 1),
            Expire(119, &[]),
            Expire(120, &[]),
            Expire(121, &[A]),
        ],
    },
    Scenario {
        name: "window rescaling with half-to-even and out-of-order events",
        max_retry: 3,
        find_time: 10,
        ban_time: 10,
        steps: &[
            Record(B, 100, 100, 1, None),
            // 1 * 10 / 20 = 0.5 -> 0 rounded, then +1.
            Record(B, 120, 120, 1, None),
            Record(B, 121, 121, 2, None),
            // The older event increments without moving the ticket time back.
            Record(B, 119, 122, 3, Some("added")),
            Counts(B, None, 4, 1),
            Expire(130, &[]),
            Expire(131, &[]),
            Expire(132, &[B]),
        ],
    },
    Scenario {
        name: "explicit housekeeping deletes at the exact findtime cutoff",
        max_retry: 3,
        find_time: 10,
        ban_time: 10,
        steps: &[
            Record(A, 100, 100, 1, None),
            Record(B, 101, 101, 1, None),
            Cleanup(109, 0),
            Cleanup(110, 1),
            Counts(A, None, 2, 0),
            Counts(B, Some(1), 2, 0),
            Record(A, 110, 110, 1, None),
            Cleanup(111, 1),
            Counts(B, None, 3, 0),
        ],
    },
    Scenario {
        name: "longer repeat prolongs without raising total, then can ban again",
        max_retry: 2,
        find_time: 10,
        ban_time: 10,
        steps: &[
            Record(A, 100, 100, 1, None),
            Record(A, 101, 101, 2, Some("added")),
            Record(A, 104, 104, 1, None),
            Record(A, 105, 105, 2, Some("prolonged")),
            Counts(A, None, 4, 1),
            Expire(112, &[]),
            Expire(115, &[]),
            Expire(116, &[A]),
            Record(A, 118, 118, 1, None),
            Record(A, 119, 119, 2, Some("added")),
            Counts(A, None, 6, 2),
        ],
    },
    Scenario {
        name: "old incoming timer rejected only strictly past end",
        max_retry: 1,
        find_time: 10,
        ban_time: 10,
        steps: &[
            Record(A, 100, 111, 1, Some("expired")),
            Counts(A, None, 1, 0),
            Record(B, 101, 111, 1, Some("added")),
            Counts(B, None, 2, 1),
            Expire(111, &[]),
            Expire(112, &[B]),
        ],
    },
    Scenario {
        name: "permanent timers survive sweeps and repeats are duplicates",
        max_retry: 1,
        find_time: 10,
        ban_time: -1,
        steps: &[
            Record(A, 100, 100, 1, Some("added")),
            Record(A, 100, 100, 1, Some("duplicate")),
            Record(A, 102, 102, 1, Some("duplicate")),
            Counts(A, None, 3, 1),
            Expire(2_000_000_000, &[]),
            Record(B, 2_000_000_001, 2_000_000_001, 1, Some("added")),
            Counts(B, None, 4, 2),
        ],
    },
];

fn ip(raw: &str) -> IpAddr {
    raw.parse().expect("typed documentation-only IP fixture")
}

fn decision(result: AddResult) -> &'static str {
    match result {
        AddResult::Added => "added",
        AddResult::Duplicate => "duplicate",
        AddResult::Prolonged => "prolonged",
        AddResult::Expired => "expired",
    }
}

impl Step {
    const fn request(self) -> (&'static str, Option<&'static str>, i64, i64) {
        match self {
            Self::Record(ip, event, now, _, _) => ("record", Some(ip), event, now),
            Self::Cleanup(now, _) => ("cleanup", None, now, now),
            Self::Expire(now, _) => ("expire", None, now, now),
            Self::Counts(ip, _, _, _) => ("counts", Some(ip), 0, 0),
        }
    }

    fn expected(self) -> Value {
        match self {
            Self::Record(_, _, _, retry, decision) => json!([retry, decision]),
            Self::Cleanup(_, removed) => json!(removed),
            Self::Expire(_, expired) => json!(expired),
            Self::Counts(_, retry, total_fail, total_ban) => json!([retry, total_fail, total_ban]),
        }
    }

    fn apply(self, jail: &mut LegacyJail) -> Value {
        match self {
            Self::Record(address, event, now, _, _) => {
                let out = jail.record(ip(address), event, now);
                json!([out.retry, out.decision.map(decision)])
            }
            Self::Cleanup(now, _) => json!(jail.cleanup_failures(now)),
            Self::Expire(now, _) => {
                let mut addresses = jail
                    .expire(now)
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>();
                addresses.sort();
                json!(addresses)
            }
            Self::Counts(address, _, _, _) => {
                json!([
                    jail.failure_count(ip(address)),
                    jail.total_failures(),
                    jail.total_bans()
                ])
            }
        }
    }
}

fn native(scenario: &Scenario) -> Vec<Value> {
    let duration = if scenario.ban_time == -1 {
        Duration::Permanent
    } else {
        Duration::Finite(scenario.ban_time)
    };
    let mut jail = LegacyJail::new(scenario.max_retry, scenario.find_time, duration);
    scenario
        .steps
        .iter()
        .map(|step| step.apply(&mut jail))
        .collect()
}

#[test]
fn legacy_jail_state_matches_golden() {
    for scenario in SCENARIOS {
        let observed = native(scenario);
        for (answer, step) in observed.iter().zip(scenario.steps) {
            assert_eq!(answer, &step.expected(), "{}", scenario.name);
        }
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_jail_state_agrees_with_pinned_fail2ban_111() {
    let source = pinned_source();
    let original = oracle(&source);
    assert_eq!(original.len(), SCENARIOS.len());
    for (scenario, original) in SCENARIOS.iter().zip(original) {
        assert_eq!(original.len(), scenario.steps.len());
        let native = native(scenario);
        for (index, ((answer, ours), step)) in
            original.iter().zip(native).zip(scenario.steps).enumerate()
        {
            assert_eq!(
                answer,
                &step.expected(),
                "oracle {} #{index}",
                scenario.name
            );
            assert_eq!(&ours, answer, "Rust {} #{index}", scenario.name);
        }
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

fn oracle(source: &Path) -> Vec<Vec<Value>> {
    const ORACLE: &str = r"
import json
import sys
source, scenarios = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.server.banmanager import BanManager
from fail2ban.server.failmanager import FailManager
from fail2ban.server.ipdns import IPAddr
from fail2ban.server.mytime import MyTime
from fail2ban.server.ticket import BanTicket, FailTicket
from fail2ban.version import version
assert version == '1.1.1', version
answer = []
for max_retry, find_time, ban_time, steps in json.loads(scenarios):
    failures = FailManager()
    failures.setMaxRetry(max_retry)
    failures.setMaxTime(find_time)
    bans = BanManager()
    bans.setBanTime(ban_time)
    trace = []
    for kind, address, event, now in steps:
        ip = None if address is None else IPAddr(address)
        if kind == 'record':
            MyTime.setTime(now)
            retry = failures.addFailure(FailTicket(ip, event))
            decision = None
            if retry >= max_retry:
                reason = {}
                ticket = BanTicket.wrap(failures.toBan(ip))
                if bans.addBanTicket(ticket, reason):
                    decision = 'added'
                elif 'expired' in reason:
                    decision = 'expired'
                elif 'prolong' in reason:
                    decision = 'prolonged'
                else:
                    assert 'ticket' in reason
                    decision = 'duplicate'
            trace.append([retry, decision])
        elif kind == 'cleanup':
            before = failures.size()
            failures.cleanup(now)
            trace.append(before - failures.size())
        elif kind == 'expire':
            trace.append(sorted(str(item.getIP()) for item in bans.unBanList(now)))
        elif kind == 'counts':
            # Original exposes the combined pending count publicly, not the
            # per-address pending count. Inspect the pinned map without editing it.
            ticket = failures._FailManager__failList.get(ip)
            trace.append([None if ticket is None else ticket.getRetry(),
                          failures.getFailTotal(), bans.getBanTotal()])
        else:
            raise ValueError(kind)
    answer.append(trace)
print(json.dumps(answer))
";
    let scenarios = SCENARIOS
        .iter()
        .map(|s| {
            json!([
                s.max_retry,
                s.find_time,
                s.ban_time,
                s.steps
                    .iter()
                    .map(|step| step.request())
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
        .expect("run original offline jail timer");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
