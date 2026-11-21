//! Offline action static expansion and cross-family deduplication parity.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::tempdir;

use super::legacy_action_lifecycle::{Family, Lifecycle, OperationIdentity, Step, StepKind};
use super::legacy_action_tags;

type StaticCase = (
    &'static str,
    &'static [(&'static str, &'static str)],
    [Option<&'static str>; 3],
);

const TAGS: &[StaticCase] = &[
    (
        "<outer><br><sp><absent>|<ip>|<matches>|<ipmatches>|<ipjailmatches>",
        &[
            ("inner", "base"),
            ("inner?family=inet4", "v4-token"),
            ("inner?family=inet6", "v6-token"),
            ("outer", "tag-<inner>"),
        ],
        [
            Some("tag-base\n <absent>|<ip>|<matches>|<ipmatches>|<ipjailmatches>"),
            Some("tag-v4-token\n <absent>|<ip>|<matches>|<ipmatches>|<ipjailmatches>"),
            Some("tag-v6-token\n <absent>|<ip>|<matches>|<ipmatches>|<ipjailmatches>"),
        ],
    ),
    (
        "<pick>|<exact>|<Exact>|<other>",
        &[
            ("pick", "base"),
            ("pick?family=inet6", ""),
            ("Exact", "upper"),
            ("exact", "lower"),
            ("other", "before-<pick>-after"),
        ],
        [
            Some("base|lower|upper|before-base-after"),
            Some("base|lower|upper|before-base-after"),
            Some("|lower|upper|before--after"),
        ],
    ),
    (
        "start-<<key>><br><sp>finish",
        &[
            ("key", "choice"),
            ("choice", "common"),
            ("choice?family=inet6", "six"),
            ("br", "-BREAK-"),
            ("sp", "-SPACE-"),
        ],
        [
            Some("start-common-BREAK--SPACE-finish"),
            Some("start-common-BREAK--SPACE-finish"),
            Some("start-six-BREAK--SPACE-finish"),
        ],
    ),
    ("<a>", &[("a", "<b>"), ("b", "<a>")], [None; 3]),
    (
        "<key>",
        &[("key", "<one>"), ("one", "<two>"), ("two", "end")],
        [Some("end"); 3],
    ),
];

type Call = (
    &'static str,
    Option<u8>,
    Option<&'static str>,
    bool,
    &'static [&'static str],
);

const LAZY: &[Call] = &[
    ("start", None, None, true, &[]),
    ("ban", Some(6), None, true, &["start-shared", "ban6"]),
    ("ban", Some(4), None, true, &["ban4"]),
    ("flush", None, None, true, &["flush-shared"]),
    ("ban", Some(4), None, true, &["ban4"]),
    ("flush", None, None, true, &[]),
    ("ban", Some(4), None, true, &["ban4"]),
    ("ban", Some(6), None, true, &["ban6"]),
    ("flush", None, None, true, &[]),
    ("stop", None, None, true, &["stop-shared"]),
    ("ban", Some(4), None, true, &["start-shared", "ban4"]),
    ("ban", Some(6), None, true, &["ban6"]),
    ("flush", None, None, true, &[]),
    ("stop", None, None, true, &["stop-shared"]),
];

const EAGER: &[Call] = &[
    (
        "start",
        None,
        Some("start-shared"),
        false,
        &["start-shared", "start-shared"],
    ),
    ("ban", Some(4), None, true, &["ban4"]),
    ("ban", Some(6), None, true, &["ban6"]),
    (
        "flush",
        None,
        Some("flush-shared"),
        false,
        &["flush-shared", "flush-shared"],
    ),
    ("unban", Some(6), None, true, &["unban6"]),
    ("unban", Some(4), None, true, &[]),
    ("flush", None, None, true, &[]),
    (
        "stop",
        None,
        Some("stop-shared"),
        false,
        &["stop-shared", "stop-shared"],
    ),
    ("stop", None, None, true, &[]),
    ("start", None, None, true, &[]),
    ("stop", None, None, true, &["stop-shared"]),
];

const SAME_FAMILY: &[Call] = &[
    ("ban", Some(4), None, true, &["start-shared", "ban4"]),
    ("flush", None, None, true, &["flush-shared"]),
    ("ban", Some(4), None, true, &["ban4"]),
    ("flush", None, None, true, &["flush-shared"]),
    ("ban", Some(6), None, true, &["ban6"]),
    ("stop", None, None, true, &["stop-shared"]),
];

const DEDUP: &[(bool, &[Call])] = &[(true, LAZY), (false, EAGER), (true, SAME_FAMILY)];

fn static_native() -> Vec<Vec<Option<String>>> {
    TAGS.iter()
        .map(|(query, entries, _)| {
            let props = entries
                .iter()
                .map(|(key, val)| ((*key).to_owned(), (*val).to_owned()))
                .collect::<BTreeMap<_, _>>();
            [Family::Common, Family::Ipv4, Family::Ipv6]
                .into_iter()
                .map(|family| {
                    legacy_action_tags::expand(query, &props, family)
                        .ok()
                        .map(|expanded| expanded.as_str().to_owned())
                })
                .collect()
        })
        .collect()
}

fn golden_tags() -> Vec<Vec<Option<String>>> {
    TAGS.iter()
        .map(|(_, _, expected)| {
            expected
                .iter()
                .map(|item| item.map(str::to_owned))
                .collect()
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Trace(bool, Vec<String>);

fn native_lifecycle(on_demand: bool, calls: &[Call]) -> Vec<Trace> {
    let mut life = Lifecycle::new(on_demand, vec![Family::Ipv4, Family::Ipv6], false, false);
    for family in [Family::Ipv4, Family::Ipv6] {
        for kind in [StepKind::Start, StepKind::Flush, StepKind::Stop] {
            // Same ID on both families and all three kinds. The identity
            // cache is partitioned by operation, so start can't suppress flush.
            life.set_operation_identity(Step { kind, family }, OperationIdentity(7));
        }
    }
    calls
        .iter()
        .map(|&(operation, family, failure, _, _)| {
            let mut record = Vec::new();
            let mut failure = failure;
            let mut executor = |step: Step| {
                let token = match step.kind {
                    StepKind::Start => "start-shared",
                    StepKind::Flush => "flush-shared",
                    StepKind::Stop => "stop-shared",
                    StepKind::Ban if step.family == Family::Ipv4 => "ban4",
                    StepKind::Ban => "ban6",
                    StepKind::Unban if step.family == Family::Ipv4 => "unban4",
                    StepKind::Unban => "unban6",
                    StepKind::Check | StepKind::Repair => return None,
                };
                record.push(token.to_owned());
                let failed = failure == Some(token);
                if failed {
                    failure = None;
                }
                Some(!failed)
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
                ("ban", Some(family)) => life.ban(family, &mut executor),
                ("unban", Some(family)) => life.unban(family, &mut executor),
                ("start", _) => life.start(&mut executor),
                ("flush", _) => life.flush(&mut executor),
                ("stop", _) => life.stop(&mut executor),
                _ => false,
            };
            assert!(failure.is_none(), "injected failure not reached");
            Trace(ok, record)
        })
        .collect()
}

fn golden_lifecycle(calls: &[Call]) -> Vec<Trace> {
    calls
        .iter()
        .map(|&(_, _, _, ok, commands)| {
            Trace(ok, commands.iter().map(|s| (*s).to_owned()).collect())
        })
        .collect()
}

#[test]
fn action_static_tags_and_cache_match_golden() {
    assert_eq!(static_native(), golden_tags());
    for &(on_demand, calls) in DEDUP {
        assert_eq!(native_lifecycle(on_demand, calls), golden_lifecycle(calls));
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn action_static_tags_and_cache_agree_with_fail2ban_111() {
    let source = pinned_source();
    let original = oracle(&source);
    assert_eq!(
        original.tags,
        golden_tags(),
        "pinned static expansion golden"
    );
    assert_eq!(static_native(), original.tags, "Rust static expansions");
    assert_eq!(original.dedup.len(), DEDUP.len());
    for ((on_demand, calls), observed) in DEDUP.iter().zip(original.dedup) {
        assert_eq!(observed, golden_lifecycle(calls), "pinned dedup golden");
        assert_eq!(native_lifecycle(*on_demand, calls), observed, "Rust dedup");
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

#[derive(Deserialize)]
struct Reference {
    tags: Vec<Vec<Option<String>>>,
    dedup: Vec<Vec<Trace>>,
}

fn oracle(source: &Path) -> Reference {
    const ORACLE: &str = r"
import json
import os
import subprocess
import sys

def blocked(*args, **kwargs):
    raise AssertionError('unexpected original execution path')
def reject_exec(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn',
                 'socket.connect', 'socket.sendto', 'socket.getaddrinfo'):
        blocked()
sys.addaudithook(reject_exec)
subprocess.Popen = blocked
os.system = blocked

source, checks = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.server.action import CommandAction
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version
Utils.executeCmd = blocked

static_cases, dedup_cases = json.loads(checks)
tags = []
for query, props in static_cases:
    results = []
    for condition in ('', 'family=inet4', 'family=inet6'):
        try:
            results.append(CommandAction.replaceTag(query, dict(props), conditional=condition))
        except ValueError:
            results.append(None)
    tags.append(results)

known = {'start-shared', 'flush-shared', 'stop-shared', 'ban4', 'ban6', 'unban4', 'unban6'}
ips = {4: '192.0.2.1', 6: '2001:db8::1'}
dedup = []
for on_demand, calls in dedup_cases:
    action = CommandAction(None, 'offline-shared-token-fixture')
    action.families = ['inet4', 'inet6']
    action.actionstart_on_demand = on_demand
    for cmd in ('start', 'flush', 'stop'):
        # Obtain equal operation text by interpolation from distinct properties,
        # not by installing actual action definitions or executing any shell.
        setattr(action, 'action' + cmd, '<' + cmd + '-token4>')
        setattr(action, 'action' + cmd + '?family=inet6', '<' + cmd + '-token6>')
        setattr(action, cmd + '-token4', cmd + '-shared')
        setattr(action, cmd + '-token6', cmd + '-shared')
    for cmd in ('ban', 'unban'):
        setattr(action, 'action' + cmd, cmd + '4')
        setattr(action, 'action' + cmd + '?family=inet6', cmd + '6')
    entries = []
    for operation, family, failure in calls:
        emitted = []
        fail_once = [failure] if failure is not None else []
        def record(token, timeout, **kwargs):
            assert token in known, 'not a fixture-only operation token: ' + token
            emitted.append(token)
            if fail_once and token == fail_once[0]:
                fail_once.pop()
                return False
            return True
        action.executeCmd = record
        try:
            if family is None:
                outcome = getattr(action, operation)()
            else:
                outcome = getattr(action, operation)({'family': f'inet{family}', 'ip': ips[family]})
            ok = outcome is not False
        except RuntimeError:
            ok = False
        assert not fail_once, ('unreached injected failure', operation, failure)
        entries.append([ok, emitted])
    dedup.append(entries)
print(json.dumps({'tags': tags, 'dedup': dedup}))
";
    let input: Value = json!([
        TAGS.iter()
            .map(|(query, props, _)| (query, props))
            .collect::<Vec<_>>(),
        DEDUP
            .iter()
            .map(|(on_demand, calls)| (
                on_demand,
                calls
                    .iter()
                    .map(|&(op, family, fail, _, _)| (op, family, fail))
                    .collect::<Vec<_>>(),
            ))
            .collect::<Vec<_>>()
    ]);
    let scratch = tempdir().expect("temporary oracle directory");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(serde_json::to_string(&input).expect("fixtures serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original in-memory action recorder");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
