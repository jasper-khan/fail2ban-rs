//! Dated synthetic sshd normal-mode streams against the original in-memory filter.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::tempdir;

use super::legacy_ssh_sessions::LegacySshSessions;

const NOW: i64 = 1_752_537_600; // 2025-07-15 00:00:00 UTC
const YEAR: i32 = 2025;
const START: i64 = NOW - 30;
const CONN: &str = "Connection from 192.0.2.7 port 50001 on 192.0.2.20 port 22";
const LOCKED: &str = "User alice not allowed because account is locked";
const TOO_MANY: &str = "Disconnecting: Too many authentication failures for alice [preauth]";
const DISCONNECTED: &str =
    "Disconnected from authenticating user alice 192.0.2.7 port 50001 [preauth]";
const ACCEPTED: &str = "Accepted publickey for alice from 192.0.2.7 port 50001 ssh2";
const ACCEPTED_OTHER: &str = "Accepted password for carol from 192.0.2.7 port 50001 ssh2";
const FAILED: &str = "Failed password for alice from 192.0.2.7 port 50001 ssh2";
const INVALID: &str = "Failed password for invalid user visitor from 198.51.100.37 port 50002 ssh2";
const PAM: &str = "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.8 user=carol";
const VALID_KEY: &str =
    "Failed publickey for alice from 192.0.2.7 port 50001 ssh2: ED25519 SHA256:example";
const INVALID_KEY: &str = "Failed publickey for invalid user visitor from 198.51.100.37 port 50002 ssh2: ED25519 SHA256:example";

type Finding = Option<(&'static str, &'static str)>;
const ALICE: Finding = Some(("192.0.2.7", "alice"));
const CAROL: Finding = Some(("192.0.2.7", "carol"));
const CAROL_PAM: Finding = Some(("192.0.2.8", "carol"));
const VISITOR: Finding = Some(("198.51.100.37", "visitor"));

type Stream = (&'static str, &'static [&'static str], &'static [Finding]);
const STREAMS: &[Stream] = &[
    (
        "source context and addressless failures",
        &[CONN, LOCKED, TOO_MANY, TOO_MANY],
        &[None, ALICE, ALICE, ALICE],
    ),
    (
        "pending failure released on source context",
        &[LOCKED, CONN, LOCKED],
        &[None, ALICE, ALICE],
    ),
    (
        "ordinary close forgets",
        &[CONN, DISCONNECTED, LOCKED, TOO_MANY],
        &[None, None, None, None],
    ),
    (
        "close releases pending then forgets",
        &[LOCKED, DISCONNECTED, LOCKED],
        &[None, ALICE, None],
    ),
    (
        "ordinary success forgets",
        &[CONN, FAILED, ACCEPTED, LOCKED, TOO_MANY],
        &[None, ALICE, None, None, None],
    ),
    (
        "same-user success resets pending",
        &[LOCKED, ACCEPTED, LOCKED],
        &[None, None, None],
    ),
    (
        "different-user success can emit before forgetting",
        &[CONN, FAILED, ACCEPTED_OTHER, LOCKED],
        &[None, ALICE, CAROL, None],
    ),
    (
        "PAM supplies context but isn't a standalone failure",
        &[PAM, "User carol not allowed because account is locked"],
        &[None, CAROL_PAM],
    ),
    (
        "ordinary invalid password and public-key mode",
        &[VALID_KEY, LOCKED, INVALID_KEY, INVALID],
        &[None, ALICE, VISITOR, VISITOR],
    ),
];

fn stream(bodies: &[&str]) -> Vec<String> {
    bodies
        .iter()
        .enumerate()
        .map(|(index, body)| line(index, "host-a", 2760, body))
        .collect()
}

fn line(index: usize, host: &str, pid: u32, body: &str) -> String {
    format!("Jul 14 23:59:{:02} {host} sshd[{pid}]: {body}", 30 + index)
}

fn golden(findings: &[Finding]) -> Vec<Value> {
    findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            finding.map_or(Value::Null, |(ip, user)| {
                json!({
                    "ip": ip,
                    "timestamp": START + i64::try_from(index).expect("short fixture"),
                    "user": user
                })
            })
        })
        .collect()
}

fn native(lines: &[String]) -> Vec<Value> {
    let mut sessions = LegacySshSessions::new();
    lines
        .iter()
        .map(|line| {
            sessions
                .evaluate(line, YEAR, NOW)
                .map_or(Value::Null, |failure| {
                    json!({
                        "ip": failure.ip.to_string(),
                        "timestamp": failure.timestamp,
                        "user": failure.user
                    })
                })
        })
        .collect()
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn original_ssh_normal_ordered_sessions_agree_with_rust() {
    let source = pinned_source();
    let mut all = STREAMS
        .iter()
        .map(|(name, bodies, findings)| (*name, stream(bodies), *findings))
        .collect::<Vec<_>>();
    all.push((
        "full prefix associates host and PID independently",
        vec![
            line(0, "host-a", 2760, CONN),
            line(1, "host-a", 2761, LOCKED),
            line(2, "host-b", 2760, LOCKED),
            line(3, "host-a", 2760, LOCKED),
        ],
        &[None, None, None, ALICE],
    ));

    let original = oracle(&source, &all);
    assert_eq!(original.len(), all.len());
    for ((name, lines, findings), observed) in all.iter().zip(original) {
        assert_eq!(observed, golden(findings), "pinned original: {name}");
        assert_eq!(native(lines), observed, "native Rust: {name}");
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
            "config",
            "fail2ban",
        ],
    );
    assert!(
        status
            .lines()
            .all(|line| line.starts_with("!! fail2ban/") && line.ends_with("/__pycache__/")),
        "use unmodified stock config and Python source: {status}"
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

fn oracle(source: &Path, streams: &[(&str, Vec<String>, &[Finding])]) -> Vec<Vec<Value>> {
    // processLine does only filter accounting: it never queues a ticket,
    // runs any configured action or starts a daemon. Keep DNS off.
    const ORACLE: &str = r#"
import json
import os
import sys
source, now, streams = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client.filterreader import FilterReader
from fail2ban.server.filter import Filter
from fail2ban.server.mytime import MyTime
from fail2ban.version import version
assert version == "1.1.1", version
MyTime.setTime(int(now))
reader = FilterReader("sshd", "synthetic-jail", {"mode": "normal"}, basedir=os.path.join(source, "config"))
if not reader.read():
    raise RuntimeError("upstream reader could not load stock sshd")
reader.applyAutoOptions("auto")
reader.getOptions({})
options = reader.getCombined()
results = []
for lines in json.loads(streams):
    f = Filter(None, useDns="no")
    f.active = True
    f.checkFindTime = False
    f.setLogTimeZone("UTC")
    f.prefRegex = options["prefregex"]
    f.setDatePattern(options["datepattern"])
    f.setMaxLines(options["maxlines"])
    for rule in (options.get("failregex") or "").splitlines():
        if rule:
            f.addFailRegex(rule)
    for rule in (options.get("ignoreregex") or "").splitlines():
        if rule:
            f.addIgnoreRegex(rule)
    decisions = []
    for line in lines:
        matches = f.processLine(line)
        if matches:
            assert len(matches) == 1, matches
            _, ip, ts, data = matches[0]
            decisions.append({"ip": str(ip), "timestamp": ts, "user": data.get("user")})
        else:
            decisions.append(None)
    results.append(decisions)
print(json.dumps(results))
"#;
    let scratch = tempdir().expect("temporary oracle directory");
    let lines = streams
        .iter()
        .map(|(_, lines, _)| lines)
        .collect::<Vec<_>>();
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(NOW.to_string())
        .arg(serde_json::to_string(&lines).expect("fixtures serialize"))
        .env("TZ", "UTC")
        .current_dir(scratch.path())
        .output()
        .expect("run original offline sshd matcher");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
