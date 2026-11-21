//! Offline decision parity for dated nginx-http-auth file diagnostics.

use std::path::Path;

use serde_json::{Value, json};
use tempfile::tempdir;

use super::legacy_matcher::{LegacyMatcher, LineResult};
use crate::config::legacy_filter::read_resolved;

const MODES: &[&str] = &["", "normal", "auth", "aggressive", "fallback"];

const FIXTURES: &[(&str, &str)] = &[
    (
        "password mismatch",
        r#"2025/07/14 23:59:58 [error] 123#123: *4 user "example-user": password mismatch, client: 192.0.2.10, server: auth.example, request: "GET /signin HTTP/1.1", host: "auth.example""#,
    ),
    (
        "username not in password file",
        r#"2025/07/14 23:59:59 [error] 123#123: *5 user "example-user" was not found in "/etc/nginx/htpasswd", client: 2001:db8::12, server: auth.example"#,
    ),
    (
        "PAM authentication failure",
        "2025/07/15 00:00:01 [crit] 123#123: *6 PAM: user 'example-user' - not authenticated: Authentication failure, client: 198.51.100.40",
    ),
    (
        "TLS protocol version incompatibility",
        "2025/07/15 00:00:02 [crit] 123#123: *7 SSL_do_handshake() failed (SSL: error:0A000102:SSL routines::unsupported protocol) while SSL handshaking, client: 203.0.113.8",
    ),
    (
        "different severity",
        r#"2025/07/15 00:00:03 [warn] 123#123: *8 user "example-user": password mismatch, client: 192.0.2.10"#,
    ),
    (
        "unrelated file-not-found error",
        r#"2025/07/15 00:00:04 [error] 123#123: *9 open() "/srv/example/missing" failed (2: No such file or directory), client: 198.51.100.2"#,
    ),
    (
        "client and server addresses are distinct",
        r#"2025/07/15 00:00:05 [error] 123#123: *10 user "example-user": password mismatch, client: 192.0.2.20, server: 203.0.113.91, request: "GET /signin HTTP/1.1""#,
    ),
];

fn matcher(base: &Path, mode: &str) -> LegacyMatcher {
    let expression = if mode.is_empty() {
        "nginx-http-auth".to_owned()
    } else {
        format!("nginx-http-auth[mode={mode}]")
    };
    let filter = read_resolved(base, &expression, "auto")
        .expect("stock file filter resolves")
        .expect("stock filter exists");
    LegacyMatcher::compile(&filter).expect("supported legacy nginx file matcher")
}

fn native(matcher: &LegacyMatcher, line: &str) -> Value {
    match matcher.evaluate(line) {
        LineResult::Miss => Value::Null,
        LineResult::Matched(failure) => json!({
            "index": failure.pattern_idx,
            "ip": failure.ip.to_string(),
            "timestamp": failure.timestamp,
            "user": failure.user
        }),
        LineResult::Ignored { pattern_idx } => json!({"ignored": pattern_idx}),
    }
}

fn golden(mode: &str, index: usize) -> Value {
    let auth_user = Some("example-user");
    let matched = match (mode, index) {
        ("aggressive", 3) => Some((2, "203.0.113.8", 1_752_537_602, None)),
        ("fallback", 3) => Some((0, "203.0.113.8", 1_752_537_602, None)),
        ("fallback", _) => None,
        (_, 0) => Some((0, "192.0.2.10", 1_752_537_598, auth_user)),
        (_, 1) => Some((0, "2001:db8::12", 1_752_537_599, auth_user)),
        (_, 2) => Some((1, "198.51.100.40", 1_752_537_601, auth_user)),
        (_, 6) => Some((0, "192.0.2.20", 1_752_537_605, auth_user)),
        _ => None,
    };
    matched.map_or(Value::Null, |(index, ip, timestamp, user)| {
        json!({"index": index, "ip": ip, "timestamp": timestamp, "user": user})
    })
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_nginx_dated_file_decisions_agree_with_fail2ban_111() {
    let source = pinned_source();
    let base = source.join("config");
    let lines = FIXTURES.iter().map(|(_, line)| *line).collect::<Vec<_>>();
    for mode in MODES {
        let original = oracle(&source, &base, mode, &lines);
        let matcher = matcher(&base, mode);
        assert_eq!(original.len(), FIXTURES.len());
        for (index, (label, line)) in FIXTURES.iter().enumerate() {
            let expected = original.get(index).expect("one oracle decision per case");
            assert_eq!(
                expected,
                &golden(mode, index),
                "upstream expectation for mode {mode:?}, case {label}"
            );
            assert_eq!(
                &native(&matcher, line),
                expected,
                "native result for mode {mode:?}, case {label}"
            );
        }
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_nginx_content_ignore_agrees_with_fail2ban_111() {
    let source = pinned_source();
    let scratch = tempdir().expect("temporary config directory");
    let filters = scratch.path().join("filter.d");
    std::fs::create_dir(&filters).expect("filter fixture directory");
    for basename in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        std::fs::copy(
            source.join("config").join("filter.d").join(basename),
            filters.join(basename),
        )
        .expect("copy pinned filter into temporary config");
    }
    // The full line starts with a date and severity; the rule is anchored
    // instead to the message that prefregex extracts.
    std::fs::write(
        filters.join("nginx-http-auth.local"),
        "[Definition]\nignoreregex = ^user \"example-user\": password mismatch$\n",
    )
    .expect("write fixture local overlay");
    let lines = [
        FIXTURES.first().expect("password mismatch fixture").1,
        FIXTURES.get(1).expect("unknown user fixture").1,
        FIXTURES.get(5).expect("unrelated error fixture").1,
    ];
    let original = oracle(&source, scratch.path(), "normal", &lines);
    assert_eq!(
        original,
        vec![json!({"ignored": 0}), golden("normal", 1), Value::Null]
    );
    let matcher = matcher(scratch.path(), "normal");
    assert_eq!(
        lines.map(|line| native(&matcher, line)).as_slice(),
        original.as_slice()
    );
}

fn pinned_source() -> std::path::PathBuf {
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
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("git UTF-8")
}

fn oracle(source: &Path, base: &Path, mode: &str, lines: &[&str]) -> Vec<Value> {
    // processLine is deliberately used instead of processLineAndAdd: this
    // runs only the filter, with no jail, DNS, failures queued or ban actions.
    const ORACLE: &str = r#"
import json
import sys
source, base, mode, lines = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client.filterreader import FilterReader
from fail2ban.server.filter import Filter
from fail2ban.version import version
assert version == "1.1.1", version
reader = FilterReader("nginx-http-auth", "synthetic-jail", {"mode": mode} if mode else {}, basedir=base)
if not reader.read():
    raise RuntimeError("upstream reader could not load stock nginx-http-auth")
reader.applyAutoOptions("auto")
reader.getOptions({})
options = reader.getCombined()
f = Filter(None, useDns="no")
f.active = True
f.checkFindTime = False
f.setLogTimeZone("UTC")
f.prefRegex = options["prefregex"]
f.setDatePattern(options["datepattern"])
if options.get("maxlines") is not None:
    f.setMaxLines(options["maxlines"])
for rule in (options.get("failregex") or "").splitlines():
    if rule:
        f.addFailRegex(rule)
for rule in (options.get("ignoreregex") or "").splitlines():
    if rule:
        f.addIgnoreRegex(rule)
results = []
ignored = []
f.onIgnoreRegex = lambda index, regex: ignored.append(index)
for line in json.loads(lines):
    ignored.clear()
    matches = f.processLine(line)
    if matches:
        assert len(matches) == 1, matches
        index, ip, timestamp, data = matches[0]
        results.append({"index": index, "ip": str(ip), "timestamp": timestamp, "user": data.get("user")})
    elif ignored:
        assert len(ignored) == 1, ignored
        results.append({"ignored": ignored[0]})
    else:
        results.append(None)
print(json.dumps(results))
"#;
    let scratch = tempdir().expect("temporary oracle directory");
    let output = std::process::Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(base)
        .arg(mode)
        .arg(serde_json::to_string(lines).expect("fixture lines serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original offline nginx-http-auth matcher");
    assert!(
        output.status.success(),
        "mode {mode:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
