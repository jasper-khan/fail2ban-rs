//! Head-to-head parity test across stock Fail2Ban 1.1.1 `filter.d` configs
//! (`nginx-http-auth`, `apache-auth`, `postfix`, `dovecot`, `recidive`).
//!
//! For each stock filter, runs the EXACT same log corpus through:
//! 1. Real upstream Fail2Ban 1.1.1 (`fail2ban.client.filterreader.FilterReader`
//!    + `fail2ban.server.filter.Filter`), and
//! 2. Our Rust compat engine (`fail2ban-rs` daemon with `--legacy-dir`),
//!
//! Asserts 1-to-1 IP ban decision parity.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Datelike, Timelike};

struct Daemon {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn syslog_now() -> String {
    let now = chrono::Local::now();
    format!(
        "{} {:2} {:02}:{:02}:{:02}",
        now.format("%b"),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

fn apache_now() -> String {
    chrono::Local::now()
        .format("%a %b %d %H:%M:%S.%6f %Y")
        .to_string()
}

fn iso_now() -> String {
    chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S,123")
        .to_string()
}

fn nginx_now() -> String {
    chrono::Local::now().format("%Y/%m/%d %H:%M:%S").to_string()
}

fn upstream_matched_ips(source: &Path, filter_name: &str, lines: &[String]) -> Vec<String> {
    let script = r#"
import json, os, sys
source, filter_name = sys.argv[1], sys.argv[2]
sys.path.insert(0, source)
from fail2ban.client.filterreader import FilterReader
from fail2ban.server.filter import Filter

reader = FilterReader(filter_name, "testjail", {}, share_config={}, basedir=os.path.join(source, "config"))
assert reader.read(), f"failed to read {filter_name}"
reader.getOptions(None)
stream = reader.convert()

flt = Filter(None)
flt.setMaxRetry(1)
flt.setFindTime(600)
flt.setUseDns("no")
for cmd in stream:
    if len(cmd) >= 4 and cmd[0] in ("set", "multi-set") and cmd[1] == "testjail":
        op = cmd[2]
        vals = cmd[3] if cmd[0] == "multi-set" else [cmd[3]]
        for val in vals:
            if op == "addfailregex":
                flt.addFailRegex(val)
            elif op == "addignoreregex":
                flt.addIgnoreRegex(val)
            elif op == "prefregex":
                flt.prefRegex = val
            elif op == "datepattern":
                flt.setDatePattern(val)
            elif op == "maxlines":
                flt.setMaxLines(int(val))

matched = []
for raw in sys.stdin.read().splitlines():
    for tick in flt.processLine(raw):
        ip = str(tick[1])
        if ip not in matched:
            matched.append(ip)
print(json.dumps(sorted(matched)))
"#;
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(source)
        .arg(filter_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python upstream filter");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for l in lines {
            writeln!(stdin, "{l}").expect("write line");
        }
    }
    let out = child.wait_with_output().expect("wait python");
    assert!(
        out.status.success(),
        "upstream filter {filter_name} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse upstream ips")
}

fn rust_compat_banned_ips(
    source: &Path,
    filter_name: &str,
    lines: &[String],
    expected_count: usize,
) -> Vec<String> {
    let tmp = tempfile::tempdir().expect("scratch");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&filter_dir).expect("filter.d");
    std::fs::create_dir_all(&state).expect("state");

    // Copy all stock filter.d files so before/after includes work identically.
    for entry in std::fs::read_dir(source.join("config/filter.d")).expect("read filter.d") {
        let entry = entry.expect("entry");
        if entry.path().is_file() {
            let _ = std::fs::copy(entry.path(), filter_dir.join(entry.file_name()));
        }
    }

    let log_path = tmp.path().join("service.log");
    let record = tmp.path().join("decisions.log");
    std::fs::write(&log_path, b"").expect("create log");

    std::fs::write(
        base.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {}\ndbfile = {}\n",
            tmp.path().join("orig.sock").display(),
            state.join("fail2ban.sqlite3").display()
        ),
    )
    .expect("fail2ban.conf");

    std::fs::write(
        base.join("jail.conf"),
        format!(
            "[DEFAULT]\n\
             backend = polling\n\
             usedns = no\n\
             ignoreself = false\n\
             action =\n\
             \n\
             [testjail]\n\
             enabled = true\n\
             port = 80\n\
             filter = {filter_name}\n\
             logpath = {}\n\
             maxretry = 1\n\
             findtime = 600s\n\
             bantime = 600s\n",
            log_path.display()
        ),
    )
    .expect("jail.conf");

    let mut child = Command::new(env!("CARGO_BIN_EXE_fail2ban-rs"))
        .arg("run")
        .arg("--legacy-dir")
        .arg(&base)
        .arg("--record-decisions")
        .arg(&record)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fail2ban-rs");
    let stderr = child.stderr.take().expect("stderr");
    let err_lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&err_lines);
    std::thread::spawn(move || {
        for l in BufReader::new(stderr).lines().map_while(Result::ok) {
            sink.lock().expect("lock").push(l);
        }
    });
    let daemon = Daemon {
        child,
        lines: err_lines,
    };

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if daemon
            .lines
            .lock()
            .expect("lock")
            .iter()
            .any(|l| l.contains("fail2ban-rs started"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .expect("open log");
    for l in lines {
        writeln!(f, "{l}").expect("write log");
    }
    f.flush().expect("flush");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut ips: Vec<String> = std::fs::read_to_string(&record)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("BAN testjail ").map(str::to_owned))
            .collect();
        ips.sort();
        ips.dedup();
        if ips.len() >= expected_count || Instant::now() >= deadline {
            if ips.len() < expected_count {
                eprintln!(
                    "=== {filter_name} stderr ===\n{}",
                    daemon.lines.lock().expect("lock").join("\n")
                );
            }
            return ips;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn stock_filters_head_to_head_decision_parity() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");

    let ts_sys = syslog_now();
    let ts_ng = nginx_now();
    let ts_ap = apache_now();
    let ts_iso = iso_now();

    let cases: Vec<(&str, Vec<String>)> = vec![
        (
            "nginx-http-auth",
            vec![
                format!(
                    "{ts_ng} [error] 123#0: *1 user \"admin\": password mismatch, client: 198.51.100.21, server: example.com, request: \"GET / HTTP/1.1\", host: \"example.com\""
                ),
                format!("{ts_ng} [info] 123#0: *2 normal request from 198.51.100.99"),
            ],
        ),
        (
            "apache-auth",
            vec![
                format!(
                    "[{ts_ap}] [auth_basic:error] [pid 123] [client 198.51.100.22:54321] AH01618: user bob not found: /secret"
                ),
                format!(
                    "[{ts_ap}] [core:notice] [pid 123] [client 198.51.100.99:54322] normal notice"
                ),
            ],
        ),
        (
            "recidive",
            vec![
                format!("{ts_iso} fail2ban.actions        [123]: NOTICE  [sshd] Ban 198.51.100.26"),
                format!(
                    "{ts_iso} fail2ban.actions        [123]: NOTICE  [sshd] Unban 198.51.100.99"
                ),
            ],
        ),
        (
            "postfix",
            vec![
                format!(
                    "{ts_sys} mail postfix/smtpd[123]: NOQUEUE: reject: RCPT from unknown[198.51.100.23]: 554 5.7.1 <a@b.c>: Relay access denied; from=<x@y.z> to=<a@b.c> proto=ESMTP helo=<bad>"
                ),
                format!("{ts_sys} mail postfix/smtpd[123]: connect from good[198.51.100.99]"),
            ],
        ),
        (
            "dovecot",
            vec![
                format!(
                    "{ts_sys} mail dovecot[123]: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, rip=198.51.100.24, lip=10.0.0.1, session=<abc>"
                ),
                format!(
                    "{ts_sys} mail dovecot[123]: imap-login: Login: user=<alice>, method=PLAIN, rip=198.51.100.99, lip=10.0.0.1"
                ),
            ],
        ),
        (
            "vsftpd",
            vec![
                format!("{ts_sys} ftp vsftpd[123]: [bob] FAIL LOGIN: Client \"198.51.100.25\""),
                format!("{ts_sys} ftp vsftpd[123]: [bob] OK LOGIN: Client \"198.51.100.99\""),
            ],
        ),
    ];

    for (filter_name, lines) in cases {
        let expected = upstream_matched_ips(&source, filter_name, &lines);
        assert!(
            !expected.is_empty(),
            "upstream Fail2Ban 1.1.1 matched 0 IPs for {filter_name}; fix sample log"
        );
        let actual = rust_compat_banned_ips(&source, filter_name, &lines, expected.len());
        assert_eq!(
            actual, expected,
            "decision mismatch for stock filter {filter_name}: rust={actual:?} vs fail2ban-1.1.1={expected:?}"
        );
    }
}
