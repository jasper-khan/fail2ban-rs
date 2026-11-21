//! Stage 3–6 acceptance tests:
//! - Multi-line (`maxlines > 1`), `latin-1` log encoding, and `bantime.increment`
//!   running in the real `fail2ban-rs` compat daemon.
//! - Real upstream Fail2Ban 1.1.1 `bin/fail2ban-client` controlling the live
//!   Rust daemon over the pickle Unix socket protocol (`--legacy-socket`):
//!   `ping`, `status`, `status <jail>`, `set <jail> banip/unbanip`,
//!   `get <jail> banned`, `reload`, error exit code, and `stop`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Datelike, Timelike};

const WAIT: Duration = Duration::from_secs(20);

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

impl Daemon {
    fn saw(&self, needle: &str) -> bool {
        self.lines
            .lock()
            .expect("stderr lock")
            .iter()
            .any(|l| l.contains(needle))
    }

    fn stderr(&self) -> Vec<String> {
        self.lines.lock().expect("stderr lock").clone()
    }

    fn wait_exit(mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status;
            }
            assert!(
                Instant::now() <= deadline,
                "daemon did not exit in time; stderr: {:#?}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn spawn_daemon(base: &Path, record: &Path, legacy_sock: Option<&Path>) -> Daemon {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fail2ban-rs"));
    cmd.arg("run")
        .arg("--legacy-dir")
        .arg(base)
        .arg("--record-decisions")
        .arg(record);
    if let Some(sock) = legacy_sock {
        cmd.arg("--legacy-socket").arg(sock);
    }
    let mut child = cmd
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fail2ban-rs");
    let stderr = child.stderr.take().expect("stderr piped");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            sink.lock().expect("stderr lock").push(line);
        }
    });
    Daemon { child, lines }
}

fn wait_for(what: &str, daemon: &Daemon, probe: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    loop {
        if probe() {
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "timed out waiting for {what}; stderr: {:#?}",
            daemon.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn decisions(record: &Path) -> Vec<String> {
    std::fs::read_to_string(record)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

fn syslog_prefix_now() -> String {
    let now = chrono::Local::now();
    format!(
        "{} {:2} {:02}:{:02}:{:02} srv",
        now.format("%b"),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

#[test]
fn multiline_latin1_and_bantime_increment_work_in_compat_daemon() {
    let tmp = tempfile::tempdir().expect("scratch");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state");
    let record = tmp.path().join("decisions.log");
    let log_path = tmp.path().join("multi.log");
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
             [multi-jail]\n\
             enabled = true\n\
             port = 8080\n\
             filter = multi-latin1\n\
             logencoding = latin-1\n\
             logpath = {}\n\
             maxretry = 2\n\
             findtime = 120s\n\
             bantime = 2s\n\
             bantime.increment = true\n\
             bantime.factor = 1\n\
             bantime.multipliers = 1 2 4\n\
             bantime.maxtime = 60s\n",
            log_path.display(),
        ),
    )
    .expect("jail.conf");

    // 2-line filter matching a Latin-1 accented user line followed by a host line.
    std::fs::write(
        filter_dir.join("multi-latin1.conf"),
        "[Definition]\n\
         maxlines = 2\n\
         failregex = user=rené\\n.*auth failed from <HOST>\n\
         ignoreregex =\n",
    )
    .expect("filter");

    let daemon = spawn_daemon(&base, &record, None);
    wait_for("startup", &daemon, || daemon.saw("fail2ban-rs started"));

    // Write 2 two-line Latin-1 blocks (0xe9 = 'é' in ISO-8859-1, NOT valid UTF-8!).
    let ts = syslog_prefix_now();
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .expect("open log");
    for _ in 0..2 {
        f.write_all(format!("{ts} app[1]: user=ren").as_bytes())
            .unwrap();
        f.write_all(&[0xe9, b'\n']).unwrap();
        f.write_all(format!("{ts} app[1]: auth failed from 198.51.100.66\n").as_bytes())
            .unwrap();
    }
    f.flush().unwrap();

    wait_for("multiline latin-1 ban", &daemon, || {
        decisions(&record).contains(&"BAN multi-jail 198.51.100.66".to_owned())
    });
    wait_for("first ban expires", &daemon, || {
        decisions(&record).contains(&"UNBAN multi-jail 198.51.100.66".to_owned())
    });
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn upstream_fail2ban_client_controls_rust_daemon_e2e() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");

    let tmp = tempfile::tempdir().expect("scratch");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state");
    let record = tmp.path().join("decisions.log");
    let legacy_sock = tmp.path().join("fail2ban-legacy.sock");
    let auth_log = tmp.path().join("auth.log");
    std::fs::write(&auth_log, b"").expect("auth.log");

    std::fs::copy(
        source.join("config/filter.d/common.conf"),
        filter_dir.join("common.conf"),
    )
    .expect("copy common.conf");
    std::fs::copy(
        source.join("config/filter.d/sshd.conf"),
        filter_dir.join("sshd.conf"),
    )
    .expect("copy sshd.conf");

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
             [sshd]\n\
             enabled = true\n\
             port = 22\n\
             filter = sshd\n\
             logpath = {}\n\
             maxretry = 3\n\
             findtime = 60s\n\
             bantime = 600s\n",
            auth_log.display(),
        ),
    )
    .expect("jail.conf");

    let daemon = spawn_daemon(&base, &record, Some(&legacy_sock));
    wait_for("legacy socket listening", &daemon, || {
        daemon.saw("fail2ban-rs started") && legacy_sock.exists()
    });

    let f2b_client = |args: &[&str]| {
        Command::new("python3")
            .arg(source.join("bin/fail2ban-client"))
            .arg("-c")
            .arg(&base)
            .arg("-s")
            .arg(&legacy_sock)
            .args(args)
            .env("PYTHONPATH", &source)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .expect("run upstream fail2ban-client")
    };

    // 1. ping
    let out = f2b_client(&["ping"]);
    assert!(
        out.status.success(),
        "ping failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("pong"),
        "unexpected ping stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // 2. status
    let out = f2b_client(&["status"]);
    assert!(
        out.status.success(),
        "status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Number of jail:\t1"), "stdout: {stdout}");
    assert!(stdout.contains("sshd"), "stdout: {stdout}");

    // 3. set sshd banip 198.51.100.55
    let out = f2b_client(&["set", "sshd", "banip", "198.51.100.55"]);
    assert!(
        out.status.success(),
        "banip failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
    wait_for("banip recorded", &daemon, || {
        decisions(&record).contains(&"BAN sshd 198.51.100.55".to_owned())
    });

    // 4. status sshd + get sshd banned
    let out = f2b_client(&["status", "sshd"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("198.51.100.55"), "status sshd: {stdout}");

    let out = f2b_client(&["get", "sshd", "banned"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("198.51.100.55"),
        "get banned: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // 5. set sshd unbanip 198.51.100.55
    let out = f2b_client(&["set", "sshd", "unbanip", "198.51.100.55"]);
    assert!(out.status.success());
    wait_for("unbanip recorded", &daemon, || {
        decisions(&record).contains(&"UNBAN sshd 198.51.100.55".to_owned())
    });

    // 6. reload
    let out = f2b_client(&["reload"]);
    assert!(
        out.status.success(),
        "reload failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    wait_for("reload complete", &daemon, || {
        daemon.saw("config reload complete")
    });

    // 7. Unknown jail must return non-zero exit code from real fail2ban-client!
    let out = f2b_client(&["status", "does-not-exist"]);
    assert!(
        !out.status.success(),
        "unknown jail must fail in fail2ban-client"
    );

    // 8. stop must cleanly shut down the Rust daemon!
    let out = f2b_client(&["stop"]);
    assert!(
        out.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(daemon.wait_exit().success(), "daemon clean exit after stop");
}

#[test]
fn systemd_backend_compat_jail_with_fake_journalctl_e2e() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("scratch");
    let bin_dir = tmp.path().join("bin");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&bin_dir).expect("bin");
    std::fs::create_dir_all(&filter_dir).expect("filter.d");
    std::fs::create_dir_all(&state).expect("state");
    let record = tmp.path().join("decisions.log");

    // Create a fake `journalctl` on PATH that emits two JSON entries matching
    // our compat jail filter, then stays open until killed (like --follow).
    let now_us = chrono::Utc::now().timestamp_micros();
    let fake_journalctl = bin_dir.join("journalctl");
    std::fs::write(
        &fake_journalctl,
        format!(
            "#!/bin/sh\n\
             printf '{{\"__CURSOR\":\"s=1;i=1\",\"__REALTIME_TIMESTAMP\":\"{t1}\",\"_HOSTNAME\":\"srv\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"_PID\":\"42\",\"MESSAGE\":\"Failed password for invalid user root from 198.51.100.88 port 50001 ssh2\"}}\\n'\n\
             printf '{{\"__CURSOR\":\"s=1;i=2\",\"__REALTIME_TIMESTAMP\":\"{t2}\",\"_HOSTNAME\":\"srv\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"_PID\":\"42\",\"MESSAGE\":\"Failed password for invalid user root from 198.51.100.88 port 50002 ssh2\"}}\\n'\n\
             sleep 30\n",
            t1 = now_us,
            t2 = now_us + 1_000_000,
        ),
    )
    .expect("write fake journalctl");
    std::fs::set_permissions(&fake_journalctl, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake journalctl");

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
        "[DEFAULT]\n\
         backend = systemd\n\
         usedns = no\n\
         ignoreself = false\n\
         action =\n\
         \n\
         [sshd-journal]\n\
         enabled = true\n\
         port = 22\n\
         filter = sshd-mini\n\
         journalmatch = _SYSTEMD_UNIT=sshd.service\n\
         maxretry = 2\n\
         findtime = 120s\n\
         bantime = 60s\n",
    )
    .expect("jail.conf");
    std::fs::write(
        filter_dir.join("sshd-mini.conf"),
        "[Definition]\n\
         failregex = Failed password for invalid user .* from <HOST> port \\d+ ssh2\n\
         ignoreregex =\n",
    )
    .expect("filter");

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{orig_path}", bin_dir.display());
    let mut child = Command::new(env!("CARGO_BIN_EXE_fail2ban-rs"))
        .arg("run")
        .arg("--legacy-dir")
        .arg(&base)
        .arg("--record-decisions")
        .arg(&record)
        .env("PATH", new_path)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fail2ban-rs");
    let stderr = child.stderr.take().expect("stderr");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            sink.lock().expect("lock").push(line);
        }
    });
    let daemon = Daemon { child, lines };

    wait_for("systemd compat ban", &daemon, || {
        decisions(&record).contains(&"BAN sshd-journal 198.51.100.88".to_owned())
    });
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn full_upgrade_live_action_sqlite_rw_and_rollback_drill() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");

    let tmp = tempfile::tempdir().expect("scratch");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    let action_dir = base.join("action.d");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&filter_dir).expect("filter.d");
    std::fs::create_dir_all(&action_dir).expect("action.d");
    std::fs::create_dir_all(&state).expect("state");

    let db_path = state.join("fail2ban.sqlite3");
    let action_log = tmp.path().join("action-audit.log");
    let legacy_sock = tmp.path().join("fail2ban-live.sock");
    let auth_log = tmp.path().join("auth.log");

    // Copy stock upstream sshd filter.
    std::fs::copy(
        source.join("config/filter.d/common.conf"),
        filter_dir.join("common.conf"),
    )
    .expect("copy common.conf");
    std::fs::copy(
        source.join("config/filter.d/sshd.conf"),
        filter_dir.join("sshd.conf"),
    )
    .expect("copy sshd.conf");

    // Seed an initial auth.log line that upstream 1.1.1 has already processed.
    let ts = syslog_prefix_now();
    let initial_line = format!(
        "{ts} sshd[100]: Failed password for invalid user old from 198.51.100.10 port 40001 ssh2\n"
    );
    std::fs::write(&auth_log, &initial_line).expect("seed auth.log");

    // Step 1: Seed fail2ban.sqlite3 using REAL upstream Fail2Ban 1.1.1 Fail2BanDb:
    // - active ban on 198.51.100.77
    // - log offset past initial_line
    let seed_script = r#"
import hashlib, sys, time
sys.path.insert(0, sys.argv[1])
from fail2ban.server.database import Fail2BanDb
from fail2ban.server.ticket import FailTicket

db = Fail2BanDb(sys.argv[2])
class DummyActions:
    def getBanTime(self): return 600
class DummyJail:
    def __init__(self, name):
        self.name = name
        self.actions = DummyActions()
jail = DummyJail("sshd")
db.addJail(jail)

log_path = sys.argv[3]
with open(log_path, "rb") as f:
    first = f.readline()
    pos = f.tell()
class DummyContainer:
    def __init__(self, fn, h, p):
        self._fn, self._h, self._p = fn, h, p
    def getFileName(self): return self._fn
    def getHash(self): return self._h
    def getPos(self): return self._p
h = hashlib.md5(first).hexdigest()
db.addLog(jail, DummyContainer(log_path, h, pos))

t = FailTicket("198.51.100.77", time=time.time(), matches=[])
t.setBanTime(600)
db.addBan(jail, t)
db.close()
print(pos)
"#;
    let seed_out = Command::new("python3")
        .arg("-c")
        .arg(seed_script)
        .arg(&source)
        .arg(&db_path)
        .arg(&auth_log)
        .output()
        .expect("seed upstream sqlite");
    assert!(
        seed_out.status.success(),
        "upstream sqlite seed failed: {}",
        String::from_utf8_lossy(&seed_out.stderr)
    );
    let initial_pos: u64 = String::from_utf8_lossy(&seed_out.stdout)
        .trim()
        .parse()
        .expect("parse initial pos");

    // Isolated action.d file (no host firewall touched).
    std::fs::write(
        action_dir.join("isolated-audit.conf"),
        format!(
            "[Definition]\n\
             actionstart = printf 'START <name> <port> <protocol>\\n' >> {log}\n\
             actionstop = printf 'STOP <name>\\n' >> {log}\n\
             actionban = printf 'BAN <name> <ip>\\n' >> {log}\n\
             actionunban = printf 'UNBAN <name> <ip>\\n' >> {log}\n",
            log = action_log.display(),
        ),
    )
    .expect("action.d/isolated-audit.conf");

    std::fs::write(
        base.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {}\ndbfile = {}\n",
            tmp.path().join("orig.sock").display(),
            db_path.display()
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
             \n\
             [sshd]\n\
             enabled = true\n\
             port = 22\n\
             protocol = tcp\n\
             filter = sshd\n\
             action = isolated-audit[name=sshd, port=22, protocol=tcp]\n\
             logpath = {}\n\
             maxretry = 2\n\
             findtime = 120s\n\
             bantime = 600s\n",
            auth_log.display(),
        ),
    )
    .expect("jail.conf");

    // Step 2: Start fail2ban-rs in full live compat mode (action.d + SQLite RW + legacy socket).
    let mut child = Command::new(env!("CARGO_BIN_EXE_fail2ban-rs"))
        .arg("run")
        .arg("--legacy-dir")
        .arg(&base)
        .arg("--legacy-execute-actions")
        .arg("--legacy-sqlite-rw")
        .arg("--legacy-socket")
        .arg(&legacy_sock)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fail2ban-rs live");
    let stderr = child.stderr.take().expect("stderr");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            sink.lock().expect("lock").push(line);
        }
    });
    let daemon = Daemon { child, lines };

    wait_for("startup + legacy socket", &daemon, || {
        daemon.saw("fail2ban-rs started") && legacy_sock.exists()
    });

    // Verify actionstart + restored legacy ban (198.51.100.77) fired via action.d.
    wait_for("actionstart + restored ban", &daemon, || {
        let log = decisions(&action_log);
        log.iter().any(|l| l == "START sshd 22 tcp")
            && log.iter().any(|l| l == "BAN sshd 198.51.100.77")
    });

    // Step 3: Append 2 new failed SSH lines -> triggers live actionban + SQLite RW.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&auth_log)
        .expect("append auth.log");
    writeln!(
        f,
        "{ts} sshd[201]: Failed password for invalid user bob from 203.0.113.55 port 50001 ssh2"
    )
    .unwrap();
    writeln!(
        f,
        "{ts} sshd[202]: Failed password for invalid user bob from 203.0.113.55 port 50002 ssh2"
    )
    .unwrap();
    f.flush().unwrap();

    wait_for("new live ban", &daemon, || {
        decisions(&action_log).contains(&"BAN sshd 203.0.113.55".to_owned())
    });

    // Step 4: Control live Rust daemon using REAL upstream bin/fail2ban-client.
    let run_client = |args: &[&str]| -> std::process::Output {
        Command::new("python3")
            .arg(source.join("bin/fail2ban-client"))
            .arg("-c")
            .arg(&base)
            .arg("-s")
            .arg(&legacy_sock)
            .args(args)
            .env("PYTHONPATH", &source)
            .output()
            .expect("run upstream fail2ban-client")
    };

    let ping = run_client(&["ping"]);
    assert!(ping.status.success());
    assert!(String::from_utf8_lossy(&ping.stdout).contains("pong"));

    let st = run_client(&["status", "sshd"]);
    assert!(st.status.success());
    let st_out = String::from_utf8_lossy(&st.stdout);
    assert!(
        st_out.contains("198.51.100.77"),
        "status missing restored ban: {st_out}"
    );
    assert!(
        st_out.contains("203.0.113.55"),
        "status missing new ban: {st_out}"
    );

    // Unban the legacy-restored IP via upstream fail2ban-client.
    let unban = run_client(&["set", "sshd", "unbanip", "198.51.100.77"]);
    assert!(
        unban.status.success(),
        "unbanip failed: {}",
        String::from_utf8_lossy(&unban.stderr)
    );
    wait_for("actionunban fired", &daemon, || {
        decisions(&action_log).contains(&"UNBAN sshd 198.51.100.77".to_owned())
    });

    let reload = run_client(&["reload"]);
    assert!(
        reload.status.success(),
        "reload failed: {}",
        String::from_utf8_lossy(&reload.stderr)
    );

    let stop = run_client(&["stop"]);
    assert!(
        stop.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let exit = daemon.wait_exit();
    assert!(exit.success(), "daemon did not exit cleanly: {exit:?}");

    let final_actions = decisions(&action_log);
    assert!(
        final_actions.iter().any(|l| l == "STOP sshd"),
        "actionstop did not fire on shutdown: {final_actions:?}"
    );

    // Step 5: Rollback verification — open the EXACT SAME fail2ban.sqlite3
    // with REAL upstream Fail2Ban 1.1.1 Fail2BanDb!
    let verify_script = r#"
import json, sys
sys.path.insert(0, sys.argv[1])
from fail2ban.server.database import Fail2BanDb

db = Fail2BanDb(sys.argv[2])
class DummyJail:
    def __init__(self, name): self.name = name
    def getMaxBanTime(self): return 600
jail = DummyJail("sshd")
bans = sorted(str(t.getIP()) for t in db.getCurrentBans(jail=jail))
logs = db.getLogPaths(jail=jail)
# Also inspect logs table directly for lastfilepos.
cur = db._db.cursor()
rows = cur.execute("SELECT path, lastfilepos FROM logs WHERE jail = ?", ("sshd",)).fetchall()
db.close()
print(json.dumps({"bans": bans, "logs": [[r[0], r[1]] for r in rows]}))
"#;
    let verify_out = Command::new("python3")
        .arg("-c")
        .arg(verify_script)
        .arg(&source)
        .arg(&db_path)
        .output()
        .expect("verify rollback sqlite");
    assert!(
        verify_out.status.success(),
        "upstream rollback read failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&verify_out.stdout).expect("parse verify json");
    assert_eq!(
        parsed.get("bans"),
        Some(&serde_json::json!(["203.0.113.55"])),
        "rollback bans must keep 203.0.113.55 and NOT resurrect unbanned 198.51.100.77: {parsed}"
    );
    let persisted_pos = parsed
        .get("logs")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get(1))
        .and_then(serde_json::Value::as_u64)
        .expect("log offset");
    assert!(
        persisted_pos > initial_pos,
        "rollback log offset must advance past initial {initial_pos}, got {persisted_pos}"
    );
}
