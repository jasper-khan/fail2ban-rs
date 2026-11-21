//! End-to-end compat chain: the real daemon binary runs from an original
//! Fail2Ban INI tree, watches two log files for one jail, records ban and
//! unban decisions, and survives a SIGHUP reload without skipping or
//! double-counting any log line or failure.
//!
//! Unix-only: the daemon binds a Unix control socket.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Datelike, Timelike};

/// Wall-clock deadline for one wait_for poll loop before the test fails.
const WAIT: Duration = Duration::from_secs(20);

/// Append access to one log file.
struct Tail(PathBuf);

impl Tail {
    fn create(path: &Path) -> std::io::Result<Self> {
        std::fs::write(path, b"")?;
        Ok(Self(path.to_path_buf()))
    }

    fn append(&self, lines: Vec<String>) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.0)
            .expect("open log for append");
        for line in lines {
            writeln!(file, "{line}").expect("write log line");
        }
    }
}

/// A running daemon with its stderr collected into a shared buffer.
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

fn spawn_daemon(base: &Path, record: &Path) -> std::io::Result<Daemon> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fail2ban-rs"))
        .arg("run")
        .arg("--legacy-dir")
        .arg(base)
        .arg("--record-decisions")
        .arg(record)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().expect("stderr piped");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            sink.lock().expect("stderr lock").push(line);
        }
    });
    Ok(Daemon { child, lines })
}

impl Daemon {
    fn signal(&self, sig: &str) {
        let status = Command::new("sh")
            .args(["-c", &format!("kill -{} {}", sig, self.child.id())])
            .status()
            .expect("send signal");
        assert!(status.success(), "kill -{sig} failed");
    }

    fn saw(&self, needle: &str) -> bool {
        self.lines
            .lock()
            .expect("stderr lock")
            .iter()
            .any(|line| line.contains(needle))
    }

    /// Everything the daemon has printed, for failure context.
    fn stderr(&self) -> Vec<String> {
        self.lines.lock().expect("stderr lock").clone()
    }

    /// SIGTERM, wait for exit, and check the status code.
    fn terminate(mut self) -> std::process::ExitStatus {
        self.signal("TERM");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status;
            }
            assert!(
                Instant::now() <= deadline,
                "daemon did not exit on SIGTERM within 15s"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Poll `probe` until it returns true or the deadline passes, dumping the
/// daemon's stderr in the failure message.
fn wait_for(what: &str, daemon: &Daemon, probe: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    loop {
        if probe() {
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "timed out waiting for {what}; daemon said: {:#?}",
            daemon.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A syslog-prefixed line dated now. The daemon's date parser must land the
/// failure inside the jail's findtime window against the wall clock, so the
/// date is the true calendar date (chrono, not a hand-rolled %365 calendar).
fn syslog_line(body: &str) -> String {
    let now = chrono::Local::now();
    format!(
        "{} {:2} {:02}:{:02}:{:02} srv {body}",
        now.format("%b"),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

fn failure(ip: &str) -> String {
    syslog_line(&format!(
        "chain-auth[2143]: failed login for user bob from {ip} port 8081"
    ))
}

/// Stock-format 1.1.1 nginx prefix common include (comments removed).
const NGINX_ERROR_COMMON: &str = concat!(
    "[DEFAULT]\n",
    "logtype = file\n",
    "_daemon = nginx\n",
    "__prefix = <lt_<logtype>/__prefix>\n",
    "__err_type = error\n",
    "__prefix_line = %(__prefix)s\\[%(__err_type)s\\] \\d+#\\d+: \\*\\d+\\s+\n",
    "[lt_file]\n",
    "__prefix = \\s*\n",
    "[lt_short]\n",
    "__prefix = \\s*(?:(?!\\[)\\S+ %(_daemon)s\\[\\d+\\]: [^\\[]*)?\n",
    "[lt_journal]\n",
    "__prefix = %(lt_short/__prefix)s\n",
);

/// Stock-format 1.1.1 nginx-http-auth filter body (comments removed) to run
/// the original prefregex class through the parity-proven legacy engine.
const NGINX_HTTP_AUTH: &str = concat!(
    "[INCLUDES]\n",
    "before = nginx-error-common.conf\n",
    "[Definition]\n",
    "mode = normal\n",
    "__err_type = (?:error|crit)\n",
    "__suffix_line = , client: <ADDR>(?:, (?:server|request|host|referrer): (?:\"[^\"]*\"|\\S*)){0,4}\n",
    "prefregex = ^%(__prefix_line)s<F-CONTENT>.*</F-CONTENT>%(__suffix_line)s\\s*$\n",
    "mdre-auth = ^user \"<F-USER>(?:[^\"]+|.*?)</F-USER>\":? (?:password mismatch|was not found in \"[^\\\"]*\")$\n",
    "            ^(?:PAM: )?user '<F-USER>(?:[^']+|.*?)</F-USER>' - not authenticated: Authentication failure$\n",
    "mdre-fallback = ^SSL_(?:do_handshake|read)\\(\\) failed \\(SSL: error:\\S+(?: \\S+){1,3}[^\\)]*\\)[^,]*\n",
    "mdre-normal = %(mdre-auth)s\n",
    "mdre-aggressive = %(mdre-auth)s\n",
    "                  %(mdre-fallback)s\n",
    "failregex = <mdre-<mode>>\n",
    "ignoreregex = \n",
    "datepattern = {^LN-BEG}\n",
    "journalmatch = _SYSTEMD_UNIT=nginx.service + _COMM=nginx\n",
);

fn nginx_failure() -> String {
    let date = chrono::Utc::now().format("%Y/%m/%d %H:%M:%S");
    format!(
        "{date} [error] 123#123: *4 user \"bob\": password mismatch, \
         client: 192.0.2.10, server: auth.example"
    )
}

/// The original `bips` schema, copied from Fail2Ban 1.1.1 database.py.
const BIPS_DDL: &str = concat!(
    "CREATE TABLE IF NOT EXISTS bips(",
    "ip TEXT NOT NULL, ",
    "jail TEXT NOT NULL, ",
    "timeofban INTEGER NOT NULL, ",
    "bantime INTEGER NOT NULL, ",
    "bancount INTEGER NOT NULL default 1, ",
    "data JSON, ",
    "PRIMARY KEY(ip, jail)",
    ");",
    "CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);",
    "CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);",
);

/// Seed one unexpired original ban for the given jail.
fn seed_original_db(path: &Path, jail: &str, ip: &str, time_of_ban: f64, ban_time: i64) {
    use rusqlite::Connection;
    let connection = Connection::open(path).expect("create original database");
    connection.execute_batch(BIPS_DDL).expect("original DDL");
    connection
        .execute(
            &format!(
                "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data) \
                 VALUES('{ip}', '{jail}', {time_of_ban}, {ban_time}, 1, NULL)"
            ),
            [],
        )
        .expect("seed original ban");
}

/// Wall-clock seconds, shared by the seeded row and the test schedule.
fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_secs() as f64
}

/// The recorded decision lines, "KIND jail ip" each.
fn decisions(record: &Path) -> Vec<String> {
    std::fs::read_to_string(record)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn compat_chain_survives_reload_without_miss_or_duplicate() {
    let tmp = tempfile::tempdir().expect("scratch dir");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let socket = tmp.path().join("f2b.sock");
    let record = tmp.path().join("decisions.log");
    let runtime = tmp.path().join("decisions.log.fail2ban-rs");
    let original_listener = std::os::unix::net::UnixListener::bind(&socket)
        .expect("bind independent original socket fixture");
    let web1_path = tmp.path().join("web1.log");
    let web2_path = tmp.path().join("web2.log");
    let web3_path = tmp.path().join("web3.log");
    let web1 = Tail::create(&web1_path).expect("web1");
    let web2 = Tail::create(&web2_path).expect("web2");
    let web3 = Tail::create(&web3_path).expect("web3");

    std::fs::write(
        base.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {}\ndbfile = {}\n",
            socket.display(),
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
             [chain-jail]\n\
             enabled = true\n\
             port = 8081\n\
             filter = chain-auth\n\
             logpath = {}\n\
             \x20   {}\n\
             maxretry = 3\n\
             findtime = 120s\n\
             bantime = 4s\n\
             \n\
             [nginx-class]\n\
             enabled = true\n\
             port = 443\n\
             filter = nginx-http-auth\n\
             logpath = {web3}\n\
             maxretry = 3\n\
             findtime = 120s\n\
             bantime = 4s\n",
            web1_path.display(),
            web2_path.display(),
            web3 = web3_path.display(),
        ),
    )
    .expect("jail.conf");
    std::fs::write(
        filter_dir.join("chain-auth.conf"),
        "[Definition]\n\
         failregex = chain-auth\\[\\d+\\]: failed login for user \\S+ from <HOST> port \\d+\n\
         ignoreregex =\n",
    )
    .expect("filter");
    std::fs::write(
        filter_dir.join("nginx-error-common.conf"),
        NGINX_ERROR_COMMON,
    )
    .expect("nginx common");
    std::fs::write(filter_dir.join("nginx-http-auth.conf"), NGINX_HTTP_AUTH).expect("nginx filter");

    // Pre-start content must be ignored: the daemon tails from EOF.
    web1.append(vec![failure("9.9.9.9")]);

    // Seed an original 1.1.1 ban database: an unexpired ban from one second
    // ago must be re-applied at startup and expire three seconds in.
    let dbfile = state.join("fail2ban.sqlite3");
    seed_original_db(&dbfile, "chain-jail", "4.4.4.4", wall_now() - 1.0, 4);
    let original_db = std::fs::read(&dbfile).expect("read original DB bytes");

    let daemon = spawn_daemon(&base, &record).expect("spawn daemon");
    wait_for("daemon startup", &daemon, || {
        daemon.saw("fail2ban-rs started") && runtime.join("control.sock").exists()
    });
    let assert_original_untouched = || {
        std::os::unix::net::UnixStream::connect(&socket)
            .expect("original listener still reachable");
        original_listener
            .accept()
            .expect("accept in original fixture");
        assert_eq!(
            std::fs::read(&dbfile).expect("original DB bytes"),
            original_db
        );
        assert_eq!(
            std::fs::read_dir(&state)
                .expect("original state directory")
                .count(),
            1,
            "recording must not write WAL/control files beside the original database"
        );
    };
    assert_original_untouched();
    assert!(runtime.join("state").is_dir(), "missing isolated WAL");

    // The restored original ban re-applies before any log line is read; it
    // must be the daemon's first recorded decision.
    wait_for("original ban restored at startup", &daemon, || {
        decisions(&record)
            .first()
            .is_some_and(|line| line == "BAN chain-jail 4.4.4.4")
    });
    assert_eq!(
        decisions(&record).first().map(String::as_str),
        Some("BAN chain-jail 4.4.4.4"),
        "restoration is the first decision: {:?}",
        decisions(&record)
    );

    // Failures from BOTH log files merge into one jail counter.
    web1.append(vec![failure("1.2.3.4")]);
    web2.append(vec![failure("1.2.3.4")]);
    web1.append(vec![failure("1.2.3.4")]);
    wait_for("first ban across both logs", &daemon, || {
        decisions(&record).contains(&"BAN chain-jail 1.2.3.4".to_owned())
    });

    // The stock nginx class (prefregex, {^LN-BEG}) runs through the
    // parity-proven original engine in the same daemon.
    web3.append(vec![nginx_failure(), nginx_failure(), nginx_failure()]);
    wait_for("legacy-engine ban", &daemon, || {
        decisions(&record).contains(&"BAN nginx-class 192.0.2.10".to_owned())
    });

    // One below the threshold before the reload.
    web1.append(vec![failure("5.6.7.8"), failure("5.6.7.8")]);

    // Reload, and feed one failure into the handover window right away.
    daemon.signal("HUP");
    web2.append(vec![failure("7.7.7.8")]);
    wait_for("config reload marker", &daemon, || {
        daemon.saw("config reload complete")
    });

    // The pre-reload counter survives the reload: one more failure bans.
    web2.append(vec![failure("5.6.7.8")]);
    wait_for("post-reload ban", &daemon, || {
        decisions(&record).contains(&"BAN chain-jail 5.6.7.8".to_owned())
    });

    // The handover-window failure was counted exactly once: with one
    // already counted, a second line must NOT ban yet.
    web1.append(vec![failure("7.7.7.8")]);
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !decisions(&record).contains(&"BAN chain-jail 7.7.7.8".to_owned()),
        "handover line was counted more than once: {:?}",
        decisions(&record)
    );
    // ...and the third one crosses the threshold.
    web2.append(vec![failure("7.7.7.8")]);
    wait_for("handover-counted ban", &daemon, || {
        decisions(&record).contains(&"BAN chain-jail 7.7.7.8".to_owned())
    });

    // Every ban expires and unbans exactly once.
    let expected = [
        "BAN chain-jail 4.4.4.4",
        "BAN chain-jail 1.2.3.4",
        "BAN nginx-class 192.0.2.10",
        "BAN chain-jail 5.6.7.8",
        "BAN chain-jail 7.7.7.8",
        "UNBAN chain-jail 4.4.4.4",
        "UNBAN chain-jail 1.2.3.4",
        "UNBAN nginx-class 192.0.2.10",
        "UNBAN chain-jail 5.6.7.8",
        "UNBAN chain-jail 7.7.7.8",
    ];
    wait_for("all unbans", &daemon, || {
        let recorded = decisions(&record);
        expected
            .iter()
            .all(|line| recorded.contains(&(*line).to_string()))
    });
    std::thread::sleep(Duration::from_secs(1));
    let recorded = decisions(&record);
    let mut sorted = recorded.clone();
    sorted.sort();
    let mut expected_sorted: Vec<String> = expected.iter().map(ToString::to_string).collect();
    expected_sorted.sort();
    assert_eq!(
        sorted, expected_sorted,
        "decisions must contain each entry exactly once and never the pre-start IP: {recorded:?}"
    );
    assert!(
        !recorded.iter().any(|line| line.contains("9.9.9.9")),
        "pre-start content was read: {recorded:?}"
    );

    // Clean shutdown on SIGTERM.
    let status = daemon.terminate();
    assert!(
        status.success(),
        "daemon exited with {status}: {recorded:?}"
    );
    assert!(!runtime.join("control.sock").exists());
    assert_original_untouched();
}
