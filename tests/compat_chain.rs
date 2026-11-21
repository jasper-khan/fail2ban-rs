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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Poll `probe` until it returns true or the deadline passes.
fn wait_for(what: &str, probe: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    loop {
        if probe() {
            return;
        }
        assert!(Instant::now() <= deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A syslog-prefixed line with the current wall time. The concrete date
/// does not matter for the test; all lines share the helper's clock.
fn syslog_line(body: &str) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock")
        .as_secs();
    const MONTH_DAYS: [(&str, u32); 12] = [
        ("Jan", 31),
        ("Feb", 28),
        ("Mar", 31),
        ("Apr", 30),
        ("May", 31),
        ("Jun", 30),
        ("Jul", 31),
        ("Aug", 31),
        ("Sep", 30),
        ("Oct", 31),
        ("Nov", 30),
        ("Dec", 31),
    ];
    let mut rest = ((secs / 86_400) % 365) as u32;
    let secs_of_day = secs % 86_400;
    let mut month = "Jan";
    for (name, days) in MONTH_DAYS {
        if rest < days {
            month = name;
            break;
        }
        rest -= days;
    }
    format!(
        "{month} {:2} {:02}:{:02}:{:02} srv {body}",
        rest + 1,
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60,
    )
}

fn failure(ip: &str) -> String {
    syslog_line(&format!(
        "chain-auth[2143]: failed login for user bob from {ip} port 8081"
    ))
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
    let web1_path = tmp.path().join("web1.log");
    let web2_path = tmp.path().join("web2.log");
    let web1 = Tail::create(&web1_path).expect("web1");
    let web2 = Tail::create(&web2_path).expect("web2");

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
             bantime = 4s\n",
            web1_path.display(),
            web2_path.display(),
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

    // Pre-start content must be ignored: the daemon tails from EOF.
    web1.append(vec![failure("9.9.9.9")]);

    let daemon = spawn_daemon(&base, &record).expect("spawn daemon");
    wait_for("daemon startup", || daemon.saw("fail2ban-rs started"));

    // Failures from BOTH log files merge into one jail counter.
    web1.append(vec![failure("1.2.3.4")]);
    web2.append(vec![failure("1.2.3.4")]);
    web1.append(vec![failure("1.2.3.4")]);
    wait_for("first ban across both logs", || {
        decisions(&record).contains(&"BAN chain-jail 1.2.3.4".to_owned())
    });

    // One below the threshold before the reload.
    web1.append(vec![failure("5.6.7.8"), failure("5.6.7.8")]);

    // Reload, and feed one failure into the handover window right away.
    daemon.signal("HUP");
    web2.append(vec![failure("7.7.7.8")]);
    wait_for("config reload marker", || {
        daemon.saw("config reload complete")
    });

    // The pre-reload counter survives the reload: one more failure bans.
    web2.append(vec![failure("5.6.7.8")]);
    wait_for("post-reload ban", || {
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
    wait_for("handover-counted ban", || {
        decisions(&record).contains(&"BAN chain-jail 7.7.7.8".to_owned())
    });

    // Every ban expires and unbans exactly once.
    let expected = [
        "BAN chain-jail 1.2.3.4",
        "BAN chain-jail 5.6.7.8",
        "BAN chain-jail 7.7.7.8",
        "UNBAN chain-jail 1.2.3.4",
        "UNBAN chain-jail 5.6.7.8",
        "UNBAN chain-jail 7.7.7.8",
    ];
    wait_for("all unbans", || {
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
}
