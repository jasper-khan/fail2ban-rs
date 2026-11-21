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

/// The original `logs` schema, copied from Fail2Ban 1.1.1 database.py.
const LOGS_DDL: &str = concat!(
    "CREATE TABLE IF NOT EXISTS logs(",
    "jail TEXT NOT NULL, ",
    "path TEXT, ",
    "firstlinemd5 TEXT, ",
    "lastfilepos INTEGER DEFAULT 0, ",
    "UNIQUE(jail, path)",
    ");"
);

/// Minimal SHA-1 hex helper matching Fail2Ban 1.1.1's Python 3 first-line hash.
#[allow(clippy::many_single_char_names, clippy::indexing_slicing)]
fn sha1_hex(input: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let transform = |st: &mut [u32; 5], block: &[u8; 64]| {
        let mut w = [0_u32; 16];
        for (slot, chunk) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*chunk);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *st;
        for round in 0..80_usize {
            let word = if round < 16 {
                w[round]
            } else {
                let next = (w[(round - 3) % 16]
                    ^ w[(round - 8) % 16]
                    ^ w[(round - 14) % 16]
                    ^ w[(round - 16) % 16])
                    .rotate_left(1);
                w[round % 16] = next;
                next
            };
            let (mix, k) = match round {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(mix)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            (a, b, c, d, e) = (next, a, b.rotate_left(30), c, d);
        }
        for (cur, delta) in st.iter_mut().zip([a, b, c, d, e]) {
            *cur = cur.wrapping_add(delta);
        }
    };
    let (blocks, tail) = input.as_chunks::<64>();
    for block in blocks {
        transform(&mut state, block);
    }
    let size = if tail.len() < 56 { 64 } else { 128 };
    let mut pad = [0_u8; 128];
    pad[..tail.len()].copy_from_slice(tail);
    pad[tail.len()] = 0x80;
    let bits = (input.len() as u64).wrapping_mul(8);
    pad[size - 8..size].copy_from_slice(&bits.to_be_bytes());
    for block in pad[..size].as_chunks::<64>().0 {
        transform(&mut state, block);
    }
    let mut out = String::with_capacity(40);
    for byte in state.into_iter().flat_map(u32::to_be_bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn send_control(
    socket: &Path,
    req: &fail2ban_rs::control::Request,
) -> fail2ban_rs::control::Response {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("control tokio runtime");
    rt.block_on(fail2ban_rs::control::send_request(socket, req))
        .expect("send control request")
}

fn kill_hard(mut daemon: Daemon) {
    let _ = daemon.child.kill();
    let _ = daemon.child.wait();
}

#[test]
fn compat_chain_legacy_checkpoints_restart_unban_and_reload() {
    let tmp = tempfile::tempdir().expect("scratch dir");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let socket = tmp.path().join("f2b.sock");
    let record = tmp.path().join("decisions.log");
    let runtime = tmp.path().join("decisions.log.fail2ban-rs");
    let _original_listener = std::os::unix::net::UnixListener::bind(&socket)
        .expect("bind independent original socket fixture");

    let web1_path = tmp.path().join("web1.log");
    let web2_path = tmp.path().join("web2.log");
    let web3_path = tmp.path().join("web3.log");
    let web4_path = tmp.path().join("web4.log");
    let web1 = Tail::create(&web1_path).expect("web1");
    let web2 = Tail::create(&web2_path).expect("web2");
    let _web3 = Tail::create(&web3_path).expect("web3");
    let web4 = Tail::create(&web4_path).expect("web4");

    // Pre-populate logs before startup:
    // - web1: valid checkpoint after 3 lines of 9.9.9.9; 2 lines of 1.2.3.4 appended after checkpoint.
    let w1_line1 = format!("{}\n", failure("9.9.9.9"));
    let w1_pre = format!("{w1_line1}{}\n{}\n", failure("9.9.9.9"), failure("9.9.9.9"));
    let w1_checkpoint = w1_pre.len() as i64;
    let w1_hash = sha1_hex(w1_line1.as_bytes());
    std::fs::write(&web1_path, &w1_pre).expect("write web1 pre");
    web1.append(vec![failure("1.2.3.4"), failure("1.2.3.4")]);

    // - web2: rotated file (DB has a different first-line hash + offset 500) -> must read from 0.
    web2.append(vec![
        failure("2.3.4.5"),
        failure("2.3.4.5"),
        failure("2.3.4.5"),
    ]);

    // - web3: truncated file (DB has matching first-line hash + offset 99999 > size) -> must read from 0.
    let w3_line1 = format!("{}\n", failure("3.4.5.6"));
    let w3_hash = sha1_hex(w3_line1.as_bytes());
    std::fs::write(
        &web3_path,
        format!("{w3_line1}{}\n{}\n", failure("3.4.5.6"), failure("3.4.5.6")),
    )
    .expect("write web3");

    // - web4: invalid checkpoint (NULL hash, negative offset) -> must read from 0.
    web4.append(vec![
        failure("6.7.8.9"),
        failure("6.7.8.9"),
        failure("6.7.8.9"),
    ]);

    let dbfile = state.join("fail2ban.sqlite3");
    std::fs::write(
        base.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {}\ndbfile = {}\n",
            socket.display(),
            dbfile.display()
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
             \x20   {}\n\
             \x20   {}\n\
             maxretry = 3\n\
             findtime = 120s\n\
             bantime = 600s\n",
            web1_path.display(),
            web2_path.display(),
            web3_path.display(),
            web4_path.display(),
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

    // Seed original SQLite with one long-lived ban (4.4.4.4) + all 4 log checkpoints.
    seed_original_db(&dbfile, "chain-jail", "4.4.4.4", wall_now() - 1.0, 600);
    {
        let conn = rusqlite::Connection::open(&dbfile).expect("open db");
        conn.execute_batch(LOGS_DDL).expect("logs ddl");
        conn.execute(
            "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('chain-jail', ?1, ?2, ?3)",
            rusqlite::params![web1_path.to_string_lossy().as_ref(), w1_hash, w1_checkpoint],
        )
        .expect("seed web1");
        conn.execute(
            "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('chain-jail', ?1, ?2, 500)",
            rusqlite::params![web2_path.to_string_lossy().as_ref(), "0".repeat(40)],
        )
        .expect("seed web2");
        conn.execute(
            "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('chain-jail', ?1, ?2, 99999)",
            rusqlite::params![web3_path.to_string_lossy().as_ref(), w3_hash],
        )
        .expect("seed web3");
        conn.execute(
            "INSERT INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES('chain-jail', ?1, NULL, -10)",
            rusqlite::params![web4_path.to_string_lossy().as_ref()],
        )
        .expect("seed web4");
    }
    let original_db = std::fs::read(&dbfile).expect("original DB bytes");

    // Pre-populate a non-empty isolated WAL with a different active ban (198.51.100.10)
    // to verify non-empty WAL still imports 4.4.4.4 without losing existing WAL entries.
    {
        use std::os::unix::fs::PermissionsExt;
        let wal_dir = runtime.join("state");
        std::fs::create_dir_all(&wal_dir).expect("wal dir");
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("chmod runtime 0700");
        std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod state 0700");
        let store = fail2ban_rs::track::persist::open_ban_store(wal_dir).expect("open wal");
        let now = chrono::Utc::now().timestamp();
        let ip: std::net::IpAddr = "198.51.100.10".parse().expect("ip");
        store
            .write_durable(|tx| {
                tx.bans.put(
                    (ip, "chain-jail".to_owned()),
                    fail2ban_rs::track::state::BanRecord {
                        ip,
                        jail_id: "chain-jail".to_owned(),
                        banned_at: now - 5,
                        expires_at: Some(now + 600),
                    },
                )?;
                Ok(())
            })
            .expect("seed non-empty wal");
    }

    // --- Run #1: first migration from legacy DB + non-empty WAL ---
    let daemon1 = spawn_daemon(&base, &record).expect("spawn daemon 1");
    let ctrl_sock = runtime.join("control.sock");
    wait_for("daemon 1 startup", &daemon1, || {
        daemon1.saw("fail2ban-rs started") && ctrl_sock.exists()
    });

    // Both the pre-existing WAL ban and the imported legacy ban must be applied,
    // plus all three fallback logs (rotated/truncated/invalid) must ban immediately.
    let initial_bans = [
        "BAN chain-jail 198.51.100.10",
        "BAN chain-jail 4.4.4.4",
        "BAN chain-jail 2.3.4.5",
        "BAN chain-jail 3.4.5.6",
        "BAN chain-jail 6.7.8.9",
    ];
    wait_for("initial bans + fallbacks", &daemon1, || {
        let rec = decisions(&record);
        initial_bans.iter().all(|b| rec.iter().any(|l| l == b))
    });

    // Pre-checkpoint 9.9.9.9 must NOT have been read, and 1.2.3.4 only had 2 post-checkpoint lines.
    std::thread::sleep(Duration::from_millis(600));
    let rec = decisions(&record);
    assert!(
        !rec.iter().any(|l| l.contains("9.9.9.9")),
        "pre-checkpoint lines were re-read: {rec:?}"
    );
    assert!(
        !rec.iter().any(|l| l.contains("1.2.3.4")),
        "1.2.3.4 had only 2 lines after checkpoint: {rec:?}"
    );

    // One more failure for 1.2.3.4 crosses maxretry=3 (proving the 2 post-checkpoint lines were read!).
    web1.append(vec![failure("1.2.3.4")]);
    wait_for("resumed 1.2.3.4 ban", &daemon1, || {
        decisions(&record).contains(&"BAN chain-jail 1.2.3.4".to_owned())
    });

    // Manually unban the imported legacy ban 4.4.4.4 via the control socket.
    let unban_resp = send_control(
        &ctrl_sock,
        &fail2ban_rs::control::Request::Unban {
            ip: "4.4.4.4".parse().expect("ip"),
            jail: "chain-jail".to_owned(),
        },
    );
    assert!(
        matches!(unban_resp, fail2ban_rs::control::Response::Ok { .. }),
        "manual unban failed: {unban_resp:?}"
    );
    wait_for("manual unban recorded", &daemon1, || {
        decisions(&record).contains(&"UNBAN chain-jail 4.4.4.4".to_owned())
    });

    // Reload via SIGHUP with a handover line.
    daemon1.signal("HUP");
    web1.append(vec![failure("7.7.7.1")]);
    wait_for("reload complete", &daemon1, || {
        daemon1.saw("config reload complete")
    });
    web1.append(vec![failure("7.7.7.1"), failure("7.7.7.1")]);
    wait_for("post-reload ban 7.7.7.1", &daemon1, || {
        decisions(&record).contains(&"BAN chain-jail 7.7.7.1".to_owned())
    });

    // Graceful shutdown persists Rust's own log_positions.json.
    assert!(daemon1.terminate().success(), "daemon 1 clean exit");
    assert!(
        runtime.join("state").join("log_positions.json").is_file(),
        "Rust must persist its own log_positions.json"
    );
    assert_eq!(
        std::fs::read(&dbfile).expect("db bytes"),
        original_db,
        "original SQLite DB must stay strictly read-only"
    );
    assert_eq!(
        std::fs::read_dir(&state)
            .expect("original state dir")
            .count(),
        1,
        "no WAL/SHM files beside original SQLite DB"
    );

    // Clear the decision log before Run #2 so we can verify exact post-restart behavior.
    std::fs::write(&record, b"").expect("clear record before run 2");

    // Append 3 lines for 8.8.8.1 while daemon is stopped.
    web1.append(vec![
        failure("8.8.8.1"),
        failure("8.8.8.1"),
        failure("8.8.8.1"),
    ]);

    // --- Run #2: restart from Rust's persisted WAL + log_positions.json ---
    let daemon2 = spawn_daemon(&base, &record).expect("spawn daemon 2");
    wait_for("daemon 2 startup", &daemon2, || {
        daemon2.saw("fail2ban-rs started") && ctrl_sock.exists()
    });
    wait_for("offline lines read on restart", &daemon2, || {
        decisions(&record).contains(&"BAN chain-jail 8.8.8.1".to_owned())
    });
    std::thread::sleep(Duration::from_millis(600));
    let rec2 = decisions(&record);
    assert!(
        !rec2.iter().any(|l| l.contains("4.4.4.4")),
        "manually unbanned legacy IP 4.4.4.4 resurrected after restart: {rec2:?}"
    );
    assert!(
        !rec2.iter().any(|l| l.contains("9.9.9.9")),
        "pre-checkpoint 9.9.9.9 was read after restart: {rec2:?}"
    );

    // Wait until log_positions.json reflects the current web1.log length, then SIGKILL.
    let web1_len = std::fs::metadata(&web1_path).expect("web1 meta").len();
    wait_for("checkpoint flushed after 8.8.8.1", &daemon2, || {
        std::fs::read_to_string(runtime.join("state").join("log_positions.json"))
            .unwrap_or_default()
            .contains(&format!("\"offset\":{web1_len}"))
    });
    kill_hard(daemon2);

    // Remove stale control.sock only if needed? No — recording_listener refuses pre-existing
    // sockets, so simulate clean runtime socket cleanup or verify fresh socket after SIGKILL?
    // Wait: recording_listener refuses any pre-existing socket file by design (safety invariant),
    // so remove only the dead control.sock left by SIGKILL before starting Run #3.
    let _ = std::fs::remove_file(&ctrl_sock);

    std::fs::write(&record, b"").expect("clear record before run 3");
    // Append 3 lines for 8.8.8.2 while dead after SIGKILL.
    web1.append(vec![
        failure("8.8.8.2"),
        failure("8.8.8.2"),
        failure("8.8.8.2"),
    ]);

    // --- Run #3: recovery after SIGKILL post-checkpoint-save ---
    let daemon3 = spawn_daemon(&base, &record).expect("spawn daemon 3");
    wait_for("daemon 3 startup", &daemon3, || {
        daemon3.saw("fail2ban-rs started") && ctrl_sock.exists()
    });
    wait_for("post-SIGKILL lines read", &daemon3, || {
        decisions(&record).contains(&"BAN chain-jail 8.8.8.2".to_owned())
    });
    std::thread::sleep(Duration::from_millis(600));
    let rec3 = decisions(&record);
    assert!(
        !rec3.iter().any(|l| l.contains("4.4.4.4")),
        "unbanned 4.4.4.4 resurrected after SIGKILL recovery: {rec3:?}"
    );
    assert!(
        !rec3.iter().any(|l| l.contains("9.9.9.9")),
        "pre-checkpoint 9.9.9.9 read after SIGKILL recovery: {rec3:?}"
    );
    assert!(daemon3.terminate().success(), "daemon 3 clean exit");
    assert_eq!(
        std::fs::read(&dbfile).expect("db bytes final"),
        original_db,
        "original SQLite DB must remain untouched across all restarts"
    );
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn compat_chain_real_fail2ban_111_db_migration_and_restart() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");
    let tmp = tempfile::tempdir().expect("scratch dir");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let socket = tmp.path().join("f2b.sock");
    let record = tmp.path().join("decisions.log");
    let runtime = tmp.path().join("decisions.log.fail2ban-rs");
    let dbfile = state.join("fail2ban.sqlite3");

    let web1_path = tmp.path().join("web1.log");
    let web2_path = tmp.path().join("web2.log");
    let web3_path = tmp.path().join("web3.log");
    let web1 = Tail::create(&web1_path).expect("web1");
    let _web2 = Tail::create(&web2_path).expect("web2");
    let _web3 = Tail::create(&web3_path).expect("web3");

    let pre1 = format!(
        "{}\n{}\n{}\n",
        failure("9.9.9.9"),
        failure("9.9.9.9"),
        failure("9.9.9.9")
    );
    let pos1 = pre1.len();
    std::fs::write(&web1_path, &pre1).expect("write web1");
    std::fs::write(&web2_path, format!("{}\n", failure("9.9.9.8"))).expect("write web2 old");
    let pre3 = format!("{}\n{}\n", failure("3.3.3.3"), failure("3.3.3.3"));
    let pos3 = pre3.len();
    std::fs::write(&web3_path, &pre3).expect("write web3 old");

    // Generate a REAL Fail2Ban 1.1.1 SQLite DB using upstream Fail2BanDb + FileContainer + BanTicket.
    let py = r"
import sys, time
from types import SimpleNamespace
from fail2ban.server.database import Fail2BanDb
from fail2ban.server.filter import FileContainer
from fail2ban.server.ticket import BanTicket

db_path, p1, pos1, p2, p3, pos3 = sys.argv[1:7]
db = Fail2BanDb(db_path)
class Jail:
    name = 'chain-jail'
    actions = SimpleNamespace(getBanTime=lambda: 600)
jail = Jail()
db.addJail(jail)

for path, pos in [(p1, int(pos1)), (p2, 20), (p3, int(pos3))]:
    fc = FileContainer(path, 'utf-8', tail=False)
    fc.setPos(pos)
    db.addLog(jail, fc)
    db.updateLog(jail, fc)

ticket = BanTicket('4.4.4.4', time.time() - 1.0, ['failed login from 4.4.4.4'])
ticket.setBanTime(600)
db.addBan(jail, ticket)
db.close()
";
    let out = Command::new("python3")
        .args(["-S", "-c", py])
        .arg(&dbfile)
        .arg(&web1_path)
        .arg(pos1.to_string())
        .arg(&web2_path)
        .arg(&web3_path)
        .arg(pos3.to_string())
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run Fail2Ban 1.1.1 DB generator");
    assert!(
        out.status.success(),
        "Fail2Ban 1.1.1 DB generator failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Mutate logs after 1.1.1 shut down:
    // - web1: append 2 failures for 1.2.3.4 after checkpoint
    web1.append(vec![failure("1.2.3.4"), failure("1.2.3.4")]);
    // - web2: rotate to a new file with 3 failures for 2.3.4.5
    std::fs::write(
        &web2_path,
        format!(
            "{}\n{}\n{}\n",
            failure("2.3.4.5"),
            failure("2.3.4.5"),
            failure("2.3.4.5")
        ),
    )
    .expect("rotate web2");
    // - web3: truncate shorter than pos3, keeping same first line, then 3 failures for 3.3.3.4?
    //   Use 3 short lines that total less than pos3? Instead just write 1 line (shorter than pos3),
    //   then after start append 2 more for 3.3.3.3 so all 3 count from offset 0!
    std::fs::write(&web3_path, format!("{}\n", failure("3.3.3.3"))).expect("truncate web3");

    std::fs::write(
        base.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {}\ndbfile = {}\n",
            socket.display(),
            dbfile.display()
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
             \x20   {}\n\
             maxretry = 3\n\
             findtime = 120s\n\
             bantime = 600s\n",
            web1_path.display(),
            web2_path.display(),
            web3_path.display(),
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

    let original_db = std::fs::read(&dbfile).expect("original 1.1.1 DB bytes");

    let daemon1 = spawn_daemon(&base, &record).expect("spawn daemon 1");
    let ctrl_sock = runtime.join("control.sock");
    wait_for("daemon 1 startup", &daemon1, || {
        daemon1.saw("fail2ban-rs started") && ctrl_sock.exists()
    });
    wait_for("1.1.1 ban + rotated log ban", &daemon1, || {
        let rec = decisions(&record);
        rec.contains(&"BAN chain-jail 4.4.4.4".to_owned())
            && rec.contains(&"BAN chain-jail 2.3.4.5".to_owned())
    });

    // 1 more line on web1 bans 1.2.3.4; 2 more lines on truncated web3 bans 3.3.3.3.
    web1.append(vec![failure("1.2.3.4")]);
    Tail(web3_path.clone()).append(vec![failure("3.3.3.3"), failure("3.3.3.3")]);
    wait_for("resumed web1 + truncated web3 bans", &daemon1, || {
        let rec = decisions(&record);
        rec.contains(&"BAN chain-jail 1.2.3.4".to_owned())
            && rec.contains(&"BAN chain-jail 3.3.3.3".to_owned())
    });
    assert!(
        !decisions(&record).iter().any(|l| l.contains("9.9.9.9")),
        "pre-checkpoint 9.9.9.9 from real 1.1.1 DB must not be re-read"
    );

    // Unban 4.4.4.4, reload, shut down, append offline lines, restart!
    assert!(matches!(
        send_control(
            &ctrl_sock,
            &fail2ban_rs::control::Request::Unban {
                ip: "4.4.4.4".parse().expect("ip"),
                jail: "chain-jail".to_owned(),
            },
        ),
        fail2ban_rs::control::Response::Ok { .. }
    ));
    daemon1.signal("HUP");
    wait_for("reload complete", &daemon1, || {
        daemon1.saw("config reload complete")
    });
    assert!(daemon1.terminate().success());

    std::fs::write(&record, b"").expect("clear record");
    web1.append(vec![
        failure("8.8.8.8"),
        failure("8.8.8.8"),
        failure("8.8.8.8"),
    ]);

    let daemon2 = spawn_daemon(&base, &record).expect("spawn daemon 2");
    wait_for("daemon 2 startup", &daemon2, || {
        daemon2.saw("fail2ban-rs started") && ctrl_sock.exists()
    });
    wait_for("offline lines resumed on restart", &daemon2, || {
        decisions(&record).contains(&"BAN chain-jail 8.8.8.8".to_owned())
    });
    std::thread::sleep(Duration::from_millis(600));
    let rec2 = decisions(&record);
    assert!(
        !rec2.iter().any(|l| l.contains("4.4.4.4")),
        "unbanned 4.4.4.4 resurrected: {rec2:?}"
    );
    assert!(
        !rec2.iter().any(|l| l.contains("9.9.9.9")),
        "pre-checkpoint 9.9.9.9 re-read: {rec2:?}"
    );
    assert!(daemon2.terminate().success());
    assert_eq!(std::fs::read(&dbfile).expect("1.1.1 DB bytes"), original_db);
}

/// Format a UTC RFC3164 syslog line at `unix_ts` for SSH parity tests.
fn ssh_syslog_at(unix_ts: i64, pid: u32, msg: &str) -> String {
    let dt = chrono::DateTime::from_timestamp(unix_ts, 0).expect("valid utc ts");
    format!(
        "{} {:2} {:02}:{:02}:{:02} srv sshd[{pid}]: {msg}",
        dt.format("%b"),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    )
}

#[test]
fn compat_chain_legacy_failmanager_rate_and_rotation_e2e() {
    let tmp = tempfile::tempdir().expect("scratch dir");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let socket = tmp.path().join("f2b.sock");
    let record = tmp.path().join("decisions.log");
    let log_path = tmp.path().join("auth.log");
    let log = Tail::create(&log_path).expect("auth.log");

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
             [rate-jail]\n\
             enabled = true\n\
             port = 22\n\
             filter = chain-auth\n\
             logpath = {}\n\
             maxretry = 3\n\
             findtime = 60s\n\
             bantime = 600s\n",
            log_path.display(),
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

    let daemon = spawn_daemon(&base, &record).expect("spawn daemon");
    wait_for("daemon startup", &daemon, || {
        daemon.saw("fail2ban-rs started")
    });

    // Helper for a local syslog line at `now - offset_secs`.
    let line_ago = |offset_secs: i64, ip: &str| {
        let dt = chrono::Local::now() - chrono::Duration::seconds(offset_secs);
        format!(
            "{} {:2} {:02}:{:02}:{:02} srv chain-auth[100]: failed login for user bob from {ip} port 22",
            dt.format("%b"),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        )
    };

    // 1. LegacyFailManager rate-adjusted findtime boundary (maxretry=3, findtime=60):
    //    t = now-70, now-69, now-5 (span = 65s > 60s).
    //    Native CircularTimestamps would NOT ban (65 > 60), whereas Fail2Ban 1.1.1's
    //    FailManager adjusts retry = round_ties_even(2 / 65 * 60) = 2, then +1 = 3 -> BANS!
    log.append(vec![
        line_ago(70, "198.51.100.21"),
        line_ago(69, "198.51.100.21"),
        line_ago(5, "198.51.100.21"),
    ]);
    wait_for("LegacyFailManager rate-adjusted ban", &daemon, || {
        decisions(&record).contains(&"BAN rate-jail 198.51.100.21".to_owned())
    });

    // 2. Live log rotation via rename (new inode + new first line): legacy_poll_reader
    //    must detect rotation via FileIdentityState::reopen and read the new file from 0.
    let rotated = tmp.path().join("auth.log.new");
    std::fs::write(
        &rotated,
        format!(
            "{}\n{}\n{}\n",
            line_ago(2, "198.51.100.22"),
            line_ago(1, "198.51.100.22"),
            line_ago(0, "198.51.100.22"),
        ),
    )
    .expect("write rotated");
    std::fs::rename(&rotated, &log_path).expect("rotate auth.log");
    wait_for("post-rotation ban", &daemon, || {
        decisions(&record).contains(&"BAN rate-jail 198.51.100.22".to_owned())
    });

    assert!(daemon.terminate().success(), "clean exit");
}

#[test]
#[ignore = "requires local pinned Fail2Ban 1.1.1 via FAIL2BAN_111_SOURCE and Python 3"]
fn compat_chain_sshd_file_jail_matches_fail2ban_111_decisions() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");

    let tmp = tempfile::tempdir().expect("scratch dir");
    let base = tmp.path().join("f2b");
    let filter_dir = base.join("filter.d");
    std::fs::create_dir_all(&filter_dir).expect("tree");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let socket = tmp.path().join("f2b.sock");
    let record = tmp.path().join("decisions.log");
    let runtime = tmp.path().join("decisions.log.fail2ban-rs");

    // Copy real stock Fail2Ban 1.1.1 sshd.conf + common.conf verbatim!
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

    let auth1_path = tmp.path().join("auth1.log");
    let auth2_path = tmp.path().join("auth2.log");
    let auth1 = Tail::create(&auth1_path).expect("auth1");
    let auth2 = Tail::create(&auth2_path).expect("auth2");

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
             [sshd]\n\
             enabled = true\n\
             port = 22\n\
             filter = sshd\n\
             ignoreip = 192.0.2.99\n\
             logpath = {}\n\
             \x20   {}\n\
             maxretry = 3\n\
             findtime = 60s\n\
             bantime = 600s\n",
            auth1_path.display(),
            auth2_path.display(),
        ),
    )
    .expect("jail.conf");

    let now = chrono::Utc::now().timestamp();

    // Shared corpus fed identically to upstream Fail2Ban 1.1.1 AND the real Rust daemon:
    let batch1_auth1 = vec![
        // 198.51.100.11: multi-file failures (2 in auth1 + 1 in auth2 -> BANNED)
        ssh_syslog_at(
            now - 20,
            1001,
            "Failed password for root from 198.51.100.11 port 50001 ssh2",
        ),
        ssh_syslog_at(
            now - 19,
            1002,
            "Invalid user admin from 198.51.100.11 port 50002",
        ),
        // 198.51.100.12: LegacyFailManager rate-adjusted findtime boundary (span=65s > 60s -> BANNED)
        ssh_syslog_at(
            now - 70,
            2001,
            "Failed password for root from 198.51.100.12 port 51001 ssh2",
        ),
        ssh_syslog_at(
            now - 69,
            2002,
            "Failed password for root from 198.51.100.12 port 51002 ssh2",
        ),
        ssh_syslog_at(
            now - 5,
            2003,
            "Failed password for root from 198.51.100.12 port 51003 ssh2",
        ),
        // 198.51.100.13: multi-line SSH session correlation (<F-MLFID>) via shared PID 3001
        // (addressless failure lines inherit IP from "Connection from ...") -> BANNED
        ssh_syslog_at(
            now - 15,
            3001,
            "Connection from 198.51.100.13 port 52001 on 192.0.2.1 port 22",
        ),
        ssh_syslog_at(
            now - 14,
            3001,
            "User alice not allowed because account is locked",
        ),
        ssh_syslog_at(
            now - 13,
            3001,
            "Disconnecting: Too many authentication failures",
        ),
        ssh_syslog_at(
            now - 12,
            3001,
            "Disconnecting: Too many authentication failures",
        ),
        // 198.51.100.14: benign Accepted publickey -> NOT BANNED
        ssh_syslog_at(
            now - 12,
            4001,
            "Accepted publickey for alice from 198.51.100.14 port 53001 ssh2",
        ),
        ssh_syslog_at(
            now - 11,
            4002,
            "Accepted publickey for alice from 198.51.100.14 port 53002 ssh2",
        ),
        ssh_syslog_at(
            now - 10,
            4003,
            "Accepted publickey for alice from 198.51.100.14 port 53003 ssh2",
        ),
        // 192.0.2.99: in ignoreip -> NOT BANNED
        ssh_syslog_at(
            now - 9,
            5001,
            "Failed password for root from 192.0.2.99 port 54001 ssh2",
        ),
        ssh_syslog_at(
            now - 8,
            5002,
            "Failed password for root from 192.0.2.99 port 54002 ssh2",
        ),
        ssh_syslog_at(
            now - 7,
            5003,
            "Failed password for root from 192.0.2.99 port 54003 ssh2",
        ),
        // 198.51.100.15: only 2 failures -> NOT BANNED
        ssh_syslog_at(
            now - 6,
            6001,
            "Failed password for root from 198.51.100.15 port 55001 ssh2",
        ),
        ssh_syslog_at(
            now - 5,
            6002,
            "Failed password for root from 198.51.100.15 port 55002 ssh2",
        ),
    ];
    let batch1_auth2 = vec![ssh_syslog_at(
        now - 18,
        1003,
        "Failed password for root from 198.51.100.11 port 50003 ssh2",
    )];

    // 1. Run upstream Fail2Ban 1.1.1 (f6097861) oracle on the exact same sshd.conf + logs
    //    in the same live tail mode (empty files attached with tail=True, then lines appended)!
    let oracle_log1 = tmp.path().join("oracle1.log");
    let oracle_log2 = tmp.path().join("oracle2.log");
    std::fs::write(&oracle_log1, b"").expect("oracle1");
    std::fs::write(&oracle_log2, b"").expect("oracle2");
    let payload1 = format!("{}\n", batch1_auth1.join("\n"));
    let payload2 = format!("{}\n", batch1_auth2.join("\n"));

    let py_oracle = r"
import json, sys, time
from fail2ban.client.filterreader import FilterReader
from fail2ban.server.jail import Jail
from fail2ban.server.mytime import MyTime

basedir, log1, log2, now_ts, p1, p2 = sys.argv[1:7]
MyTime.setTime(float(now_ts))

jail = Jail('sshd', backend='polling')
jail.filter.setUseDns('no')
jail.filter.setMaxRetry(3)
jail.filter.setFindTime(60)
jail.actions.setBanTime(600)
jail.filter.addIgnoreIP('192.0.2.99')

jail.filter.active = True
jail.filter.setLogTimeZone('UTC')
fr = FilterReader('sshd', 'sshd', {'mode': 'normal', 'logtype': 'file'}, basedir=basedir)
assert fr.read(), 'failed to read stock sshd filter'
fr.applyAutoOptions('polling')
fr.getOptions({})
options = fr.getCombined()
jail.filter.prefRegex = options['prefregex']
jail.filter.setDatePattern(options['datepattern'])
jail.filter.setMaxLines(options['maxlines'])
for rule in (options.get('failregex') or '').splitlines():
    if rule:
        jail.filter.addFailRegex(rule)
for rule in (options.get('ignoreregex') or '').splitlines():
    if rule:
        jail.filter.addIgnoreRegex(rule)

jail.filter.addLogPath(log1, tail=True, autoSeek=False)
jail.filter.addLogPath(log2, tail=True, autoSeek=False)
with open(log1, 'a', encoding='utf-8') as f:
    f.write(p1)
with open(log2, 'a', encoding='utf-8') as f:
    f.write(p2)
jail.filter.getFailures(log1)
jail.filter.getFailures(log2)
jail.filter.performBan()

banned = []
while True:
    ticket = jail.getFailTicket()
    if not ticket:
        break
    if jail.actions.banManager.addBanTicket(ticket):
        banned.append(str(ticket.getIP()))
banned.sort()
print(json.dumps(banned))
";
    let oracle_out = Command::new("python3")
        .args(["-S", "-c", py_oracle])
        .arg(&base)
        .arg(&oracle_log1)
        .arg(&oracle_log2)
        .arg(now.to_string())
        .arg(&payload1)
        .arg(&payload2)
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("TZ", "UTC")
        .output()
        .expect("run upstream Fail2Ban 1.1.1 sshd oracle");
    assert!(
        oracle_out.status.success(),
        "upstream sshd oracle failed: {}",
        String::from_utf8_lossy(&oracle_out.stderr)
    );
    let expected_ips: Vec<String> =
        serde_json::from_slice(&oracle_out.stdout).expect("parse oracle JSON");
    assert_eq!(
        expected_ips,
        vec![
            "198.51.100.11".to_owned(),
            "198.51.100.12".to_owned(),
            "198.51.100.13".to_owned(),
        ],
        "upstream Fail2Ban 1.1.1 in live mode bans .11 (multi-log), .12 (live-clamped), and .13 (session), rejecting benign .14, ignored .99, and 2-hit .15"
    );

    // 2. Now run the REAL Rust daemon on the exact same sshd.conf + log corpus!
    let daemon1 = spawn_daemon(&base, &record).expect("spawn sshd daemon");
    let ctrl_sock = runtime.join("control.sock");
    wait_for("sshd daemon startup", &daemon1, || {
        daemon1.saw("fail2ban-rs started") && ctrl_sock.exists()
    });

    auth1.append(batch1_auth1);
    auth2.append(batch1_auth2);

    wait_for("rust sshd bans match upstream 1.1.1", &daemon1, || {
        let rec = decisions(&record);
        expected_ips
            .iter()
            .all(|ip| rec.contains(&format!("BAN sshd {ip}")))
    });
    std::thread::sleep(Duration::from_millis(600));
    let mut rust_ips: Vec<String> = decisions(&record)
        .into_iter()
        .filter_map(|line| line.strip_prefix("BAN sshd ").map(str::to_owned))
        .collect();
    rust_ips.sort();
    assert_eq!(
        rust_ips, expected_ips,
        "Rust daemon SSH file jail decisions MUST match upstream Fail2Ban 1.1.1 1-to-1"
    );

    // 3. Also verify reload + restart continuation on the same SSH jail!
    auth1.append(vec![
        ssh_syslog_at(
            now - 2,
            7001,
            "Failed password for root from 198.51.100.17 port 56001 ssh2",
        ),
        ssh_syslog_at(
            now - 1,
            7002,
            "Failed password for root from 198.51.100.17 port 56002 ssh2",
        ),
    ]);
    daemon1.signal("HUP");
    wait_for("sshd reload complete", &daemon1, || {
        daemon1.saw("config reload complete")
    });
    auth2.append(vec![ssh_syslog_at(
        now,
        7003,
        "Failed password for root from 198.51.100.17 port 56003 ssh2",
    )]);
    wait_for("post-reload sshd ban", &daemon1, || {
        decisions(&record).contains(&"BAN sshd 198.51.100.17".to_owned())
    });

    assert!(daemon1.terminate().success(), "sshd daemon 1 clean exit");
    std::fs::write(&record, b"").expect("clear decisions before restart");

    // Append offline SSH failures while daemon is stopped, then restart.
    let now2 = chrono::Utc::now().timestamp();
    auth1.append(vec![
        ssh_syslog_at(
            now2,
            8001,
            "Failed password for root from 198.51.100.18 port 57001 ssh2",
        ),
        ssh_syslog_at(
            now2,
            8002,
            "Failed password for root from 198.51.100.18 port 57002 ssh2",
        ),
        ssh_syslog_at(
            now2,
            8003,
            "Failed password for root from 198.51.100.18 port 57003 ssh2",
        ),
    ]);
    let daemon2 = spawn_daemon(&base, &record).expect("spawn sshd daemon 2");
    wait_for("sshd daemon 2 startup", &daemon2, || {
        daemon2.saw("fail2ban-rs started") && ctrl_sock.exists()
    });
    wait_for("post-restart offline sshd ban", &daemon2, || {
        decisions(&record).contains(&"BAN sshd 198.51.100.18".to_owned())
    });
    assert!(daemon2.terminate().success(), "sshd daemon 2 clean exit");
}
