#![allow(clippy::panic, clippy::unwrap_used)]
//! Head-to-head parity tests against real Fail2Ban 1.1.1 (`FAIL2BAN_111_SOURCE`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use fail2ban_rs::config::{ActionReader, Configurator, FilterReader};
use fail2ban_rs::filter::Filter;
use fail2ban_rs::protocol::{PickleValue, decode_pickle, encode_pickle_v2};

fn upstream_source() -> Option<PathBuf> {
    std::env::var_os("FAIL2BAN_111_SOURCE").map(PathBuf::from)
}

#[test]
fn pickle_interoperates_with_python3_protocols_2_to_5() {
    let val = PickleValue::Tuple(vec![
        PickleValue::Int(0),
        PickleValue::List(vec![
            PickleValue::Str("status".to_owned()),
            PickleValue::Bool(true),
            PickleValue::None,
            PickleValue::Int(-1),
            PickleValue::Int(1_000_000_000_000),
            PickleValue::Dict(vec![(
                PickleValue::Str("k".to_owned()),
                PickleValue::Str("v".to_owned()),
            )]),
        ]),
    ]);
    let enc = encode_pickle_v2(&val);
    let hex_in: String = enc.iter().map(|b| format!("{b:02x}")).collect();

    let script = r#"
import pickle, sys
raw = bytes.fromhex(sys.argv[1])
obj = pickle.loads(raw)
assert obj == (0, ["status", True, None, -1, 1000000000000, {"k": "v"}]), repr(obj)
for proto in (2, 3, 4, 5):
    print(pickle.dumps(["multi-set", "sshd", "addfailregex", ["a", "b"]], protocol=proto).hex())
"#;
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&hex_in)
        .output()
        .expect("python3 must run");
    assert!(
        out.status.success(),
        "python3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = PickleValue::List(vec![
        PickleValue::Str("multi-set".to_owned()),
        PickleValue::Str("sshd".to_owned()),
        PickleValue::Str("addfailregex".to_owned()),
        PickleValue::str_list(["a", "b"]),
    ]);
    for line in stdout.lines() {
        let bytes: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("hex"))
            .collect();
        let decoded = decode_pickle(&bytes).expect("decode python pickle");
        assert_eq!(decoded, expected);
    }
}

#[test]
fn load_all_103_stock_filters_and_65_stock_actions_from_fail2ban_111() {
    let Some(src) = upstream_source() else {
        eprintln!("FAIL2BAN_111_SOURCE not set; skipping stock catalog test");
        return;
    };
    let config_dir = src.join("config");

    // 1. All stock filter.d/*.conf
    let mut filter_count = 0usize;
    for entry in std::fs::read_dir(config_dir.join("filter.d")).expect("read filter.d") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".conf") else {
            continue;
        };
        if stem == "common" || stem.ends_with("-common") || stem == "botsearch-common" {
            continue;
        }
        let mut reader = FilterReader::new(&config_dir, stem, "testjail", BTreeMap::new());
        assert!(reader.read().expect("read filter"), "failed reading {stem}");
        reader.apply_auto_options("polling");
        reader
            .get_options(&BTreeMap::new(), false)
            .unwrap_or_else(|e| panic!("filter {stem} get_options failed: {e}"));
        let stream = reader.convert();
        let mut filter = Filter::new(stem);
        let _ = filter.set_use_dns_str("no");
        for cmd in &stream {
            let Some(args) = cmd.as_list() else { continue };
            let Some(op) = args.get(2).and_then(PickleValue::as_str) else {
                continue;
            };
            match op {
                "maxlines" => {
                    if let Some(n) = args.get(3).and_then(PickleValue::as_i64) {
                        filter
                            .set_max_lines(n as usize)
                            .unwrap_or_else(|e| panic!("filter {stem} maxlines failed: {e}"));
                    }
                }
                "datepattern" => {
                    if let Some(p) = args.get(3).and_then(PickleValue::as_str) {
                        filter
                            .set_date_pattern(Some(p))
                            .unwrap_or_else(|e| panic!("filter {stem} datepattern failed: {e}"));
                    }
                }
                "prefregex" => {
                    if let Some(p) = args.get(3).and_then(PickleValue::as_str) {
                        filter
                            .set_prefregex(Some(p))
                            .unwrap_or_else(|e| panic!("filter {stem} prefregex failed: {e}"));
                    }
                }
                "addfailregex" => {
                    let patterns: Vec<&str> = match args.get(3) {
                        Some(PickleValue::List(items)) => {
                            items.iter().filter_map(PickleValue::as_str).collect()
                        }
                        Some(PickleValue::Str(s)) => vec![s.as_str()],
                        _ => Vec::new(),
                    };
                    for pat in patterns {
                        filter.add_fail_regex(pat).unwrap_or_else(|e| {
                            panic!("filter {stem} failregex {pat:?} failed: {e}")
                        });
                    }
                }
                "addignoreregex" => {
                    let patterns: Vec<&str> = match args.get(3) {
                        Some(PickleValue::List(items)) => {
                            items.iter().filter_map(PickleValue::as_str).collect()
                        }
                        Some(PickleValue::Str(s)) => vec![s.as_str()],
                        _ => Vec::new(),
                    };
                    for pat in patterns {
                        filter.add_ignore_regex(pat).unwrap_or_else(|e| {
                            panic!("filter {stem} ignoreregex {pat:?} failed: {e}")
                        });
                    }
                }
                _ => {}
            }
        }
        filter_count += 1;
    }
    assert!(
        filter_count >= 90,
        "expected >=90 runnable stock filters, got {filter_count}"
    );

    // 2. All stock action.d/*.conf
    let mut action_count = 0usize;
    for entry in std::fs::read_dir(config_dir.join("action.d")).expect("read action.d") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".conf") else {
            continue;
        };
        if stem.ends_with("-common") {
            continue;
        }
        let mut init = BTreeMap::new();
        init.insert("port".to_owned(), "ssh".to_owned());
        init.insert("protocol".to_owned(), "tcp".to_owned());
        init.insert("chain".to_owned(), "INPUT".to_owned());
        let mut reader = ActionReader::new(&config_dir, stem, "testjail", init);
        assert!(reader.read().expect("read action"), "failed reading {stem}");
        reader
            .get_options(&BTreeMap::new())
            .unwrap_or_else(|e| panic!("action {stem} get_options failed: {e}"));
        let _ = reader.convert();
        action_count += 1;
    }
    assert!(
        action_count >= 50,
        "expected >=50 runnable stock actions, got {action_count}"
    );

    // 3. Stock fail2ban.conf + jail.conf via Configurator
    let mut cfg = Configurator::new(&config_dir, false);
    cfg.read_all()
        .expect("read stock fail2ban.conf + jail.conf");
    let early = cfg.get_early_options().expect("early options");
    assert_eq!(early.socket, "/var/run/fail2ban/fail2ban.sock");
    assert!(cfg.get_options(None, None, true).expect("get_options"));
    cfg.convert_to_protocol(true).expect("convert_to_protocol");
    let stream = cfg.get_config_stream();
    assert!(
        !stream.is_empty(),
        "general config stream must not be empty"
    );
}

#[test]
fn upstream_and_rust_servers_can_take_over_each_others_sqlite_state() {
    use std::fs;
    use std::path::Path;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    let Some(upstream) = upstream_source() else {
        eprintln!("FAIL2BAN_111_SOURCE not set; skipping daemon and SQLite parity test");
        return;
    };

    struct RunningServer(Child);

    impl Drop for RunningServer {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    fn upstream_command(source: &Path, binary: &str) -> Command {
        let mut command = Command::new("python3");
        command.arg(source.join("bin").join(binary));
        command.env("PYTHONPATH", source);
        command
    }

    fn invoke(mut client: Command, config: &Path, args: &[&str]) -> String {
        let output = client.arg("-c").arg(config).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn launch(mut server: Command, config: &Path) -> RunningServer {
        let mut running = RunningServer(
            server
                .arg("-c")
                .arg(config)
                .args(["-xf", "start"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            assert!(
                running.0.try_wait().unwrap().is_none(),
                "server exited during startup"
            );
            let status = Command::new(env!("CARGO_BIN_EXE_fail2ban-client"))
                .arg("-c")
                .arg(config)
                .args(["--timeout", "0.1", "status", "fixture"])
                .output()
                .unwrap();
            if status.status.success() {
                return running;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("server did not activate the fixture jail");
    }

    fn stop(client: Command, config: &Path, mut server: RunningServer) {
        invoke(client, config, &["stop"]);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(exit) = server.0.try_wait().unwrap() {
                assert!(exit.success(), "server exited with {exit}");
                assert!(!config.join("sock").exists());
                assert!(!config.join("pid").exists());
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("server did not shut down");
    }

    let root = tempfile::TempDir::new().unwrap();
    let conf = root.path();
    fs::create_dir(conf.join("filter.d")).unwrap();
    fs::create_dir(conf.join("action.d")).unwrap();
    fs::write(conf.join("auth.log"), "").unwrap();
    fs::write(
        conf.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {0}/sock\npidfile = {0}/pid\n\
             loglevel = ERROR\nlogtarget = STDERR\ndbfile = {0}/state.sqlite3\n",
            conf.display()
        ),
    )
    .unwrap();
    fs::write(
        conf.join("jail.conf"),
        format!(
            "[fixture]\nenabled = true\nbackend = polling\n\
             logpath = {}/auth.log\nfilter = fixture\naction = fixture\n\
             datepattern = {{NONE}}\nmaxretry = 2\nbantime = 10m\n",
            conf.display()
        ),
    )
    .unwrap();
    fs::write(
        conf.join("filter.d/fixture.conf"),
        "[Definition]\nfailregex = ^Failed from <HOST>$\n",
    )
    .unwrap();
    fs::write(
        conf.join("action.d/fixture.conf"),
        format!(
            "[Definition]\nactionban = echo '<ip>' >> '{}/bans.log'\n",
            conf.display()
        ),
    )
    .unwrap();

    let python_server = || upstream_command(&upstream, "fail2ban-server");
    let python_client = || upstream_command(&upstream, "fail2ban-client");
    let rust_client = || Command::new(env!("CARGO_BIN_EXE_fail2ban-client"));
    let original = launch(python_server(), conf);
    assert_eq!(
        invoke(
            rust_client(),
            conf,
            &["set", "fixture", "banip", "192.0.2.17"]
        ),
        "1"
    );
    // Append 1 failure for 192.0.2.99 (below maxretry=2) so Python saves a nonzero log offset
    fs::write(conf.join("auth.log"), "Failed from 192.0.2.99\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !invoke(rust_client(), conf, &["status", "fixture"]).contains("Total failed:\t1") {
        assert!(Instant::now() < deadline, "Python did not consume auth.log");
        std::thread::sleep(Duration::from_millis(50));
    }
    stop(rust_client(), conf, original);

    let replacement = launch(Command::new(env!("CARGO_BIN_EXE_fail2ban-server")), conf);
    assert!(invoke(python_client(), conf, &["get", "fixture", "banip"]).contains("192.0.2.17"));
    // Rust resumed from Python's nonzero SQLite offset, so the old line was not re-counted
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        invoke(python_client(), conf, &["status", "fixture"]).contains("Total failed:\t0"),
        "Rust must resume from Python's nonzero log offset without re-reading line 1"
    );
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(conf.join("auth.log"))
            .unwrap();
        writeln!(f, "Failed from 192.0.2.99").unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !invoke(python_client(), conf, &["status", "fixture"]).contains("Total failed:\t1") {
        assert!(
            Instant::now() < deadline,
            "Rust did not consume appended auth.log line"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !invoke(python_client(), conf, &["get", "fixture", "banip"]).contains("192.0.2.99"),
        "192.0.2.99 must have only 1 failure under Rust (not 2)"
    );
    assert_eq!(
        invoke(
            python_client(),
            conf,
            &["set", "fixture", "banip", "192.0.2.18"]
        ),
        "1"
    );
    invoke(python_client(), conf, &["reload"]);
    let banned = invoke(python_client(), conf, &["get", "fixture", "banip"]);
    assert!(banned.contains("192.0.2.17") && banned.contains("192.0.2.18"));
    stop(python_client(), conf, replacement);

    let original = launch(python_server(), conf);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let banned = invoke(rust_client(), conf, &["get", "fixture", "banip"]);
        if banned.contains("192.0.2.17") && banned.contains("192.0.2.18") {
            break;
        }
        assert!(Instant::now() < deadline, "original restored {banned:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !invoke(rust_client(), conf, &["get", "fixture", "banip"]).contains("192.0.2.99"),
        "Python rollback must resume from Rust's advanced nonzero log offset without re-reading the first 2 lines"
    );
    assert_eq!(invoke(rust_client(), conf, &["unban", "--all"]), "2");
    stop(rust_client(), conf, original);
}

#[tokio::test]
async fn smtp_starttls_upgrades_with_self_signed_cert_and_delivers_authenticated_mail() {
    use std::io::BufRead;
    use std::process::Stdio;

    let dir = tempfile::TempDir::new().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let cert_gen = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-days", "1", "-subj", "/CN=localhost"])
        .output()
        .expect("openssl must be installed");
    assert!(
        cert_gen.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&cert_gen.stderr)
    );

    let script = r#"
import socket, ssl, sys, json

cert, key = sys.argv[1], sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
print(srv.getsockname()[1], flush=True)

conn, _ = srv.accept()
def readline(s):
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            break
        buf.extend(chunk)
    return buf.decode("utf-8", "replace")

conn.sendall(b"220 starttls.local ESMTP\r\n")
plain_cmds = []
tls_cmds = []
body_lines = []

line = readline(conn).strip()
plain_cmds.append(line)
assert line.startswith("EHLO "), line
conn.sendall(b"250-starttls.local\r\n250 STARTTLS\r\n")

line = readline(conn).strip()
plain_cmds.append(line)
assert line == "STARTTLS", line
conn.sendall(b"220 Ready to start TLS\r\n")

tls = ctx.wrap_socket(conn, server_side=True)
in_data = False
while True:
    raw = readline(tls)
    if not raw:
        break
    if in_data:
        if raw == ".\r\n":
            in_data = False
            tls.sendall(b"250 2.0.0 Queued\r\n")
        else:
            body_lines.append(raw)
        continue
    cmd = raw.strip()
    tls_cmds.append(cmd)
    if cmd.startswith("EHLO "):
        tls.sendall(b"250-starttls.local\r\n250 AUTH PLAIN\r\n")
    elif cmd.startswith("AUTH PLAIN "):
        tls.sendall(b"235 2.7.0 OK\r\n")
    elif cmd.startswith("MAIL FROM:") or cmd.startswith("RCPT TO:"):
        tls.sendall(b"250 2.1.0 OK\r\n")
    elif cmd == "DATA":
        in_data = True
        tls.sendall(b"354 Go ahead\r\n")
    elif cmd == "QUIT":
        tls.sendall(b"221 Bye\r\n")
        break

tls.close()
srv.close()
print(json.dumps({
    "tls_version": tls.version(),
    "plain_cmds": plain_cmds,
    "tls_cmds": tls_cmds,
    "body": "".join(body_lines),
}), flush=True)
"#;

    let mut child = Command::new("python3")
        .args(["-u", "-c", script])
        .arg(&cert)
        .arg(&key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python3 TLS SMTP mock");
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut port_line = String::new();
    stdout.read_line(&mut port_line).unwrap();
    let port: u16 = port_line.trim().parse().expect("valid port");

    let init = serde_json::json!({
        "host": format!("127.0.0.1:{port}"),
        "ssl": true,
        "user": "alice",
        "password": "secret",
        "sender": "f2b@example.com",
        "dest": "ops@example.com",
    })
    .to_string();
    let mut act =
        fail2ban_rs::action::SmtpAction::from_json("sshd".to_owned(), "smtp".to_owned(), &init)
            .unwrap();
    act.start().await.expect("STARTTLS delivery must succeed");

    let mut json_line = String::new();
    stdout.read_line(&mut json_line).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "mock TLS SMTP server failed: {status}");

    let report: serde_json::Value = serde_json::from_str(&json_line).unwrap();
    let plain_cmds: Vec<&str> = report["plain_cmds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(plain_cmds.len(), 2);
    assert!(plain_cmds[0].starts_with("EHLO "));
    assert_eq!(plain_cmds[1], "STARTTLS");

    let tls_cmds: Vec<&str> = report["tls_cmds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(tls_cmds[0].starts_with("EHLO "));
    assert_eq!(tls_cmds[1], "AUTH PLAIN AGFsaWNlAHNlY3JldA==");
    assert_eq!(tls_cmds[2], "MAIL FROM:<f2b@example.com>");
    assert_eq!(tls_cmds[3], "RCPT TO:<ops@example.com>");
    assert_eq!(tls_cmds[4], "DATA");
    assert_eq!(tls_cmds[5], "QUIT");

    let body = report["body"].as_str().unwrap();
    assert!(body.contains("Subject: [Fail2Ban] sshd: started on "));
    assert!(body.contains("The jail sshd has been started successfully."));
}

#[tokio::test]
async fn reload_safety_action_handoff_sqlite_restore_live_eof_idle_reconfig_journal_supervision_and_cp932()
 {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;

    use fail2ban_rs::db::Fail2BanDb;
    use fail2ban_rs::filter::LogEncoding;
    use fail2ban_rs::filter::backend::systemd::FilterSystemd;
    use fail2ban_rs::filter::backend::{JournalConfig, LogEvent};
    use fail2ban_rs::protocol::PickleValue;
    use fail2ban_rs::server::Transmitter;
    use fail2ban_rs::server::jail::{Jail, current_unix_seconds};
    use fail2ban_rs::ticket::TicketId;
    use tokio::sync::{mpsc, watch};

    let dir = tempfile::TempDir::new().unwrap();

    // 1. Backend option validation: reject invalid options on polling/pyinotify/systemd
    assert!(Jail::new("bad1", "polling[foo=1]", None).is_err());
    assert!(Jail::new("bad2", "pyinotify[bar=2]", None).is_err());
    assert!(Jail::new("bad3", "systemd[tail=true]", None).is_err());
    assert!(Jail::new("bad4", "systemd[unknown=1]", None).is_err());
    assert!(Jail::new("ok_sys", "systemd[useDns=no, rotated=1]", None).is_ok());

    // 2. CP932 logencoding decoding in shared decoder
    let cp932 = LogEncoding::parse("cp932").unwrap();
    let cp932_bytes = [
        0x32, 0x30, 0x32, 0x36, 0x2d, 0x31, 0x31, 0x2d, 0x32, 0x32, 0x20, 0x31, 0x30, 0x3a, 0x30,
        0x30, 0x3a, 0x30, 0x30, 0x20, 0x94, 0x46, 0x8f, 0xd8, 0x8e, 0xb8, 0x94, 0x73, 0x20, 0x66,
        0x72, 0x6f, 0x6d, 0x20, 0x31, 0x39, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x35, 0x35,
    ];
    let decoded_cp932 = cp932.decode(&cp932_bytes);
    assert_eq!(
        decoded_cp932,
        "2026-11-22 10:00:00 認証失敗 from 192.0.2.55"
    );

    // 3. SQLite restore of migrated bantime=-2 rows and non-incrementing cap
    let db_path = dir.path().join("restore.sqlite3");
    let now_i = current_unix_seconds().floor() as i64;
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE fail2banDb(version INTEGER);
             INSERT INTO fail2banDb(version) VALUES(1);
             CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);
             INSERT INTO jails(name, enabled) VALUES('noninc', 1);
             INSERT INTO jails(name, enabled) VALUES('inc_nocap', 1);
             CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0);
             CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, data JSON);
             INSERT INTO bans(jail, ip, timeofban, data) VALUES('noninc', '192.0.2.10', {0}, '{{}}');
             INSERT INTO bans(jail, ip, timeofban, data) VALUES('inc_nocap', '192.0.2.11', {0}, '{{}}');",
            now_i - 10
        ))
        .unwrap();
    }
    let db = Arc::new(std::sync::Mutex::new(
        Fail2BanDb::open(db_path.to_str().unwrap(), 86_400, 10).unwrap(),
    ));
    {
        // Also insert a permanent (-1) ban in `noninc` to verify non-incrementing restore caps it to 1800
        let guard = db.lock().unwrap();
        let mut perm =
            fail2ban_rs::ticket::Ticket::new(TicketId::parse("192.0.2.12"), (now_i - 5) as f64);
        perm.ban_count = 1;
        perm.ban_time = Some(-1);
        guard.add_ban("noninc", &perm, -1).unwrap();
    }

    let j_noninc = Jail::new("noninc", "polling", Some(Arc::clone(&db))).unwrap();
    {
        let mut st = j_noninc.state.lock().await;
        st.filter.set_ignore_self(false);
        st.ban_manager.set_ban_time(1800);
    }
    j_noninc.start().await.unwrap();
    {
        let st = j_noninc.state.lock().await;
        let t_mig = st
            .ban_manager
            .get_ticket_by_id(&TicketId::parse("192.0.2.10"))
            .unwrap();
        assert_eq!(t_mig.ban_time, Some(1800));
        let t_capped = st
            .ban_manager
            .get_ticket_by_id(&TicketId::parse("192.0.2.12"))
            .unwrap();
        assert_eq!(t_capped.ban_time, Some(1800));
    }
    j_noninc.stop().await.unwrap();

    let j_inc = Jail::new("inc_nocap", "polling", Some(Arc::clone(&db))).unwrap();
    {
        let mut st = j_inc.state.lock().await;
        st.filter.set_ignore_self(false);
        st.ban_manager.set_ban_time(900);
        st.ban_extra.set_opt("increment", Some("true")).unwrap();
    }
    j_inc.start().await.unwrap();
    {
        let st = j_inc.state.lock().await;
        let t_mig = st
            .ban_manager
            .get_ticket_by_id(&TicketId::parse("192.0.2.11"))
            .unwrap();
        assert_eq!(
            t_mig.ban_time,
            Some(900),
            "migrated -2 row in incrementing jail without maxtime must get base bantime, not -1"
        );
    }
    j_inc.stop().await.unwrap();

    // 4. Failed reload preserves healthy jails; action replacement replays active bans before retiring old action;
    //    failed unban retains ticket and propagates error until fixed.
    let mut tr = Transmitter::default();
    let act_order_log = dir.path().join("action_order.log");
    let unban_flag = dir.path().join("allow_unban");
    let s = |v: &str| PickleValue::Str(v.to_owned());

    tr.dispatch(&PickleValue::List(vec![
        s("add"),
        s("healthy"),
        s("polling"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("healthy"),
        s("ignoreself"),
        s("false"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("healthy"),
        s("addfailregex"),
        s("^fail <HOST>$"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("healthy"),
        s("addaction"),
        s("fw1"),
    ]))
    .await
    .unwrap();
    for (k, v) in [
        (
            "actionstart",
            format!("echo fw1:start >> '{}'", act_order_log.display()),
        ),
        (
            "actionban",
            format!("echo fw1:ban:<ip> >> '{}'", act_order_log.display()),
        ),
        (
            "actionunban",
            format!(
                "test -f '{}' && echo fw1:unban:<ip> >> '{}'",
                unban_flag.display(),
                act_order_log.display()
            ),
        ),
        (
            "actionstop",
            format!("echo fw1:stop >> '{}'", act_order_log.display()),
        ),
    ] {
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("action"),
            s("fw1"),
            s(k),
            s(&v),
        ]))
        .await
        .unwrap();
    }
    tr.dispatch(&PickleValue::List(vec![s("start"), s("healthy")]))
        .await
        .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("healthy"),
        s("banip"),
        s("192.0.2.88"),
    ]))
    .await
    .unwrap();

    // 4a. Explicit unban when actionunban fails matches upstream Actions.removeBannedIP:
    //     logs the hook failure, removes 192.0.2.88, and returns count 1.
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("unbanip"),
            s("192.0.2.88")
        ]))
        .await
        .unwrap(),
        PickleValue::Int(1)
    );
    let after_unban = tr
        .dispatch(&PickleValue::List(vec![s("get"), s("healthy"), s("banip")]))
        .await
        .unwrap();
    assert_eq!(
        after_unban,
        PickleValue::List(vec![]),
        "explicit unban must remove ticket even when actionunban fails (matching upstream)"
    );

    // Allow unban to succeed and re-ban 192.0.2.88 for subsequent reload tests
    fs::write(&unban_flag, "ok").unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("healthy"),
        s("banip"),
        s("192.0.2.88"),
    ]))
    .await
    .unwrap();

    // 4b. Reload with malformed regex in another jail fails without tearing down `healthy`
    let bad_reload_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("healthy"), s("polling")]),
        PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("addfailregex"),
            s("^fail <HOST>$"),
        ]),
        PickleValue::List(vec![s("add"), s("broken"), s("polling")]),
        PickleValue::List(vec![
            s("set"),
            s("broken"),
            s("addfailregex"),
            s("[unclosed("),
        ]),
        PickleValue::List(vec![s("start"), s("healthy")]),
        PickleValue::List(vec![s("start"), s("broken")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            bad_reload_stream
        ]))
        .await
        .is_err()
    );
    let banned_after_failed_reload = tr
        .dispatch(&PickleValue::List(vec![s("get"), s("healthy"), s("banip")]))
        .await
        .unwrap();
    assert_eq!(
        banned_after_failed_reload,
        PickleValue::List(vec![s("192.0.2.88")]),
        "healthy jail and its active ban must survive failed reload"
    );

    // 4c. Replacing `fw1` with `fw2` on plain reload matches upstream Actions.add/reload
    //     (retires `fw1` without starting/replaying `fw2`, removing both absent from `_reload_actions`),
    //     while `reload --restart` starts `fw2` cleanly after `fw1` stopped.
    let replace_action_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("healthy"), s("polling")]),
        PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("addfailregex"),
            s("^fail <HOST>$"),
        ]),
        PickleValue::List(vec![s("set"), s("healthy"), s("addaction"), s("fw2")]),
        PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("action"),
            s("fw2"),
            s("actionstart"),
            s(&format!("echo fw2:start >> '{}'", act_order_log.display())),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("action"),
            s("fw2"),
            s("actionban"),
            s(&format!(
                "echo fw2:ban:<ip> >> '{}'",
                act_order_log.display()
            )),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("action"),
            s("fw2"),
            s("actionunban"),
            s(&format!(
                "echo fw2:unban:<ip> >> '{}'",
                act_order_log.display()
            )),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("action"),
            s("fw2"),
            s("actionstop"),
            s(&format!("echo fw2:stop >> '{}'", act_order_log.display())),
        ]),
        PickleValue::List(vec![s("start"), s("healthy")]),
    ]);
    tr.dispatch(&PickleValue::List(vec![
        s("reload"),
        s("--all"),
        PickleValue::List(vec![]),
        replace_action_stream.clone(),
    ]))
    .await
    .unwrap();

    let order_lines: Vec<String> = fs::read_to_string(&act_order_log)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let fw1_unban_pos = order_lines
        .iter()
        .position(|l| l == "fw1:unban:192.0.2.88")
        .unwrap();
    let fw1_stop_pos = order_lines.iter().position(|l| l == "fw1:stop").unwrap();
    assert!(
        fw1_unban_pos < fw1_stop_pos && !order_lines.iter().any(|l| l.starts_with("fw2:")),
        "plain reload rename must unban/stop fw1 without starting or replaying fw2: {order_lines:?}"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![
            s("get"),
            s("healthy"),
            s("actions")
        ]))
        .await
        .unwrap(),
        PickleValue::List(vec![])
    );

    tr.dispatch(&PickleValue::List(vec![
        s("reload"),
        s("--all"),
        PickleValue::List(vec![s("--restart")]),
        replace_action_stream,
    ]))
    .await
    .unwrap();
    let order_lines_after: Vec<String> = fs::read_to_string(&act_order_log)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let fw2_start_pos = order_lines_after
        .iter()
        .position(|l| l == "fw2:start")
        .unwrap();
    assert!(
        fw1_stop_pos < fw2_start_pos,
        "reload --restart must start fw2 after fw1 stopped: {order_lines_after:?}"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![
            s("get"),
            s("healthy"),
            s("actions")
        ]))
        .await
        .unwrap(),
        PickleValue::List(vec![s("fw2")])
    );
    let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 5. Delayed live file record admission after initial EOF (inOperation) + busy idle queue reconfiguration
    let live_log = dir.path().join("live.log");
    let stale_ts = (current_unix_seconds() as i64) - 7200; // 2 hours old (> findtime=600)
    fs::write(&live_log, format!("{stale_ts} fail 192.0.2.200\n")).unwrap();

    let live_jail = Jail::new("live", "polling", None).unwrap();
    {
        let mut st = live_jail.state.lock().await;
        st.filter.set_ignore_self(false);
        st.filter.set_date_pattern(Some("^EPOCH")).unwrap();
        st.filter.add_fail_regex("^\\s*fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
        st.add_log_path(live_log.clone(), false).unwrap();
    }
    live_jail.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    {
        let st = live_jail.state.lock().await;
        assert!(
            !st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.200")),
            "stale line present before initial EOF must be ignored"
        );
    }

    // Append the exact same stale timestamp AFTER initial EOF -> admitted in operation mode!
    {
        let mut f = OpenOptions::new().append(true).open(&live_log).unwrap();
        writeln!(f, "{stale_ts} fail 192.0.2.200").unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut banned_live = false;
    while tokio::time::Instant::now() < deadline {
        if live_jail
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.200"))
        {
            banned_live = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        banned_live,
        "delayed live record appended after initial EOF must be admitted"
    );

    // 6. Busy idle jail reconfiguration does not hang and preserves last consumed checkpoint
    live_jail.set_idle(true).await;
    {
        let mut f = OpenOptions::new().append(true).open(&live_log).unwrap();
        for i in 0..1500 {
            writeln!(f, "{stale_ts} benign line {i}").unwrap();
        }
        writeln!(f, "{stale_ts} fail 192.0.2.201").unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;
    {
        let mut st = live_jail.state.lock().await;
        st.filter.set_log_encoding_str("cp932").unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), live_jail.restart_backend_if_alive())
        .await
        .expect("restart_backend_if_alive must not hang when idle queue is full");
    live_jail.set_idle(false).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut banned_after_resume = false;
    while tokio::time::Instant::now() < deadline {
        if live_jail
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.201"))
        {
            banned_after_resume = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        banned_after_resume,
        "resumed jail must replay from last consumed checkpoint and ban 192.0.2.201"
    );
    live_jail.stop().await.unwrap();

    // 7. Systemd journal reader exit supervision & resume from last processed position
    let mock_jctl = dir.path().join("mock-journalctl.sh");
    let state_marker = dir.path().join("jctl_runs");
    fs::write(
        &mock_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             count=0\n\
             if [[ -f '{0}' ]]; then count=$(cat '{0}'); fi\n\
             count=$((count + 1))\n\
             echo \"$count: $*\" >> '{0}.args'\n\
             echo \"$count\" > '{0}'\n\
             if [[ $count -eq 1 ]]; then\n\
                 echo '{{\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"first entry\",\"__REALTIME_TIMESTAMP\":\"1715675415000000\"}}'\n\
                 exit 1\n\
             else\n\
                 echo '{{\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"second entry\",\"__REALTIME_TIMESTAMP\":\"1715675416000000\"}}'\n\
                 sleep 30\n\
             fi\n",
            state_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&mock_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let (j_tx, mut j_rx) = mpsc::channel(16);
    let (j_shut_tx, j_shut_rx) = watch::channel(false);
    let reader = FilterSystemd::new(JournalConfig::default(), LogEncoding::Utf8, false)
        .with_journalctl_bin(mock_jctl.to_str().unwrap());
    let j_handle = tokio::spawn(async move { reader.run(j_tx, j_shut_rx).await });

    let ev1 = tokio::time::timeout(Duration::from_secs(3), j_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let ev2 = tokio::time::timeout(Duration::from_secs(3), j_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let _ = j_shut_tx.send(true);
    j_handle.await.unwrap().unwrap();

    match (&ev1, &ev2) {
        (LogEvent::Line { line: l1, .. }, LogEvent::Line { line: l2, .. }) => {
            assert!(l1.contains("first entry"), "{l1}");
            assert!(l2.contains("second entry"), "{l2}");
        }
        other => panic!("unexpected journal events: {other:?}"),
    }
    let recorded_args = fs::read_to_string(format!("{}.args", state_marker.display())).unwrap();
    assert!(
        recorded_args.contains("--since=2024-05-14 08:30:15.000001 UTC"),
        "restarted journalctl must resume from last seen timestamp + 1us:\n{recorded_args}"
    );
}

#[tokio::test]
async fn round2_action_handoff_journal_cursor_tick_priority_tail_reconfig_unban_and_cli_test() {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;

    use fail2ban_rs::db::Fail2BanDb;
    use fail2ban_rs::filter::LogEncoding;
    use fail2ban_rs::filter::backend::systemd::FilterSystemd;
    use fail2ban_rs::filter::backend::{JournalConfig, LogEvent};
    use fail2ban_rs::protocol::PickleValue;
    use fail2ban_rs::server::Transmitter;
    use fail2ban_rs::server::jail::{Jail, current_unix_seconds};
    use fail2ban_rs::ticket::TicketId;
    use tokio::sync::{mpsc, watch};

    let dir = tempfile::TempDir::new().unwrap();
    let s = |v: &str| PickleValue::Str(v.to_owned());

    // 1. Failed action handoff & shared firewall state preserve live enforcement;
    //    failed backend switch preserves running jail;
    //    partial unban retry skips succeeded actions; bulk unban failure retains DB + tickets.
    let db_path = dir.path().join("r2.sqlite3");
    let order_log = dir.path().join("r2_actions.log");
    let mut tr = Transmitter::default();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("dbfile"),
        s(db_path.to_str().unwrap()),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![s("add"), s("svc"), s("polling")]))
        .await
        .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("ignoreself"),
        s("false"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("addaction"),
        s("fw1"),
    ]))
    .await
    .unwrap();
    for (k, v) in [
        (
            "actionstart",
            format!("echo fw1:start >> '{}'", order_log.display()),
        ),
        (
            "actionban",
            format!("echo fw1:ban:<ip> >> '{}'", order_log.display()),
        ),
        (
            "actionunban",
            format!("echo fw1:unban:<ip> >> '{}'", order_log.display()),
        ),
        (
            "actionstop",
            format!("echo fw1:stop >> '{}'", order_log.display()),
        ),
    ] {
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw1"),
            s(k),
            s(&v),
        ]))
        .await
        .unwrap();
    }
    tr.dispatch(&PickleValue::List(vec![s("start"), s("svc")]))
        .await
        .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("banip"),
        s("192.0.2.50"),
    ]))
    .await
    .unwrap();

    // 1a. Failing in-place actionreload on fw1 must NOT retire fw1 and must return Err.
    let fail_reload_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![s("set"), s("svc"), s("addaction"), s("fw1")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw1"),
            s("actionreload"),
            s("false"),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            fail_reload_stream
        ]))
        .await
        .is_err(),
        "failed in-place actionreload must fail reload"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("fw1")]),
        "fw1 must remain active after failed in-place reload"
    );
    let log_after_fail = fs::read_to_string(&order_log).unwrap();
    assert!(
        !log_after_fail.contains("fw1:unban") && !log_after_fail.contains("fw1:stop"),
        "fw1 must not be unbanned or stopped when in-place reload fails:\n{log_after_fail}"
    );

    // 1b. Failed backend switch (polling -> systemd with failing Python action import) leaves old jail live.
    let bad_switch_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("systemd")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("addaction"),
            s("broken_py"),
            s("/nonexistent/fail2ban_broken_action.py"),
            s("{}"),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            bad_switch_stream
        ]))
        .await
        .is_err(),
        "backend switch with failing action import must fail reload"
    );
    let stats_after_switch = tr
        .dispatch(&PickleValue::List(vec![s("stats")]))
        .await
        .unwrap();
    let stats_str = format!("{stats_after_switch:?}");
    assert!(
        stats_str.contains("polling"),
        "old polling jail must remain running after failed switch: {stats_str}"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.50")]),
        "active ban must remain enforced after failed backend switch"
    );
    let log_after_switch = fs::read_to_string(&order_log).unwrap();
    assert!(
        !log_after_switch.contains("fw1:stop"),
        "old jail must not be stopped before staged replacement is validated:\n{log_after_switch}"
    );

    // 1c. Plain reload renaming fw1 -> fw_alias matches upstream Actions.add/reload:
    //     fw_alias is never started or replayed, fw1 is unbanned/stopped, and both absent from
    //     _reload_actions are removed while the ticket stays; `--restart` provides stop-and-restore.
    let alias_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![s("set"), s("svc"), s("ignoreself"), s("false")]),
        PickleValue::List(vec![s("set"), s("svc"), s("addaction"), s("fw_alias")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_alias"),
            s("actionstart"),
            s(&format!("echo fw_alias:start >> '{}'", order_log.display())),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_alias"),
            s("actionban"),
            s(&format!(
                "echo fw_alias:ban:<ip> >> '{}'",
                order_log.display()
            )),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_alias"),
            s("actionunban"),
            s(&format!(
                "echo fw_alias:unban:<ip> >> '{}'",
                order_log.display()
            )),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_alias"),
            s("actionstop"),
            s(&format!("echo fw_alias:stop >> '{}'", order_log.display())),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    tr.dispatch(&PickleValue::List(vec![
        s("reload"),
        s("--all"),
        PickleValue::List(vec![]),
        alias_stream.clone(),
    ]))
    .await
    .unwrap();
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![]),
        "plain reload rename must match upstream by removing actions absent from _reload_actions"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.50")])
    );
    let log_after_plain_rename = fs::read_to_string(&order_log).unwrap();
    assert!(
        log_after_plain_rename.contains("fw1:unban:192.0.2.50")
            && log_after_plain_rename.contains("fw1:stop")
            && !log_after_plain_rename.contains("fw_alias:start")
            && !log_after_plain_rename.contains("fw_alias:ban"),
        "plain reload must retire fw1 without starting/replaying fw_alias:\n{log_after_plain_rename}"
    );

    // Reload --restart supplies stop-and-restore semantics with fw_alias active and restored.
    tr.dispatch(&PickleValue::List(vec![
        s("reload"),
        s("--all"),
        PickleValue::List(vec![s("--restart")]),
        alias_stream,
    ]))
    .await
    .unwrap();
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("fw_alias")])
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.50")])
    );
    let log_after_restart_rename = fs::read_to_string(&order_log).unwrap();
    assert!(
        log_after_restart_rename.contains("fw_alias:start")
            && log_after_restart_rename.contains("fw_alias:ban:192.0.2.50"),
        "reload --restart must start fw_alias and restore active ban:\n{log_after_restart_rename}"
    );
    let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 2. Multi-IP per-IP unban and bulk unban match upstream 1.1.1 error/counting/DB semantics.
    let unban_db_path = dir.path().join("unban.sqlite3");
    let unban_log = dir.path().join("unban_hooks.log");
    let flaky_ok = dir.path().join("fw_flaky_ok");
    let mut tr2 = Transmitter::default();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("dbfile"),
        s(unban_db_path.to_str().unwrap()),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![s("add"), s("multi"), s("polling")]))
        .await
        .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("ignoreself"),
        s("false"),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("addaction"),
        s("fw_flaky"),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_flaky"),
        s("actionban"),
        s("true"),
    ]))
    .await
    .unwrap();
    // Fails for 192.0.2.80 (unless flaky_ok exists), succeeds for other IPs; logs every invocation.
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_flaky"),
        s("actionunban"),
        s(&format!(
            "echo flaky:<ip> >> '{0}' && {{ test -f '{1}' || test '<ip>' != '192.0.2.80'; }}",
            unban_log.display(),
            flaky_ok.display()
        )),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("addaction"),
        s("fw_ok"),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_ok"),
        s("actionban"),
        s("true"),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_ok"),
        s("actionunban"),
        s(&format!("echo ok:<ip> >> '{}'", unban_log.display())),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![s("start"), s("multi")]))
        .await
        .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("banip"),
        s("192.0.2.80"),
        s("192.0.2.82"),
    ]))
    .await
    .unwrap();

    // 2a. Explicit multi-IP unban matches upstream Actions.removeBannedIP: deletes history and
    //     removes ticket for first IP even when its hook fails, logs hook error, processes second IP,
    //     and returns 2 when both were banned and DB deletes succeeded.
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![
            s("set"),
            s("multi"),
            s("unbanip"),
            s("192.0.2.80"),
            s("192.0.2.82"),
        ]))
        .await
        .unwrap(),
        PickleValue::Int(2),
        "multi-IP unban must log first hook failure, process second IP, and return count 2"
    );
    let recorded_unbans = fs::read_to_string(&unban_log).unwrap();
    assert!(
        recorded_unbans.contains("flaky:192.0.2.80")
            && recorded_unbans.contains("ok:192.0.2.80")
            && recorded_unbans.contains("flaky:192.0.2.82")
            && recorded_unbans.contains("ok:192.0.2.82"),
        "both IPs must run through all actions despite first hook failing:\n{recorded_unbans}"
    );
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![s("get"), s("multi"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![])
    );
    {
        let check_db = Fail2BanDb::open(unban_db_path.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("multi"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert!(
            active.is_empty(),
            "SQLite ban rows for both IPs must be cleared on explicit per-IP unban"
        );
    }

    // 2b. Bulk `unban --all` matches upstream 1.1.1 contract: logs action failures, clears ban_manager
    //     and SQLite history so restart will not restore the ban, and returns the unbanned count.
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("banip"),
        s("192.0.2.80"),
    ]))
    .await
    .unwrap();
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
            .await
            .unwrap(),
        PickleValue::Int(1),
        "bulk unban --all must return count even when an action fails (matching upstream)"
    );
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![s("get"), s("multi"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![])
    );
    {
        let check_db = Fail2BanDb::open(unban_db_path.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("multi"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert!(
            active.is_empty(),
            "bulk unban --all must clear SQLite ban rows so restart cannot restore them"
        );
    }
    let _ = tr2.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 3. Journal reader keeps fixed cutoff within child (equal + out-of-order _SOURCE_REALTIME_TIMESTAMP)
    //    and resumes restarted child via --after-cursor.
    let cursor_jctl = dir.path().join("mock-cursor-jctl.sh");
    let cursor_state = dir.path().join("cursor_runs");
    fs::write(
        &cursor_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             count=0\n\
             if [[ -f '{0}' ]]; then count=$(cat '{0}'); fi\n\
             count=$((count + 1))\n\
             echo \"$count: $*\" >> '{0}.args'\n\
             echo \"$count\" > '{0}'\n\
             if [[ $count -eq 1 ]]; then\n\
                 echo '{{\"__CURSOR\":\"s=1;i=1\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"rec1\",\"__REALTIME_TIMESTAMP\":\"1715675415000000\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1715675415000000\"}}'\n\
                 echo '{{\"__CURSOR\":\"s=1;i=2\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"rec2-same-ts\",\"__REALTIME_TIMESTAMP\":\"1715675415000000\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1715675415000000\"}}'\n\
                 echo '{{\"__CURSOR\":\"s=1;i=3\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"rec3-older-source\",\"__REALTIME_TIMESTAMP\":\"1715675415500000\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1715675410000000\"}}'\n\
                 exit 1\n\
             else\n\
                 echo '{{\"__CURSOR\":\"s=1;i=4\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"rec4-after-cursor\",\"__REALTIME_TIMESTAMP\":\"1715675415500000\",\"_SOURCE_REALTIME_TIMESTAMP\":\"1715675415000000\"}}'\n\
                 sleep 30\n\
             fi\n",
            cursor_state.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&cursor_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let (j_tx, mut j_rx) = mpsc::channel(16);
    let (j_shut_tx, j_shut_rx) = watch::channel(false);
    let reader = FilterSystemd::new(JournalConfig::default(), LogEncoding::Utf8, false)
        .with_since(Some(1_715_675_415.0))
        .with_journalctl_bin(cursor_jctl.to_str().unwrap());
    let j_handle = tokio::spawn(async move { reader.run(j_tx, j_shut_rx).await });

    let mut received = Vec::new();
    for _ in 0..4 {
        let ev = tokio::time::timeout(Duration::from_secs(3), j_rx.recv())
            .await
            .unwrap()
            .unwrap();
        if let LogEvent::Line { line, .. } = ev {
            received.push(line);
        }
    }
    let _ = j_shut_tx.send(true);
    j_handle.await.unwrap().unwrap();

    assert!(received[0].contains("rec1"), "{received:?}");
    assert!(received[1].contains("rec2-same-ts"), "{received:?}");
    assert!(received[2].contains("rec3-older-source"), "{received:?}");
    assert!(received[3].contains("rec4-after-cursor"), "{received:?}");
    let cursor_args = fs::read_to_string(format!("{}.args", cursor_state.display())).unwrap();
    assert!(
        cursor_args.contains("--after-cursor=s=1;i=3"),
        "restarted journalctl must resume with --after-cursor:\n{cursor_args}"
    );

    // 4. Invalid journalmatch is rejected without disturbing live reader, and dead reader surfaces in status.
    let status_jctl = dir.path().join("mock-status-jctl.sh");
    let kill_flag = dir.path().join("jctl_die");
    fs::write(
        &status_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             for a in \"$@\"; do\n\
                 if [[ \"$a\" == \"--lines=0\" ]]; then\n\
                     for m in \"$@\"; do\n\
                         if [[ \"$m\" == \"_REJECT=1\" ]]; then echo 'rejected match' >&2; exit 1; fi\n\
                     done\n\
                     exit 0\n\
                 fi\n\
             done\n\
             if [[ -f '{}' ]]; then\n\
                 echo 'simulated journal failure' >&2\n\
                 exit 1\n\
             fi\n\
             sleep 30\n",
            kill_flag.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&status_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let j_sys = Jail::new("syshealth", "systemd", None).unwrap();
    {
        let mut st = j_sys.state.lock().await;
        st.set_journalctl_bin(status_jctl.to_str().unwrap());
        st.add_journal_match(&["_SYSTEMD_UNIT=sshd.service".to_owned()])
            .await
            .unwrap();
        assert!(
            st.add_journal_match(&["INVALID_NO_EQ".to_owned()])
                .await
                .is_err(),
            "syntactically invalid journalmatch must be rejected"
        );
        assert!(
            st.add_journal_match(&["_REJECT=1".to_owned()])
                .await
                .is_err(),
            "journalctl-rejected match must fail before replacing live reader"
        );
        assert_eq!(st.journal_matches.len(), 1);
    }
    fs::write(&kill_flag, "1").unwrap();
    j_sys.start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut saw_backend_error = false;
    while tokio::time::Instant::now() < deadline {
        let st = j_sys.state.lock().await;
        let basic = format!("{:?}", st.status("basic"));
        let stats = format!("{:?}", st.status("stats"));
        if basic.contains("Backend error")
            && basic.contains("simulated journal failure")
            && stats.contains("systemd (error)")
        {
            saw_backend_error = true;
            break;
        }
        drop(st);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_backend_error,
        "dead journal reader must expose backend error in status and stats"
    );
    j_sys.stop().await.unwrap();

    // 5. Idle `tail` jail reconfiguration before any line consumed does not skip queued records
    //    (covers both non-empty and initially empty tail files).
    let tail_nonempty = dir.path().join("tail_nonempty.log");
    let tail_empty = dir.path().join("tail_empty.log");
    fs::write(&tail_nonempty, "old pre-existing line\n").unwrap();
    fs::write(&tail_empty, "").unwrap();

    let tail_jail = Jail::new("tailrec", "polling", None).unwrap();
    {
        let mut st = tail_jail.state.lock().await;
        st.filter.set_ignore_self(false);
        st.filter.set_date_pattern(Some("{NONE}")).unwrap();
        st.filter.add_fail_regex("^fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
        st.add_log_path(tail_nonempty.clone(), true).unwrap();
        st.add_log_path(tail_empty.clone(), true).unwrap();
    }
    tail_jail.start().await.unwrap();
    // Immediately idle before any new record is consumed.
    tail_jail.set_idle(true).await;
    {
        let mut f1 = OpenOptions::new()
            .append(true)
            .open(&tail_nonempty)
            .unwrap();
        writeln!(f1, "fail 192.0.2.41").unwrap();
        let mut f2 = OpenOptions::new().append(true).open(&tail_empty).unwrap();
        writeln!(f2, "fail 192.0.2.42").unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;
    {
        let mut st = tail_jail.state.lock().await;
        st.filter.set_log_encoding_str("utf-8").unwrap();
    }
    tail_jail.restart_backend_if_alive().await;
    tail_jail.set_idle(false).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut both_banned = false;
    while tokio::time::Instant::now() < deadline {
        let st = tail_jail.state.lock().await;
        if st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.41"))
            && st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.42"))
        {
            both_banned = true;
            break;
        }
        drop(st);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        both_banned,
        "idle tail reconfiguration must not skip queued records in nonempty or empty files"
    );
    tail_jail.stop().await.unwrap();

    // 6. Sustained log traffic must not starve 1-second periodic tick / ban expiry,
    //    and file offsets must not commit to SQLite ahead of ban writes or per benign line.
    let batch_db_path = dir.path().join("batch.sqlite3");
    let batch_db = Arc::new(std::sync::Mutex::new(
        Fail2BanDb::open(batch_db_path.to_str().unwrap(), 86_400, 10).unwrap(),
    ));
    let batch_log = dir.path().join("batch.log");
    let pos_seen_during_ban = dir.path().join("pos_during_ban.txt");
    fs::write(&batch_log, "").unwrap();
    let batch_jail = Jail::new("batch", "polling", Some(Arc::clone(&batch_db))).unwrap();
    {
        let mut st = batch_jail.state.lock().await;
        st.filter.set_ignore_self(false);
        st.filter.set_date_pattern(Some("{NONE}")).unwrap();
        st.filter.add_fail_regex("^banme <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
        st.ban_manager.set_ban_time(1);
        st.add_log_path(batch_log.clone(), false).unwrap();
        st.add_action("probe", None, None).await.unwrap();
        st.get_action_mut("probe")
            .unwrap()
            .set_property(
                "actionban",
                &format!(
                    "python3 -c \"import sqlite3; c=sqlite3.connect('{}'); r=c.execute('SELECT lastfilepos FROM logs').fetchall(); print(r)\" > '{}'",
                    batch_db_path.display(),
                    pos_seen_during_ban.display()
                ),
            )
            .await
            .unwrap();
        // Process benign lines directly without LogEvent::Checkpoint: SQLite `logs` must stay untouched per line.
        let now = current_unix_seconds();
        for i in 0..5u64 {
            st.handle_log_event(
                LogEvent::Line {
                    line: format!("benign line {i}"),
                    preset_date: None,
                    log_path: Some(batch_log.to_string_lossy().into_owned()),
                    in_operation: true,
                    checkpoint: Some(("fp_test".to_owned(), (i + 1) * 14)),
                    journal_cursor: None,
                },
                now,
            )
            .await;
        }
        assert!(
            batch_db
                .lock()
                .unwrap()
                .get_logs("batch")
                .unwrap()
                .is_empty(),
            "benign LogEvent::Line must not synchronously commit SQLite per line"
        );
        // Trigger a ban line: during actionban, SQLite must NOT already have the post-line offset.
        st.handle_log_event(
            LogEvent::Line {
                line: "banme 192.0.2.77".to_owned(),
                preset_date: None,
                log_path: Some(batch_log.to_string_lossy().into_owned()),
                in_operation: true,
                checkpoint: Some(("fp_test".to_owned(), 999)),
                journal_cursor: None,
            },
            now,
        )
        .await;
        let seen_mid_ban = fs::read_to_string(&pos_seen_during_ban).unwrap();
        assert!(
            !seen_mid_ban.contains("999"),
            "SQLite offset must not advance before ban action & DB write finish: {seen_mid_ban}"
        );
        // Periodic tick / Checkpoint flushes batched offset after ban persistence.
        st.periodic_tick(now).await;
        let saved_logs = batch_db.lock().unwrap().get_logs("batch").unwrap();
        assert!(
            saved_logs.iter().any(|(_, _, pos)| *pos == 999),
            "batched offset must persist on tick/checkpoint: {saved_logs:?}"
        );
    }

    // Now test sustained traffic does not starve ban expiry for 192.0.2.78 (bantime=1s).
    let flood_jail = Jail::new("flood", "polling", None).unwrap();
    let flood_log = dir.path().join("flood.log");
    fs::write(&flood_log, "").unwrap();
    {
        let mut st = flood_jail.state.lock().await;
        st.filter.set_ignore_self(false);
        st.filter.set_date_pattern(Some("{NONE}")).unwrap();
        st.filter.add_fail_regex("^hit <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
        st.ban_manager.set_ban_time(1);
        st.add_log_path(flood_log.clone(), false).unwrap();
    }
    flood_jail.start().await.unwrap();
    flood_jail
        .state
        .lock()
        .await
        .ban_ip(&["192.0.2.78".to_owned()])
        .await
        .unwrap();
    let flood_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flood_stop_bg = Arc::clone(&flood_stop);
    let flood_log_bg = flood_log.clone();
    let writer_task = tokio::spawn(async move {
        let mut batch = String::new();
        for i in 0..400 {
            batch.push_str(&format!("benign flood line {i}\n"));
        }
        while !flood_stop_bg.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(mut f) = OpenOptions::new().append(true).open(&flood_log_bg) {
                let _ = f.write_all(batch.as_bytes());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut expired = false;
    while tokio::time::Instant::now() < deadline {
        if !flood_jail
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.78"))
        {
            expired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    flood_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = writer_task.await;
    flood_jail.stop().await.unwrap();
    assert!(
        expired,
        "expired ban must still unban promptly under sustained log traffic"
    );

    // 7. `fail2ban-client -t` rejects Rust 1.1.1's `systemd[tail=true]` with a migration diagnostic.
    let cli_conf = dir.path().join("cli_test_conf");
    fs::create_dir_all(cli_conf.join("filter.d")).unwrap();
    fs::create_dir_all(cli_conf.join("action.d")).unwrap();
    fs::write(
        cli_conf.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {0}/sock\npidfile = {0}/pid\n\
             loglevel = ERROR\nlogtarget = STDERR\ndbfile = None\n",
            cli_conf.display()
        ),
    )
    .unwrap();
    fs::write(
        cli_conf.join("filter.d/dummy.conf"),
        "[Definition]\nfailregex = ^fail <HOST>$\n",
    )
    .unwrap();
    fs::write(
        cli_conf.join("jail.conf"),
        "[legacy]\nenabled = true\nbackend = systemd[tail=true]\nfilter = dummy\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_fail2ban-client"))
        .arg("-c")
        .arg(&cli_conf)
        .arg("-t")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "fail2ban-client -t must reject backend = systemd[tail=true]"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("unexpected keyword argument 'tail'") && combined.contains("1.1.1"),
        "expected migration diagnostic in -t output:\n{combined}"
    );
}

#[tokio::test]
async fn round3_journal_rotated_db_switch_reload_rollback_dual_stack_and_inclusive_resume_test() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;

    use fail2ban_rs::db::Fail2BanDb;
    use fail2ban_rs::protocol::PickleValue;
    use fail2ban_rs::server::Transmitter;
    use fail2ban_rs::server::jail::{Jail, current_unix_seconds};
    use fail2ban_rs::ticket::{Ticket, TicketId};

    let dir = tempfile::TempDir::new().unwrap();
    let s = |v: &str| PickleValue::Str(v.to_owned());

    // 1. Default journal reader (daemon AND fail2ban-regex) excludes rotated *@*.journal files
    //    unless rotated=true / rotated=on is explicitly requested.
    let jdir = dir.path().join("journals");
    fs::create_dir_all(&jdir).unwrap();
    let active_j = jdir.join("system.journal");
    let rotated_j = jdir.join("system@0001.journal");
    fs::write(&active_j, b"active").unwrap();
    fs::write(&rotated_j, b"rotated").unwrap();

    let mock_bin_dir = dir.path().join("mock_bin");
    fs::create_dir_all(&mock_bin_dir).unwrap();
    let mock_jctl = mock_bin_dir.join("journalctl");
    let recent_us = ((current_unix_seconds() as i64) - 5) * 1_000_000;
    fs::write(
        &mock_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             is_follow=0\n\
             is_probe=0\n\
             want_active=0\n\
             want_rotated=0\n\
             for a in \"$@\"; do\n\
                 case \"$a\" in\n\
                     --follow) is_follow=1 ;;\n\
                     --lines=0) is_probe=1 ;;\n\
                     --file=*system.journal) want_active=1 ;;\n\
                     --file=*@*.journal) want_rotated=1 ;;\n\
                     --directory=*) want_active=1; want_rotated=1 ;;\n\
                 esac\n\
             done\n\
             if [[ $is_probe -eq 1 ]]; then exit 0; fi\n\
             if [[ $want_active -eq 1 ]]; then\n\
                 echo '{{\"__CURSOR\":\"c=active\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"fail 192.0.2.11\",\"__REALTIME_TIMESTAMP\":\"{recent_us}\"}}'\n\
             fi\n\
             if [[ $want_rotated -eq 1 ]]; then\n\
                 echo '{{\"__CURSOR\":\"c=rot\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"fail 192.0.2.12\",\"__REALTIME_TIMESTAMP\":\"{recent_us}\"}}'\n\
             fi\n\
             if [[ $is_follow -eq 1 ]]; then sleep 30; fi\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&mock_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let j_default = Jail::new(
        "jr_def",
        format!("systemd[journalpath={}]", jdir.display()),
        None,
    )
    .unwrap();
    {
        let mut st = j_default.state.lock().await;
        st.set_journalctl_bin(mock_jctl.to_str().unwrap());
        st.filter.set_ignore_self(false);
        st.filter.add_fail_regex("fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
    }
    j_default.start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if j_default
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.11"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    {
        let st = j_default.state.lock().await;
        assert!(
            st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.11")),
            "default systemd jail must read active system.journal"
        );
        assert!(
            !st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.12")),
            "default systemd jail must ignore rotated *@*.journal"
        );
    }
    j_default.stop().await.unwrap();

    let j_rot = Jail::new(
        "jr_rot",
        format!("systemd[journalpath={}, rotated=true]", jdir.display()),
        None,
    )
    .unwrap();
    {
        let mut st = j_rot.state.lock().await;
        st.set_journalctl_bin(mock_jctl.to_str().unwrap());
        st.filter.set_ignore_self(false);
        st.filter.add_fail_regex("fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
    }
    j_rot.start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let st = j_rot.state.lock().await;
        if st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.11"))
            && st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.12"))
        {
            break;
        }
        drop(st);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    {
        let st = j_rot.state.lock().await;
        assert!(st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.11")));
        assert!(
            st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.12")),
            "systemd[rotated=true] must include rotated journal files"
        );
    }
    j_rot.stop().await.unwrap();

    // Verify fail2ban-regex shares the exact same non-rotated default and rotated=on opt-in.
    let orig_path = std::env::var("PATH").unwrap_or_default();
    let test_path = format!("{}:{orig_path}", mock_bin_dir.display());
    let regex_default = Command::new(env!("CARGO_BIN_EXE_fail2ban-regex"))
        .env("PATH", &test_path)
        .args([
            &format!("systemd-journal[journalpath={}]", jdir.display()),
            "fail <HOST>$",
        ])
        .output()
        .unwrap();
    assert!(
        regex_default.status.success(),
        "fail2ban-regex default failed: {}",
        String::from_utf8_lossy(&regex_default.stderr)
    );
    let out_def = String::from_utf8_lossy(&regex_default.stdout);
    assert!(
        out_def.contains("1 matched"),
        "fail2ban-regex default must ignore rotated journal:\n{out_def}"
    );
    let regex_rot = Command::new(env!("CARGO_BIN_EXE_fail2ban-regex"))
        .env("PATH", &test_path)
        .args([
            &format!(
                "systemd-journal[journalpath={}, rotated=on]",
                jdir.display()
            ),
            "fail <HOST>$",
        ])
        .output()
        .unwrap();
    assert!(regex_rot.status.success());
    let out_rot = String::from_utf8_lossy(&regex_rot.stdout);
    assert!(
        out_rot.contains("2 matched"),
        "fail2ban-regex rotated=on must include rotated journal:\n{out_rot}"
    );

    // 2. `reload --restart --all` can switch databases (to another SQLite DB or None), while
    //    plain `reload --all` still rejects dbfile changes and failed restart reloads keep old DB.
    let db_a_path = dir.path().join("db_a.sqlite3");
    let db_b_path = dir.path().join("db_b.sqlite3");
    {
        let db_b = Fail2BanDb::open(db_b_path.to_str().unwrap(), 86_400, 10).unwrap();
        db_b.add_jail("svc").unwrap();
        let mut ticket = Ticket::new(TicketId::parse("192.0.2.32"), current_unix_seconds());
        ticket.ban_time = Some(600);
        db_b.add_ban("svc", &ticket, 600).unwrap();
    }

    let mut tr = Transmitter::default();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("dbfile"),
        s(db_a_path.to_str().unwrap()),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![s("add"), s("svc"), s("polling")]))
        .await
        .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("ignoreself"),
        s("false"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![s("start"), s("svc")]))
        .await
        .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("banip"),
        s("192.0.2.31"),
    ]))
    .await
    .unwrap();

    let switch_db_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("set"), s("dbfile"), s(db_b_path.to_str().unwrap())]),
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![s("set"), s("svc"), s("ignoreself"), s("false")]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    // Plain reload without --restart must reject changing dbfile while jails exist.
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            switch_db_stream.clone(),
        ]))
        .await
        .is_err()
    );
    // Failed reload --restart --all with broken action must keep DB A and old ban intact.
    let bad_db_switch_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("set"), s("dbfile"), s(db_b_path.to_str().unwrap())]),
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("addaction"),
            s("broken"),
            s("/nonexistent/fail2ban_db_switch_broken.py"),
            s("{}"),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![s("--restart")]),
            bad_db_switch_stream,
        ]))
        .await
        .is_err()
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("dbfile")]))
            .await
            .unwrap(),
        s(db_a_path.to_str().unwrap())
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.31")])
    );

    // Valid reload --restart --all switches to DB B and restores DB B's active ban.
    tr.dispatch(&PickleValue::List(vec![
        s("reload"),
        s("--all"),
        PickleValue::List(vec![s("--restart")]),
        switch_db_stream,
    ]))
    .await
    .unwrap();
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("dbfile")]))
            .await
            .unwrap(),
        s(db_b_path.to_str().unwrap())
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.32")]),
        "restarted jail must restore bans from switched DB B"
    );

    // Switching dbfile to None via reload --restart --all also succeeds.
    let disable_db_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("set"), s("dbfile"), s("None")]),
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![s("set"), s("svc"), s("ignoreself"), s("false")]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    tr.dispatch(&PickleValue::List(vec![
        s("reload"),
        s("--all"),
        PickleValue::List(vec![s("--restart")]),
        disable_db_stream,
    ]))
    .await
    .unwrap();
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("dbfile")]))
            .await
            .unwrap(),
        PickleValue::None
    );

    // 3. Failed reload restores ALL live jail settings (maxretry, findtime, bantime, maxmatches, bantime.increment),
    //    both on mid-stream error and on action-handoff failure.
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("maxretry"),
        PickleValue::Int(2),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("findtime"),
        s("600"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("bantime"),
        s("600"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("maxmatches"),
        PickleValue::Int(5),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("bantime.increment"),
        s("false"),
    ]))
    .await
    .unwrap();
    let fail_settings_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("maxretry"),
            PickleValue::Int(99),
        ]),
        PickleValue::List(vec![s("set"), s("svc"), s("findtime"), s("3600")]),
        PickleValue::List(vec![s("set"), s("svc"), s("bantime"), s("7200")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("maxmatches"),
            PickleValue::Int(20),
        ]),
        PickleValue::List(vec![s("set"), s("svc"), s("bantime.increment"), s("true")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("addaction"),
            s("broken_import"),
            s("/nonexistent/fail2ban_broken_settings.py"),
            s("{}"),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            fail_settings_stream,
        ]))
        .await
        .is_err()
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("maxretry")]))
            .await
            .unwrap(),
        PickleValue::Int(2)
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("findtime")]))
            .await
            .unwrap(),
        PickleValue::Int(600)
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("bantime")]))
            .await
            .unwrap(),
        PickleValue::Int(600)
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![
            s("get"),
            s("svc"),
            s("maxmatches")
        ]))
        .await
        .unwrap(),
        PickleValue::Int(5)
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![
            s("get"),
            s("svc"),
            s("bantime.increment")
        ]))
        .await
        .unwrap(),
        PickleValue::Bool(false)
    );
    // Confirm live enforcement still bans after 2 attempts (not 99).
    for _ in 0..2 {
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("attempt"),
            s("192.0.2.66"),
            s("line"),
        ]))
        .await
        .unwrap();
    }
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.66")])
    );

    // 4. Failing in-place actionreload restores live settings (maxretry), and a partly started
    //    eager dual-stack action stops only the family half that actually started.
    let dual_log = dir.path().join("dual_stack.log");
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("addaction"),
        s("dual_act"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("action"),
        s("dual_act"),
        s("actionstart_on_demand"),
        s("false"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("action"),
        s("dual_act"),
        s("families"),
        s("inet4, inet6"),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("action"),
        s("dual_act"),
        s("actionstart?family=inet4"),
        s(&format!(
            "echo dual:start:inet4 >> '{}'",
            dual_log.display()
        )),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("action"),
        s("dual_act"),
        s("actionstart?family=inet6"),
        s(&format!(
            "echo dual:start:inet6 >> '{}' && false",
            dual_log.display()
        )),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("action"),
        s("dual_act"),
        s("actionstop?family=inet4"),
        s(&format!("echo dual:stop:inet4 >> '{}'", dual_log.display())),
    ]))
    .await
    .unwrap();
    tr.dispatch(&PickleValue::List(vec![
        s("set"),
        s("svc"),
        s("action"),
        s("dual_act"),
        s("actionstop?family=inet6"),
        s(&format!("echo dual:stop:inet6 >> '{}'", dual_log.display())),
    ]))
    .await
    .unwrap();
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("dual_act"),
            s("start"),
        ]))
        .await
        .is_err(),
        "partial dual-stack action start failure must return Err"
    );
    let fail_in_place_reload_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("maxretry"),
            PickleValue::Int(77),
        ]),
        PickleValue::List(vec![s("set"), s("svc"), s("addaction"), s("dual_act")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("dual_act"),
            s("actionreload"),
            s("false"),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            fail_in_place_reload_stream,
        ]))
        .await
        .is_err(),
        "failing in-place actionreload must fail reload"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("maxretry")]))
            .await
            .unwrap(),
        PickleValue::Int(2),
        "actionreload failure must also restore live maxretry"
    );
    let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;
    let dual_events = fs::read_to_string(&dual_log).unwrap();
    assert!(
        dual_events.contains("dual:start:inet4") && dual_events.contains("dual:stop:inet4"),
        "stop must clean up the IPv4 half that started:\n{dual_events}"
    );
    assert!(
        !dual_events.contains("dual:stop:inet6"),
        "stop must not stop the IPv6 half that never started:\n{dual_events}"
    );

    // 5. Migrated timestamp-only journal checkpoint resumes inclusively without skipping
    //    an unread record sharing the exact saved timestamp.
    let mig_db_path = dir.path().join("mig_journal.sqlite3");
    let mig_db = Arc::new(std::sync::Mutex::new(
        Fail2BanDb::open(mig_db_path.to_str().unwrap(), 86_400, 10).unwrap(),
    ));
    let saved_sec = (current_unix_seconds() as i64) - 20;
    let saved_ts = saved_sec as f64;
    let saved_us = saved_sec * 1_000_000;
    {
        let guard = mig_db.lock().unwrap();
        guard.add_jail("migj").unwrap();
        guard
            .update_journal("migj", "systemd-journal", saved_ts, "2024-01-01 00:00:00 ")
            .unwrap();
    }
    let mig_jctl = dir.path().join("mock-mig-jctl.sh");
    let mig_args_log = dir.path().join("mig_jctl.args");
    fs::write(
        &mig_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             for a in \"$@\"; do\n\
                 if [[ \"$a\" == \"--lines=0\" ]]; then exit 0; fi\n\
             done\n\
             echo \"$*\" >> '{}'\n\
             echo '{{\"__CURSOR\":\"s=m;i=2\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"fail 192.0.2.99\",\"__REALTIME_TIMESTAMP\":\"{saved_us}\",\"_SOURCE_REALTIME_TIMESTAMP\":\"{saved_us}\"}}'\n\
             sleep 30\n",
            mig_args_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&mig_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let mig_jail = Jail::new("migj", "systemd", Some(Arc::clone(&mig_db))).unwrap();
    {
        let mut st = mig_jail.state.lock().await;
        st.set_journalctl_bin(mig_jctl.to_str().unwrap());
        st.filter.set_ignore_self(false);
        st.filter.add_fail_regex("fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
    }
    mig_jail.start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut banned_same_ts = false;
    while tokio::time::Instant::now() < deadline {
        if mig_jail
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.99"))
        {
            banned_same_ts = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    mig_jail.stop().await.unwrap();
    assert!(
        banned_same_ts,
        "migrated journal checkpoint must inclusively read unread record at exact saved timestamp"
    );
    let mig_args = fs::read_to_string(&mig_args_log).unwrap();
    assert!(
        !mig_args.contains(".000001"),
        "timestamp-only checkpoint must not advance by +1us:\n{mig_args}"
    );
}

#[tokio::test]
async fn round4_installer_reload_unban_journal_and_runtime_flag_test() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration;

    use fail2ban_rs::db::Fail2BanDb;
    use fail2ban_rs::protocol::PickleValue;
    use fail2ban_rs::server::Transmitter;
    use fail2ban_rs::server::jail::{Jail, current_unix_seconds};
    use fail2ban_rs::ticket::TicketId;

    let dir = tempfile::TempDir::new().unwrap();
    let s = |v: &str| PickleValue::Str(v.to_owned());

    // 1. Simplified installer: installs binaries/units/manpages into /usr/local, preserves user
    //    /etc/fail2ban config, upgrades untouched stock apache-fakegooglebot, and `--uninstall`
    //    idempotently removes only /usr/local files while keeping /etc/fail2ban and /var/lib/fail2ban.
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let pkg_name = format!("fail2ban-rs-1.1.2-linux-{arch}");
    let pkg_root = dir.path().join("pkg").join(&pkg_name);
    for sub in ["bin", "man", "config/filter.d/ignorecommands"] {
        fs::create_dir_all(pkg_root.join(sub)).unwrap();
    }
    for bin in ["fail2ban-server", "fail2ban-client", "fail2ban-regex"] {
        fs::write(pkg_root.join("bin").join(bin), format!("RUST-{bin}\n")).unwrap();
    }
    fs::write(pkg_root.join("fail2ban.service"), "RUST-service\n").unwrap();
    fs::write(pkg_root.join("fail2ban.socket"), "RUST-socket\n").unwrap();
    for page in [
        "fail2ban.1",
        "fail2ban-server.1",
        "fail2ban-client.1",
        "fail2ban-regex.1",
        "jail.conf.5",
    ] {
        fs::write(pkg_root.join("man").join(page), format!("RUST-{page}\n")).unwrap();
    }
    fs::write(pkg_root.join("config/jail.conf"), "STOCK-jail.conf\n").unwrap();
    fs::write(
        pkg_root.join("config/filter.d/ignorecommands/apache-fakegooglebot"),
        "RUST-fakegooglebot\n",
    )
    .unwrap();

    let archive = dir.path().join(format!("{pkg_name}.tar.gz"));
    let tar_status = Command::new("tar")
        .args([
            "-czf",
            archive.to_str().unwrap(),
            "-C",
            dir.path().join("pkg").to_str().unwrap(),
            &pkg_name,
        ])
        .status()
        .unwrap();
    assert!(
        tar_status.success(),
        "creating synthetic release archive failed"
    );
    let sha_out = Command::new("sha256sum").arg(&archive).output().unwrap();
    assert!(sha_out.status.success());
    let sha_file = dir.path().join(format!("{pkg_name}.tar.gz.sha256"));
    fs::write(&sha_file, &sha_out.stdout).unwrap();

    let stock_helper_bytes = upstream_source()
        .and_then(|u| fs::read(u.join("config/filter.d/ignorecommands/apache-fakegooglebot")).ok());
    let install_script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install.sh");
    let run_installer = |dest: &Path, arg: &str| {
        let out = Command::new("bash")
            .arg(&install_script)
            .arg(arg)
            .env("DESTDIR", dest)
            .env("FAIL2BAN_VERSION", "1.1.2")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "install.sh {arg} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };

    let dest = dir.path().join("dest_install");
    fs::create_dir_all(dest.join("etc/fail2ban/filter.d/ignorecommands")).unwrap();
    fs::write(dest.join("etc/fail2ban/jail.local"), "USER-jail.local\n").unwrap();
    if let Some(ref bytes) = stock_helper_bytes {
        fs::write(
            dest.join("etc/fail2ban/filter.d/ignorecommands/apache-fakegooglebot"),
            bytes,
        )
        .unwrap();
    }
    run_installer(&dest, archive.to_str().unwrap());
    assert_eq!(
        fs::read_to_string(dest.join("usr/local/bin/fail2ban-server")).unwrap(),
        "RUST-fail2ban-server\n"
    );
    assert_eq!(
        fs::read_to_string(dest.join("usr/local/lib/systemd/system/fail2ban.service")).unwrap(),
        "RUST-service\n"
    );
    assert_eq!(
        fs::read_to_string(dest.join("etc/fail2ban/jail.local")).unwrap(),
        "USER-jail.local\n"
    );
    if stock_helper_bytes.is_some() {
        assert_eq!(
            fs::read_to_string(
                dest.join("etc/fail2ban/filter.d/ignorecommands/apache-fakegooglebot")
            )
            .unwrap(),
            "RUST-fakegooglebot\n"
        );
    }

    run_installer(&dest, "--uninstall");
    run_installer(&dest, "--uninstall");
    assert!(!dest.join("usr/local/bin/fail2ban-server").exists());
    assert!(
        !dest
            .join("usr/local/lib/systemd/system/fail2ban.service")
            .exists()
    );
    assert!(!dest.join("usr/local/share/man/man1/fail2ban.1").exists());
    assert_eq!(
        fs::read_to_string(dest.join("etc/fail2ban/jail.local")).unwrap(),
        "USER-jail.local\n"
    );
    assert!(dest.join("var/lib/fail2ban").is_dir());

    // 2. Shared firewall-set action rename: plain reload matches upstream (retires old and new
    //    aliases absent from _reload_actions instead of reporting live enforcement on fw2),
    //    while `reload --restart` stops fw1 before starting fw2 and restoring the ban.
    let shared_set = dir.path().join("shared_fw.set");
    let rename_db = dir.path().join("rename.sqlite3");
    let mut tr_ren = Transmitter::default();
    tr_ren
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("dbfile"),
            s(rename_db.to_str().unwrap()),
        ]))
        .await
        .unwrap();
    let add_shared_action = |act: &str| {
        vec![
            PickleValue::List(vec![s("set"), s("sshd"), s("addaction"), s(act)]),
            PickleValue::List(vec![
                s("set"),
                s("sshd"),
                s("action"),
                s(act),
                s("actionstart"),
                s(&format!(": > '{}'", shared_set.display())),
            ]),
            PickleValue::List(vec![
                s("set"),
                s("sshd"),
                s("action"),
                s(act),
                s("actionban"),
                s(&format!("echo <ip> >> '{}'", shared_set.display())),
            ]),
            PickleValue::List(vec![
                s("set"),
                s("sshd"),
                s("action"),
                s(act),
                s("actionflush"),
                s(&format!(": > '{}'", shared_set.display())),
            ]),
            PickleValue::List(vec![
                s("set"),
                s("sshd"),
                s("action"),
                s(act),
                s("actionstop"),
                s(&format!("rm -f '{}'", shared_set.display())),
            ]),
        ]
    };
    tr_ren
        .dispatch(&PickleValue::List(vec![s("add"), s("sshd"), s("polling")]))
        .await
        .unwrap();
    tr_ren
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("sshd"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
    for cmd in add_shared_action("fw1") {
        tr_ren.dispatch(&cmd).await.unwrap();
    }
    tr_ren
        .dispatch(&PickleValue::List(vec![s("start"), s("sshd")]))
        .await
        .unwrap();
    tr_ren
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("sshd"),
            s("banip"),
            s("192.0.2.55"),
        ]))
        .await
        .unwrap();
    assert!(
        fs::read_to_string(&shared_set)
            .unwrap()
            .contains("192.0.2.55")
    );

    let mut fw2_cmds = vec![
        PickleValue::List(vec![s("add"), s("sshd"), s("polling")]),
        PickleValue::List(vec![s("set"), s("sshd"), s("ignoreself"), s("false")]),
    ];
    fw2_cmds.extend(add_shared_action("fw2"));
    fw2_cmds.push(PickleValue::List(vec![s("start"), s("sshd")]));
    let fw2_stream = PickleValue::List(fw2_cmds);

    tr_ren
        .dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            fw2_stream.clone(),
        ]))
        .await
        .unwrap();
    assert_eq!(
        tr_ren
            .dispatch(&PickleValue::List(vec![s("get"), s("sshd"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![]),
        "plain reload rename must not leave fw2 registered after fw1 flushed/stopped shared set"
    );
    assert!(
        !shared_set.exists(),
        "fw1 stop cleared the shared set on plain reload"
    );

    tr_ren
        .dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![s("--restart")]),
            fw2_stream,
        ]))
        .await
        .unwrap();
    assert_eq!(
        tr_ren
            .dispatch(&PickleValue::List(vec![s("get"), s("sshd"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("fw2")])
    );
    assert!(
        fs::read_to_string(&shared_set)
            .unwrap()
            .contains("192.0.2.55"),
        "reload --restart must stop old action before starting fw2 and restoring ban"
    );
    let _ = tr_ren.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 3. `unban --all` propagates SQLite write-lock errors instead of reporting success while
    //    leaving bans on disk.
    let lock_db_path = dir.path().join("locked_unban.sqlite3");
    let mut tr_lock = Transmitter::default();
    tr_lock
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("dbfile"),
            s(lock_db_path.to_str().unwrap()),
        ]))
        .await
        .unwrap();
    tr_lock
        .dispatch(&PickleValue::List(vec![s("add"), s("lkj"), s("polling")]))
        .await
        .unwrap();
    tr_lock
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("lkj"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
    tr_lock
        .dispatch(&PickleValue::List(vec![s("start"), s("lkj")]))
        .await
        .unwrap();
    tr_lock
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("lkj"),
            s("banip"),
            s("192.0.2.60"),
        ]))
        .await
        .unwrap();

    let (locked_tx, locked_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let lock_db_bg = lock_db_path.clone();
    let locker = std::thread::spawn(move || {
        let conn = rusqlite::Connection::open(&lock_db_bg).unwrap();
        conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let _ = locked_tx.send(());
        let _ = release_rx.recv();
        let _ = conn.execute_batch("ROLLBACK");
    });
    locked_rx.recv().unwrap();
    let unban_res = tr_lock
        .dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
        .await;
    let _ = release_tx.send(());
    locker.join().unwrap();
    assert!(
        unban_res.is_err(),
        "unban --all must propagate SQLite write-lock failure instead of returning success: {unban_res:?}"
    );
    {
        let check_db = Fail2BanDb::open(lock_db_path.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("lkj"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert_eq!(
            active.len(),
            1,
            "failed bulk delete must leave DB row observable until unlocked retry"
        );
    }
    // Once lock is released, bulk unban clears the database cleanly.
    tr_lock
        .dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
        .await
        .unwrap();
    {
        let check_db = Fail2BanDb::open(lock_db_path.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("lkj"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert!(active.is_empty());
    }
    let _ = tr_lock.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 4. Systemd journal reader transitions to operation mode on initial end of matching records
    //    (both empty match and drained historical records), so delayed live records are not dropped
    //    while genuinely old startup records are still dropped.
    let now_s = current_unix_seconds() as i64;
    let now_us = now_s * 1_000_000;
    let delayed_src_us = (now_s - 660) * 1_000_000; // 11m old (> 10m findtime)
    let hist_rt_us = (now_s - 60) * 1_000_000;

    // 4a. Initially empty match -> delayed live record must ban.
    let empty_jctl = dir.path().join("mock-empty-jctl.sh");
    fs::write(
        &empty_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             is_follow=0\n\
             for a in \"$@\"; do\n\
                 case \"$a\" in\n\
                     --lines=0) exit 0 ;;\n\
                     --follow) is_follow=1 ;;\n\
                 esac\n\
             done\n\
             if [[ $is_follow -eq 0 ]]; then\n\
                 exit 0\n\
             fi\n\
             echo '{{\"__CURSOR\":\"s=e;i=1\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"fail 192.0.2.150\",\"__REALTIME_TIMESTAMP\":\"{now_us}\",\"_SOURCE_REALTIME_TIMESTAMP\":\"{delayed_src_us}\"}}'\n\
             sleep 30\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&empty_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let j_empty = Jail::new("jempty", "systemd", None).unwrap();
    {
        let mut st = j_empty.state.lock().await;
        st.set_journalctl_bin(empty_jctl.to_str().unwrap());
        st.filter.set_ignore_self(false);
        st.filter.set_find_time_str("10m").unwrap();
        st.fail_manager.set_max_time(600.0);
        st.filter.add_fail_regex("fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
    }
    j_empty.start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut empty_banned = false;
    while tokio::time::Instant::now() < deadline {
        if j_empty
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.150"))
        {
            empty_banned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    j_empty.stop().await.unwrap();
    assert!(
        empty_banned,
        "initially empty journal match must enter operation mode and ban delayed live record"
    );

    // 4b. Initially non-empty match: old historical record dropped in startup mode, then delayed
    //     live record after initial EOF banned in operation mode.
    let drain_jctl = dir.path().join("mock-drain-jctl.sh");
    let drain_args_log = dir.path().join("drain.args");
    fs::write(
        &drain_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             is_follow=0\n\
             for a in \"$@\"; do\n\
                 case \"$a\" in\n\
                     --lines=0) exit 0 ;;\n\
                     --follow) is_follow=1 ;;\n\
                 esac\n\
             done\n\
             echo \"$*\" >> '{0}'\n\
             if [[ $is_follow -eq 0 ]]; then\n\
                 echo '{{\"__CURSOR\":\"s=d;i=1\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"fail 192.0.2.151\",\"__REALTIME_TIMESTAMP\":\"{hist_rt_us}\",\"_SOURCE_REALTIME_TIMESTAMP\":\"{delayed_src_us}\"}}'\n\
                 exit 0\n\
             fi\n\
             echo '{{\"__CURSOR\":\"s=d;i=2\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"MESSAGE\":\"fail 192.0.2.152\",\"__REALTIME_TIMESTAMP\":\"{now_us}\",\"_SOURCE_REALTIME_TIMESTAMP\":\"{delayed_src_us}\"}}'\n\
             sleep 30\n",
            drain_args_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&drain_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let j_drain = Jail::new("jdrain", "systemd", None).unwrap();
    {
        let mut st = j_drain.state.lock().await;
        st.set_journalctl_bin(drain_jctl.to_str().unwrap());
        st.filter.set_ignore_self(false);
        st.filter.set_find_time_str("10m").unwrap();
        st.fail_manager.set_max_time(600.0);
        st.filter.add_fail_regex("fail <HOST>$").unwrap();
        st.fail_manager.set_max_retry(1);
    }
    j_drain.start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if j_drain
            .state
            .lock()
            .await
            .ban_manager
            .in_ban_list(&TicketId::parse("192.0.2.152"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    {
        let st = j_drain.state.lock().await;
        assert!(
            !st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.151")),
            "old startup record must still be dropped before operation mode"
        );
        assert!(
            st.ban_manager.in_ban_list(&TicketId::parse("192.0.2.152")),
            "delayed live record after initial EOF must be banned in operation mode"
        );
    }
    j_drain.stop().await.unwrap();
    let drain_args = fs::read_to_string(&drain_args_log).unwrap();
    assert!(
        drain_args.contains("--after-cursor=s=d;i=1"),
        "follow phase must resume seamlessly after initial catch-up cursor:\n{drain_args}"
    );

    // 5. fail2ban-regex preserves runtime-only journal restriction (journalflags=2) both with
    //    rotated=on and on active-discovery fallback.
    let rt_bin_dir = dir.path().join("rt_mock_bin");
    fs::create_dir_all(&rt_bin_dir).unwrap();
    let rt_args_log = dir.path().join("rt_jctl.args");
    let rt_jctl = rt_bin_dir.join("journalctl");
    fs::write(
        &rt_jctl,
        format!(
            "#!/usr/bin/env bash\n\
             echo \"$*\" >> '{}'\n\
             exit 0\n",
            rt_args_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&rt_jctl, fs::Permissions::from_mode(0o755)).unwrap();

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let test_path = format!("{}:{orig_path}", rt_bin_dir.display());
    for spec in [
        "systemd-journal[journalflags=2,rotated=on]",
        "systemd-journal[journalflags=2]",
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_fail2ban-regex"))
            .env("PATH", &test_path)
            .args([spec, "fail <HOST>$"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "fail2ban-regex {spec} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let rt_logged = fs::read_to_string(&rt_args_log).unwrap();
    let rt_lines: Vec<&str> = rt_logged.lines().collect();
    assert_eq!(
        rt_lines.len(),
        2,
        "expected two journalctl runs:\n{rt_logged}"
    );
    assert!(
        rt_lines[0].contains("--directory=") && rt_lines[0].contains("/journal"),
        "journalflags=2,rotated=on must pass runtime --directory:\n{}",
        rt_lines[0]
    );
    assert!(
        (rt_lines[1].contains("--directory=") || rt_lines[1].contains("--file="))
            && rt_lines[1].contains("/journal"),
        "journalflags=2 without rotated must keep runtime restriction:\n{}",
        rt_lines[1]
    );
}

#[tokio::test]
async fn round5_subnet_unban_and_flush_recovery_test() {
    use std::fs;
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration;

    use fail2ban_rs::db::Fail2BanDb;
    use fail2ban_rs::protocol::PickleValue;
    use fail2ban_rs::server::Transmitter;
    use fail2ban_rs::server::jail::current_unix_seconds;

    let s = |v: &str| PickleValue::Str(v.to_owned());
    let dir = tempfile::TempDir::new().unwrap();

    // 1. Subnet unban with a SQLite write lock acquired during the first IP's unban action must
    //    keep the remaining ticket(s) in memory and SQLite so retry cleans firewall + DB.
    let sub_db = dir.path().join("subnet_lock.sqlite3");
    let sub_fw = dir.path().join("subnet_fw.log");
    let sub_hit = dir.path().join("subnet_hit.flag");
    let sub_locked = dir.path().join("subnet_locked.flag");
    let mut tr_sub = Transmitter::default();
    tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("dbfile"),
            s(sub_db.to_str().unwrap()),
        ]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![s("add"), s("subj"), s("polling")]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("subj"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("subj"),
            s("addaction"),
            s("fw"),
        ]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("subj"),
            s("action"),
            s("fw"),
            s("actionban"),
            s(&format!("echo ban:<ip> >> '{}'", sub_fw.display())),
        ]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("subj"),
            s("action"),
            s("fw"),
            s("actionunban"),
            s(&format!(
                "echo unban:<ip> >> '{}'; if [ \"<ip>\" = \"192.0.2.10\" ]; then : > '{}'; while [ ! -f '{}' ]; do sleep 0.02; done; fi",
                sub_fw.display(),
                sub_hit.display(),
                sub_locked.display()
            )),
        ]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![s("start"), s("subj")]))
        .await
        .unwrap();
    tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("subj"),
            s("banip"),
            s("192.0.2.10"),
            s("192.0.2.20"),
        ]))
        .await
        .unwrap();

    let (release_tx, release_rx) = std_mpsc::channel();
    let sub_db_bg = sub_db.clone();
    let sub_hit_bg = sub_hit.clone();
    let sub_locked_bg = sub_locked.clone();
    let sub_locker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !sub_hit_bg.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let conn = rusqlite::Connection::open(&sub_db_bg).unwrap();
        conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
        fs::write(&sub_locked_bg, "").unwrap();
        let _ = release_rx.recv();
        let _ = conn.execute_batch("ROLLBACK");
    });

    let first_sub_unban = tr_sub
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("subj"),
            s("unbanip"),
            s("192.0.2.0/24"),
        ]))
        .await;
    let _ = release_tx.send(());
    sub_locker.join().unwrap();
    assert!(
        first_sub_unban.is_err(),
        "mid-subnet SQLite lock must propagate error: {first_sub_unban:?}"
    );
    assert_eq!(
        tr_sub
            .dispatch(&PickleValue::List(vec![
                s("get"),
                s("subj"),
                s("banned"),
                s("192.0.2.10"),
            ]))
            .await
            .unwrap(),
        PickleValue::Int(0),
        "first IP already unbanned before lock"
    );
    assert_eq!(
        tr_sub
            .dispatch(&PickleValue::List(vec![
                s("get"),
                s("subj"),
                s("banned"),
                s("192.0.2.20"),
            ]))
            .await
            .unwrap(),
        PickleValue::Int(1),
        "second IP must remain in BanManager after DB delete failure"
    );
    let fw_mid = fs::read_to_string(&sub_fw).unwrap();
    assert!(fw_mid.contains("unban:192.0.2.10"));
    assert!(
        !fw_mid.contains("unban:192.0.2.20"),
        "second IP actionunban must not have run on failed DB delete"
    );
    {
        let check_db = Fail2BanDb::open(sub_db.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("subj"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].fid.to_string(), "192.0.2.20");
    }

    // Retry subnet unban after lock release cleanly removes 192.0.2.20 from DB, memory, and firewall.
    assert_eq!(
        tr_sub
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("subj"),
                s("unbanip"),
                s("192.0.2.0/24"),
            ]))
            .await
            .unwrap(),
        PickleValue::Int(1)
    );
    assert_eq!(
        tr_sub
            .dispatch(&PickleValue::List(vec![
                s("get"),
                s("subj"),
                s("banned"),
                s("192.0.2.20"),
            ]))
            .await
            .unwrap(),
        PickleValue::Int(0)
    );
    let fw_after = fs::read_to_string(&sub_fw).unwrap();
    assert!(
        fw_after.contains("unban:192.0.2.20"),
        "retry subnet unban must run firewall unban for remaining IP:\n{fw_after}"
    );
    {
        let check_db = Fail2BanDb::open(sub_db.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("subj"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert!(active.is_empty());
    }
    let _ = tr_sub.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 2. Flush exceptions follow upstream consistencyCheck recovery and stop-specific repair
    //    decisions before selecting individual-unban fallback.
    // 2a. Bulk unban --all (stop=False): failed flush runs check + repair and skips individual unban.
    let broken_marker = dir.path().join("broken_bulk.flag");
    let bulk_log = dir.path().join("flush_bulk.log");
    let mut tr_bulk = Transmitter::default();
    tr_bulk
        .dispatch(&PickleValue::List(vec![s("add"), s("flb"), s("polling")]))
        .await
        .unwrap();
    tr_bulk
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("flb"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
    tr_bulk
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("flb"),
            s("addaction"),
            s("fw"),
        ]))
        .await
        .unwrap();
    for (prop, val) in [
        (
            "actionstart",
            format!("echo start >> '{}'", bulk_log.display()),
        ),
        (
            "actionban",
            format!("echo ban:<ip> >> '{}'", bulk_log.display()),
        ),
        (
            "actionunban",
            format!("echo unban:<ip> >> '{}'", bulk_log.display()),
        ),
        (
            "actionflush",
            format!("echo flush >> '{}'; exit 1", bulk_log.display()),
        ),
        (
            "actioncheck",
            format!(
                "echo check >> '{}'; test ! -f '{}'",
                bulk_log.display(),
                broken_marker.display()
            ),
        ),
        (
            "actionrepair",
            format!(
                "echo repair >> '{}'; rm -f '{}'",
                bulk_log.display(),
                broken_marker.display()
            ),
        ),
    ] {
        tr_bulk
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("flb"),
                s("action"),
                s("fw"),
                s(prop),
                s(&val),
            ]))
            .await
            .unwrap();
    }
    tr_bulk
        .dispatch(&PickleValue::List(vec![s("start"), s("flb")]))
        .await
        .unwrap();
    tr_bulk
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("flb"),
            s("banip"),
            s("192.0.2.190"),
        ]))
        .await
        .unwrap();
    fs::write(&broken_marker, "").unwrap();
    assert_eq!(
        tr_bulk
            .dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
            .await
            .unwrap(),
        PickleValue::Int(1)
    );
    let bulk_events = fs::read_to_string(&bulk_log).unwrap();
    assert!(
        bulk_events.contains("flush"),
        "expected flush:\n{bulk_events}"
    );
    assert!(
        bulk_events.contains("check"),
        "expected check:\n{bulk_events}"
    );
    assert!(
        bulk_events.contains("repair"),
        "bulk flush error must run actionrepair:\n{bulk_events}"
    );
    assert!(
        !bulk_events.contains("unban:192.0.2.190"),
        "action with consistencyCheck must skip individual unban fallback:\n{bulk_events}"
    );
    assert!(
        !broken_marker.exists(),
        "repair must have restored environment"
    );
    let _ = tr_bulk.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 4b. Obsolete-action cleanup on reload (stop=True): respects actionrepair_on_unban and skips
    //     individual unban fallback while still calling actionstop.
    let rel_log_no = dir.path().join("reload_norepair.log");
    let rel_log_yes = dir.path().join("reload_repair.log");
    let rel_broken = dir.path().join("reload_broken.flag");
    fs::write(&rel_broken, "").unwrap();
    let mut tr_rel = Transmitter::default();
    tr_rel
        .dispatch(&PickleValue::List(vec![s("add"), s("flr"), s("polling")]))
        .await
        .unwrap();
    tr_rel
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("flr"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
    for (act_name, log_path, repair_on_unban) in [
        ("obs_no", &rel_log_no, "false"),
        ("obs_yes", &rel_log_yes, "true"),
    ] {
        tr_rel
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("flr"),
                s("addaction"),
                s(act_name),
            ]))
            .await
            .unwrap();
        for (prop, val) in [
            (
                "actionstart",
                format!("echo start >> '{}'", log_path.display()),
            ),
            (
                "actionban",
                format!("echo ban:<ip> >> '{}'", log_path.display()),
            ),
            (
                "actionunban",
                format!("echo unban:<ip> >> '{}'", log_path.display()),
            ),
            (
                "actionflush",
                format!("echo flush >> '{}'; exit 1", log_path.display()),
            ),
            (
                "actioncheck",
                format!(
                    "echo check >> '{}'; test ! -f '{}'",
                    log_path.display(),
                    rel_broken.display()
                ),
            ),
            (
                "actionrepair",
                format!("echo repair >> '{}'", log_path.display()),
            ),
            (
                "actionstop",
                format!("echo stop >> '{}'", log_path.display()),
            ),
            ("actionrepair_on_unban", repair_on_unban.to_owned()),
        ] {
            tr_rel
                .dispatch(&PickleValue::List(vec![
                    s("set"),
                    s("flr"),
                    s("action"),
                    s(act_name),
                    s(prop),
                    s(&val),
                ]))
                .await
                .unwrap();
        }
    }
    tr_rel
        .dispatch(&PickleValue::List(vec![s("start"), s("flr")]))
        .await
        .unwrap();
    tr_rel
        .dispatch(&PickleValue::List(vec![
            s("set"),
            s("flr"),
            s("banip"),
            s("192.0.2.191"),
        ]))
        .await
        .unwrap();
    // Plain reload omits both actions, triggering obsolete-action cleanup with stop=True.
    let drop_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("flr"), s("polling")]),
        PickleValue::List(vec![s("set"), s("flr"), s("ignoreself"), s("false")]),
        PickleValue::List(vec![s("start"), s("flr")]),
    ]);
    tr_rel
        .dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            drop_stream,
        ]))
        .await
        .unwrap();
    let no_ev = fs::read_to_string(&rel_log_no).unwrap();
    assert!(no_ev.contains("check"), "obs_no must run check:\n{no_ev}");
    assert!(
        !no_ev.contains("repair"),
        "obs_no with stop=True and actionrepair_on_unban=false must skip repair:\n{no_ev}"
    );
    assert!(
        !no_ev.contains("unban:192.0.2.191"),
        "obs_no must skip individual unban fallback:\n{no_ev}"
    );
    assert!(
        no_ev.contains("stop"),
        "obs_no must still execute actionstop:\n{no_ev}"
    );
    let yes_ev = fs::read_to_string(&rel_log_yes).unwrap();
    assert!(
        yes_ev.contains("check"),
        "obs_yes must run check:\n{yes_ev}"
    );
    assert!(
        yes_ev.contains("repair"),
        "obs_yes with actionrepair_on_unban=true must repair on stop flush error:\n{yes_ev}"
    );
    assert!(
        !yes_ev.contains("unban:192.0.2.191"),
        "obs_yes must skip individual unban fallback:\n{yes_ev}"
    );
    let _ = tr_rel.dispatch(&PickleValue::List(vec![s("stop")])).await;
}

#[tokio::test]
async fn round6_unban_cidr_and_stop_reload_test() {
    use std::fs;
    use std::sync::mpsc as std_mpsc;

    use fail2ban_rs::db::Fail2BanDb;
    use fail2ban_rs::protocol::PickleValue;
    use fail2ban_rs::server::Transmitter;
    use fail2ban_rs::server::jail::current_unix_seconds;

    let s = |v: &str| PickleValue::Str(v.to_owned());
    let dir = tempfile::tempdir().unwrap();

    // 1. `unban --all` on a per-IP action (no actionflush, like ufw) under SQLite write lock:
    //    must retain in-memory tickets and skip actionunban until lock clears, then recover on retry.
    {
        let db_path = dir.path().join("r6_ufw_lock.sqlite3");
        let unban_log = dir.path().join("r6_ufw_unban.log");
        let mut tr = Transmitter::default();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("dbfile"),
            s(db_path.to_str().unwrap()),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("add"), s("ufwj"), s("polling")]))
            .await
            .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("ufwj"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("ufwj"),
            s("addaction"),
            s("ufwlike"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("ufwj"),
            s("action"),
            s("ufwlike"),
            s("actionban"),
            s("true"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("ufwj"),
            s("action"),
            s("ufwlike"),
            s("actionunban"),
            s(&format!(
                "printf '%s\\n' '<ip>' >> '{}'",
                unban_log.display()
            )),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("start"), s("ufwj")]))
            .await
            .unwrap();
        for ip in ["192.0.2.211", "192.0.2.212"] {
            tr.dispatch(&PickleValue::List(vec![
                s("set"),
                s("ufwj"),
                s("banip"),
                s(ip),
            ]))
            .await
            .unwrap();
        }

        let (locked_tx, locked_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let lock_path = db_path.clone();
        let locker = std::thread::spawn(move || {
            let conn = rusqlite::Connection::open(&lock_path).unwrap();
            conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
            let _ = locked_tx.send(());
            let _ = release_rx.recv();
            let _ = conn.execute_batch("ROLLBACK");
        });
        locked_rx.recv().unwrap();
        let locked_res = tr
            .dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
            .await;
        let _ = release_tx.send(());
        locker.join().unwrap();
        assert!(
            locked_res.is_err(),
            "unban --all must fail when SQLite is write-locked: {locked_res:?}"
        );
        assert!(
            !unban_log.exists(),
            "per-IP actionunban must not run when DB delete fails under lock"
        );
        let still_banned = tr
            .dispatch(&PickleValue::List(vec![s("get"), s("ufwj"), s("banip")]))
            .await
            .unwrap();
        assert_eq!(
            still_banned,
            PickleValue::List(vec![s("192.0.2.211"), s("192.0.2.212")]),
            "in-memory tickets must remain intact for retry after SQLite lock failure"
        );

        let retry_res = tr
            .dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
            .await
            .unwrap();
        assert_eq!(retry_res, PickleValue::Int(2));
        let unbanned_ips: Vec<String> = fs::read_to_string(&unban_log)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(unbanned_ips, vec!["192.0.2.211", "192.0.2.212"]);
        let check_db = Fail2BanDb::open(db_path.to_str().unwrap(), 86_400, 10).unwrap();
        assert!(
            check_db
                .get_current_bans(Some("ufwj"), None, None, current_unix_seconds() as i64)
                .unwrap()
                .is_empty()
        );
        let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;
    }

    // 3. Large CIDR unban + partial DB failure expiry recomputation.
    {
        let db_path = dir.path().join("r6_cidr.sqlite3");
        let mut tr = Transmitter::default();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("dbfile"),
            s(db_path.to_str().unwrap()),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("add"), s("cidrj"), s("polling")]))
            .await
            .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("cidrj"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("start"), s("cidrj")]))
            .await
            .unwrap();

        let mut ban_cmd = vec![s("set"), s("cidrj"), s("banip")];
        for host in 1..=254u8 {
            ban_cmd.push(s(&format!("198.51.100.{host}")));
        }
        ban_cmd.push(s("203.0.113.9"));
        let added = tr.dispatch(&PickleValue::List(ban_cmd)).await.unwrap();
        assert_eq!(added, PickleValue::Int(255));

        let unbanned = tr
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("cidrj"),
                s("unbanip"),
                s("198.51.100.0/24"),
            ]))
            .await
            .unwrap();
        assert_eq!(unbanned, PickleValue::Int(254));
        assert_eq!(
            tr.dispatch(&PickleValue::List(vec![s("get"), s("cidrj"), s("banip")]))
                .await
                .unwrap(),
            PickleValue::List(vec![s("203.0.113.9")])
        );
        let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;
    }

    // 3. CIDR unban mid-batch DB error integration test (partial removal + retry).
    {
        let db_path = dir.path().join("r7_cidr_partial.sqlite3");
        let mut tr = Transmitter::default();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("dbfile"),
            s(db_path.to_str().unwrap()),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("add"), s("pcidr"), s("polling")]))
            .await
            .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("pcidr"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("start"), s("pcidr")]))
            .await
            .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("pcidr"),
            s("banip"),
            s("198.51.100.1"),
            s("198.51.100.2"),
            s("198.51.100.3"),
        ]))
        .await
        .unwrap();

        let trig_conn = rusqlite::Connection::open(&db_path).unwrap();
        trig_conn
            .execute_batch(
                "CREATE TRIGGER fail_second_ip BEFORE DELETE ON bips \
                 WHEN OLD.ip = '198.51.100.2' \
                 BEGIN SELECT RAISE(ABORT, 'inject mid-batch failure'); END;",
            )
            .unwrap();

        let partial = tr
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("pcidr"),
                s("unbanip"),
                s("198.51.100.0/24"),
            ]))
            .await;
        assert!(partial.is_err());
        assert_eq!(
            tr.dispatch(&PickleValue::List(vec![s("get"), s("pcidr"), s("banip")]))
                .await
                .unwrap(),
            PickleValue::List(vec![s("198.51.100.2"), s("198.51.100.3")]),
            "mid-batch CIDR failure must leave unremoved tickets intact"
        );

        trig_conn
            .execute_batch("DROP TRIGGER fail_second_ip;")
            .unwrap();
        drop(trig_conn);
        let retry = tr
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("pcidr"),
                s("unbanip"),
                s("198.51.100.0/24"),
            ]))
            .await
            .unwrap();
        assert_eq!(retry, PickleValue::Int(2));
        let check_db = Fail2BanDb::open(db_path.to_str().unwrap(), 86_400, 10).unwrap();
        assert!(
            check_db
                .get_current_bans(Some("pcidr"), None, None, current_unix_seconds() as i64)
                .unwrap()
                .is_empty()
        );
        let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;
    }

    // 4. `reload --restart` must not drop a jail when the old action fails flush/check on stop,
    //    and custom third-party `.py` actions must be rejected cleanly.
    {
        let mut tr = Transmitter::default();
        tr.dispatch(&PickleValue::List(vec![s("add"), s("rstj"), s("polling")]))
            .await
            .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("ignoreself"),
            s("false"),
        ]))
        .await
        .unwrap();
        let custom_py_err = tr
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("rstj"),
                s("addaction"),
                s("custom"),
                s("/tmp/custom_action.py"),
                s("{}"),
            ]))
            .await;
        assert!(
            custom_py_err
                .as_ref()
                .is_err_and(|e| e.to_string().contains("not supported")),
            "custom .py action must fail clearly: {custom_py_err:?}"
        );

        let perip_log = dir.path().join("r6_rst_perip.log");
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("addaction"),
            s("brokenfw"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("action"),
            s("brokenfw"),
            s("actionban"),
            s("true"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("action"),
            s("brokenfw"),
            s("actionflush"),
            s("false"),
        ]))
        .await
        .unwrap();
        // Invalid tag inside actioncheck forces consistency_check_on_flush to return Err.
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("action"),
            s("brokenfw"),
            s("actioncheck"),
            s("<missing_tag>"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("addaction"),
            s("perip"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("action"),
            s("perip"),
            s("actionban"),
            s("true"),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("action"),
            s("perip"),
            s("actionunban"),
            s(&format!(
                "printf '%s\\n' '<ip>' >> '{}'",
                perip_log.display()
            )),
        ]))
        .await
        .unwrap();
        tr.dispatch(&PickleValue::List(vec![s("start"), s("rstj")]))
            .await
            .unwrap();
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("rstj"),
            s("banip"),
            s("192.0.2.77"),
        ]))
        .await
        .unwrap();

        let restart_stream = PickleValue::List(vec![
            PickleValue::List(vec![s("add"), s("rstj"), s("polling")]),
            PickleValue::List(vec![s("set"), s("rstj"), s("ignoreself"), s("false")]),
            PickleValue::List(vec![s("set"), s("rstj"), s("addaction"), s("cleanfw")]),
            PickleValue::List(vec![s("start"), s("rstj")]),
        ]);
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![s("--restart")]),
            restart_stream,
        ]))
        .await
        .unwrap();
        assert_eq!(
            tr.dispatch(&PickleValue::List(vec![s("get"), s("rstj"), s("actions")]))
                .await
                .unwrap(),
            PickleValue::List(vec![s("cleanfw")]),
            "reload --restart must install replacement jail even if old action cleanup errored"
        );
        assert_eq!(
            fs::read_to_string(&perip_log).unwrap().trim(),
            "192.0.2.77",
            "failing action cleanup on stop must still unban sibling per-IP action"
        );
        let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;
    }
}
