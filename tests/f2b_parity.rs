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

#[test]
fn third_party_python_actions_match_upstream_properties_methods_ainfo_flush_and_reload() {
    use std::fs;
    use std::path::Path;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    let Some(upstream) = upstream_source() else {
        eprintln!("FAIL2BAN_111_SOURCE not set; skipping Python action E2E test");
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

    fn client(config: &Path, args: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_fail2ban-client"))
            .arg("-c")
            .arg(config)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    let root = tempfile::TempDir::new().unwrap();
    let conf = root.path();
    fs::create_dir(conf.join("filter.d")).unwrap();
    fs::create_dir(conf.join("action.d")).unwrap();
    fs::write(conf.join("auth.log"), "").unwrap();

    let upstream_actions = upstream.join("fail2ban/tests/files/action.d");
    for file in ["action.py", "action_checkainfo.py", "action_modifyainfo.py"] {
        fs::copy(
            upstream_actions.join(file),
            conf.join("action.d").join(file),
        )
        .unwrap();
    }

    let log_file = conf.join("server.log");
    fs::write(
        conf.join("fail2ban.conf"),
        format!(
            "[Definition]\nsocket = {0}/sock\npidfile = {0}/pid\n\
             loglevel = INFO\nlogtarget = {1}\ndbfile = {0}/state.sqlite3\n",
            conf.display(),
            log_file.display()
        ),
    )
    .unwrap();
    fs::write(
        conf.join("jail.conf"),
        format!(
            concat!(
                "[pyjail]\n",
                "enabled = true\n",
                "backend = polling\n",
                "logpath = {0}/auth.log\n",
                "filter = pyfilter\n",
                "action = action.py[actname=pyact, opt1=value]\n",
                "         action_checkainfo.py[actname=checkinfo]\n",
                "         action_modifyainfo.py[actname=modinfo]\n",
                "bantime = 10m\n",
            ),
            conf.display()
        ),
    )
    .unwrap();
    fs::write(
        conf.join("filter.d/pyfilter.conf"),
        "[Definition]\nfailregex = ^Failed from <HOST>$\n",
    )
    .unwrap();

    let mut server = RunningServer(
        Command::new(env!("CARGO_BIN_EXE_fail2ban-server"))
            .arg("-c")
            .arg(conf)
            .args(["-xf", "start"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "server exited during startup"
        );
        let probe = Command::new(env!("CARGO_BIN_EXE_fail2ban-client"))
            .arg("-c")
            .arg(conf)
            .args(["--timeout", "0.1", "status", "pyjail"])
            .output()
            .unwrap();
        if probe.status.success() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Properties & methods parity (matching upstream servertestcase.py:766)
    let props = client(conf, &["get", "pyjail", "actionproperties", "pyact"]);
    assert!(props.contains("opt1") && props.contains("opt2"), "{props}");
    assert_eq!(
        client(conf, &["get", "pyjail", "action", "pyact", "opt1"]),
        "value"
    );
    assert_eq!(
        client(conf, &["get", "pyjail", "action", "pyact", "opt2"]),
        "None"
    );

    let meths = client(conf, &["get", "pyjail", "actionmethods", "pyact"]);
    for expected in ["ban", "reban", "start", "stop", "testmethod", "unban"] {
        assert!(meths.contains(expected), "{meths}");
    }
    assert_eq!(
        client(
            conf,
            &[
                "set",
                "pyjail",
                "action",
                "pyact",
                "testmethod",
                r#"{"text": "world!"}"#
            ]
        ),
        "Hello world! value"
    );
    assert_eq!(
        client(
            conf,
            &["set", "pyjail", "action", "pyact", "opt1", "another value"]
        ),
        "another value"
    );
    assert_eq!(
        client(
            conf,
            &[
                "set",
                "pyjail",
                "action",
                "pyact",
                "testmethod",
                r#"{"text": "world!"}"#
            ]
        ),
        "Hello world! another value"
    );

    // Ban triggers Python ActionInfo stats + isolated aInfo mutation
    assert_eq!(
        client(conf, &["set", "pyjail", "banip", "198.51.100.42"]),
        "1"
    );

    // Reload keeps non-reloadable Python actions active and preserves live runtime state
    client(conf, &["reload"]);
    let actions_after_reload = client(conf, &["get", "pyjail", "actions"]);
    assert!(
        actions_after_reload.contains("pyact")
            && actions_after_reload.contains("checkinfo")
            && actions_after_reload.contains("modinfo"),
        "actions after reload: {actions_after_reload}"
    );
    assert_eq!(
        client(conf, &["get", "pyjail", "action", "pyact", "opt1"]),
        "another value"
    );
    assert_eq!(
        client(
            conf,
            &[
                "set",
                "pyjail",
                "action",
                "pyact",
                "testmethod",
                r#"{"text": "still-live"}"#
            ]
        ),
        "Hello still-live another value"
    );

    // Unban --all invokes failing flush() on modinfo and falls back to individual unban()
    assert_eq!(client(conf, &["unban", "--all"]), "1");
    client(conf, &["stop"]);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(exit) = server.0.try_wait().unwrap() {
            assert!(exit.success(), "server exited with {exit}");
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let logs = fs::read_to_string(&log_file).unwrap();
    assert!(
        logs.contains("jail info 1, 1, 0, 0"),
        "expected ActionInfo jail stats in logs:\n{logs}"
    );
    assert!(
        logs.contains("modinfo ban deleted aInfo IP"),
        "expected modinfo ban log:\n{logs}"
    );
    assert!(
        logs.contains("modinfo unban deleted aInfo IP"),
        "expected flush fallback to individual unban:\n{logs}"
    );
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

    // 4a. Explicit unban when actionunban fails propagates error and retains 192.0.2.88
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("set"),
            s("healthy"),
            s("unbanip"),
            s("192.0.2.88")
        ]))
        .await
        .is_err()
    );
    let still_banned = tr
        .dispatch(&PickleValue::List(vec![s("get"), s("healthy"), s("banip")]))
        .await
        .unwrap();
    assert_eq!(
        still_banned,
        PickleValue::List(vec![s("192.0.2.88")]),
        "failed unban must retain ticket in ban_manager"
    );

    // Allow unban to succeed for subsequent tests
    fs::write(&unban_flag, "ok").unwrap();

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

    // 4c. Replacing `fw1` with `fw2` on reload starts `fw2` and replays 192.0.2.88 before retiring `fw1`
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
        replace_action_stream,
    ]))
    .await
    .unwrap();

    let order_lines: Vec<String> = fs::read_to_string(&act_order_log)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let fw2_start_pos = order_lines.iter().position(|l| l == "fw2:start").unwrap();
    let fw2_ban_pos = order_lines
        .iter()
        .position(|l| l == "fw2:ban:192.0.2.88")
        .unwrap();
    let fw1_unban_pos = order_lines
        .iter()
        .position(|l| l == "fw1:unban:192.0.2.88")
        .unwrap();
    let fw1_stop_pos = order_lines.iter().position(|l| l == "fw1:stop").unwrap();
    assert!(
        fw2_start_pos < fw2_ban_pos && fw2_ban_pos < fw1_unban_pos && fw1_unban_pos < fw1_stop_pos,
        "unexpected action handoff order: {order_lines:?}"
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

    // 1a. Replacement action whose replay ban fails must NOT retire fw1 and must return Err.
    let fail_replay_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![s("set"), s("svc"), s("addaction"), s("fw_bad")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_bad"),
            s("actionstart"),
            s(&format!("echo fw_bad:start >> '{}'", order_log.display())),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_bad"),
            s("actionban"),
            s("false"),
        ]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_bad"),
            s("actionstop"),
            s(&format!("echo fw_bad:stop >> '{}'", order_log.display())),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    assert!(
        tr.dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            fail_replay_stream
        ]))
        .await
        .is_err(),
        "failed replay on replacement action must fail reload"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("fw1")]),
        "fw1 must remain active after failed replacement replay"
    );
    let log_after_fail = fs::read_to_string(&order_log).unwrap();
    assert!(
        !log_after_fail.contains("fw1:unban") && !log_after_fail.contains("fw1:stop"),
        "fw1 must not be unbanned or stopped when replacement fails:\n{log_after_fail}"
    );

    // 1b. Replacement sharing firewall cleanup command with fw1 requires reload --restart.
    let shared_fw_stream = PickleValue::List(vec![
        PickleValue::List(vec![s("add"), s("svc"), s("polling")]),
        PickleValue::List(vec![s("set"), s("svc"), s("addaction"), s("fw_shared")]),
        PickleValue::List(vec![
            s("set"),
            s("svc"),
            s("action"),
            s("fw_shared"),
            s("actionunban"),
            s(&format!("echo fw1:unban:<ip> >> '{}'", order_log.display())),
        ]),
        PickleValue::List(vec![s("start"), s("svc")]),
    ]);
    let shared_err = tr
        .dispatch(&PickleValue::List(vec![
            s("reload"),
            s("--all"),
            PickleValue::List(vec![]),
            shared_fw_stream,
        ]))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        shared_err.contains("reload --restart"),
        "expected reload --restart error, got: {shared_err}"
    );
    assert_eq!(
        tr.dispatch(&PickleValue::List(vec![s("get"), s("svc"), s("actions")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("fw1")])
    );

    // 1c. Failed backend switch (polling -> systemd with failing Python action import) leaves old jail live.
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
    let _ = tr.dispatch(&PickleValue::List(vec![s("stop")])).await;

    // 2. Partial unban retry skips already-succeeded actions; bulk unban retains DB + ticket on error.
    let unban_db_path = dir.path().join("unban.sqlite3");
    let once_marker = dir.path().join("fw_once_deleted");
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
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_flaky"),
        s("actionunban"),
        s(&format!("test -f '{}'", flaky_ok.display())),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("addaction"),
        s("fw_once"),
    ]))
    .await
    .unwrap();
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_once"),
        s("actionban"),
        s("true"),
    ]))
    .await
    .unwrap();
    // Fails if invoked a second time (like `nft delete element` on an already-removed element).
    tr2.dispatch(&PickleValue::List(vec![
        s("set"),
        s("multi"),
        s("action"),
        s("fw_once"),
        s("actionunban"),
        s(&format!(
            "test ! -f '{0}' && touch '{0}'",
            once_marker.display()
        )),
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
    ]))
    .await
    .unwrap();

    // Bulk `unban --all` fails because fw_flaky fails while fw_once succeeds -> ticket & DB row retained!
    assert!(
        tr2.dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
            .await
            .is_err(),
        "bulk unban must return error when any action fails"
    );
    assert!(once_marker.exists(), "fw_once must have run once");
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![s("get"), s("multi"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![s("192.0.2.80")]),
        "ticket must remain banned after failed bulk unban"
    );
    {
        let check_db = Fail2BanDb::open(unban_db_path.to_str().unwrap(), 86_400, 10).unwrap();
        let active = check_db
            .get_current_bans(Some("multi"), None, None, current_unix_seconds() as i64)
            .unwrap();
        assert_eq!(
            active.len(),
            1,
            "SQLite ban row must be retained when bulk unban fails"
        );
    }

    // Now allow fw_flaky to succeed: retry must NOT re-run fw_once (which would fail!) and must clear the ban.
    fs::write(&flaky_ok, "ok").unwrap();
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![s("unban"), s("--all")]))
            .await
            .unwrap(),
        PickleValue::Int(1),
        "retry must skip already-succeeded fw_once and succeed via fw_flaky"
    );
    assert_eq!(
        tr2.dispatch(&PickleValue::List(vec![s("get"), s("multi"), s("banip")]))
            .await
            .unwrap(),
        PickleValue::List(vec![])
    );
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

    // 8. Non-reloadable Python action with changed init options on a live jail requires `reload --restart`
    //    and leaves the running action intact on plain `reload`.
    if let Some(upstream) = upstream_source() {
        let py_act_path = upstream
            .join("fail2ban/tests/files/action.d/action.py")
            .to_string_lossy()
            .into_owned();
        let mut tr_py = Transmitter::default();
        tr_py
            .dispatch(&PickleValue::List(vec![s("add"), s("pyj"), s("polling")]))
            .await
            .unwrap();
        tr_py
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("pyj"),
                s("addaction"),
                s("pyact"),
                s(&py_act_path),
                s(r#"{"opt1":"v1"}"#),
            ]))
            .await
            .unwrap();
        tr_py
            .dispatch(&PickleValue::List(vec![s("start"), s("pyj")]))
            .await
            .unwrap();
        tr_py
            .dispatch(&PickleValue::List(vec![
                s("set"),
                s("pyj"),
                s("banip"),
                s("192.0.2.91"),
            ]))
            .await
            .unwrap();
        let py_change_stream = PickleValue::List(vec![
            PickleValue::List(vec![s("add"), s("pyj"), s("polling")]),
            PickleValue::List(vec![
                s("set"),
                s("pyj"),
                s("addaction"),
                s("pyact"),
                s(&py_act_path),
                s(r#"{"opt1":"v2"}"#),
            ]),
            PickleValue::List(vec![s("start"), s("pyj")]),
        ]);
        let err = tr_py
            .dispatch(&PickleValue::List(vec![
                s("reload"),
                s("--all"),
                PickleValue::List(vec![]),
                py_change_stream,
            ]))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("reload --restart"),
            "changing non-reloadable Python action options must require reload --restart: {err}"
        );
        assert_eq!(
            tr_py
                .dispatch(&PickleValue::List(vec![
                    s("get"),
                    s("pyj"),
                    s("action"),
                    s("pyact"),
                    s("opt1")
                ]))
                .await
                .unwrap(),
            s("v1"),
            "original Python action instance must remain active"
        );
        assert_eq!(
            tr_py
                .dispatch(&PickleValue::List(vec![s("get"), s("pyj"), s("banip")]))
                .await
                .unwrap(),
            PickleValue::List(vec![s("192.0.2.91")])
        );
        let _ = tr_py.dispatch(&PickleValue::List(vec![s("stop")])).await;
    }
}
