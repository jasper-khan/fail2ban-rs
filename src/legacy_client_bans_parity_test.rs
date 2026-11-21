//! Offline original client + ban-query parity; the transport stays in memory.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;

use crate::legacy_client::{ClientError, ClientReply, ClientRequest, ServerError, dispatch};
use crate::legacy_client_bans::{self, ActiveBan, JailBans, UnknownJail};

type Snapshot = (&'static str, &'static [(&'static str, Option<i64>)]);

const SNAPSHOT: &[Snapshot] = &[
    (
        "z-auth",
        &[
            ("198.51.100.5", None),
            ("192.0.2.20", Some(140)),
            ("2001:db8::10", Some(120)),
            ("192.0.2.10", Some(140)),
        ],
    ),
    ("empty", &[]),
    (
        "a-ssh",
        &[("192.0.2.20", Some(180)), ("2001:db8::20", None)],
    ),
];

const UNKNOWN: &str = "Sorry but the jail 'missing' does not exist\n";
const UNKNOWN_DIAGNOSTIC: &str = "NOK: ('missing',)\n";
type Case = (&'static [&'static str], &'static str, &'static str, u8);

const CASES: &[Case] = &[
    (
        &["get", "z-auth", "banip"],
        "2001:db8::10 192.0.2.20 192.0.2.10 198.51.100.5\n",
        "",
        0,
    ),
    (
        &["get", "z-auth", "banip", ""],
        "2001:db8::10192.0.2.20192.0.2.10198.51.100.5\n",
        "",
        0,
    ),
    (
        &["get", "z-auth", "banip", " \t "],
        "2001:db8::10 \t 192.0.2.20 \t 192.0.2.10 \t 198.51.100.5\n",
        "",
        0,
    ),
    (
        &["get", "z-auth", "banip", "\n"],
        "2001:db8::10\n192.0.2.20\n192.0.2.10\n198.51.100.5\n",
        "",
        0,
    ),
    (&["get", "empty", "banip", ","], "\n", "", 0),
    (
        &["get", "missing", "banip"],
        UNKNOWN,
        UNKNOWN_DIAGNOSTIC,
        255,
    ),
    (
        &["banned"],
        "[{'z-auth': ['198.51.100.5', '192.0.2.20', '2001:db8::10', '192.0.2.10']}, {'empty': []}, {'a-ssh': ['192.0.2.20', '2001:db8::20']}]\n",
        "",
        0,
    ),
    (&["banned", "192.0.2.20"], "[['z-auth', 'a-ssh']]\n", "", 0),
    (
        &[
            "banned",
            "192.0.2.20",
            "203.0.113.27",
            "192.0.2.20",
            "2001:db8::10",
        ],
        "[['z-auth', 'a-ssh'], [], ['z-auth', 'a-ssh'], ['z-auth']]\n",
        "",
        0,
    ),
    (
        &["get", "z-auth", "banned"],
        "['198.51.100.5', '192.0.2.20', '2001:db8::10', '192.0.2.10']\n",
        "",
        0,
    ),
    (&["get", "z-auth", "banned", "192.0.2.20"], "1\n", "", 0),
    (&["get", "z-auth", "banned", "203.0.113.27"], "0\n", "", 0),
    (
        &[
            "get",
            "z-auth",
            "banned",
            "192.0.2.20",
            "203.0.113.27",
            "2001:db8::10",
            "192.0.2.20",
        ],
        "[1, 0, 1, 1]\n",
        "",
        0,
    ),
    (&["get", "empty", "banned"], "[]\n", "", 0),
    (&["get", "empty", "banned", "192.0.2.20"], "0\n", "", 0),
    (
        &["get", "missing", "banned"],
        UNKNOWN,
        UNKNOWN_DIAGNOSTIC,
        255,
    ),
];

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Trace {
    stdout: String,
    stderr: String,
    exit_code: u8,
}

fn ip(address: &str) -> IpAddr {
    address.parse().expect("documentation address in fixture")
}

fn no_jail(error: UnknownJail) -> ClientError {
    ClientError::Server(ServerError::UnknownJail(error.0))
}

fn native(argv: &[&str]) -> Trace {
    let storage = SNAPSHOT
        .iter()
        .map(|(_, bans)| {
            bans.iter()
                .map(|(address, expires_at)| ActiveBan {
                    address: ip(address),
                    expires_at: *expires_at,
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let jails = SNAPSHOT
        .iter()
        .zip(&storage)
        .map(|((name, _), bans)| JailBans { name, bans })
        .collect::<Vec<_>>();
    let mut seen = false;
    let output = dispatch(argv, |request| {
        assert!(!seen);
        seen = true;
        match request {
            ClientRequest::GetBanIp { jail, separator } => {
                assert_eq!(Some(jail), argv.get(1).copied());
                assert_eq!(separator, argv.get(3).copied());
                legacy_client_bans::get_banip(&jails, jail)
                    .map(ClientReply::BanIps)
                    .map_err(no_jail)
            }
            ClientRequest::Banned { jail, ids } => {
                if argv.first() == Some(&"get") {
                    assert_eq!(jail, argv.get(1).copied());
                    assert_eq!(Some(ids), argv.get(3..));
                } else {
                    assert_eq!(jail, None);
                    assert_eq!(Some(ids), argv.get(1..));
                }
                let addrs = ids.iter().map(|address| ip(address)).collect::<Vec<_>>();
                legacy_client_bans::banned(&jails, jail, &addrs)
                    .map(ClientReply::Banned)
                    .map_err(no_jail)
            }
            _ => Err(ClientError::Transport(
                "unexpected request in ban-query fixture".to_owned(),
            )),
        }
    });
    assert!(seen, "confirmed query reaches one fake exchange");
    Trace {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
    }
}

fn golden(stdout: &str, stderr: &str, exit_code: u8) -> Trace {
    Trace {
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        exit_code,
    }
}

#[test]
fn legacy_client_ban_queries_match_golden() {
    for &(argv, stdout, stderr, code) in CASES {
        assert_eq!(native(argv), golden(stdout, stderr, code), "{argv:?}");
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_client_ban_queries_agree_with_fail2ban_111() {
    let source = pinned_source();
    let original = oracle(&source);
    assert_eq!(original.len(), CASES.len());
    for (&(argv, stdout, stderr, code), observed) in CASES.iter().zip(original) {
        assert_eq!(observed, golden(stdout, stderr, code), "original {argv:?}");
        assert_eq!(native(argv), observed, "Rust {argv:?}");
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

fn oracle(source: &Path) -> Vec<Trace> {
    const ORACLE: &str = r"
import contextlib
import io
import json
import logging
import pickle
import socket
import sys
from types import SimpleNamespace

def blocked(*args, **kwargs):
    raise AssertionError('unexpected real I/O or state action')
def audit(event, args):
    if event.startswith('socket.') or event.startswith('pickle.') or event in (
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'
    ):
        blocked()
sys.addaudithook(audit)

source, input = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client import csocket, fail2bancmdline, fail2banclient as client
from fail2ban.client.configurator import Configurator
from fail2ban.server import transmitter
from fail2ban.server.actions import Actions
from fail2ban.server.banmanager import BanManager
from fail2ban.server.ipdns import IPAddr
from fail2ban.server.jail import Jail
from fail2ban.server.jails import Jails
from fail2ban.server.mytime import MyTime
from fail2ban.server.server import Server
from fail2ban.server.ticket import BanTicket
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version
Configurator.readEarly = blocked
socket.socket = blocked
pickle.loads = pickle.dumps = blocked
csocket.loads = csocket.dumps = blocked
Utils.executeCmd = blocked
Server.start = Jail.start = Actions.start = blocked

snapshot, cases = json.loads(input)
now = 100
MyTime.setTime(now)
server = Server.__new__(Server)
jails = Jails()
server._Server__jails = jails
for name, bans in snapshot:
    actions = Actions.__new__(Actions)
    actions.banManager = BanManager()
    for address, end in bans:
        ticket = BanTicket(IPAddr(address), now)
        ticket.setBanTime(-1 if end is None else end - now)
        assert actions.banManager.addBanTicket(ticket, {})
    jails._jails[name] = SimpleNamespace(name=name, actions=actions)
query = transmitter.Transmitter(server)
# In production the server's logs are separate from the client's stderr.
transmitter.logSys.disabled = True

def typed_values(value):
    # IPAddr serializes as its canonical string upstream. Project typed
    # in-memory values without calling the serialization machinery.
    if isinstance(value, IPAddr):
        return str(value)
    if isinstance(value, list):
        return [typed_values(item) for item in value]
    if isinstance(value, dict):
        return {key: typed_values(item) for key, item in value.items()}
    return value

# Capture diagnostic messages without time/PID prefixes.
fail2bancmdline.PRODUCTION = False
log = client.logSys
log.setLevel(logging.WARNING)
log.propagate = False
path = '/offline/synthetic-never-connect.sock'
result = []
for argv in cases:
    operations = []
    class FakeSocket:
        def __init__(self, filename, timeout=-1):
            assert filename == path and timeout == -1
            operations.append(('constructor',))
        def send(self, words):
            operations.append(('send', words))
            assert words == argv
            assert words[0] == 'banned' or (
                words[0] == 'get' and words[2] in ('banip', 'banned')
            )
            assert '--with-time' not in words
            status, value = query.proceed(words)
            return status, typed_values(value) if status == 0 else value
        def close(self):
            operations.append(('close',))
    client.CSocket = FakeSocket
    out, err = io.StringIO(), io.StringIO()
    handler = logging.StreamHandler(err)
    handler.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(handler)
    try:
        with contextlib.redirect_stdout(out):
            client.exec_command_line([
                'fail2ban-client', '-s', path, '-p', '/offline/synthetic.pid',
                '--logtarget=STDERR', '--loglevel=INFO', '--syslogsocket=auto',
            ] + argv)
    except SystemExit as exit:
        result.append({'stdout': out.getvalue(), 'stderr': err.getvalue(), 'exit_code': exit.code})
    else:
        raise AssertionError('expected original exit')
    finally:
        log.removeHandler(handler)
    assert operations == [('constructor',), ('send', argv), ('close',)], operations
print(json.dumps(result))
";
    let cases = CASES.iter().map(|(argv, _, _, _)| argv).collect::<Vec<_>>();
    let scratch = tempdir().expect("temporary oracle directory");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(serde_json::to_string(&json!([SNAPSHOT, cases])).expect("fixtures serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original fake ban queries");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
