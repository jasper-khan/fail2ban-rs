//! Original client command parity over a typed, in-memory fake only.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;

use crate::legacy_client::{
    ClientError, ClientReply, ClientRequest, ServerError, StatusTarget, dispatch,
};
use crate::legacy_client_render::{JailStatus, StatusSource};

const MISSING: &str =
    "Failed to access socket path: /offline/synthetic-never-connect.sock. Is fail2ban running?";
const FILE_BODY: &str = concat!(
    "Status for the jail: sshd\n",
    "|- Filter\n",
    "|  |- Currently failed:\t2\n",
    "|  |- Total failed:\t7\n",
    "|  `- File list:\t/synthetic/auth.log /synthetic/extra.log\n",
    "`- Actions\n",
    "   |- Currently banned:\t2\n",
    "   |- Total banned:\t5\n",
    "   `- Banned IP list:\t192.0.2.4 2001:db8::2\n",
);
const SHORT_BODY: &str = concat!(
    "Status for the jail: sshd\n",
    "|- Filter\n",
    "|  |- Currently failed:\t2\n",
    "|  |- Total failed:\t7\n",
    "|  `- File list:\t/synthetic/auth.log /synthetic/extra.log\n",
    "`- Actions\n",
    "   |- Currently banned:\t2\n",
    "   `- Total banned:\t5\n",
);

#[derive(Clone, Copy)]
enum Fake {
    Pong,
    Global,
    Empty,
    File,
    Journal,
    Short,
    UnknownJail,
    Invalid,
    Generic,
    NoSocket,
}

impl Fake {
    const fn code(self) -> &'static str {
        match self {
            Self::Pong => "pong",
            Self::Global => "global",
            Self::Empty => "empty",
            Self::File => "file",
            Self::Journal => "journal",
            Self::Short => "short",
            Self::UnknownJail => "unknown",
            Self::Invalid => "invalid",
            Self::Generic => "generic",
            Self::NoSocket => "no_socket",
        }
    }

    fn reply(self) -> Result<ClientReply, ClientError> {
        match self {
            Self::Pong => Ok(ClientReply::Pong("pong".to_owned())),
            Self::Global => Ok(ClientReply::GlobalStatus(vec![
                "auth".to_owned(),
                "sshd".to_owned(),
            ])),
            Self::Empty => Ok(ClientReply::GlobalStatus(vec![])),
            Self::File | Self::Short => Ok(ClientReply::JailStatus(JailStatus {
                name: "sshd".to_owned(),
                currently_failed: 2,
                total_failed: 7,
                source: StatusSource::Files(vec![
                    "/synthetic/auth.log".to_owned(),
                    "/synthetic/extra.log".to_owned(),
                ]),
                currently_banned: 2,
                total_banned: 5,
                banned_ips: vec!["192.0.2.4".to_owned(), "2001:db8::2".to_owned()],
            })),
            Self::Journal => Ok(ClientReply::JailStatus(JailStatus {
                name: "sshd".to_owned(),
                currently_failed: 0,
                total_failed: 3,
                source: StatusSource::JournalMatches(vec![
                    vec!["_SYSTEMD_UNIT=sshd.service".to_owned()],
                    vec!["_COMM=sshd".to_owned()],
                ]),
                currently_banned: 0,
                total_banned: 1,
                banned_ips: vec![],
            })),
            Self::UnknownJail => Err(ClientError::Server(ServerError::UnknownJail(
                "unknown".to_owned(),
            ))),
            Self::Invalid => Err(ClientError::Server(ServerError::InvalidCommand(
                "bad fixture command".to_owned(),
            ))),
            Self::Generic => Err(ClientError::Server(ServerError::Message(
                "not available".to_owned(),
            ))),
            Self::NoSocket => Err(ClientError::Transport(MISSING.to_owned())),
        }
    }
}

type Case = (
    &'static [&'static str],
    Fake,
    &'static str,
    &'static str,
    u8,
);

const CASES: &[Case] = &[
    (&["ping"], Fake::Pong, "Server replied: pong\n", "", 0),
    (
        &["ping", "0.5"],
        Fake::Pong,
        "Server replied: pong\n",
        "",
        0,
    ),
    (
        &["status"],
        Fake::Global,
        "Status\n|- Number of jail:\t2\n`- Jail list:\tauth, sshd\n",
        "",
        0,
    ),
    (
        &["status"],
        Fake::Empty,
        "Status\n|- Number of jail:\t0\n`- Jail list:\t\n",
        "",
        0,
    ),
    (&["status", "sshd"], Fake::File, FILE_BODY, "", 0),
    (
        &["status", "sshd", "basic"],
        Fake::Journal,
        concat!(
            "Status for the jail: sshd\n",
            "|- Filter\n",
            "|  |- Currently failed:\t0\n",
            "|  |- Total failed:\t3\n",
            "|  `- Journal matches:\t_SYSTEMD_UNIT=sshd.service + _COMM=sshd\n",
            "`- Actions\n",
            "   |- Currently banned:\t0\n",
            "   |- Total banned:\t1\n",
            "   `- Banned IP list:\t\n",
        ),
        "",
        0,
    ),
    (&["status", "sshd", "short"], Fake::Short, SHORT_BODY, "", 0),
    (
        &["status", "unknown"],
        Fake::UnknownJail,
        "Sorry but the jail 'unknown' does not exist\n",
        "NOK: ('unknown',)\n",
        255,
    ),
    (
        &["status", "sshd"],
        Fake::Invalid,
        "Sorry but the command is invalid\n",
        "NOK: ('bad fixture command',)\n",
        255,
    ),
    (
        &["status"],
        Fake::Generic,
        "not available\n",
        "NOK: ('not available',)\n",
        255,
    ),
    (
        &["ping"],
        Fake::NoSocket,
        "",
        "Failed to access socket path: /offline/synthetic-never-connect.sock. Is fail2ban running?\n",
        255,
    ),
];

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Trace {
    stdout: String,
    stderr: String,
    exit_code: u8,
}

fn native(argv: &[&str], fake: Fake) -> Trace {
    let mut seen = false;
    let output = dispatch(argv, |request| {
        assert!(!seen);
        seen = true;
        match request {
            ClientRequest::Ping { argument, timeout } => {
                assert_eq!(argv.first(), Some(&"ping"));
                assert_eq!(argument, argv.get(1).copied());
                assert_eq!(
                    timeout,
                    argv.get(1).map(|arg| arg.parse().expect("fixture timeout"))
                );
            }
            ClientRequest::Status(StatusTarget::Global) => assert_eq!(argv, ["status"]),
            ClientRequest::Status(StatusTarget::Jail { name, flavor }) => {
                assert_eq!(argv.first(), Some(&"status"));
                assert_eq!(Some(name), argv.get(1).copied());
                assert_eq!(flavor, argv.get(2).copied());
            }
            ClientRequest::Status(StatusTarget::All { .. }) => {
                assert_eq!(argv.get(1), Some(&"--all"));
            }
            ClientRequest::GetBanIp { .. } | ClientRequest::Banned { .. } => {
                assert!(matches!(argv.first(), Some(&"get" | &"banned")));
            }
        }
        fake.reply()
    });
    assert!(seen, "every confirmed command reaches only the fake");
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
fn legacy_client_basic_commands_match_golden() {
    for &(argv, fake, stdout, stderr, code) in CASES {
        assert_eq!(native(argv, fake), golden(stdout, stderr, code), "{argv:?}");
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_client_basic_commands_agree_with_fail2ban_111() {
    let source = pinned_source();
    let original = oracle(&source);
    assert_eq!(original.len(), CASES.len());
    for (&(argv, fake, stdout, stderr, code), observed) in CASES.iter().zip(original) {
        assert_eq!(observed, golden(stdout, stderr, code), "original {argv:?}");
        assert_eq!(native(argv, fake), observed, "Rust {argv:?}");
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
import errno
import io
import json
import logging
import os
import pickle
import socket
import sys

def blocked(*args, **kwargs):
    raise AssertionError('unexpected real client I/O')
def audit(event, args):
    if event.startswith('socket.') or event.startswith('pickle.') or event in (
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'
    ):
        blocked()
sys.addaudithook(audit)

source, cases = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client import csocket, fail2bancmdline, fail2banclient as client
from fail2ban.client.configurator import Configurator
from fail2ban.exceptions import UnknownJailException
from fail2ban.version import version
assert version == '1.1.1', version
Configurator.readEarly = blocked
socket.socket = blocked
pickle.loads = pickle.dumps = blocked
csocket.loads = csocket.dumps = blocked

file_filter = ('Filter', [('Currently failed', 2), ('Total failed', 7),
                         ('File list', ['/synthetic/auth.log', '/synthetic/extra.log'])])
file_actions = [('Currently banned', 2), ('Total banned', 5),
                ('Banned IP list', ['192.0.2.4', '2001:db8::2'])]
journal_filter = ('Filter', [('Currently failed', 0), ('Total failed', 3),
                            ('Journal matches', ['_SYSTEMD_UNIT=sshd.service + _COMM=sshd'])])
journal_actions = [('Currently banned', 0), ('Total banned', 1), ('Banned IP list', [])]
success = {
    'pong': 'pong',
    'global': [('Number of jail', 2), ('Jail list', 'auth, sshd')],
    'empty': [('Number of jail', 0), ('Jail list', '')],
    'file': [file_filter, ('Actions', file_actions)],
    'journal': [journal_filter, ('Actions', journal_actions)],
    'short': [file_filter, ('Actions', file_actions[:2])],
}
errors = {
    'unknown': UnknownJailException('unknown'),
    'invalid': IndexError('bad fixture command'),
    'generic': RuntimeError('not available'),
}

path = '/offline/synthetic-never-connect.sock'
def fake_access(name, mode):
    assert name == path and mode == os.F_OK, (name, mode)
    return False
client.os.access = fake_access

# Compare diagnostic message text, not default log formatter time/PID.
fail2bancmdline.PRODUCTION = False
log = client.logSys
log.setLevel(logging.WARNING)
log.propagate = False
result = []
for argv, kind in json.loads(cases):
    operations = []
    class FakeSocket:
        def __init__(self, filename, timeout=-1):
            assert filename == path
            operations.append(('constructor', timeout))
            if kind == 'no_socket':
                raise OSError(errno.ENOENT, 'fake socket is missing')
        def send(self, words):
            operations.append(('send', words))
            if kind in errors:
                return 1, errors[kind]
            return 0, success[kind]
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
    timeout = float(argv[1]) if argv[0] == 'ping' and len(argv) > 1 else -1
    expected = [('constructor', timeout)]
    if kind != 'no_socket':
        expected.extend([('send', argv), ('close',)])
    assert operations == expected, (operations, expected)
print(json.dumps(result))
";
    let cases = CASES
        .iter()
        .map(|(argv, fake, _, _, _)| json!([argv, fake.code()]))
        .collect::<Vec<_>>();
    let scratch = tempdir().expect("temporary oracle directory");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(serde_json::to_string(&cases).expect("fixtures serialize"))
        .current_dir(scratch.path())
        .output()
        .expect("run original client with fake transport");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
