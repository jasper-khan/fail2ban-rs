//! Original config-to-log-to-decision replay using only synthetic inputs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use tempfile::{TempDir, tempdir};

use crate::legacy_jail_replay::{ReplayDecision, ReplayStep, replay};

const JAIL: &str = "web-auth";
const MIDNIGHT: i64 = 1_752_537_600; // 2025-07-15 00:00:00 UTC
const MAIN: &str = r"
[DEFAULT]
findtime = 10s
maxretry = 3
bantime = 30s

[web-auth]
enabled = true
backend = polling
usedns = no
ignoreself = false
ignoreip = 192.0.2.0/28
logtimezone = UTC
logpath = /offline/synthetic-nginx-error.log
filter = nginx-http-auth[mode=normal]
action =
";
const OVERLAY: &str = r"
[web-auth]
filter = nginx-http-auth[mode=aggressive]
maxretry = 2
bantime = 5s
";

const STEPS: &[ReplayStep<'static>] = &[
    ReplayStep::Line {
        line: r#"2025/07/14 23:59:50 [error] 123#123: *1 user "example-user": password mismatch, client: 192.0.2.5"#,
        observed_at: MIDNIGHT - 10,
    },
    ReplayStep::Line {
        line: r#"2025/07/14 23:59:51 [error] 123#123: *2 user "example-user": password mismatch, client: 192.0.2.5"#,
        observed_at: MIDNIGHT - 9,
    },
    ReplayStep::Line {
        line: r#"2025/07/14 23:59:52 [error] 123#123: *3 user "example-user": password mismatch, client: 192.0.2.20, server: 203.0.113.80"#,
        observed_at: MIDNIGHT - 8,
    },
    ReplayStep::Line {
        line: r#"2025/07/14 23:59:53 [error] 123#123: *4 open() "/srv/example/missing" failed (2: No such file or directory), client: 192.0.2.20"#,
        observed_at: MIDNIGHT - 7,
    },
    ReplayStep::Line {
        line: "2025/07/14 23:59:54 [crit] 123#123: *5 SSL_do_handshake() failed (SSL: error:0A000102:SSL routines::unsupported protocol) while SSL handshaking, client: 192.0.2.20",
        observed_at: MIDNIGHT - 6,
    },
    ReplayStep::Expire { now: MIDNIGHT - 2 },
    ReplayStep::Expire { now: MIDNIGHT - 1 },
    ReplayStep::Expire { now: MIDNIGHT },
    ReplayStep::Line {
        line: r#"2025/07/15 00:00:01 [error] 123#123: *6 user "example-user": password mismatch, client: 2001:db8::12"#,
        observed_at: MIDNIGHT + 1,
    },
    ReplayStep::Line {
        line: r#"2025/07/15 00:00:21 [error] 123#123: *7 user "example-user": password mismatch, client: 2001:db8::12"#,
        observed_at: MIDNIGHT + 21,
    },
    ReplayStep::Line {
        line: "2025/07/15 00:00:22 [crit] 123#123: *8 PAM: user 'example-user' - not authenticated: Authentication failure, client: 2001:db8::12",
        observed_at: MIDNIGHT + 22,
    },
    ReplayStep::Expire { now: MIDNIGHT + 27 },
    ReplayStep::Expire { now: MIDNIGHT + 28 },
];

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Record(String, String, i64);

fn golden() -> Vec<Record> {
    [
        ("ban", "192.0.2.20", MIDNIGHT - 6),
        ("unban", "192.0.2.20", MIDNIGHT),
        ("ban", "2001:db8::12", MIDNIGHT + 22),
        ("unban", "2001:db8::12", MIDNIGHT + 28),
    ]
    .into_iter()
    .map(|(state, ip, time)| Record(state.to_owned(), ip.to_owned(), time))
    .collect()
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_jail_replay_agrees_with_fail2ban_111() {
    let source = pinned_source();
    let config = fixture(&source);
    let original = oracle(&source, config.path());
    assert_eq!(original, golden(), "original replay decision stream");
    let ours = replay(config.path(), JAIL, STEPS).expect("admitted offline replay");
    let ours = ours
        .into_iter()
        .map(|event| match event {
            ReplayDecision::Ban { ip, at } => Record("ban".to_owned(), ip.to_string(), at),
            ReplayDecision::Unban { ip, at } => Record("unban".to_owned(), ip.to_string(), at),
        })
        .collect::<Vec<_>>();
    assert_eq!(ours, original);
}

fn fixture(source: &Path) -> TempDir {
    let root = tempdir().expect("isolated replay config");
    let overlays = root.path().join("jail.d");
    let filters = root.path().join("filter.d");
    fs::create_dir(&overlays).expect("synthetic jail overlays directory");
    fs::create_dir(&filters).expect("synthetic filter directory");
    fs::write(root.path().join("jail.conf"), MAIN).expect("write synthetic jail");
    fs::write(overlays.join("20-replay.local"), OVERLAY).expect("write synthetic overlay");
    for basename in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config").join("filter.d").join(basename),
            filters.join(basename),
        )
        .expect("copy pinned filter into isolated temporary config");
    }
    root
}

fn pinned_source() -> PathBuf {
    let source =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
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
        "use unmodified Python source and stock filters: {status}"
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

fn oracle(source: &Path, base: &Path) -> Vec<Record> {
    const ORACLE: &str = r"
import json
import os
import socket
import subprocess
import sys

def blocked(*args, **kwargs):
    raise AssertionError('unexpected real I/O or state action')
def audit(event, args):
    if event.startswith('socket.') or event in (
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'
    ):
        blocked()
sys.addaudithook(audit)
subprocess.Popen = blocked
os.system = blocked

source, base, jail_name, steps = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client.jailreader import JailReader
from fail2ban.server.actions import Actions
from fail2ban.server.banmanager import BanManager
from fail2ban.server.filter import Filter
from fail2ban.server.jail import Jail
from fail2ban.server.mytime import MyTime
from fail2ban.server.server import Server
from fail2ban.server.ticket import BanTicket, FailTicket
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version
Utils.executeCmd = blocked
socket.socket = blocked
Server.start = Jail.start = Actions.start = blocked

# Read the actual sandbox config without converting logpath to a file/journal
# stream; the test deliberately owns only supplied lines, not a log backend.
cfg = JailReader(jail_name, basedir=base)
assert cfg.read()
assert cfg.getOptions()
assert cfg.isEnabled()
jail = cfg.options
assert jail['backend'] == 'polling'
assert jail['action'] == '' and not jail.get('ignorecommand')
assert jail['logtimezone'] == 'UTC' and jail['usedns'] == 'no'
assert jail['ignoreself'] is False and jail['ignoreip'] == '192.0.2.0/28'
assert jail['maxretry'] == 2 and jail['findtime'] == '10s' and jail['bantime'] == '5s'
assert jail['filter'] == 'nginx-http-auth[mode=aggressive]'
options = cfg.filter.getCombined()
assert options['mode'] == 'aggressive'

filter = Filter(None, useDns=jail['usedns'])
filter.active = True
filter.checkFindTime = True
filter.inOperation = True
filter.ignoreSelf = jail['ignoreself']
filter.addIgnoreIP(jail['ignoreip'])
filter.setLogTimeZone(jail['logtimezone'])
filter.setFindTime(jail['findtime'])
filter.setMaxRetry(jail['maxretry'])
filter.prefRegex = options['prefregex']
filter.setDatePattern(options['datepattern'])
if options.get('maxlines') is not None:
    filter.setMaxLines(options['maxlines'])
for rule in (options.get('failregex') or '').splitlines():
    if rule:
        filter.addFailRegex(rule)
for rule in (options.get('ignoreregex') or '').splitlines():
    if rule:
        filter.addIgnoreRegex(rule)
bans = BanManager()
bans.setBanTime(MyTime.str2seconds(jail['bantime']))

# Model the immediate ordinary threshold→ban consumption using the
# original in-memory filter and managers, never queue or invoke actions.
results = []
for line, now in json.loads(steps):
    MyTime.setTime(now)
    if line is None:
        for ban in bans.unBanList(now):
            results.append(['unban', str(ban.getID()), now])
        continue
    for _, ip, timestamp, data in filter.processLine(line):
        assert timestamp == now and not data.get('nofail')
        attempt = FailTicket(ip, timestamp, data=data)
        if filter.inIgnoreIPList(attempt, log_ignore=False):
            continue
        retry = filter.failManager.addFailure(attempt)
        if retry >= filter.getMaxRetry():
            ban = BanTicket.wrap(filter.failManager.toBan(ip))
            if bans.addBanTicket(ban, {}):
                results.append(['ban', str(ban.getID()), now])
print(json.dumps(results))
";
    let steps = STEPS
        .iter()
        .map(|step| match step {
            ReplayStep::Line { line, observed_at } => json!([line, observed_at]),
            ReplayStep::Expire { now } => json!([null, now]),
        })
        .collect::<Vec<_>>();
    let scratch = tempdir().expect("temporary oracle cwd");
    let output = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(base)
        .arg(JAIL)
        .arg(serde_json::to_string(&steps).expect("fixtures serialize"))
        .env("TZ", "UTC")
        .current_dir(scratch.path())
        .output()
        .expect("execute original offline replay oracle");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
