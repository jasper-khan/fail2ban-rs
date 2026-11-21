//! Actual Fail2Ban FileFilter phase transitions against named private fixtures.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use tempfile::{TempDir, tempdir};

use crate::config::legacy_jail_plan;
use crate::detect::legacy_file_cursor::StartAt;
use crate::detect::legacy_observation_time::FilePhase;
use crate::legacy_queued_file::QueuedFile;

const JAIL: &str = "web-auth";
const NOW: i64 = 1_752_537_600;
const CONFIG: &str = r"
[web-auth]
enabled = true
backend = polling
filter = nginx-http-auth[mode=normal]
usedns = no
ignoreself = false
logtimezone = UTC
logpath = /offline/synthetic-nginx-error.log
maxretry = 1
findtime = 10s
bantime = 5s
action =
";
const OLD: &str = r#"2025/07/14 23:57:00 [error] 123#123: *1 user "example-user": password mismatch, client: 192.0.2.20"#;
const FRESH: &str = r#"2025/07/15 00:00:00 [error] 123#123: *2 user "example-user": password mismatch, client: 2001:db8::12"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Label {
    Initial,
    Live,
}
use Label::{Initial, Live};

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct PhaseRead {
    phase: Label,
    offset: u64,
    lines: Vec<Observation>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Observation(u64, Label, bool);

struct Step {
    append: String,
    now: i64,
    expected: PhaseRead,
}

struct Scenario {
    name: &'static str,
    initial: String,
    steps: Vec<Step>,
}

fn lf(line: &str) -> String {
    format!("{line}\n")
}

fn bytes(line: &str) -> u64 {
    u64::try_from(line.len()).expect("short fixture byte offset")
}

fn step(append: String, now: i64, phase: Label, offset: u64, lines: Vec<Observation>) -> Step {
    Step {
        append,
        now,
        expected: PhaseRead {
            phase,
            offset,
            lines,
        },
    }
}

fn scenarios() -> Vec<Scenario> {
    let old = lf(OLD);
    let fresh = lf(FRESH);
    let old_end = bytes(&old);
    let fresh_end = bytes(&fresh);
    vec![
        Scenario {
            name: "an empty poll stays initial; a later stale line is not queued",
            initial: String::new(),
            steps: vec![
                step(String::new(), NOW, Initial, 0, vec![]),
                step(
                    old.clone(),
                    NOW,
                    Live,
                    old_end,
                    vec![Observation(old_end, Initial, false)],
                ),
                step(
                    old.clone(),
                    NOW + 1,
                    Live,
                    2 * old_end,
                    vec![Observation(2 * old_end, Live, true)],
                ),
                step(String::new(), NOW + 2, Live, 2 * old_end, vec![]),
            ],
        },
        Scenario {
            name: "a sole incomplete record flips live without committing bytes",
            initial: OLD.to_owned(),
            steps: vec![
                step(String::new(), NOW, Live, 0, vec![]),
                step(String::new(), NOW + 1, Live, 0, vec![]),
                step(
                    "\n".to_owned(),
                    NOW + 2,
                    Live,
                    old_end,
                    vec![Observation(old_end, Live, true)],
                ),
            ],
        },
        Scenario {
            name: "all records in the first batch remain initial until incomplete EOF",
            initial: format!("{old}{fresh}{OLD}"),
            steps: vec![
                step(
                    String::new(),
                    NOW,
                    Live,
                    old_end + fresh_end,
                    vec![
                        Observation(old_end, Initial, false),
                        Observation(old_end + fresh_end, Initial, true),
                    ],
                ),
                step(
                    "\n".to_owned(),
                    NOW + 1,
                    Live,
                    2 * old_end + fresh_end,
                    vec![Observation(2 * old_end + fresh_end, Live, true)],
                ),
            ],
        },
    ]
}

fn native(base: &Path, scenario: &Scenario) -> Vec<PhaseRead> {
    let dir = tempdir().expect("private Rust file scenario");
    let path = dir.path().join("original-format.log");
    fs::write(&path, &scenario.initial).expect("fixture bytes");
    let plan = legacy_jail_plan::read(base, JAIL).expect("admitted synthetic jail");
    let file = File::open(&path).expect("only the scenario file is opened");
    let mut replay = QueuedFile::new(plan, file, StartAt::Head).expect("open replay fixture");
    scenario
        .steps
        .iter()
        .map(|step| {
            if !step.append.is_empty() {
                OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .expect("fixture append handle")
                    .write_all(step.append.as_bytes())
                    .expect("append fixture bytes");
            }
            let mut lines = Vec::new();
            while let Some(record) = replay.poll_one(step.now).expect("read next replay record") {
                lines.push(Observation(
                    record.end_offset,
                    phase(record.phase),
                    record.queued,
                ));
                assert!(lines.len() <= 3, "scenario must reach its controlled EOF");
            }
            PhaseRead {
                phase: phase(replay.phase()),
                offset: replay.acknowledged_offset(),
                lines,
            }
        })
        .collect()
}

const fn phase(value: FilePhase) -> Label {
    match value {
        FilePhase::Initial => Initial,
        FilePhase::Live => Live,
    }
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn queued_file_phase_agrees_with_original_file_filter() {
    let source = pinned_source();
    let config = fixture(&source);
    let scenarios = scenarios();
    let payload = oracle(&source, config.path(), &scenarios);
    let original: Vec<Vec<PhaseRead>> = serde_json::from_slice(&payload).expect("oracle JSON");
    assert_eq!(original.len(), scenarios.len());
    for (scenario, observed) in scenarios.iter().zip(original) {
        let expected = scenario
            .steps
            .iter()
            .map(|p| &p.expected)
            .collect::<Vec<_>>();
        assert_eq!(
            observed.iter().collect::<Vec<_>>(),
            expected,
            "original: {}",
            scenario.name
        );
        assert_eq!(
            native(config.path(), scenario),
            observed,
            "Rust: {}",
            scenario.name
        );
    }
}

fn fixture(source: &Path) -> TempDir {
    let root = tempdir().expect("isolated synthetic configuration root");
    fs::write(root.path().join("jail.conf"), CONFIG).expect("write synthetic jail config");
    let filters = root.path().join("filter.d");
    fs::create_dir(&filters).expect("fixture filter directory");
    for basename in ["nginx-http-auth.conf", "nginx-error-common.conf"] {
        fs::copy(
            source.join("config").join("filter.d").join(basename),
            filters.join(basename),
        )
        .expect("copy original checked fixture filter");
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
        "use unmodified Python source and stock config: {status}"
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

fn oracle(source: &Path, config: &Path, scenarios: &[Scenario]) -> Vec<u8> {
    const ORACLE: &str = r"
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

violations = []
def blocked(*args, **kwargs):
    violations.append('attempted forbidden process, thread, socket or service')
    raise AssertionError(violations[-1])
def audit(event, args):
    if event.startswith('socket.') or event in (
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'
    ):
        blocked()
sys.addaudithook(audit)

source, base, name, scenarios = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client.jailreader import JailReader
from fail2ban.server.actions import Actions
from fail2ban.server.filter import FileFilter, Observers
from fail2ban.server.jail import Jail
from fail2ban.server.mytime import MyTime
from fail2ban.server.server import Server
from fail2ban.server.utils import Utils
from fail2ban.version import version
assert version == '1.1.1', version
subprocess.Popen = os.system = socket.socket = Utils.executeCmd = blocked
threading.Thread.start = Server.start = Jail.start = Actions.start = blocked
Observers.Main = None

config = JailReader(name, basedir=base)
assert config.read() and config.getOptions() and config.isEnabled()
jail = config.options
assert jail['action'] == '' and not jail.get('ignorecommand')
assert jail['ignoreself'] is False and jail['usedns'] == 'no'
opt = config.filter.getCombined()

class QueueOnly:
    name = 'fake-file-jail'
    database = None
    def __init__(self):
        self.ticket_count = 0
    def putFailTicket(self, ticket):
        self.ticket_count += 1

answers = []
for index, (initial, steps) in enumerate(json.loads(scenarios)):
    file = Path.cwd() / f'fixture-{index}.log'
    file.write_bytes(initial.encode('utf-8'))
    path = str(file)
    queue = QueueOnly()
    filt = FileFilter(queue, useDns=jail['usedns'])
    filt.active = True
    filt.ignoreSelf = jail['ignoreself']
    filt.setLogEncoding('UTF-8')
    filt.setLogTimeZone(jail['logtimezone'])
    filt.setFindTime(jail['findtime'])
    filt.setMaxRetry(jail['maxretry'])
    filt.prefRegex = opt['prefregex']
    filt.setDatePattern(opt['datepattern'])
    for rule in (opt.get('failregex') or '').splitlines():
        if rule:
            filt.addFailRegex(rule)
    for rule in (opt.get('ignoreregex') or '').splitlines():
        if rule:
            filt.addIgnoreRegex(rule)
    # No age-based auto-seek, rotating files or persistent log positions.
    filt.addLogPath(path, tail=False, autoSeek=False)
    container = filt.getLog(path)
    original_process = filt.processLineAndAdd
    phases = []
    for append, now in steps:
        if append:
            with file.open('ab') as writer:
                writer.write(append.encode('utf-8'))
        entries = []
        def observe(line):
            prior = queue.ticket_count
            original_process(line)
            assert queue.ticket_count - prior <= 1
            entries.append([container.tell(), 'live' if filt.inOperation else 'initial',
                            queue.ticket_count > prior])
        filt.processLineAndAdd = observe
        MyTime.setTime(now)
        assert filt.getFailures(path) is True
        phases.append({'phase': 'live' if container.inOperation else 'initial',
                       'offset': container.getPos(), 'lines': entries})
    answers.append(phases)
assert not violations, violations
print(json.dumps(answers))
";
    let inputs = scenarios
        .iter()
        .map(|scenario| {
            let appends = scenario
                .steps
                .iter()
                .map(|step| (&step.append, step.now))
                .collect::<Vec<_>>();
            json!([scenario.initial, appends])
        })
        .collect::<Vec<_>>();
    let dir = tempdir().expect("private Python file scenarios");
    let result = Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(config)
        .arg(JAIL)
        .arg(serde_json::to_string(&inputs).expect("serialize fixture scenarios"))
        .env("TZ", "UTC")
        .current_dir(dir.path())
        .output()
        .expect("run original FileFilter against fixture only");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}
