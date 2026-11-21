//! Pinned file positioning on generated scratch logs, with no watch or action.

use std::fs::{self, File};
use std::io::{Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::detect::legacy_file_cursor::{LegacyFileCursor, StartAt};
use crate::detect::legacy_file_seek::seek_nginx_offset;

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const MIDNIGHT: i64 = 1_704_153_600;
const RECORD_LIMIT: usize = 1_024;
const MIXED: &str = concat!(
    "2024/01/02 00:00:01 aa\n",
    "2024/01/02 00:00:02 second-row\r\n",
    "2024/01/02 00:00:04 café-row\n",
    "2024/01/02 00:00:04 duplicate-equal\n",
    "2024/01/02 00:00:07 final\n",
);
const PARTIAL: &str = concat!("2024/01/02 00:00:01 old\n", "2024/01/02 00:00:04 partial");
const WITH_UNDATED: &str = concat!(
    "2024/01/02 00:00:01 old\n",
    "note without timestamp\n",
    "2024/01/02 00:00:04 new\n",
);

struct Case {
    label: &'static str,
    data: String,
    resume: u64,
    cutoff: i64,
    expected_offset: u64,
}

fn cases() -> Vec<Case> {
    let old = "2024/01/02 00:00:01 old\n";
    let next = "2024/01/02 00:00:04 new\n";
    let many_undated = format!("{old}{}{next}", "note without timestamp\n".repeat(30));
    let invalid_date = format!("{old}2024/02/30 00:00:02 invalid-calendar\n{next}");
    let mut large = String::new();
    for i in 0..1_024 {
        use std::fmt::Write as _;
        writeln!(
            large,
            "2024/01/02 00:{:02}:{:02} row {i:04}",
            i / 60,
            i % 60
        )
        .expect("generate a scratch row");
    }
    [
        ("empty", String::new(), 0, 4, 0),
        (
            "only-undated",
            "unknown text\nnext note\r\n".to_owned(),
            0,
            4,
            0,
        ),
        ("before-first", MIXED.to_owned(), 0, 0, 0),
        ("first-equal", MIXED.to_owned(), 0, 4, 55),
        ("at-line-start", MIXED.to_owned(), 23, 4, 55),
        ("middle-of-line", MIXED.to_owned(), 14, 4, 55),
        ("already-at-second-equal", MIXED.to_owned(), 85, 4, 85),
        ("after-all", MIXED.to_owned(), 0, 9, 147),
        ("already-eof", MIXED.to_owned(), 147, 4, 147),
        ("partial-probe-at-cutoff", PARTIAL.to_owned(), 0, 4, 24),
        ("partial-probe-after-cutoff", PARTIAL.to_owned(), 0, 5, 51),
        ("one-undated", WITH_UNDATED.to_owned(), 0, 4, 24),
        ("thirty-undated", many_undated, 0, 4, 24),
        ("invalid-calendar", invalid_date, 0, 4, 24),
        ("ordered-1024", large, 5_000, 753, 21_837),
    ]
    .into_iter()
    .map(|(label, data, resume, delta, expected_offset)| Case {
        label,
        data,
        resume,
        cutoff: MIDNIGHT + delta,
        expected_offset,
    })
    .collect()
}

fn source() -> PathBuf {
    let path =
        fs::canonicalize(std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"))
            .expect("locate original source");
    let git = |args: &[&str]| {
        let result = Command::new("git")
            .args(args)
            .current_dir(&path)
            .output()
            .expect("run git");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).expect("git UTF-8 output")
    };
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), ORIGINAL_REV);
    let status = git(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        "fail2ban",
    ]);
    assert!(
        status.is_empty(),
        "unmodified original source required: {status}"
    );
    path
}

fn native(root: &Path, case: &Case) -> Value {
    let path = root.join(format!("{}.log", case.label));
    fs::write(&path, &case.data).expect("write synthetic log");
    let mut file = File::open(path).expect("open synthetic log");
    let initial_position = file
        .seek(SeekFrom::Start(3))
        .expect("place caller's descriptor");
    let offset = seek_nginx_offset(&file, case.resume, case.cutoff, RECORD_LIMIT)
        .expect("seek synthetic log");
    assert_eq!(
        file.stream_position().expect("caller descriptor position"),
        initial_position
    );
    let mut cursor = LegacyFileCursor::open(file, StartAt::Resume(offset), RECORD_LIMIT)
        .expect("open a fixture cursor at the selected offset");
    let next = cursor
        .next_record()
        .expect("read the ordinary next synthetic line")
        .map_or(Value::Null, |line| json!([line.text, line.end_offset]));
    assert_eq!(
        cursor.acknowledged_offset(),
        offset,
        "seek or peek may not acknowledge data"
    );
    json!([case.label, offset, next])
}

const ORACLE: &str = r"
import json
import logging
import pathlib
import sys

def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'):
        raise AssertionError('unexpected external operation: ' + event)
sys.addaudithook(audit)

from fail2ban.server.filter import FileContainer, FileFilter
from fail2ban.version import version
assert version == '1.1.1'
logging.disable(logging.CRITICAL)

class ScratchContainer(FileContainer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.probes = 0
    def seek(self, offset, endLine=True):
        if endLine:
            self.probes += 1
        return super().seek(offset, endLine)

root = pathlib.Path.cwd()
out = []
for label, contents, resume, cutoff in json.loads(sys.argv[1]):
    log = root / (label + '.log')
    log.write_bytes(contents.encode('utf-8'))
    fixture = ScratchContainer(str(log), 'utf-8')
    fixture.setPos(resume)
    matcher = FileFilter(None, useDns='no')
    matcher.setLogTimeZone('UTC')
    matcher.setDatePattern('{^LN-BEG}')
    matcher.seekToTime(fixture, cutoff)
    selected = fixture.getPos()
    fixture.close()
    following = None
    if fixture.open():
        line = fixture.readline()
        if line is not None:
            following = [line, fixture.tell()]
        fixture.close()
    if label == 'ordered-1024':
        assert 1 < fixture.probes < 32, fixture.probes
    out.append([label, selected, following])
print(json.dumps(out))
";

#[test]
#[ignore = "requires the unchanged Fail2Ban 1.1.1 Python source via FAIL2BAN_111_SOURCE"]
fn legacy_file_seek_offsets_and_ordinary_next_records_match_original() {
    let source = source();
    let original_root = tempfile::tempdir().expect("isolated original oracle");
    let ours_root = tempfile::tempdir().expect("isolated native fixture");
    let cases = cases();
    let args = cases
        .iter()
        .map(|case| json!([case.label, case.data, case.resume, case.cutoff]))
        .collect::<Vec<_>>();
    let result = Command::new("python3")
        .args([
            "-S",
            "-c",
            ORACLE,
            &serde_json::to_string(&args).expect("serialize fixtures"),
        ])
        .current_dir(original_root.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .env("PYTHONPATH", &source)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run pinned synthetic positioning oracle");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original: Vec<Value> = serde_json::from_slice(&result.stdout).expect("oracle rows");
    assert_eq!(original.len(), cases.len());
    for (case, oracle) in cases.iter().zip(original) {
        assert_eq!(
            oracle.get(1),
            Some(&json!(case.expected_offset)),
            "{} pinned offset",
            case.label
        );
        assert_eq!(native(ours_root.path(), case), oracle, "{}", case.label);
    }
}
