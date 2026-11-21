//! Differential fixtures for the raw Fail2Ban 1.1.1 configuration layers.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::legacy_layers::read;

const LAYERS: &[(&str, &str)] = &[
    (
        "jail.d/90-final.local",
        "[DEFAULT]\ndefaultlast = d_final_local\n[sshd]\nwinner = final_local\n",
    ),
    (
        "jail.d/20-shared.local",
        "[DEFAULT]\ndefaultlast = d_shared_local\n[sshd]\nwinner = shared_local\nsame_stem = shared_local\nOverLocal = shared_local\n",
    ),
    (
        "jail.local",
        "[DEFAULT]\ndefaultlast = d_base_local\n[sshd]\nwinner = base_local\nOverLocal = base_local\n",
    ),
    (
        "jail.d/90-final.conf",
        "[DEFAULT]\ndefaultlast = d_final_conf\n[sshd]\nwinner = final_conf\nsame_stem = final_conf\nconf_sorted = final_conf\nbase_local = final_conf\n",
    ),
    (
        "jail.d/20-shared.conf",
        "[DEFAULT]\ndefaultlast = d_shared_conf\n[sshd]\nWINNER = shared_conf\nsame_stem = shared_conf\nconf_sorted = shared_conf\n",
    ),
    (
        "jail.conf",
        "[DEFAULT]\ndefaultlast = d_base_conf\nport = 22\n[sshd]\nwinner = base_conf\nRawValue = %(known/port)s %% ${section:port}\nbase_local = base_conf\n[SSHD]\nwinner = case_section\n",
    ),
];

const INCLUDES: &[(&str, &str)] = &[
    (
        "jail.conf",
        "[INCLUDES]\nbefore = nested/base.conf\n         second.conf\nafter = final.conf\n[sshd]\nseen = jail\nbefore_vs_current = jail\n",
    ),
    (
        "nested/base.conf",
        "[INCLUDES]\nbefore = defaults.conf\n[sshd]\nseen = base\nbase_vs_local = base\nbefore_order = base\n",
    ),
    (
        "nested/base.local",
        "[sshd]\nseen = base_local\nbase_vs_local = base_local\nbefore_vs_current = base_local\n",
    ),
    (
        "nested/defaults.conf",
        "[DEFAULT]\nseed = 42\n[sshd]\nseen = defaults\ndefaults_are_relative = yes\n",
    ),
    (
        "second.conf",
        "[sshd]\nseen = second\nbefore_order = second\n",
    ),
    (
        "final.conf",
        "[sshd]\nseen = final\nafter_vs_local = final\n",
    ),
    (
        "final.local",
        "[sshd]\nseen = final_local\nafter_vs_local = final_local\n",
    ),
];

const OVERLAYS_ONLY: &[(&str, &str)] = &[
    ("jail.d/only.local", "[sshd]\nwinner = local\n"),
    ("jail.d/only.conf", "[sshd]\nwinner = conf\n"),
    ("jail.d/ignored.txt", "[sshd]\nwinner = ignored\n"),
];

fn write_fixture(files: &[(&str, &str)]) -> TempDir {
    let dir = tempdir().unwrap();
    for (relative, contents) in files {
        let path = dir.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    dir
}

fn rust_projection(path: &Path) -> (Value, Vec<String>) {
    let snapshot = read(path, "jail")
        .unwrap()
        .expect("fixture has a jail config");
    let files = snapshot
        .files
        .iter()
        .map(|file| {
            file.strip_prefix(path)
                .unwrap_or(file)
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    (
        json!({"defaults": snapshot.defaults, "sections": snapshot.sections}),
        files,
    )
}

fn expected_layers() -> Value {
    json!({
        "defaults": {"defaultlast": "d_final_local", "port": "22"},
        "sections": {
            "sshd": {
                "winner": "final_local",
                "same_stem": "shared_local",
                "conf_sorted": "final_conf",
                "overlocal": "shared_local",
                "base_local": "final_conf",
                "rawvalue": "%(known/port)s %% ${section:port}"
            },
            "SSHD": {"winner": "case_section"},
            "KNOWN/sshd": {
                "winner": "shared_local",
                "same_stem": "final_conf",
                "conf_sorted": "shared_conf",
                "overlocal": "base_local",
                "base_local": "base_conf"
            }
        }
    })
}

fn expected_includes() -> Value {
    json!({
        "defaults": {"seed": "42"},
        "sections": {
            "sshd": {
                "seen": "final_local",
                "defaults_are_relative": "yes",
                "base_vs_local": "base_local",
                "before_order": "second",
                "before_vs_current": "jail",
                "after_vs_local": "final_local"
            },
            "INCLUDES": {"before": "nested/base.conf\nsecond.conf", "after": "final.conf"},
            "KNOWN/sshd": {
                "seen": "final",
                "base_vs_local": "base",
                "before_order": "base",
                "before_vs_current": "base_local",
                "after_vs_local": "final"
            },
            "KNOWN/INCLUDES": {"before": "defaults.conf"}
        }
    })
}

fn expected_overlays_only() -> Value {
    json!({
        "defaults": {},
        "sections": {
            "sshd": {"winner": "local"},
            "KNOWN/sshd": {"winner": "conf"}
        }
    })
}

#[test]
fn legacy_layer_order_and_raw_overrides_match_the_golden_projection() {
    // Fixtures are created in reverse precedence order so the test doesn't use
    // filesystem iteration order as an accidental proxy for lexical ordering.
    let dir = write_fixture(LAYERS);
    let (actual, files) = rust_projection(dir.path());
    assert_eq!(
        files,
        [
            "jail.conf",
            "jail.d/20-shared.conf",
            "jail.d/90-final.conf",
            "jail.local",
            "jail.d/20-shared.local",
            "jail.d/90-final.local",
        ]
    );
    assert_eq!(actual, expected_layers());
}

#[test]
fn legacy_include_order_and_local_companions_match_the_golden_projection() {
    let dir = write_fixture(INCLUDES);
    let (actual, files) = rust_projection(dir.path());
    assert_eq!(
        files,
        [
            "nested/defaults.conf",
            "nested/base.conf",
            "nested/base.local",
            "second.conf",
            "jail.conf",
            "final.conf",
            "final.local",
        ]
    );
    assert_eq!(actual, expected_includes());
}

#[test]
fn legacy_drop_ins_can_load_without_a_base_file() {
    let dir = write_fixture(OVERLAYS_ONLY);
    let (actual, files) = rust_projection(dir.path());
    assert_eq!(files, ["jail.d/only.conf", "jail.d/only.local"]);
    assert_eq!(actual, expected_overlays_only());
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_raw_projection_matches_pinned_fail2ban_111() {
    use std::process::Command;

    const PIN: &str = "f60978618a101427b06924fc932b44350fec2b63";
    const ORACLE: &str = r#"
import json
import sys
sys.path.insert(0, sys.argv[1])
from fail2ban.client.configreader import ConfigReaderUnshared
from fail2ban.version import version
assert version == "1.1.1", version
reader = ConfigReaderUnshared(basedir=sys.argv[2])
if not reader.read("jail"):
    raise RuntimeError("oracle did not load the fixture")
print(json.dumps({"defaults": reader.get_defaults(), "sections": reader.get_sections()}))
"#;
    let source = std::env::var_os("FAIL2BAN_111_SOURCE")
        .expect("set FAIL2BAN_111_SOURCE to the pinned Fail2Ban Git checkout");
    let source = fs::canonicalize(source).expect("resolve FAIL2BAN_111_SOURCE");
    let rev = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&source)
        .output()
        .expect("run git rev-parse");
    assert!(rev.status.success(), "{rev:?}");
    assert_eq!(String::from_utf8(rev.stdout).unwrap().trim(), PIN);
    let status = Command::new("git")
        .args([
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "fail2ban",
        ])
        .current_dir(&source)
        .output()
        .expect("verify upstream oracle checkout");
    assert!(status.status.success(), "{status:?}");
    assert!(
        status.stdout.is_empty(),
        "upstream oracle source was modified: {}",
        String::from_utf8_lossy(&status.stdout)
    );

    for (fixture, expected) in [
        (LAYERS, expected_layers()),
        (INCLUDES, expected_includes()),
        (OVERLAYS_ONLY, expected_overlays_only()),
    ] {
        let dir = write_fixture(fixture);
        let output = Command::new("python3")
            .args(["-I", "-S", "-B", "-c", ORACLE])
            .arg(&source)
            .arg(dir.path())
            .current_dir(dir.path())
            .output()
            .expect("run upstream Python config reader");
        assert!(
            output.status.success(),
            "upstream reader error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let python: Value = serde_json::from_slice(&output.stdout).unwrap();
        let (rust, _) = rust_projection(dir.path());
        assert_eq!(
            python, expected,
            "update the golden only after checking parity"
        );
        assert_eq!(rust, python);
    }
}
