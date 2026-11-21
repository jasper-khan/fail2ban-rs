//! Read-only comparison of the original shipped config, without starting a daemon.

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use super::{legacy_interp, legacy_layers};

const ORIGINAL_REV: &str = "f60978618a101427b06924fc932b44350fec2b63";
const CONFIG_NAMES: &[&str] = &["jail", "filter.d/nginx-http-auth", "filter.d/sshd"];

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("git UTF-8 output")
}

#[test]
#[ignore = "requires the clean local checkout of original Fail2Ban 1.1.1 and Python 3"]
fn stock_config_raw_results_agree_with_original() {
    let root = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate original Fail2Ban");
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), ORIGINAL_REV);
    let status = git(
        &root,
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
        "use unmodified stock config and Python source: {status}"
    );
    let scratch = tempfile::tempdir().expect("oracle scratch directory");
    let base = root.join("config");
    let python = Command::new("python3")
        .args([
            "-S",
            "-c",
            r"
import json, sys
from fail2ban.client.configreader import ConfigReaderUnshared
checks = {
    'jail': ('sshd', ('enabled', 'findtime', 'logpath', 'backend')),
    'filter.d/nginx-http-auth': ('Definition', ('datepattern', 'prefregex', 'failregex')),
    'filter.d/sshd': ('Definition', ('prefregex', 'failregex')),
}
out = {}
for name in sys.argv[2:]:
    cfg = ConfigReaderUnshared(basedir=sys.argv[1])
    if not cfg.read(name):
        raise ValueError('cannot read original stock config: ' + name)
    section, options = checks[name]
    out[name] = {
        'defaults': cfg.get_defaults(),
        'sections': cfg.get_sections(),
        'expanded_section': section,
        'expanded': {option: cfg.get(section, option) for option in options},
    }
print(json.dumps(out))
",
        ])
        .arg(&base)
        .args(CONFIG_NAMES)
        .current_dir(scratch.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONPATH", &root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env(
            "PYTHONPYCACHEPREFIX",
            scratch.path().join("isolated-pycache"),
        )
        .env("LC_ALL", "C")
        .output()
        .expect("run original offline config reader");
    assert!(
        python.status.success(),
        "{}",
        String::from_utf8_lossy(&python.stderr)
    );
    let original: Value = serde_json::from_slice(&python.stdout).expect("oracle JSON");
    for name in CONFIG_NAMES {
        let resolved = legacy_layers::read(&base, name)
            .expect("load stock config")
            .expect("stock config present");
        let denormalized = json!({"defaults": &resolved.defaults, "sections": &resolved.sections});
        let expected = original.get(name).expect("config in oracle JSON");
        for part in ["defaults", "sections"] {
            let ours = denormalized
                .get(part)
                .and_then(Value::as_object)
                .expect("native config map");
            let theirs = expected
                .get(part)
                .and_then(Value::as_object)
                .expect("original config map");
            for (k, v) in theirs {
                assert_eq!(ours.get(k), Some(v), "{name}: {part}/{k}");
            }
            assert_eq!(ours.len(), theirs.len(), "{name}: {part} item count");
        }
        let section = expected
            .get("expanded_section")
            .and_then(Value::as_str)
            .expect("section name");
        let expanded = expected
            .get("expanded")
            .and_then(Value::as_object)
            .expect("expanded configuration values");
        for (opt, value) in expanded {
            let text = legacy_interp::get_effective(
                section,
                opt,
                &resolved.defaults,
                |name| resolved.sections.get(name),
                None,
            )
            .expect("native expansion");
            assert_eq!(text.as_deref(), value.as_str(), "{name}: {section}/{opt}");
        }
    }
}
