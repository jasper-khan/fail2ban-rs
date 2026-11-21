//! Read-only comparison of the original shipped config, without starting a daemon.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
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

fn pinned_root() -> PathBuf {
    let root = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate original Fail2Ban");
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), ORIGINAL_REV);
    root
}

fn assert_stale_free(root: &Path) {
    let status = git(
        root,
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
}

fn oracle_json(scratch: &Path, root: &Path, script: &str, args: &[String]) -> Value {
    let base = root.join("config");
    let python = Command::new("python3")
        .args(["-S", "-c", script])
        .arg(&base)
        .args(args)
        .current_dir(scratch)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONPATH", root)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONPYCACHEPREFIX", scratch.join("isolated-pycache"))
        .env("LC_ALL", "C")
        .output()
        .expect("run original offline config reader");
    assert!(
        python.status.success(),
        "{}",
        String::from_utf8_lossy(&python.stderr)
    );
    serde_json::from_slice(&python.stdout).expect("oracle JSON")
}

/// Compare the whole merged raw projection: DEFAULT and every section map.
fn assert_same_raw(name: &str, resolved: &legacy_layers::LayeredConfig, expected: &Value) {
    let denormalized = json!({"defaults": &resolved.defaults, "sections": &resolved.sections});
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
}

/// Compare one interpolated value or interpolation error against the original.
fn assert_same_expansion(
    name: &str,
    resolved: &legacy_layers::LayeredConfig,
    section: &str,
    option: &str,
    probe: &Value,
) {
    let pair = probe.as_array().expect("oracle probe pair");
    let mut fields = pair.iter();
    let kind = fields
        .next()
        .and_then(Value::as_str)
        .expect("probe outcome kind");
    let text = fields
        .next()
        .and_then(Value::as_str)
        .expect("probe outcome text");
    let outcome = legacy_interp::get_effective(
        section,
        option,
        &resolved.defaults,
        |sect| resolved.sections.get(sect),
        None,
    );
    let ours = match outcome {
        Ok(value) => {
            assert_eq!(
                kind, "ok",
                "{name}: {section}/{option} expands in the original but not here: {value:?}"
            );
            value.unwrap_or_default()
        }
        Err(err) => {
            assert_eq!(
                kind, "err",
                "{name}: {section}/{option} is an original error but expanded here: {err}"
            );
            err.to_string()
        }
    };
    assert_eq!(ours, text, "{name}: {section}/{option}");
}

#[test]
#[ignore = "requires the clean local checkout of original Fail2Ban 1.1.1 and Python 3"]
fn stock_config_raw_results_agree_with_original() {
    let root = pinned_root();
    assert_stale_free(&root);
    let scratch = tempfile::tempdir().expect("oracle scratch directory");
    let base = root.join("config");
    let original: Value = oracle_json(
        scratch.path(),
        &root,
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
        &CONFIG_NAMES
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    );
    for name in CONFIG_NAMES {
        let resolved = legacy_layers::read(&base, name)
            .expect("load stock config")
            .expect("stock config present");
        let expected = original.get(name).expect("config in oracle JSON");
        assert_same_raw(name, &resolved, expected);
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
                |sect| resolved.sections.get(sect),
                None,
            )
            .expect("native expansion");
            assert_eq!(text.as_deref(), value.as_str(), "{name}: {section}/{opt}");
        }
    }
}

const CATALOG_SCRIPT: &str = r"
import json, sys
from fail2ban.client.configreader import ConfigReaderUnshared
base = sys.argv[1]
out = {}
for name in sys.argv[2:]:
    cfg = ConfigReaderUnshared(basedir=base)
    if not cfg.read(name):
        raise ValueError('cannot read original stock config: ' + name)
    sections = cfg.get_sections()
    defaults = cfg.get_defaults()
    expanded = {}
    def probe(section, option):
        try:
            expanded.setdefault(section, {})[option] = ['ok', cfg.get(section, option)]
        except Exception as err:
            expanded.setdefault(section, {})[option] = ['err', str(err)]
    for section, options in sections.items():
        for option in options:
            probe(section, option)
    for option in defaults:
        probe('DEFAULT', option)
    out[name] = {'defaults': defaults, 'sections': sections, 'expanded': expanded}
print(json.dumps(out))
";

/// Every stock config name: the daemon config, the jail tree, and standalone
/// paths overlays beside it, then the whole filter and action catalogues.
fn stock_names(base: &Path) -> Vec<String> {
    let mut names = BTreeSet::from(["fail2ban".to_owned(), "jail".to_owned()]);
    for sub in ["", "filter.d", "action.d"] {
        let dir = if sub.is_empty() {
            base.to_path_buf()
        } else {
            base.join(sub)
        };
        for entry in fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
        {
            let is_file = entry.file_type().is_ok_and(|ty| ty.is_file());
            let stem = entry
                .file_name()
                .to_string_lossy()
                .strip_suffix(".conf")
                .map(str::to_owned);
            if let Some(stem) = stem
                && is_file
            {
                if sub.is_empty() {
                    names.insert(stem);
                } else {
                    names.insert(format!("{sub}/{stem}"));
                }
            }
        }
    }
    names.into_iter().collect()
}

#[test]
#[ignore = "requires the clean local checkout of original Fail2ban 1.1.1 and Python 3"]
fn stock_catalog_layering_and_expansion_agree_with_original() {
    let root = pinned_root();
    assert_stale_free(&root);
    let scratch = tempfile::tempdir().expect("oracle scratch directory");
    let base = root.join("config");
    let names = stock_names(&base);
    assert!(!names.is_empty(), "stock catalog enumeration failed");
    let original: Value = oracle_json(scratch.path(), &root, CATALOG_SCRIPT, &names);
    let catalog = original.as_object().expect("oracle catalog");
    assert_eq!(
        catalog.len(),
        names.len(),
        "oracle must answer every requested stock config"
    );
    for name in &names {
        let expected = catalog
            .get(name.as_str())
            .expect("oracle answered the request");
        let resolved = legacy_layers::read(&base, name)
            .expect("load stock config")
            .expect("stock config present");
        assert_same_raw(name, &resolved, expected);
        let expanded = expected
            .get("expanded")
            .and_then(Value::as_object)
            .expect("expanded oracle values");
        for (section, options) in expanded {
            for (option, probe) in options.as_object().expect("expanded section options") {
                assert_same_expansion(name, &resolved, section, option, probe);
            }
        }
    }
}
