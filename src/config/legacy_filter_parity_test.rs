//! Effective configuration parity only: no regex execution or action dispatch.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::legacy_filter::{self, Parameters};
use super::legacy_filter_spec;

const STOCK: &[(&str, &str, &str)] = &[
    ("sshd", "auto", ""),
    ("sshd", "auto", "aggressive"),
    ("sshd", "systemd", ""),
    ("nginx-http-auth", "auto", ""),
    ("nginx-http-auth", "auto", "aggressive"),
];

const SYNTHETIC: &str = r#"[DEFAULT]
global = inherited
[Definition]
token = definition
prefregex = ^<F-CONTENT>.+</F-CONTENT>$
failregex = ^%(token)s <token> %(global)s <HOST>$
            ^<source-<logtype>> <ADDR>$
source-file = FILE
source-journal = JOURNAL
ignoreregex = ^ignore <token>$
datepattern = %%Y-%%m-%%d
maxlines = 2
journalmatch = _COMM="sample app" + _SYSTEMD_UNIT=sample.service
               _UID=1000
[Init]
token = init
maxlines = 3
"#;

const NO_OPTS: &[(&str, &str)] = &[];

fn fixture() -> TempDir {
    let dir = tempdir().expect("temporary config base");
    fs::create_dir(dir.path().join("filter.d")).expect("filter directory");
    fs::write(dir.path().join("filter.d/synthetic.conf"), SYNTHETIC).expect("filter fixture");
    dir
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, val)| ((*key).to_owned(), (*val).to_owned()))
        .collect()
}

fn native(
    base: &Path,
    name: &str,
    backend: &str,
    jail: &[(&str, &str)],
    call: &[(&str, &str)],
) -> Value {
    native_with_call(base, name, backend, &map(jail), &map(call))
}

fn native_with_call(
    base: &Path,
    name: &str,
    backend: &str,
    jail: &BTreeMap<String, String>,
    call: &BTreeMap<String, String>,
) -> Value {
    let config = legacy_filter::read(base, name)
        .expect("filter config reads")
        .expect("filter config is present");
    let parameters = Parameters {
        backend,
        jail,
        call,
        all: false,
    };
    let resolved = legacy_filter::resolve(&config, &parameters).expect("filter config resolves");
    let get = |key: &str| resolved.options.get(key);
    json!({
        "usedns": get("usedns"),
        "prefregex": get("prefregex"),
        "failregex": get("failregex"),
        "ignoreregex": get("ignoreregex"),
        "datepattern": get("datepattern"),
        "maxlines": resolved.maxlines,
        "journalmatch": get("journalmatch")
    })
}

fn expected(percent: &str, angle: &str, source: &str, maxlines: i64) -> Value {
    json!({
        "usedns": null,
        "prefregex": "^<F-CONTENT>.+</F-CONTENT>$",
        "failregex": format!("^{percent} {angle} inherited <HOST>$\n^{source} <ADDR>$"),
        "ignoreregex": format!("^ignore {angle}$"),
        "datepattern": "%Y-%m-%d",
        "maxlines": maxlines,
        "journalmatch": "_COMM=\"sample app\" + _SYSTEMD_UNIT=sample.service\n_UID=1000",
    })
}

#[test]
fn legacy_filter_definition_init_and_jail_precedence_match_golden() {
    let dir = fixture();
    let base = dir.path();
    assert_eq!(
        native(base, "synthetic", "auto", NO_OPTS, NO_OPTS),
        expected("definition", "init", "FILE", 3)
    );
    assert_eq!(
        native(base, "synthetic", "systemd", &[("token", "jail")], NO_OPTS),
        expected("jail", "init", "JOURNAL", 3)
    );
    assert_eq!(
        native(
            base,
            "synthetic",
            "systemd",
            &[("token", "jail")],
            &[
                ("token", "argument"),
                ("maxlines", "4"),
                ("logtype", "file")
            ],
        ),
        expected("argument", "argument", "FILE", 4)
    );
}

#[test]
#[ignore = "requires a clean local Fail2Ban 1.1.1 checkout via FAIL2BAN_111_SOURCE and Python 3"]
fn legacy_effective_filter_config_matches_pinned_fail2ban_111() {
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
        "use unmodified stock config and Python source: {status}"
    );

    let base = source.join("config");
    for &(name, backend, mode) in STOCK {
        let mode_opt = [("mode", mode)];
        let call = if mode.is_empty() { NO_OPTS } else { &mode_opt };
        let original = oracle(&source, &base, name, backend, NO_OPTS, call);
        let spec = if mode.is_empty() {
            name.to_owned()
        } else {
            format!("{name}[mode={mode}]")
        };
        let parsed = legacy_filter_spec::parse(&spec).expect("legacy filter specification");
        let ours = native_with_call(
            &base,
            parsed.name,
            backend,
            &BTreeMap::new(),
            &parsed.parameters,
        );
        for (key, expected) in original.as_object().expect("object") {
            assert_eq!(
                ours.get(key),
                Some(expected),
                "{name} {backend} {mode}: {key}"
            );
        }
    }

    let synthetic = fixture();
    let base = synthetic.path();
    let jail = &[("token", "jail")];
    let call = &[
        ("token", "argument"),
        ("maxlines", "4"),
        ("logtype", "file"),
    ];
    for (backend, jail, call, golden) in [
        (
            "auto",
            NO_OPTS,
            NO_OPTS,
            expected("definition", "init", "FILE", 3),
        ),
        (
            "systemd",
            jail,
            NO_OPTS,
            expected("jail", "init", "JOURNAL", 3),
        ),
        (
            "systemd",
            jail,
            call,
            expected("argument", "argument", "FILE", 4),
        ),
    ] {
        let original = oracle(&source, base, "synthetic", backend, jail, call);
        assert_eq!(original, golden, "golden must match Fail2Ban 1.1.1");
        assert_eq!(native(base, "synthetic", backend, jail, call), original);
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("git UTF-8")
}

fn oracle(
    source: &Path,
    base: &Path,
    name: &str,
    backend: &str,
    jail: &[(&str, &str)],
    call: &[(&str, &str)],
) -> Value {
    const ORACLE: &str = r#"
import json
import sys
source, base, name, backend, jail, call = sys.argv[1:]
sys.path.insert(0, source)
from fail2ban.client.filterreader import FilterReader
from fail2ban.version import version
assert version == "1.1.1", version
reader = FilterReader(name, "synthetic-jail", json.loads(call), basedir=base)
if not reader.read():
    raise RuntimeError("upstream reader could not load filter: " + name)
reader.applyAutoOptions(backend)
reader.getOptions(json.loads(jail))
options = reader.getCombined()
keys = ("usedns", "prefregex", "failregex", "ignoreregex", "datepattern", "maxlines", "journalmatch")
print(json.dumps({key: options.get(key) for key in keys}))
"#;
    let scratch = tempdir().expect("temporary oracle directory");
    let output = std::process::Command::new("python3")
        .args(["-I", "-B", "-S", "-c", ORACLE])
        .arg(source)
        .arg(base)
        .args([name, backend])
        .arg(serde_json::to_string(&map(jail)).unwrap())
        .arg(serde_json::to_string(&map(call)).unwrap())
        .current_dir(scratch.path())
        .output()
        .expect("run original offline FilterReader");
    assert!(
        output.status.success(),
        "{name} {backend}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("upstream oracle JSON")
}
