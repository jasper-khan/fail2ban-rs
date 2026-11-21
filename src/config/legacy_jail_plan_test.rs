use super::*;
use crate::detect::legacy_matcher::LineResult;

const JAIL: &str = "[DEFAULT]\nbackend=polling\nusedns=no\nignoreself=false\nmaxretry=3\nfindtime=10m\nbantime=2h\nignoreip=192.0.2.0/28, ::ffff:198.51.100.44\nlogencoding=utf-8\naction=\n[web-auth]\nenabled=yes\nfilter=nginx-http-auth[mode=normal]\nlogpath=/no-log-access/auth.log\n";
const FILTER_CONFIG: &str = "[Definition]\nmode=normal\nmdre-normal=^refused$\nmdre-fallback=^incompatible$\nfailregex=<mdre-<mode>>\nprefregex=^ *demo <F-CONTENT>[^,]+</F-CONTENT>, client: <ADDR>$\ndatepattern={^LN-BEG}\n";

fn fixture(config: &str) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("jail.d")).unwrap();
    std::fs::create_dir_all(tmp.path().join("filter.d")).unwrap();
    std::fs::write(tmp.path().join("jail.conf"), config).unwrap();
    std::fs::write(
        tmp.path().join("filter.d/nginx-http-auth.conf"),
        FILTER_CONFIG,
    )
    .unwrap();
    tmp
}

#[test]
fn admits_layered_file_plan_only_to_compile_offline_matcher() {
    let tmp = fixture(JAIL);
    std::fs::write(
        tmp.path().join("jail.d/99-web.local"),
        "[web-auth]\nmaxretry=4\nbantime=-1\nfilter=nginx-http-auth[mode=fallback]\n",
    )
    .unwrap();
    let plan = read(tmp.path(), "web-auth").unwrap();
    assert_eq!(plan.name, "web-auth");
    assert_eq!(plan.max_retry, 4);
    assert_eq!(plan.find_time, 600);
    assert_eq!(plan.ban_time_seconds, -1);
    assert_eq!(plan.log_paths, [PathBuf::from("/no-log-access/auth.log")]);
    assert!(plan.ignores("192.0.2.8".parse().unwrap()));
    assert!(plan.ignores("::ffff:198.51.100.44".parse().unwrap()));
    assert!(!plan.ignores("192.0.2.24".parse().unwrap()));
    assert!(matches!(
        plan.matcher
            .evaluate("2024/01/02 03:04:05 demo incompatible, client: 192.0.2.24"),
        LineResult::Matched(_),
    ));
    assert_eq!(
        plan.matcher
            .evaluate("2024/01/02 03:04:05 demo refused, client: 192.0.2.24"),
        LineResult::Miss,
    );
}

#[test]
fn rejects_unsupported_options_and_keeps_unrelated_jail_out_of_scope() {
    for (overlay, detail) in [
        ("enabled=no", "not enabled"),
        ("backend=systemd", "backend=polling"),
        ("usedns=warn", "usedns=no"),
        ("ignoreself=true", "ignoreself=false"),
        ("filter=sshd", "nginx-http-auth"),
        ("filter=nginx-http-auth[mode=unknown]", "filter parameter"),
        ("action=unresolved-marker", "option action"),
        ("ignorecommand=unresolved-marker", "ignorecommand"),
        ("ignoreip=example.invalid", "ignoreip"),
        ("bantime.increment=true", "incremental"),
        ("failregex=extra", "failregex"),
        ("logpath=/tmp/*.log", "literal paths"),
        ("logpath=/tmp/plain.log tail", "literal paths"),
        ("logtimezone=+0200", "UTC"),
        ("unknown_property=value", "unknown_property"),
    ] {
        let tmp = fixture(JAIL);
        std::fs::write(
            tmp.path().join("jail.d/99-web.local"),
            format!("[web-auth]\n{overlay}\n"),
        )
        .unwrap();
        let err = read(tmp.path(), "web-auth").unwrap_err().to_string();
        assert!(err.contains(detail), "{overlay}: {err}");
    }
    let tmp = fixture(&format!("{JAIL}\n[other]\nunknown_property=out-of-scope\n"));
    assert!(read(tmp.path(), "web-auth").is_ok());
    assert!(read(tmp.path(), "not-defined").is_err());
}

#[test]
fn durations_accept_pinned_units_and_reject_expressions() {
    for (input, seconds) in [("10m", 600), ("2 hours", 7200), ("1w", 604_800), ("-1", -1)] {
        assert_eq!(duration(input, "test").unwrap(), seconds);
    }
    for input in [
        "",
        "3月",
        "1+2",
        "1h 20m",
        "1.5h",
        "-3",
        "9999999999999999999m",
    ] {
        assert!(duration(input, "test").is_err(), "{input}");
    }
}

#[test]
fn rejects_nonfile_filter_logtype_even_if_not_exposed_as_combined_option() {
    let tmp = fixture(JAIL);
    std::fs::write(
        tmp.path().join("filter.d/nginx-http-auth.local"),
        "[Definition]\nlogtype=journal\n",
    )
    .unwrap();
    let error = read(tmp.path(), "web-auth").unwrap_err().to_string();
    assert!(error.contains("filter logtype=file"));
}
