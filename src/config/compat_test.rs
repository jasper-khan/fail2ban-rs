//! Unit tests for the original-tree compatibility loader.

use std::path::{Path, PathBuf};

use super::load;
use crate::config::types::{Backend, LogBackend};
use crate::detect::date::DateFormat;

/// Write a minimal original configuration tree with one enabled jail.
fn tree(dir: &Path, jail_conf: &str, filter: &str) -> PathBuf {
    std::fs::create_dir_all(dir.join("filter.d")).expect("create tree");
    std::fs::write(
        dir.join("fail2ban.conf"),
        concat!(
            "[Definition]\n",
            "socket = /run/record-test/f2b.sock\n",
            "dbfile = /run/record-test/state/fail2ban.sqlite3\n",
        ),
    )
    .expect("write fail2ban.conf");
    std::fs::write(dir.join("jail.conf"), jail_conf).expect("write jail.conf");
    std::fs::write(dir.join("filter.d/chain-auth.conf"), filter).expect("write filter");
    dir.to_path_buf()
}

const JAIL: &str = concat!(
    "[DEFAULT]\n",
    "backend = polling\n",
    "usedns = no\n",
    "ignoreself = false\n",
    "action =\n",
    "\n",
    "[chain-jail]\n",
    "enabled = true\n",
    "port = 8081\n",
    "filter = chain-auth\n",
    "logpath = /tmp/web1.log\n",
    "    /tmp/web2.log\n",
    "maxretry = 3\n",
    "findtime = 45s\n",
    "bantime = 4s\n",
);

const FILTER: &str = concat!(
    "[Definition]\n",
    "failregex = ^chain auth failure .* from <HOST> port \\d+\n",
    "ignoreregex =\n",
);

#[test]
fn converts_an_original_jail_into_the_daemon_config() {
    let tmp = tempfile::tempdir().expect("scratch");
    let base = tree(tmp.path(), JAIL, FILTER);
    let record = Path::new("/tmp/decisions.log");
    let config = load(&base, record).expect("load");
    assert_eq!(
        config.global.socket_path,
        PathBuf::from("/run/record-test/f2b.sock")
    );
    assert_eq!(
        config.global.state_dir,
        PathBuf::from("/run/record-test/state")
    );
    let jail = config.jail.get("chain-jail").expect("jail converted");
    assert_eq!(
        jail.filter,
        ["^chain auth failure .* from <HOST> port \\d+"]
    );
    assert!(jail.ignoreregex.is_empty());
    assert_eq!(jail.max_retry, 3);
    assert_eq!(jail.find_time, 45);
    assert_eq!(jail.ban_time, 4);
    assert_eq!(jail.port, ["8081"]);
    assert_eq!(jail.protocol, "tcp");
    assert_eq!(jail.date_format, DateFormat::Syslog);
    assert_eq!(jail.log_backend, LogBackend::File);
    assert_eq!(
        jail.log_paths,
        [
            PathBuf::from("/tmp/web1.log"),
            PathBuf::from("/tmp/web2.log")
        ]
    );
    assert_eq!(jail.log_path, PathBuf::from("/tmp/web1.log"));
    let Backend::Script { ban_cmd, unban_cmd } = &jail.backend else {
        panic!("expected the decision-recording script backend");
    };
    assert_eq!(
        ban_cmd.as_str(),
        "printf 'BAN <JAIL> <IP>\\n' >> /tmp/decisions.log"
    );
    assert_eq!(
        unban_cmd.as_str(),
        "printf 'UNBAN <JAIL> <IP>\\n' >> /tmp/decisions.log"
    );
}

#[test]
fn disabled_original_jails_are_skipped_without_jail_entries() {
    let tmp = tempfile::tempdir().expect("scratch");
    let jail_conf = concat!(
        "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
        "[off]\nenabled = false\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
    );
    let base = tree(tmp.path(), jail_conf, FILTER);
    let err = load(&base, Path::new("/tmp/decisions.log"))
        .expect_err("no enabled jails must fail validation");
    assert!(
        err.to_string().contains("no jails defined"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_options_outside_the_stage_one_subset() {
    for (jail_conf, needle) in [
        (
            concat!(
                "[DEFAULT]\nbackend = auto\nusedns = no\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "polling",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = warn\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "usedns=no",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = true\naction =\n",
                "[bad]\nenabled = true\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "ignoreself=false",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 80\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
                "action = /usr/bin/ping <ip>\n",
            ),
            "unsupported original jail option action",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = http\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "numeric ports",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 8081\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
                "bantime.increment = true\n",
            ),
            "bantime.increment",
        ),
    ] {
        let tmp = tempfile::tempdir().expect("scratch");
        let base = tree(tmp.path(), jail_conf, FILTER);
        let err = load(&base, Path::new("/tmp/decisions.log"))
            .expect_err("config outside the stage-one subset must be rejected");
        assert!(
            err.to_string().contains(needle),
            "expected {needle:?} in {err}"
        );
    }
}

#[test]
fn rejects_filters_with_unsupported_features() {
    for (filter, needle) in [
        (
            concat!(
                "[Definition]\n",
                "prefregex = ^.*from <HOST>\n",
                "failregex = <F-NOBEGGARING>.*\n",
            ),
            "prefregex",
        ),
        (
            concat!(
                "[Definition]\n",
                "failregex = ^fail .* from <HOST>\n",
                "datepattern = %%Y %%m %%d\n",
            ),
            "datepattern",
        ),
        (
            concat!(
                "[Definition]\n",
                "journalmatch = _SYSTEMD_UNIT=chain.service\n",
                "failregex = ^fail .* from <HOST>\n",
            ),
            "journalmatch",
        ),
    ] {
        let tmp = tempfile::tempdir().expect("scratch");
        let base = tree(tmp.path(), JAIL, filter);
        let err = load(&base, Path::new("/tmp/decisions.log"))
            .expect_err("filter feature must be rejected");
        assert!(
            err.to_string().contains(needle),
            "expected {needle} in {err}"
        );
    }
}

#[test]
fn rejects_unsafe_record_paths() {
    let tmp = tempfile::tempdir().expect("scratch");
    let base = tree(tmp.path(), JAIL, FILTER);
    for bad in ["decisions.log", "/tmp/a b.log", "/tmp/$(x).log"] {
        assert!(
            load(&base, Path::new(bad)).is_err(),
            "record path {bad:?} must be rejected"
        );
    }
}
