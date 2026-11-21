//! Unit tests for the original-tree compatibility loader.

use std::path::{Path, PathBuf};

use super::{dbfile_of, load};
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
    std::fs::write(
        dir.join("filter.d/nginx-error-common.conf"),
        NGINX_ERROR_COMMON,
    )
    .expect("write nginx-error-common");
    std::fs::write(dir.join("filter.d/nginx-http-auth.conf"), NGINX_HTTP_AUTH)
        .expect("write nginx-http-auth");
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

/// Stock 1.1.1 filter pair bodies (comments removed), so the legacy-engine
/// fixture exercises the real include and conditional-tag machinery.
const NGINX_ERROR_COMMON: &str = concat!(
    "[DEFAULT]\n",
    "logtype = file\n",
    "_daemon = nginx\n",
    "__prefix = <lt_<logtype>/__prefix>\n",
    "__err_type = error\n",
    "__prefix_line = %(__prefix)s\\[%(__err_type)s\\] \\d+#\\d+: \\*\\d+\\s+\n",
    "[lt_file]\n",
    "__prefix = \\s*\n",
    "[lt_short]\n",
    "__prefix = \\s*(?:(?!\\[)\\S+ %(_daemon)s\\[\\d+\\]: [^\\[]*)?\n",
    "[lt_journal]\n",
    "__prefix = %(lt_short/__prefix)s\n",
);

const NGINX_HTTP_AUTH: &str = concat!(
    "[INCLUDES]\n",
    "before = nginx-error-common.conf\n",
    "\n",
    "[Definition]\n",
    "\n",
    "mode = normal\n",
    "\n",
    "__err_type = (?:error|crit)\n",
    "\n",
    "__suffix_line = , client: <ADDR>(?:, (?:server|request|host|referrer): (?:\"[^\"]*\"|\\S*)){0,4}\n",
    "\n",
    "prefregex = ^%(__prefix_line)s<F-CONTENT>.*</F-CONTENT>%(__suffix_line)s\\s*$\n",
    "\n",
    "mdre-auth = ^user \"<F-USER>(?:[^\"]+|.*?)</F-USER>\":? (?:password mismatch|was not found in \"[^\\\"]*\")$\n",
    "            ^(?:PAM: )?user '<F-USER>(?:[^']+|.*?)</F-USER>' - not authenticated: Authentication failure$\n",
    "mdre-fallback = ^SSL_(?:do_handshake|read)\\(\\) failed \\(SSL: error:\\S+(?: \\S+){1,3}[^\\)]*\\)[^,]*\n",
    "\n",
    "mdre-normal = %(mdre-auth)s\n",
    "mdre-aggressive = %(mdre-auth)s\n",
    "                  %(mdre-fallback)s\n",
    "\n",
    "failregex = <mdre-<mode>>\n",
    "\n",
    "ignoreregex = \n",
    "\n",
    "datepattern = {^LN-BEG}\n",
    "journalmatch = _SYSTEMD_UNIT=nginx.service + _COMM=nginx\n",
);

#[test]
fn converts_an_original_jail_into_the_daemon_config() {
    let tmp = tempfile::tempdir().expect("scratch");
    let base = tree(tmp.path(), JAIL, FILTER);
    let record = Path::new("/tmp/decisions.log");
    let config = load(&base, record).expect("load");
    assert_eq!(
        config.global.socket_path,
        PathBuf::from("/tmp/decisions.log.fail2ban-rs/control.sock")
    );
    assert_eq!(
        config.global.state_dir,
        PathBuf::from("/tmp/decisions.log.fail2ban-rs/state")
    );
    assert_eq!(
        dbfile_of(&base).expect("read original database path"),
        PathBuf::from("/run/record-test/state/fail2ban.sqlite3")
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
                "[DEFAULT]\nbackend = bogus\nusedns = no\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "polling",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = yes\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "usedns=",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = maybe\naction =\n",
                "[bad]\nenabled = true\nport = 1\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "invalid ignoreself",
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
                "[bad]\nenabled = true\nport = not-a-real-service-xyz\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
            ),
            "unknown port or service name",
        ),
        (
            concat!(
                "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
                "[bad]\nenabled = true\nport = 8081\nfilter = chain-auth\nlogpath = /tmp/x.log\n",
                "bantime.formula = ban.Time * 2\n",
            ),
            "bantime.formula",
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
fn rejects_custom_pattern_list_date_formats() {
    let tmp = tempfile::tempdir().expect("scratch");
    let base = tree(
        tmp.path(),
        JAIL,
        concat!(
            "[Definition]\n",
            "failregex = ^fail .* from <HOST>\n",
            "datepattern = %%Y %%m %%d\n",
        ),
    );
    let err = load(&base, Path::new("/tmp/decisions.log"))
        .expect_err("unsupported format must be rejected");
    assert!(err.to_string().contains("datepattern"), "{err}");
}

#[test]
fn converts_prefregex_filters_onto_the_legacy_engine() {
    let tmp = tempfile::tempdir().expect("scratch");
    let jail_conf = concat!(
        "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
        "[nginx-class]\nenabled = true\nport = 443\nfilter = nginx-http-auth\n",
        "logpath = /tmp/web3.log\nmaxretry = 3\nfindtime = 120s\nbantime = 4s\n",
    );
    let base = tree(tmp.path(), jail_conf, FILTER);
    let config = load(&base, Path::new("/tmp/decisions.log"))
        .expect("the stock nginx class converts onto the legacy engine");
    let jail = config
        .jail
        .get("nginx-class")
        .expect("legacy jail converted");
    assert!(jail.filter.is_empty(), "patterns run in the legacy engine");
    assert!(jail.ignoreregex.is_empty());
    let legacy = jail
        .legacy_filter
        .as_ref()
        .expect("resolved filter definition is carried through");
    assert!(
        legacy
            .options
            .get("prefregex")
            .expect("prefregex resolved")
            .contains("<F-CONTENT>")
    );
    assert_eq!(
        legacy.options.get("datepattern").map(String::as_str),
        Some("{^LN-BEG}")
    );
    let failregex = legacy
        .options
        .get("failregex")
        .expect("mode substitution applied");
    assert!(failregex.contains("password mismatch"));
    assert!(failregex.contains("not authenticated"));
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

#[test]
#[ignore = "requires the original Fail2Ban 1.1.1 Git checkout (FAIL2BAN_111_SOURCE)"]
fn stock_nginx_filter_with_journalmatch_compiles_in_polling_mode() {
    use std::process::Command;

    let original = std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE");
    let tmp = tempfile::tempdir().expect("scratch");
    let jail_conf = concat!(
        "[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\naction =\n",
        "[nginx-class]\nenabled = true\nport = 443\nfilter = nginx-http-auth\n",
        "logpath = /tmp/web3.log\nmaxretry = 3\nfindtime = 120s\nbantime = 4s\n",
    );
    let base = tree(tmp.path(), jail_conf, FILTER);
    for name in ["nginx-error-common.conf", "nginx-http-auth.conf"] {
        // Read pinned blobs rather than the operator's worktree; the latter
        // might be a local variant missing the journal-only setting.
        let object = format!("f60978618a101427b06924fc932b44350fec2b63:config/filter.d/{name}");
        let blob = Command::new("git")
            .args(["show", &object])
            .current_dir(&original)
            .output()
            .expect("read pinned Git blob");
        assert!(
            blob.status.success(),
            "{}",
            String::from_utf8_lossy(&blob.stderr)
        );
        std::fs::write(base.join("filter.d").join(name), blob.stdout).expect("write stock filter");
    }
    let config = load(&base, &tmp.path().join("decisions.log")).expect("admit stock Nginx");
    let resolved = config
        .jail
        .get("nginx-class")
        .expect("converted jail")
        .legacy_filter
        .as_ref()
        .expect("legacy matcher");
    assert_eq!(
        resolved.options.get("journalmatch").map(String::as_str),
        Some("_SYSTEMD_UNIT=nginx.service + _COMM=nginx")
    );
    let _matcher = crate::detect::legacy_matcher::LegacyMatcher::compile(resolved)
        .expect("compile stock matcher with journal-only metadata");
}

#[test]
#[ignore = "requires the original Fail2Ban 1.1.1 Git checkout (FAIL2BAN_111_SOURCE)"]
#[allow(clippy::indexing_slicing)]
fn stock_upstream_nftables_and_iptables_actions_resolve_cleanly() {
    let source = std::fs::canonicalize(
        std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
    )
    .expect("locate Fail2Ban 1.1.1 source");
    let config_dir = source.join("config");

    let nft = super::resolve_legacy_action(
        &config_dir,
        "sshd",
        "nftables[type=multiport, port=22, protocol=tcp]",
        &["22".into()],
        "tcp",
        600,
    )
    .expect("stock nftables.conf should resolve cleanly");
    let crate::config::Backend::LegacyAction { actions } = nft else {
        panic!("expected LegacyAction");
    };
    assert_eq!(actions.len(), 1);
    assert!(
        actions[0].ipv4.ban.contains("addr-set-sshd") && actions[0].ipv4.ban.contains("<ip>"),
        "unexpected v4 nft ban: {}",
        actions[0].ipv4.ban
    );
    assert!(
        actions[0].ipv6.ban.contains("addr6-set-sshd") && actions[0].ipv6.ban.contains("<ip>"),
        "unexpected v6 nft ban: {}",
        actions[0].ipv6.ban
    );

    let ipt = super::resolve_legacy_action(
        &config_dir,
        "sshd",
        "iptables-multiport[name=sshd, port=22, protocol=tcp]",
        &["22".into()],
        "tcp",
        600,
    )
    .expect("stock iptables-multiport.conf should resolve cleanly");
    let crate::config::Backend::LegacyAction { actions: ipt_acts } = ipt else {
        panic!("expected LegacyAction");
    };
    assert_eq!(ipt_acts.len(), 1);
    assert!(
        ipt_acts[0].ipv4.ban.contains("iptables") && ipt_acts[0].ipv4.ban.contains("<ip>"),
        "unexpected v4 ipt ban: {}",
        ipt_acts[0].ipv4.ban
    );
    assert!(
        ipt_acts[0].ipv6.ban.contains("ip6tables") && ipt_acts[0].ipv6.ban.contains("<ip>"),
        "unexpected v6 ipt ban: {}",
        ipt_acts[0].ipv6.ban
    );
}
