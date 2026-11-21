//! Offline, synthetic SSH detector comparison. No sshd, client connections,
//! firewall actions, installed jail config, or production logs are used.
//!
//! The comparison below is against upstream Fail2Ban 1.1.1 (normal mode,
//! publickey=nofail, usedns=no), deliberately not a distro or live-jail
//! oracle. These are failure identities emitted by fail2ban-regex, not
//! sessions, threshold transitions, real bans, or report requests. Because
//! this uses syslog-formatted text, it doesn't establish journal cursor,
//! metadata, rotation, PAM session correlation, DNS, or other mode parity.

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use fail2ban_rs::detect::{filters, matcher::JailMatcher};

const UPSTREAM_111: &str = "f60978618a101427b06924fc932b44350fec2b63";
const UPSTREAM_FILTER: &str = "sshd[mode=normal,publickey=nofail]";

struct Case {
    id: &'static str,
    daemon: &'static str,
    messages: &'static [&'static str],
    upstream: &'static [&'static str],
}

// The oracle was recorded one scenario at a time with the pinned upstream
// command in verified_upstream_ssh_111_oracle. The two-line PAM/password
// scenario shares one PID and exercises normal context without a connection.
const CASES: &[Case] = &[
    Case {
        id: "password-ipv4",
        daemon: "sshd",
        messages: &["Failed password for demo from 192.0.2.10 port 55100 ssh2"],
        upstream: &["192.0.2.10"],
    },
    Case {
        id: "password-ipv6",
        daemon: "sshd",
        messages: &["Failed password for invalid user demo from 2001:db8::11 port 55101 ssh2"],
        upstream: &["2001:db8::11"],
    },
    Case {
        id: "invalid-user",
        daemon: "sshd",
        messages: &["Invalid user demo from 192.0.2.12 port 55102"],
        upstream: &["192.0.2.12"],
    },
    Case {
        id: "illegal-user",
        daemon: "sshd",
        messages: &["Illegal user demo from 192.0.2.13 port 55103"],
        upstream: &["192.0.2.13"],
    },
    Case {
        id: "password-without-port",
        daemon: "sshd",
        messages: &["Failed password for demo from 192.0.2.14 ssh2"],
        upstream: &["192.0.2.14"],
    },
    Case {
        id: "sshd-session",
        daemon: "sshd-session",
        messages: &["Failed password for demo from 192.0.2.15 port 55105 ssh2"],
        upstream: &["192.0.2.15"],
    },
    Case {
        id: "publickey-valid-user",
        daemon: "sshd",
        messages: &["Failed publickey for demo from 192.0.2.16 port 55106 ssh2"],
        upstream: &[],
    },
    Case {
        id: "publickey-invalid-user",
        daemon: "sshd",
        messages: &["Failed publickey for invalid user demo from 192.0.2.17 port 55107 ssh2"],
        upstream: &["192.0.2.17"],
    },
    Case {
        id: "keyboard-interactive",
        daemon: "sshd",
        messages: &["Failed keyboard-interactive/pam for demo from 192.0.2.18 port 55108 ssh2"],
        upstream: &["192.0.2.18"],
    },
    Case {
        id: "max-auth",
        daemon: "sshd",
        messages: &[
            "error: maximum authentication attempts exceeded for demo from 192.0.2.19 port 55109 ssh2 [preauth]",
        ],
        upstream: &["192.0.2.19"],
    },
    Case {
        id: "allowusers-policy",
        daemon: "sshd",
        messages: &["User demo from 192.0.2.20 not allowed because not listed in AllowUsers"],
        upstream: &["192.0.2.20"],
    },
    Case {
        id: "denyusers-policy",
        daemon: "sshd",
        messages: &["User demo from 192.0.2.31 not allowed because listed in DenyUsers"],
        upstream: &["192.0.2.31"],
    },
    Case {
        id: "allowgroups-policy",
        daemon: "sshd",
        messages: &[
            "User demo from 2001:db8::32 not allowed because none of user's groups are listed in AllowGroups",
        ],
        upstream: &["2001:db8::32"],
    },
    Case {
        id: "authentication-module-failure",
        daemon: "sshd",
        messages: &["error: PAM: Authentication failure for demo from 192.0.2.33"],
        upstream: &["192.0.2.33"],
    },
    Case {
        id: "underlying-authentication-module-unknown-user",
        daemon: "sshd",
        messages: &[
            "error: PAM: User not known to the underlying authentication module for demo from 192.0.2.34",
        ],
        upstream: &["192.0.2.34"],
    },
    Case {
        id: "refused-connect",
        daemon: "sshd",
        messages: &["refused connect from example.test (192.0.2.35)"],
        upstream: &["192.0.2.35"],
    },
    Case {
        id: "received-auth-fail",
        daemon: "sshd",
        messages: &["Received disconnect from 192.0.2.36 port 55120: 3: Client: Auth fail"],
        upstream: &["192.0.2.36"],
    },
    Case {
        id: "pam-context",
        daemon: "sshd",
        messages: &[
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.21  user=demo",
        ],
        upstream: &[],
    },
    Case {
        id: "pam-plus-password",
        daemon: "sshd",
        messages: &[
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.22  user=demo",
            "Failed password for demo from 192.0.2.22 port 55112 ssh2",
        ],
        upstream: &["192.0.2.22"],
    },
    Case {
        id: "closed-authenticating",
        daemon: "sshd",
        messages: &[
            "Connection closed by authenticating user demo 198.51.100.23 port 55113 [preauth]",
        ],
        upstream: &[],
    },
    Case {
        id: "disconnected-authenticating",
        daemon: "sshd",
        messages: &[
            "Disconnected from authenticating user demo 198.51.100.24 port 55114 [preauth]",
        ],
        upstream: &[],
    },
    Case {
        id: "reset-authenticating",
        daemon: "sshd",
        messages: &[
            "Connection reset by authenticating user demo 198.51.100.25 port 55115 [preauth]",
        ],
        upstream: &[],
    },
    Case {
        id: "accepted-password",
        daemon: "sshd",
        messages: &["Accepted password for demo from 198.51.100.26 port 55116 ssh2"],
        upstream: &[],
    },
    Case {
        id: "accepted-publickey",
        daemon: "sshd",
        messages: &["Accepted publickey for demo from 198.51.100.27 port 55117 ssh2"],
        upstream: &[],
    },
    Case {
        id: "connection-open",
        daemon: "sshd",
        messages: &["Connection from 198.51.100.28 port 55118 on 203.0.113.15 port 22"],
        upstream: &[],
    },
    Case {
        id: "orderly-disconnect",
        daemon: "sshd",
        messages: &["Received disconnect from 198.51.100.29 port 55119:11: disconnected by user"],
        upstream: &[],
    },
    Case {
        id: "other-service",
        daemon: "audit-example",
        messages: &["Accepted audit event for demo at 198.51.100.30"],
        upstream: &[],
    },
];

impl Case {
    fn log(&self) -> String {
        let mut log = String::new();
        for (i, message) in self.messages.iter().enumerate() {
            use std::fmt::Write as _;
            writeln!(
                log,
                "Nov 21 00:00:{i:02} example-host {}[4711]: {message}",
                self.daemon
            )
            .expect("fixture string");
        }
        log
    }
}

fn addresses(lines: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<IpAddr> {
    lines
        .into_iter()
        .map(|line| line.as_ref().parse().expect("fixture or oracle IP"))
        .collect()
}

fn assert_fixture_parity(patterns: &[String], source: &str) {
    let matcher = JailMatcher::new(patterns).expect("build Rust sshd filter");
    for case in CASES {
        let native: Vec<IpAddr> = case
            .log()
            .lines()
            .filter_map(|line| matcher.try_match(line).map(|found| found.ip))
            .collect();
        assert_eq!(native, addresses(case.upstream), "{source}: {}", case.id);
    }
}

#[test]
fn native_normal_ssh_matches_upstream_on_synthetic_logs() {
    let sshd = filters::find("sshd").expect("built-in Rust sshd filter");
    let patterns: Vec<_> = sshd.patterns.iter().map(ToString::to_string).collect();
    assert_fixture_parity(&patterns, "built-in sshd");

    let shipped: toml::Value =
        toml::from_str(include_str!("../config/default.toml")).expect("shipped default TOML");
    let shipped: Vec<_> = shipped
        .get("jail")
        .and_then(|jails| jails.get("sshd"))
        .and_then(|sshd| sshd.get("filter"))
        .and_then(toml::Value::as_array)
        .expect("shipped sshd filter patterns")
        .iter()
        .map(|p| p.as_str().expect("filter pattern").to_owned())
        .collect();
    assert_eq!(shipped, patterns, "keep shipped sshd rules in sync");
    assert_fixture_parity(&shipped, "config/default.toml");
}

fn verify_clean_upstream(dir: &Path) {
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("local git");
        assert!(output.status.success(), "git: {:?}", output.stderr);
        String::from_utf8(output.stdout).expect("git UTF-8")
    };
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), UPSTREAM_111);
    let changes = git(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--ignored=matching",
        "--",
        "config",
        "bin",
        "fail2ban",
    ]);
    // Existing Python cache directories are harmless: the replay below uses
    // a fresh cache prefix and disables writing bytecode. Other local
    // overlays or module modifications would invalidate the oracle.
    assert!(
        changes
            .lines()
            .all(|line| { line.starts_with("!! fail2ban/") && line.ends_with("/__pycache__/") }),
        "upstream parser/config tree must be clean"
    );
}

/// Reproduce the recorded oracle without any package install or service.
/// `FAIL2BAN_111_SOURCE=/path/to/local/upstream cargo test --test sshd_normal_parity -- --ignored`
#[test]
#[ignore = "requires a clean local checkout of pinned upstream Fail2Ban 1.1.1 and Python 3"]
fn verify_upstream_ssh_111_oracle() {
    let checkout = std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE");
    let root = std::fs::canonicalize(checkout).expect("local upstream checkout");
    verify_clean_upstream(&root);
    let temp = tempfile::tempdir().expect("synthetic log directory");
    let log = temp.path().join("fixture.log");
    for case in CASES {
        std::fs::write(&log, case.log()).expect("write generated audit log");
        let output = Command::new("python3")
            .arg("-S")
            .arg(root.join("bin/fail2ban-regex"))
            .arg("-c")
            .arg(root.join("config"))
            .args(["--usedns=no", "--out=ip"])
            .arg(&log)
            .arg(UPSTREAM_FILTER)
            .current_dir(&root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("PYTHONPATH", &root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONPYCACHEPREFIX", temp.path().join("isolated-pycache"))
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .output()
            .expect("run pinned offline regex tool");
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "upstream case {}: {}",
            case.id,
            String::from_utf8_lossy(&output.stderr)
        );
        let data = String::from_utf8(output.stdout).expect("upstream IPs");
        assert_eq!(
            addresses(data.lines()),
            addresses(case.upstream),
            "upstream case {}",
            case.id
        );
    }
}
