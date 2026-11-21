//! Built-in filter definitions for authentication / SSH.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "auth_test.rs"]
mod auth_test;

// Fail2Ban 1.1.1's sshd normal-mode, publickey=nofail: keep direct
// failures that identify an IP on this record. Context-only NOFAIL lines
// (including ordinary disconnects, successful auth and PAM helper messages)
// must not count. The line matcher cannot recover an IP from older PID context.
macro_rules! ssh_failure {
    ($($fragment:expr),+ $(,)?) => {
        concat!(
            // Syslog or ISO timestamp, optional host, then the daemon tag.
            r"^\s*(?:(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+)?",
            r"(?:[^:\s]+\s+)?sshd(?:-session)?(?:\[\d+\])?:\s+",
            r"(?:(?:error|fatal): (?:PAM: )?)?",
            $($fragment),+
        )
    };
}

// Fragment spelling follows the upstream port and suffix positions.
macro_rules! ssh_port {
    () => {
        r"(?: (?:port \d+|on \S+)){0,2}"
    };
}

macro_rules! ssh_suffix {
    () => {
        r"(?: (?:port \d+|on \S+|\[preauth\])){0,3}\s*$"
    };
}

macro_rules! ssh_failed_end {
    () => {
        concat!(
            ssh_port!(),
            r"(?: ssh\d*)?(?:: [^\r\n]*|(?: \[preauth\])?)\s*$"
        )
    };
}

const SSHD_NORMAL: &[&str] = &[
    ssh_failure!(
        r"[aA]uthentication (?:failure|error|failed) for .*? (?:from )?(?:<HOST>)",
        r"(?: via \S+)?",
        ssh_suffix!(),
    ),
    ssh_failure!(
        r"User not known to the underlying authentication module for .*? (?:from )?(?:<HOST>)",
        ssh_suffix!(),
    ),
    // Rust regex has no negative lookahead. Accept every non-space method
    // token except the exact word "publickey": lengths other than nine,
    // or a different character at any index of a nine-character token.
    ssh_failure!(
        r"Failed (?:\S{1,8}|\S{10,}|[^p\s]\S{8}|p[^u\s]\S{7}|pu[^b\s]\S{6}|",
        r"pub[^l\s]\S{5}|publ[^i\s]\S{4}|publi[^c\s]\S{3}|public[^k\s]\S{2}|",
        r"publick[^e\s]\S|publicke[^y\s]) for (?:invalid user )?[^:\r\n]+? from (?:<HOST>)",
        ssh_failed_end!(),
    ),
    ssh_failure!(
        r"Failed publickey for invalid user [^:\r\n]+? from (?:<HOST>)",
        ssh_failed_end!(),
    ),
    ssh_failure!(r"ROOT LOGIN REFUSED FROM (?:<HOST>)(?:\s|$)"),
    ssh_failure!(
        r"[iI](?:llegal|nvalid) user .*? (?:from )?(?:<HOST>)",
        ssh_suffix!(),
    ),
    ssh_failure!(
        r"User .*? (?:from )?(?:<HOST>) not allowed because ",
        r"(?:not listed in AllowUsers|listed in DenyUsers|not in any group|",
        r"a group is listed in DenyGroups|none of user\x27s groups are listed in AllowGroups)",
        ssh_suffix!(),
    ),
    ssh_failure!(r"refused connect from \S+ \((?:<HOST>)\)"),
    ssh_failure!(
        r"Received disconnect from (?:<HOST>)",
        ssh_port!(),
        r":\s*3: .*: Auth fail",
        ssh_suffix!(),
    ),
    ssh_failure!(
        r"maximum authentication attempts exceeded for (?:invalid user )?.*? (?:from )?(?:<HOST>)",
        ssh_port!(),
        r"(?: ssh\d*)?",
        ssh_suffix!(),
    ),
    ssh_failure!(
        r"Disconnecting(?: from)?(?: (?:invalid|authenticating))? user \S+ (?:<HOST>)",
        ssh_port!(),
        r":\s*Change of username or service not allowed:\s*.*\[preauth\]\s*$",
    ),
];

/// Filter templates for authentication / SSH.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "dropbear",
        description: "Dropbear SSH authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[
            r"dropbear\[\d+\].*[Bb]ad password attempt for .* from <HOST>:\d+",
            r"dropbear\[\d+\].*[Ll]ogin attempt for nonexistent user.*from <HOST>:\d+",
            r"dropbear\[\d+\].*[Ee]xit before auth.*from .?<HOST>:\d+",
        ],
    },
    FilterTemplate {
        name: "pam-generic",
        description: "Generic PAM authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"pam_unix.*authentication failure;.* rhost=<HOST>"],
    },
    FilterTemplate {
        name: "selinux-ssh",
        description: "SELinux SSH access denials",
        log_path: "/var/log/audit/audit.log",
        date_format: "epoch",
        patterns: &[r"addr=<HOST>.*terminal=ssh.*res=failed"],
    },
    FilterTemplate {
        name: "sshd",
        description: "OpenSSH daemon — normal-mode authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: SSHD_NORMAL,
    },
];
