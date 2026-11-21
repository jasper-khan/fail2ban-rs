use super::*;
use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "dropbear",
        "Mar 24 15:25:51 buffalo1 dropbear[4092]: bad password attempt for 'root' from 198.51.100.87:5543",
        "198.51.100.87",
    ),
    (
        "dropbear",
        "Feb 11 15:23:17 dropbear[1252]: login attempt for nonexistent user from ::ffff:198.51.100.215:60495",
        "198.51.100.215",
    ),
    (
        "dropbear",
        "Jul 27 01:04:12 fail2ban-test dropbear[1335]: Bad password attempt for 'root' from 1.2.3.4:60588",
        "1.2.3.4",
    ),
    (
        "dropbear",
        "Jul 27 01:04:22 fail2ban-test dropbear[1335]: Exit before auth (user 'root', 10 fails): Max auth tries reached - user 'root' from 1.2.3.4:60588",
        "1.2.3.4",
    ),
    (
        "dropbear",
        "Jul 10 23:57:29 fail2ban-test dropbear[825]: [825] Jul 10 23:57:29 Exit before auth from <192.0.2.3:52289>: (user 'root', 10 fails): Max auth tries reached - user 'root'",
        "192.0.2.3",
    ),
    (
        "dropbear",
        "Jul 10 23:53:52 fail2ban-test dropbear[825]: [825] Jul 10 23:53:52 Bad password attempt for 'root' from 1.2.3.4:52289",
        "1.2.3.4",
    ),
    (
        "pam-generic",
        "Feb  7 15:10:42 example pure-ftpd: (pam_unix) authentication failure; logname= uid=0 euid=0 tty=pure-ftpd ruser=sample-user rhost=192.168.1.1",
        "192.168.1.1",
    ),
    (
        "pam-generic",
        "May 12 09:47:54 vaio sshd[16004]: (pam_unix) authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=71.13.115.12  user=root",
        "71.13.115.12",
    ),
    (
        "pam-generic",
        "Jul 19 18:11:26 srv2 vsftpd: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=an8767 rhost=10.20.30.40",
        "10.20.30.40",
    ),
    (
        "pam-generic",
        "Nov 25 17:12:13 webmail pop(pam_unix)[4920]: authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=192.168.10.3 user=mailuser",
        "192.168.10.3",
    ),
    (
        "selinux-ssh",
        r#"type=USER_ERR msg=audit(1373330717.000:4070): user pid=12000 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:bad_ident acct="?" exe="/usr/sbin/sshd" hostname=173.242.116.187 addr=173.242.116.187 terminal=ssh res=failed'"#,
        "173.242.116.187",
    ),
    (
        "sshd",
        "Feb 25 14:34:10 belka sshd[31602]: Failed password for invalid user ROOT from 194.117.26.69 port 50273 ssh2",
        "194.117.26.69",
    ),
    (
        "sshd",
        "Feb 25 14:34:10 belka sshd[31603]: Failed password for invalid user ROOT from aaaa:bbbb:cccc:1234::1:1 port 50273 ssh2",
        "aaaa:bbbb:cccc:1234::1:1",
    ),
    (
        "sshd",
        "Jul 20 14:42:12 localhost sshd[22708]: Invalid user ftp from 192.0.2.2 port 37220",
        "192.0.2.2",
    ),
    (
        "sshd",
        "Sep 29 16:28:02 spaceman sshd[16699]: Failed password for dan from 127.0.0.1 port 45416 ssh1",
        "127.0.0.1",
    ),
    (
        "sshd",
        "Nov 21 00:00:01 example sshd-session[17]: Illegal user demo from 192.0.2.10",
        "192.0.2.10",
    ),
    (
        "sshd",
        "Nov 21 00:00:02 example sshd[17]: Failed publickey for invalid user demo from 2001:db8::10 port 22 ssh2: ED25519 SHA256:example",
        "2001:db8::10",
    ),
    (
        "sshd",
        "Nov 21 00:00:03 example sshd[17]: Failed keyboard-interactive/pam for demo from 192.0.2.12 ssh2",
        "192.0.2.12",
    ),
    (
        "sshd",
        "Nov 21 00:00:04 example sshd[17]: error: maximum authentication attempts exceeded for demo from 192.0.2.13 port 22 ssh2 [preauth]",
        "192.0.2.13",
    ),
    (
        "sshd",
        "Nov 21 00:00:05 example sshd[17]: User demo from 192.0.2.14 not allowed because not listed in AllowUsers",
        "192.0.2.14",
    ),
    (
        "sshd",
        "Nov 21 00:00:06 example sshd[17]: User demo 192.0.2.15 not allowed because none of user's groups are listed in AllowGroups",
        "192.0.2.15",
    ),
    (
        "sshd",
        "2026-11-21T00:00:07Z example sshd[17]: error: PAM: Authentication failure for demo from 192.0.2.16",
        "192.0.2.16",
    ),
    (
        "sshd",
        "sshd[17]: ROOT LOGIN REFUSED FROM 192.0.2.17",
        "192.0.2.17",
    ),
    (
        "sshd",
        "sshd[17]: fatal: User not known to the underlying authentication module for demo 192.0.2.18",
        "192.0.2.18",
    ),
    (
        "sshd",
        "sshd[17]: Failed password for demo.example from 2001:db8::19 port 22 on 192.0.2.100 ssh2",
        "2001:db8::19",
    ),
];

/// (filter_name, log_line) rows that must NOT match.
const NO_MATCH_CASES: &[(&str, &str)] = &[
    (
        "sshd",
        "Nov 21 00:00:08 example sshd[17]: Failed publickey for demo from 192.0.2.20 port 22 ssh2: ED25519 SHA256:example",
    ),
    (
        "sshd",
        "Nov 21 00:00:09 example sshd[17]: Disconnected from authenticating user demo 192.0.2.21 port 22 [preauth]",
    ),
    (
        "sshd",
        "Nov 21 00:00:10 example sshd[17]: Connection closed by authenticating user demo 192.0.2.22 port 22 [preauth]",
    ),
    (
        "sshd",
        "Nov 21 00:00:11 example unexpected-sshd[17]: Failed password for demo from 192.0.2.23 port 22",
    ),
    (
        "sshd",
        "Nov 21 00:00:12 example system-audit[17]: sshd[17]: Failed password for demo from 192.0.2.24 port 22",
    ),
    (
        "sshd",
        "Nov 21 00:00:13 example sshd[17]: Failed password for demo from 192.0.2.25x",
    ),
    (
        "sshd",
        "Oct 15 19:51:35 server sshd[7592]: Address 1.2.3.4 maps to 1234.bbbbbb.com, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!",
    ),
    (
        "sshd",
        "Apr 24 01:39:19 host sshd[3719]: User root not allowed because account is locked",
    ),
    (
        "sshd",
        "Feb 12 04:09:18 localhost sshd[26713]: Connection from 115.249.163.77 port 51353",
    ),
    (
        "sshd",
        "Nov 28 09:16:03 srv sshd[32307]: Accepted publickey for git from 192.0.2.1 port 57904 ssh2: DSA 36:48:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx",
    ),
];

#[test]
fn match_samples() {
    for &(name, line, ip) in MATCH_CASES {
        assert_filter_matches(name, line, ip);
    }
}

#[test]
fn no_match_samples() {
    for &(name, line) in NO_MATCH_CASES {
        assert_filter_no_match(name, line);
    }
}

/// Every sample row targets a filter that lives in this category's table.
#[test]
fn cases_target_this_category() {
    let names: std::collections::HashSet<&str> = FILTERS.iter().map(|f| f.name).collect();
    for &(name, ..) in MATCH_CASES {
        assert!(
            names.contains(name),
            "match case for '{name}' is not in this category"
        );
    }
    for &(name, ..) in NO_MATCH_CASES {
        assert!(
            names.contains(name),
            "no-match case for '{name}' is not in this category"
        );
    }
}
