//! Offline recognition of a narrow set of normal-mode OpenSSH log records.
//!
//! This is not a replacement for the stock filter's syntax or all of its
//! branches. It recognizes the ordinary login/session records used to test
//! Fail2Ban 1.1.1's `mode=normal, publickey=nofail, usedns=no` behavior.
//! The separate session tracker decides whether a record yields a failure.

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;

use super::extract::normalize_mapped;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event<'a> {
    Connected {
        address: IpAddr,
    },
    Context {
        address: IpAddr,
        user: Option<&'a str>,
    },
    Failed {
        address: Option<IpAddr>,
        user: Option<&'a str>,
    },
    Accepted {
        address: IpAddr,
        user: &'a str,
    },
    Disconnected {
        address: IpAddr,
        user: Option<&'a str>,
    },
    FailedAndDisconnected {
        address: IpAddr,
        user: Option<&'a str>,
    },
}

#[derive(Clone, Copy)]
enum Rule {
    Connect,
    FailedAuth,
    InvalidUser,
    DirectAuth,
    AttemptsWithAddress,
    PamHelper,
    Locked,
    TooMany,
    Accepted,
    Disconnect,
    DisconnectCode11,
    DisconnectAuth,
}

macro_rules! address {
    () => {
        concat!(
            r"(?P<address>\[?(?:::ffff:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|",
            r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|",
            r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){1,7})\]?)"
        )
    };
}

macro_rules! transport {
    () => {
        r"(?: (?:port [0-9]+|on \S+)){0,2}"
    };
}

macro_rules! suffix {
    () => {
        r"(?: (?:port [0-9]+|on \S+|\[preauth\])){0,3}[ \t]*$"
    };
}

const RULES: &[(Rule, &str)] = &[
    (
        Rule::Connect,
        concat!(r"^Connection from ", address!(), r"(?:[ \t]|$)"),
    ),
    (
        Rule::FailedAuth,
        concat!(
            r"^Failed (?P<method>\S+) for (?:(?P<invalid>invalid user) )?(?P<user>[^\s:]+) from ",
            address!(),
            transport!(),
            r"(?: ssh[0-9]*)?(?:: [^\r\n]*|(?: \[preauth\])?[ \t]*)$"
        ),
    ),
    (
        Rule::InvalidUser,
        concat!(
            r"^[Ii](?:llegal|nvalid) user (?P<user>[^\s:]+) (?:from )?",
            address!(),
            suffix!()
        ),
    ),
    (
        Rule::DirectAuth,
        concat!(
            r"^[Aa]uthentication (?:failure|error|failed) for (?P<user>[^\s:]+) (?:from )?",
            address!(),
            r"(?: via \S+)?",
            suffix!()
        ),
    ),
    (
        Rule::AttemptsWithAddress,
        concat!(
            r"^maximum authentication attempts exceeded for (?:invalid user )?(?P<user>[^\s:]+) (?:from )?",
            address!(),
            transport!(),
            r"(?: ssh[0-9]*)?",
            suffix!()
        ),
    ),
    (
        Rule::PamHelper,
        concat!(
            r"^pam_[a-z]+\(sshd:auth\):[ \t]+authentication failure;",
            r"(?:[ \t]+(?:logname|e?uid|tty)=\S*){0,4}[ \t]+ruser=(?P<alt_user>\S*)[ \t]+rhost=",
            address!(),
            r"(?:[ \t]+user=(?P<user>\S*))?",
            suffix!()
        ),
    ),
    (
        Rule::Locked,
        concat!(
            r"^User (?P<user>[^\s:]+) not allowed because account is locked",
            suffix!()
        ),
    ),
    (
        Rule::TooMany,
        concat!(
            r"^Disconnecting: Too many authentication failures(?: for (?P<user>[^\s:]+))?",
            suffix!()
        ),
    ),
    (
        Rule::Accepted,
        concat!(
            r"^Accepted \w+ for (?P<user>\S+) from ",
            address!(),
            r"(?:[ \t]|$)"
        ),
    ),
    (
        Rule::Disconnect,
        concat!(
            r"^(?:Connection (?:closed|reset)|Disconnect(?:ed|ing))(?: (?:by|from))?",
            r"(?: (?:invalid|authenticating) user (?P<user>\S+))?(?: from)? ",
            address!(),
            transport!(),
            r"(?:: (?P<reason>[^\[]+?))?(?: \[preauth\])?[ \t]*$"
        ),
    ),
    (
        Rule::DisconnectAuth,
        concat!(
            r"^Received disconnect from ",
            address!(),
            transport!(),
            r":[ \t]*3: .*: Auth fail",
            suffix!()
        ),
    ),
    (
        Rule::DisconnectCode11,
        concat!(
            r"^Received disconnect from ",
            address!(),
            transport!(),
            r":[ \t]*11:"
        ),
    ),
];

static COMPILED: LazyLock<Result<Vec<(Rule, Regex)>, regex::Error>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|&(rule, pattern)| Regex::new(pattern).map(|regex| (rule, regex)))
        .collect()
});

const MAX_BODY_BYTES: usize = 8 * 1024;

/// Classify one timestamp- and daemon-prefix-free OpenSSH log record.
pub(super) fn classify(message: &str) -> Option<Event<'_>> {
    if message.len() > MAX_BODY_BYTES || message.contains(['\n', '\r', '\0']) {
        return None;
    }
    let message = ["error: PAM: ", "fatal: PAM: ", "error: ", "fatal: "]
        .into_iter()
        .find_map(|prefix| message.strip_prefix(prefix))
        .unwrap_or(message);
    let compiled = COMPILED.as_ref().ok()?;
    let (rule, captures) = compiled
        .iter()
        .find_map(|(rule, regex)| regex.captures(message).map(|captures| (rule, captures)))?;
    let optional = |name| {
        captures
            .name(name)
            .map(|capture| capture.as_str())
            .filter(|value| !value.is_empty())
    };
    let address = || parse_ip(optional("address")?);
    let user = optional("user");
    match rule {
        Rule::Connect => Some(Event::Connected {
            address: address()?,
        }),
        Rule::FailedAuth
            if optional("method") == Some("publickey") && optional("invalid").is_none() =>
        {
            Some(Event::Context {
                address: address()?,
                user,
            })
        }
        Rule::FailedAuth | Rule::InvalidUser | Rule::DirectAuth | Rule::AttemptsWithAddress => {
            Some(Event::Failed {
                address: Some(address()?),
                user,
            })
        }
        Rule::Locked | Rule::TooMany => Some(Event::Failed {
            address: None,
            user,
        }),
        Rule::PamHelper => Some(Event::Context {
            address: address()?,
            user: user.or_else(|| optional("alt_user")),
        }),
        Rule::Accepted => Some(Event::Accepted {
            address: address()?,
            user: user?,
        }),
        Rule::Disconnect
            if optional("reason")
                .is_some_and(|reason| reason.starts_with("Too many authentication failures")) =>
        {
            None
        }
        Rule::Disconnect | Rule::DisconnectCode11 => Some(Event::Disconnected {
            address: address()?,
            user,
        }),
        Rule::DisconnectAuth => Some(Event::FailedAndDisconnected {
            address: address()?,
            user,
        }),
    }
}

fn parse_ip(raw: &str) -> Option<IpAddr> {
    let token = raw
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(raw);
    token.parse().ok().map(normalize_mapped)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn recognizes_login_failures_and_distinguishes_publickey_context() {
        let address = ip("192.0.2.11");
        for line in [
            "Failed password for alice from 192.0.2.11 port 23009 ssh2",
            "Failed password for invalid user alice from 192.0.2.11 port 23009 ssh2",
            "Failed publickey for invalid user alice from 192.0.2.11 port 23009 ssh2",
            "Invalid user alice from 192.0.2.11 port 23009",
            "error: PAM: Authentication failure for alice from 192.0.2.11",
            "maximum authentication attempts exceeded for alice from 192.0.2.11 port 23009 ssh2 [preauth]",
        ] {
            assert_eq!(
                classify(line),
                Some(Event::Failed {
                    address: Some(address),
                    user: Some("alice"),
                }),
                "{line}"
            );
        }
        assert_eq!(
            classify("Failed publickey for alice from 192.0.2.11 port 23009 ssh2"),
            Some(Event::Context {
                address,
                user: Some("alice"),
            })
        );
    }

    #[test]
    fn recognizes_connection_and_pam_context_by_explicit_source() {
        let address = ip("2001:db8::7");
        assert_eq!(
            classify("Connection from [2001:db8::7] port 23009 on 198.51.100.4 port 22"),
            Some(Event::Connected { address })
        );
        let pam = "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser=remote rhost=2001:db8::7 user=alice";
        assert_eq!(
            classify(pam),
            Some(Event::Context {
                address,
                user: Some("alice"),
            })
        );
        assert_eq!(
            classify(pam.strip_suffix(" user=alice").unwrap()),
            Some(Event::Context {
                address,
                user: Some("remote"),
            })
        );
    }

    #[test]
    fn addressless_failures_need_context_from_the_tracker() {
        for line in [
            "User alice not allowed because account is locked",
            "Disconnecting: Too many authentication failures for alice [preauth]",
        ] {
            assert_eq!(
                classify(line),
                Some(Event::Failed {
                    address: None,
                    user: Some("alice"),
                })
            );
        }
        assert_eq!(
            classify("Disconnecting: Too many authentication failures [preauth]"),
            Some(Event::Failed {
                address: None,
                user: None,
            })
        );
    }

    #[test]
    fn recognizes_gain_and_non_failure_disconnect() {
        let address = ip("192.0.2.11");
        assert_eq!(
            classify("Accepted password for alice from ::ffff:192.0.2.11 port 23009 ssh2"),
            Some(Event::Accepted {
                address,
                user: "alice",
            })
        );
        assert_eq!(
            classify("Disconnected from authenticating user alice 192.0.2.11 port 23009 [preauth]"),
            Some(Event::Disconnected {
                address,
                user: Some("alice"),
            })
        );
        for line in [
            "Connection closed by 192.0.2.11 port 23009 [preauth]",
            "Received disconnect from 192.0.2.11 port 23009:11: disconnected by user",
        ] {
            assert_eq!(
                classify(line),
                Some(Event::Disconnected {
                    address,
                    user: None,
                })
            );
        }
        assert_eq!(
            classify(
                "Received disconnect from 192.0.2.11 port 23009:3: SSH service: Auth fail [preauth]"
            ),
            Some(Event::FailedAndDisconnected {
                address,
                user: None,
            })
        );
    }

    #[test]
    fn ignores_unrecognized_lines_and_invalid_addresses_without_fallback() {
        for line in [
            "Connection from example.test port 23009",
            "Connection from 192.0.2.999 port 23009 on 198.51.100.4 port 22",
            "Connection from [2001:db8::7 port 23009",
            "Failed password for alice from 192.0.2.11 port 23009 ssh2\nextra line",
            "Connection closed by 192.0.2.11 port 23009: Too many authentication failures [preauth]",
            "Did not receive identification string from 192.0.2.11",
        ] {
            assert_eq!(classify(line), None, "{line}");
        }
    }
}
