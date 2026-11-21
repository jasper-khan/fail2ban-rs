//! Offline projection of the original Fail2Ban 1.1.1 read-only client.
//!
//! Input is an already split command argv, without a program name or global
//! options. Only specified ping, status and ban queries can reach a
//! caller-owned fake transport. There is no command execution, socket, pickle, or service
//! integration in this module.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::legacy_client_bans::Banned;
use crate::legacy_client_render::{self as render, JailStatus, StatusFlavor};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ClientRequest<'a> {
    /// `argument` preserves the sent argv token. No token means the default
    /// timeout; the explicit `-1` value also asks the original to keep it.
    Ping {
        argument: Option<&'a str>,
        timeout: Option<f64>,
    },
    Status(StatusTarget<'a>),
    GetBanIp {
        jail: &'a str,
        separator: Option<&'a str>,
    },
    /// No jail means a global query. Empty identifiers mean list, rather than
    /// membership. Nonempty identifiers preserve the already checked argv.
    Banned {
        jail: Option<&'a str>,
        ids: &'a [&'a str],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusTarget<'a> {
    Global,
    Jail {
        name: &'a str,
        flavor: Option<&'a str>,
    },
    All {
        flavor: Option<&'a str>,
    },
}

#[derive(Debug)]
pub(crate) enum ClientReply {
    Pong(String),
    GlobalStatus(Vec<String>),
    JailStatus(JailStatus),
    AllStatus(Vec<JailStatus>),
    BanIps(Vec<IpAddr>),
    Banned(Banned),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServerError {
    UnknownJail(String),
    /// Original IndexError with one argument.
    InvalidCommand(String),
    /// Original generic server rejection with one argument.
    Message(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientError {
    Server(ServerError),
    /// Already-normalized semantic log message; no path check is performed.
    Transport(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientOutput {
    pub(crate) stdout: String,
    /// Logger message only, excluding timestamp, process ID and log prefix.
    pub(crate) stderr: String,
    pub(crate) exit_code: u8,
}

const FAILURE: u8 = 255;

impl ClientOutput {
    fn failure(stdout: String, stderr: String) -> Self {
        Self {
            stdout,
            stderr,
            exit_code: FAILURE,
        }
    }

    fn local_error(message: &str) -> Self {
        Self::failure(String::new(), format!("{message}\n"))
    }
}

/// Project one whitelisted command and format its typed fake response.
pub(crate) fn dispatch<'a>(
    argv: &'a [&'a str],
    exchange: impl FnOnce(ClientRequest<'a>) -> Result<ClientReply, ClientError>,
) -> ClientOutput {
    let request = match parse(argv) {
        Ok(request) => request,
        Err(message) => return ClientOutput::local_error(&message),
    };
    match exchange(request) {
        Ok(reply) => match success(request, reply) {
            Some(stdout) => ClientOutput {
                stdout,
                stderr: String::new(),
                exit_code: 0,
            },
            None => ClientOutput::local_error("unexpected reply for offline client command"),
        },
        Err(ClientError::Server(error)) => server_failure(error),
        Err(ClientError::Transport(message)) => ClientOutput::local_error(&message),
    }
}

fn parse<'a>(argv: &'a [&'a str]) -> Result<ClientRequest<'a>, String> {
    match argv {
        ["ping"] => Ok(ClientRequest::Ping {
            argument: None,
            timeout: None,
        }),
        ["ping", argument] => parse_ping(argument),
        ["status"] => Ok(ClientRequest::Status(StatusTarget::Global)),
        ["status", target] => parse_status(target, None),
        ["status", target, flavor] => parse_status(target, Some(flavor)),
        ["get", jail, "banip"] => parse_banip(jail, None),
        ["get", jail, "banip", separator] => parse_banip(jail, Some(separator)),
        ["get", jail, "banned", ids @ ..] => parse_banned(Some(jail), ids),
        ["banned", ids @ ..] => parse_banned(None, ids),
        _ => Err("unsupported offline client command".to_owned()),
    }
}

#[allow(clippy::float_cmp)] // The original uses exact -1 as a timeout flag.
fn parse_ping(argument: &str) -> Result<ClientRequest<'_>, String> {
    let timeout = argument
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("could not convert string to float: {}", quoted(argument)))?;
    if !timeout.is_finite() || (timeout < 0.0 && timeout != -1.0) {
        return Err("unsupported offline ping timeout".to_owned());
    }
    Ok(ClientRequest::Ping {
        argument: Some(argument),
        timeout: Some(timeout),
    })
}

fn parse_status<'a>(target: &'a str, flavor: Option<&'a str>) -> Result<ClientRequest<'a>, String> {
    if status_flavor(flavor).is_none() || (target == "--all" && flavor == Some("short")) {
        return Err("unsupported offline status flavor".to_owned());
    }
    match target {
        "" => Err("expected an offline status jail name".to_owned()),
        "--all" => Ok(ClientRequest::Status(StatusTarget::All { flavor })),
        name => Ok(ClientRequest::Status(StatusTarget::Jail { name, flavor })),
    }
}

fn status_flavor(flavor: Option<&str>) -> Option<StatusFlavor> {
    match flavor {
        None | Some("basic") => Some(StatusFlavor::Basic),
        Some("short") => Some(StatusFlavor::Short),
        _ => None,
    }
}

fn parse_banip<'a>(jail: &'a str, separator: Option<&'a str>) -> Result<ClientRequest<'a>, String> {
    validate_query_jail(jail)?;
    if separator == Some("--with-time") {
        return Err("offline banip --with-time is not supported".to_owned());
    }
    Ok(ClientRequest::GetBanIp { jail, separator })
}

fn parse_banned<'a>(
    jail: Option<&'a str>,
    ids: &'a [&'a str],
) -> Result<ClientRequest<'a>, String> {
    if let Some(jail) = jail {
        validate_query_jail(jail)?;
    }
    if ids.iter().any(|id| id.parse::<IpAddr>().is_err()) {
        return Err("offline banned queries require IPv4 or IPv6 host literals".to_owned());
    }
    Ok(ClientRequest::Banned { jail, ids })
}

fn validate_query_jail(jail: &str) -> Result<(), String> {
    // The original transmitter treats these names as its global get
    // selectors instead of jail names, even when more arguments follow.
    if jail.is_empty()
        || matches!(
            jail,
            "loglevel"
                | "logtarget"
                | "syslogsocket"
                | "thread"
                | "dbfile"
                | "dbmaxmatches"
                | "dbpurgeage"
        )
    {
        Err("expected an offline ban query jail name".to_owned())
    } else {
        Ok(())
    }
}

fn banned_shape(jail: Option<&str>, ids: &[&str], reply: &Banned) -> bool {
    match (jail.is_some(), ids.len(), reply) {
        (false, 0, Banned::Jails(_)) | (true, 0, Banned::Addresses(_)) => true,
        (false, n, Banned::ByAddress(matches)) if n > 0 => matches.len() == n,
        (true, 1, Banned::Membership(value)) => *value <= 1,
        (true, n, Banned::Memberships(values)) if n > 1 => {
            values.len() == n && values.iter().all(|&value| value <= 1)
        }
        _ => false,
    }
}

fn success(request: ClientRequest<'_>, reply: ClientReply) -> Option<String> {
    match (request, reply) {
        (ClientRequest::Ping { .. }, ClientReply::Pong(response)) => Some(render::ping(&response)),
        (ClientRequest::Status(StatusTarget::Global), ClientReply::GlobalStatus(jails)) => {
            Some(render::status(&jails))
        }
        (
            ClientRequest::Status(StatusTarget::Jail { name, flavor }),
            ClientReply::JailStatus(jail),
        ) if name == jail.name => Some(render::status_jail(&jail, status_flavor(flavor)?)),
        (ClientRequest::Status(StatusTarget::All { flavor }), ClientReply::AllStatus(jails)) => {
            Some(render::status_all(&jails, status_flavor(flavor)?))
        }
        (ClientRequest::GetBanIp { separator, .. }, ClientReply::BanIps(addresses)) => {
            Some(render::banip(&addresses, separator))
        }
        (ClientRequest::Banned { jail, ids }, ClientReply::Banned(results))
            if banned_shape(jail, ids, &results) =>
        {
            Some(render::banned(&results))
        }
        _ => None,
    }
}

fn server_failure(error: ServerError) -> ClientOutput {
    let (stdout, arg) = match error {
        ServerError::UnknownJail(name) => (render::unknown_jail(&name), name),
        ServerError::InvalidCommand(message) => {
            ("Sorry but the command is invalid\n".to_owned(), message)
        }
        ServerError::Message(message) => (format!("{message}\n"), message),
    };
    ClientOutput::failure(stdout, format!("NOK: ({},)\n", quoted(&arg)))
}

// Quotes typical single-string exception arguments like Python repr, without
// modeling the surrounding logger's process/time formatting.
pub(crate) fn quoted(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::new();
    result.push(quote);
    for c in text.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c == quote => {
                result.push('\\');
                result.push(c);
            }
            c if c.is_control() => {
                let _ = write!(result, "\\x{:02x}", u32::from(c));
            }
            c => result.push(c),
        }
    }
    result.push(quote);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_client_render::StatusSource;

    fn jail() -> JailStatus {
        JailStatus {
            name: "sshd".to_owned(),
            currently_failed: 0,
            total_failed: 4,
            source: StatusSource::Files(vec!["/var/log/auth.log".to_owned()]),
            currently_banned: 1,
            total_banned: 2,
            banned_ips: vec!["192.0.2.44".to_owned()],
        }
    }

    #[test]
    fn ping_success_and_timeout_are_observable_to_fake_transport() {
        for (argv, expected) in [
            (
                &["ping"][..],
                ClientRequest::Ping {
                    argument: None,
                    timeout: None,
                },
            ),
            (
                &["ping", "0.25"][..],
                ClientRequest::Ping {
                    argument: Some("0.25"),
                    timeout: Some(0.25),
                },
            ),
            (
                &["ping", "-1"][..],
                ClientRequest::Ping {
                    argument: Some("-1"),
                    timeout: Some(-1.0),
                },
            ),
        ] {
            let output = dispatch(argv, |request| {
                assert_eq!(request, expected);
                Ok(ClientReply::Pong("pong".to_owned()))
            });
            assert_eq!(
                output,
                ClientOutput {
                    stdout: "Server replied: pong\n".to_owned(),
                    stderr: String::new(),
                    exit_code: 0
                }
            );
        }
    }

    #[test]
    fn typed_status_requests_route_distinct_replies() {
        let names = vec!["sshd".to_owned()];
        let output = dispatch(&["status"], |request| {
            assert_eq!(request, ClientRequest::Status(StatusTarget::Global));
            Ok(ClientReply::GlobalStatus(names.clone()))
        });
        assert_eq!(output.stdout, render::status(&names));
        assert_eq!(output.exit_code, 0);

        let detail = jail();
        let output = dispatch(&["status", "sshd"], |request| {
            assert_eq!(
                request,
                ClientRequest::Status(StatusTarget::Jail {
                    name: "sshd",
                    flavor: None
                })
            );
            Ok(ClientReply::JailStatus(jail()))
        });
        assert_eq!(
            output.stdout,
            render::status_jail(&detail, StatusFlavor::Basic)
        );
        assert_eq!(output.exit_code, 0);

        let output = dispatch(&["status", "--all", "basic"], |request| {
            assert_eq!(
                request,
                ClientRequest::Status(StatusTarget::All {
                    flavor: Some("basic")
                })
            );
            Ok(ClientReply::AllStatus(vec![jail()]))
        });
        assert_eq!(
            output.stdout,
            render::status_all(&[detail], StatusFlavor::Basic)
        );
        assert_eq!(output.exit_code, 0);
    }

    #[test]
    fn short_jail_status_uses_the_requested_jail_and_omits_ban_list() {
        let output = dispatch(&["status", "sshd", "short"], |request| {
            assert_eq!(
                request,
                ClientRequest::Status(StatusTarget::Jail {
                    name: "sshd",
                    flavor: Some("short")
                })
            );
            Ok(ClientReply::JailStatus(jail()))
        });
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.starts_with(
            "Status for the jail: sshd
"
        ));
        assert!(!output.stdout.contains("Banned IP list"));

        let mismatched = dispatch(&["status", "different"], |_| {
            Ok(ClientReply::JailStatus(jail()))
        });
        assert_eq!(mismatched.exit_code, FAILURE);
        assert!(mismatched.stdout.is_empty());
    }

    #[test]
    fn failures_keep_stdout_and_stderr_separate() {
        for (error, stdout, stderr) in [
            (
                ClientError::Server(ServerError::UnknownJail("missing".to_owned())),
                "Sorry but the jail 'missing' does not exist\n",
                "NOK: ('missing',)\n",
            ),
            (
                ClientError::Server(ServerError::InvalidCommand("invalid command".to_owned())),
                "Sorry but the command is invalid\n",
                "NOK: ('invalid command',)\n",
            ),
            (
                ClientError::Server(ServerError::Message("request wasn't found".to_owned())),
                "request wasn't found\n",
                "NOK: (\"request wasn't found\",)\n",
            ),
            (
                ClientError::Transport("Fixture unavailable".to_owned()),
                "",
                "Fixture unavailable\n",
            ),
        ] {
            let output = dispatch(&["status", "missing"], |_| Err(error));
            assert_eq!(
                output,
                ClientOutput {
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                    exit_code: FAILURE
                }
            );
        }
    }

    #[test]
    fn unsupported_commands_and_timeouts_do_not_reach_fake_transport() {
        for argv in [
            &[][..],
            &["stop"][..],
            &["status", "sshd", "cymru"][..],
            &["status", "--all", "short"][..],
            &["ping", "invalid"][..],
            &["ping", "-2"][..],
            &["ping", "1", "extra"][..],
        ] {
            let mut calls = 0;
            let output = dispatch(argv, |_| {
                calls += 1;
                Ok(ClientReply::Pong("pong".to_owned()))
            });
            assert_eq!(calls, 0);
            assert_eq!(output.exit_code, FAILURE);
            assert!(output.stdout.is_empty());
        }
    }

    #[test]
    fn banip_preserves_separator_and_fake_reply_order() {
        let address1 = IpAddr::from([192, 0, 2, 8]);
        let address2 = IpAddr::from([192, 0, 2, 1]);
        let output = dispatch(&["get", "sshd", "banip", " | "], |request| {
            assert_eq!(
                request,
                ClientRequest::GetBanIp {
                    jail: "sshd",
                    separator: Some(" | ")
                }
            );
            Ok(ClientReply::BanIps(vec![address1, address2]))
        });
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "192.0.2.8 | 192.0.2.1\n");

        let output = dispatch(&["get", "sshd", "banip"], |request| {
            assert_eq!(
                request,
                ClientRequest::GetBanIp {
                    jail: "sshd",
                    separator: None
                }
            );
            Ok(ClientReply::BanIps(Vec::new()))
        });
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "\n");
    }

    #[test]
    fn banned_query_checks_scope_and_preserves_duplicate_identifiers() {
        let output = dispatch(&["banned"], |request| {
            assert_eq!(
                request,
                ClientRequest::Banned {
                    jail: None,
                    ids: &[]
                }
            );
            Ok(ClientReply::Banned(Banned::Jails(vec![(
                "sshd".to_owned(),
                vec![IpAddr::from([192, 0, 2, 9])],
            )])))
        });
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "[{'sshd': ['192.0.2.9']}]\n");
        let output = dispatch(&["banned", "192.0.2.9"], |request| {
            assert_eq!(
                request,
                ClientRequest::Banned {
                    jail: None,
                    ids: &["192.0.2.9"]
                }
            );
            Ok(ClientReply::Banned(Banned::ByAddress(vec![vec![
                "sshd".to_owned(),
            ]])))
        });
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "[['sshd']]\n");

        let argv = [
            "get",
            "sshd",
            "banned",
            "2001:0db8::1",
            "192.0.2.9",
            "2001:0db8::1",
        ];
        let output = dispatch(&argv, |request| {
            assert_eq!(
                request,
                ClientRequest::Banned {
                    jail: Some("sshd"),
                    ids: &["2001:0db8::1", "192.0.2.9", "2001:0db8::1"]
                }
            );
            Ok(ClientReply::Banned(Banned::Memberships(vec![0, 1, 0])))
        });
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "[0, 1, 0]\n");
        let scalar = dispatch(&["get", "sshd", "banned", "192.0.2.9"], |_| {
            Ok(ClientReply::Banned(Banned::Membership(1)))
        });
        assert_eq!(scalar.exit_code, 0);
        assert_eq!(scalar.stdout, "1\n");
    }

    #[test]
    fn unsupported_ban_queries_and_invalid_response_shapes_fail_closed() {
        for argv in [
            &["get", "sshd", "banip", "--with-time"][..],
            &["get", "sshd", "banip", ",", "extra"][..],
            &["get", "sshd", "banned", "192.0.2.0/24"][..],
            &["get", "loglevel", "banned"][..],
            &["banned", "example.test"][..],
            &["set", "sshd", "banip", "192.0.2.1"][..],
        ] {
            let mut calls = 0;
            let result = dispatch(argv, |_| {
                calls += 1;
                Ok(ClientReply::BanIps(Vec::new()))
            });
            assert_eq!(calls, 0);
            assert_eq!(result.exit_code, FAILURE);
        }
        let inconsistent = dispatch(&["get", "sshd", "banned", "192.0.2.1"], |_| {
            Ok(ClientReply::Banned(Banned::Memberships(vec![1])))
        });
        assert_eq!(inconsistent.exit_code, FAILURE);
        let invalid_flag = dispatch(&["get", "sshd", "banned", "192.0.2.1"], |_| {
            Ok(ClientReply::Banned(Banned::Membership(2)))
        });
        assert_eq!(invalid_flag.exit_code, FAILURE);
    }

    #[test]
    fn mismatched_typed_reply_is_an_offline_failure() {
        let output = dispatch(&["status", "--all"], |_| {
            Ok(ClientReply::Pong("pong".to_owned()))
        });
        assert_eq!(output.exit_code, FAILURE);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.contains("unexpected reply"));
    }
}
