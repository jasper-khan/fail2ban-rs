//! Offline projections of original Fail2Ban 1.1.1 read-only ban queries.
//!
//! The caller supplies an ordered snapshot of registered jails and active
//! tickets. These functions do not sweep, check the clock, read settings,
//! connect to a socket, or change any state. This slice accepts canonical,
//! single typed IPs only, not raw failure IDs or networks.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

// Original BanTicket.MAX_TIME is used for ordering permanent tickets.
const PERMANENT_END: i64 = 0x7fff_ffff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActiveBan {
    pub(crate) address: IpAddr,
    /// Original effective Unix end time, or None for a permanent ticket.
    pub(crate) expires_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JailBans<'a> {
    pub(crate) name: &'a str,
    /// Active tickets in their registration order; empty is a known jail.
    pub(crate) bans: &'a [ActiveBan],
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnknownJail(pub(crate) String);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Banned {
    /// Global command without IDs: jail-name and ticket lists in snapshot
    /// order. The original outer list holds one singleton map per jail.
    Jails(Vec<(String, Vec<IpAddr>)>),
    /// Global command with IDs: one jail list per input ID, even for one ID.
    ByAddress(Vec<Vec<String>>),
    /// Jail-scoped command without IDs: ticket insertion order.
    Addresses(Vec<IpAddr>),
    /// Jail-scoped query of one ID: original numeric 1/0, not a boolean.
    Membership(u8),
    /// Jail-scoped query of multiple IDs: one numeric 1/0 per input ID.
    Memberships(Vec<u8>),
}

fn find_jail<'a>(snapshot: &[JailBans<'a>], name: &str) -> Result<JailBans<'a>, UnknownJail> {
    snapshot
        .iter()
        .copied()
        .find(|jail| jail.name == name)
        .ok_or_else(|| UnknownJail(name.to_owned()))
}

/// `get JAIL banip`: sort active tickets by effective end time. The sort must
/// stay stable: ties preserve insertion order rather than sorting by address.
pub(crate) fn get_banip(snapshot: &[JailBans<'_>], jail: &str) -> Result<Vec<IpAddr>, UnknownJail> {
    let mut ordered = find_jail(snapshot, jail)?.bans.to_vec();
    ordered.sort_by_key(|ban| ban.expires_at.unwrap_or(PERMANENT_END));
    Ok(ordered.into_iter().map(|ban| ban.address).collect())
}

/// `banned [IP ...]` or `get JAIL banned [IP ...]`, preserving the original
/// response shape and jail, ban, and request ordering.
pub(crate) fn banned(
    snapshot: &[JailBans<'_>],
    jail: Option<&str>,
    ids: &[IpAddr],
) -> Result<Banned, UnknownJail> {
    if let Some(name) = jail {
        let jail = find_jail(snapshot, name)?;
        return Ok(match ids {
            [] => Banned::Addresses(addresses(jail)),
            [id] => Banned::Membership(u8::from(jail.bans.iter().any(|ban| ban.address == *id))),
            _ => {
                let active: HashSet<_> = jail.bans.iter().map(|ban| ban.address).collect();
                Banned::Memberships(ids.iter().map(|id| u8::from(active.contains(id))).collect())
            }
        });
    }
    if ids.is_empty() {
        return Ok(Banned::Jails(
            snapshot
                .iter()
                .map(|&jail| (jail.name.to_owned(), addresses(jail)))
                .collect(),
        ));
    }

    let mut matched: HashMap<IpAddr, Vec<&str>> = ids.iter().map(|&id| (id, Vec::new())).collect();
    for jail in snapshot {
        for ban in jail.bans {
            if let Some(jails) = matched.get_mut(&ban.address)
                && jails.last() != Some(&jail.name)
            {
                jails.push(jail.name);
            }
        }
    }
    Ok(Banned::ByAddress(
        ids.iter()
            .map(|id| {
                matched
                    .get(id)
                    .into_iter()
                    .flatten()
                    .map(|&name| name.to_owned())
                    .collect()
            })
            .collect(),
    ))
}

fn addresses(jail: JailBans<'_>) -> Vec<IpAddr> {
    jail.bans.iter().map(|ban| ban.address).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    fn ban(raw: &str, expires_at: Option<i64>) -> ActiveBan {
        ActiveBan {
            address: ip(raw),
            expires_at,
        }
    }

    #[test]
    fn banip_sorts_by_expiry_and_keeps_insertion_order_for_ties() {
        let bans = [
            ban("192.0.2.1", None),
            ban("192.0.2.7", Some(400)),
            ban("192.0.2.2", Some(400)),
            ban("2001:db8::7", Some(200)),
        ];
        let snapshot = [JailBans {
            name: "ssh",
            bans: &bans,
        }];
        assert_eq!(
            get_banip(&snapshot, "ssh"),
            Ok([
                ip("2001:db8::7"),
                ip("192.0.2.7"),
                ip("192.0.2.2"),
                ip("192.0.2.1"),
            ]
            .to_vec())
        );
        assert_eq!(
            banned(&snapshot, Some("ssh"), &[]),
            Ok(Banned::Addresses(
                bans.iter().map(|ban| ban.address).collect()
            ))
        );
    }

    #[test]
    fn empty_jail_exists_and_is_different_from_missing_jail() {
        let snapshot = [JailBans {
            name: "ssh",
            bans: &[],
        }];
        assert_eq!(get_banip(&snapshot, "ssh"), Ok(vec![]));
        assert_eq!(get_banip(&snapshot, "SSH"), Err(UnknownJail("SSH".into())));
        assert_eq!(
            banned(&snapshot, Some("ssh"), &[]),
            Ok(Banned::Addresses(vec![]))
        );
        assert_eq!(
            banned(&snapshot, Some("ssh"), &[ip("192.0.2.7")]),
            Ok(Banned::Membership(0))
        );
        assert_eq!(
            banned(&snapshot, Some("missing"), &[]),
            Err(UnknownJail("missing".into()))
        );
    }

    #[test]
    fn global_results_include_empty_jails_and_preserve_jail_order() {
        let first = [ban("192.0.2.7", None), ban("2001:db8::7", Some(500))];
        let last = [ban("192.0.2.7", Some(100))];
        let snapshot = [
            JailBans {
                name: "zeta",
                bans: &first,
            },
            JailBans {
                name: "empty",
                bans: &[],
            },
            JailBans {
                name: "alpha",
                bans: &last,
            },
        ];
        assert_eq!(
            banned(&snapshot, None, &[]),
            Ok(Banned::Jails(vec![
                ("zeta".into(), vec![ip("192.0.2.7"), ip("2001:db8::7")]),
                ("empty".into(), vec![]),
                ("alpha".into(), vec![ip("192.0.2.7")]),
            ]))
        );
        assert_eq!(
            banned(&snapshot, None, &[ip("192.0.2.7")]),
            Ok(Banned::ByAddress(vec![vec!["zeta".into(), "alpha".into()]]))
        );
        assert_eq!(
            banned(
                &snapshot,
                None,
                &[
                    ip("2001:db8::7"),
                    ip("192.0.2.7"),
                    ip("192.0.2.15"),
                    ip("2001:db8::7"),
                ],
            ),
            Ok(Banned::ByAddress(vec![
                vec!["zeta".into()],
                vec!["zeta".into(), "alpha".into()],
                vec![],
                vec!["zeta".into()],
            ]))
        );
    }

    #[test]
    fn jail_membership_preserves_request_shape_and_duplicates() {
        let snapshot = [JailBans {
            name: "ssh",
            bans: &[ban("192.0.2.7", None)],
        }];
        assert_eq!(
            banned(&snapshot, Some("ssh"), &[ip("192.0.2.7")]),
            Ok(Banned::Membership(1))
        );
        assert_eq!(
            banned(
                &snapshot,
                Some("ssh"),
                &[ip("192.0.2.7"), ip("2001:db8::7"), ip("192.0.2.7")]
            ),
            Ok(Banned::Memberships(vec![1, 0, 1]))
        );
        assert_eq!(
            banned(&[], None, &[ip("192.0.2.7")]),
            Ok(Banned::ByAddress(vec![vec![]]))
        );
    }
}
