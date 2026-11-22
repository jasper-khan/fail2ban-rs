//! Fail2Ban 1.1.1 `CommandAction` family detection and `actionstart_on_demand` projection.
//!
//! Mirrors `_hasCondSection`, `_startOnDemand`, and `_families` from
//! `fail2ban/server/action.py`.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::{Error, Result};
use crate::ticket::TicketId;

/// Address family dimension for conditional action properties (`?family=inet4`, `?family=inet6`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    Common,
    Ipv4,
    Ipv6,
}

impl Family {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Common => "",
            Self::Ipv4 => "inet4",
            Self::Ipv6 => "inet6",
        }
    }

    pub fn from_ticket_id(id: &TicketId) -> Self {
        match id {
            TicketId::Ip(IpAddr::V4(_)) | TicketId::Net(IpNet::V4(_)) => Self::Ipv4,
            TicketId::Ip(IpAddr::V6(_)) | TicketId::Net(IpNet::V6(_)) => Self::Ipv6,
            TicketId::Raw(_) => Self::Common,
        }
    }
}

/// Projected startup policy for a [`CommandAction`](super::command_action::CommandAction).
#[derive(Debug, PartialEq, Eq)]
pub struct ActionPolicy {
    pub has_family_condition: bool,
    pub start_on_demand: bool,
    /// Ordered eager-start family list. Explicit duplicates remain duplicates.
    pub families: Vec<Family>,
}

/// Project `CommandAction._hasCondSection`, `_startOnDemand`, and `_families`.
pub fn project<'a>(
    keys: impl IntoIterator<Item = &'a str>,
    configured_on_demand: Option<&str>,
    family_setting: Option<&str>,
    ipv6_allowed: bool,
) -> Result<ActionPolicy> {
    let has_family_condition = keys.into_iter().any(is_family_condition);
    let start_on_demand = configured_on_demand.map_or(has_family_condition, action_bool);
    let families = if let Some(setting) = family_setting.filter(|value| !value.is_empty()) {
        setting
            .split(|ch: char| ch == ',' || is_python_space(ch))
            .filter(|word| !word.is_empty())
            .map(|word| match word {
                "inet4" => Ok(Family::Ipv4),
                "inet6" => Ok(Family::Ipv6),
                _ => Err(Error::config(format!(
                    "unsupported CommandAction family {word:?}"
                ))),
            })
            .collect::<Result<Vec<_>>>()?
    } else if has_family_condition {
        if ipv6_allowed {
            vec![Family::Ipv4, Family::Ipv6]
        } else {
            vec![Family::Ipv4]
        }
    } else {
        vec![Family::Common]
    };

    Ok(ActionPolicy {
        has_family_condition,
        start_on_demand,
        families,
    })
}

fn is_python_space(ch: char) -> bool {
    // Python's re `\s` includes four ASCII information separators in addition
    // to Unicode white space.
    ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}')
}

fn is_family_condition(key: &str) -> bool {
    // Standard conditional detector is `^(\w+)\?family=(.*)$`.
    !key.starts_with('_')
        && key.split_once("?family=").is_some_and(|(base, value)| {
            !base.is_empty()
                && base.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
                && !value.strip_suffix('\n').unwrap_or(value).contains('\n')
        })
}

fn action_bool(raw: &str) -> bool {
    ["1", "on", "true", "yes"]
        .iter()
        .any(|word| raw.trim().eq_ignore_ascii_case(word))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn absent_settings_choose_common_or_detect_family_conditions() {
        for (keys, ipv6, expected) in [
            (&["actionstart"][..], true, vec![Family::Common]),
            (
                &["action_start?family=inet6"][..],
                false,
                vec![Family::Ipv4],
            ),
            (
                &["actionstart?family=custom"][..],
                true,
                vec![Family::Ipv4, Family::Ipv6],
            ),
            (&["actionstart?family="][..], false, vec![Family::Ipv4]),
            (
                &[
                    "_private?family=inet6",
                    "nonword-key?family=inet6",
                    "other?Family=inet6",
                ][..],
                true,
                vec![Family::Common],
            ),
        ] {
            let conditional = expected != [Family::Common];
            let got = project(keys.iter().copied(), None, None, ipv6).unwrap();
            assert_eq!(
                got,
                ActionPolicy {
                    has_family_condition: conditional,
                    start_on_demand: conditional,
                    families: expected
                }
            );
        }
    }

    #[test]
    fn resolved_explicit_flag_overrides_automatic_choice() {
        for (value, expected) in [
            ("yes", true),
            ("TRUE", true),
            ("On", true),
            ("1", true),
            ("false", false),
            ("off", false),
            ("0", false),
            ("other", false),
            ("", false),
        ] {
            let got = project(["actionstart?family=inet6"], Some(value), None, true).unwrap();
            assert_eq!(got.start_on_demand, expected);
            assert!(got.has_family_condition);
            assert_eq!(got.families, [Family::Ipv4, Family::Ipv6]);
        }
        assert!(
            project(["actionstart"], Some("yes"), None, false)
                .unwrap()
                .start_on_demand
        );
    }

    #[test]
    fn explicit_order_and_empty_splitting_match_original_string_property() {
        let got = project(["actionstart"], None, Some("inet6, inet4\tinet6"), false).unwrap();
        assert_eq!(got.families, [Family::Ipv6, Family::Ipv4, Family::Ipv6]);
        assert!(!got.start_on_demand);
        assert!(
            project(["actionstart"], None, Some(", \t"), true)
                .unwrap()
                .families
                .is_empty()
        );
        assert_eq!(
            project(["actionstart"], None, Some(""), true)
                .unwrap()
                .families,
            [Family::Common]
        );
        assert!(project(["actionstart"], None, Some("custom"), true).is_err());
    }

    #[test]
    fn family_from_ticket_id_maps_v4_v6_raw() {
        assert_eq!(
            Family::from_ticket_id(&TicketId::parse("192.0.2.1")),
            Family::Ipv4
        );
        assert_eq!(
            Family::from_ticket_id(&TicketId::parse("192.0.2.0/24")),
            Family::Ipv4
        );
        assert_eq!(
            Family::from_ticket_id(&TicketId::parse("2001:db8::1")),
            Family::Ipv6
        );
        assert_eq!(
            Family::from_ticket_id(&TicketId::parse("2001:db8::/32")),
            Family::Ipv6
        );
        assert_eq!(
            Family::from_ticket_id(&TicketId::parse("alice@example")),
            Family::Common
        );
    }
}
