//! Pure configuration projection of original Fail2Ban 1.1.1 CommandAction.
//!
//! No runtime action, operating-system IPv6 probe, command template, or shell
//! is used here. Inputs are already resolved ActionReader property values.

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Family {
    Common,
    Ipv4,
    Ipv6,
}

impl Family {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Common => "",
            Self::Ipv4 => "inet4",
            Self::Ipv6 => "inet6",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ActionPolicy {
    pub(super) has_family_condition: bool,
    pub(super) start_on_demand: bool,
    /// Ordered eager-start family list. Explicit duplicates remain duplicates.
    pub(super) families: Vec<Family>,
}

/// Project the original ActionReader bool conversion and CommandAction
/// `_hasCondSection`, `_startOnDemand`, and `_families` properties.
/// This stock family subset accepts explicit `inet4` and `inet6` only;
/// arbitrary user strings and native Python list/set properties are out of scope.
pub(super) fn project<'a>(
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
                    "unsupported original CommandAction family {word:?}"
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
    // Python's re \s includes four ASCII information separators in addition
    // to Unicode white space.
    ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}')
}

fn is_family_condition(key: &str) -> bool {
    // CommandAction exposes only non-private, non-callable properties. The
    // standard conditional detector itself is ^(\w+)\?family=(.*)$.
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
        .any(|word| raw.eq_ignore_ascii_case(word))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    #[ignore = "requires unchanged local Fail2Ban 1.1.1 source and Python"]
    fn pinned_original_action_policy_properties_match() {
        use std::process::Command;
        let source = std::fs::canonicalize(
            std::env::var_os("FAIL2BAN_111_SOURCE").expect("set FAIL2BAN_111_SOURCE"),
        )
        .unwrap();
        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&source)
                .output()
                .unwrap()
        };
        let head = git(&["rev-parse", "HEAD"]);
        assert!(head.status.success());
        assert_eq!(
            String::from_utf8_lossy(&head.stdout).trim(),
            "f60978618a101427b06924fc932b44350fec2b63"
        );
        let status = git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "fail2ban",
        ]);
        assert!(status.status.success() && status.stdout.is_empty());
        let scratch = tempfile::tempdir().unwrap();

        let fixtures = [
            ("actionstart", None, None, true),
            ("some_setting?family=inet6", None, None, true),
            ("some_setting?family=inet6", None, None, false),
            ("some_setting?family=inet6", Some("no"), None, true),
            ("some_setting?family=", None, None, false),
            ("_private?family=inet6", None, None, true),
            (
                "actionstart",
                Some("YES"),
                Some("inet6,inet4\tinet6"),
                false,
            ),
            ("actionstart", Some("other"), Some(" , "), true),
            ("actionstart", None, Some(""), true),
        ];
        let provided = serde_json::to_string(&fixtures).unwrap();
        let oracle = r"
import json, sys
import fail2ban.server.action as action
from fail2ban.helpers import _as_bool
result = []
for key, lazy, families, ipv6 in json.loads(sys.argv[1]):
    action.allowed_ipv6 = lambda: ipv6
    obj = action.CommandAction(None, 'offline-policy')
    if key != 'actionstart':
        setattr(obj, key, 'example-property')
    if lazy is not None:
        obj.actionstart_on_demand = _as_bool(lazy)
    if families is not None:
        obj.families = families
    result.append([obj._hasCondSection, obj._startOnDemand, obj._families])
print(json.dumps(result))
";
        let result = Command::new("python3")
            .args(["-S", "-c", oracle, &provided])
            .current_dir(scratch.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("PYTHONPATH", &source)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let expected: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let observed = fixtures
            .into_iter()
            .map(|(key, lazy, families, ipv6)| {
                let policy = project([key], lazy, families, ipv6).unwrap();
                serde_json::json!([
                    policy.has_family_condition,
                    policy.start_on_demand,
                    policy
                        .families
                        .into_iter()
                        .map(Family::as_str)
                        .collect::<Vec<_>>()
                ])
            })
            .collect::<Vec<_>>();
        assert_eq!(serde_json::json!(observed), expected);
    }
}
