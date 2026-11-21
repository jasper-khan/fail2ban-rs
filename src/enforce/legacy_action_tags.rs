//! Inert CommandAction static tag expansion for original Fail2Ban 1.1.1.
//!
//! Resolved action-file properties and the selected conditional family are
//! inputs. Runtime bindings, host/environment lookups, shell escaping and
//! command execution are deliberately not part of this static projection.

use std::collections::BTreeMap;

use crate::config::legacy_tags;
use crate::error::{Error, Result};

use super::legacy_action_policy::Family;

/// Expanded static text, still containing any unresolved runtime tags.
/// This type contains text only and cannot execute or bind it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct StaticTemplate(String);

impl StaticTemplate {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(super) fn expand(
    query: &str,
    properties: &BTreeMap<String, String>,
    family: Family,
) -> Result<StaticTemplate> {
    if !query.contains('<') {
        return Ok(StaticTemplate(query.to_owned()));
    }

    let mut resolved = BTreeMap::new();
    // CommandAction.replaceTag first interpolates the property dictionary.
    // Resolve every ordinary static property, even if unused by this query.
    // Original runtime-only escaped tags are never consumed here.
    for (key, value) in properties {
        if is_runtime_property(key) {
            continue;
        }
        let mut self_reference = false;
        let result = legacy_tags::expand(value, |tag| {
            if is_runtime_tag(tag) {
                return None;
            }
            if tag == key {
                self_reference = true;
                return None;
            }
            static_value(properties, tag, family).cloned()
        });
        if self_reference {
            return Err(Error::config(format!(
                "recursive original CommandAction property {key:?}"
            )));
        }
        let expanded = result.map_err(|err| {
            Error::config(format!("original CommandAction property {key:?}: {err}"))
        })?;
        resolved.insert(key.clone(), expanded);
    }

    // Unlike the property pass, the final query has the original built-in
    // text fallbacks. fq-hostname/sh-hostname are left unresolved by design.
    legacy_tags::expand(query, |tag| {
        if is_runtime_tag(tag) {
            return None;
        }
        static_value(&resolved, tag, family)
            .map(String::as_str)
            .or(match tag {
                "br" => Some("\n"),
                "sp" => Some(" "),
                _ => None,
            })
            .map(str::to_owned)
    })
    .map(StaticTemplate)
    .map_err(|err| Error::config(format!("original CommandAction static query: {err}")))
}

fn static_value<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &str,
    family: Family,
) -> Option<&'a String> {
    let conditional = match family {
        Family::Common => None,
        Family::Ipv4 | Family::Ipv6 => {
            properties.get(&format!("{name}?family={}", family.as_str()))
        }
    };
    // Some("") is a configured value. It must not fall through to a
    // generic property or built-in replacement.
    conditional.or_else(|| properties.get(name))
}

fn is_runtime_tag(tag: &str) -> bool {
    matches!(tag, "matches" | "ipmatches" | "ipjailmatches")
}

fn is_runtime_property(key: &str) -> bool {
    is_runtime_tag(key.split_once("?family=").map_or(key, |(base, _)| base))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn options(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn nested_static_tags_prefer_conditionals_and_keep_unknowns() {
        let properties = options(&[
            ("collection", "alpha"),
            ("collection?family=inet6", "beta"),
            ("title-alpha", "report-a"),
            ("title-beta", "report-b"),
            ("view", "<title-<collection>>"),
        ]);
        for (family, expected) in [
            (Family::Common, "report-a|<missing>"),
            (Family::Ipv4, "report-a|<missing>"),
            (Family::Ipv6, "report-b|<missing>"),
        ] {
            assert_eq!(
                expand("<view>|<missing>", &properties, family)
                    .unwrap()
                    .as_str(),
                expected,
            );
        }
    }

    #[test]
    fn known_empty_family_value_shadows_generic_and_builtin_fallbacks() {
        let properties = options(&[
            ("leaf", "fallback"),
            ("leaf?family=inet4", ""),
            ("sp?family=inet4", ""),
        ]);
        assert_eq!(
            expand("[<leaf>]<sp>done", &properties, Family::Ipv4)
                .unwrap()
                .as_str(),
            "[]done"
        );
        assert_eq!(
            expand("[<leaf>]<sp>done", &properties, Family::Ipv6)
                .unwrap()
                .as_str(),
            "[fallback] done"
        );
    }

    #[test]
    fn static_text_does_not_take_runtime_bindings_or_probe_environment() {
        let properties = options(&[
            ("view", "<matches><br><ipmatches><sp><ipjailmatches>"),
            ("matches", "ignored-static"),
            ("ipmatches?family=inet6", "ignored-static"),
        ]);
        assert_eq!(
            expand(
                "<view> <family> <fq-hostname> <sh-hostname>",
                &properties,
                Family::Ipv6
            )
            .unwrap()
            .as_str(),
            "<matches>\n<ipmatches> <ipjailmatches> <family> <fq-hostname> <sh-hostname>"
        );
        let properties = options(&[("family", "raw-config-value")]);
        assert_eq!(
            expand("<family>", &properties, Family::Ipv4)
                .unwrap()
                .as_str(),
            "raw-config-value"
        );
    }

    #[test]
    fn property_prepass_fails_on_cycles_except_when_fast_path_skips_it() {
        for properties in [
            options(&[("a", "<a>"), ("a?family=inet4", "alternate")]),
            options(&[("a", "<b>"), ("b", "<a>")]),
        ] {
            assert!(expand("<unrelated>", &properties, Family::Ipv4).is_err());
            assert_eq!(
                expand("ordinary literal", &properties, Family::Ipv4)
                    .unwrap()
                    .as_str(),
                "ordinary literal"
            );
        }
    }
}
