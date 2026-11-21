//! Single-pass, non-executable action binding over a trusted static template.
//!
//! Ticket fields are opaque values, never template or command text. Deliberately
//! no renderer, process adapter, or system/hostname lookup lives here.

use std::collections::BTreeMap;

use super::legacy_action_tags::StaticTemplate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BindingKind {
    Ticket,
    MatchData,
    Capture,
    Builtin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BoundSegment<'a> {
    Literal(&'a str),
    Binding {
        name: &'a str,
        value: &'a str,
        kind: BindingKind,
    },
    /// The original leaves an unknown ordinary tag unchanged.
    Unresolved(&'a str),
    /// A recognized but absent capture denotes an empty value, not a literal
    /// marker. Retain its identity in the plan for diagnostics/inspection.
    MissingCapture(&'a str),
}

type Values = BTreeMap<String, String>;

/// Bind ticket options and filter captures into typed segments. The only
/// parsed input is trusted static template text. Data is borrowed without
/// parsing, transformation, or caching; the result is not a command string.
pub(super) fn bind<'a>(
    template: &'a StaticTemplate,
    values: &'a Values,
    captures: &'a Values,
) -> Vec<BoundSegment<'a>> {
    bind_template(template.as_str(), values, captures)
}

fn bind_template<'a>(
    template: &'a str,
    values: &'a Values,
    captures: &'a Values,
) -> Vec<BoundSegment<'a>> {
    let mut plan = Vec::new();
    let mut literal_start = 0;
    let mut tag_start = None;
    for (index, c) in template.char_indices() {
        match c {
            '<' => tag_start = Some(index),
            ' ' => tag_start = None,
            '>' => {
                let Some(open) = tag_start.take() else {
                    continue;
                };
                let Some(name) = template
                    .get(open + 1..index)
                    .filter(|part| !part.is_empty())
                else {
                    continue;
                };
                push_literal(&mut plan, template.get(literal_start..open));
                plan.push(bind_tag(name, values, captures));
                literal_start = index + 1;
            }
            _ => {}
        }
    }
    push_literal(&mut plan, template.get(literal_start..));
    plan
}

fn push_literal<'a>(plan: &mut Vec<BoundSegment<'a>>, literal: Option<&'a str>) {
    if let Some(literal) = literal.filter(|part| !part.is_empty()) {
        plan.push(BoundSegment::Literal(literal));
    }
}

fn bind_tag<'a>(name: &'a str, values: &'a Values, captures: &'a Values) -> BoundSegment<'a> {
    // The original's ordinary-pass dictionary wins over builtin fallback
    // and recognized capture syntax at this specific source position.
    if let Some(value) = values.get(name) {
        let kind = if matches!(name, "matches" | "ipmatches" | "ipjailmatches") {
            BindingKind::MatchData
        } else {
            BindingKind::Ticket
        };
        return BoundSegment::Binding { name, value, kind };
    }

    let builtin = match name {
        "br" => Some("\n"),
        "sp" => Some(" "),
        // Hostname values, if available, must be supplied explicitly by the
        // caller. This offline phase never queries the host or DNS.
        _ => None,
    };
    if let Some(value) = builtin {
        return BoundSegment::Binding {
            name,
            value,
            kind: BindingKind::Builtin,
        };
    }
    let Some(capture) = name.strip_prefix("F-").filter(|part| is_capture_name(part)) else {
        return BoundSegment::Unresolved(name);
    };
    let capture = capture.to_ascii_lowercase();
    let key = match capture.as_str() {
        "id" => "fid",
        "port" => "fport",
        other => other,
    };
    captures
        .get(key)
        .map_or(BoundSegment::MissingCapture(name), |value| {
            BoundSegment::Binding {
                name,
                value,
                kind: BindingKind::Capture,
            }
        })
}

fn is_capture_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || matches!(ch, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_values(input: &[(&str, &str)]) -> Values {
        input
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn binding<'a>(name: &'a str, value: &'a str, kind: BindingKind) -> BoundSegment<'a> {
        BoundSegment::Binding { name, value, kind }
    }

    #[test]
    fn source_order_and_capture_name_aliases_are_preserved() {
        let values = fixture_values(&[("jail", "sshd")]);
        let captures = fixture_values(&[("fid", "sample"), ("fport", "22"), ("user", "Zoë")]);
        assert_eq!(
            bind_template("test <jail>/<F-ID>/<F-PORT>/<F-USER>", &values, &captures),
            [
                BoundSegment::Literal("test "),
                binding("jail", "sshd", BindingKind::Ticket),
                BoundSegment::Literal("/"),
                binding("F-ID", "sample", BindingKind::Capture),
                BoundSegment::Literal("/"),
                binding("F-PORT", "22", BindingKind::Capture),
                BoundSegment::Literal("/"),
                binding("F-USER", "Zoë", BindingKind::Capture),
            ]
        );
    }

    #[test]
    fn missing_capture_ordinary_tag_and_safe_builtins_are_distinct() {
        let empty = Values::new();
        assert_eq!(
            bind_template(
                "<F-USER><F-user><other><br><sp><fq-hostname>",
                &empty,
                &empty
            ),
            [
                BoundSegment::MissingCapture("F-USER"),
                BoundSegment::Unresolved("F-user"),
                BoundSegment::Unresolved("other"),
                binding("br", "\n", BindingKind::Builtin),
                binding("sp", " ", BindingKind::Builtin),
                BoundSegment::Unresolved("fq-hostname"),
            ]
        );
    }

    #[test]
    fn independent_tickets_bind_opaque_values_without_reinterpreting_values() {
        let first = fixture_values(&[
            ("matches", "entrée\nligne suivante"),
            ("ipmatches", "historical record"),
            ("ipjailmatches", "jail record"),
            ("user", "Ada"),
        ]);
        let second = fixture_values(&[("user", "Grace"), ("fq-hostname", "box.example")]);
        let capture = fixture_values(&[("user", "captured user")]);
        let template = "<user> <matches> <ipmatches> <ipjailmatches> <F-USER> <fq-hostname>";
        assert_eq!(
            bind_template(template, &first, &capture),
            [
                binding("user", "Ada", BindingKind::Ticket),
                BoundSegment::Literal(" "),
                binding("matches", "entrée\nligne suivante", BindingKind::MatchData),
                BoundSegment::Literal(" "),
                binding("ipmatches", "historical record", BindingKind::MatchData),
                BoundSegment::Literal(" "),
                binding("ipjailmatches", "jail record", BindingKind::MatchData),
                BoundSegment::Literal(" "),
                binding("F-USER", "captured user", BindingKind::Capture),
                BoundSegment::Literal(" "),
                BoundSegment::Unresolved("fq-hostname"),
            ]
        );
        assert_eq!(
            bind_template(template, &second, &capture),
            [
                binding("user", "Grace", BindingKind::Ticket),
                BoundSegment::Literal(" "),
                BoundSegment::Unresolved("matches"),
                BoundSegment::Literal(" "),
                BoundSegment::Unresolved("ipmatches"),
                BoundSegment::Literal(" "),
                BoundSegment::Unresolved("ipjailmatches"),
                BoundSegment::Literal(" "),
                binding("F-USER", "captured user", BindingKind::Capture),
                BoundSegment::Literal(" "),
                binding("fq-hostname", "box.example", BindingKind::Ticket),
            ]
        );
    }

    #[test]
    fn ordinary_pass_can_resolve_a_tag_spelled_like_a_capture() {
        let explicit = fixture_values(&[("F-USER", "explicit value")]);
        let captures = fixture_values(&[("user", "capture value")]);
        assert_eq!(
            bind_template("<F-USER>", &explicit, &captures),
            [binding("F-USER", "explicit value", BindingKind::Ticket)]
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn static_handoff_keeps_match_data_out_of_expanded_text() {
        use crate::enforce::{legacy_action_policy::Family, legacy_action_tags::expand};

        let properties =
            fixture_values(&[("prefix", "fixture"), ("matches", "not a trusted property")]);
        let template = expand("<prefix>: <matches>/<F-USER>", &properties, Family::Common).unwrap();
        let provided = fixture_values(&[("matches", "observed record")]);
        let captures = fixture_values(&[("user", "Ada")]);
        assert_eq!(
            bind(&template, &provided, &captures),
            [
                BoundSegment::Literal("fixture: "),
                binding("matches", "observed record", BindingKind::MatchData),
                BoundSegment::Literal("/"),
                binding("F-USER", "Ada", BindingKind::Capture),
            ]
        );
    }

    #[test]
    fn tag_positions_are_only_from_original_template() {
        let input = fixture_values(&[("entry", "Box <note>")]);
        let empty = Values::new();
        assert_eq!(
            bind_template("α <> <not a tag> <entry> β", &input, &empty),
            [
                BoundSegment::Literal("α <> <not a tag> "),
                binding("entry", "Box <note>", BindingKind::Ticket),
                BoundSegment::Literal(" β"),
            ]
        );
    }
}
