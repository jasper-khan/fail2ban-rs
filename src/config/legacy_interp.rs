//! Legacy INI value substitutions, evaluated after selecting the effective option.
//! File ordering and the lookup precedence remain with the caller.
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

type Options = BTreeMap<String, String>;

const MAX_DEPTH: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InterpError {
    option: String,
    section: String,
    kind: ErrorKind,
}

#[derive(Debug, PartialEq, Eq)]
enum ErrorKind {
    Missing { raw: String, reference: String },
    Depth { raw: String },
    Malformed { tail: String, reference: bool },
}

// The original diagnostics render strings as single-quoted Python reprs
// (or double-quoted when that avoids escaping an apostrophe).
fn quoted(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == quote => {
                out.push('\\');
                out.push(ch);
            }
            ch if ch.is_control() || (ch.is_whitespace() && ch != ' ') => {
                let code = u32::from(ch);
                if code <= 0xff {
                    let _ = write!(out, "\\x{code:02x}");
                } else if code <= 0xffff {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let _ = write!(out, "\\U{code:08x}");
                }
            }
            ch => out.push(ch),
        }
    }
    out.push(quote);
    out
}

impl fmt::Display for InterpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Missing { raw, reference } => write!(
                f,
                "Bad value substitution: option {} in section {} contains an interpolation key {} which is not a valid option name. Raw value: {}",
                quoted(&self.option),
                quoted(&self.section),
                quoted(reference),
                quoted(raw)
            ),
            ErrorKind::Depth { raw } => write!(
                f,
                "Recursion limit exceeded in value substitution: option {} in section {} contains an interpolation key which cannot be substituted in {MAX_DEPTH} steps. Raw value: {}",
                quoted(&self.option),
                quoted(&self.section),
                quoted(raw)
            ),
            ErrorKind::Malformed {
                tail,
                reference: true,
            } => {
                write!(f, "bad interpolation variable reference {}", quoted(tail))
            }
            ErrorKind::Malformed {
                tail,
                reference: false,
            } => write!(
                f,
                "'%' must be followed by '%' or '(', found: {}",
                quoted(tail)
            ),
        }
    }
}

impl std::error::Error for InterpError {}

struct Expansion<'a, F, A> {
    section: &'a str,
    option: &'a str,
    diagnostic_raw: Option<&'a str>,
    lookup: F,
    lookup_alias: A,
}

impl<'v, F, A> Expansion<'_, F, A>
where
    F: Fn(&str) -> Option<&'v str>,
    A: Fn(&str) -> Option<&'v str>,
{
    fn error(&self, kind: ErrorKind) -> InterpError {
        InterpError {
            option: self.option.to_lowercase(),
            section: self.section.to_owned(),
            kind,
        }
    }

    fn append(
        &self,
        out: &mut String,
        mut tail: &str,
        depth: usize,
        prior_aliases: &BTreeMap<String, &'v str>,
    ) -> Result<(), InterpError> {
        let diagnostic_raw = self.diagnostic_raw.unwrap_or(tail);
        if depth > MAX_DEPTH {
            return Err(self.error(ErrorKind::Depth {
                raw: diagnostic_raw.to_owned(),
            }));
        }
        // Synthetic slash keys were added to a copy of the lookup map before
        // Python parsed a value. Even an escaped reference can prepare the
        // alias used by a later reference with a different spelling.
        let mut aliases = prior_aliases.clone();
        let mut scan = if tail.contains('/') { tail } else { "" };
        while let Some(index) = scan.find("%(") {
            let (_, candidate) = scan.split_at(index + 2);
            if let Some((name, after)) = candidate.split_once(")s")
                && !name.contains(')')
                && section_option(name).is_some()
            {
                if (self.lookup)(name).is_none()
                    && !aliases.contains_key(name)
                    && let Some(raw) = (self.lookup_alias)(name)
                {
                    aliases.insert(name.to_owned(), raw);
                }
                scan = after;
            } else {
                scan = candidate;
            }
        }
        while let Some(offset) = tail.find('%') {
            let (literal, marker) = tail.split_at(offset);
            out.push_str(literal);
            if let Some(after) = marker.strip_prefix("%%") {
                out.push('%');
                tail = after;
                continue;
            }
            let Some(name) = marker.strip_prefix("%(") else {
                return Err(self.error(ErrorKind::Malformed {
                    tail: marker.to_owned(),
                    reference: false,
                }));
            };
            let Some((name, after)) = name.split_once(')').filter(|(name, _)| !name.is_empty())
            else {
                return Err(self.error(ErrorKind::Malformed {
                    tail: marker.to_owned(),
                    reference: true,
                }));
            };
            let Some(after) = after.strip_prefix('s') else {
                return Err(self.error(ErrorKind::Malformed {
                    tail: marker.to_owned(),
                    reference: true,
                }));
            };
            tail = after;

            let reference = name.to_lowercase();
            let value = if reference == "__name__" && !self.section.is_empty() {
                Some(self.section)
            } else {
                (self.lookup)(&reference).or_else(|| aliases.get(&reference).copied())
            }
            .ok_or_else(|| {
                self.error(ErrorKind::Missing {
                    raw: diagnostic_raw.to_owned(),
                    reference,
                })
            })?;
            if value.contains('%') {
                self.append(out, value, depth + 1, &aliases)?;
            } else {
                out.push_str(value);
            }
        }
        out.push_str(tail);
        Ok(())
    }
}

/// Expand a value using the selected section's context without changing the raw
/// table. Lookup receives the lowercased reference and returns its *raw* value.
/// In normal use the caller checks local/overrides before inherited defaults.
pub(crate) fn expand<'v>(
    section: &str,
    option: &str,
    raw: &str,
    lookup: impl Fn(&str) -> Option<&'v str>,
) -> Result<String, InterpError> {
    expand_with_aliases(section, option, raw, Some(raw), lookup, |_| None)
}

fn expand_with_aliases<'v>(
    section: &str,
    option: &str,
    raw: &str,
    diagnostic_raw: Option<&str>,
    lookup: impl Fn(&str) -> Option<&'v str>,
    lookup_alias: impl Fn(&str) -> Option<&'v str>,
) -> Result<String, InterpError> {
    let exp = Expansion {
        section,
        option,
        diagnostic_raw,
        lookup,
        lookup_alias,
    };
    let mut out = String::with_capacity(raw.len());
    exp.append(&mut out, raw, 1, &BTreeMap::new())?;
    Ok(out)
}

fn section_option(name: &str) -> Option<(&str, &str)> {
    let (group, key) = name.split_once('/')?;
    (!group.is_empty()
        && group
            .chars()
            .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '-'))
        && !key.is_empty())
    .then_some((group, key))
}

/// Read the effective value from a ConfigParser section. Explicit overrides
/// (vars) precede the section, then DEFAULT. Option maps use normalized keys;
/// section names keep their original spelling.
pub(super) fn get_effective<'v>(
    section: &str,
    option: &str,
    defaults: &'v Options,
    sections: impl Fn(&str) -> Option<&'v Options>,
    vars: Option<&'v Options>,
) -> Result<Option<String>, InterpError> {
    let local = if section == "DEFAULT" {
        defaults
    } else if let Some(options) = sections(section) {
        options
    } else {
        return Ok(None);
    };
    let raw_option = |key: &str| {
        local
            .get(key)
            .or_else(|| defaults.get(key))
            .map(String::as_str)
    };
    let vars = vars.map(|options| {
        options
            .iter()
            .map(|(name, value)| (name.to_lowercase(), value.as_str()))
            .collect::<BTreeMap<_, _>>()
    });
    let lookup = |key: &str| {
        vars.as_ref()
            .and_then(|map| map.get(key).copied())
            .or_else(|| raw_option(key))
    };
    let normalized = option.to_lowercase();
    let Some(raw) = lookup(&normalized) else {
        return Ok(None);
    };
    // 1.1.1's section-name decorator checks for its module name in the map;
    // the interpolator is a no-op (with empty output) if that literal exists.
    if lookup("fail2ban.client.configparserinc").is_some() {
        return Ok(Some(String::new()));
    }
    let known_group = format!("KNOWN/{section}");
    let lookup_alias = |name: &str| {
        let (group, key) = section_option(name)?;
        let group_lower = group.to_lowercase();
        let value = if group_lower == "default" {
            defaults.get(key)
        } else if group_lower == "known" {
            sections(&known_group)
                .and_then(|opts| opts.get(key))
                .or_else(|| defaults.get(key))
        } else {
            sections(group)?.get(key).or_else(|| defaults.get(key))
        };
        value.map(String::as_str)
    };
    expand_with_aliases(
        section,
        &normalized,
        raw,
        raw_option(&normalized),
        lookup,
        lookup_alias,
    )
    .map(Some)
}

/// Legacy get_ex lookup, used by definition tag readers. A slash address first
/// selects another section without the caller's overrides. It is not the same
/// as percent interpolation: the addressed value expands in its own section.
pub(super) fn get_extended<'v>(
    section: &str,
    option: &str,
    defaults: &'v Options,
    sections: impl Fn(&str) -> Option<&'v Options>,
    vars: Option<&'v Options>,
) -> Result<Option<String>, InterpError> {
    if let Some((group, key)) = section_option(option.strip_suffix('\n').unwrap_or(option))
        && !key.chars().any(|ch| ch.is_whitespace() || ch == '>')
    {
        let group_lower = group.to_lowercase();
        if group_lower == "known" {
            let known_group = format!("KNOWN/{section}");
            for addressed in [known_group.as_str(), section] {
                if let Some(value) = get_effective(addressed, key, defaults, &sections, None)? {
                    return Ok(Some(value));
                }
            }
        } else {
            let addressed = if group_lower == "default" {
                "DEFAULT"
            } else {
                group
            };
            if let Some(value) = get_effective(addressed, key, defaults, &sections, None)? {
                return Ok(Some(value));
            }
        }
    }
    get_effective(section, option, defaults, sections, vars)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ErrorKind, Options, expand, get_effective, get_extended};
    use std::collections::BTreeMap;

    fn options(values: &[(&str, &str)]) -> Options {
        values
            .iter()
            .map(|&(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
    }

    #[test]
    fn slash_lookup_precedence_and_case_match_the_legacy_get() {
        let defaults = options(&[("fallback", "default")]);
        let local = options(&[
            ("choice", "local"),
            ("nested", "%(other/file)s"),
            ("lower", "%(default/fallback)s"),
            ("upper", "%(DEFAULT/fallback)s"),
            ("case", "%(Alt/file)s"),
            ("known", "%(known/choice)s"),
            ("known_default", "%(known/fallback)s"),
            ("named_default", "%(other/fallback)s"),
            ("absent", "%(missing/fallback)s"),
            ("prime", "%%(other/file)s %(OTHER/file)s"),
            ("sibling", "%(inner)s %(OTHER/file)s"),
            ("inner", "%(other/file)s"),
            ("cross", "%(other/choice)s"),
            ("literal_ref", "%(DIRECT/value)s"),
            ("direct/value", "literal"),
        ]);
        let sections = BTreeMap::from([
            ("Definition", local),
            (
                "other",
                options(&[("file", "%(choice)s"), ("choice", "remote")]),
            ),
            ("Alt", options(&[("file", "caps")])),
            ("KNOWN/Definition", options(&[("choice", "older")])),
        ]);
        let vars = options(&[("choice", "override")]);
        let get = |key| {
            get_effective(
                "Definition",
                key,
                &defaults,
                |name| sections.get(name),
                Some(&vars),
            )
        };
        for (key, expected) in [
            ("nested", "override"),
            ("lower", "default"),
            ("known", "older"),
            ("known_default", "default"),
            ("named_default", "default"),
            ("prime", "%(other/file)s override"),
            ("cross", "remote"),
            ("literal_ref", "literal"),
        ] {
            assert_eq!(get(key).unwrap().as_deref(), Some(expected), "{key}");
        }
        for (key, expected_ref) in [
            ("upper", "default/fallback"),
            ("case", "alt/file"),
            ("absent", "missing/fallback"),
            ("sibling", "other/file"),
        ] {
            assert!(
                matches!(
                    get(key).unwrap_err().kind,
                    ErrorKind::Missing { reference, .. } if reference == expected_ref
                ),
                "{key}"
            );
        }
        assert!(get("not_set").unwrap().is_none());
    }

    #[test]
    fn extended_get_changes_section_context_and_falls_back_only_on_absence() {
        let defaults = options(&[
            ("name", "%(__name__)s"),
            ("base", "%(choice)s"),
            ("fallback", "default"),
        ]);
        let sections = BTreeMap::from([
            (
                "Definition",
                options(&[("choice", "local"), ("missing/raw", "%(choice)s")]),
            ),
            (
                "other",
                options(&[("file", "%(choice)s"), ("choice", "remote")]),
            ),
            ("Alt", options(&[("file", "caps")])),
            ("KNOWN/Definition", options(&[("choice", "older")])),
        ]);
        let vars = options(&[("choice", "override")]);
        let get = |name| {
            get_extended(
                "Definition",
                name,
                &defaults,
                |n| sections.get(n),
                Some(&vars),
            )
        };
        for (name, expected) in [
            ("choice", "override"),
            ("other/FILE", "remote"),
            ("Alt/FILE", "caps"),
            ("known/CHOICE", "older"),
            ("known/fallback", "default"),
            ("missing/raw", "override"),
            ("default/name", "DEFAULT"),
            ("other/name", "other"),
            ("known/name", "KNOWN/Definition"),
        ] {
            assert_eq!(get(name).unwrap().as_deref(), Some(expected), "{name}");
        }
        assert!(get("OTHER/file").unwrap().is_none());
        assert_eq!(
            get("default/base").unwrap_err().to_string(),
            "Bad value substitution: option 'base' in section 'DEFAULT' contains an interpolation key 'choice' which is not a valid option name. Raw value: '%(choice)s'"
        );
    }

    #[test]
    fn override_diagnostics_use_unoverridden_option_or_current_level() {
        let defaults = options(&[("base", "original")]);
        let definition = options(&[("outer", "%(bad)s")]);
        let vars = options(&[("BASE", "%(outer)s"), ("ABSENT", "%(outer)s")]);
        let get = |name| {
            get_effective(
                "Definition",
                name,
                &defaults,
                |section| (section == "Definition").then_some(&definition),
                Some(&vars),
            )
        };
        for (name, expected_raw) in [("base", "original"), ("absent", "%(bad)s")] {
            assert!(matches!(
                get(name).unwrap_err().kind,
                ErrorKind::Missing { raw, reference } if raw == expected_raw && reference == "bad"
            ));
        }
    }

    #[test]
    fn effective_local_values_and_defaults_expand_late_in_same_section() {
        let local = BTreeMap::from([
            ("path", "/local"),
            ("label", "%(__NAME__)s:%(PATH)s"),
            ("__name__", "not the section name"),
        ]);
        let defaults = BTreeMap::from([("path", "/default"), ("tool", "%(label)s/app")]);
        let out = expand("Service Case", "run", "%(tool)s %% %(PATH)s", |name| {
            local.get(name).or_else(|| defaults.get(name)).copied()
        });
        assert_eq!(out.unwrap(), "Service Case:/local/app % /local");
        assert_eq!(
            expand("DEFAULT", "name", "%(__name__)s", |_| None).unwrap(),
            "DEFAULT"
        );
    }

    #[test]
    fn doubled_percent_is_literal_not_a_second_expansion() {
        assert_eq!(
            expand(
                "Definition",
                "regex",
                "%%(not-defined)s %(inner)s %%%%(still)s",
                |key| { (key == "inner").then_some("%%") }
            )
            .unwrap(),
            "%(not-defined)s % %%(still)s"
        );
    }

    #[test]
    fn malformed_values_and_nested_missing_refs_report_original_context() {
        let missing = expand("Jail", "CoMmAnD", "prefix %(outer)s", |key| {
            (key == "outer").then_some("%(NotHere)s")
        })
        .unwrap_err();
        assert_eq!(
            missing.to_string(),
            "Bad value substitution: option 'command' in section 'Jail' contains an interpolation key 'nothere' which is not a valid option name. Raw value: 'prefix %(outer)s'"
        );
        let syntax = expand("Definition", "command", "run %D", |_| None).unwrap_err();
        assert_eq!(
            syntax.to_string(),
            "'%' must be followed by '%' or '(', found: '%D'"
        );
        for value in ["%()s", "%(missing)x", "%(missing", "%(x)S", "%(x)y)s"] {
            assert_eq!(
                expand("Definition", "command", value, |_| None)
                    .unwrap_err()
                    .to_string(),
                format!("bad interpolation variable reference '{value}'")
            );
        }
    }

    #[test]
    fn permits_ten_levels_but_rejects_a_deeper_substitution_or_cycle() {
        let vars = (1..=10)
            .map(|depth| (depth.to_string(), format!("%({})s", depth + 1)))
            .chain([("11".to_owned(), "leaf".to_owned())])
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            expand("Definition", "value", "%(2)s", |key| vars
                .get(key)
                .map(String::as_str))
            .unwrap(),
            "leaf"
        );
        let deeper = expand("Definition", "value", "%(1)s", |key| {
            vars.get(key).map(String::as_str)
        })
        .unwrap_err();
        assert!(matches!(deeper.kind, ErrorKind::Depth { .. }));
        let cycle = expand("Definition", "value", "%(x)s", |key| match key {
            "x" => Some("%(y)s"),
            "y" => Some("%(x)s"),
            _ => None,
        })
        .unwrap_err();
        assert_eq!(
            cycle.to_string(),
            "Recursion limit exceeded in value substitution: option 'value' in section 'Definition' contains an interpolation key which cannot be substituted in 10 steps. Raw value: '%(x)s'"
        );
    }
}
