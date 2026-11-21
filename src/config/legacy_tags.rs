//! Structural angle-tag substitution for original Fail2Ban configuration.
//!
//! Unlike percent interpolation, angle tags can construct other tag names.
//! This module expands one value; context-specific lookup and runtime regex
//! tags belong to the caller.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

// The upstream per-name replacement limit also catches indirect references
// formed only after two or more tokens construct a new name.
const MAX_PER_NAME: usize = 25;
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_SCAN_BYTES: usize = 32 * MAX_VALUE_BYTES;
const MAX_STEPS: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TagError {
    Recursive(String),
    ValueLimit,
    WorkLimit,
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recursive(name) => write!(f, "recursive angle tag <{name}> cannot be resolved"),
            Self::ValueLimit => write!(f, "angle tag value exceeds {MAX_VALUE_BYTES} bytes"),
            Self::WorkLimit => write!(f, "angle tag expansion exceeds its work limit"),
        }
    }
}

impl std::error::Error for TagError {}

/// Expand one value with exact, case-sensitive tag names.
///
/// Return `None` for unknown tags and tags to preserve for the runtime. A
/// lookup may return an empty string, which is a real replacement. Lookup
/// precedence (e.g. conditional options and `known/`) belongs to the caller.
pub(super) fn expand(
    raw: &str,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<String, TagError> {
    if raw.len() > MAX_VALUE_BYTES {
        return Err(TagError::ValueLimit);
    }
    let mut value = raw.to_owned();
    let mut remaining_scan = MAX_SCAN_BYTES;
    let mut counts = HashMap::<String, usize>::new();
    for _ in 0..MAX_STEPS {
        remaining_scan = remaining_scan
            .checked_sub(value.len())
            .ok_or(TagError::WorkLimit)?;
        let Some((tag, replacement)) = first_resolvable(&value, &mut lookup) else {
            return Ok(value);
        };
        let needle = value.get(tag.clone()).ok_or(TagError::WorkLimit)?;
        // Matching delimiters are ASCII, so the name boundaries are valid
        // even when a configured tag name contains non-ASCII characters.
        let name = value
            .get(tag.start + 1..tag.end - 1)
            .ok_or(TagError::WorkLimit)?;
        let count = counts.entry(name.to_owned()).or_default();
        if replacement == needle || *count == MAX_PER_NAME {
            return Err(TagError::Recursive(name.to_owned()));
        }
        *count += 1;

        // A replacement applies to every occurrence of the same token. In
        // particular, ordinary repeated references are not recursion.
        let occurrence_count = value.matches(needle).count();
        let retained = value.len() - occurrence_count * needle.len();
        if retained.saturating_add(occurrence_count.saturating_mul(replacement.len()))
            > MAX_VALUE_BYTES
        {
            return Err(TagError::ValueLimit);
        }
        value = value.replace(needle, &replacement);
    }
    Err(TagError::WorkLimit)
}

fn first_resolvable(
    value: &str,
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> Option<(Range<usize>, String)> {
    let mut opener = None;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'<' => opener = Some(index),
            b' ' => opener = None,
            b'>' => {
                if let Some(start) = opener.take()
                    && start + 1 < index
                    && let Some(name) = value.get(start + 1..index)
                    && let Some(replacement) = lookup(name)
                {
                    return Some((start..index + 1, replacement));
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn resolve(raw: &str, options: &[(&str, &str)]) -> Result<String, TagError> {
        expand(raw, |tag| {
            options
                .iter()
                .find(|(key, _)| *key == tag)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn selects_nested_tags_and_keeps_unknowns() {
        let options = [
            ("mode", "normal"),
            ("mdre-normal", "<body>"),
            ("body", "^<F-USER>demo</F-USER> from <HOST>"),
            ("unused", ""),
        ];
        assert_eq!(
            resolve("<mdre-<mode>> <unused><missing> <<mode>_unknown>", &options).unwrap(),
            "^<F-USER>demo</F-USER> from <HOST> <missing> <normal_unknown>"
        );
    }

    #[test]
    fn compound_names_and_independent_references_share_replacement() {
        let options = [("L", "le"), ("R", "af"), ("leaf", "ok"), ("Tea", "tea")];
        assert_eq!(
            resolve("<<L><R>> <L> <Tea> <TEA>", &options).unwrap(),
            "ok le tea <TEA>"
        );
        assert_eq!(
            resolve(&"<Tea>".repeat(100), &options).unwrap(),
            "tea".repeat(100)
        );
    }

    #[test]
    fn allows_caller_to_supply_options_and_preserve_delayed_tags() {
        let options = [
            ("known/name", "before"),
            ("default/name", "fallback"),
            ("choice?family=inet", "later"),
            ("choice", "early"),
        ];
        let result = expand("<known/name> <default/name> <choice> <delayed>", |tag| {
            let conditional = format!("{tag}?family=inet");
            options
                .iter()
                .find(|(key, _)| *key == conditional)
                .or_else(|| options.iter().find(|(key, _)| *key == tag))
                .map(|(_, value)| (*value).to_owned())
        });
        assert_eq!(result.unwrap(), "before fallback later <delayed>");
    }

    #[test]
    fn finds_exact_tag_syntax_without_interpreting_regex() {
        let options = [("two\twords", "tab"), ("café", "yes"), ("empty", "")];
        assert_eq!(
            resolve(
                "(?P<user>.*) <two words> <two\twords> <café><empty> <> <",
                &options
            )
            .unwrap(),
            "(?P<user>.*) <two words> tab yes <> <"
        );
    }

    #[test]
    fn rejects_direct_indirect_and_constructed_cycles() {
        for options in [
            vec![("a", "<a>")],
            vec![("a", "<b>"), ("b", "<a>")],
            vec![("a", "<<b><c>>"), ("b", "d"), ("c", "e"), ("de", "x<a>")],
        ] {
            assert!(matches!(
                resolve("<a>", &options),
                Err(TagError::Recursive(_))
            ));
        }
    }

    #[test]
    fn rejects_oversized_and_excessive_expansion() {
        let input = "<grow>".repeat(100);
        let large = "x".repeat(MAX_VALUE_BYTES / 2);
        assert_eq!(
            resolve(&input, &[("grow", &large)]),
            Err(TagError::ValueLimit)
        );
        let long_chain = ["x".repeat(MAX_VALUE_BYTES / 2), "<n0>".to_owned()].concat();
        let result = expand(&long_chain, |name| {
            let index = name.strip_prefix('n')?.parse::<usize>().ok()?;
            Some(format!("<n{}>", index + 1))
        });
        assert_eq!(result, Err(TagError::WorkLimit));
    }
}
