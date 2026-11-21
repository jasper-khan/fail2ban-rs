//! Parse the original named filter and optional bracket parameters.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FilterSpec<'a> {
    pub(super) name: &'a str,
    pub(super) parameters: BTreeMap<String, String>,
}

/// Parse a filter expression as it appears in a jail's original INI.
/// Option names and literals are not case-folded and the last duplicate wins.
pub(super) fn parse(input: &str) -> Result<FilterSpec<'_>> {
    let mut spec = FilterSpec {
        name: input,
        parameters: BTreeMap::new(),
    };
    if input.is_empty() {
        return Err(Error::config("expected original Fail2Ban filter name"));
    }
    let Some((name, groups)) = input.split_once('[') else {
        return Ok(spec);
    };
    spec.name = name;
    let Some(mut body) = groups
        .trim_end()
        .strip_suffix(']')
        .filter(|_| !name.is_empty())
    else {
        return Err(Error::config("invalid original Fail2Ban filter brackets"));
    };
    loop {
        let rest = body.trim_start();
        if rest.is_empty() || rest.strip_prefix(',').is_some_and(|s| s.trim().is_empty()) {
            return Ok(spec);
        }
        let (key, value) = assignment(rest).ok_or_else(|| {
            Error::config("expected original Fail2Ban filter parameter assignment")
        })?;
        let (value, suffix) = parameter_value(value);
        spec.parameters
            .insert(key.to_owned(), value.trim().to_owned());
        if suffix.is_empty() {
            return Ok(spec);
        }
        body = if let Some(remaining) = suffix.strip_prefix(',') {
            remaining
        } else if let Some(remaining) = suffix
            .strip_prefix(']')
            .and_then(|s| s.trim_start().strip_prefix('['))
        {
            remaining
        } else {
            return Err(Error::config(format!(
                "invalid filter parameter separator after {key:?}"
            )));
        };
    }
}

fn is_key(ch: char) -> bool {
    ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.')
}

fn key_component(text: &str) -> (&str, &str) {
    text.split_at(text.find(|c| !is_key(c)).unwrap_or(text.len()))
}

fn assignment(text: &str) -> Option<(&str, &str)> {
    let (base, mut rest) = key_component(text);
    if base.is_empty() {
        return None;
    }
    if let Some(predicate) = rest.strip_prefix('?') {
        let (kind, tail) = key_component(predicate);
        let (value, next) = key_component(tail.strip_prefix('=')?);
        if kind.is_empty() || value.is_empty() {
            return None;
        }
        rest = next;
    }
    let key = text.get(..text.len() - rest.len())?;
    Some((key, rest.strip_prefix('=')?))
}

fn parameter_value(value: &str) -> (&str, &str) {
    if let Some(quote @ ('\'' | '"')) = value.chars().next()
        && let Some((inside, after)) = value.get(1..).and_then(|v| v.split_once(quote))
    {
        return (inside, after);
    }
    value.split_at(value.find([',', ']']).unwrap_or(value.len()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_grouped_and_quoted_parameters_without_changing_case() {
        let spec = parse(
            "sshd[mode=normal, match?family=inet6='test, with ] bracket'][mode=aggressive][EMPTY=]",
        )
        .unwrap();
        assert_eq!(spec.name, "sshd");
        assert_eq!(
            spec.parameters,
            BTreeMap::from([
                ("EMPTY".into(), String::new()),
                ("match?family=inet6".into(), "test, with ] bracket".into()),
                ("mode".into(), "aggressive".into()),
            ]),
        );
    }

    #[test]
    fn accepts_plain_name_empty_options_and_final_comma() {
        assert_eq!(parse("sshd").unwrap().name, "sshd");
        assert!(parse("sshd[]").unwrap().parameters.is_empty());
        assert_eq!(
            parse("sshd[mode= normal, ] ")
                .unwrap()
                .parameters
                .get("mode")
                .map(String::as_str),
            Some("normal"),
        );
    }

    #[test]
    fn rejects_non_assignments_unclosed_brackets_and_bad_separators() {
        for invalid in [
            "",
            "[a=b]",
            "sshd[a=b",
            "sshd[s]",
            "sshd[a='x' y]",
            "sshd[a=b, y]",
        ] {
            assert!(parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }
}
