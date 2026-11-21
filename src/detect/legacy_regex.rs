//! Scoped regex compiler for original Fail2Ban single-line file filters.
//!
//! It compiles directly to the bounded Rust regex engine. Unsupported state
//! tags and Python-only regex operators are rejected rather than dropped or
//! approximated. This is not a general Python `re` compatibility layer.

use std::fmt;

use regex::Regex;

use crate::error::{Error, Result};

pub(super) const ADDRESS: &str = "f2b_address";
pub(super) const CONTENT: &str = "f2b_content";
pub(super) const USER: &str = "f2b_user";

const MAX_PATTERN_BYTES: usize = 64 * 1024;

// IP-shaped token, not an authorization or validity check. The caller must
// parse the entire capture as an IpAddr before returning a failure. Address
// brackets are optional outside the capture, as in original Fail2Ban.
const ADDR_TOKEN: &str = concat!(
    r"(?:",
    r"::ffff:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|",
    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|",
    r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){1,7}",
    r")",
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Prefix,
    Failure,
    Ignore,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Prefix => "prefregex",
            Self::Failure => "failregex",
            Self::Ignore => "ignoreregex",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capture {
    Content,
    User,
}

impl Capture {
    fn name(self) -> &'static str {
        match self {
            Self::Content => CONTENT,
            Self::User => USER,
        }
    }
}

fn config_error(role: Role, why: &str) -> Error {
    Error::config(format!("original Fail2Ban {role}: {why}"))
}

fn tag_at_start(rest: &str) -> Option<(&str, usize)> {
    let name = rest.strip_prefix('<')?;
    let end =
        name.find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '/')))?;
    let tag = name.get(..end)?;
    (!tag.is_empty() && name.as_bytes().get(end) == Some(&b'>')).then_some((tag, end + 2))
}

fn push_capture(out: &mut String, name: &str) {
    out.push_str("(?P<");
    out.push_str(name);
    out.push('>');
}

/// Compile an original filter regex for one line, without DNS or session
/// state. `<HOST>` is supported only as an alias of the IP-only `<ADDR>`.
pub(super) fn compile(pattern: &str, role: Role) -> Result<Regex> {
    if pattern.trim().is_empty() {
        return Err(config_error(role, "empty regex"));
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(config_error(role, "regex exceeds the size limit"));
    }
    if pattern.contains(['\n', '\r']) {
        return Err(config_error(role, "multiline regexes are unsupported"));
    }

    let mut expanded = String::with_capacity(pattern.len());
    let mut captures = Vec::new();
    let mut previous = None;
    let mut class = false;
    let mut class_first = false;
    let mut address = false;
    let mut cursor = 0;
    while let Some(rest) = pattern.get(cursor..).filter(|s| !s.is_empty()) {
        let Some(ch) = rest.chars().next() else {
            break;
        };
        if ch == '\\' {
            if rest
                .get(1..)
                .and_then(|s| s.chars().next())
                .is_some_and(|next| matches!(next, '0'..='9' | 'n' | 'p' | 'P' | 'k' | 'z' | 'Z'))
            {
                return Err(config_error(role, "unsupported regex escape"));
            }
            if let Some((tag, _)) = rest.get(1..).and_then(tag_at_start)
                && is_filter_tag(tag)
            {
                return Err(config_error(role, "escaped filter tags are unsupported"));
            }
            if let Some(next) = rest.get(1..).and_then(|s| s.chars().next()) {
                expanded.push('\\');
                expanded.push(next);
                cursor += 1 + next.len_utf8();
            } else {
                expanded.push(ch);
                cursor += 1;
            }
            class_first = false;
            previous = None;
            continue;
        }

        if ch == '<'
            && let Some((tag, length)) = tag_at_start(rest)
            && is_filter_tag(tag)
        {
            if class {
                return Err(config_error(
                    role,
                    "filter tags inside a character class are unsupported",
                ));
            }
            match tag {
                "ADDR" | "HOST" => {
                    if address {
                        return Err(config_error(role, "more than one address tag"));
                    }
                    address = true;
                    expanded.push_str(r"\[?");
                    push_capture(&mut expanded, ADDRESS);
                    expanded.push_str(ADDR_TOKEN);
                    expanded.push_str(r")\]?");
                }
                "F-CONTENT" | "F-USER" => {
                    let capture = if tag == "F-CONTENT" {
                        if role != Role::Prefix {
                            return Err(config_error(
                                role,
                                "F-CONTENT is only supported in prefregex",
                            ));
                        }
                        Capture::Content
                    } else {
                        Capture::User
                    };
                    captures.push(capture);
                    push_capture(&mut expanded, capture.name());
                }
                "/F-CONTENT" | "/F-USER" => {
                    let capture = if tag == "/F-CONTENT" {
                        Capture::Content
                    } else {
                        Capture::User
                    };
                    if captures.pop() != Some(capture) {
                        return Err(config_error(
                            role,
                            &format!("mismatched filter tag <{tag}>"),
                        ));
                    }
                    expanded.push(')');
                }
                _ => {
                    return Err(config_error(
                        role,
                        &format!("unsupported filter tag <{tag}>"),
                    ));
                }
            }
            cursor += length;
            previous = None;
            continue;
        }

        if class {
            if rest.starts_with("&&") || rest.starts_with("--") || rest.starts_with("~~") {
                return Err(config_error(
                    role,
                    "character class set operators are unsupported",
                ));
            }
            match ch {
                '[' => {
                    return Err(config_error(
                        role,
                        "nested character classes are unsupported",
                    ));
                }
                ']' if !class_first => class = false,
                _ => {}
            }
            // Immediately after '[' or '[^', a ']' is a literal.
            if !(class_first && ch == '^' && previous == Some('[')) {
                class_first = false;
            }
        } else {
            if ch == '(' && rest.starts_with("(?") && !rest.starts_with("(?:") {
                return Err(config_error(role, "unsupported regex group extension"));
            }
            if ch == '+' && previous.is_some_and(|c| matches!(c, '*' | '+' | '?' | '}')) {
                return Err(config_error(role, "possessive quantifiers are unsupported"));
            }
            if ch == '[' {
                class = true;
                class_first = true;
            }
        }
        previous = Some(ch);
        expanded.push(ch);
        cursor += ch.len_utf8();
    }
    if !captures.is_empty() {
        return Err(config_error(role, "unclosed filter capture tag"));
    }
    Regex::new(&expanded).map_err(|source| Error::Regex {
        pattern: pattern.to_owned(),
        source,
    })
}

fn is_filter_tag(tag: &str) -> bool {
    matches!(
        tag,
        "ADDR" | "HOST" | "IP4" | "IP6" | "DNS" | "CIDR" | "SUBNET" | "SKIPLINES"
    ) || tag.starts_with("F-")
        || tag.starts_with("/F-")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn separates_prefix_content_and_ip_then_captures_user() {
        let prefix = compile(
            r"^\s*\[(?:error|crit)\] [0-9]+#[0-9]+: \*[0-9]+\s+<F-CONTENT>.*</F-CONTENT>, client: <ADDR>(?:, server: \S+)?\s*$",
            Role::Prefix,
        )
        .unwrap();
        let failure = compile(
            r#"^user "<F-USER>(?:[^"]+|.*?)</F-USER>":? password mismatch$"#,
            Role::Failure,
        )
        .unwrap();
        let line = r#"  [error] 12#34: *56 user "sample user": password mismatch, client: [2001:db8::7], server: example.test"#;
        let prefix_match = prefix.captures(line).unwrap();
        let ip = prefix_match.name(ADDRESS).unwrap().as_str();
        assert_eq!(ip.parse::<IpAddr>().unwrap().to_string(), "2001:db8::7");
        let content = prefix_match.name(CONTENT).unwrap().as_str();
        let failure_match = failure.captures(content).unwrap();
        assert_eq!(failure_match.name(USER).unwrap().as_str(), "sample user");
        assert!(failure_match.name(ADDRESS).is_none());
    }

    #[test]
    fn preserves_single_line_regexes_without_capture_tags() {
        let expression = compile(r"^sample [^0-9]+$", Role::Ignore).unwrap();
        assert!(expression.is_match("sample test"));
        assert!(!expression.is_match("sample test3"));
        assert!(
            compile(r"^literal <text>$", Role::Ignore)
                .unwrap()
                .is_match("literal <text>")
        );
    }

    #[test]
    fn host_is_an_ip_only_alias_with_full_capture() {
        let expression = compile(r"^source <HOST>$", Role::Failure).unwrap();
        for address in [
            "192.0.2.8",
            "2001:0db8:0000:0000:0000:0000:0000:0007",
            "2001:db8::",
            "::",
            "::ffff:192.0.2.8",
        ] {
            let line = format!("source [{address}]");
            let captures = expression.captures(&line).unwrap();
            let raw_ip = captures.name(ADDRESS).unwrap().as_str();
            assert_eq!(raw_ip, address);
            assert!(raw_ip.parse::<IpAddr>().is_ok());
        }
        assert!(!expression.is_match("source example.test"));
    }

    #[test]
    fn explicitly_rejects_out_of_scope_fail2ban_tags() {
        for pattern in [
            r"^<F-NOFAIL>message</F-NOFAIL> from <ADDR>",
            r"^<F-MLFID>session</F-MLFID> from <ADDR>",
            r"^first<SKIPLINES>from <ADDR>",
            r"^source <SUBNET>",
            r"^raw <F-ID/>",
            r"^<F-USER>sample</F-CONTENT>",
            r"^<F-USER>sample",
            r"^source <ADDR> route <ADDR>",
            r"^source [<ADDR>]",
            r"^source \<ADDR>",
        ] {
            assert!(
                compile(pattern, Role::Failure).is_err(),
                "accepted unsupported pattern {pattern}"
            );
        }
    }

    #[test]
    fn explicitly_rejects_incompatible_regex_syntax() {
        for pattern in [
            r"^(?<!prefix)sample from <ADDR>",
            r"^(?P<kind>sample)?(?(kind) value) from <ADDR>",
            r"^(?>sample) from <ADDR>",
            r"^sample++ from <ADDR>",
            r"^(sample) \1 from <ADDR>",
            r"^sample\nfrom <ADDR>",
            r"^sample\Z",
            r"^(?<f2b_address>sample)$",
            r"^[a&&b] from <ADDR>",
            r"^invalid [$",
        ] {
            assert!(
                compile(pattern, Role::Failure).is_err(),
                "accepted unsupported pattern {pattern}"
            );
        }
    }
}
