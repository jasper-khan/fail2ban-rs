//! Offline single-record matching for the original file-filter semantics.
//!
//! This is deliberately smaller than Fail2Ban's server Filter. It handles the
//! stock nginx HTTP-auth pipeline, including trusted prefix capture, and
//! returns match evidence without queueing failures or invoking actions.

use std::borrow::Cow;
use std::net::IpAddr;

use regex::{Captures, Regex};

use crate::config::legacy_filter::ResolvedFilter;
use crate::detect::extract::normalize_mapped;
use crate::detect::legacy_date::split_nginx_ln_begin;
use crate::detect::legacy_regex::{self, ADDRESS, CONTENT, Role, USER};
use crate::detect::watcher::MAX_LINE_LEN;
use crate::error::{Error, Result};

/// Public because it sits in the [`LineMatcher`](crate::detect::line_matcher::LineMatcher)
/// public enum; compiling stays crate-internal.
#[derive(Debug)]
pub struct LegacyMatcher {
    prefix: Option<Regex>,
    prefix_has_address: bool,
    failures: Vec<Regex>,
    ignores: Vec<Regex>,
    pub(super) file_find_time: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LineResult {
    Matched(Failure),
    Ignored {
        /// Index in the ordered ignoreregex list, not in the failures list.
        pattern_idx: usize,
    },
    Miss,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) ip: IpAddr,
    pub(crate) timestamp: i64,
    pub(crate) pattern_idx: usize,
    pub(crate) user: Option<String>,
}

impl LegacyMatcher {
    pub(crate) fn compile(filter: &ResolvedFilter) -> Result<Self> {
        let option = |key: &str| filter.options.get(key).map(String::as_str);
        if option("logtype").is_some_and(|value| value != "file") {
            return Err(Error::config(
                "legacy matcher supports file-format filters only",
            ));
        }
        if filter.maxlines.is_some_and(|n| n != 1) {
            return Err(Error::config(
                "legacy matcher does not support multiline filters",
            ));
        }
        if option("datepattern") != Some("{^LN-BEG}") {
            return Err(Error::config(
                "legacy matcher supports only datepattern {^LN-BEG} with the nginx timestamp format",
            ));
        }
        let usedns = option("usedns");
        if usedns.is_some_and(|value| value != "no") {
            return Err(Error::config(
                "legacy matcher does not support DNS; set usedns=no",
            ));
        }
        let compile = |pattern: &str, role| {
            if usedns != Some("no") && pattern.contains("<HOST>") {
                return Err(Error::config(
                    "legacy matcher requires usedns=no for <HOST>",
                ));
            }
            legacy_regex::compile(pattern, role)
        };
        let prefix = option("prefregex")
            .filter(|pattern| !pattern.is_empty())
            .map(|pattern| compile(pattern, Role::Prefix))
            .transpose()?;
        let prefix_has_address = prefix.as_ref().is_some_and(has_address);
        let failures = split_rules(option("failregex"))
            .map(|pattern| {
                let rule = compile(pattern, Role::Failure)?;
                if has_address(&rule) == prefix_has_address {
                    return Err(Error::config(if prefix_has_address {
                        // Stock nginx has a single authoritative prefix IP.
                        // Upstream merges capture dictionaries in other rules;
                        // this subset intentionally does not resolve conflicts.
                        "legacy matcher does not support IP captures in both prefregex and failregex"
                    } else {
                        "legacy failregex must supply an IP when prefregex supplies none"
                    }));
                }
                Ok(rule)
            })
            .collect::<Result<Vec<_>>>()?;
        if failures.is_empty() {
            return Err(Error::config(
                "legacy matcher requires at least one failregex",
            ));
        }
        let ignores = split_rules(option("ignoreregex"))
            .map(|pattern| compile(pattern, Role::Ignore))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            prefix,
            prefix_has_address,
            failures,
            ignores,
            file_find_time: None,
        })
    }

    /// Evaluate one dated file record; no inherited clock, I/O, or state.
    ///
    /// Missing and invalid dates are both missed. This slice uses a single
    /// Rust record buffer, not Python's synthetic trailing newline; original
    /// filters depending on that extra character are outside this subset.
    pub(crate) fn evaluate(&self, line: &str) -> LineResult {
        self.evaluate_with_date(line, Some)
    }

    /// Apply timestamp admission before regex and ignore evaluation, retaining
    /// the original supported whole-second dated record subset.
    pub(super) fn evaluate_with_date(
        &self,
        line: &str,
        admit: impl FnOnce(i64) -> Option<i64>,
    ) -> LineResult {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.len() > MAX_LINE_LEN || line.contains(['\r', '\n']) {
            return LineResult::Miss;
        }
        let Some(date) = split_nginx_ln_begin(line) else {
            return LineResult::Miss;
        };
        let Some(timestamp) = date.unix_seconds.and_then(admit) else {
            return LineResult::Miss;
        };
        let whole = if date.before.is_empty() {
            Cow::Borrowed(date.after)
        } else {
            Cow::Owned(format!("{}{}", date.before, date.after))
        };

        // In upstream findFailure, an inexpensive ignore list can short
        // circuit against the full timestamp-stripped buffer before prefregex.
        if self.ignores.len().saturating_add(2) < self.failures.len()
            && let Some(pattern_idx) = first_ignore(&self.ignores, &whole)
        {
            return LineResult::Ignored { pattern_idx };
        }
        let (prefix, content) = if let Some(rule) = &self.prefix {
            let Some(captures) = rule.captures(&whole) else {
                return LineResult::Miss;
            };
            let content = capture(&captures, CONTENT)
                .filter(|value| !value.is_empty())
                .unwrap_or(&whole);
            (Some(captures), content)
        } else {
            (None, whole.as_ref())
        };
        let prefix_user = prefix.as_ref().and_then(|captures| capture(captures, USER));
        let prefix_address = prefix
            .as_ref()
            .and_then(|captures| capture(captures, ADDRESS));

        for (pattern_idx, rule) in self.failures.iter().enumerate() {
            let Some(captures) = rule.captures(content) else {
                continue;
            };
            // For MaxLines=1, original _ignoreLine sees the same narrowed
            // buffer as the failregex; do not redo this on the outer record.
            if let Some(pattern_idx) = first_ignore(&self.ignores, content) {
                return LineResult::Ignored { pattern_idx };
            }
            let address = if self.prefix_has_address {
                prefix_address
            } else {
                capture(&captures, ADDRESS)
            };
            let Some(ip) = address.and_then(|value| value.parse::<IpAddr>().ok()) else {
                // Do not try another source after a selected rule's capture
                // failed validation.
                return LineResult::Miss;
            };
            let user = capture(&captures, USER).or(prefix_user).map(str::to_owned);
            return LineResult::Matched(Failure {
                ip: normalize_mapped(ip),
                timestamp,
                pattern_idx,
                user,
            });
        }
        LineResult::Miss
    }
}

fn split_rules(list: Option<&str>) -> impl Iterator<Item = &str> {
    list.into_iter()
        .flat_map(|text| text.split('\n'))
        .filter(|pattern| !pattern.is_empty())
}

fn has_address(regex: &Regex) -> bool {
    regex
        .capture_names()
        .flatten()
        .any(|group| group == ADDRESS)
}

fn capture<'h>(captures: &Captures<'h>, key: &str) -> Option<&'h str> {
    captures.name(key).map(|matched| matched.as_str())
}

fn first_ignore(ignores: &[Regex], line: &str) -> Option<usize> {
    ignores.iter().position(|regex| regex.is_match(line))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "legacy_matcher_test.rs"]
mod tests;
