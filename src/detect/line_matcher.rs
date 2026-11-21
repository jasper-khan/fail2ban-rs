//! Per-line matching engine used by the watchers.
//!
//! `Modern` is the native pattern pipeline (`JailMatcher`). `Legacy` runs
//! the offline-parity original 1.1.1 engine (nginx-class file filters:
//! prefregex with trusted-prefix capture, `{^LN-BEG}` dates) inside the
//! live daemon path, so compatibility-tree filters keep original match
//! and timestamp semantics.

use std::net::IpAddr;

use crate::detect::date::DateParser;
use crate::detect::legacy_matcher::{LegacyMatcher, LineResult};
use crate::detect::matcher::JailMatcher;
use crate::error::Result;

/// One matched log line.
pub(crate) struct LineMatch {
    pub(crate) ip: IpAddr,
    /// The line's timestamp: extracted by the legacy engine itself, or via
    /// the date parser on the modern path.
    pub(crate) timestamp: i64,
}

/// The per-line engine of one watcher: the native pattern pipeline or the
/// parity-proven original 1.1.1 matcher. Public because [`crate::detect::watcher::run`]
/// takes it in its signature.
pub enum LineMatcher {
    Modern(JailMatcher),
    Legacy(LegacyMatcher),
}

impl LineMatcher {
    /// Compile the native engine from jail patterns.
    pub(crate) fn modern(filter: &[String], ignoreregex: &[String]) -> Result<Self> {
        Ok(Self::Modern(if ignoreregex.is_empty() {
            JailMatcher::new(filter)?
        } else {
            JailMatcher::with_ignoreregex(filter, ignoreregex)?
        }))
    }

    /// Compile the original 1.1.1 engine from a resolved filter.
    pub(crate) fn legacy(filter: &crate::config::legacy_filter::ResolvedFilter) -> Result<Self> {
        Ok(Self::Legacy(LegacyMatcher::compile(filter)?))
    }

    /// Match one line, returning the offending IP and its log timestamp.
    pub(crate) fn try_match(&self, line: &str, dates: &DateParser) -> Option<LineMatch> {
        match self {
            Self::Modern(m) => {
                let m = m.try_match(line)?;
                let timestamp = dates
                    .parse_line(line)
                    .unwrap_or_else(|| chrono::Utc::now().timestamp());
                Some(LineMatch {
                    ip: m.ip,
                    timestamp,
                })
            }
            Self::Legacy(m) => match m.evaluate(line) {
                LineResult::Matched(failure) => Some(LineMatch {
                    ip: failure.ip,
                    timestamp: failure.timestamp,
                }),
                LineResult::Ignored { .. } | LineResult::Miss => None,
            },
        }
    }
}
