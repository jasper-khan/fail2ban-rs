//! Per-line matching engine used by the watchers.
//!
//! `Modern` is the native pattern pipeline (`JailMatcher`). `Legacy` runs
//! the supported original 1.1.1 single-line file subset in the existing
//! daemon tailer: trusted-prefix capture, whole-second `{^LN-BEG}` dates,
//! and initial/live timestamp correction. File scheduling is unchanged.

use std::net::IpAddr;
use std::sync::Mutex;

use chrono::Datelike;

use crate::detect::date::DateParser;
use crate::detect::legacy_matcher::{LegacyMatcher, LineResult};
use crate::detect::legacy_observation_time::{DateObservation, FilePhase, ObservationClock};
use crate::detect::legacy_ssh_sessions::LegacySshSessions;
use crate::detect::matcher::JailMatcher;
use crate::error::Result;

/// One matched log line.
pub(crate) struct LineMatch {
    pub(crate) ip: IpAddr,
    /// Event time, after compatibility admission on the legacy path.
    pub(crate) timestamp: i64,
}

/// The per-line engine of one watcher: the native pattern pipeline or the
/// parity-proven original 1.1.1 matcher. Public because [`crate::detect::watcher::run`]
/// takes it in its signature.
/// Stateful wrapper around the parity-proven Fail2Ban 1.1.1 SSH normal-mode
/// session engine (`LegacySshSessions`).
pub struct LegacySshMatcher {
    sessions: Mutex<LegacySshSessions>,
    find_time: i64,
}

impl LegacySshMatcher {
    fn new(find_time: i64) -> Self {
        Self {
            sessions: Mutex::new(LegacySshSessions::new()),
            find_time,
        }
    }
}

pub enum LineMatcher {
    Modern(JailMatcher),
    Legacy(LegacyMatcher),
    LegacySsh(LegacySshMatcher),
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
    pub(crate) fn legacy(
        filter: &crate::config::legacy_filter::ResolvedFilter,
        find_time: i64,
    ) -> Result<Self> {
        if filter.ssh_normal {
            return Ok(Self::LegacySsh(LegacySshMatcher::new(find_time)));
        }
        let mut compiled = LegacyMatcher::compile(filter)?;
        compiled.file_find_time = Some(find_time);
        Ok(Self::Legacy(compiled))
    }

    pub(super) fn file_timing(&self) -> Option<FileTiming> {
        match self {
            Self::Legacy(matcher) => matcher.file_find_time.map(FileTiming::new),
            Self::LegacySsh(matcher) => Some(FileTiming::new(matcher.find_time)),
            Self::Modern(_) => None,
        }
    }

    /// Match one file record and return the IP with its event timestamp.
    /// Compat timestamps are rewritten only in the supported dated subset.
    pub(super) fn try_match(
        &self,
        line: &str,
        dates: &DateParser,
        file_timing: Option<&mut FileTiming>,
        now: impl FnOnce() -> i64,
    ) -> Option<LineMatch> {
        match self {
            Self::Modern(m) => {
                let m = m.try_match(line)?;
                let timestamp = dates.parse_line(line).unwrap_or_else(now);
                Some(LineMatch {
                    ip: m.ip,
                    timestamp,
                })
            }
            Self::Legacy(m) => {
                let result = m.evaluate_with_date(line, |timestamp| {
                    if let Some(timing) = file_timing {
                        timing.observation.admit(
                            DateObservation::Parsed(timestamp),
                            now(),
                            timing.phase,
                        )
                    } else {
                        Some(timestamp)
                    }
                });
                match result {
                    LineResult::Matched(failure) => Some(LineMatch {
                        ip: failure.ip,
                        timestamp: failure.timestamp,
                    }),
                    LineResult::Ignored { .. } | LineResult::Miss => None,
                }
            }
            Self::LegacySsh(m) => {
                let observed_at = now();
                let year = chrono::DateTime::from_timestamp(observed_at, 0)
                    .map_or_else(|| chrono::Utc::now().year(), |dt| dt.year());
                let failure = m
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .evaluate(line, year, observed_at)?;
                let timestamp = if let Some(timing) = file_timing {
                    timing.observation.admit(
                        DateObservation::Parsed(failure.timestamp),
                        observed_at,
                        timing.phase,
                    )?
                } else {
                    failure.timestamp
                };
                Some(LineMatch {
                    ip: failure.ip,
                    timestamp,
                })
            }
        }
    }
}

/// Keeps the original time policy separate from modern matching. The state
/// runs on the existing file reader, and switches to live at its first EOF.
/// Missing and invalid dates are not admitted by the compatibility matcher.
pub(super) struct FileTiming {
    observation: ObservationClock,
    phase: FilePhase,
}

impl FileTiming {
    fn new(find_time: i64) -> Self {
        Self {
            observation: ObservationClock::new(find_time),
            phase: FilePhase::Initial,
        }
    }

    pub(super) fn reached_eof(&mut self) {
        self.phase = FilePhase::Live;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::legacy_filter::ResolvedFilter;
    use crate::detect::date::DateFormat;

    const EVENT: i64 = 1_704_164_645;
    const FAILURE: &str = "2024/01/02 03:04:05 [error] account check, client: 192.0.2.41";
    const NONMATCH: &str = "2024/01/02 03:04:05 [notice] service ready";

    fn legacy() -> LineMatcher {
        let options = [
            ("datepattern", "{^LN-BEG}"),
            ("failregex", r"^\s*\[error\] account check, client: <ADDR>$"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        LineMatcher::legacy(
            &ResolvedFilter {
                ssh_normal: false,
                options,
                maxlines: Some(1),
            },
            60,
        )
        .expect("compile bounded dated example")
    }

    #[test]
    fn initial_cutoff_and_live_skew_are_strict_and_future_times_are_clamped() {
        let matcher = legacy();
        let dates = DateParser::new(DateFormat::Syslog).expect("create unused modern parser");
        let mut timing = matcher.file_timing().expect("compiled compat timing");
        let try_line = |clock: &mut FileTiming, now| {
            matcher
                .try_match(FAILURE, &dates, Some(clock), || now)
                .map(|matched| matched.timestamp)
        };
        assert_eq!(try_line(&mut timing, EVENT + 60), Some(EVENT));
        assert_eq!(try_line(&mut timing, EVENT + 61), None);
        assert_eq!(try_line(&mut timing, EVENT - 61), Some(EVENT - 61));

        timing.reached_eof();
        assert_eq!(try_line(&mut timing, EVENT + 60), Some(EVENT));
        assert_eq!(try_line(&mut timing, EVENT + 61), Some(EVENT + 61));
        assert_eq!(try_line(&mut timing, EVENT - 1), Some(EVENT - 1));
        assert_eq!(try_line(&mut timing, EVENT - 61), Some(EVENT - 61));
    }

    #[test]
    fn dated_nonmatch_updates_clock_but_legacy_reader_still_rejects_undated_records() {
        let matcher = legacy();
        let dates = DateParser::new(DateFormat::Syslog).expect("create unused modern parser");
        let mut timing = matcher.file_timing().expect("compiled compat timing");
        timing.reached_eof();
        assert!(
            matcher
                .try_match(NONMATCH, &dates, Some(&mut timing), || EVENT + 1)
                .is_none()
        );
        assert_eq!(
            timing
                .observation
                .admit(DateObservation::Missing, EVENT + 2, FilePhase::Live),
            Some(EVENT),
            "the valid timestamp was observed before regex rejected the record"
        );
        for invalid in [
            " [error] account check, client: 192.0.2.41",
            "2024/02/30 03:04:05 [error] account check, client: 192.0.2.41",
        ] {
            assert!(
                matcher
                    .try_match(invalid, &dates, Some(&mut timing), || EVENT + 2)
                    .is_none()
            );
        }
    }
}
