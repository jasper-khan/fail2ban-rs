//! Whole-second timestamp admission for the original Fail2Ban 1.1.1 file path.
//!
//! The caller supplies clock and file phase. This model has no clock reads,
//! regex admission, date parsing, logging, queue, scheduler, or matcher side
//! effects. Upstream fractional timestamps/clock ticks and its preserved
//! date-text buffer are outside this slice.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilePhase {
    /// Existing log content before the first EOF.
    Initial,
    /// Subsequent file observations, after the file reaches EOF.
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DateObservation {
    Parsed(i64),
    /// The date detector matched an empty group (optional date).
    MatchedEmpty,
    /// No date group, or a nonempty group that could not convert to epoch time.
    Missing,
}

const RECENT_SECONDS: i128 = 60;

#[derive(Debug)]
pub(crate) struct ObservationClock {
    find_time: i64,
    last_date: Option<i64>,
}

impl ObservationClock {
    pub(crate) fn new(find_time: i64) -> Self {
        Self {
            find_time,
            last_date: None,
        }
    }

    /// Observe one parsed line BEFORE any failure matching or ignore rules.
    /// Returns the timestamp a qualifying failure ticket would receive, or
    /// None if the original file filter would discard it for timing reasons.
    ///
    /// Mirrors the original with checkFindTime enabled and a single explicit
    /// now reused for date normalization and the final future clamp.
    pub(crate) fn admit(
        &mut self,
        parsed: DateObservation,
        now: i64,
        phase: FilePhase,
    ) -> Option<i64> {
        let date = match parsed {
            DateObservation::Parsed(date) => {
                // Upstream remembers the parsed date even if this line is
                // subsequently ignored or falls outside the initial window.
                self.last_date = Some(date);
                date
            }
            DateObservation::MatchedEmpty => self.recent_date(now).unwrap_or(now),
            DateObservation::Missing => match phase {
                FilePhase::Initial => self.recent_date(now)?,
                FilePhase::Live => self.recent_date(now).unwrap_or(now),
            },
        };

        // Widen before subtracting; all i64 values and their differences fit
        // in i128. Original Python compares arbitrary-precision seconds here.
        let delta = i128::from(date) - i128::from(now);
        let adjusted = match phase {
            FilePhase::Initial if delta < -i128::from(self.find_time) => return None,
            FilePhase::Live if delta.abs() > RECENT_SECONDS => {
                self.last_date = Some(now);
                now
            }
            FilePhase::Initial | FilePhase::Live => date,
        };
        // The late processLineAndAdd clamp changes the ticket, not last_date.
        Some(adjusted.min(now))
    }

    fn recent_date(&self, now: i64) -> Option<i64> {
        self.last_date.filter(|&date| {
            // Original lastDate truthiness test treats the UNIX epoch as false.
            date != 0 && i128::from(date) > i128::from(now) - RECENT_SECONDS
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_cutoff_is_strict_and_future_clamp_does_not_modify_history() {
        let mut clock = ObservationClock::new(120);
        assert_eq!(
            clock.admit(DateObservation::Parsed(879), 1000, FilePhase::Initial),
            None
        );
        assert_eq!(clock.last_date, Some(879));
        assert_eq!(
            clock.admit(DateObservation::Parsed(880), 1000, FilePhase::Initial),
            Some(880)
        );
        assert_eq!(
            clock.admit(DateObservation::Parsed(1200), 1000, FilePhase::Initial),
            Some(1000)
        );
        assert_eq!(clock.last_date, Some(1200));
        assert_eq!(
            clock.admit(DateObservation::Missing, 1201, FilePhase::Initial),
            Some(1200)
        );
    }

    #[test]
    fn live_outlier_is_strict_and_changes_later_missing_timestamp() {
        let mut clock = ObservationClock::new(120);
        assert_eq!(
            clock.admit(DateObservation::Parsed(940), 1000, FilePhase::Live),
            Some(940)
        );
        assert_eq!(clock.last_date, Some(940));
        assert_eq!(
            clock.admit(DateObservation::Parsed(939), 1000, FilePhase::Live),
            Some(1000)
        );
        assert_eq!(clock.last_date, Some(1000));
        assert_eq!(
            clock.admit(DateObservation::Missing, 1001, FilePhase::Live),
            Some(1000)
        );
        assert_eq!(
            clock.admit(DateObservation::Parsed(1060), 1000, FilePhase::Live),
            Some(1000)
        );
        assert_eq!(clock.last_date, Some(1060));
        assert_eq!(
            clock.admit(DateObservation::Parsed(1061), 1000, FilePhase::Live),
            Some(1000)
        );
        assert_eq!(clock.last_date, Some(1000));
    }

    #[test]
    fn optional_empty_and_missing_differ_without_recent_history() {
        let mut clock = ObservationClock::new(120);
        assert_eq!(
            clock.admit(DateObservation::Missing, 1000, FilePhase::Initial),
            None
        );
        assert_eq!(
            clock.admit(DateObservation::MatchedEmpty, 1000, FilePhase::Initial),
            Some(1000)
        );
        assert_eq!(clock.last_date, None);
        assert_eq!(
            clock.admit(DateObservation::Missing, 1001, FilePhase::Live),
            Some(1001)
        );
        assert_eq!(clock.last_date, None);

        assert_eq!(
            clock.admit(DateObservation::Parsed(950), 1000, FilePhase::Initial),
            Some(950)
        );
        assert_eq!(
            clock.admit(DateObservation::Missing, 1009, FilePhase::Initial),
            Some(950)
        );
        assert_eq!(
            clock.admit(DateObservation::Missing, 1010, FilePhase::Initial),
            None
        );
        assert_eq!(
            clock.admit(DateObservation::MatchedEmpty, 1010, FilePhase::Live),
            Some(1010)
        );
        assert_eq!(clock.last_date, Some(950));
        assert_eq!(
            clock.admit(DateObservation::Parsed(0), 5, FilePhase::Initial),
            Some(0)
        );
        assert_eq!(
            clock.admit(DateObservation::Missing, 5, FilePhase::Initial),
            None
        );
    }

    #[test]
    fn differences_do_not_overflow_at_whole_second_limits() {
        let mut clock = ObservationClock::new(i64::MAX);
        assert_eq!(
            clock.admit(
                DateObservation::Parsed(i64::MIN),
                i64::MAX,
                FilePhase::Initial
            ),
            None
        );
        assert_eq!(
            clock.admit(DateObservation::Parsed(i64::MAX), i64::MIN, FilePhase::Live),
            Some(i64::MIN)
        );
    }
}
