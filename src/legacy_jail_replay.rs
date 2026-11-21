//! Isolated original-jail replay for a single supported legacy file case.
//!
//! The configuration is read in the original format. Log lines, clock ticks,
//! and housekeeping points are supplied by the caller; no log is opened,
//! process started, shell rendered, or real action dispatched. This does not
//! model concurrent scheduler, observation-date correction, or a live jail.

use std::net::IpAddr;
use std::path::Path;

use crate::config::legacy_jail_plan::{self, JailPlan};
use crate::detect::legacy_matcher::LineResult;
use crate::error::{Error, Result};
use crate::track::legacy_jail::LegacyJail;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayStep<'a> {
    /// Deliver one line at an explicit observation time.
    Line { line: &'a str, observed_at: i64 },
    /// Run the expiry pass at the specified time.
    Expire { now: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayDecision {
    Ban { ip: IpAddr, at: i64 },
    Unban { ip: IpAddr, at: i64 },
}

/// Retain typed decision state across multiple caller-driven checkpoints.
pub(crate) struct RecordedJail {
    plan: JailPlan,
    state: LegacyJail,
    previous: Option<i64>,
}

impl RecordedJail {
    pub(crate) fn new(plan: JailPlan) -> Self {
        let state = LegacyJail::for_replay(plan.max_retry, plan.find_time, plan.ban_time_seconds);
        Self {
            plan,
            state,
            previous: None,
        }
    }

    fn check_clock(&self, at: i64) -> Result<()> {
        if self.previous.is_some_and(|earlier| earlier > at) {
            return Err(Error::config(
                "legacy replay observation time moved backwards",
            ));
        }
        Ok(())
    }

    pub(crate) fn feed_line(&mut self, line: &str, at: i64) -> Result<Option<ReplayDecision>> {
        self.check_clock(at)?;
        let decision = if let LineResult::Matched(failure) = self.plan.matcher.evaluate(line)
            && !self.plan.ignores(failure.ip)
        {
            // This slice checks zero-latency logs. Older or future record
            // timing is a separate, live/initial-mode compatibility concern.
            if failure.timestamp != at {
                return Err(Error::config(
                    "legacy replay only supports matched events at their observation time",
                ));
            }
            self.state
                .record(failure.ip, failure.timestamp, at)
                .newly_banned()
                .then_some(ReplayDecision::Ban { ip: failure.ip, at })
        } else {
            None
        };
        self.previous = Some(at);
        Ok(decision)
    }

    pub(crate) fn expire(&mut self, at: i64) -> Result<Vec<ReplayDecision>> {
        self.check_clock(at)?;
        self.previous = Some(at);
        Ok(self
            .state
            .expire(at)
            .into_iter()
            .map(|ip| ReplayDecision::Unban { ip, at })
            .collect())
    }
}

pub(crate) fn replay(
    base: &Path,
    jail: &str,
    operations: &[ReplayStep<'_>],
) -> Result<Vec<ReplayDecision>> {
    let mut jail = RecordedJail::new(legacy_jail_plan::read(base, jail)?);
    let mut decisions = Vec::new();
    for step in operations {
        match *step {
            ReplayStep::Line { line, observed_at } => {
                decisions.extend(jail.feed_line(line, observed_at)?);
            }
            ReplayStep::Expire { now } => decisions.extend(jail.expire(now)?),
        }
    }
    Ok(decisions)
}
