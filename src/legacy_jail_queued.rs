//! Deterministic original-jail observation and action-queue harness.
//!
//! Caller selects the observation phase and when the worker ticks. This
//! slice does not infer a phase from EOF or run threads, processes, sockets,
//! or enforcement. It recognizes only the existing dated file filter subset.

use crate::config::legacy_jail_plan::JailPlan;
use crate::detect::legacy_date::split_nginx_ln_begin;
use crate::detect::legacy_matcher::LineResult;
use crate::detect::legacy_observation_time::{DateObservation, FilePhase, ObservationClock};
use crate::error::{Error, Result};
use crate::legacy_jail_replay::ReplayDecision;
use crate::track::legacy_action_queue::LegacyActionQueue;
use crate::track::legacy_fail_manager::LegacyFailManager;

pub(crate) struct QueuedJail {
    plan: JailPlan,
    time: ObservationClock,
    failures: LegacyFailManager,
    actions: LegacyActionQueue,
    previous_clock: Option<i64>,
}

impl QueuedJail {
    pub(crate) fn new(plan: JailPlan) -> Result<Self> {
        let find_time = i64::try_from(plan.find_time)
            .map_err(|_| Error::config("findtime outside queued replay range"))?;
        Ok(Self {
            time: ObservationClock::new(find_time),
            failures: LegacyFailManager::new(plan.max_retry, plan.find_time),
            actions: LegacyActionQueue::for_replay(plan.ban_time_seconds),
            plan,
            previous_clock: None,
        })
    }

    fn advance(&mut self, now: i64) -> Result<()> {
        if self.previous_clock.is_some_and(|previous| previous > now) {
            return Err(Error::config(
                "queued replay observation time moved backwards",
            ));
        }
        self.previous_clock = Some(now);
        Ok(())
    }

    /// True means a qualifying ticket was queued, not that a ban occurred.
    pub(crate) fn observe(&mut self, line: &str, now: i64, phase: FilePhase) -> Result<bool> {
        self.advance(now)?;
        // Parse dates before matching: dated non-failures also update the
        // original filter's recent-time history.
        let parsed = split_nginx_ln_begin(line).and_then(|date| date.unix_seconds);
        let observation = parsed.map_or(DateObservation::Missing, DateObservation::Parsed);
        let Some(event_time) = self.time.admit(observation, now, phase) else {
            return Ok(false);
        };
        let LineResult::Matched(failure) = self.plan.matcher.evaluate(line) else {
            return Ok(false);
        };
        if self.plan.ignores(failure.ip) {
            return Ok(false);
        }
        self.failures.record(failure.ip, event_time);
        let Some(ticket) = self.failures.take_for_ban(Some(failure.ip)) else {
            return Ok(false);
        };
        self.actions.enqueue_failure(ticket.ip, ticket.time);
        Ok(true)
    }

    pub(crate) fn tick(&mut self, now: i64) -> Result<Vec<ReplayDecision>> {
        self.advance(now)?;
        let tick = self.actions.tick(now);
        let mut decisions = tick
            .newly_added()
            .map(|ip| ReplayDecision::Ban { ip, at: now })
            .collect::<Vec<_>>();
        decisions.extend(
            tick.expired
                .into_iter()
                .map(|ip| ReplayDecision::Unban { ip, at: now }),
        );
        Ok(decisions)
    }

    /// Counter cleanup is a caller-scheduled event, not a side-effect of every tick.
    pub(crate) fn cleanup_failures(&mut self, now: i64) -> Result<usize> {
        self.advance(now)?;
        Ok(self.failures.cleanup(now))
    }
}
