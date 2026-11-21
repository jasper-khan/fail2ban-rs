//! Deterministic original-jail observation and action-queue harness.
//!
//! Caller selects the observation phase and when the worker ticks. The jail
//! shares the original failure-maintenance gate across file sources. This
//! does not infer EOF phase or run threads, processes, sockets or enforcement.

#[cfg(test)]
use std::net::IpAddr;

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
    maintenance: Maintenance,
    filter_budget: FilterBudget,
    previous_clock: Option<i64>,
}

#[derive(Default)]
struct FilterBudget {
    errors: u8,
    idle: bool,
}

impl FilterBudget {
    fn stat_error(&mut self) {
        self.errors += 1;
        if self.errors >= 100 {
            self.errors /= 2;
            self.idle = true;
        }
    }

    fn processed_line(&mut self) {
        self.errors /= 2;
    }
}

struct Maintenance {
    processed_lines: u8,
    completed_polls: u8,
    next_service: i128,
    #[cfg(test)]
    trace: Vec<(i64, usize)>,
}

impl Default for Maintenance {
    fn default() -> Self {
        Self {
            processed_lines: 0,
            completed_polls: 0,
            next_service: i128::from(i64::MIN),
            #[cfg(test)]
            trace: Vec::new(),
        }
    }
}

impl Maintenance {
    fn request(&mut self, now: i64, failures: &mut LegacyFailManager) {
        let now_wide = i128::from(now);
        if now_wide < self.next_service {
            return;
        }
        self.next_service = now_wide + 5;
        let removed = failures.cleanup(now);
        #[cfg(test)]
        self.trace.push((now, removed));
        #[cfg(not(test))]
        let _ = removed;
    }

    fn line(&mut self, now: i64, failures: &mut LegacyFailManager) {
        self.processed_lines = (self.processed_lines + 1) % 100;
        if self.processed_lines == 0 {
            self.request(now, failures);
        }
    }

    fn poll(&mut self, now: i64, active: bool, failures: &mut LegacyFailManager) {
        self.completed_polls = (self.completed_polls + 1) % 10;
        if active && self.completed_polls == 0 {
            self.request(now, failures);
        }
    }
}

impl QueuedJail {
    pub(crate) fn new(plan: JailPlan) -> Result<Self> {
        let find_time = i64::try_from(plan.find_time)
            .map_err(|_| Error::config("findtime outside queued replay range"))?;
        Ok(Self {
            time: ObservationClock::new(find_time),
            failures: LegacyFailManager::new(plan.max_retry, plan.find_time),
            actions: LegacyActionQueue::for_replay(plan.ban_time_seconds),
            maintenance: Maintenance::default(),
            filter_budget: FilterBudget::default(),
            plan,
            previous_clock: None,
        })
    }

    pub(crate) fn validate_clock(&self, now: i64) -> Result<()> {
        if self.previous_clock.is_some_and(|previous| previous > now) {
            return Err(Error::config(
                "queued replay observation time moved backwards",
            ));
        }
        Ok(())
    }

    fn advance(&mut self, now: i64) -> Result<()> {
        self.validate_clock(now)?;
        self.previous_clock = Some(now);
        Ok(())
    }

    /// True means a qualifying ticket was queued, not that a ban occurred.
    pub(crate) fn observe(&mut self, line: &str, now: i64, phase: FilePhase) -> Result<bool> {
        self.advance(now)?;
        let queued = self.observe_finding(line, now, phase);
        // Original procLines increments after the complete matching loop,
        // including successful processing of misses and ignored/rejected lines.
        self.maintenance.line(now, &mut self.failures);
        self.filter_budget.processed_line();
        Ok(queued)
    }

    fn observe_finding(&mut self, line: &str, now: i64, phase: FilePhase) -> bool {
        // Parse dates before matching: dated non-failures also update the
        // original filter's recent-time history.
        let parsed = split_nginx_ln_begin(line).and_then(|date| date.unix_seconds);
        let observation = parsed.map_or(DateObservation::Missing, DateObservation::Parsed);
        let Some(event_time) = self.time.admit(observation, now, phase) else {
            return false;
        };
        let LineResult::Matched(failure) = self.plan.matcher.evaluate(line) else {
            return false;
        };
        if self.plan.ignores(failure.ip) {
            return false;
        }
        self.failures.record(failure.ip, event_time);
        let Some(ticket) = self.failures.take_for_ban(Some(failure.ip)) else {
            return false;
        };
        self.actions.enqueue_failure(ticket.ip, ticket.time);
        // Original performBan hands the ticket to the queue before requesting
        // maintenance. A simultaneous 100th-line trigger shares this gate.
        self.maintenance.request(now, &mut self.failures);
        true
    }

    /// Called only after an entire active polling iteration succeeds.
    pub(crate) fn complete_active_poll(&mut self, now: i64) -> Result<()> {
        self.advance(now)?;
        self.maintenance.poll(now, true, &mut self.failures);
        Ok(())
    }

    pub(crate) fn note_stat_error(&mut self) {
        self.filter_budget.stat_error();
    }

    pub(crate) fn filter_idle(&self) -> bool {
        self.filter_budget.idle
    }

    #[cfg(test)]
    pub(crate) fn filter_errors(&self) -> u8 {
        self.filter_budget.errors
    }

    pub(crate) fn idle_timeout(&mut self, now: i64) -> Result<()> {
        if !self.filter_idle() {
            return Err(Error::config("queued replay filter is not idle"));
        }
        self.advance(now)?;
        self.maintenance.poll(now, false, &mut self.failures);
        Ok(())
    }

    pub(crate) fn resume_filter(&mut self) {
        self.filter_budget.idle = false;
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

    /// Existing explicit state-only cleanup, independent of the service gate
    /// and never invoked from an action tick.
    pub(crate) fn cleanup_failures(&mut self, now: i64) -> Result<usize> {
        self.advance(now)?;
        Ok(self.failures.cleanup(now))
    }

    #[cfg(test)]
    pub(crate) fn maintenance_trace(&self) -> &[(i64, usize)] {
        &self.maintenance.trace
    }

    #[cfg(test)]
    pub(crate) fn maintenance_counts(&self) -> (u8, u8) {
        (
            self.maintenance.processed_lines,
            self.maintenance.completed_polls,
        )
    }

    #[cfg(test)]
    pub(crate) fn failure_retry(&self, ip: IpAddr) -> Option<u64> {
        self.failures.ticket(ip).map(|ticket| ticket.retry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_is_shared_and_suppression_does_not_move_the_deadline() {
        let mut maintenance = Maintenance::default();
        let mut failures = LegacyFailManager::new(2, 10);
        let address = "192.0.2.10".parse().expect("fixture IP");
        failures.record(address, 95);
        maintenance.request(100, &mut failures);
        for _ in 0..10 {
            maintenance.poll(104, true, &mut failures);
        }
        assert!(failures.ticket(address).is_some());
        for _ in 0..100 {
            maintenance.line(105, &mut failures);
        }
        assert_eq!(maintenance.trace, [(100, 0), (105, 1)]);
        assert!(failures.ticket(address).is_none());
        assert_eq!(
            (maintenance.processed_lines, maintenance.completed_polls),
            (0, 0)
        );
    }

    #[test]
    fn gate_extends_beyond_the_largest_model_clock_without_overflow() {
        let mut maintenance = Maintenance::default();
        let mut failures = LegacyFailManager::new(2, 10);
        maintenance.request(i64::MIN, &mut failures);
        maintenance.request(i64::MAX - 1, &mut failures);
        maintenance.request(i64::MAX, &mut failures);
        assert_eq!(maintenance.next_service, i128::from(i64::MAX) + 4);
        assert_eq!(maintenance.trace, [(i64::MIN, 0), (i64::MAX - 1, 0)]);
    }
}
