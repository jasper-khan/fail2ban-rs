//! Original Fail2Ban jail decision path for offline replay.
//!
//! Composes the original failure-counter and ban-timer semantics on one
//! typed source IP at a time. Timestamp selection, log filtering, ignore
//! rules, observer escalation, queues and actions are outside this layer.
//! The caller drives housekeeping; it does not run a service or change any
//! firewall or host state.

use std::net::IpAddr;

use super::legacy_ban_manager::{AddResult, BanManager, Duration};
use super::legacy_fail_manager::LegacyFailManager;

pub(super) struct LegacyJail {
    failures: LegacyFailManager,
    bans: BanManager,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Attempt {
    /// Retry score before a qualifying failure ticket is removed.
    pub(super) retry: u64,
    /// Disposition of the qualifying ticket, if the threshold was reached.
    pub(super) decision: Option<AddResult>,
}

impl LegacyJail {
    pub(super) fn new(max_retry: u64, find_time: u64, bantime: Duration) -> Self {
        Self {
            failures: LegacyFailManager::new(max_retry, find_time),
            bans: BanManager::new(bantime),
        }
    }

    /// Accept an already matched, non-ignored failure.
    ///
    /// The timestamp on the failure ticket (not the cleanup or processing
    /// clock) starts its ban. A repeated qualifying ticket is still consumed
    /// from the failure counter even when the address was already banned.
    pub(super) fn record(&mut self, ip: IpAddr, event_time: i64, observed_at: i64) -> Attempt {
        let retry = self.failures.record(ip, event_time);
        let decision = self
            .failures
            .take_for_ban(Some(ip))
            .map(|ticket| self.bans.add(ticket.ip, ticket.time, None, observed_at));
        Attempt { retry, decision }
    }

    pub(super) fn cleanup_failures(&mut self, now: i64) -> usize {
        self.failures.cleanup(now)
    }

    pub(super) fn expire(&mut self, now: i64) -> Vec<IpAddr> {
        self.bans
            .expire(now)
            .into_iter()
            .map(|record| record.address)
            .collect()
    }

    pub(super) fn failure_count(&self, ip: IpAddr) -> Option<u64> {
        self.failures.ticket(ip).map(|record| record.retry)
    }

    pub(super) fn total_failures(&self) -> u64 {
        self.failures.total_failures()
    }

    pub(super) fn total_bans(&self) -> u64 {
        self.bans.total_bans()
    }
}
