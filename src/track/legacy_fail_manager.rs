//! Offline per-IP FailManager decisions from original Fail2Ban 1.1.1.
//!
//! The original FailTicket estimates a retry rate across an extended interval;
//! it does not keep or prune a list of individual event timestamps. This
//! module uses explicit integer-second clocks and performs no side effects.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FailureTicket {
    pub(crate) ip: IpAddr,
    /// Beginning of the current (possibly estimated) interval.
    pub(crate) first_time: i64,
    /// Latest timestamp supplied, independent of arrival order.
    pub(crate) time: i64,
    /// The possibly weighted and time-adjusted retry count used for thresholds.
    pub(crate) retry: u64,
    /// Original FailTicket attempt count; rate adjustment does not change it.
    pub(crate) attempts: u64,
}

#[derive(Debug)]
struct Entry {
    ticket: FailureTicket,
    insertion: u64,
}

#[derive(Debug)]
pub(crate) struct LegacyFailManager {
    entries: HashMap<IpAddr, Entry>,
    max_retry: u64,
    find_time: u64,
    total_failures: u64,
}

impl LegacyFailManager {
    pub(crate) fn new(max_retry: u64, find_time: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_retry,
            find_time,
            total_failures: 0,
        }
    }

    /// Add a fresh ordinary filter failure with the original default weight.
    pub(crate) fn record(&mut self, ip: IpAddr, time: i64) -> u64 {
        self.add_failure(ip, time, 1, 0, false)
    }

    /// Add a fresh distinct FailTicket with explicit attempt count and weight.
    ///
    /// The incoming attempt metadata is supplied at construction, so its
    /// initial retry value is also `attempt`. When `observed` is true, a
    /// missing ticket is not recreated. This does not model an asynchronous
    /// observer, BanTicket, a pre-reweighted ticket, or object-identity cases.
    pub(crate) fn add_failure(
        &mut self,
        ip: IpAddr,
        time: i64,
        count: u64,
        attempt: u64,
        observed: bool,
    ) -> u64 {
        let ip = ip.to_canonical();
        let retry = if let Some(entry) = self.entries.get_mut(&ip) {
            let ticket = &mut entry.ticket;
            adjust_time(ticket, time, self.find_time);
            // Original inc() increments internal retries by count, but
            // tracks actual attempts independently, at least one for an
            // incoming distinct ticket whose attempt field was zero.
            ticket.retry = ticket.retry.saturating_add(count);
            ticket.attempts = ticket.attempts.saturating_add(attempt.max(1));
            ticket.retry
        } else if observed {
            return attempt;
        } else {
            let retry = count.max(attempt);
            let attempts = if count > attempt {
                attempt.max(1)
            } else {
                attempt
            };
            self.entries.insert(
                ip,
                Entry {
                    insertion: self.total_failures,
                    ticket: FailureTicket {
                        ip,
                        first_time: time,
                        time,
                        retry,
                        attempts,
                    },
                },
            );
            retry
        };
        // FailManager's total counts accepted calls, not weights/attempts.
        self.total_failures = self.total_failures.saturating_add(1);
        retry
    }

    /// Clean up when asked by the caller, using the most recent event time.
    pub(crate) fn cleanup(&mut self, now: i64) -> usize {
        let cutoff = i128::from(now) - i128::from(self.find_time);
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| i128::from(entry.ticket.time) > cutoff);
        before - self.entries.len()
    }

    /// Return and remove one eligible ticket. No action is run.
    ///
    /// Original FailManager tries only the requested ID if it is present,
    /// even if it is below threshold. When absent (or unspecified), it
    /// chooses the first eligible entry in insertion order.
    pub(crate) fn take_for_ban(&mut self, requested: Option<IpAddr>) -> Option<FailureTicket> {
        let requested = requested.map(|ip| ip.to_canonical());
        let preferred = requested.filter(|ip| self.entries.contains_key(ip));
        let eligible = |entry: &&Entry| entry.ticket.retry >= self.max_retry;
        let key = if let Some(ip) = preferred {
            self.entries.get(&ip).filter(eligible)?.ticket.ip
        } else {
            self.entries
                .values()
                .filter(eligible)
                .min_by_key(|entry| entry.insertion)?
                .ticket
                .ip
        };
        self.entries.remove(&key).map(|entry| entry.ticket)
    }

    pub(crate) fn ticket(&self, ip: IpAddr) -> Option<&FailureTicket> {
        self.entries
            .get(&ip.to_canonical())
            .map(|entry| &entry.ticket)
    }

    pub(crate) fn total_failures(&self) -> u64 {
        self.total_failures
    }
}

fn adjust_time(ticket: &mut FailureTicket, time: i64, find_time: u64) {
    if time <= ticket.time {
        return;
    }
    let cutoff = i128::from(time) - i128::from(find_time);
    if i128::from(ticket.first_time) < cutoff {
        let span = i128::from(time) - i128::from(ticket.first_time);
        let retry = (ticket.retry as f64 / span as f64 * find_time as f64).round_ties_even();
        ticket.retry = retry as u64;
        // This branch proves first_time < cutoff <= time, so cutoff is
        // representable as i64 even for a large input window.
        ticket.first_time = cutoff as i64;
    }
    ticket.time = time;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "legacy_fail_manager_test.rs"]
mod tests;
