//! Controlled integer-second ticks of the original Fail2Ban action worker.
//!
//! Tickets and returned decisions are inert. The caller owns the clock and
//! step boundaries. No thread, service, observer, action transport, command,
//! or failure/repair re-ban semantics are modeled here.

use std::collections::VecDeque;
use std::net::IpAddr;

use super::legacy_ban_manager::{AddResult, BanManager, Duration};

const BAN_PRECEDENCE: usize = 10;
const UNBAN_MAX_COUNT: usize = BAN_PRECEDENCE * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Ticket {
    pub(super) ip: IpAddr,
    pub(super) time: i64,
    pub(super) duration: Option<Duration>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Tick {
    pub(super) attempted: Vec<(Ticket, AddResult)>,
    pub(crate) expired: Vec<IpAddr>,
    /// None means expiry was deferred, distinct from a sweep that removed none.
    pub(crate) sweep_limit: Option<usize>,
}

impl Tick {
    pub(crate) fn newly_added(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.attempted
            .iter()
            .filter_map(|(ticket, result)| (*result == AddResult::Added).then_some(ticket.ip))
    }
}

#[derive(Debug)]
pub(crate) struct LegacyActionQueue {
    tickets: VecDeque<Ticket>,
    bans: BanManager,
    added_since_sweep: usize,
}

impl LegacyActionQueue {
    pub(super) fn new(base: Duration) -> Self {
        Self {
            tickets: VecDeque::new(),
            bans: BanManager::new(base),
            added_since_sweep: 0,
        }
    }

    pub(crate) fn for_replay(ban_time: i64) -> Self {
        Self::new(Duration::from_seconds(ban_time))
    }

    pub(super) fn enqueue(&mut self, ticket: Ticket) {
        self.tickets.push_back(ticket);
    }

    pub(crate) fn enqueue_failure(&mut self, ip: IpAddr, time: i64) {
        self.enqueue(Ticket {
            ip,
            time,
            duration: None,
        });
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.tickets.len()
    }

    pub(crate) const fn total_bans(&self) -> u64 {
        self.bans.total_bans()
    }

    /// Process up to ten queued tickets before considering expiry. The
    /// threshold counts newly added bans across positive ticks, not dequeued
    /// tickets; a tick with no new ban permits a sweep immediately.
    pub(crate) fn tick(&mut self, now: i64) -> Tick {
        let count = self.tickets.len().min(BAN_PRECEDENCE);
        let mut attempted = Vec::with_capacity(count);
        let mut added = 0;
        for ticket in self.tickets.drain(..count) {
            let result = self.bans.add(ticket.ip, ticket.time, ticket.duration, now);
            added += usize::from(result == AddResult::Added);
            attempted.push((ticket, result));
        }

        self.added_since_sweep += added;
        let sweep_limit = if added == 0 {
            Some(UNBAN_MAX_COUNT)
        } else if self.added_since_sweep >= BAN_PRECEDENCE {
            Some((added * 2).min(UNBAN_MAX_COUNT))
        } else {
            None
        };
        let expired = sweep_limit.map_or_else(Vec::new, |limit| {
            self.added_since_sweep = 0;
            self.bans
                .expire_up_to(now, limit)
                .into_iter()
                .map(|record| record.address)
                .collect()
        });

        Tick {
            attempted,
            expired,
            sweep_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(index: u8) -> IpAddr {
        Ipv4Addr::new(192, 0, 2, index).into()
    }

    fn enqueue_range(
        queue: &mut LegacyActionQueue,
        range: impl IntoIterator<Item = u8>,
        time: i64,
    ) {
        for index in range {
            queue.enqueue_failure(ip(index), time);
        }
    }

    #[test]
    fn drains_only_ten_fifo_tickets_per_tick() {
        let mut queue = LegacyActionQueue::for_replay(15);
        enqueue_range(&mut queue, 1..=11, 100);
        let first = queue.tick(100);
        assert_eq!(
            first.newly_added().collect::<Vec<_>>(),
            (1..=10).map(ip).collect::<Vec<_>>()
        );
        assert_eq!(first.sweep_limit, Some(20));
        assert_eq!(queue.pending_len(), 1);
        assert_eq!(queue.total_bans(), 10);

        let last = queue.tick(100);
        assert_eq!(last.newly_added().collect::<Vec<_>>(), [ip(11)]);
        assert_eq!(last.sweep_limit, None);
        assert_eq!(queue.pending_len(), 0);
        assert_eq!(queue.total_bans(), 11);
        assert_eq!(queue.tick(100).sweep_limit, Some(20));
    }

    #[test]
    fn short_positive_ticks_accumulate_and_use_the_last_batch_for_the_sweep_limit() {
        let mut queue = LegacyActionQueue::for_replay(10);
        enqueue_range(&mut queue, 1..=8, 100);
        assert_eq!(queue.tick(100).sweep_limit, None);
        assert_eq!(queue.tick(100).sweep_limit, Some(20));

        // All eight original bans are now due, but short positive ticks defer
        // expiry until the number of new bans since last sweep reaches ten.
        enqueue_range(&mut queue, 10..=15, 111);
        assert_eq!(queue.tick(111).sweep_limit, None);
        enqueue_range(&mut queue, 16..=18, 111);
        assert_eq!(queue.tick(111).sweep_limit, None);
        enqueue_range(&mut queue, 19..=20, 111);
        let threshold = queue.tick(111);
        assert_eq!(threshold.sweep_limit, Some(4));
        assert_eq!(threshold.expired, (1..=4).map(ip).collect::<Vec<_>>());
        assert_eq!(queue.tick(111).expired, (5..=8).map(ip).collect::<Vec<_>>());
    }

    #[test]
    fn expired_duplicate_and_prolonged_attempts_do_not_count_as_additions() {
        let mut queue = LegacyActionQueue::new(Duration::Finite(10));
        enqueue_range(&mut queue, 1..=2, 100);
        assert_eq!(queue.tick(100).sweep_limit, None);

        // Same ticket at equality is a duplicate, not a new insertion.
        queue.enqueue_failure(ip(1), 100);
        assert_eq!(queue.tick(110).sweep_limit, Some(20));

        // Process before sweeping: extend the still-present first address,
        // reject an old ticket, then unban only the second address.
        queue.enqueue_failure(ip(1), 101);
        queue.enqueue_failure(ip(3), 100);
        let tick = queue.tick(111);
        assert_eq!(
            tick.attempted
                .iter()
                .map(|(_, result)| *result)
                .collect::<Vec<_>>(),
            [AddResult::Prolonged, AddResult::Expired]
        );
        assert_eq!(tick.newly_added().count(), 0);
        assert_eq!(tick.sweep_limit, Some(20));
        assert_eq!(tick.expired, [ip(2)]);
        assert_eq!(queue.tick(112).expired, [ip(1)]);
        assert_eq!(queue.total_bans(), 2);
    }

    #[test]
    fn idle_sweeps_remove_only_twenty_due_bans_in_insertion_order() {
        let mut queue = LegacyActionQueue::for_replay(10);
        enqueue_range(&mut queue, (1..=25).rev(), 100);
        for _ in 0..3 {
            assert!(queue.tick(100).expired.is_empty());
        }
        assert!(queue.tick(110).expired.is_empty()); // Strict end boundary.

        let first = queue.tick(111);
        assert_eq!(first.sweep_limit, Some(20));
        assert_eq!(first.expired, (6..=25).rev().map(ip).collect::<Vec<_>>());
        assert_eq!(
            queue.tick(111).expired,
            (1..=5).rev().map(ip).collect::<Vec<_>>()
        );
        assert!(queue.tick(111).expired.is_empty());
    }
}
