//! Pure integer-second active-ban timing for original Fail2Ban 1.1.1.
//!
//! This is a per-jail decision model. It never changes firewall or service
//! state, and does not load state, perform escalation, or read a clock.

use std::collections::{HashMap, hash_map::Entry};
use std::net::IpAddr;

// The original manager compares the permanent ticket's numeric end with
// observed time, even though its public status describes it as permanent.
const PERMANENT_END: i128 = 0x7fff_ffff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Duration {
    Finite(i64),
    Permanent,
}

impl Duration {
    pub(super) const fn from_seconds(seconds: i64) -> Self {
        if seconds == -1 {
            Self::Permanent
        } else {
            Self::Finite(seconds)
        }
    }

    fn end(self, start: i64) -> Option<i128> {
        match self {
            Self::Finite(seconds) => Some(i128::from(start) + i128::from(seconds)),
            Self::Permanent => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ActiveBan {
    pub(super) address: IpAddr,
    pub(super) started_at: i64,
    end: Option<i128>,
}

impl ActiveBan {
    pub(super) const fn expires_at(self) -> Option<i128> {
        self.end
    }

    fn comparison_end(self) -> i128 {
        self.end.unwrap_or(PERMANENT_END)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AddResult {
    Added,
    Duplicate,
    Prolonged,
    Expired,
}

#[derive(Debug)]
pub(super) struct BanManager {
    base: Duration,
    active: HashMap<IpAddr, (u64, ActiveBan)>,
    total: u64,
}

impl BanManager {
    pub(super) fn new(base: Duration) -> Self {
        Self {
            base,
            active: HashMap::new(),
            total: 0,
        }
    }

    /// Consider a ticket from `started_at` as observed at `observed_at`.
    /// `None` for its duration selects the jail's base duration.
    pub(super) fn add(
        &mut self,
        address: IpAddr,
        started_at: i64,
        duration: Option<Duration>,
        observed_at: i64,
    ) -> AddResult {
        let duration = duration.unwrap_or(self.base);
        let incoming = ActiveBan {
            address,
            started_at,
            end: duration.end(started_at),
        };
        if incoming.comparison_end() < i128::from(observed_at) {
            return AddResult::Expired;
        }

        match self.active.entry(address) {
            Entry::Vacant(entry) => {
                entry.insert((self.total, incoming));
                self.total = self.total.saturating_add(1);
                AddResult::Added
            }
            Entry::Occupied(mut entry) => {
                let (_, current) = entry.get_mut();
                if incoming.comparison_end() <= current.comparison_end() {
                    return AddResult::Duplicate;
                }
                // Keep the original start. The new duration gains the
                // positive start difference only; an earlier incoming
                // start must not subtract time from the current ticket.
                current.end = duration.end(started_at.max(current.started_at));
                AddResult::Prolonged
            }
        }
    }

    /// Number of new active tickets, excluding duplicates and prolongations.
    pub(super) const fn total_bans(&self) -> u64 {
        self.total
    }

    pub(super) fn get(&self, address: IpAddr) -> Option<ActiveBan> {
        self.active.get(&address).map(|&(_, ban)| ban)
    }

    /// Remove all strictly expired tickets, in original insertion order.
    pub(super) fn expire(&mut self, observed_at: i64) -> Vec<ActiveBan> {
        let mut expired = Vec::new();
        self.active.retain(|_, (sequence, ban)| {
            if ban.comparison_end() < i128::from(observed_at) {
                expired.push((*sequence, *ban));
                false
            } else {
                true
            }
        });
        expired.sort_unstable_by_key(|(sequence, _)| *sequence);
        expired.into_iter().map(|(_, ban)| ban).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    #[test]
    fn ticket_at_end_is_accepted_and_active_until_strictly_after_end() {
        let mut manager = BanManager::new(Duration::from_seconds(10));
        let address = ip("192.0.2.7");
        assert_eq!(manager.add(address, 100, None, 111), AddResult::Expired);
        assert_eq!(manager.total_bans(), 0);
        assert!(manager.get(address).is_none());

        assert_eq!(manager.add(address, 100, None, 110), AddResult::Added);
        assert_eq!(manager.total_bans(), 1);
        let ban = manager.get(address).unwrap();
        assert_eq!(ban.expires_at(), Some(110));
        assert!(manager.expire(109).is_empty());
        assert!(manager.expire(110).is_empty());
        assert_eq!(manager.expire(111), [ban]);
        assert!(manager.get(address).is_none());
        assert!(manager.expire(999).is_empty());
    }

    #[test]
    fn duplicates_do_not_change_total_or_reduce_end_and_only_extend_later_ends() {
        let mut manager = BanManager::new(Duration::from_seconds(10));
        let address = ip("192.0.2.7");
        assert_eq!(manager.add(address, 100, None, 100), AddResult::Added);
        assert_eq!(
            manager.add(address, 103, Some(Duration::from_seconds(7)), 103),
            AddResult::Duplicate
        );
        assert_eq!(
            manager.add(address, 105, Some(Duration::from_seconds(3)), 105),
            AddResult::Duplicate
        );
        assert_eq!(manager.add(address, 105, None, 105), AddResult::Prolonged);
        let ban = manager.get(address).unwrap();
        assert_eq!(ban.started_at, 100);
        assert_eq!(ban.expires_at(), Some(115));
        assert_eq!(manager.total_bans(), 1);
        assert_eq!(
            manager.add(address, 100, Some(Duration::from_seconds(2)), 105),
            AddResult::Expired
        );
        assert_eq!(manager.get(address), Some(ban));
        assert!(manager.expire(115).is_empty());
        assert_eq!(manager.expire(116), [ban]);
        assert_eq!(manager.add(address, 116, None, 116), AddResult::Added);
        assert_eq!(manager.total_bans(), 2);
    }

    #[test]
    fn older_incoming_start_gains_no_negative_offset_when_prolonged() {
        let mut manager = BanManager::new(Duration::from_seconds(10));
        let address = ip("2001:db8::7");
        assert_eq!(manager.add(address, 100, None, 100), AddResult::Added);
        assert_eq!(
            manager.add(address, 90, Some(Duration::from_seconds(30)), 105),
            AddResult::Prolonged
        );
        let ban = manager.get(address).unwrap();
        assert_eq!(ban.started_at, 100);
        assert_eq!(ban.expires_at(), Some(130));
        assert!(manager.expire(129).is_empty());
        assert_eq!(manager.expire(131), [ban]);
    }

    #[test]
    fn permanent_base_and_explicit_permanent_prolongation() {
        let address = ip("192.0.2.7");
        let mut permanent = BanManager::new(Duration::from_seconds(-1));
        assert_eq!(permanent.add(address, 100, None, 100), AddResult::Added);
        assert_eq!(permanent.get(address).unwrap().expires_at(), None);
        assert!(permanent.expire(1_000_000).is_empty());
        assert_eq!(
            permanent.add(address, 110, Some(Duration::from_seconds(600)), 110),
            AddResult::Duplicate
        );

        let mut finite = BanManager::new(Duration::from_seconds(600));
        assert_eq!(finite.add(address, 100, None, 100), AddResult::Added);
        assert_eq!(
            finite.add(address, 110, Some(Duration::from_seconds(-1)), 110),
            AddResult::Prolonged
        );
        let ban = finite.get(address).unwrap();
        assert_eq!(ban.started_at, 100);
        assert_eq!(ban.expires_at(), None);
        assert!(finite.expire(1_000_000).is_empty());
        assert_eq!(finite.total_bans(), 1);
    }

    #[test]
    fn removes_only_due_records_in_insertion_order() {
        let mut manager = BanManager::new(Duration::from_seconds(10));
        let late = ip("192.0.2.7");
        let early = ip("2001:db8::7");
        let remaining = ip("192.0.2.6");
        assert_eq!(manager.add(late, 103, None, 103), AddResult::Added);
        assert_eq!(manager.add(early, 101, None, 103), AddResult::Added);
        assert_eq!(manager.add(remaining, 104, None, 104), AddResult::Added);
        assert_eq!(
            manager
                .expire(114)
                .into_iter()
                .map(|ban| ban.address)
                .collect::<Vec<_>>(),
            [late, early]
        );
        assert!(manager.get(remaining).is_some());
    }
}
