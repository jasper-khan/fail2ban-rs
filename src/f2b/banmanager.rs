//! Per-jail active ban manager (`BanManager`).
//!
//! Mirrors Fail2Ban 1.1.1 `fail2ban/server/banmanager.py` and
//! `BanTicket` timing in `fail2ban/server/ticket.py`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::ticket::{Ticket, TicketId};

/// Sentinel end-of-ban timestamp used for permanent bans (`-1`).
pub const PERMANENT_END: f64 = 0x7fff_ffff_ffff_u64 as f64;

const DEFAULT_BAN_TIME: i64 = 600;

/// Outcome of submitting a ticket to [`BanManager::add_ban_ticket`].
#[derive(Debug, Clone, PartialEq)]
pub enum AddBanOutcome {
    /// Ticket was not banned yet and has been added.
    Added,
    /// Ticket was already banned with an equal or later end-of-ban time.
    Duplicate,
    /// Existing active ban was extended; carries the updated ticket.
    Prolonged(Ticket),
    /// Incoming ticket was already expired relative to `now`.
    Expired,
}

#[derive(Debug)]
struct BanEntry {
    ticket: Ticket,
    insertion: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PendingActions {
    pub(crate) ban: Vec<String>,
    pub(crate) reban: Vec<String>,
    pub(crate) previously_banned: bool,
}

/// Tracks active bans per `TicketId`, preserving insertion order for expiration.
#[derive(Debug)]
pub struct BanManager {
    ban_list: HashMap<TicketId, BanEntry>,
    pending_actions: HashMap<TicketId, PendingActions>,
    next_seq: u64,
    ban_time: i64,
    total_bans: u64,
    next_unban_time: f64,
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BanManager {
    pub fn new() -> Self {
        Self {
            ban_list: HashMap::new(),
            pending_actions: HashMap::new(),
            next_seq: 0,
            ban_time: DEFAULT_BAN_TIME,
            total_bans: 0,
            next_unban_time: PERMANENT_END,
        }
    }

    pub fn ban_time(&self) -> i64 {
        self.ban_time
    }

    pub fn set_ban_time(&mut self, ban_time: i64) {
        self.ban_time = ban_time;
        self.recompute_next_unban();
    }

    pub fn size(&self) -> usize {
        self.ban_list
            .len()
            .saturating_sub(self.pending_actions.len())
    }

    pub fn total_bans(&self) -> u64 {
        self.total_bans
    }

    pub fn set_total_bans(&mut self, total: u64) {
        self.total_bans = total;
    }

    pub fn in_ban_list(&self, id: &TicketId) -> bool {
        self.ban_list.contains_key(id) && !self.pending_actions.contains_key(id)
    }

    pub(crate) fn pending_ban(&self, id: &TicketId) -> Option<(&Ticket, &PendingActions)> {
        Some((self.get_ticket_by_id(id)?, self.pending_actions.get(id)?))
    }

    pub(crate) fn pending_tickets(&self) -> impl Iterator<Item = &Ticket> {
        self.pending_actions
            .keys()
            .filter_map(|id| self.get_ticket_by_id(id))
    }

    /// Partial bans remain available for expiry and explicit unban.
    pub(crate) fn begin_actions(&mut self, id: &TicketId) {
        if !self.ban_list.contains_key(id) {
            return;
        }
        self.pending_actions
            .insert(id.clone(), PendingActions::default());
        self.total_bans = self.total_bans.saturating_sub(1);
    }

    pub(crate) fn failed_reban(&mut self, id: &TicketId, action: String) {
        if !self.ban_list.contains_key(id) {
            return;
        }
        let pending = self
            .pending_actions
            .entry(id.clone())
            .or_insert_with(|| PendingActions {
                previously_banned: true,
                ..Default::default()
            });
        if !pending.reban.contains(&action) {
            pending.reban.push(action);
        }
    }

    /// Return true only on the first successful application of this ticket.
    pub(crate) fn finish_actions(&mut self, id: &TicketId, failed: PendingActions) -> bool {
        if !self.ban_list.contains_key(id) {
            self.pending_actions.remove(id);
            return false;
        }
        if !failed.ban.is_empty() || !failed.reban.is_empty() {
            self.pending_actions.insert(id.clone(), failed);
            return false;
        }
        self.pending_actions.remove(id);
        if !failed.previously_banned {
            self.total_bans = self.total_bans.saturating_add(1);
        }
        !failed.previously_banned
    }

    pub fn get_ticket_by_id(&self, id: &TicketId) -> Option<&Ticket> {
        self.ban_list.get(id).map(|entry| &entry.ticket)
    }

    /// Add a ban ticket or prolong an existing active ban.
    pub fn add_ban_ticket(&mut self, mut ticket: Ticket, now: f64) -> AddBanOutcome {
        let eob = comparison_end(&ticket, self.ban_time);
        if eob < now {
            return AddBanOutcome::Expired;
        }
        match self.ban_list.entry(ticket.fid.clone()) {
            Entry::Occupied(mut occupied) => {
                let current = &mut occupied.get_mut().ticket;
                let cur_eob = comparison_end(current, self.ban_time);
                if eob <= cur_eob {
                    return AddBanOutcome::Duplicate;
                }
                let mut btm = ticket.effective_ban_time(self.ban_time);
                if btm >= 0 {
                    let diftm = ticket.time - current.time;
                    if diftm > 0.0 {
                        let extended = (btm as f64 + diftm).round_ties_even();
                        btm = if extended.is_finite() {
                            extended.clamp(0.0, i64::MAX as f64) as i64
                        } else {
                            i64::MAX
                        };
                    }
                } else {
                    btm = -1;
                }
                current.ban_time = Some(btm);
                let prolonged = current.clone();
                if cur_eob <= self.next_unban_time {
                    self.recompute_next_unban();
                }
                AddBanOutcome::Prolonged(prolonged)
            }
            Entry::Vacant(vacant) => {
                self.total_bans = self.total_bans.saturating_add(1);
                ticket.ban_count = ticket.ban_count.saturating_add(1);
                if self.next_unban_time > eob {
                    self.next_unban_time = eob;
                }
                let seq = self.next_seq;
                self.next_seq = self.next_seq.saturating_add(1);
                vacant.insert(BanEntry {
                    ticket,
                    insertion: seq,
                });
                AddBanOutcome::Added
            }
        }
    }

    /// Return banned IDs in insertion order, or ordered by end-of-ban time when `ordered` is true.
    pub fn get_ban_list(&self, ordered: bool) -> Vec<TicketId> {
        let mut items: Vec<(&TicketId, f64, u64)> = self
            .ban_list
            .iter()
            .filter(|(id, _)| !self.pending_actions.contains_key(*id))
            .map(|(id, entry)| {
                (
                    id,
                    comparison_end(&entry.ticket, self.ban_time),
                    entry.insertion,
                )
            })
            .collect();
        if ordered {
            items.sort_unstable_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
        } else {
            items.sort_unstable_by_key(|item| item.2);
        }
        items.into_iter().map(|(id, _, _)| id.clone()).collect()
    }

    /// Return `(id, start_time, end_of_ban)` ordered by end-of-ban time.
    ///
    /// When `with_time` is `false`, `end_of_ban` is `None`. When `with_time` is `true`,
    /// `end_of_ban` is `Some(timestamp)` for finite bans and `None` for permanent `-1` bans.
    pub fn get_ban_list_extended(&self, with_time: bool) -> Vec<(TicketId, f64, Option<f64>)> {
        let mut entries: Vec<&BanEntry> = self
            .ban_list
            .values()
            .filter(|entry| !self.pending_actions.contains_key(&entry.ticket.fid))
            .collect();
        entries.sort_unstable_by(|a, b| {
            comparison_end(&a.ticket, self.ban_time)
                .total_cmp(&comparison_end(&b.ticket, self.ban_time))
                .then_with(|| a.insertion.cmp(&b.insertion))
        });
        entries
            .into_iter()
            .map(|entry| {
                let end = if with_time {
                    entry.ticket.end_of_ban(self.ban_time)
                } else {
                    None
                };
                (entry.ticket.fid.clone(), entry.ticket.time, end)
            })
            .collect()
    }

    /// Remove and return all expired tickets (`now > end_of_ban`) in insertion order.
    pub fn unban(&mut self, now: f64) -> Vec<Ticket> {
        if self.next_unban_time >= now {
            return Vec::new();
        }
        let mut due: Vec<(u64, TicketId)> = self
            .ban_list
            .iter()
            .filter_map(|(id, entry)| {
                let eob = entry.ticket.end_of_ban(self.ban_time)?;
                if now > eob {
                    Some((entry.insertion, id.clone()))
                } else {
                    None
                }
            })
            .collect();
        if due.is_empty() {
            self.recompute_next_unban();
            return Vec::new();
        }
        due.sort_unstable_by_key(|(seq, _)| *seq);
        let removed: Vec<Ticket> = due
            .into_iter()
            .filter_map(|(_, id)| self.remove_by_id_deferred(&id))
            .collect();
        self.recompute_next_unban();
        removed
    }

    /// Remove and return all active ban tickets in insertion order.
    pub fn flush_ban_list(&mut self) -> Vec<Ticket> {
        self.pending_actions.clear();
        let mut entries: Vec<BanEntry> = self.ban_list.drain().map(|(_, e)| e).collect();
        entries.sort_unstable_by_key(|e| e.insertion);
        self.next_unban_time = PERMANENT_END;
        entries.into_iter().map(|e| e.ticket).collect()
    }

    /// Remove and return the active ban ticket for `id` if present.
    pub fn remove_by_id(&mut self, id: &TicketId) -> Option<Ticket> {
        let removed = self.remove_by_id_deferred(id)?;
        self.recompute_next_unban();
        Some(removed)
    }

    /// Remove and return the active ban ticket for `id` without recomputing `next_unban_time`.
    /// Callers using this in a batch must call [`Self::recompute_next_unban`] before returning.
    pub fn remove_by_id_deferred(&mut self, id: &TicketId) -> Option<Ticket> {
        self.pending_actions.remove(id);
        self.ban_list.remove(id).map(|e| e.ticket)
    }

    /// Return all active ban IDs equal to or contained in `target` (supports CIDR/subnet)
    /// in insertion order without removing them.
    pub fn matching_ids(&self, target: &TicketId) -> Vec<TicketId> {
        let mut matches: Vec<(u64, TicketId)> = self
            .ban_list
            .iter()
            .filter_map(|(id, entry)| {
                if id.is_in_net(target) {
                    Some((entry.insertion, id.clone()))
                } else {
                    None
                }
            })
            .collect();
        matches.sort_unstable_by_key(|(seq, _)| *seq);
        matches.into_iter().map(|(_, id)| id).collect()
    }

    /// Recompute the earliest expiration timestamp across all active bans.
    pub fn recompute_next_unban(&mut self) {
        self.next_unban_time = self
            .ban_list
            .values()
            .map(|entry| comparison_end(&entry.ticket, self.ban_time))
            .fold(PERMANENT_END, f64::min);
    }
}

fn comparison_end(ticket: &Ticket, default_ban_time: i64) -> f64 {
    ticket.end_of_ban(default_ban_time).unwrap_or(PERMANENT_END)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn id(s: &str) -> TicketId {
        TicketId::parse(s)
    }

    #[test]
    fn expired_and_exact_boundary_unban() {
        let mut bm = BanManager::new();
        bm.set_ban_time(10);
        let addr = id("192.0.2.7");

        assert_eq!(
            bm.add_ban_ticket(Ticket::new(addr.clone(), 100.0), 111.0),
            AddBanOutcome::Expired
        );
        assert_eq!(bm.total_bans(), 0);
        assert!(!bm.in_ban_list(&addr));

        assert_eq!(
            bm.add_ban_ticket(Ticket::new(addr.clone(), 100.0), 110.0),
            AddBanOutcome::Added
        );
        assert_eq!(bm.total_bans(), 1);
        assert_eq!(bm.get_ticket_by_id(&addr).unwrap().ban_count, 1);

        assert!(bm.unban(109.0).is_empty());
        assert!(bm.unban(110.0).is_empty());
        let unbanned = bm.unban(111.0);
        assert_eq!(unbanned.len(), 1);
        assert_eq!(unbanned[0].fid, addr);
        assert_eq!(bm.size(), 0);
    }

    #[test]
    fn duplicate_and_prolong_semantics_preserve_start_time_and_total() {
        let mut bm = BanManager::new();
        bm.set_ban_time(10);
        let addr = id("192.0.2.7");

        assert_eq!(
            bm.add_ban_ticket(Ticket::new(addr.clone(), 100.0), 100.0),
            AddBanOutcome::Added
        );
        let mut shorter = Ticket::new(addr.clone(), 103.0);
        shorter.ban_time = Some(7);
        assert_eq!(bm.add_ban_ticket(shorter, 103.0), AddBanOutcome::Duplicate);

        let mut same_start_newer = Ticket::new(addr.clone(), 105.0);
        same_start_newer.ban_time = None;
        let outcome = bm.add_ban_ticket(same_start_newer, 105.0);
        match outcome {
            AddBanOutcome::Prolonged(t) => {
                assert_eq!(t.time, 100.0);
                assert_eq!(t.ban_time, Some(15));
                assert_eq!(t.end_of_ban(10), Some(115.0));
            }
            other => panic!("expected Prolonged, got {other:?}"),
        }
        assert_eq!(bm.total_bans(), 1);
        assert!(bm.unban(115.0).is_empty());
        assert_eq!(bm.unban(116.0).len(), 1);
    }

    #[test]
    fn permanent_bans_never_expire_and_prolong_from_finite() {
        let mut bm = BanManager::new();
        bm.set_ban_time(600);
        let addr = id("192.0.2.8");

        assert_eq!(
            bm.add_ban_ticket(Ticket::new(addr.clone(), 100.0), 100.0),
            AddBanOutcome::Added
        );
        let mut perm = Ticket::new(addr.clone(), 110.0);
        perm.ban_time = Some(-1);
        match bm.add_ban_ticket(perm, 110.0) {
            AddBanOutcome::Prolonged(t) => {
                assert_eq!(t.time, 100.0);
                assert_eq!(t.ban_time, Some(-1));
                assert_eq!(t.end_of_ban(600), None);
            }
            other => panic!("expected Prolonged to permanent, got {other:?}"),
        }

        // Subsequent finite ban is a duplicate after permanent.
        let mut finite = Ticket::new(addr.clone(), 200.0);
        finite.ban_time = Some(1000);
        assert_eq!(bm.add_ban_ticket(finite, 200.0), AddBanOutcome::Duplicate);
        assert!(bm.unban(10_000_000.0).is_empty());
        assert_eq!(bm.size(), 1);
    }

    #[test]
    fn ordered_list_extended_list_and_unban_insertion_order() {
        let mut bm = BanManager::new();
        bm.set_ban_time(100);

        let a = id("192.0.2.1");
        let b = id("192.0.2.2");
        let c = id("192.0.2.3");

        let mut ta = Ticket::new(a.clone(), 50.0);
        ta.ban_time = Some(200); // eob 250
        let tb = Ticket::new(b.clone(), 60.0); // eob 160
        let mut tc = Ticket::new(c.clone(), 70.0);
        tc.ban_time = Some(-1); // permanent

        assert_eq!(bm.add_ban_ticket(ta, 50.0), AddBanOutcome::Added);
        assert_eq!(bm.add_ban_ticket(tb, 60.0), AddBanOutcome::Added);
        assert_eq!(bm.add_ban_ticket(tc, 70.0), AddBanOutcome::Added);

        assert_eq!(
            bm.get_ban_list(false),
            vec![a.clone(), b.clone(), c.clone()]
        );
        assert_eq!(bm.get_ban_list(true), vec![b.clone(), a.clone(), c.clone()]);

        let ext = bm.get_ban_list_extended(true);
        assert_eq!(
            ext,
            vec![
                (b.clone(), 60.0, Some(160.0)),
                (a.clone(), 50.0, Some(250.0)),
                (c.clone(), 70.0, None),
            ]
        );
        let ext_no_time = bm.get_ban_list_extended(false);
        assert_eq!(
            ext_no_time,
            vec![
                (b.clone(), 60.0, None),
                (a.clone(), 50.0, None),
                (c.clone(), 70.0, None),
            ]
        );

        // Both a and b expire at 300; returned in insertion order [a, b].
        let expired = bm.unban(300.0);
        assert_eq!(
            expired.into_iter().map(|t| t.fid).collect::<Vec<_>>(),
            vec![a, b]
        );
        assert_eq!(bm.get_ban_list(false), vec![c]);
    }

    #[test]
    fn remove_by_id_matching_ids_cidr_and_flush() {
        let mut bm = BanManager::new();
        let ip1 = id("192.0.2.10");
        let ip2 = id("192.0.2.20");
        let outside = id("198.51.100.5");

        bm.add_ban_ticket(Ticket::new(ip1.clone(), 100.0), 100.0);
        bm.add_ban_ticket(Ticket::new(ip2.clone(), 101.0), 101.0);
        bm.add_ban_ticket(Ticket::new(outside.clone(), 102.0), 102.0);

        let matched_subnet = bm.matching_ids(&id("192.0.2.0/24"));
        assert_eq!(matched_subnet, vec![ip1.clone(), ip2.clone()]);
        assert_eq!(bm.size(), 3);
        for id in matched_subnet {
            assert!(bm.remove_by_id(&id).is_some());
        }
        assert_eq!(bm.size(), 1);
        assert_eq!(bm.remove_by_id(&outside).unwrap().fid, outside);
        assert_eq!(bm.size(), 0);

        bm.add_ban_ticket(Ticket::new(id("2001:db8::1"), 200.0), 200.0);
        bm.add_ban_ticket(Ticket::new(id("2001:db8::2"), 201.0), 201.0);
        let flushed = bm.flush_ban_list();
        assert_eq!(flushed.len(), 2);
        assert_eq!(bm.size(), 0);
    }

    #[test]
    fn deferred_batch_remove_recomputes_next_unban_on_exit() {
        let mut bm = BanManager::new();
        bm.set_ban_time(100);
        let early1 = id("192.0.2.1");
        let early2 = id("192.0.2.2");
        let later = id("198.51.100.9");

        bm.add_ban_ticket(Ticket::new(early1.clone(), 10.0), 10.0); // ends at 110
        bm.add_ban_ticket(Ticket::new(early2.clone(), 20.0), 20.0); // ends at 120
        bm.add_ban_ticket(Ticket::new(later.clone(), 50.0), 50.0); // ends at 150

        // Simulate partial batch removal (e.g. early1 removed, then batch aborts).
        assert!(bm.remove_by_id_deferred(&early1).is_some());
        bm.recompute_next_unban();
        assert!(bm.unban(115.0).is_empty());
        assert_eq!(bm.size(), 2);

        // Remove early2 via deferred removal and recompute once on exit.
        assert!(bm.remove_by_id_deferred(&early2).is_some());
        bm.recompute_next_unban();
        assert!(bm.unban(150.0).is_empty());
        let expired = bm.unban(151.0);
        assert_eq!(
            expired.into_iter().map(|t| t.fid).collect::<Vec<_>>(),
            vec![later]
        );
    }
}
