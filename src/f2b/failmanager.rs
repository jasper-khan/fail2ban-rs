//! Per-jail failure tracking and rate-adjusted retry window (`FailManager`).
//!
//! Mirrors Fail2Ban 1.1.1 `fail2ban/server/failmanager.py` and
//! `FailTicket.adjustTime` in `fail2ban/server/ticket.py`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::ticket::{Ticket, TicketId};

const DEFAULT_MAX_RETRY: u64 = 3;
const DEFAULT_MAX_TIME: f64 = 600.0;
const DEFAULT_MAX_MATCHES: usize = 5;

#[derive(Debug)]
struct FailEntry {
    ticket: Ticket,
    insertion: u64,
}

/// Tracks active failure tickets per `TicketId` before promotion to bans.
#[derive(Debug)]
pub struct FailManager {
    entries: HashMap<TicketId, FailEntry>,
    next_seq: u64,
    max_retry: u64,
    max_time: f64,
    max_matches: usize,
    total_failures: u64,
}

impl Default for FailManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FailManager {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_seq: 0,
            max_retry: DEFAULT_MAX_RETRY,
            max_time: DEFAULT_MAX_TIME,
            max_matches: DEFAULT_MAX_MATCHES,
            total_failures: 0,
        }
    }

    pub fn set_max_retry(&mut self, max_retry: u64) {
        self.max_retry = max_retry;
    }

    pub fn max_retry(&self) -> u64 {
        self.max_retry
    }

    pub fn set_max_time(&mut self, max_time: f64) {
        self.max_time = max_time;
    }

    pub fn max_time(&self) -> f64 {
        self.max_time
    }

    pub fn set_max_matches(&mut self, max_matches: usize) {
        self.max_matches = max_matches;
    }

    pub fn max_matches(&self) -> usize {
        self.max_matches
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }

    pub fn total_failures(&self) -> u64 {
        self.total_failures
    }

    pub fn set_total_failures(&mut self, total: u64) {
        self.total_failures = total;
    }

    pub fn reset_total(&mut self) {
        self.total_failures = 0;
    }

    pub fn get_ticket(&self, id: &TicketId) -> Option<&Ticket> {
        self.entries.get(id).map(|entry| &entry.ticket)
    }

    pub fn del_failure(&mut self, id: &TicketId) {
        self.entries.remove(id);
    }

    /// Record a failure ticket (or an observer retry boost when `observed` is true)
    /// and return the resulting rate-adjusted retry count.
    pub fn add_failure(&mut self, mut ticket: Ticket, count: u64, observed: bool) -> u64 {
        let retry = match self.entries.entry(ticket.fid.clone()) {
            Entry::Occupied(mut occupied) => {
                let current = &mut occupied.get_mut().ticket;
                adjust_time(current, ticket.time, self.max_time);
                current.retry = current.retry.saturating_add(count);
                // When observed is true, the filter already counted this line's attempts/matches.
                let attempt = if observed { 1 } else { ticket.attempts.max(1) };
                current.attempts = current.attempts.saturating_add(attempt);
                if self.max_matches == 0 {
                    current.matches.clear();
                } else if !observed {
                    current.matches.extend(ticket.matches);
                    truncate_matches(&mut current.matches, self.max_matches);
                }
                if !observed {
                    for (k, v) in ticket.data {
                        current.data.insert(k, v);
                    }
                    if current.ip.is_none() {
                        current.ip = ticket.ip;
                    }
                }
                current.ban_count = current.ban_count.max(ticket.ban_count);
                current.retry
            }
            Entry::Vacant(vacant) => {
                if observed {
                    return ticket.retry;
                }
                if ticket.first_time > ticket.time {
                    ticket.first_time = ticket.time;
                }
                if count > ticket.attempts {
                    ticket.retry = ticket.retry.max(count);
                    if ticket.attempts == 0 {
                        ticket.attempts = 1;
                    }
                } else {
                    ticket.retry = ticket.retry.max(ticket.attempts);
                }
                if self.max_matches == 0 {
                    ticket.matches.clear();
                } else {
                    truncate_matches(&mut ticket.matches, self.max_matches);
                }
                let retry = ticket.retry;
                let seq = self.next_seq;
                self.next_seq = self.next_seq.saturating_add(1);
                vacant.insert(FailEntry {
                    ticket,
                    insertion: seq,
                });
                retry
            }
        };
        self.total_failures = self.total_failures.saturating_add(1);
        retry
    }

    /// Evict failure entries whose latest timestamp is at or before `now - max_time`.
    pub fn cleanup(&mut self, now: f64) -> usize {
        let cutoff = now - self.max_time;
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.ticket.time > cutoff);
        before - self.entries.len()
    }

    /// Pop and return an eligible ticket (`retry >= max_retry`).
    ///
    /// Matches upstream `FailManager.toBan`: if `id` is `Some` and currently tracked,
    /// only that entry is checked; otherwise the earliest inserted eligible entry is popped.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_ban(&mut self, id: Option<&TicketId>) -> Option<Ticket> {
        let key = if let Some(req) = id
            && let Some(entry) = self.entries.get(req)
        {
            if entry.ticket.retry >= self.max_retry {
                req.clone()
            } else {
                return None;
            }
        } else {
            self.entries
                .iter()
                .filter(|(_, entry)| entry.ticket.retry >= self.max_retry)
                .min_by_key(|(_, entry)| entry.insertion)?
                .0
                .clone()
        };
        self.entries.remove(&key).map(|entry| entry.ticket)
    }
}

fn adjust_time(ticket: &mut Ticket, time: f64, max_time: f64) {
    if time <= ticket.time {
        return;
    }
    let cutoff = time - max_time;
    if ticket.first_time < cutoff {
        let span = time - ticket.first_time;
        if span > 0.0 && max_time > 0.0 {
            let est = (ticket.retry as f64 / span * max_time).round_ties_even();
            ticket.retry = if est.is_finite() && est >= 0.0 {
                est as u64
            } else {
                0
            };
        } else {
            ticket.retry = 0;
        }
        ticket.first_time = cutoff;
    }
    ticket.time = time;
}

fn truncate_matches(matches: &mut Vec<String>, max_matches: usize) {
    if matches.len() > max_matches {
        let excess = matches.len() - max_matches;
        matches.drain(..excess);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn id(s: &str) -> TicketId {
        TicketId::parse(s)
    }

    #[test]
    fn rate_adjusted_window_uses_ties_to_even_and_preserves_window() {
        let mut fm = FailManager::new();
        fm.set_max_retry(3);
        fm.set_max_time(10.0);

        let up = id("192.0.2.1");
        let down = id("192.0.2.2");

        // 3 / 20 * 10 = 1.5 -> round_ties_even() = 2; +1 = 3.
        assert_eq!(fm.add_failure(Ticket::new(up.clone(), 100.0), 3, false), 3);
        assert_eq!(fm.add_failure(Ticket::new(up.clone(), 120.0), 1, false), 3);
        let up_t = fm.get_ticket(&up).unwrap();
        assert_eq!(up_t.first_time, 110.0);
        assert_eq!(up_t.time, 120.0);
        assert_eq!(up_t.attempts, 2);

        // 5 / 20 * 10 = 2.5 -> round_ties_even() = 2; +1 = 3.
        assert_eq!(
            fm.add_failure(Ticket::new(down.clone(), 100.0), 5, false),
            5
        );
        assert_eq!(
            fm.add_failure(Ticket::new(down.clone(), 120.0), 1, false),
            3
        );
    }

    #[test]
    fn out_of_order_timestamps_do_not_shrink_time_or_first_time() {
        let mut fm = FailManager::new();
        fm.set_max_retry(9);
        fm.set_max_time(10.0);
        let subj = id("192.0.2.10");

        assert_eq!(
            fm.add_failure(Ticket::new(subj.clone(), 100.0), 1, false),
            1
        );
        assert_eq!(
            fm.add_failure(Ticket::new(subj.clone(), 110.0), 1, false),
            2
        );
        assert_eq!(fm.get_ticket(&subj).unwrap().first_time, 100.0);

        assert_eq!(
            fm.add_failure(Ticket::new(subj.clone(), 111.0), 1, false),
            3
        );
        assert_eq!(fm.get_ticket(&subj).unwrap().first_time, 101.0);

        assert_eq!(fm.add_failure(Ticket::new(subj.clone(), 80.0), 1, false), 4);
        let t = fm.get_ticket(&subj).unwrap();
        assert_eq!(t.first_time, 101.0);
        assert_eq!(t.time, 111.0);
        assert_eq!(t.retry, 4);
        assert_eq!(t.attempts, 4);
    }

    #[test]
    fn max_matches_retains_latest_lines_and_merges_data() {
        let mut fm = FailManager::new();
        fm.set_max_matches(2);
        let subj = id("custom-user-id");

        for (idx, line) in ["line1", "line2", "line3", "line4"].iter().enumerate() {
            let mut t = Ticket::new(subj.clone(), 1000.0 + idx as f64);
            t.matches.push((*line).to_owned());
            t.data.insert("user".to_owned(), format!("u{idx}"));
            if idx == 0 {
                t.data.insert("port".to_owned(), "22".to_owned());
            }
            fm.add_failure(t, 1, false);
        }

        let stored = fm.get_ticket(&subj).unwrap();
        assert_eq!(stored.attempts, 4);
        assert_eq!(stored.matches, vec!["line3", "line4"]);
        assert_eq!(stored.data.get("port").map(String::as_str), Some("22"));
        assert_eq!(stored.data.get("user").map(String::as_str), Some("u3"));

        fm.set_max_matches(0);
        let mut t = Ticket::new(subj.clone(), 1010.0);
        t.matches.push("line5".to_owned());
        fm.add_failure(t, 1, false);
        assert!(fm.get_ticket(&subj).unwrap().matches.is_empty());
    }

    #[test]
    fn observed_does_not_create_missing_ticket_or_duplicate_matches() {
        let mut fm = FailManager::new();
        fm.set_max_retry(5);
        let missing = id("192.0.2.50");
        let existing = id("192.0.2.51");

        let mut t_missing = Ticket::new(missing.clone(), 100.0);
        t_missing.retry = 3;
        assert_eq!(fm.add_failure(t_missing, 2, true), 3);
        assert_eq!(fm.size(), 0);
        assert_eq!(fm.total_failures(), 0);

        let mut t_exist = Ticket::new(existing.clone(), 100.0);
        t_exist.matches.push("failed login".to_owned());
        assert_eq!(fm.add_failure(t_exist.clone(), 1, false), 1);
        assert_eq!(fm.add_failure(t_exist, 2, true), 3);
        let stored = fm.get_ticket(&existing).unwrap();
        assert_eq!(stored.matches, vec!["failed login"]);
        assert_eq!(stored.attempts, 2);
        assert_eq!(fm.total_failures(), 2);
    }

    #[test]
    fn cleanup_to_ban_del_failure_and_reset_total() {
        let mut fm = FailManager::new();
        fm.set_max_retry(2);
        fm.set_max_time(10.0);

        let a = id("192.0.2.200");
        let b = id("192.0.2.50");
        let below = id("192.0.2.1");

        fm.add_failure(Ticket::new(a.clone(), 100.0), 1, false);
        fm.add_failure(Ticket::new(b.clone(), 100.0), 1, false);
        fm.add_failure(Ticket::new(b.clone(), 101.0), 1, false);
        fm.add_failure(Ticket::new(a.clone(), 102.0), 1, false);
        fm.add_failure(Ticket::new(below.clone(), 103.0), 1, false);

        // Requesting a tracked ID below max_retry returns None without falling back.
        assert_eq!(fm.to_ban(Some(&below)), None);
        // Absent requested ID falls back to earliest inserted eligible ticket (`a`).
        let absent = id("192.0.2.99");
        assert_eq!(fm.to_ban(Some(&absent)).unwrap().fid, a);
        assert_eq!(fm.to_ban(None).unwrap().fid, b);
        assert_eq!(fm.to_ban(None), None);

        // Boundary: time <= now - max_time is evicted.
        assert_eq!(fm.cleanup(112.0), 0);
        assert_eq!(fm.cleanup(113.0), 1);
        assert_eq!(fm.size(), 0);

        fm.add_failure(Ticket::new(a.clone(), 200.0), 1, false);
        assert_eq!(fm.size(), 1);
        fm.del_failure(&a);
        assert_eq!(fm.size(), 0);

        assert_eq!(fm.total_failures(), 6);
        fm.reset_total();
        assert_eq!(fm.total_failures(), 0);
    }

    #[test]
    fn cidr_and_ipv4_mapped_keys_behave_consistently() {
        let mut fm = FailManager::new();
        fm.set_max_retry(2);
        let mapped = id("::ffff:192.0.2.25");
        let plain = id("192.0.2.25");
        let net = id("198.51.100.0/24");

        assert_eq!(
            fm.add_failure(Ticket::new(mapped.clone(), 100.0), 1, false),
            1
        );
        assert_eq!(
            fm.add_failure(Ticket::new(plain.clone(), 101.0), 1, false),
            2
        );
        assert_eq!(fm.to_ban(Some(&mapped)).unwrap().fid, plain);

        assert_eq!(fm.add_failure(Ticket::new(net.clone(), 102.0), 2, false), 2);
        assert_eq!(fm.to_ban(Some(&net)).unwrap().fid, net);
    }
}
