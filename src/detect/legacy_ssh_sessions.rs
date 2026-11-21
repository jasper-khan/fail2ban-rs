//! Bounded offline replay of a verified subset of Fail2Ban 1.1.1 SSH sessions.
//!
//! Scope: stock `sshd` normal mode, `publickey=nofail`, IP literals and
//! canonical syslog records. Unknown records do not change state. This does
//! not implement general multiline filters, SSH configuration, match history,
//! detector clock heuristics, jail decisions, or a daemon integration.

use std::collections::VecDeque;
use std::net::IpAddr;

use super::extract::normalize_mapped;
use super::legacy_ssh_events::{self, Event};
use super::legacy_ssh_log::parse_ssh_syslog_utc;
use super::watcher::MAX_LINE_LEN;

const MAX_SESSIONS: usize = 100;
const SESSION_TTL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Default)]
pub(crate) struct LegacySshSessions {
    // Original Utils.Cache evicts in insertion order; ordinary hits/updates do
    // not refresh TTL or reorder the entry. The small fixed cap also bounds a
    // linear lookup and the number of owned prefix/user strings.
    sessions: VecDeque<Session>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SshFailure {
    pub(crate) ip: IpAddr,
    pub(crate) timestamp: i64,
    pub(crate) user: Option<String>,
}

#[derive(Debug)]
struct Session {
    key: String,
    inserted_at: i64,
    address: Option<IpAddr>,
    latest_user: Option<String>,
    multiple_users: bool,
    pending: bool,
}

impl Session {
    fn new(key: &str, inserted_at: i64) -> Self {
        Self {
            key: key.to_owned(),
            inserted_at,
            address: None,
            latest_user: None,
            multiple_users: false,
            pending: false,
        }
    }

    fn expired(&self, now: i64) -> bool {
        now.saturating_sub(self.inserted_at) >= SESSION_TTL_SECONDS
    }

    fn remember_user(&mut self, user: &str) {
        if self.latest_user.as_deref() == Some(user) {
            return;
        }
        // Before the first different name, latest is also the initial name;
        // after divergence, the flag stays true without storing a user set.
        self.multiple_users |= self.latest_user.is_some();
        self.latest_user = Some(user.to_owned());
    }

    fn step(&mut self, event: Event<'_>, timestamp: i64) -> (Option<SshFailure>, bool) {
        let (address, user, nofail, gained, forget) = match event {
            Event::Connected { address } => (Some(address), None, true, false, false),
            Event::Context { address, user } => (Some(address), user, true, false, false),
            Event::Failed { address, user } => (address, user, false, false, false),
            Event::Accepted { address, user } => (Some(address), Some(user), true, true, true),
            Event::Disconnected { address, user } => (Some(address), user, true, false, true),
            Event::FailedAndDisconnected { address, user } => {
                (Some(address), user, false, false, true)
            }
        };
        if let Some(address) = address {
            self.address = Some(normalize_mapped(address));
        }
        if let Some(user) = user.filter(|name| !name.is_empty()) {
            self.remember_user(user);
        }

        // Original MLFGAINED resets an unresolved pending failure before the
        // nofail override. Multiple distinct users still override NOFAIL,
        // even for an Accepted event; this is covered by pinned replay.
        let counts = !nofail || (!gained && self.pending) || self.multiple_users;
        let failure = counts
            .then_some(self.address)
            .flatten()
            .map(|ip| SshFailure {
                ip,
                timestamp,
                user: self.latest_user.clone(),
            });
        self.pending = counts && self.address.is_none() && !forget;
        (failure, forget)
    }
}

impl LegacySshSessions {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Replay an ordinary RFC3164 SSH record with explicit input clocks.
    ///
    /// `year` is the UTC calendar year of the source record. The independent
    /// `observed_at` epoch seconds control the bounded session cache, not
    /// the reported event timestamp. No clock is read from this environment.
    pub(crate) fn evaluate(
        &mut self,
        line: &str,
        year: i32,
        observed_at: i64,
    ) -> Option<SshFailure> {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.len() > MAX_LINE_LEN || line.contains(['\r', '\n']) {
            return None;
        }
        let log = parse_ssh_syslog_utc(line, year)?;
        let event = legacy_ssh_events::classify(log.message)?;
        self.apply(log.session_key, log.unix_seconds, observed_at, event)
    }

    fn apply(
        &mut self,
        key: &str,
        timestamp: i64,
        observed_at: i64,
        event: Event<'_>,
    ) -> Option<SshFailure> {
        let existing = self.sessions.iter().position(|session| session.key == key);
        if let Some(index) = existing
            && !self.sessions.get(index)?.expired(observed_at)
        {
            let (failure, forget) = self.sessions.get_mut(index)?.step(event, timestamp);
            if forget {
                self.sessions.remove(index);
            }
            return failure;
        }
        if let Some(index) = existing {
            self.sessions.remove(index);
        }

        let mut new = Session::new(key, observed_at);
        let (failure, forget) = new.step(event, timestamp);
        if !forget {
            if self.sessions.len() >= MAX_SESSIONS {
                while let Some(front) = self.sessions.pop_front() {
                    if !front.expired(observed_at) && self.sessions.len() < MAX_SESSIONS {
                        break;
                    }
                }
            }
            self.sessions.push_back(new);
        }
        failure
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "legacy_ssh_sessions_test.rs"]
mod tests;
