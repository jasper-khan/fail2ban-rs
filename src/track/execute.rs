//! Shared ban/unban execution primitives.
//!
//! These mutate [`TrackerState`], persist to the store, and drive the firewall
//! executor. They are shared by the failure hot path (automatic bans), command
//! handling (manual ban/unban), and the sweep (expiry unbans).

use std::net::IpAddr;

use tokio::sync::oneshot;
use tracing::warn;

use crate::enforce::FirewallCmd;
use crate::error::{Error, Result};
use crate::track::persist::BanCount;
use crate::track::state::BanRecord;
use crate::track::tracker_state::{FailKey, TrackerState};

/// Why a recorded ban was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollbackReason {
    /// The executor channel was closed; the ban command was never delivered.
    ChannelClosed,
    /// The firewall backend reported an error applying the ban.
    FirewallBanFailed,
    /// The firewall did not acknowledge the ban in time.
    Timeout,
}

impl RollbackReason {
    /// Stable label for structured logs.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ChannelClosed => "channel_closed",
            Self::FirewallBanFailed => "firewall_ban_failed",
            Self::Timeout => "firewall_ban_timeout",
        }
    }
}

/// Automatic ban: record the ban, send the fire-and-forget firewall command,
/// and notify. If the executor is gone the ban is rolled back and no
/// notification fires (the firewall never saw it).
///
/// `new_ban_count` carries the escalation counter so the count increment and
/// the ban record land in one atomic store write.
pub(super) async fn execute_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) {
    execute_ban_at(
        ip,
        jail_id,
        chrono::Utc::now().timestamp(),
        ban_time,
        new_ban_count,
        s,
    )
    .await;
}

/// Automatic ban starting at an explicit `banned_at` timestamp (used by
/// Fail2Ban 1.1.1 compat jails, where ban expiry is anchored to `ticket.time`).
pub(super) async fn execute_ban_at(
    ip: IpAddr,
    jail_id: &str,
    banned_at: i64,
    ban_time: i64,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) {
    let ban = match record_ban_at(ip, jail_id, banned_at, ban_time, new_ban_count, s) {
        Ok(ban) => ban,
        Err(e) => {
            s.automatic_persistence_failed = true;
            warn!(%ip, jail = %jail_id, error = %e, "ban not applied because persistence failed");
            return;
        }
    };
    if s.executor_tx.send(ban_cmd(&ban, None)).await.is_err() {
        s.automatic_persistence_failed = true;
        warn!(%ip, jail = %jail_id, "executor channel closed");
        rollback_ban(ip, jail_id, RollbackReason::ChannelClosed, s);
        return;
    }
    s.notify_ban(ip, jail_id, ban_time, false);
}

/// Prolong an existing active ban's expiry in place (Fail2Ban 1.1.1
/// `BanManager::add` -> `Prolonged`), without re-running the ban action or
/// incrementing ban totals.
pub(super) fn prolong_ban(
    ip: IpAddr,
    jail_id: &str,
    new_expires_at: Option<i64>,
    s: &mut TrackerState,
) {
    let key: FailKey = (ip, jail_id.to_string());
    let Some(previous) = s.store.read().bans.get(&key).cloned() else {
        return;
    };
    let mut record = previous.clone();
    record.expires_at = new_expires_at;
    let mut wal_committed = false;
    let commit_wal = || {
        s.store
            .write(|tx| {
                tx.bans.put(key.clone(), record.clone())?;
                Ok(())
            })
            .map_err(|e| Error::persistence(format!("extending ban: {e}")))?;
        wal_committed = true;
        Ok(())
    };
    let result = if let Some(db) = &s.sqlite_mirror {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prolong_ban_then(&record, commit_wal)
    } else {
        let mut commit_wal = commit_wal;
        commit_wal()
    };
    if let Err(err) = result {
        s.automatic_persistence_failed = true;
        let err = if wal_committed {
            compensate_ban(s, &key, Some(previous), CountRollback::Unchanged, err)
        } else {
            err
        };
        warn!(%ip, jail = %jail_id, error = %err, "ban prolongation persist failed");
    }
}

/// Persist a ban record (and any updated ban count) in a single transaction,
/// index it, clear stale failures, and bump counters. Returns the record.
pub(super) fn record_ban(
    ip: IpAddr,
    jail_id: &str,
    ban_time: i64,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) -> Result<BanRecord> {
    record_ban_at(
        ip,
        jail_id,
        chrono::Utc::now().timestamp(),
        ban_time,
        new_ban_count,
        s,
    )
}

fn record_ban_at(
    ip: IpAddr,
    jail_id: &str,
    banned_at: i64,
    ban_time: i64,
    new_ban_count: Option<u32>,
    s: &mut TrackerState,
) -> Result<BanRecord> {
    let expires_at = (ban_time >= 0).then(|| banned_at.saturating_add(ban_time));
    let key: FailKey = (ip, jail_id.to_string());
    let ban = BanRecord {
        ip,
        jail_id: jail_id.to_string(),
        banned_at,
        expires_at,
    };
    persist_then_apply(
        s,
        |state| persist_ban(state, &key, &ban, new_ban_count),
        |state| {
            // A failed write leaves the failure buffer and index intact.
            state.failures.remove(&key);
            state.index.banned_keys.insert(key.clone());
            if let Some(exp) = expires_at {
                state.index.next_expiry =
                    Some(state.index.next_expiry.map_or(exp, |cur| cur.min(exp)));
            }
            state.counters.total_bans += 1;
            *state
                .counters
                .jail_bans
                .entry(jail_id.to_string())
                .or_insert(0) += 1;
            ban.clone()
        },
    )
}

/// Run in-memory changes only after the persistent write succeeds.
fn persist_then_apply<S, T>(
    state: &mut S,
    persist: impl FnOnce(&S) -> Result<()>,
    apply: impl FnOnce(&mut S) -> T,
) -> Result<T> {
    persist(state)?;
    Ok(apply(state))
}

/// Build the firewall `Ban` command for a record.
pub(super) fn ban_cmd(ban: &BanRecord, done: Option<oneshot::Sender<Result<()>>>) -> FirewallCmd {
    FirewallCmd::Ban {
        ip: ban.ip,
        jail_id: ban.jail_id.clone(),
        banned_at: ban.banned_at,
        expires_at: ban.expires_at,
        done,
    }
}

/// Persist the ban record and any updated escalation count in one transaction.
fn persist_ban(
    s: &TrackerState,
    key: &FailKey,
    ban: &BanRecord,
    new_ban_count: Option<u32>,
) -> Result<()> {
    let state = s.store.read();
    let previous = state.bans.get(key).cloned();
    let previous_count = if new_ban_count.is_some() {
        CountRollback::Restore(state.ban_counts.get(&ban.ip).copied())
    } else {
        CountRollback::Unchanged
    };
    drop(state);
    let mut wal_committed = false;
    let commit_wal = || {
        s.store
            .write(|tx| {
                tx.bans.put(key.clone(), ban.clone())?;
                if let Some(count) = new_ban_count {
                    tx.ban_counts.put(
                        ban.ip,
                        BanCount {
                            count,
                            last_ban: ban.banned_at,
                        },
                    )?;
                }
                Ok(())
            })
            .map_err(|e| Error::persistence(format!("recording ban: {e}")))?;
        wal_committed = true;
        Ok(())
    };
    let result = if let Some(db) = &s.sqlite_mirror {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upsert_ban_then(ban, i64::from(new_ban_count.unwrap_or(1)), commit_wal)
    } else {
        let mut commit_wal = commit_wal;
        commit_wal()
    };
    result.map_err(|err| {
        if wal_committed {
            compensate_ban(s, key, previous, previous_count, err)
        } else {
            err
        }
    })
}

#[derive(Clone, Copy)]
pub(super) enum CountRollback {
    Unchanged,
    Restore(Option<BanCount>),
}

// These are separate storage engines, not a distributed transaction. If
// SQLite COMMIT returns an error after the WAL write, restore the prior WAL
// values and report the failure (including any failed compensation).
pub(super) fn compensate_ban(
    s: &TrackerState,
    key: &FailKey,
    previous: Option<BanRecord>,
    previous_count: CountRollback,
    source: Error,
) -> Error {
    let result = s.store.write(|tx| {
        if let Some(record) = previous {
            tx.bans.put(key.clone(), record)?;
        } else {
            tx.bans.delete(key);
        }
        match previous_count {
            CountRollback::Restore(Some(count)) => tx.ban_counts.put(key.0, count)?,
            CountRollback::Restore(None) => {
                tx.ban_counts.delete(&key.0);
            }
            CountRollback::Unchanged => {}
        }
        Ok(())
    });
    match result {
        Ok(()) => source,
        Err(err) => Error::persistence(format!("{source}; WAL compensation failed: {err}")),
    }
}

/// Roll back a ban the firewall never applied.
///
/// Deletes the persisted ban record, drops the index entry, and decrements the
/// counters `record_ban` bumped. Idempotent via `banned_keys`: a ban already
/// unbanned (or rolled back) is left untouched. No firewall `Unban` is issued —
/// the kernel never had the ban. The failure buffer was cleared by
/// `record_ban` and stays cleared, so the IP re-accumulates and retries.
pub(super) fn rollback_ban(
    ip: IpAddr,
    jail_id: &str,
    reason: RollbackReason,
    s: &mut TrackerState,
) {
    let key: FailKey = (ip, jail_id.to_string());
    s.pending_manual.by_key.remove(&key);
    if !s.index.banned_keys.contains(&key) {
        return;
    }
    if let Err(err) = crate::track::unban::persist_removal(&key, s) {
        s.automatic_persistence_failed = true;
        warn!(%ip, jail = %jail_id, error = %err, "failed to persist rollback of unapplied ban");
        return;
    }
    s.index.banned_keys.remove(&key);
    s.counters.total_bans = s.counters.total_bans.saturating_sub(1);
    if let Some(v) = s.counters.jail_bans.get_mut(jail_id) {
        *v = v.saturating_sub(1);
    }
    warn!(%ip, jail = %jail_id, reason = reason.as_str(), "ban rolled back");
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
#[path = "execute_test.rs"]
mod execute_test;
