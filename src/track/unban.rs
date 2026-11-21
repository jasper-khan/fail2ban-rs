//! Acknowledged, retryable firewall unbans.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::enforce::FirewallCmd;
use crate::error::{Error, Result};
use crate::track::execute::{CountRollback, compensate_ban};
use crate::track::sweep::request_jail_reconcile;
use crate::track::tracker_state::{FailKey, TrackerState};

const ACK_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const RETRY_SECS: i64 = 60;

pub(super) struct UnbanOutcome {
    key: FailKey,
    manual: bool,
    result: Result<()>,
    respond: Option<oneshot::Sender<Result<()>>>,
}

/// Queue an unban without blocking the tracker. The ban stays indexed and
/// persisted until the executor confirms removal.
pub(super) async fn start_unban(
    ip: IpAddr,
    jail_id: String,
    manual: bool,
    respond: Option<oneshot::Sender<Result<()>>>,
    s: &mut TrackerState,
) {
    let key = (ip, jail_id.clone());
    if !s.pending_unbans.insert(key.clone()) {
        if let Some(respond) = respond {
            let _ = respond.send(Err(Error::firewall("unban already pending")));
        }
        return;
    }
    let (done, ack) = oneshot::channel();
    let cmd = FirewallCmd::Unban {
        ip,
        jail_id,
        done: Some(done),
    };
    if s.executor_tx.send(cmd).await.is_err() {
        s.pending_unbans.remove(&key);
        schedule_retry(&key, s);
        if let Some(respond) = respond {
            let _ = respond.send(Err(Error::ChannelClosed));
        }
        return;
    }
    let tx: mpsc::Sender<UnbanOutcome> = s.unban_outcome_tx.clone();
    tokio::spawn(async move {
        let result = match tokio::time::timeout(ACK_TIMEOUT, ack).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::ChannelClosed),
            Err(_) => Err(Error::firewall("unban acknowledgement timed out")),
        };
        let _ = tx
            .send(UnbanOutcome {
                key,
                manual,
                result,
                respond,
            })
            .await;
    });
}

pub(super) fn handle_unban_outcome(outcome: UnbanOutcome, s: &mut TrackerState) {
    let key = outcome.key;
    s.pending_unbans.remove(&key);
    let result = outcome.result.and_then(|()| {
        let persisted = persist_removal(&key, s);
        if persisted.is_err() {
            // The action succeeded, but SQLite/WAL removal did not. Keep the
            // ban retryable and inhibit checkpoints that would hide the gap.
            s.automatic_persistence_failed = true;
        }
        persisted
    });
    match &result {
        Ok(()) => {
            s.index.banned_keys.remove(&key);
            s.pending_manual.by_key.remove(&key);
            s.unban_retry_after.remove(&key);
            s.counters.total_unbans += 1;
            s.notify_unban(key.0, &key.1, outcome.manual);
            info!(ip = %key.0, jail = %key.1, "unbanned");
        }
        Err(e) => {
            warn!(ip = %key.0, jail = %key.1, error = %e, "unban failed; ban remains retryable");
            schedule_retry(&key, s);
            // A backend may have removed the element before reporting an
            // error. Reconcile the retained record against actual state.
            request_jail_reconcile(&key.1, s);
        }
    }
    if let Some(respond) = outcome.respond {
        let _ = respond.send(result);
    }
}

pub(super) fn persist_removal(key: &FailKey, s: &TrackerState) -> Result<()> {
    let previous = s.store.read().bans.get(key).cloned();
    let mut wal_committed = false;
    let commit_wal = || {
        s.store
            .write(|tx| {
                tx.bans.delete(key);
                Ok(())
            })
            .map_err(|e| Error::persistence(format!("removing ban after firewall unban: {e}")))?;
        wal_committed = true;
        Ok(())
    };
    let result = if let Some(db) = &s.sqlite_mirror {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .delete_ban_then(&key.1, key.0, commit_wal)
    } else {
        let mut commit_wal = commit_wal;
        commit_wal()
    };
    result.map_err(|err| {
        if wal_committed {
            compensate_ban(s, key, previous, CountRollback::Unchanged, err)
        } else {
            err
        }
    })
}

fn schedule_retry(key: &FailKey, s: &mut TrackerState) {
    let retry_at = chrono::Utc::now().timestamp().saturating_add(RETRY_SECS);
    s.unban_retry_after.insert(key.clone(), retry_at);
    s.index.next_expiry = Some(
        s.index
            .next_expiry
            .map_or(retry_at, |old| old.min(retry_at)),
    );
}
