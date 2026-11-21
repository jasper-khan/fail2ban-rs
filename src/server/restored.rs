//! Startup ban-state loading: open the WAL store, purge expired bans, and
//! hand the survivors to the executor (restore) and tracker (seed).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use etchdb::{FlushPolicy, Store, WalBackend};
use tracing::{info, warn};

use crate::track::persist::{BanCount, BanState};
use crate::track::state::BanRecord;

use super::startup::{handle_legacy_state, open_store_migrating};

/// Shared handle to the persistent ban store.
pub(super) type BanStore = Arc<Store<BanState, WalBackend<BanState>>>;

/// Persisted state recovered at startup.
pub(super) struct Restored {
    /// The opened store, shared with the tracker.
    pub(super) store: BanStore,
    /// Unexpired bans to re-apply.
    pub(super) bans: Vec<BanRecord>,
    /// Per-IP escalation counts.
    pub(super) ban_counts: HashMap<IpAddr, BanCount>,
}

/// Open the ban store (migrating legacy or incompatible state aside) and read
/// back every unexpired ban, purging expired ones from the WAL.
pub(super) async fn open_state(state_dir: &Path) -> crate::error::Result<Restored> {
    handle_legacy_state(state_dir).await?;
    let mut store = open_store_migrating(state_dir).await?;
    store.set_flush_policy(FlushPolicy::Grouped {
        interval: Duration::from_millis(100),
    });
    let store = Arc::new(store);
    let (bans, ban_counts) = load_restored(&store);
    Ok(Restored {
        store,
        bans,
        ban_counts,
    })
}

// A compatibility state directory represents one migration from an old
// database. Keep the marker in the same transaction as its imported rows:
// an unban may remove the row, but must not make SQLite authoritative again.
const SQLITE_IMPORT_MARKER: &str = "original_fail2ban_sqlite_import_v1";

/// Import the original database once, durably, before any action is replayed.
/// The caller runs this at startup with exclusive access to the state store.
pub(super) fn seed_original_once(
    restored: &mut Restored,
    read_original: impl FnOnce() -> crate::error::Result<Vec<BanRecord>>,
) -> crate::error::Result<()> {
    let mut keys: HashSet<_> = {
        let previous = restored.store.read();
        if previous.meta.contains_key(SQLITE_IMPORT_MARKER) {
            return Ok(());
        }
        previous.bans.keys().cloned().collect()
    };
    let imported: Vec<_> = read_original()?
        .into_iter()
        .filter(|record| keys.insert((record.ip, record.jail_id.clone())))
        .collect();
    restored
        .store
        .write_durable(|tx| {
            for record in &imported {
                tx.bans
                    .put((record.ip, record.jail_id.clone()), record.clone())?;
            }
            tx.meta.put(SQLITE_IMPORT_MARKER.to_owned(), 1)?;
            Ok(())
        })
        .map_err(|err| {
            crate::error::Error::persistence(format!("committing original ban migration: {err}"))
        })?;
    info!(
        phase = "startup",
        bans = imported.len(),
        "original ban migration committed"
    );
    restored.bans.extend(imported);
    Ok(())
}

/// Split persisted bans into live ones (returned) and expired ones (purged).
fn load_restored(store: &BanStore) -> (Vec<BanRecord>, HashMap<IpAddr, BanCount>) {
    let now = chrono::Utc::now().timestamp();
    let (expired, bans, counts) = {
        let state = store.read();
        let expired: Vec<_> = state
            .bans
            .iter()
            .filter(|(_, ban)| ban.expires_at.is_some_and(|exp| exp <= now))
            .map(|(key, _)| key.clone())
            .collect();
        let bans: Vec<BanRecord> = state
            .bans
            .values()
            .filter(|ban| ban.expires_at.is_none_or(|exp| exp > now))
            .cloned()
            .collect();
        (expired, bans, state.ban_counts.clone())
    };
    purge_expired(store, &expired);
    if bans.is_empty() {
        info!(phase = "startup", "no persisted state found");
    } else {
        info!(
            phase = "startup",
            bans = bans.len(),
            "persisted state loaded"
        );
    }
    (bans, counts)
}

/// Delete expired ban keys from the store in one transaction.
fn purge_expired(store: &BanStore, keys: &[(IpAddr, String)]) {
    if keys.is_empty() {
        return;
    }
    info!(phase = "startup", bans = keys.len(), "expired bans purged");
    let result = store.write(|tx| {
        for key in keys {
            tx.bans.delete(key);
        }
        Ok(())
    });
    if let Err(e) = result {
        warn!(phase = "startup", error = %e, "expired ban purge failed");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
#[path = "restored_test.rs"]
mod restored_test;
