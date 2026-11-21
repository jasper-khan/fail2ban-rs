//! Startup loading of persisted bans, pinned for expired records.

use super::*;

use std::net::Ipv4Addr;

use crate::track::persist::open_ban_store;

const EXPIRED_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
const LIVE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45));

/// Persist one expired and one live ban, then close the store.
fn write_bans(dir: &Path) {
    let store = open_ban_store(dir.to_path_buf()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let ban = |ip, expires_at| BanRecord {
        ip,
        jail_id: "sshd".to_string(),
        banned_at: now - 120,
        expires_at: Some(expires_at),
    };
    store
        .write(|tx| {
            tx.bans
                .put((EXPIRED_IP, "sshd".to_string()), ban(EXPIRED_IP, now - 60))?;
            tx.bans
                .put((LIVE_IP, "sshd".to_string()), ban(LIVE_IP, now + 600))?;
            Ok(())
        })
        .unwrap();
}

/// Pins current behaviour: an expired record is deleted from the store at
/// startup and is NOT handed to the executor or tracker, so no firewall
/// `Unban` is ever issued for it. Backends without a kernel-side timeout
/// (iptables, script) would keep such an address blocked with no record left
/// to retry; nftables/ipset elements carry their own timeout and self-clear.
#[tokio::test]
async fn test_open_state_purges_expired_ban_without_any_unban() {
    let dir = tempfile::tempdir().unwrap();
    write_bans(dir.path());

    let restored = open_state(dir.path()).await.unwrap();

    let restored_ips: Vec<IpAddr> = restored.bans.iter().map(|b| b.ip).collect();
    assert_eq!(restored_ips, vec![LIVE_IP], "expired ban not restored");
    let persisted = restored.store.read();
    assert!(
        !persisted
            .bans
            .contains_key(&(EXPIRED_IP, "sshd".to_string()))
    );
    assert!(persisted.bans.contains_key(&(LIVE_IP, "sshd".to_string())));
}

/// A non-empty WAL retains the existing key and durably inserts a different
/// imported key before the executor can observe the combined list.
#[tokio::test]
async fn test_original_seed_merges_individual_keys_without_overwriting_wal() {
    let dir = tempfile::tempdir().unwrap();
    write_bans(dir.path());
    let mut state = open_state(dir.path()).await.unwrap();
    let prior = state.bans.first().unwrap().clone();
    let incoming_ip = "192.0.2.46".parse().unwrap();
    let overlap = BanRecord {
        expires_at: None,
        ..prior.clone()
    };
    let incoming = BanRecord {
        ip: incoming_ip,
        ..prior.clone()
    };

    seed_original_once(&mut state, || Ok(vec![overlap, incoming.clone()])).unwrap();
    assert_eq!(state.bans.len(), 2);
    assert!(state.bans.iter().any(|ban| ban.ip == incoming_ip));
    {
        let persisted = state.store.read();
        let same_key = persisted.bans.get(&(LIVE_IP, "sshd".to_owned())).unwrap();
        assert_eq!(same_key.expires_at, prior.expires_at);
        let new_key = persisted
            .bans
            .get(&(incoming_ip, "sshd".to_owned()))
            .unwrap();
        assert_eq!(new_key.expires_at, incoming.expires_at);
        assert_eq!(persisted.meta.get(SQLITE_IMPORT_MARKER), Some(&1));
    }

    // Simulate the store-side result of a successful unban. The unchanged
    // original database must no longer be consulted after reopening.
    state
        .store
        .write_durable(|tx| {
            tx.bans.delete(&(incoming_ip, "sshd".to_owned()));
            Ok(())
        })
        .unwrap();
    drop(state);
    let mut reopened = open_state(dir.path()).await.unwrap();
    seed_original_once(&mut reopened, || panic!("already imported")).unwrap();
    assert!(reopened.bans.iter().all(|ban| ban.ip != incoming_ip));
    assert!(reopened.bans.iter().any(|ban| ban.ip == LIVE_IP));
}

#[tokio::test]
async fn test_failed_original_read_does_not_mark_migration_as_done() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = open_state(dir.path()).await.unwrap();
    assert!(
        seed_original_once(&mut state, || Err(crate::error::Error::config(
            "invalid fixture"
        )))
        .is_err()
    );
    assert!(!state.store.read().meta.contains_key(SQLITE_IMPORT_MARKER));
    seed_original_once(&mut state, || Ok(Vec::new())).unwrap();
    assert_eq!(state.store.read().meta.get(SQLITE_IMPORT_MARKER), Some(&1));
}

#[tokio::test]
async fn test_original_log_seed_runs_once_and_recovers_from_interrupted_migration() {
    use crate::server::log_positions::LogPositionStore;
    use crate::track::legacy_sqlite::LegacyLogCheckpoint;

    let dir = tempfile::tempdir().unwrap();
    let state = open_state(dir.path()).await.unwrap();
    let log_positions = LogPositionStore::open(dir.path());

    // 1. Failed read must not set the log-import marker.
    assert!(
        seed_original_logs_once(&state, &log_positions, || Err(
            crate::error::Error::config("broken sqlite")
        ))
        .is_err()
    );
    assert!(!state.store.read().meta.contains_key(SQLITE_LOG_IMPORT_MARKER));

    // 2. Simulate interruption AFTER log_positions.json already has a Rust-saved
    //    position for web1.log, BEFORE SQLITE_LOG_IMPORT_MARKER is committed.
    let key1 = watcher_key("chain-jail", "/tmp/web1.log");
    let key2 = watcher_key("chain-jail", "/tmp/web2.log");
    let rust_pos = PersistedFilePosition {
        path: std::path::PathBuf::from("/tmp/web1.log"),
        inode: Some(77),
        first_line_sha1: Some("aaaa".to_owned()),
        offset: Some(500),
    };
    log_positions.update_one(&key1, rust_pos.clone()).unwrap();

    seed_original_logs_once(&state, &log_positions, || {
        Ok(vec![
            LegacyLogCheckpoint {
                jail: "chain-jail".to_owned(),
                path: std::path::PathBuf::from("/tmp/web1.log"),
                first_line_sha1: Some("aaaa".to_owned()),
                offset: Some(100),
            },
            LegacyLogCheckpoint {
                jail: "chain-jail".to_owned(),
                path: std::path::PathBuf::from("/tmp/web2.log"),
                first_line_sha1: Some("bbbb".to_owned()),
                offset: Some(200),
            },
        ])
    })
    .unwrap();

    assert_eq!(state.store.read().meta.get(SQLITE_LOG_IMPORT_MARKER), Some(&1));
    let snapshot = log_positions.snapshot_resume_points();
    assert_eq!(
        snapshot
            .get(&key1)
            .and_then(crate::detect::ResumePoint::persisted_file_position),
        Some(&rust_pos),
        "existing Rust position must not be overwritten by legacy SQLite"
    );
    assert_eq!(
        snapshot
            .get(&key2)
            .and_then(crate::detect::ResumePoint::persisted_file_position)
            .and_then(|p| p.offset),
        Some(200)
    );

    // 3. Reopen after marker commit: original SQLite must never be read again.
    drop(state);
    let reopened = open_state(dir.path()).await.unwrap();
    let reopened_logs = LogPositionStore::open(dir.path());
    seed_original_logs_once(&reopened, &reopened_logs, || {
        panic!("legacy logs must not be re-imported once marker is set")
    })
    .unwrap();
}
