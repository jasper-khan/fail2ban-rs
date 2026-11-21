use super::*;

use std::path::PathBuf;

fn sample_pos(
    path: &str,
    inode: Option<u64>,
    hash: Option<&str>,
    offset: Option<u64>,
) -> PersistedFilePosition {
    PersistedFilePosition {
        path: PathBuf::from(path),
        inode,
        first_line_sha1: hash.map(str::to_owned),
        offset,
    }
}

#[test]
fn round_trip_and_seed_missing_preserve_existing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = LogPositionStore::open(dir.path());
    let key_a = "sshd\u{1}/var/log/a.log".to_owned();
    let key_b = "sshd\u{1}/var/log/b.log".to_owned();

    let pos_a_new = sample_pos("/var/log/a.log", Some(10), Some("aaaa"), Some(250));
    store.update_one(&key_a, pos_a_new.clone()).unwrap();

    // Seeding from legacy SQLite must not overwrite key_a, but must insert key_b.
    let pos_a_legacy = sample_pos("/var/log/a.log", None, Some("aaaa"), Some(100));
    let pos_b_legacy = sample_pos("/var/log/b.log", None, Some("bbbb"), Some(400));
    let added = store
        .seed_missing([
            (key_a.clone(), pos_a_legacy),
            (key_b.clone(), pos_b_legacy.clone()),
        ])
        .unwrap();
    assert_eq!(added, 1);

    // Reopen from disk and verify both keys survived durably.
    let reopened = LogPositionStore::open(dir.path());
    let points = reopened.snapshot_resume_points();
    assert_eq!(points.len(), 2);
    assert_eq!(
        points
            .get(&key_a)
            .and_then(ResumePoint::persisted_file_position),
        Some(&pos_a_new)
    );
    assert_eq!(
        points
            .get(&key_b)
            .and_then(ResumePoint::persisted_file_position),
        Some(&pos_b_legacy)
    );
}

#[test]
fn corrupt_file_and_leftover_temp_file_do_not_block_startup() {
    let dir = tempfile::tempdir().unwrap();
    // Simulate a torn temp file alongside a valid committed file.
    let store = LogPositionStore::open(dir.path());
    let key = "sshd\u{1}/var/log/a.log".to_owned();
    let pos = sample_pos("/var/log/a.log", Some(1), Some("abcd"), Some(42));
    store.update_one(&key, pos.clone()).unwrap();
    std::fs::write(dir.path().join("log_positions.json.tmp.999.0"), b"{torn").unwrap();

    let reopened = LogPositionStore::open(dir.path());
    assert_eq!(
        reopened
            .snapshot_resume_points()
            .get(&key)
            .and_then(ResumePoint::persisted_file_position),
        Some(&pos)
    );

    // Corrupting the committed file itself falls back cleanly to empty.
    std::fs::write(dir.path().join(LOG_POSITIONS_FILENAME), b"not-json").unwrap();
    let recovered = LogPositionStore::open(dir.path());
    assert!(recovered.snapshot_resume_points().is_empty());
}

#[test]
fn failed_checkpoint_save_leaves_memory_unchanged_and_same_offset_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    std::fs::write(&state_dir, b"not a directory").unwrap();
    let store = LogPositionStore::open(&state_dir);
    let key = "sshd\u{1}/var/log/a.log";
    let pos = sample_pos("/var/log/a.log", Some(2), Some("abcd"), Some(41));

    assert!(store.update_one(key, pos.clone()).is_err());
    assert!(store.snapshot_resume_points().is_empty());
    std::fs::remove_file(&state_dir).unwrap();
    store.update_one(key, pos.clone()).unwrap();

    let reopened = LogPositionStore::open(&state_dir);
    assert_eq!(
        reopened
            .snapshot_resume_points()
            .get(key)
            .and_then(ResumePoint::persisted_file_position),
        Some(&pos),
    );
}
