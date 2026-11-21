use super::*;

use std::io::Read;
use std::time::Duration;

use tempfile::TempDir;

fn position_of(path: &Path, offset: u64) -> FilePosition {
    let file = std::fs::File::open(path).unwrap();
    FilePosition {
        path: path.to_path_buf(),
        identity: FileIdentity::from_handle(&file),
        offset,
    }
}

fn start_of(path: &Path, resume: Option<&FilePosition>) -> StartAt {
    let file = std::fs::File::open(path).unwrap();
    start_for(path, resume, &file)
}

#[test]
fn test_start_for_no_resume_is_end() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "one\n").unwrap();
    assert_eq!(start_of(&path, None), StartAt::End);
}

#[test]
fn test_start_for_other_path_is_end() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.log");
    let b = dir.path().join("b.log");
    std::fs::write(&a, "one\n").unwrap();
    std::fs::write(&b, "one\n").unwrap();
    let pos = position_of(&a, 4);
    assert_eq!(start_of(&b, Some(&pos)), StartAt::End);
}

#[test]
fn test_start_for_absent_marker_is_start() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "one\n").unwrap();
    let pos = FilePosition::absent(path.clone());
    assert_eq!(start_of(&path, Some(&pos)), StartAt::Start);
}

#[test]
fn test_start_for_same_file_grown_is_offset() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "one\n").unwrap();
    let pos = position_of(&path, 4);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut f, b"two\n").unwrap();
    assert_eq!(start_of(&path, Some(&pos)), StartAt::Offset(4));
}

#[test]
fn test_start_for_truncated_file_is_start() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "one\ntwo\n").unwrap();
    let pos = position_of(&path, 8);
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(4).unwrap();
    assert_eq!(start_of(&path, Some(&pos)), StartAt::Start);
}

#[test]
fn test_start_for_replaced_file_is_start() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "one\n").unwrap();
    let pos = position_of(&path, 4);
    let tmp = dir.path().join("new.log");
    std::fs::write(&tmp, "one\nmore\n").unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    assert_eq!(start_of(&path, Some(&pos)), StartAt::Start);
}

#[test]
fn test_open_log_resumes_at_offset() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "one\ntwo\n").unwrap();
    let pos = position_of(&path, 4);
    let cancel = CancellationToken::new();
    let mut reader = open_log("t", &path, Some(&pos), &cancel).unwrap();
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "two\n");
}

#[test]
fn test_open_log_missing_file_read_from_start_when_created() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("late.log");
    let cancel = CancellationToken::new();
    let p = path.clone();
    let c = cancel.clone();
    let handle = std::thread::spawn(move || open_log("t", &p, None, &c));
    std::thread::sleep(Duration::from_millis(200));
    std::fs::write(&path, "first\n").unwrap();
    let mut reader = handle.join().unwrap().expect("file should open");
    let mut content = String::new();
    reader.read_to_string(&mut content).unwrap();
    assert_eq!(
        content, "first\n",
        "a late file must be read from its start"
    );
}

#[test]
fn test_open_log_cancel_while_missing_returns_none() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("never.log");
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    let handle = std::thread::spawn(move || open_log("t", &path, None, &c).is_none());
    std::thread::sleep(Duration::from_millis(100));
    let start = std::time::Instant::now();
    cancel.cancel();
    assert!(handle.join().unwrap());
    assert!(start.elapsed() < Duration::from_millis(500));
}

#[test]
fn test_resume_point_kind_mismatch_is_ignored() {
    assert!(ResumePoint::journal("c".into()).into_file().is_none());
    let file = ResumePoint::file(FilePosition::absent(PathBuf::from("/x")));
    assert!(file.into_journal_cursor().is_none());
}

#[cfg(unix)]
#[test]
fn test_start_for_persisted_valid_rotated_truncated_and_invalid() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.log");
    std::fs::write(&path, "first line\nsecond line\n").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let sha1 = crate::detect::legacy_file_identity::file_first_line_sha1(
        &file,
        crate::detect::watcher::MAX_LINE_LEN + 1,
    )
    .unwrap();
    let meta = file.metadata().unwrap();
    let ino = std::os::unix::fs::MetadataExt::ino(&meta);

    // 1. Legacy-style valid checkpoint (no inode, matching SHA-1, 0 < offset <= size).
    let valid = PersistedFilePosition {
        path: path.clone(),
        inode: None,
        first_line_sha1: Some(sha1.clone()),
        offset: Some(11),
    };
    assert_eq!(start_for_persisted(&path, &valid, &file), StartAt::Offset(11));

    // 2. Valid at exact EOF.
    let at_eof = PersistedFilePosition {
        offset: Some(meta.len()),
        ..valid.clone()
    };
    assert_eq!(
        start_for_persisted(&path, &at_eof, &file),
        StartAt::Offset(meta.len())
    );

    // 3. Truncated (size < offset) -> fallback to Start (0).
    let truncated = PersistedFilePosition {
        offset: Some(meta.len() + 1),
        ..valid.clone()
    };
    assert_eq!(
        start_for_persisted(&path, &truncated, &file),
        StartAt::Start
    );

    // 4. Rotated (different first-line SHA-1) -> fallback to Start (0).
    let rotated_hash = PersistedFilePosition {
        first_line_sha1: Some("0".repeat(40)),
        ..valid.clone()
    };
    assert_eq!(
        start_for_persisted(&path, &rotated_hash, &file),
        StartAt::Start
    );

    // 5. Rotated (Rust-persisted inode mismatch even with same first line) -> Start (0).
    let rotated_ino = PersistedFilePosition {
        inode: Some(ino.wrapping_add(1)),
        ..valid.clone()
    };
    assert_eq!(
        start_for_persisted(&path, &rotated_ino, &file),
        StartAt::Start
    );

    // 6. Invalid checkpoints (offset None/0, hash None/empty) -> fallback to Start (0).
    for invalid in [
        PersistedFilePosition { offset: None, ..valid.clone() },
        PersistedFilePosition { offset: Some(0), ..valid.clone() },
        PersistedFilePosition { first_line_sha1: None, ..valid.clone() },
        PersistedFilePosition { first_line_sha1: Some(String::new()), ..valid.clone() },
    ] {
        assert_eq!(start_for_persisted(&path, &invalid, &file), StartAt::Start);
    }

    // 7. Mismatched path -> End.
    let other_path = dir.path().join("other.log");
    assert_eq!(start_for_persisted(&other_path, &valid, &file), StartAt::End);
}
