use super::{FileIdentityState, Reopen, sha1_hex};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use tempfile::{NamedTempFile, tempdir};

fn fixture(bytes: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create fixture");
    file.write_all(bytes).expect("write fixture");
    file
}

#[test]
fn sha1_reference_vectors_include_padding_and_multiple_blocks() {
    for (data, hex) in [
        (vec![], "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"abc".to_vec(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (vec![b'x'; 56], "901305367c259952f4e7af8323f480d59f81335b"),
        (
            b"abc".repeat(100),
            "c95466320eaae6d19ee314ae4f135b12d45ced9a",
        ),
    ] {
        assert_eq!(sha1_hex(&data), hex);
    }
}

#[test]
fn fingerprint_includes_exact_raw_terminator_and_does_not_seek_descriptor() {
    for (record, hash) in [
        (
            b"alpha\r\ntrailer".as_slice(),
            "378db57aa7e9ec5b4f3921bf1e82b1d045a38a93",
        ),
        (
            b"alpha\ntrailer".as_slice(),
            "d046cd9b7ffb7661e449683313d41f6fc33e3130",
        ),
        (
            b"alpha\r".as_slice(),
            "d7745d745d609b4e2c85665797b304ed588a0ede",
        ),
        (b"alpha".as_slice(), ""),
        (b"".as_slice(), ""),
    ] {
        let mut test = fixture(record);
        let offset = test.seek(SeekFrom::End(0)).expect("cursor at EOF");
        let state = FileIdentityState::initialize(test.as_file(), 100, 64).expect("read at offset");
        assert_eq!(state.fingerprint(), hash);
        assert_eq!(test.stream_position().expect("cursor unchanged"), offset);
    }
}

#[test]
fn stored_position_checks_exact_fingerprint_tail_and_zero() {
    let file = fixture(b"alpha\nnext\n");
    let state = FileIdentityState::initialize(file.as_file(), 100, 64).expect("initial state");
    let correct = "d046cd9b7ffb7661e449683313d41f6fc33e3130";
    assert_eq!(state.resume_offset(correct, 6, false), Some(6));
    assert_eq!(state.resume_offset(correct, 0, false), None);
    assert_eq!(state.resume_offset(correct, 6, true), None);
    assert_eq!(state.resume_offset("", 6, false), None);
    assert_eq!(
        state.resume_offset("d046cd9b7ffb7661e449683313d41f6fc33e313A", 6, false),
        None
    );
    let partial = fixture(b"alpha");
    let state =
        FileIdentityState::initialize(partial.as_file(), 100, 64).expect("partial initial state");
    assert_eq!(state.resume_offset("", 3, false), Some(3));
}

#[test]
fn same_first_record_different_inode_and_shrinking_same_inode_both_reset() {
    let original = fixture(b"alpha\nsecond\n");
    let mut state =
        FileIdentityState::initialize(original.as_file(), 100, 64).expect("initial state");
    let replacement = fixture(b"alpha\n");
    assert_eq!(
        state
            .reopen(replacement.as_file(), 6, 101)
            .expect("replaced descriptor"),
        Reopen {
            offset: 0,
            rotated: true,
            has_content: true
        }
    );
    assert_eq!(
        state.fingerprint(),
        "d046cd9b7ffb7661e449683313d41f6fc33e3130"
    );
    replacement
        .as_file()
        .set_len(0)
        .expect("copytruncate fixture");
    assert_eq!(
        state
            .reopen(replacement.as_file(), 6, 102)
            .expect("shortened descriptor"),
        Reopen {
            offset: 0,
            rotated: true,
            has_content: false
        }
    );
    assert_eq!(state.fingerprint(), "");
}

#[test]
fn regrown_copytruncate_is_seen_only_strictly_after_hash_deadline() {
    let file = fixture(b"alpha\nsecond\n");
    let inode = file.as_file().metadata().expect("old inode").ino();
    let mut state = FileIdentityState::initialize(file.as_file(), 100, 64).expect("initial state");
    fs::write(file.path(), b"new\nreplacement is longer\n")
        .expect("truncate and regrow same inode");
    assert_eq!(file.as_file().metadata().expect("new inode").ino(), inode);
    assert_eq!(
        state
            .reopen(file.as_file(), 13, 130)
            .expect("deadline has not passed"),
        Reopen {
            offset: 13,
            rotated: false,
            has_content: true
        }
    );
    assert_eq!(
        state.fingerprint(),
        "d046cd9b7ffb7661e449683313d41f6fc33e3130"
    );
    assert_eq!(
        state
            .reopen(file.as_file(), 13, 131)
            .expect("overdue rescan"),
        Reopen {
            offset: 0,
            rotated: true,
            has_content: true
        }
    );
    assert_eq!(
        state.fingerprint(),
        "389cc6b7ae5a659383eab5dfc253764eccf84732"
    );
    assert_eq!(
        state.reopen(file.as_file(), 26, 132).expect("no new bytes"),
        Reopen {
            offset: 26,
            rotated: false,
            has_content: false
        }
    );
}

#[test]
fn no_prior_fingerprint_does_not_reset_until_second_reopen() {
    let original = fixture(b"raw");
    let replacement = fixture(b"new\nrest\n");
    let mut state =
        FileIdentityState::initialize(original.as_file(), 100, 64).expect("initial state");
    assert_eq!(
        state
            .reopen(replacement.as_file(), 3, 101)
            .expect("first replacement"),
        Reopen {
            offset: 3,
            rotated: false,
            has_content: true
        }
    );
    assert_eq!(
        state.fingerprint(),
        "389cc6b7ae5a659383eab5dfc253764eccf84732"
    );
    assert_eq!(
        state
            .reopen(replacement.as_file(), 4, 102)
            .expect("second replacement"),
        Reopen {
            offset: 0,
            rotated: true,
            has_content: true
        }
    );
}

#[test]
fn bounded_reads_reject_oversized_first_record_transactionally() {
    let original = fixture(b"alpha\n");
    let oversized = fixture(b"alphax\n");
    let mut state = FileIdentityState::initialize(original.as_file(), 100, 6).expect("exact limit");
    let error = state
        .reopen(oversized.as_file(), 6, 101)
        .expect_err("must reject first");
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert_eq!(
        state.fingerprint(),
        "d046cd9b7ffb7661e449683313d41f6fc33e3130"
    );
    let mut writer = OpenOptions::new()
        .append(true)
        .open(original.path())
        .expect("open append");
    writer
        .write_all(b"long later record outside hashing scope\n")
        .expect("test append");
    assert!(
        !state
            .reopen(original.as_file(), 6, 131)
            .expect("later record not scanned")
            .rotated
    );
    let partial_at_limit = fixture(b"abcdef");
    let partial = FileIdentityState::initialize(partial_at_limit.as_file(), 100, 6)
        .expect("exact-size partial EOF");
    assert_eq!(partial.fingerprint(), "");
}

#[test]
fn rejects_non_regular_descriptor_and_zero_limit() {
    let dir = tempdir().expect("synthetic temp directory");
    let handle = fs::File::open(dir.path()).expect("directory descriptor");
    assert_eq!(
        FileIdentityState::initialize(&handle, 100, 1024)
            .expect_err("must be regular")
            .kind(),
        ErrorKind::InvalidInput
    );
    let file = fixture(b"");
    assert_eq!(
        FileIdentityState::initialize(file.as_file(), 100, 0)
            .expect_err("must be bounded")
            .kind(),
        ErrorKind::InvalidInput
    );
}
