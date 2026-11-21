use super::*;
use std::fs;
use std::io::Write as _;
use tempfile::{NamedTempFile, tempdir};

const NOW: i64 = 1_752_537_600;
const LINE: &str = "2025/07/15 00:00:00 user fixture failed, client: 192.0.2.20\n";

fn plan() -> JailPlan {
    let cfg = tempdir().expect("fixture config");
    fs::create_dir(cfg.path().join("filter.d")).expect("fixture filter directory");
    fs::write(
        cfg.path().join("jail.conf"),
        r"
[fixture]
enabled = true
backend = polling
filter = nginx-http-auth
usedns = no
ignoreself = false
logtimezone = UTC
logpath = /offline/zeta.log
          /offline/alpha.log
maxretry = 2
findtime = 10s
bantime = 5s
action =
",
    )
    .expect("synthetic INI");
    fs::write(
        cfg.path().join("filter.d/nginx-http-auth.conf"),
        r"
[Definition]
prefregex = ^\s*<F-CONTENT>.*</F-CONTENT>, client: <ADDR>$
failregex = ^user .+ failed$
datepattern = {^LN-BEG}
",
    )
    .expect("synthetic filter");
    crate::config::legacy_jail_plan::read(cfg.path(), "fixture").expect("admitted plan")
}

fn fixture(bytes: &[u8]) -> NamedTempFile {
    let mut out = NamedTempFile::new().expect("regular temporary file");
    out.write_all(bytes).expect("initialize fixture");
    out
}

fn sample(slot: usize, mtime: f64, file: &NamedTempFile) -> PollInput {
    let descriptor = file.reopen().expect("open private fixture");
    let meta = descriptor.metadata().expect("fixture fstat");
    PollInput {
        slot,
        stamp: PollStamp {
            mtime,
            inode: meta.ino(),
            size: meta.len(),
        },
        file: descriptor,
    }
}

fn observed(slot: usize, mtime: f64, file: &NamedTempFile) -> PollSlot {
    let PollInput { slot, stamp, file } = sample(slot, mtime, file);
    PollSlot {
        slot,
        sample: Some((stamp, file)),
    }
}

const fn absent(slot: usize) -> PollSlot {
    PollSlot { slot, sample: None }
}

fn attach(cycle: &mut PollCycle, slot: usize, file: &NamedTempFile) {
    cycle
        .attach(
            slot,
            file.reopen().expect("attach private fixture"),
            false,
            None,
            NOW,
            None,
        )
        .expect("attach slot");
}

#[test]
fn registration_order_controls_reopen_and_drain_and_tick_is_separate() {
    let mut first = fixture(LINE.as_bytes());
    let second = fixture(LINE.as_bytes());
    let mut cycle = PollCycle::new(plan()).expect("initialize two fixtures");
    // The input handles and attach calls are reversed, but slot order still
    // comes from the admitted non-lexical INI logpath order.
    attach(&mut cycle, 1, &second);
    attach(&mut cycle, 0, &first);
    let drains = cycle
        .poll(vec![sample(1, 0.0, &second), sample(0, 0.0, &first)], NOW)
        .expect("first snapshot");
    let [a, b] = drains.as_slice() else {
        assert_eq!(drains.len(), 2);
        return;
    };
    assert_eq!((a.slot, b.slot), (0, 1));
    for entry in [a, b] {
        assert_eq!(entry.phase, FilePhase::Live);
        assert_eq!(entry.offset, LINE.len() as u64);
        assert_eq!(entry.lines.len(), 1);
        assert_eq!(
            entry.lines.first().expect("one record").phase,
            FilePhase::Initial
        );
        assert!(entry.reopen.has_content);
    }
    assert!(!a.lines.first().expect("first record").queued);
    assert!(b.lines.first().expect("second record").queued);
    assert!(
        cycle
            .poll(vec![sample(0, 0.0, &first), sample(1, 0.0, &second)], NOW)
            .expect("unchanged")
            .is_empty()
    );

    let ip = "192.0.2.20".parse().expect("fixture IP");
    assert_eq!(
        cycle.tick(NOW + 1).expect("separate tick"),
        [ReplayDecision::Ban { ip, at: NOW + 1 }]
    );
    assert!(
        cycle
            .tick(NOW + 5)
            .expect("exact timer equality")
            .is_empty()
    );
    assert_eq!(
        cycle.tick(NOW + 6).expect("past active timer"),
        [ReplayDecision::Unban { ip, at: NOW + 6 }]
    );

    first
        .write_all(LINE.as_bytes())
        .expect("append only first file");
    let drained = cycle
        .poll(
            vec![sample(1, 0.0, &second), sample(0, 1.0, &first)],
            NOW + 7,
        )
        .expect("first changed");
    let first = drained.first().expect("one changed");
    assert_eq!(drained.len(), 1);
    assert_eq!(first.slot, 0);
    assert_eq!(
        first.lines.first().expect("new record").phase,
        FilePhase::Live
    );
    assert_eq!(first.offset, 2 * LINE.len() as u64);
    assert_eq!(
        cycle
            .acknowledged_offset(1)
            .expect("second cursor unchanged"),
        LINE.len() as u64
    );
}

#[test]
fn invalid_snapshots_cannot_record_changes_or_consume_file_bytes() {
    let mut first = fixture(b"");
    let second = fixture(b"");
    let mut cycle = PollCycle::new(plan()).expect("initialize cycle");
    attach(&mut cycle, 0, &first);
    assert!(
        cycle
            .poll(vec![sample(0, 0.0, &first), sample(1, 0.0, &second)], NOW)
            .is_err()
    );
    assert_eq!(cycle.maintenance_counts(), (0, 0));
    attach(&mut cycle, 1, &second);
    assert_eq!(
        cycle
            .poll(vec![sample(0, 0.0, &first), sample(1, 0.0, &second)], NOW)
            .expect("first valid")
            .len(),
        2
    );
    assert_eq!(cycle.maintenance_counts(), (0, 1));
    first.write_all(LINE.as_bytes()).expect("append first file");

    let mut wrong_inode = sample(1, 0.0, &second);
    wrong_inode.stamp.inode ^= 1;
    let mut wrong_size = sample(1, 0.0, &second);
    wrong_size.stamp.size += 1;
    let dir = tempdir().expect("nonregular fixture");
    let mut nonregular = sample(1, 0.0, &second);
    nonregular.file = File::open(dir.path()).expect("private directory descriptor");
    for malformed in [
        vec![sample(0, 1.0, &first)],
        vec![sample(0, 1.0, &first), sample(0, 1.0, &first)],
        vec![sample(0, 1.0, &first), sample(2, 0.0, &second)],
        vec![sample(0, 1.0, &first), sample(1, f64::NAN, &second)],
        vec![sample(0, 1.0, &first), wrong_inode],
        vec![sample(0, 1.0, &first), wrong_size],
        vec![sample(0, 1.0, &first), nonregular],
    ] {
        assert!(cycle.poll(malformed, NOW).is_err());
        assert_eq!(
            cycle.acknowledged_offset(0).expect("unchanged checkpoint"),
            0
        );
        assert_eq!(cycle.phase(0).expect("unchanged phase"), FilePhase::Initial);
        assert_eq!(cycle.maintenance_counts(), (0, 1));
    }
    let done = cycle
        .poll(vec![sample(1, 0.0, &second), sample(0, 1.0, &first)], NOW)
        .expect("valid changed source");
    assert_eq!(
        done.len(),
        1,
        "malformed snapshots mustn't memoize the changed stamp"
    );
    assert_eq!(done.first().expect("one drain").slot, 0);
    assert_eq!(
        cycle.acknowledged_offset(0).expect("record consumed"),
        LINE.len() as u64
    );
    assert!(cycle.checkpoint(0).expect("tracked slot").is_some());
    assert_eq!(cycle.maintenance_counts(), (1, 2));
    assert!(
        cycle
            .poll(vec![sample(0, 1.0, &first), sample(1, 0.0, &second)], NOW)
            .expect("successful unchanged poll")
            .is_empty()
    );
    assert_eq!(cycle.maintenance_counts(), (1, 3));
}

#[test]
fn valid_stamps_stay_committed_if_a_later_drain_fails() {
    let first = fixture(b"\xff\n");
    let second = fixture(LINE.as_bytes());
    let mut cycle = PollCycle::new(plan()).expect("initialize cycle");
    attach(&mut cycle, 0, &first);
    attach(&mut cycle, 1, &second);
    assert!(
        cycle
            .poll(vec![sample(1, 0.0, &second), sample(0, 0.0, &first)], NOW)
            .is_err()
    );
    assert_eq!(cycle.maintenance_counts(), (0, 0));
    assert_eq!(
        cycle.acknowledged_offset(0).expect("malformed isn't acked"),
        0
    );
    assert_eq!(
        cycle
            .acknowledged_offset(1)
            .expect("later slot wasn't read"),
        0
    );
    assert!(
        cycle
            .poll(vec![sample(1, 0.0, &second), sample(0, 0.0, &first)], NOW)
            .expect("stamps already committed")
            .is_empty()
    );
    let done = cycle
        .poll(vec![sample(1, 1.0, &second), sample(0, 0.0, &first)], NOW)
        .expect("only changed second");
    assert_eq!(done.len(), 1);
    assert_eq!(done.first().expect("one drain").slot, 1);
}

#[test]
fn transient_missing_source_retains_cursor_and_phase_while_peer_drains() {
    let first = fixture(LINE.as_bytes());
    let mut second = fixture(b"");
    let mut cycle = PollCycle::new(plan()).expect("initialize cycle");
    attach(&mut cycle, 0, &first);
    attach(&mut cycle, 1, &second);
    let initial = cycle
        .poll_sampled(
            vec![observed(1, 0.0, &second), observed(0, 0.0, &first)],
            NOW,
        )
        .expect("initial poll");
    assert_eq!(initial.len(), 2);
    let (fingerprint, offset) = cycle
        .checkpoint(0)
        .expect("configured source")
        .expect("tracked missing candidate");
    let fingerprint = fingerprint.to_owned();
    assert_eq!(
        cycle.phase(0).expect("initial file drained"),
        FilePhase::Live
    );

    second
        .write_all(LINE.as_bytes())
        .expect("append peer record");
    let active = cycle
        .poll_sampled(vec![observed(1, 1.0, &second), absent(0)], NOW + 1)
        .expect("peer survives unavailable first source");
    let peer = active.first().expect("changed peer");
    assert_eq!(active.len(), 1);
    assert_eq!(peer.slot, 1);
    assert!(peer.lines.first().expect("peer record").queued);
    assert_eq!(
        cycle.checkpoint(0).expect("tracked source"),
        Some((fingerprint.as_str(), offset))
    );
    assert_eq!(cycle.phase(0).expect("untouched phase"), FilePhase::Live);

    let all_missing = cycle
        .poll_sampled(vec![absent(0), absent(1)], NOW + 1)
        .expect("short all-missing active sample");
    assert!(all_missing.is_empty());
    assert_eq!(cycle.maintenance_counts(), (2, 3));
    assert!(
        cycle
            .poll_sampled(
                vec![observed(0, 0.0, &first), observed(1, 1.0, &second)],
                NOW + 1
            )
            .expect("identical tuple reappears")
            .is_empty()
    );
    assert_eq!(cycle.maintenance_counts(), (2, 4));

    assert!(
        cycle
            .poll_sampled(vec![absent(1), absent(1)], NOW + 1)
            .is_err()
    );
    assert!(cycle.poll_sampled(vec![absent(0)], NOW + 1).is_err());
    assert_eq!(cycle.maintenance_counts(), (2, 4));

    let replacement = fixture(LINE.as_bytes());
    let replaced = cycle
        .poll_sampled(vec![absent(1), observed(0, 0.0, &replacement)], NOW + 1)
        .expect("new inode reopens even with identical contents");
    let result = replaced.first().expect("rotated source");
    assert_eq!(replaced.len(), 1);
    assert_eq!(result.slot, 0);
    assert!(result.reopen.rotated);
    assert_eq!(result.reopen.offset, 0);
    assert_eq!(result.phase, FilePhase::Live);
    assert_eq!(result.offset, offset);
    let ip = "192.0.2.20".parse().expect("fixture IP");
    assert_eq!(
        cycle.tick(NOW + 1).expect("separate action tick"),
        [ReplayDecision::Ban { ip, at: NOW + 1 }]
    );
}

#[test]
fn consecutive_miss_eviction_drops_only_one_cursor_and_not_the_peer_queue() {
    let left = fixture(LINE.as_bytes());
    let mut right = fixture(b"");
    let mut cycle = PollCycle::new(plan()).expect("initialize cycle");
    attach(&mut cycle, 0, &left);
    attach(&mut cycle, 1, &right);
    cycle
        .poll(vec![sample(0, 0.0, &left), sample(1, 0.0, &right)], NOW)
        .expect("observe both sources");
    for _ in 0..50 {
        assert!(
            cycle
                .poll_sampled(vec![absent(0), observed(1, 0.0, &right)], NOW)
                .expect("tolerated gap")
                .is_empty()
        );
    }
    assert!(cycle.is_registered(0).expect("configured source"));
    assert_eq!(
        cycle.missing_streak(0).expect("active missing count"),
        Some(50)
    );
    assert_eq!(
        cycle.acknowledged_offset(0).expect("retained cursor"),
        LINE.len() as u64
    );
    assert!(
        cycle.poll_sampled(vec![absent(0)], NOW).is_err(),
        "malformed 51st is not charged"
    );
    assert_eq!(cycle.missing_streak(0).expect("still missing 50"), Some(50));
    assert!(
        cycle
            .poll(vec![sample(1, 0.0, &right), sample(0, 0.0, &left)], NOW)
            .expect("same tuple returns")
            .is_empty()
    );
    assert_eq!(
        cycle.missing_streak(0).expect("reset on unchanged success"),
        Some(0)
    );
    let ordinary = b"ordinary nonmatching fixture record\n";
    right
        .write_all(ordinary)
        .expect("append benign peer record");
    assert_eq!(
        cycle
            .poll(vec![sample(1, 1.0, &right), sample(0, 0.0, &left)], NOW)
            .expect("peer still active")
            .len(),
        1,
        "a processed line also keeps this scenario below original shared idle saturation"
    );
    for _ in 0..50 {
        cycle
            .poll_sampled(vec![absent(0), observed(1, 1.0, &right)], NOW)
            .expect("new streak");
    }
    right
        .write_all(LINE.as_bytes())
        .expect("append to healthy peer");
    let drained = cycle
        .poll_sampled(vec![observed(1, 2.0, &right), absent(0)], NOW)
        .expect("remove failed source and drain healthy peer");
    assert_eq!(drained.len(), 1);
    let peer = drained.first().expect("only surviving peer");
    assert_eq!(peer.slot, 1);
    assert_eq!(peer.offset, (ordinary.len() + LINE.len()) as u64);
    assert!(
        peer.lines
            .first()
            .expect("peer uses shared failure counts")
            .queued
    );
    assert!(!cycle.is_registered(0).expect("known but evicted slot"));
    assert_eq!(
        cycle.missing_streak(0).expect("no retained miss counter"),
        None
    );
    assert!(cycle.phase(0).is_err());
    assert!(cycle.checkpoint(0).is_err());
    assert!(cycle.acknowledged_offset(0).is_err());
    assert_eq!(
        fs::read(left.path()).expect("fixture bytes retained"),
        LINE.as_bytes()
    );
    assert!(
        cycle
            .poll_sampled(vec![observed(0, 0.0, &left), observed(1, 2.0, &right)], NOW)
            .is_err()
    );
    assert!(
        cycle
            .attach(
                0,
                left.reopen().expect("preopened fixture"),
                false,
                None,
                NOW,
                None
            )
            .is_err(),
        "removed source is not reattached by this model"
    );
    assert!(
        cycle
            .poll(vec![sample(1, 2.0, &right)], NOW)
            .expect("snapshot now requires only the surviving slot")
            .is_empty()
    );
    let ip = "192.0.2.20".parse().expect("fixture IP");
    assert_eq!(
        cycle.tick(NOW).expect("peer's queued ticket survived"),
        [ReplayDecision::Ban { ip, at: NOW }]
    );
}

#[test]
fn all_evicted_sources_allow_complete_empty_snapshots() {
    let file = fixture(b"");
    let mut plan = plan();
    plan.log_paths.truncate(1);
    let mut cycle = PollCycle::new(plan).expect("one source");
    attach(&mut cycle, 0, &file);
    for _ in 0..51 {
        assert!(
            cycle
                .poll_sampled(vec![absent(0)], NOW)
                .expect("sample missing")
                .is_empty()
        );
    }
    assert!(!cycle.is_registered(0).expect("configured slot"));
    assert!(
        cycle
            .poll(vec![], NOW)
            .expect("all active sources omitted correctly")
            .is_empty()
    );
    assert!(cycle.poll_sampled(vec![absent(0)], NOW).is_err());
}

#[test]
fn backwards_observation_rejects_before_committing_the_snapshot() {
    let first = fixture(LINE.as_bytes());
    let second = fixture(b"");
    let mut cycle = PollCycle::new(plan()).expect("initialize cycle");
    attach(&mut cycle, 0, &first);
    attach(&mut cycle, 1, &second);
    assert!(
        cycle
            .tick(NOW + 1)
            .expect("advance worker clock")
            .is_empty()
    );
    assert!(
        cycle
            .poll(vec![sample(0, 0.0, &first), sample(1, 0.0, &second)], NOW)
            .is_err()
    );
    assert_eq!(cycle.acknowledged_offset(0).expect("unmodified offset"), 0);
    let result = cycle
        .poll(
            vec![sample(0, 0.0, &first), sample(1, 0.0, &second)],
            NOW + 1,
        )
        .expect("same stamps, valid clock");
    assert_eq!(result.len(), 2);
    assert_eq!(
        cycle.acknowledged_offset(0).expect("now consumed"),
        LINE.len() as u64
    );
}

#[test]
fn shared_budget_crossing_commits_stat_selection_and_skips_all_reads() {
    let normal = b"ordinary benign fixture record\n";
    let mut before = fixture(normal);
    let left = fixture(LINE.as_bytes());
    let right = fixture(LINE.as_bytes());
    let mut after = fixture(normal);
    let mut plan = plan();
    plan.log_paths.push("/offline/left-gap.log".into());
    plan.log_paths.push("/offline/right-gap.log".into());
    plan.ban_time_seconds = 120;
    let mut cycle = PollCycle::new(plan).expect("initialize four slots");
    for (slot, file) in [(0, &before), (1, &left), (2, &right), (3, &after)] {
        attach(&mut cycle, slot, file);
    }
    assert!(cycle.idle_timeout(NOW).is_err());
    for time in NOW..NOW + 8 {
        cycle
            .poll_sampled_trace(
                vec![
                    observed(3, 0.0, &after),
                    observed(1, 0.0, &left),
                    observed(2, 0.0, &right),
                    observed(0, 0.0, &before),
                ],
                time,
            )
            .expect("baseline and unchanged polls");
    }
    assert_eq!(cycle.maintenance_counts(), (4, 8));
    for time in NOW + 8..NOW + 57 {
        let scan = cycle
            .poll_sampled_trace(
                vec![
                    absent(2),
                    observed(3, 0.0, &after),
                    absent(1),
                    observed(0, 0.0, &before),
                ],
                time,
            )
            .expect("two absent paths");
        assert!(scan.selected.is_empty());
    }
    assert_eq!(cycle.filter_errors(), 98);
    assert!(!cycle.filter_idle());
    assert_eq!(cycle.missing_streak(1).expect("left"), Some(49));
    assert_eq!(cycle.missing_streak(2).expect("right"), Some(49));
    assert!(
        cycle
            .poll_sampled(vec![absent(1), absent(2)], NOW + 57)
            .is_err()
    );
    assert_eq!(cycle.filter_errors(), 98);
    cycle
        .poll_sampled(
            vec![
                observed(0, 0.0, &before),
                absent(1),
                observed(2, 0.0, &right),
                observed(3, 0.0, &after),
            ],
            NOW + 57,
        )
        .expect("unchanged right returns and does not decay the shared budget");
    assert_eq!(cycle.filter_errors(), 99);
    assert_eq!(cycle.missing_streak(1).expect("left"), Some(50));
    assert_eq!(
        cycle
            .missing_streak(2)
            .expect("same stat resets right streak"),
        Some(0)
    );

    before
        .write_all(normal)
        .expect("append before the idle-triggering slot");
    after
        .write_all(normal)
        .expect("append after the idle-triggering slot");
    let crossing = cycle
        .poll_sampled_trace(
            vec![
                observed(3, 1.0, &after),
                absent(1),
                observed(0, 1.0, &before),
                observed(2, 0.0, &right),
            ],
            NOW + 58,
        )
        .expect("active iteration crosses into idle");
    assert_eq!(crossing.selected, [0, 3]);
    assert_eq!(crossing.skipped, [0, 3]);
    assert_eq!(crossing.removed, [1]);
    assert!(crossing.drained.is_empty());
    assert_eq!(cycle.filter_errors(), 50);
    assert!(cycle.filter_idle());
    assert_eq!(cycle.maintenance_counts(), (4, 9));
    for slot in [0, 3] {
        assert_eq!(
            cycle.acknowledged_offset(slot).expect("skipped source"),
            normal.len() as u64
        );
        assert_eq!(cycle.phase(slot).expect("unchanged phase"), FilePhase::Live);
    }
    assert!(cycle.poll_sampled(vec![], NOW + 59).is_err());
    assert!(
        cycle.idle_timeout(NOW + 57).is_err(),
        "backward idle wait cannot tick"
    );
    let maintenance = cycle.maintenance_trace().to_vec();
    cycle
        .idle_timeout(NOW + 59)
        .expect("idle tick at periodic boundary");
    assert_eq!(cycle.maintenance_counts(), (4, 0));
    assert_eq!(cycle.maintenance_trace(), maintenance);
    assert_eq!(cycle.filter_errors(), 50);

    let ip = "192.0.2.20".parse().expect("fixture IP");
    assert_eq!(
        cycle
            .tick(NOW + 59)
            .expect("action worker independent of filter idle"),
        [ReplayDecision::Ban { ip, at: NOW + 59 }]
    );
    cycle.resume_filter();
    assert!(!cycle.filter_idle());
    assert_eq!(cycle.filter_errors(), 50);
    assert_eq!(cycle.maintenance_counts(), (4, 0));
    let unchanged = cycle
        .poll_sampled_trace(
            vec![
                observed(0, 1.0, &before),
                observed(2, 0.0, &right),
                observed(3, 1.0, &after),
            ],
            NOW + 60,
        )
        .expect("committed stamps make resumed unchanged files ineligible");
    assert!(unchanged.selected.is_empty());
    assert_eq!(cycle.filter_errors(), 50);
    before.write_all(normal).expect("new change after resume");
    let resumed = cycle
        .poll_sampled_trace(
            vec![
                observed(3, 1.0, &after),
                observed(2, 0.0, &right),
                observed(0, 2.0, &before),
            ],
            NOW + 61,
        )
        .expect("drain retained bytes from the original offset");
    assert_eq!(resumed.selected, [0]);
    let drain = resumed.drained.first().expect("only before poll drained");
    assert_eq!(drain.lines.len(), 2);
    assert_eq!(drain.offset, 3 * normal.len() as u64);
    assert_eq!(
        cycle.acknowledged_offset(3).expect("after remains unread"),
        normal.len() as u64
    );
    assert_eq!(
        cycle.filter_errors(),
        12,
        "both successful misses halve the counter"
    );
    assert_eq!(cycle.maintenance_counts(), (6, 2));
}
