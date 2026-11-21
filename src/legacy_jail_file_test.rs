use super::*;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use tempfile::tempdir;

const T0: i64 = 1_752_537_600;
const FIRST: &str = "2025/07/15 00:00:00 user \"fixture\" failed, client: 192.0.2.20\n";
const PARTIAL: &str = "2025/07/15 00:00:01 user \"fixture\" failed, client:";
const COMPLETION: &str = " 192.0.2.20\r\n";
const NEXT: &str = "2025/07/15 00:00:08 user \"fixture\" failed, client: 192.0.2.20\n";

fn fixture_config(root: &Path) {
    fs::create_dir(root.join("filter.d")).expect("fixture filter directory");
    fs::write(
        root.join("jail.conf"),
        "[fixture]\nenabled=true\nbackend=polling\nusedns=no\nignoreself=false\n\
         logtimezone=UTC\nlogpath=/offline/fixture.log\nfilter=nginx-http-auth\n\
         maxretry=2\nfindtime=10s\nbantime=5s\naction=\n",
    )
    .expect("fixture jail");
    fs::write(
        root.join("filter.d/nginx-http-auth.conf"),
        r"
[Definition]
prefregex = ^\s*<F-CONTENT>.*</F-CONTENT>, client: <ADDR>$
failregex = ^user .+ failed$
datepattern = {^LN-BEG}
",
    )
    .expect("fixture-only filter");
}

fn attach(root: &Path, log: &Path, start: StartAt) -> JailFileReplay {
    let plan = crate::config::legacy_jail_plan::read(root, "fixture").expect("fixture plan");
    let fp = File::open(log).expect("open explicit fixture");
    JailFileReplay::new(plan, fp, start).expect("attach explicit fixture")
}

fn append(log: &Path, content: &str) {
    fs::OpenOptions::new()
        .append(true)
        .open(log)
        .expect("open temporary log for append")
        .write_all(content.as_bytes())
        .expect("append fixture");
}

#[test]
fn complete_records_acknowledge_and_restore_the_byte_checkpoint() {
    let root = tempdir().expect("isolated workspace");
    fixture_config(root.path());
    let log = root.path().join("actual-explicit-file.log");
    fs::write(&log, format!("{FIRST}{PARTIAL}")).expect("initial records");
    let mut replay = attach(root.path(), &log, StartAt::Head);
    let first_offset = u64::try_from(FIRST.len()).expect("fixture byte length");
    assert_eq!(
        replay.poll_one(T0).expect("read first record"),
        Some(ConsumedLine {
            end_offset: first_offset,
            decision: None
        }),
    );
    assert_eq!(replay.poll_one(T0 + 1).expect("partial record"), None);
    assert_eq!(replay.acknowledged_offset(), first_offset);
    append(&log, COMPLETION);
    assert!(
        replay.poll_one(T0 + 2).is_err(),
        "clock-correction behavior is out of scope"
    );
    assert_eq!(replay.acknowledged_offset(), first_offset);

    let second = replay
        .poll_one(T0 + 1)
        .expect("retry pending complete record")
        .expect("consume second record");
    let ip = "192.0.2.20".parse().expect("fixture IP");
    assert_eq!(
        second.decision,
        Some(ReplayDecision::Ban { ip, at: T0 + 1 })
    );
    assert_eq!(replay.acknowledged_offset(), second.end_offset);
    assert!(replay.expire(T0 + 6).expect("exact deadline").is_empty());
    assert_eq!(
        replay.expire(T0 + 7).expect("after deadline"),
        vec![ReplayDecision::Unban { ip, at: T0 + 7 }]
    );

    append(&log, NEXT);
    let mut resumed = attach(root.path(), &log, StartAt::Resume(second.end_offset));
    let next = resumed
        .poll_one(T0 + 8)
        .expect("resume poll")
        .expect("resume after checkpoint");
    assert_eq!(next.decision, None);
    assert_eq!(
        next.end_offset,
        second.end_offset + u64::try_from(NEXT.len()).expect("line length")
    );
}

#[test]
fn queued_jail_separates_clock_corrected_tickets_from_worker_decisions() {
    use crate::detect::legacy_observation_time::FilePhase;
    use crate::legacy_jail_queued::QueuedJail;

    let root = tempdir().expect("isolated queue workspace");
    fixture_config(root.path());
    let plan = crate::config::legacy_jail_plan::read(root.path(), "fixture").expect("fixture plan");
    let mut jail = QueuedJail::new(plan).expect("valid queue replay");
    assert!(
        !jail
            .observe(FIRST, T0 + 11, FilePhase::Initial)
            .expect("old initial record")
    );
    let second = format!("{PARTIAL}{COMPLETION}");
    assert!(
        !jail
            .observe(&second, T0 + 80, FilePhase::Live)
            .expect("first live record")
    );
    assert!(
        jail.observe(NEXT, T0 + 81, FilePhase::Live)
            .expect("second live record")
    );
    let ip = "192.0.2.20".parse().expect("fixture IP");
    assert_eq!(
        jail.tick(T0 + 82).expect("process queued failure"),
        [ReplayDecision::Ban { ip, at: T0 + 82 }],
    );
    assert!(jail.tick(T0 + 86).expect("equal deadline").is_empty());
    assert_eq!(
        jail.tick(T0 + 87).expect("past deadline"),
        [ReplayDecision::Unban { ip, at: T0 + 87 }],
    );
}

#[test]
fn partial_eof_switches_file_phase_before_queued_threshold_and_expiry() {
    use crate::detect::legacy_observation_time::FilePhase;
    use crate::legacy_queued_file::QueuedFile;

    let root = tempdir().expect("isolated queued file");
    fixture_config(root.path());
    let log = root.path().join("queued-fixture.log");
    fs::write(&log, "").expect("empty fixture");
    let plan = crate::config::legacy_jail_plan::read(root.path(), "fixture").expect("fixture plan");
    let fd = File::open(&log).expect("explicit fixture");
    let mut replay = QueuedFile::new(plan, fd, StartAt::Head).expect("attach fixture");
    assert!(replay.poll_one(T0 + 11).expect("empty EOF").is_none());
    assert_eq!(replay.phase(), FilePhase::Initial);
    append(&log, PARTIAL);
    assert!(replay.poll_one(T0 + 80).expect("partial EOF").is_none());
    assert_eq!(replay.phase(), FilePhase::Live);
    assert_eq!(replay.acknowledged_offset(), 0);

    append(&log, COMPLETION);
    append(&log, NEXT);
    let first = replay
        .poll_one(T0 + 80)
        .expect("complete record")
        .expect("not EOF");
    assert!(!first.queued);
    assert_eq!(first.phase, FilePhase::Live);
    let second = replay
        .poll_one(T0 + 81)
        .expect("next complete record")
        .expect("not EOF");
    assert!(second.queued);
    assert!(second.end_offset > first.end_offset);
    assert_eq!(replay.acknowledged_offset(), second.end_offset);
    let ip = "192.0.2.20".parse().expect("fixture address");
    assert_eq!(
        replay.tick(T0 + 82).expect("drain pending failure"),
        [ReplayDecision::Ban { ip, at: T0 + 82 }]
    );
    assert!(
        replay
            .tick(T0 + 86)
            .expect("equal expiry boundary")
            .is_empty()
    );
    assert_eq!(
        replay.tick(T0 + 87).expect("strictly after expiry"),
        [ReplayDecision::Unban { ip, at: T0 + 87 }]
    );
}
