//! Offline adapter from one already-opened fixture file to a queued jail.
//!
//! Only complete records advance the acknowledged byte offset, and only
//! after successful observation. The caller supplies every clock and action
//! tick. This never opens configuration paths or runs an action, watcher,
//! worker thread, or service.

use std::fs::File;

use crate::config::legacy_jail_plan::JailPlan;
use crate::detect::legacy_file_cursor::{LegacyFileCursor, StartAt};
#[cfg(unix)]
use crate::detect::legacy_file_identity::{FileIdentityState, Reopen};
use crate::detect::legacy_observation_time::FilePhase;
use crate::detect::watcher::MAX_LINE_LEN;
use crate::error::{Error, Result};
use crate::legacy_jail_queued::QueuedJail;
use crate::legacy_jail_replay::ReplayDecision;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QueuedLine {
    pub(crate) end_offset: u64,
    /// A ticket was queued, not a ban. The caller must tick the action model.
    pub(crate) queued: bool,
    /// The phase in which this record was observed.
    pub(crate) phase: FilePhase,
}

pub(crate) struct QueuedFile {
    file: LegacyFileCursor,
    jail: QueuedJail,
    phase: FilePhase,
    saw_complete_record: bool,
    #[cfg(unix)]
    identity: Option<FileIdentityState>,
}

impl QueuedFile {
    pub(crate) fn new(plan: JailPlan, file: File, start: StartAt) -> Result<Self> {
        let cursor = LegacyFileCursor::open(file, start, MAX_LINE_LEN)
            .map_err(|err| Error::io("opening preselected queued log fixture", err))?;
        Self::from_cursor(plan, cursor, start)
    }

    fn from_cursor(plan: JailPlan, file: LegacyFileCursor, start: StartAt) -> Result<Self> {
        if plan.log_paths.len() != 1 {
            return Err(Error::config(
                "legacy queued file requires one configured log",
            ));
        }
        Ok(Self {
            file,
            jail: QueuedJail::new(plan)?,
            phase: if start == StartAt::Tail {
                FilePhase::Live
            } else {
                FilePhase::Initial
            },
            saw_complete_record: false,
            #[cfg(unix)]
            identity: None,
        })
    }

    /// Attach a pre-opened file with an optional typed checkpoint. A matching
    /// fingerprint enables resume; tail ignores checkpoints, like FileFilter.
    #[cfg(unix)]
    pub(crate) fn with_identity(
        plan: JailPlan,
        file: File,
        tail: bool,
        saved: Option<(&str, u64)>,
        now: i64,
    ) -> Result<Self> {
        let mut identity = FileIdentityState::initialize(&file, now, MAX_LINE_LEN)
            .map_err(|err| Error::io("identifying preselected queued log fixture", err))?;
        let mut tracked = if tail {
            Self::new(plan, file, StartAt::Tail)?
        } else {
            let saved_offset = saved
                .and_then(|(hash, offset)| identity.resume_offset(hash, offset, false))
                .unwrap_or_default();
            let position = identity
                .reopen(&file, saved_offset, now)
                .map_err(|err| Error::io("validating queued log fixture checkpoint", err))?;
            Self::from_cursor(
                plan,
                LegacyFileCursor::reopen(file, position.offset, MAX_LINE_LEN)
                    .map_err(|err| Error::io("opening preselected queued log fixture", err))?,
                StartAt::Head,
            )?
        };
        tracked.identity = Some(identity);
        Ok(tracked)
    }

    /// Switch to a fresh caller-supplied handle at the legacy resume offset.
    /// Rotation changes the byte stream, not the jail, ban queue, or phase.
    /// Drop old buffered bytes only after the new handle succeeds.
    #[cfg(unix)]
    pub(crate) fn reopen(&mut self, file: File, now: i64) -> Result<Reopen> {
        let Some(mut identity) = self.identity.clone() else {
            return Err(Error::config("queued log fixture has no tracked identity"));
        };
        let position = identity
            .reopen(&file, self.acknowledged_offset(), now)
            .map_err(|err| Error::io("checking reopened queued log fixture", err))?;
        let cursor = LegacyFileCursor::reopen(file, position.offset, MAX_LINE_LEN)
            .map_err(|err| Error::io("reopening preselected queued log fixture", err))?;
        self.file = cursor;
        self.identity = Some(identity);
        self.saw_complete_record = false;
        Ok(position)
    }

    /// Typed snapshot ready for a caller to persist; this module never opens a database.
    #[cfg(unix)]
    pub(crate) fn checkpoint(&self) -> Option<(&str, u64)> {
        self.identity
            .as_ref()
            .map(|identity| (identity.fingerprint(), self.acknowledged_offset()))
    }

    pub(crate) fn phase(&self) -> FilePhase {
        self.phase
    }

    pub(crate) fn acknowledged_offset(&self) -> u64 {
        self.file.acknowledged_offset()
    }

    /// Poll one record. A data-less poll keeps the current phase unless an
    /// initial scan had bytes to read and has now reached EOF (including an
    /// incomplete final line). An initially empty file does not start a scan.
    pub(crate) fn poll_one(&mut self, observed_at: i64) -> Result<Option<QueuedLine>> {
        let Some(line) = self
            .file
            .next_record()
            .map_err(|err| Error::io("reading preselected queued log fixture", err))?
        else {
            if self.saw_complete_record || self.file.has_partial_record() {
                self.phase = FilePhase::Live;
            }
            return Ok(None);
        };
        let end_offset = line.end_offset;
        let queued = self.jail.observe(line.text, observed_at, self.phase)?;
        self.file
            .acknowledge(end_offset)
            .map_err(|err| Error::io("acknowledging queued log fixture offset", err))?;
        self.saw_complete_record = true;
        Ok(Some(QueuedLine {
            end_offset,
            queued,
            phase: self.phase,
        }))
    }

    pub(crate) fn tick(&mut self, now: i64) -> Result<Vec<ReplayDecision>> {
        self.jail.tick(now)
    }

    pub(crate) fn cleanup_failures(&mut self, now: i64) -> Result<usize> {
        self.jail.cleanup_failures(now)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;

    use super::*;

    const T0: i64 = 1_752_537_600;
    const BODY: &str = "2025/07/15 00:00:00 user \"fixture\" failed, client:";
    const ENDING: &str = " 192.0.2.20\r\n";

    fn plan() -> JailPlan {
        let config = tempfile::tempdir().expect("fixture config root");
        fs::create_dir(config.path().join("filter.d")).expect("fixture filter directory");
        fs::write(
            config.path().join("jail.conf"),
            "[fixture]\nenabled=true\nbackend=polling\nusedns=no\nignoreself=false\n\
             logtimezone=UTC\nlogpath=/offline/fixture.log\nfilter=nginx-http-auth\n\
             maxretry=1\nfindtime=10s\nbantime=5s\naction=\n",
        )
        .expect("fixture jail");
        fs::write(
            config.path().join("filter.d/nginx-http-auth.conf"),
            r"
[Definition]
prefregex = ^\s*<F-CONTENT>.*</F-CONTENT>, client: <ADDR>$
failregex = ^user .+ failed$
datepattern = {^LN-BEG}
",
        )
        .expect("fixture filter");
        crate::config::legacy_jail_plan::read(config.path(), "fixture").expect("fixture plan")
    }

    fn attach(file: &tempfile::NamedTempFile, start: StartAt) -> QueuedFile {
        QueuedFile::new(plan(), file.reopen().expect("open fixture"), start)
            .expect("attach fixture")
    }

    #[test]
    fn initial_records_stay_initial_until_a_poll_observes_eof() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        write!(file, "{BODY}{ENDING}").expect("existing record");
        let mut replay = attach(&file, StartAt::Head);
        let end_offset = u64::try_from(BODY.len() + ENDING.len()).expect("record length");
        assert_eq!(
            replay.poll_one(T0 + 80).expect("poll initial record"),
            Some(QueuedLine {
                end_offset,
                queued: false, // Too old before reaching EOF.
                phase: FilePhase::Initial,
            })
        );
        assert_eq!(replay.phase(), FilePhase::Initial);
        assert_eq!(replay.poll_one(T0 + 80).expect("EOF"), None);
        assert_eq!(replay.phase(), FilePhase::Live);
        assert_eq!(replay.acknowledged_offset(), end_offset);

        write!(file, "{BODY}{ENDING}").expect("append the same timestamp");
        assert_eq!(
            replay.poll_one(T0 + 81).expect("poll live record"),
            Some(QueuedLine {
                end_offset: end_offset * 2,
                queued: true, // Live time correction makes this current.
                phase: FilePhase::Live,
            })
        );
        let ip = "192.0.2.20".parse().expect("fixture IP");
        assert_eq!(
            replay.tick(T0 + 82).expect("record the queued ban"),
            [ReplayDecision::Ban { ip, at: T0 + 82 }]
        );
        assert!(replay.tick(T0 + 86).expect("equal deadline").is_empty());
        assert_eq!(
            replay.tick(T0 + 87).expect("past deadline"),
            [ReplayDecision::Unban { ip, at: T0 + 87 }]
        );
    }

    #[test]
    fn empty_initial_poll_is_not_a_scan_but_partial_eof_transitions() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        let mut replay = attach(&file, StartAt::Head);
        assert_eq!(replay.poll_one(T0 + 79).expect("empty"), None);
        assert_eq!(replay.phase(), FilePhase::Initial);

        write!(file, "{BODY}").expect("unterminated bytes");
        assert_eq!(replay.poll_one(T0 + 80).expect("partial"), None);
        assert_eq!(replay.phase(), FilePhase::Live);
        assert_eq!(replay.acknowledged_offset(), 0);
        assert!(
            replay
                .tick(T0 + 80)
                .expect("partial queued nothing")
                .is_empty()
        );

        write!(file, "{ENDING}").expect("append terminator");
        let record = replay
            .poll_one(T0 + 81)
            .expect("poll completed bytes")
            .expect("completed record");
        assert!(record.queued);
        assert_eq!(record.phase, FilePhase::Live);
        assert_eq!(replay.acknowledged_offset(), record.end_offset);
    }

    #[test]
    fn tail_starts_live_while_resume_at_eof_stays_initial() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        let mut empty_tail = attach(&file, StartAt::Tail);
        assert_eq!(empty_tail.poll_one(T0 + 80).expect("empty tail"), None);
        assert_eq!(empty_tail.phase(), FilePhase::Live);

        write!(file, "{BODY}{ENDING}").expect("existing bytes");
        let end_offset = u64::try_from(BODY.len() + ENDING.len()).expect("record length");
        let mut resume = attach(&file, StartAt::Resume(end_offset));
        assert_eq!(resume.poll_one(T0 + 80).expect("resume at EOF"), None);
        assert_eq!(resume.phase(), FilePhase::Initial);
        assert_eq!(resume.acknowledged_offset(), end_offset);

        write!(file, "{BODY}{ENDING}").expect("append after resume");
        let record = resume
            .poll_one(T0 + 81)
            .expect("first resumed record")
            .expect("record");
        assert_eq!(record.phase, FilePhase::Initial);
        assert!(!record.queued);
        assert_eq!(record.end_offset, end_offset * 2);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_discards_old_partial_but_keeps_live_phase_and_queued_ticket() {
        let mut predecessor = tempfile::NamedTempFile::new().expect("predecessor");
        write!(predecessor, "{BODY}{ENDING}{BODY}").expect("first record and partial");
        let mut replay = QueuedFile::with_identity(
            plan(),
            predecessor.reopen().expect("open predecessor"),
            false,
            None,
            T0,
        )
        .expect("attach predecessor");
        assert!(
            replay
                .poll_one(T0)
                .expect("initial read")
                .expect("record")
                .queued
        );
        assert_eq!(replay.poll_one(T0).expect("partial EOF"), None);
        assert_eq!(replay.phase(), FilePhase::Live);

        let mut successor = tempfile::NamedTempFile::new().expect("successor");
        // Identical first record proves that inode replacement alone rewinds.
        write!(successor, "{BODY}{ENDING}").expect("replacement record");
        let result = replay
            .reopen(successor.reopen().expect("open successor"), T0 + 1)
            .expect("reopen successor");
        assert!(result.rotated);
        assert!(result.has_content);
        assert_eq!(replay.acknowledged_offset(), 0);
        assert_eq!(replay.phase(), FilePhase::Live);
        // The ticket produced before switching the handles must not disappear.
        let ip = "192.0.2.20".parse().expect("fixture IP");
        assert_eq!(
            replay.tick(T0 + 1).expect("drain prior ticket"),
            [ReplayDecision::Ban { ip, at: T0 + 1 }]
        );
        let record = replay
            .poll_one(T0 + 2)
            .expect("read replacement")
            .expect("record");
        assert_eq!(record.end_offset, (BODY.len() + ENDING.len()) as u64);
        assert_eq!(replay.poll_one(T0 + 2).expect("replacement EOF"), None);
    }

    #[cfg(unix)]
    #[test]
    fn tracked_attach_checks_resume_fingerprint_and_tail_precedence() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        write!(file, "{BODY}{ENDING}{BODY}{ENDING}").expect("fixture records");
        let length = (BODY.len() + ENDING.len()) as u64;
        let mut first = QueuedFile::with_identity(
            plan(),
            file.reopen().expect("open fixture"),
            false,
            None,
            T0,
        )
        .expect("initialize fixture");
        first.poll_one(T0).expect("read first persisted record");
        let (hash, first_offset) = first.checkpoint().expect("tracked checkpoint");
        assert!(!hash.is_empty());
        assert_eq!(first_offset, length);

        let mut resume = QueuedFile::with_identity(
            plan(),
            file.reopen().expect("open fixture"),
            false,
            Some((hash, length)),
            T0,
        )
        .expect("resume using stored hash");
        assert_eq!(resume.acknowledged_offset(), length);
        assert_eq!(
            resume
                .poll_one(T0)
                .expect("read resumed")
                .expect("record")
                .end_offset,
            length * 2
        );
        let incompatible = QueuedFile::with_identity(
            plan(),
            file.reopen().expect("open fixture"),
            false,
            Some(("different", length)),
            T0,
        )
        .expect("rewind using mismatched hash");
        assert_eq!(incompatible.acknowledged_offset(), 0);
        let tail = QueuedFile::with_identity(
            plan(),
            file.reopen().expect("open fixture"),
            true,
            Some((hash, length)),
            T0,
        )
        .expect("tail ignores checkpoint");
        assert_eq!(tail.acknowledged_offset(), length * 2);
        assert_eq!(tail.phase(), FilePhase::Live);
    }

    #[test]
    fn failed_observation_leaves_complete_record_unacknowledged() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        write!(file, "{BODY}{ENDING}").expect("initial record");
        let mut replay = attach(&file, StartAt::Head);
        assert_eq!(replay.cleanup_failures(T0 + 1).expect("replay clock"), 0);
        assert!(replay.poll_one(T0).is_err());
        assert_eq!(replay.acknowledged_offset(), 0);
        assert_eq!(replay.phase(), FilePhase::Initial);
        let record = replay
            .poll_one(T0 + 1)
            .expect("retry at an accepted time")
            .expect("same pending record");
        assert!(record.queued);
        assert_eq!(replay.acknowledged_offset(), record.end_offset);
    }
}
