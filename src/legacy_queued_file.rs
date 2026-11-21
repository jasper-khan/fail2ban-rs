//! Offline adapter from already-opened fixture files to one queued jail.
//!
//! Only complete records advance the acknowledged byte offset, and only
//! after successful observation. The caller supplies every clock and action
//! tick. This never opens configuration paths or runs an action, watcher,
//! worker thread, or service.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::path::Path;

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

struct SourceState {
    file: LegacyFileCursor,
    phase: FilePhase,
    scan_had_content: bool,
    #[cfg(unix)]
    identity: Option<FileIdentityState>,
    #[cfg(unix)]
    initial_nginx_cutoff: Option<i64>,
}

impl SourceState {
    fn new(file: File, start: StartAt) -> Result<Self> {
        let cursor = LegacyFileCursor::open(file, start, MAX_LINE_LEN)
            .map_err(|err| Error::io("opening preselected queued log fixture", err))?;
        Ok(Self::from_cursor(cursor, start))
    }

    fn from_cursor(file: LegacyFileCursor, start: StartAt) -> Self {
        Self {
            file,
            phase: if start == StartAt::Tail {
                FilePhase::Live
            } else {
                FilePhase::Initial
            },
            scan_had_content: false,
            #[cfg(unix)]
            identity: None,
            #[cfg(unix)]
            initial_nginx_cutoff: None,
        }
    }

    /// Scope: fixed-width UTC Nginx fixture lines only. The caller resolves
    /// the cutoff (for example, now minus findtime). It is consumed once on
    /// first poll, even on an empty file, and ignored in tail mode.
    #[cfg(unix)]
    fn with_identity_and_initial_seek(
        file: File,
        tail: bool,
        saved: Option<(&str, u64)>,
        now: i64,
        initial_nginx_cutoff: Option<i64>,
    ) -> Result<Self> {
        let mut identity = FileIdentityState::initialize(&file, now, MAX_LINE_LEN)
            .map_err(|err| Error::io("identifying preselected queued log fixture", err))?;
        let mut tracked = if tail {
            Self::new(file, StartAt::Tail)?
        } else {
            let saved_offset = saved
                .and_then(|(hash, offset)| identity.resume_offset(hash, offset, false))
                .unwrap_or_default();
            let position = identity
                .reopen(&file, saved_offset, now)
                .map_err(|err| Error::io("validating queued log fixture checkpoint", err))?;
            Self::from_cursor(
                LegacyFileCursor::reopen(file, position.offset, MAX_LINE_LEN)
                    .map_err(|err| Error::io("opening preselected queued log fixture", err))?,
                StartAt::Head,
            )
        };
        tracked.identity = Some(identity);
        if !tail {
            tracked.initial_nginx_cutoff = initial_nginx_cutoff.filter(|&cutoff| cutoff != 0);
        }
        Ok(tracked)
    }

    /// Switch to a fresh caller-supplied handle at the legacy resume offset.
    /// Rotation changes the byte stream, not the jail, ban queue, or phase.
    /// Drop old buffered bytes only after the new handle succeeds.
    #[cfg(unix)]
    fn reopen(&mut self, file: File, now: i64) -> Result<Reopen> {
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
        self.scan_had_content = false;
        Ok(position)
    }

    /// Typed snapshot ready for a caller to persist; this module never opens a database.
    #[cfg(unix)]
    fn checkpoint(&self) -> Option<(&str, u64)> {
        self.identity
            .as_ref()
            .map(|identity| (identity.fingerprint(), self.acknowledged_offset()))
    }

    fn acknowledged_offset(&self) -> u64 {
        self.file.acknowledged_offset()
    }

    /// Poll one record. A data-less poll keeps the current phase unless an
    /// initial scan had bytes to read and has now reached EOF (including an
    /// incomplete final line). An initially empty file does not start a scan.
    fn poll_one(&mut self, jail: &mut QueuedJail, observed_at: i64) -> Result<Option<QueuedLine>> {
        #[cfg(unix)]
        if let Some(cutoff) = self.initial_nginx_cutoff.take() {
            self.scan_had_content = self
                .file
                .seek_initial_nginx(cutoff)
                .map_err(|err| Error::io("seeking initial queued log fixture by time", err))?;
        }
        let Some(line) = self
            .file
            .next_record()
            .map_err(|err| Error::io("reading preselected queued log fixture", err))?
        else {
            if self.scan_had_content || self.file.has_partial_record() {
                self.phase = FilePhase::Live;
            }
            return Ok(None);
        };
        let end_offset = line.end_offset;
        let queued = jail.observe(line.text, observed_at, self.phase)?;
        self.file
            .acknowledge(end_offset)
            .map_err(|err| Error::io("acknowledging queued log fixture offset", err))?;
        self.scan_had_content = true;
        Ok(Some(QueuedLine {
            end_offset,
            queued,
            phase: self.phase,
        }))
    }
}

/// Single-fixture compatibility wrapper.
pub(crate) struct QueuedFile {
    source: SourceState,
    jail: QueuedJail,
}

impl QueuedFile {
    pub(crate) fn new(plan: JailPlan, file: File, start: StartAt) -> Result<Self> {
        Self::check_plan(&plan)?;
        Ok(Self {
            source: SourceState::new(file, start)?,
            jail: QueuedJail::new(plan)?,
        })
    }

    fn check_plan(plan: &JailPlan) -> Result<()> {
        if plan.log_paths.len() != 1 {
            return Err(Error::config(
                "legacy queued file requires one configured log",
            ));
        }
        Ok(())
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
        Self::with_identity_and_initial_seek(plan, file, tail, saved, now, None)
    }

    #[cfg(unix)]
    pub(crate) fn with_identity_and_initial_seek(
        plan: JailPlan,
        file: File,
        tail: bool,
        saved: Option<(&str, u64)>,
        now: i64,
        initial_nginx_cutoff: Option<i64>,
    ) -> Result<Self> {
        Self::check_plan(&plan)?;
        Ok(Self {
            source: SourceState::with_identity_and_initial_seek(
                file,
                tail,
                saved,
                now,
                initial_nginx_cutoff,
            )?,
            jail: QueuedJail::new(plan)?,
        })
    }

    #[cfg(unix)]
    pub(crate) fn reopen(&mut self, file: File, now: i64) -> Result<Reopen> {
        self.source.reopen(file, now)
    }

    #[cfg(unix)]
    pub(crate) fn checkpoint(&self) -> Option<(&str, u64)> {
        self.source.checkpoint()
    }

    pub(crate) fn phase(&self) -> FilePhase {
        self.source.phase
    }

    pub(crate) fn acknowledged_offset(&self) -> u64 {
        self.source.acknowledged_offset()
    }

    pub(crate) fn poll_one(&mut self, observed_at: i64) -> Result<Option<QueuedLine>> {
        self.source.poll_one(&mut self.jail, observed_at)
    }

    pub(crate) fn tick(&mut self, now: i64) -> Result<Vec<ReplayDecision>> {
        self.jail.tick(now)
    }

    pub(crate) fn cleanup_failures(&mut self, now: i64) -> Result<usize> {
        self.jail.cleanup_failures(now)
    }
}

/// Multiple configured source labels share the original filter history,
/// failure counters, and action queue, but not their cursors or file phase.
/// Source labels are admitted configuration metadata, not filesystem paths
/// to open. The caller supplies every descriptor and selects poll order.
pub(crate) struct QueuedFiles {
    sources: BTreeMap<OsString, Option<SourceState>>,
    jail: QueuedJail,
}

impl QueuedFiles {
    pub(crate) fn new(plan: JailPlan) -> Result<Self> {
        let sources = plan
            .log_paths
            .iter()
            .map(|label| (label.as_os_str().to_owned(), None))
            .collect::<BTreeMap<_, _>>();
        if sources.is_empty() || sources.len() != plan.log_paths.len() {
            return Err(Error::config(
                "legacy queued sources require unique configured labels",
            ));
        }
        Ok(Self {
            sources,
            jail: QueuedJail::new(plan)?,
        })
    }

    pub(crate) fn attach(&mut self, label: &Path, file: File, start: StartAt) -> Result<()> {
        let slot = self.attachment_slot(label)?;
        *slot = Some(SourceState::new(file, start)?);
        Ok(())
    }

    /// Drop a fixture descriptor and its in-memory checkpoint. This never
    /// renames, truncates, removes, or opens a configured path.
    pub(crate) fn detach(&mut self, label: &Path) -> Result<()> {
        let slot = get_slot(self.sources.get_mut(label.as_os_str()), label)?;
        slot.take().map(|_| ()).ok_or_else(|| unattached(label))
    }

    #[cfg(unix)]
    pub(crate) fn attach_with_identity(
        &mut self,
        label: &Path,
        file: File,
        tail: bool,
        saved: Option<(&str, u64)>,
        now: i64,
        initial_nginx_cutoff: Option<i64>,
    ) -> Result<()> {
        let slot = self.attachment_slot(label)?;
        *slot = Some(SourceState::with_identity_and_initial_seek(
            file,
            tail,
            saved,
            now,
            initial_nginx_cutoff,
        )?);
        Ok(())
    }

    pub(crate) fn poll_one(
        &mut self,
        label: &Path,
        observed_at: i64,
    ) -> Result<Option<QueuedLine>> {
        let source = get_slot(self.sources.get_mut(label.as_os_str()), label)?
            .as_mut()
            .ok_or_else(|| unattached(label))?;
        source.poll_one(&mut self.jail, observed_at)
    }

    pub(crate) fn phase(&self, label: &Path) -> Result<FilePhase> {
        Ok(self.source(label)?.phase)
    }

    pub(crate) fn acknowledged_offset(&self, label: &Path) -> Result<u64> {
        Ok(self.source(label)?.acknowledged_offset())
    }

    #[cfg(unix)]
    pub(crate) fn checkpoint(&self, label: &Path) -> Result<Option<(&str, u64)>> {
        Ok(self.source(label)?.checkpoint())
    }

    #[cfg(unix)]
    pub(crate) fn reopen(&mut self, label: &Path, file: File, now: i64) -> Result<Reopen> {
        let source = get_slot(self.sources.get_mut(label.as_os_str()), label)?
            .as_mut()
            .ok_or_else(|| unattached(label))?;
        source.reopen(file, now)
    }

    pub(crate) fn tick(&mut self, now: i64) -> Result<Vec<ReplayDecision>> {
        self.jail.tick(now)
    }

    pub(crate) fn cleanup_failures(&mut self, now: i64) -> Result<usize> {
        self.jail.cleanup_failures(now)
    }

    pub(crate) fn validate_clock(&self, now: i64) -> Result<()> {
        self.jail.validate_clock(now)
    }

    pub(crate) fn complete_active_poll(&mut self, now: i64) -> Result<()> {
        self.jail.complete_active_poll(now)
    }

    pub(crate) fn note_stat_error(&mut self) {
        self.jail.note_stat_error();
    }

    pub(crate) fn filter_idle(&self) -> bool {
        self.jail.filter_idle()
    }

    #[cfg(test)]
    pub(crate) fn filter_errors(&self) -> u8 {
        self.jail.filter_errors()
    }

    pub(crate) fn idle_timeout(&mut self, now: i64) -> Result<()> {
        self.jail.idle_timeout(now)
    }

    pub(crate) fn resume_filter(&mut self) {
        self.jail.resume_filter();
    }

    #[cfg(test)]
    pub(crate) fn maintenance_trace(&self) -> &[(i64, usize)] {
        self.jail.maintenance_trace()
    }

    #[cfg(test)]
    pub(crate) fn maintenance_counts(&self) -> (u8, u8) {
        self.jail.maintenance_counts()
    }

    #[cfg(test)]
    pub(crate) fn failure_retry(&self, ip: std::net::IpAddr) -> Option<u64> {
        self.jail.failure_retry(ip)
    }

    fn source(&self, label: &Path) -> Result<&SourceState> {
        get_slot(self.sources.get(label.as_os_str()), label)?
            .as_ref()
            .ok_or_else(|| unattached(label))
    }

    fn attachment_slot(&mut self, label: &Path) -> Result<&mut Option<SourceState>> {
        let slot = get_slot(self.sources.get_mut(label.as_os_str()), label)?;
        if slot.is_some() {
            return Err(Error::config(format!(
                "queued log fixture already attached: {}",
                label.to_string_lossy().escape_debug()
            )));
        }
        Ok(slot)
    }
}

fn get_slot<T>(slot: Option<T>, label: &Path) -> Result<T> {
    slot.ok_or_else(|| {
        Error::config(format!(
            "unknown configured queued log label: {}",
            label.to_string_lossy().escape_debug()
        ))
    })
}

fn unattached(label: &Path) -> Error {
    Error::config(format!(
        "queued log fixture not attached: {}",
        label.to_string_lossy().escape_debug()
    ))
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

    #[cfg(unix)]
    #[test]
    fn initial_seek_persists_offset_but_the_actual_poll_controls_live_phase() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        write!(file, "{BODY}{ENDING}").expect("old record");
        let mut replay = QueuedFile::with_identity_and_initial_seek(
            plan(),
            file.reopen().expect("open fixture"),
            false,
            None,
            T0 + 3,
            Some(T0 + 1),
        )
        .expect("attach with initial start time");
        assert_eq!(replay.acknowledged_offset(), 0);
        assert_eq!(replay.phase(), FilePhase::Initial);
        assert_eq!(replay.poll_one(T0 + 3).expect("skip old record"), None);
        assert_eq!(replay.phase(), FilePhase::Live);
        assert_eq!(
            replay.acknowledged_offset(),
            (BODY.len() + ENDING.len()) as u64
        );
        assert!(
            replay
                .tick(T0 + 3)
                .expect("scan created no ticket")
                .is_empty()
        );

        let mut next = tempfile::NamedTempFile::new().expect("fixture replacement");
        write!(next, "{BODY}{ENDING}").expect("replacement record with prior date");
        assert!(
            replay
                .reopen(next.reopen().expect("open replacement"), T0 + 4)
                .expect("reopen replacement")
                .rotated
        );
        assert!(
            replay
                .poll_one(T0 + 4)
                .expect("read without second seek")
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_initial_seek_is_consumed_and_tail_does_not_seek() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        let mut replay = QueuedFile::with_identity_and_initial_seek(
            plan(),
            file.reopen().expect("open fixture"),
            false,
            None,
            T0 + 3,
            Some(T0 + 10),
        )
        .expect("attach empty fixture");
        assert_eq!(
            replay.poll_one(T0 + 3).expect("no content at first poll"),
            None
        );
        assert_eq!(replay.phase(), FilePhase::Initial);

        write!(file, "{BODY}{ENDING}").expect("append first old record");
        assert!(
            replay
                .poll_one(T0 + 4)
                .expect("one-shot seek consumed")
                .is_some()
        );

        let mut tail = QueuedFile::with_identity_and_initial_seek(
            plan(),
            file.reopen().expect("open fixture"),
            true,
            Some(("", 2)),
            T0 + 4,
            Some(T0 + 10),
        )
        .expect("tail ignores seek and checkpoint");
        assert_eq!(tail.phase(), FilePhase::Live);
        assert_eq!(
            tail.acknowledged_offset(),
            (BODY.len() + ENDING.len()) as u64
        );
        write!(file, "{BODY}{ENDING}").expect("append old record after tail");
        assert!(
            tail.poll_one(T0 + 5)
                .expect("read despite cutoff")
                .is_some()
        );
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

    const A: &str = "/offline/fixture.log";
    const B: &str = "/offline/second.log";

    fn multi_plan() -> JailPlan {
        let mut plan = plan();
        plan.log_paths.push(B.into());
        plan.max_retry = 2;
        plan
    }

    #[test]
    fn multiple_files_share_failures_but_not_offsets_or_eof_phase() {
        let a = Path::new(A);
        let b = Path::new(B);
        let mut first = tempfile::NamedTempFile::new().expect("first source");
        write!(first, "{BODY}{ENDING}").expect("first record");
        let mut second = tempfile::NamedTempFile::new().expect("second source");
        write!(second, "{BODY}").expect("second partial record");
        let mut replay = QueuedFiles::new(multi_plan()).expect("configured fixtures");
        replay
            .attach(a, first.reopen().expect("open first"), StartAt::Head)
            .expect("attach first");
        replay
            .attach(b, second.reopen().expect("open second"), StartAt::Head)
            .expect("attach second");

        let from_a = replay.poll_one(a, T0).expect("poll first").expect("record");
        assert!(!from_a.queued);
        assert_eq!(from_a.phase, FilePhase::Initial);
        assert_eq!(replay.poll_one(b, T0).expect("poll incomplete"), None);
        assert_eq!(
            replay.phase(a).expect("phase for first"),
            FilePhase::Initial
        );
        assert_eq!(replay.phase(b).expect("phase for second"), FilePhase::Live);
        assert_eq!(replay.acknowledged_offset(b).expect("second offset"), 0);

        write!(second, "{ENDING}").expect("complete second record");
        let from_b = replay
            .poll_one(b, T0)
            .expect("poll second")
            .expect("record");
        assert!(from_b.queued);
        assert_eq!(from_b.phase, FilePhase::Live);
        assert_eq!(
            replay.acknowledged_offset(a).expect("first offset"),
            from_a.end_offset
        );
        assert_eq!(
            replay.cleanup_failures(T0).expect("empty pending tracker"),
            0
        );
        let ip = "192.0.2.20".parse().expect("fixture address");
        assert_eq!(
            replay.tick(T0).expect("drain shared queue"),
            [ReplayDecision::Ban { ip, at: T0 }]
        );
    }

    #[test]
    fn rejects_unknown_duplicate_or_unattached_labels_without_replacing_a_source() {
        let mut file = tempfile::NamedTempFile::new().expect("fixture");
        write!(file, "{BODY}{ENDING}").expect("first record");
        let a = Path::new(A);
        let b = Path::new(B);
        let mut replay = QueuedFiles::new(multi_plan()).expect("configured fixtures");
        assert!(replay.poll_one(b, T0).is_err(), "configured but unattached");
        let equivalent_spelling = Path::new("/offline//fixture.log");
        assert!(
            replay
                .attach(
                    equivalent_spelling,
                    file.reopen().expect("open fixture"),
                    StartAt::Head
                )
                .is_err(),
            "label spelling must be the exact admitted value"
        );
        replay
            .attach(a, file.reopen().expect("open first"), StartAt::Head)
            .expect("attach A");
        assert!(
            replay
                .attach(a, file.reopen().expect("open candidate"), StartAt::Tail)
                .is_err(),
            "duplicate attachment cannot replace the existing handler"
        );
        assert_eq!(replay.acknowledged_offset(a).expect("original offset"), 0);
        assert!(replay.poll_one(a, T0).expect("original read").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn reopening_one_source_keeps_the_other_checkpoint_and_the_shared_queue() {
        let a = Path::new(A);
        let b = Path::new(B);
        let mut first = tempfile::NamedTempFile::new().expect("first fixture");
        write!(first, "{BODY}{ENDING}").expect("first record");
        let mut second = tempfile::NamedTempFile::new().expect("second fixture");
        write!(second, "{BODY}{ENDING}").expect("second record");
        let mut replay = QueuedFiles::new(multi_plan()).expect("configured fixtures");
        for (label, file) in [(a, &first), (b, &second)] {
            replay
                .attach_with_identity(
                    label,
                    file.reopen().expect("open fixture"),
                    false,
                    None,
                    T0,
                    None,
                )
                .expect("attach tracked fixture");
            assert!(
                replay
                    .poll_one(label, T0)
                    .expect("read one record")
                    .is_some()
            );
        }
        assert_eq!(replay.poll_one(a, T0).expect("first EOF"), None);
        let (hash, offset) = replay
            .checkpoint(b)
            .expect("second label")
            .expect("second checkpoint");
        let saved = (hash.to_owned(), offset);

        let mut successor = tempfile::NamedTempFile::new().expect("replacement");
        write!(successor, "{BODY}{ENDING}").expect("replacement record");
        let position = replay
            .reopen(a, successor.reopen().expect("open replacement"), T0 + 1)
            .expect("reopen first label");
        assert!(position.rotated);
        assert_eq!(replay.phase(a).expect("first still live"), FilePhase::Live);
        assert_eq!(
            replay
                .acknowledged_offset(a)
                .expect("rotation resets first"),
            0
        );
        assert_eq!(
            replay.phase(b).expect("second still initial"),
            FilePhase::Initial
        );
        assert_eq!(
            replay.checkpoint(b).expect("second label"),
            Some((saved.0.as_str(), saved.1))
        );
        let ip = "192.0.2.20".parse().expect("fixture address");
        assert_eq!(
            replay
                .tick(T0 + 1)
                .expect("shared ticket survived rotation"),
            [ReplayDecision::Ban { ip, at: T0 + 1 }]
        );
    }
}
