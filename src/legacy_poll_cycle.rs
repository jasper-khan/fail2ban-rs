//! Caller-driven polling over already opened regular fixture descriptors.
//!
//! Admission, stat selection and file draining are distinct stages. Nothing
//! opens a configured path, starts a worker, or invokes an action.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::legacy_jail_plan::JailPlan;
use crate::detect::legacy_file_identity::Reopen;
use crate::detect::legacy_observation_time::FilePhase;
use crate::detect::legacy_poll_stamp::{PollSelection, PollStamp};
use crate::error::{Error, Result};
use crate::legacy_jail_replay::ReplayDecision;
use crate::legacy_queued_file::{QueuedFiles, QueuedLine};

// Exclusive per-source bound for fixture traces, not a backend limit.
// At this bound, the already acknowledged records remain consumed and
// the read is not retried.
const MAX_DRAINED_LINES_PER_SLOT: usize = 16_384;

pub(crate) struct PollInput {
    pub(crate) slot: usize,
    /// Caller supplies the timestamp; inode and length must agree with file.
    pub(crate) stamp: PollStamp,
    pub(crate) file: File,
}

pub(crate) struct PollSlot {
    pub(crate) slot: usize,
    /// None is a supplied synthetic ENOENT, not an omitted slot. An observed
    /// tuple includes its caller-selected descriptor, as with PollInput.
    pub(crate) sample: Option<(PollStamp, File)>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PollDrain {
    pub(crate) slot: usize,
    pub(crate) reopen: Reopen,
    pub(crate) lines: Vec<QueuedLine>,
    pub(crate) phase: FilePhase,
    pub(crate) offset: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PollIteration {
    pub(crate) selected: Vec<usize>,
    pub(crate) skipped: Vec<usize>,
    pub(crate) removed: Vec<usize>,
    pub(crate) drained: Vec<PollDrain>,
}

pub(crate) struct PollCycle {
    // Keep admitted plan order, not sorted labels or arrival order.
    labels: Vec<PathBuf>,
    accepted: PollSelection,
    files: QueuedFiles,
}

impl PollCycle {
    pub(crate) fn new(plan: JailPlan) -> Result<Self> {
        let labels = plan.log_paths.clone();
        let files = QueuedFiles::new(plan)?;
        Ok(Self {
            accepted: PollSelection::new(labels.len()),
            labels,
            files,
        })
    }

    /// Attach the initial descriptor for one configured slot; no path opens.
    pub(crate) fn attach(
        &mut self,
        slot: usize,
        file: File,
        tail: bool,
        saved: Option<(&str, u64)>,
        now: i64,
        initial_cutoff: Option<i64>,
    ) -> Result<()> {
        let label = label(&self.labels, slot)?;
        if !self.accepted.is_registered(slot) {
            return Err(removed_slot(slot));
        }
        self.files
            .attach_with_identity(label, file, tail, saved, now, initial_cutoff)
    }

    /// Same polling cycle with a successful stat sample for every slot.
    pub(crate) fn poll(
        &mut self,
        snapshot: Vec<PollInput>,
        observed_at: i64,
    ) -> Result<Vec<PollDrain>> {
        let sampled = snapshot
            .into_iter()
            .map(|PollInput { slot, stamp, file }| PollSlot {
                slot,
                sample: Some((stamp, file)),
            })
            .collect();
        self.poll_sampled(sampled, observed_at)
    }

    /// Validate a complete snapshot, then reopen/drain changed descriptors
    /// in plan order. Synthetic ENOENT never reads a source, updates its
    /// cursor/phase, or changes its previous stamp before eviction.
    ///
    /// A present sample (even unchanged) clears the per-source miss streak.
    /// The 51st consecutive missing sample drops that source's fixture
    /// descriptor and checkpoint. Future complete snapshots omit removed
    /// slots; reattachment after removal is outside this slice.
    ///
    /// Convenience projection of an active iteration's drained sources.
    pub(crate) fn poll_sampled(
        &mut self,
        snapshot: Vec<PollSlot>,
        observed_at: i64,
    ) -> Result<Vec<PollDrain>> {
        self.poll_sampled_trace(snapshot, observed_at)
            .map(|iteration| iteration.drained)
    }

    /// Run one explicit stat pass per submitted active iteration. It does
    /// not simulate repeated wait predicates, sleeps, or other stat errors.
    ///
    /// Callers supply chronological observation times and stable scratch
    /// handles. A malformed snapshot commits nothing. Once a complete
    /// snapshot is committed, a read/reopen error stops this poll; already
    /// acknowledged state and selected stamps remain committed. Successful
    /// iterations count toward periodic maintenance, even with missing slots.
    /// Static recoverable open errors and action scheduling remain separate.
    pub(crate) fn poll_sampled_trace(
        &mut self,
        snapshot: Vec<PollSlot>,
        observed_at: i64,
    ) -> Result<PollIteration> {
        if self.filter_idle() {
            return Err(Error::config(
                "queued replay filter is idle; resume before the next active poll",
            ));
        }
        for (index, label) in self.labels.iter().enumerate() {
            if self.accepted.is_registered(index) {
                self.files.phase(label)?;
            }
        }

        let mut stamps = Vec::with_capacity(snapshot.len());
        let mut candidates: Vec<Option<File>> = (0..self.labels.len()).map(|_| None).collect();
        for PollSlot { slot, sample } in snapshot {
            let candidate = candidates.get_mut(slot).ok_or_else(|| invalid_slot(slot))?;
            if !self.accepted.is_registered(slot) {
                return Err(removed_slot(slot));
            }
            let stamp = if let Some((stamp, file)) = sample {
                let metadata = file.metadata().map_err(|err| {
                    Error::io(
                        format!("checking preselected polling fixture slot {slot}"),
                        err,
                    )
                })?;
                if !metadata.is_file()
                    || metadata.ino() != stamp.inode
                    || metadata.len() != stamp.size
                {
                    return Err(Error::config(format!(
                        "polling snapshot must match a regular fixture descriptor at slot {slot}"
                    )));
                }
                *candidate = Some(file);
                Some(stamp)
            } else {
                None
            };
            stamps.push((slot, stamp));
        }

        self.files.validate_clock(observed_at)?;
        let files = &mut self.files;
        let selections = self
            .accepted
            .select_sampled_with_errors(&stamps, |_| files.note_stat_error())
            .map_err(|err| Error::config(err.to_string()))?;
        for &slot in &selections.removed {
            self.files.detach(label(&self.labels, slot)?)?;
        }
        let mut iteration = PollIteration {
            selected: selections.changed,
            removed: selections.removed,
            skipped: Vec::new(),
            drained: Vec::new(),
        };
        // The original completes the whole stat pass; the subsequent read
        // entry gate skips all selected files, even those selected before the
        // miss that tripped idle. Their new stamps are deliberately retained.
        if self.filter_idle() {
            iteration.skipped.clone_from(&iteration.selected);
            self.files.complete_active_poll(observed_at)?;
            return Ok(iteration);
        }
        iteration.drained.reserve(iteration.selected.len());
        for &slot in &iteration.selected {
            let label = label(&self.labels, slot)?;
            let candidate = candidates
                .get_mut(slot)
                .and_then(Option::take)
                .ok_or_else(|| Error::config(format!("missing validated polling handle {slot}")))?;
            let reopen = self.files.reopen(label, candidate, observed_at)?;
            let mut lines = Vec::new();
            loop {
                if lines.len() >= MAX_DRAINED_LINES_PER_SLOT {
                    return Err(Error::config(format!(
                        "polling drained record limit reached in fixture slot {slot}"
                    )));
                }
                let Some(record) = self.files.poll_one(label, observed_at)? else {
                    break;
                };
                lines.push(record);
            }
            iteration.drained.push(PollDrain {
                slot,
                reopen,
                lines,
                phase: self.files.phase(label)?,
                offset: self.files.acknowledged_offset(label)?,
            });
        }
        self.files.complete_active_poll(observed_at)?;
        Ok(iteration)
    }

    pub(crate) fn filter_idle(&self) -> bool {
        self.files.filter_idle()
    }

    #[cfg(test)]
    pub(crate) fn filter_errors(&self) -> u8 {
        self.files.filter_errors()
    }

    /// Advance the same loop tick without stat sampling or maintenance.
    pub(crate) fn idle_timeout(&mut self, now: i64) -> Result<()> {
        self.files.idle_timeout(now)
    }

    /// Clear only the file filter's idle flag. The action worker is separate.
    pub(crate) fn resume_filter(&mut self) {
        self.files.resume_filter();
    }

    pub(crate) fn phase(&self, slot: usize) -> Result<FilePhase> {
        self.files.phase(label(&self.labels, slot)?)
    }

    pub(crate) fn is_registered(&self, slot: usize) -> Result<bool> {
        label(&self.labels, slot)?;
        Ok(self.accepted.is_registered(slot))
    }

    /// None denotes a configured slot removed from this adapter.
    pub(crate) fn missing_streak(&self, slot: usize) -> Result<Option<u8>> {
        label(&self.labels, slot)?;
        Ok(self.accepted.missing_streak(slot))
    }

    pub(crate) fn acknowledged_offset(&self, slot: usize) -> Result<u64> {
        self.files.acknowledged_offset(label(&self.labels, slot)?)
    }

    pub(crate) fn checkpoint(&self, slot: usize) -> Result<Option<(&str, u64)>> {
        self.files.checkpoint(label(&self.labels, slot)?)
    }

    pub(crate) fn tick(&mut self, now: i64) -> Result<Vec<ReplayDecision>> {
        self.files.tick(now)
    }

    pub(crate) fn cleanup_failures(&mut self, now: i64) -> Result<usize> {
        self.files.cleanup_failures(now)
    }

    #[cfg(test)]
    pub(crate) fn maintenance_trace(&self) -> &[(i64, usize)] {
        self.files.maintenance_trace()
    }

    #[cfg(test)]
    pub(crate) fn maintenance_counts(&self) -> (u8, u8) {
        self.files.maintenance_counts()
    }

    #[cfg(test)]
    pub(crate) fn failure_retry(&self, ip: std::net::IpAddr) -> Option<u64> {
        self.files.failure_retry(ip)
    }
}

fn label(labels: &[PathBuf], slot: usize) -> Result<&Path> {
    labels
        .get(slot)
        .map(PathBuf::as_path)
        .ok_or_else(|| invalid_slot(slot))
}

fn invalid_slot(slot: usize) -> Error {
    Error::config(format!("unregistered polling snapshot slot {slot}"))
}

fn removed_slot(slot: usize) -> Error {
    Error::config(format!("removed polling snapshot slot {slot}"))
}

#[cfg(test)]
#[path = "legacy_poll_cycle_test.rs"]
mod tests;
