//! One-file original jail harness for an explicitly supplied fixture.
//!
//! Log paths from the INI plan are not opened here. The caller supplies a
//! pre-opened fixture handle; the cursor only reads that file. No daemon,
//! socket, real ban, subprocess or persistent writes occur.

use std::fs::File;

use crate::config::legacy_jail_plan::JailPlan;
use crate::detect::legacy_file_cursor::{LegacyFileCursor, StartAt};
use crate::detect::watcher::MAX_LINE_LEN;
use crate::error::{Error, Result};
use crate::legacy_jail_replay::{RecordedJail, ReplayDecision};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConsumedLine {
    pub(crate) end_offset: u64,
    pub(crate) decision: Option<ReplayDecision>,
}

pub(crate) struct JailFileReplay {
    file: LegacyFileCursor,
    jail: RecordedJail,
}

impl JailFileReplay {
    pub(crate) fn new(plan: JailPlan, file: File, start: StartAt) -> Result<Self> {
        if plan.log_paths.len() != 1 {
            return Err(Error::config(
                "legacy file replay requires one configured log",
            ));
        }
        let file = LegacyFileCursor::open(file, start, MAX_LINE_LEN)
            .map_err(|err| Error::io("opening preselected legacy log fixture", err))?;
        Ok(Self {
            file,
            jail: RecordedJail::new(plan),
        })
    }

    /// Consume and acknowledge a complete line only after semantic replay.
    /// Partial records and rejected timestamps retain the last good offset.
    pub(crate) fn poll_one(&mut self, observed_at: i64) -> Result<Option<ConsumedLine>> {
        let Some(line) = self
            .file
            .next_record()
            .map_err(|err| Error::io("reading preselected legacy log fixture", err))?
        else {
            return Ok(None);
        };
        let end_offset = line.end_offset;
        let decision = self.jail.feed_line(line.text, observed_at)?;
        self.file
            .acknowledge(end_offset)
            .map_err(|err| Error::io("acknowledging legacy log fixture offset", err))?;
        Ok(Some(ConsumedLine {
            end_offset,
            decision,
        }))
    }

    pub(crate) fn expire(&mut self, now: i64) -> Result<Vec<ReplayDecision>> {
        self.jail.expire(now)
    }

    /// Last accepted byte checkpoint; no persistent store is updated.
    pub(crate) fn acknowledged_offset(&self) -> u64 {
        self.file.acknowledged_offset()
    }
}

#[cfg(test)]
#[path = "legacy_jail_file_test.rs"]
mod tests;
