//! Isolated byte cursor for an already opened regular fixture file.
//!
//! This implements only the plain UTF-8 LF/CRLF log subset. It does not open
//! a configured path, watch/rotate files, infer inode/hash identity, seek by
//! time, or implement the original lossy/other-encoding handling. Resume
//! offsets are already authorized by the caller's fixture state.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartAt {
    Head,
    Tail,
    Resume(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingLine<'a> {
    pub(crate) text: &'a str,
    /// Raw end, including all bytes of the line terminator.
    pub(crate) end_offset: u64,
}

pub(crate) struct LegacyFileCursor {
    reader: BufReader<File>,
    acknowledged: u64,
    max_record_bytes: usize,
    record: Vec<u8>,
    complete_end: Option<u64>,
}

impl LegacyFileCursor {
    pub(crate) fn open(file: File, start: StartAt, max_record_bytes: usize) -> io::Result<Self> {
        Self::open_at(file, start, max_record_bytes, false)
    }

    /// A FileContainer may retain its numeric position beyond a temporarily
    /// empty/truncated file when its old fingerprint was unknown.
    #[cfg(unix)]
    pub(crate) fn reopen(file: File, offset: u64, max_record_bytes: usize) -> io::Result<Self> {
        Self::open_at(file, StartAt::Resume(offset), max_record_bytes, true)
    }

    fn open_at(
        mut file: File,
        start: StartAt,
        max_record_bytes: usize,
        allow_past_eof: bool,
    ) -> io::Result<Self> {
        if max_record_bytes == 0 {
            return Err(invalid_input("legacy fixture byte limit must be positive"));
        }
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid_input(
                "legacy fixture cursor requires a regular file",
            ));
        }
        let target = match start {
            StartAt::Head => SeekFrom::Start(0),
            StartAt::Tail => SeekFrom::End(0),
            StartAt::Resume(offset) if allow_past_eof || offset <= metadata.len() => {
                SeekFrom::Start(offset)
            }
            StartAt::Resume(_) => return Err(invalid_input("legacy fixture resume is beyond EOF")),
        };
        let acknowledged = file.seek(target)?;
        Ok(Self {
            reader: BufReader::new(file),
            acknowledged,
            max_record_bytes,
            record: Vec::new(),
            complete_end: None,
        })
    }

    pub(crate) fn acknowledged_offset(&self) -> u64 {
        self.acknowledged
    }

    /// After next_record returns Ok(None), distinguish a held partial line
    /// from EOF with no raw bytes buffered. This only inspects held data; it
    /// never reads the file or advances the acknowledged offset.
    pub(crate) fn has_partial_record(&self) -> bool {
        self.complete_end.is_none() && !self.record.is_empty()
    }

    /// Peek a complete record without advancing the committed offset. Until
    /// acknowledged, the same complete record is returned again. Partial
    /// bytes are held until a later call sees their LF terminator.
    pub(crate) fn next_record(&mut self) -> io::Result<Option<PendingLine<'_>>> {
        if self.complete_end.is_none() {
            self.read_until_complete()?;
        }
        self.pending()
    }

    /// The only offset accepted for acknowledgment is the current complete
    /// valid line's end. Invalid UTF-8 and oversized records fail closed.
    pub(crate) fn acknowledge(&mut self, end_offset: u64) -> io::Result<()> {
        let Some(line) = self.pending()? else {
            return Err(invalid_input(
                "no complete legacy fixture line to acknowledge",
            ));
        };
        if line.end_offset != end_offset {
            return Err(invalid_input(
                "legacy fixture acknowledgment does not match current line",
            ));
        }
        self.acknowledged = end_offset;
        self.record.clear();
        self.complete_end = None;
        Ok(())
    }

    fn read_until_complete(&mut self) -> io::Result<()> {
        loop {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Ok(());
            }
            let newline = available.iter().position(|&byte| byte == b'\n');
            let count = newline.map_or(available.len(), |index| index + 1);
            // The bound includes LF/CRLF and applies before allocating or
            // advancing past the unread bytes of an oversized record.
            if count > self.max_record_bytes.saturating_sub(self.record.len()) {
                return Err(invalid_data("legacy fixture line exceeds its byte limit"));
            }
            let chunk = available
                .get(..count)
                .ok_or_else(|| invalid_data("invalid legacy fixture read boundary"))?;
            self.record.extend_from_slice(chunk);
            self.reader.consume(count);
            if newline.is_some() {
                self.complete_end = u64::try_from(self.record.len())
                    .ok()
                    .and_then(|len| self.acknowledged.checked_add(len));
                if self.complete_end.is_none() {
                    return Err(invalid_data("legacy fixture offset overflow"));
                }
                return Ok(());
            }
        }
    }

    fn pending(&self) -> io::Result<Option<PendingLine<'_>>> {
        let Some(end_offset) = self.complete_end else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&self.record)
            .map_err(|_| invalid_data("legacy fixture line is not valid UTF-8"))?
            .trim_end_matches(['\r', '\n']);
        Ok(Some(PendingLine { text, end_offset }))
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn head_tracks_raw_offsets_and_requires_acknowledgment() {
        let mut fixture = tempfile::tempfile().unwrap();
        fixture.write_all("a\r\nβ\n\n".as_bytes()).unwrap();
        let mut cursor = LegacyFileCursor::open(fixture, StartAt::Head, 16).unwrap();
        for (text, end) in [("a", 3), ("β", 6), ("", 7)] {
            let previous = cursor.acknowledged_offset();
            let expected = Some(PendingLine {
                text,
                end_offset: end,
            });
            assert_eq!(cursor.next_record().unwrap(), expected);
            assert_eq!(cursor.acknowledged_offset(), previous);
            assert!(cursor.acknowledge(end + 1).is_err());
            assert_eq!(cursor.next_record().unwrap(), expected);
            cursor.acknowledge(end).unwrap();
            assert_eq!(cursor.acknowledged_offset(), end);
        }
        assert_eq!(cursor.next_record().unwrap(), None);
        assert!(cursor.acknowledge(7).is_err());
    }

    #[test]
    fn tail_reads_only_appends_and_holds_partial_lines() {
        let mut fixture = tempfile::NamedTempFile::new().unwrap();
        fixture.write_all(b"old\n").unwrap();
        let mut cursor =
            LegacyFileCursor::open(fixture.reopen().unwrap(), StartAt::Tail, 16).unwrap();
        assert_eq!(cursor.acknowledged_offset(), 4);
        assert_eq!(cursor.next_record().unwrap(), None);
        assert!(!cursor.has_partial_record());
        fixture.write_all(b"new").unwrap();
        assert_eq!(cursor.next_record().unwrap(), None);
        assert!(cursor.has_partial_record());
        assert_eq!(cursor.acknowledged_offset(), 4);
        assert_eq!(cursor.next_record().unwrap(), None);
        assert!(cursor.has_partial_record());
        assert_eq!(cursor.acknowledged_offset(), 4);
        fixture.write_all(b"\r\n").unwrap();
        let line = cursor.next_record().unwrap().unwrap();
        assert_eq!(line.text, "new");
        let end = line.end_offset;
        assert!(!cursor.has_partial_record());
        assert_eq!(cursor.acknowledged_offset(), 4);
        cursor.acknowledge(end).unwrap();
        assert_eq!(cursor.acknowledged_offset(), 9);
        assert_eq!(cursor.next_record().unwrap(), None);
        assert!(!cursor.has_partial_record());
    }

    #[test]
    fn resume_replays_delivered_but_unacknowledged_bytes() {
        let mut fixture = tempfile::NamedTempFile::new().unwrap();
        fixture.write_all(b"one\ntwo\n").unwrap();
        let mut first =
            LegacyFileCursor::open(fixture.reopen().unwrap(), StartAt::Head, 4).unwrap();
        let end = first.next_record().unwrap().unwrap().end_offset;
        first.acknowledge(end).unwrap();
        assert_eq!(first.next_record().unwrap().unwrap().text, "two");
        let checkpoint = first.acknowledged_offset();
        drop(first);
        let mut resumed =
            LegacyFileCursor::open(fixture.reopen().unwrap(), StartAt::Resume(checkpoint), 4)
                .unwrap();
        assert_eq!(resumed.next_record().unwrap().unwrap().text, "two");
        assert_eq!(resumed.acknowledged_offset(), 4);
    }

    #[test]
    fn malformed_and_oversized_lines_cannot_commit_or_skip() {
        for (bytes, max) in [(b"wide\nabc\n".as_slice(), 4), (b"\xff\na\n", 4)] {
            let mut fixture = tempfile::tempfile().unwrap();
            fixture.write_all(bytes).unwrap();
            let mut cursor = LegacyFileCursor::open(fixture, StartAt::Head, max).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    cursor.next_record().unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(cursor.acknowledged_offset(), 0);
            }
            assert!(cursor.acknowledge(2).is_err());
        }
    }

    #[test]
    fn rejects_out_of_range_resume_and_non_regular_file() {
        let empty = tempfile::tempfile().unwrap();
        assert!(LegacyFileCursor::open(empty, StartAt::Resume(1), 1).is_err());
        let empty = tempfile::tempfile().unwrap();
        assert!(LegacyFileCursor::open(empty, StartAt::Head, 0).is_err());
        #[cfg(unix)]
        {
            let directory = tempfile::tempdir().unwrap();
            let fd = File::open(directory.path()).unwrap();
            assert!(LegacyFileCursor::open(fd, StartAt::Head, 8).is_err());
        }
    }
}
