//! Bounded positional seek for an original Fail2Ban 1.1.1 Nginx fixture.
//!
//! The caller owns the regular file and supplies a resolved resume position
//! and UTC cutoff. Probes never consume a cursor line, change the descriptor
//! position, observe a timestamp for the jail, or open a configured path.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use super::legacy_date::split_nginx_ln_begin;

const LOOKAHEAD_RECORDS: usize = 6;
const ACCURACY: usize = 3;
const MAX_PROBES: usize = 128;
const MAX_PROBE_BYTES: usize = 16 * 1024 * 1024;

/// Return the original seek's final lower byte bound for the supported
/// fixed-width, whole-second UTC date grammar. An undated suffix can remain
/// at the selected position. A dated terminal fragment may affect the
/// position but is not an observed/acknowledged record.
pub(crate) fn seek_nginx_offset(
    file: &File,
    resume: u64,
    cutoff: i64,
    max_record_bytes: usize,
) -> io::Result<u64> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || max_record_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legacy time seek requires a regular file and positive record limit",
        ));
    }
    let mut high = metadata.len();
    if resume > high {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legacy time seek resume is beyond EOF",
        ));
    }
    let mut reader = ProbeReader {
        file,
        size: high,
        max_record_bytes,
        remaining_bytes: MAX_PROBE_BYTES,
    };
    let mut line = Vec::new();
    let mut low = resume;
    let mut forced_probe = Some(resume);
    let mut previous_position = None;
    let mut stall_budget = ACCURACY;
    for _ in 0..MAX_PROBES {
        if high <= low {
            return Ok(low);
        }
        let center = forced_probe.take().unwrap_or(low + (high - low) / 2);
        let probe = reader.probe(center.saturating_sub(2), high, &mut line)?;
        let mut position = probe.position;
        if let Some((date, next)) = probe.found {
            if date < cutoff {
                position = next;
                low = low.max(position);
            } else {
                if position == high {
                    position = probe.aligned;
                }
                high = high.min(position);
            }
        }
        if previous_position == Some(position) {
            stall_budget -= 1;
            if stall_budget == 0 || low == position {
                return Ok(low);
            }
            // At an uninformative midpoint, retry the exact lower bound.
            previous_position = Some(low);
            forced_probe = Some(low);
        } else {
            previous_position = Some(position);
        }
    }
    Err(invalid_data("legacy time seek exceeded its probe limit"))
}

struct Probe {
    aligned: u64,
    position: u64,
    /// Parsed timestamp and the candidate for advancing the lower bound.
    found: Option<(i64, u64)>,
}

struct ProbeReader<'a> {
    file: &'a File,
    size: u64,
    max_record_bytes: usize,
    remaining_bytes: usize,
}

impl ProbeReader<'_> {
    fn probe(&mut self, start: u64, upper: u64, line: &mut Vec<u8>) -> io::Result<Probe> {
        let aligned = if start == 0 {
            0
        } else {
            // A raw nonzero seek discards through the next LF even when
            // already aligned. Its discarded bytes need not be valid UTF-8.
            self.raw_record(start, line)?.unwrap_or(start)
        };
        let mut read_at = aligned;
        let mut position = aligned;
        let mut next_undated = None;
        for _ in 0..LOOKAHEAD_RECORDS {
            let Some(end) = self.raw_record(read_at, line)? else {
                break;
            };
            read_at = end;
            let text = std::str::from_utf8(line)
                .map_err(|_| invalid_data("legacy time seek record is not valid UTF-8"))?
                .trim_end_matches(['\r', '\n']);
            if let Some(date) = split_nginx_ln_begin(text) {
                if let Some(time) = date.unix_seconds {
                    return Ok(Probe {
                        aligned,
                        position,
                        found: Some((time, next_undated.unwrap_or(end))),
                    });
                }
                // A matched but invalid date does not advance the
                // position marker, unlike an entirely undated line.
            } else {
                if end > upper {
                    position = aligned;
                    break;
                }
                next_undated = Some(end);
                position = end;
            }
        }
        Ok(Probe {
            aligned,
            position,
            found: None,
        })
    }

    fn raw_record(&mut self, start: u64, record: &mut Vec<u8>) -> io::Result<Option<u64>> {
        record.clear();
        if start >= self.size {
            return Ok(None);
        }
        let mut cursor = start;
        let mut buffer = [0; 4096];
        while cursor < self.size {
            let remaining_record = self.max_record_bytes.saturating_sub(record.len());
            let remaining_file = usize::try_from(self.size - cursor).unwrap_or(usize::MAX);
            let capacity = buffer
                .len()
                .min(remaining_record.saturating_add(1))
                .min(remaining_file)
                .min(self.remaining_bytes);
            if capacity == 0 {
                return Err(invalid_data("legacy time seek exceeded its byte budget"));
            }
            let chunk = buffer
                .get_mut(..capacity)
                .ok_or_else(|| invalid_data("invalid legacy time seek read boundary"))?;
            let read = loop {
                match self.file.read_at(chunk, cursor) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    result => break result?,
                }
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "legacy time seek fixture shrank while probing",
                ));
            }
            self.remaining_bytes -= read;
            let bytes = chunk
                .get(..read)
                .ok_or_else(|| invalid_data("invalid legacy time seek record boundary"))?;
            let newline = bytes.iter().position(|&byte| byte == b'\n');
            let keep = newline.map_or(read, |index| index + 1);
            if keep > remaining_record {
                return Err(invalid_data(
                    "legacy time seek record exceeds its byte limit",
                ));
            }
            let bytes = bytes
                .get(..keep)
                .ok_or_else(|| invalid_data("invalid legacy time seek record length"))?;
            record.extend_from_slice(bytes);
            let advance = u64::try_from(keep)
                .map_err(|_| invalid_data("legacy time seek offset overflow"))?;
            cursor = cursor
                .checked_add(advance)
                .ok_or_else(|| invalid_data("legacy time seek offset overflow"))?;
            if newline.is_some() {
                break;
            }
        }
        Ok(Some(cursor))
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write as _};

    use super::*;

    const BASE: i64 = 1_752_537_600;
    const MAX_RECORD: usize = 4_096;

    fn fixture(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().expect("scratch fixture");
        file.write_all(bytes).expect("write fixture");
        file
    }

    fn selected(file: &File, resume: u64, second: i64) -> u64 {
        seek_nginx_offset(file, resume, BASE + second, MAX_RECORD).expect("fixture seek")
    }

    #[test]
    fn cutoff_and_resume_preserve_original_byte_boundaries() {
        let mut file = fixture(
            concat!(
                "2025/07/15 00:00:00 a\r\n",
                "2025/07/15 00:00:02 é previous\n",
                "2025/07/15 00:00:04 same one\r\n",
                "2025/07/15 00:00:04 same two longer\n",
                "2025/07/15 00:00:05 after\n",
            )
            .as_bytes(),
        );
        file.seek(SeekFrom::Start(4)).expect("independent position");
        for (resume, cutoff, expected) in [
            (0, -1, 0),
            (0, 4, 55),
            (0, 9, 147),
            (23, 4, 55),
            (85, 4, 85),
            (14, 4, 55),
            (147, 4, 147),
        ] {
            assert_eq!(selected(&file, resume, cutoff), expected);
            assert_eq!(file.stream_position().expect("unchanged position"), 4);
        }
    }

    #[test]
    fn empty_undated_and_partial_records_match_original_probe_behavior() {
        let empty = fixture(b"");
        assert_eq!(selected(&empty, 0, 0), 0);
        let undated = fixture(b"undated\nundated\nundated\nundated\nundated\nundated\nundated\n");
        assert_eq!(selected(&undated, 0, 4), 0);
        let partial = fixture(b"2025/07/15 00:00:00 old\n2025/07/15 00:00:02 partial");
        assert_eq!(selected(&partial, 0, 4), 51);
        assert_eq!(selected(&partial, 0, 2), 24);
        let mut sparse = b"2025/07/15 00:00:00 old\n".to_vec();
        sparse.extend_from_slice(&b"undated\n".repeat(12));
        sparse.extend_from_slice(b"2025/07/15 00:00:05 future\n");
        assert_eq!(selected(&fixture(&sparse), 0, 2), 24);
    }

    #[test]
    fn larger_ordered_fixture_seeks_to_the_first_equal_cutoff() {
        let mut bytes = Vec::new();
        for offset in 0..1024 {
            writeln!(
                bytes,
                "2025/07/15 00:{:02}:{:02} synthetic row",
                offset / 60,
                offset % 60
            )
            .expect("fixture record");
        }
        let file = fixture(&bytes);
        let row_len = u64::try_from(bytes.len() / 1024).expect("fixture length");
        assert_eq!(selected(&file, 0, 547), row_len * 547);
        assert_eq!(selected(&file, 7, 1025), row_len * 1024);
    }

    #[test]
    fn invalid_probe_and_resume_cannot_move_the_descriptor() {
        let mut file = fixture(b"\xff test\n");
        file.seek(SeekFrom::Start(3)).expect("caller position");
        for (resume, max, expected) in [
            (0, MAX_RECORD, io::ErrorKind::InvalidData),
            (0, 3, io::ErrorKind::InvalidData),
            (9, MAX_RECORD, io::ErrorKind::InvalidInput),
            (0, 0, io::ErrorKind::InvalidInput),
        ] {
            let error = seek_nginx_offset(&file, resume, BASE, max).expect_err("invalid fixture");
            assert_eq!(error.kind(), expected);
            assert_eq!(file.stream_position().expect("unchanged position"), 3);
        }
    }
}
