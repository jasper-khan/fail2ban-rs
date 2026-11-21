//! Offline physical identity and first-record resume for original Fail2Ban files.
//!
//! Operates on caller-selected regular descriptors only; never opens a path.
//! SHA-1 is used solely to match the pinned Python 3 Fail2Ban logs-table
//! fingerprint, not for authentication or tamper detection. In Fail2Ban
//! 1.1.1 the MD5 probe passes a string to hashlib and falls back to SHA-1.
//! Older MD5 fingerprints do not match. Inode comparison mirrors the original.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};

const HASH_INTERVAL: i64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity(u64);

#[derive(Clone, Debug)]
pub(crate) struct FileIdentityState {
    identity: Identity,
    fingerprint: String,
    hash_next_time: i64,
    max_first_record_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reopen {
    /// Checkpoint to read from if there is data.
    pub(crate) offset: u64,
    /// Original would reset an established fingerprint/position to head.
    pub(crate) rotated: bool,
    pub(crate) has_content: bool,
}

impl FileIdentityState {
    pub(crate) fn initialize(
        file: &File,
        now: i64,
        max_first_record_bytes: usize,
    ) -> io::Result<Self> {
        if max_first_record_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "legacy first-record limit must be positive",
            ));
        }
        let (_, identity) = file_metadata(file)?;
        Ok(Self {
            identity,
            fingerprint: first_fingerprint(file, max_first_record_bytes)?,
            hash_next_time: now.saturating_add(HASH_INTERVAL),
            max_first_record_bytes,
        })
    }

    /// Persisted representation: empty until the first raw record is complete.
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The old database position is used only for an exact fingerprint match,
    /// in non-tail mode, with a positive position. The subsequent reopen
    /// separately detects when the physical file is smaller than this offset.
    pub(crate) fn resume_offset(
        &self,
        stored_fingerprint: &str,
        stored_offset: u64,
        tail: bool,
    ) -> Option<u64> {
        (!tail && stored_offset > 0 && stored_fingerprint == self.fingerprint)
            .then_some(stored_offset)
    }

    /// Update identity for an explicit candidate descriptor. An overdue hash
    /// check can detect same-inode rewrites even when the file regrew before
    /// the poll. Like FileContainer, do not reset an offset when there is no
    /// previously established hash, even if the inode has changed.
    pub(crate) fn reopen(
        &mut self,
        file: &File,
        acknowledged: u64,
        now: i64,
    ) -> io::Result<Reopen> {
        let (metadata, candidate) = file_metadata(file)?;
        let size = metadata.len();
        let rotation_hint = size < acknowledged || candidate != self.identity;
        let mut offset = acknowledged;
        let mut rotated = false;
        if rotation_hint || self.fingerprint.is_empty() || now > self.hash_next_time {
            // Read before mutating state: a bounded-read or descriptor error
            // cannot change the previously acknowledged file identity.
            let fingerprint = first_fingerprint(file, self.max_first_record_bytes)?;
            if !fingerprint.is_empty() {
                self.hash_next_time = now.saturating_add(HASH_INTERVAL);
            }
            if (rotation_hint || fingerprint != self.fingerprint) && !self.fingerprint.is_empty() {
                rotated = true;
                self.identity = candidate;
                offset = 0;
            }
            self.fingerprint = fingerprint;
        }
        Ok(Reopen {
            offset,
            rotated,
            has_content: size > offset,
        })
    }
}

fn file_metadata(file: &File) -> io::Result<(Metadata, Identity)> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legacy file identity requires a regular descriptor",
        ));
    }
    let identity = Identity(metadata.ino());
    Ok((metadata, identity))
}

fn first_fingerprint(file: &File, max: usize) -> io::Result<String> {
    let mut record = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        // Read at most one byte above the limit to distinguish a too-large
        // first record from one that ends exactly at the quota.
        let remaining = max.saturating_sub(record.len());
        let limit = chunk.len().min(remaining.saturating_add(1));
        let buffer = chunk
            .get_mut(..limit)
            .ok_or_else(|| io::Error::other("legacy fingerprint buffer boundary"))?;
        let offset = u64::try_from(record.len())
            .map_err(|_| io::Error::other("legacy first-record offset overflow"))?;
        let count = loop {
            match file.read_at(buffer, offset) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                outcome => break outcome?,
            }
        };
        if count == 0 {
            // Python's raw readline is LF-delimited, but its complete
            // fingerprint test is rstrip(b'\r\n'), so a final CR at EOF also
            // establishes a hash. The actual UTF-8 line cursor remains LF-only.
            return Ok(if record.last() == Some(&b'\r') {
                sha1_hex(&record)
            } else {
                String::new()
            });
        }
        let bytes = buffer
            .get(..count)
            .ok_or_else(|| io::Error::other("legacy fingerprint read boundary"))?;
        let lf = bytes.iter().position(|&byte| byte == b'\n');
        let take = lf.map_or(count, |index| index + 1);
        if take > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy first record exceeds fingerprint byte limit",
            ));
        }
        let bytes = bytes
            .get(..take)
            .ok_or_else(|| io::Error::other("legacy fingerprint line boundary"))?;
        record.extend_from_slice(bytes);
        if lf.is_some() {
            return Ok(sha1_hex(&record));
        }
    }
}

fn sha1_hex(input: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut state = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let (blocks, tail) = input.as_chunks::<64>();
    for block in blocks {
        transform(&mut state, block);
    }
    let size = if tail.len() < 56 { 64 } else { 128 };
    let mut pad = [0_u8; 128];
    if let Some(section) = pad.get_mut(..tail.len()) {
        section.copy_from_slice(tail);
    }
    if let Some(marker) = pad.get_mut(tail.len()) {
        *marker = 0x80;
    }
    if let Some(length) = pad.get_mut(size - 8..size) {
        let bits = u64::try_from(input.len())
            .unwrap_or(u64::MAX)
            .wrapping_mul(8);
        length.copy_from_slice(&bits.to_be_bytes());
    }
    for block in pad.get(..size).unwrap_or_default().as_chunks::<64>().0 {
        transform(&mut state, block);
    }
    let mut result = String::with_capacity(40);
    for byte in state.into_iter().flat_map(u32::to_be_bytes) {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[allow(clippy::many_single_char_names)] // SHA-1 specifies registers a through e.
fn transform(state: &mut [u32; 5], block: &[u8; 64]) {
    // Standard SHA-1 message schedule and 80 rounds. The rolling words
    // avoid allocating a second 80-word message buffer.
    let mut words = [0_u32; 16];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for round in 0..80_usize {
        let word = if round < 16 {
            words.get(round).copied().unwrap_or_default()
        } else {
            let old = |delta| words.get((round - delta) % 16).copied().unwrap_or_default();
            let next = (old(3) ^ old(8) ^ old(14) ^ old(16)).rotate_left(1);
            if let Some(slot) = words.get_mut(round % 16) {
                *slot = next;
            }
            next
        };
        let (mix, constant) = match round {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(mix)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(word);
        (a, b, c, d, e) = (next, a, b.rotate_left(30), c, d);
    }
    for (current, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *current = current.wrapping_add(value);
    }
}

#[cfg(test)]
#[path = "legacy_file_identity_test.rs"]
mod tests;
