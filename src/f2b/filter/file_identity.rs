//! File identity, rotation/truncation detection, and SHA-1 first-line
//! fingerprinting matching Fail2Ban 1.1.1 `FileContainer`.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Re-verify first-line SHA-1 every `HASH_INTERVAL` polls to catch same-inode reuse.
pub const HASH_INTERVAL: usize = 30;
/// Maximum line length scanned when computing the first-line fingerprint.
const MAX_FIRST_LINE_BYTES: usize = 64 * 1024;

/// Classification returned when re-checking an open log file against its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reopen {
    /// Same underlying file `(dev, ino)` with unchanged first-line fingerprint and size >= pos.
    Same,
    /// Same underlying file shrunk below current offset (`copytruncate`).
    Truncated,
    /// Underlying file replaced (different `(dev, ino)` or mismatched first-line fingerprint).
    Rotated,
}

/// Persistent identity and read offset state for a watched file.
#[derive(Debug, Clone)]
pub struct FileIdentityState {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub pos: u64,
    pub fingerprint: String,
    read_cycles: usize,
}

impl FileIdentityState {
    /// Open `path`, establish identity, and compute initial read offset from `tail` and
    /// any saved database `(resume_fingerprint, resume_offset)`.
    pub fn open(
        path: &Path,
        tail: bool,
        resume_fingerprint: Option<&str>,
        resume_offset: u64,
    ) -> io::Result<(Self, File)> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        let dev = meta.dev();
        let ino = meta.ino();
        let size = meta.len();

        let fingerprint = file_first_line_sha1(&mut file, size)?;

        let pos = match resume_fingerprint {
            Some(saved_fp) if !saved_fp.is_empty() => {
                if !fingerprint.is_empty() && fingerprint == saved_fp {
                    if size >= resume_offset {
                        resume_offset
                    } else {
                        // Truncated while offline.
                        0
                    }
                } else if fingerprint.is_empty() && size == 0 {
                    0
                } else {
                    // Rotated while offline: read new file from start.
                    0
                }
            }
            _ => {
                if tail {
                    size
                } else {
                    0
                }
            }
        };

        file.seek(SeekFrom::Start(pos))?;

        let state = Self {
            path: path.to_path_buf(),
            dev,
            ino,
            pos,
            fingerprint,
            read_cycles: 0,
        };
        Ok((state, file))
    }

    /// Check whether `self.path` still points to the same non-truncated, non-rotated file.
    ///
    /// When rotated or truncated, `*file` is replaced/rewound and `self` is updated
    /// (`self.pos = 0`). Returns [`Reopen`] indicating what happened.
    pub fn check_reopen(&mut self, file: &mut File) -> io::Result<Reopen> {
        let path_meta = fs::metadata(&self.path)?;
        if path_meta.dev() != self.dev || path_meta.ino() != self.ino {
            let mut new_file = File::open(&self.path)?;
            let new_meta = new_file.metadata()?;
            let new_size = new_meta.len();
            let new_fp = file_first_line_sha1(&mut new_file, new_size)?;
            new_file.seek(SeekFrom::Start(0))?;

            self.dev = new_meta.dev();
            self.ino = new_meta.ino();
            self.pos = 0;
            self.fingerprint = new_fp;
            self.read_cycles = 0;
            *file = new_file;
            return Ok(Reopen::Rotated);
        }

        let cur_meta = file.metadata()?;
        let cur_size = cur_meta.len();

        if cur_size < self.pos {
            let new_fp = file_first_line_sha1(file, cur_size)?;
            file.seek(SeekFrom::Start(0))?;
            self.pos = 0;
            self.fingerprint = new_fp;
            self.read_cycles = 0;
            return Ok(Reopen::Truncated);
        }

        self.read_cycles += 1;
        if (self.fingerprint.is_empty() && cur_size > 0)
            || self.read_cycles >= HASH_INTERVAL
        {
            self.read_cycles = 0;
            let saved_pos = self.pos;
            let cur_fp = file_first_line_sha1(file, cur_size)?;
            if !self.fingerprint.is_empty() && !cur_fp.is_empty() && cur_fp != self.fingerprint {
                file.seek(SeekFrom::Start(0))?;
                self.pos = 0;
                self.fingerprint = cur_fp;
                return Ok(Reopen::Rotated);
            }
            if self.fingerprint.is_empty() && !cur_fp.is_empty() {
                self.fingerprint = cur_fp;
            }
            file.seek(SeekFrom::Start(saved_pos))?;
        }

        Ok(Reopen::Same)
    }

    /// Update tracked read byte position (only advances when caller acknowledges consumed bytes).
    pub fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

/// Compute lowercase hex SHA-1 of the first line of `file` (empty string if file
/// is empty or its first line is not yet terminated by `\n` or `\r`).
///
/// Always rewinds or leaves caller to re-seek explicitly (`SeekFrom::Start(0)` is performed).
pub fn file_first_line_sha1(file: &mut File, size: u64) -> io::Result<String> {
    if size == 0 {
        return Ok(String::new());
    }
    file.seek(SeekFrom::Start(0))?;
    let to_read = (size as usize).min(MAX_FIRST_LINE_BYTES);
    let mut buf = vec![0u8; to_read];
    let mut total = 0usize;
    while total < to_read {
        let n = file.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        if let Some(rel_nl) = buf[total..total + n].iter().position(|&b| b == b'\n') {
            let line_end = total + rel_nl + 1;
            return Ok(sha1_hex(&buf[..line_end]));
        }
        total += n;
    }

    if total == 0 {
        return Ok(String::new());
    }
    let slice = &buf[..total];
    // Incomplete line without trailing newline/carriage-return is not hashed yet.
    if total < MAX_FIRST_LINE_BYTES && !slice.ends_with(b"\r") {
        return Ok(String::new());
    }
    Ok(sha1_hex(slice))
}

/// Pure-Rust RFC 3174 SHA-1 digest formatted as 40 lowercase hex characters.
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([
                word_bytes[0],
                word_bytes[1],
                word_bytes[2],
                word_bytes[3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4]
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("f2b_id_{name}_{}_{nanos}.log", std::process::id()))
    }

    #[test]
    fn sha1_rfc3174_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn first_line_fingerprint_requires_newline_unless_cr() {
        let path = unique_temp_path("partial");
        fs::write(&path, b"incomplete line").unwrap();
        let mut f = File::open(&path).unwrap();
        assert_eq!(file_first_line_sha1(&mut f, 15).unwrap(), "");

        fs::write(&path, b"first line\nsecond line\n").unwrap();
        let mut f2 = File::open(&path).unwrap();
        assert_eq!(
            file_first_line_sha1(&mut f2, 23).unwrap(),
            sha1_hex(b"first line\n")
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn open_resume_truncate_and_rotate() {
        let path = unique_temp_path("rotate");
        let rotated = unique_temp_path("rotate_old");
        fs::write(&path, b"line1\nline2\n").unwrap();

        let (mut state, mut file) = FileIdentityState::open(&path, false, None, 0).unwrap();
        assert_eq!(state.pos, 0);
        assert_eq!(state.fingerprint, sha1_hex(b"line1\n"));

        // Resume matching fingerprint jumps to saved offset.
        let fp = state.fingerprint.clone();
        let (resumed, _) = FileIdentityState::open(&path, false, Some(&fp), 6).unwrap();
        assert_eq!(resumed.pos, 6);

        // Resume with mismatched fingerprint resets to 0 (rotated while offline).
        let (offline_rot, _) =
            FileIdentityState::open(&path, true, Some("0000000000000000000000000000000000000000"), 6)
                .unwrap();
        assert_eq!(offline_rot.pos, 0);

        // Tail mode without checkpoint jumps to end.
        let (tailed, _) = FileIdentityState::open(&path, true, None, 0).unwrap();
        assert_eq!(tailed.pos, 12);

        // Advance pos past current size -> truncation check.
        state.set_pos(12);
        {
            let mut wf = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            wf.write_all(b"new\n").unwrap();
        }
        assert_eq!(state.check_reopen(&mut file).unwrap(), Reopen::Truncated);
        assert_eq!(state.pos, 0);

        // Rename + recreate new file -> rotation check.
        fs::rename(&path, &rotated).unwrap();
        fs::write(&path, b"brandnew\n").unwrap();
        assert_eq!(state.check_reopen(&mut file).unwrap(), Reopen::Rotated);
        assert_eq!(state.pos, 0);
        assert_eq!(state.fingerprint, sha1_hex(b"brandnew\n"));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&rotated);
    }
}
