//! Log input backends for Fail2Ban (`polling`, Linux `inotify`, systemd `journald`)
//! plus shared [`WatchedFile`] line/checkpoint stream handling.

pub mod inotify;
pub mod polling;
pub mod systemd;

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use tokio::sync::{mpsc, watch};

use crate::config::configurator::glob_existing;
use crate::date::DateDetector;
use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};

use super::LogEncoding;
use super::file_identity::{FileIdentityState, Reopen};

/// Read chunk size for log tailing (64 KiB).
const READ_CHUNK_SIZE: usize = 64 * 1024;
/// Maximum raw bytes held for a single unterminated log line before force-flushing.
const MAX_PENDING_LINE_BYTES: usize = 1024 * 1024;
/// Probe chunk size and per-line cap for binary `seek_to_time`.
const PROBE_CHUNK_SIZE: usize = 4096;
const MAX_PROBE_LINE_BYTES: usize = 64 * 1024;

/// Backend selector matching Fail2Ban's `backend` jail option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendKind {
    #[default]
    Auto,
    Pyinotify,
    Polling,
    Systemd,
}

impl BackendKind {
    /// Parse a Fail2Ban `backend` configuration value (case-insensitive).
    pub fn parse(raw: &str) -> Result<Self> {
        // Upstream allows e.g. "pyinotify[...]" or "systemd[...]"; strip optional bracket params.
        let base = raw.trim().split('[').next().unwrap_or("").trim();
        match base.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "pyinotify" => Ok(Self::Pyinotify),
            "polling" => Ok(Self::Polling),
            "systemd" => Ok(Self::Systemd),
            _ => Err(Error::config(format!("Unsupported backend {raw:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Pyinotify => "pyinotify",
            Self::Polling => "polling",
            Self::Systemd => "systemd",
        }
    }
}

/// Events produced by log monitoring backends for consumption by [`super::super::Filter`].
#[derive(Debug, Clone, PartialEq)]
pub enum LogEvent {
    Line {
        line: String,
        preset_date: Option<f64>,
        log_path: Option<String>,
        in_operation: bool,
        checkpoint: Option<(String, u64)>,
    },
    Checkpoint {
        path: String,
        fingerprint: String,
        offset: u64,
    },
}

/// Cold-start half-interval seek parameters matching upstream `FileFilter.seekToTime`.
#[derive(Debug, Clone)]
pub struct AutoSeekConfig {
    pub start_time: f64,
    pub date_detector: DateDetector,
}

/// Per-file configuration shared by file-tailing backends.
#[derive(Debug, Clone)]
pub struct FileLogConfig {
    pub path: PathBuf,
    pub tail: bool,
    pub resume_fingerprint: Option<String>,
    pub resume_offset: u64,
    pub auto_seek: Option<AutoSeekConfig>,
}

/// Systemd journal query configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalConfig {
    pub matches: Vec<Vec<String>>,
    pub flags: Option<u32>,
    pub path: Option<PathBuf>,
    pub files: Vec<PathBuf>,
    pub namespace: Option<String>,
}

/// Expand Fail2Ban's `journalfiles` parameter (whitespace/comma-separated glob patterns)
/// into a deduplicated, sorted list of existing paths matching `filtersystemd.py`.
pub fn expand_journal_files(raw: &str) -> Vec<PathBuf> {
    let mut set = BTreeSet::new();
    for token in raw
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
    {
        for matched in glob_existing(token) {
            set.insert(PathBuf::from(matched));
        }
    }
    set.into_iter().collect()
}

/// Shared open-file reader preserving partial lines across reads and handling
/// rotation and truncation cleanly via [`FileIdentityState`].
#[derive(Debug)]
pub(crate) struct WatchedFile {
    config: FileLogConfig,
    encoding: LogEncoding,
    active_encoding: LogEncoding,
    identity: FileIdentityState,
    file: File,
    pending: Vec<u8>,
    in_operation: bool,
}

impl WatchedFile {
    /// Attempt to open `config.path` using `FileIdentityState::open`.
    /// `tail_override` overrides `config.tail` (used when a previously absent file is created).
    pub(crate) fn open(
        config: FileLogConfig,
        encoding: LogEncoding,
        tail_override: Option<bool>,
    ) -> io::Result<Self> {
        let tail = tail_override.unwrap_or(config.tail);
        let (mut identity, mut file) = FileIdentityState::open(
            &config.path,
            tail,
            config.resume_fingerprint.as_deref(),
            config.resume_offset,
        )?;
        let active_encoding = resolve_file_utf16_encoding(&mut file, encoding, identity.pos)?;

        if !tail
            && tail_override != Some(false)
            && let Some(mut seek_cfg) = config.auto_seek.clone()
        {
            let file_size = file.metadata()?.len();
            if file_size > identity.pos {
                let sought = seek_to_time(
                    &mut file,
                    active_encoding,
                    identity.pos,
                    file_size,
                    &mut seek_cfg.date_detector,
                    seek_cfg.start_time,
                )?;
                identity.set_pos(sought);
                file.seek(SeekFrom::Start(sought))?;
            }
        }

        let in_operation =
            tail || (config.resume_fingerprint.is_some() && config.auto_seek.is_none());
        Ok(Self {
            config,
            encoding,
            active_encoding,
            identity,
            file,
            pending: Vec::new(),
            in_operation,
        })
    }

    /// Read any newly appended bytes, handle rotation/truncation, and emit
    /// complete lines and offset checkpoints into `out`.
    pub(crate) fn collect_events(&mut self, out: &mut Vec<LogEvent>) {
        // Only drain old fd prior to reopen when path already switched to another inode
        // (e.g. logrotate rename), so tailing lines on the unlinked/renamed fd aren't lost.
        let same_inode = fs::metadata(&self.config.path)
            .map(|m| m.dev() == self.identity.dev && m.ino() == self.identity.ino)
            .unwrap_or(false);

        if !same_inode {
            self.drain_current_fd(out);
        }

        match self.identity.check_reopen(&mut self.file) {
            Ok(Reopen::Same) => {
                self.drain_current_fd(out);
            }
            Ok(Reopen::Rotated | Reopen::Truncated) => {
                self.flush_pending_on_reset(out);
                self.active_encoding = self.encoding;
                out.push(self.checkpoint_event());
                self.drain_current_fd(out);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // Temporarily absent (e.g. mid-rotation); keep fd open until recreated.
            }
            Err(err) => {
                log_msg(
                    LogLevel::Warning,
                    "fail2ban.filter",
                    &format!("Unable to check {:?}: {err}", self.config.path),
                );
            }
        }
    }

    fn ensure_fingerprint(&mut self) {
        if self.identity.fingerprint.is_empty() {
            let cur = self.file.stream_position().ok();
            if let Ok(meta) = self.file.metadata()
                && let Ok(fp) =
                    super::file_identity::file_first_line_sha1(&mut self.file, meta.len())
                && !fp.is_empty()
            {
                self.identity.fingerprint = fp;
            }
            if let Some(pos) = cur {
                let _ = self.file.seek(SeekFrom::Start(pos));
            }
        }
    }

    fn drain_current_fd(&mut self, out: &mut Vec<LogEvent>) {
        let seek_target = self.identity.pos + self.pending.len() as u64;
        if let Err(err) = self.file.seek(SeekFrom::Start(seek_target)) {
            log_msg(
                LogLevel::Warning,
                "fail2ban.filter",
                &format!("Seek failed on {:?}: {err}", self.config.path),
            );
            return;
        }

        let mut buf = [0u8; READ_CHUNK_SIZE];
        let mut emitted_lines = false;
        let path_str = self.config.path.to_string_lossy().into_owned();

        loop {
            match self.file.read(&mut buf) {
                Ok(0) => {
                    self.in_operation = true;
                    break;
                }
                Ok(n) => {
                    self.pending.extend_from_slice(&buf[..n]);
                    if self.active_encoding == LogEncoding::Utf16
                        && self.identity.pos == 0
                        && self.pending.len() >= 2
                    {
                        let (resolved, bom) = self.active_encoding.resolve_bom(&self.pending);
                        self.active_encoding = resolved;
                        if bom > 0 {
                            self.pending.drain(..bom);
                            self.identity.set_pos(self.identity.pos + bom as u64);
                        }
                    }
                    let consumed = self.emit_complete_lines(&path_str, out);
                    if consumed > 0 {
                        self.identity.set_pos(self.identity.pos + consumed as u64);
                        emitted_lines = true;
                    }
                    if self.pending.len() >= MAX_PENDING_LINE_BYTES {
                        self.ensure_fingerprint();
                        let line = self.active_encoding.decode(&self.pending);
                        let next_pos = self.identity.pos + self.pending.len() as u64;
                        self.identity.set_pos(next_pos);
                        self.pending.clear();
                        out.push(LogEvent::Line {
                            line,
                            preset_date: None,
                            log_path: Some(path_str.clone()),
                            in_operation: self.in_operation,
                            checkpoint: Some((self.identity.fingerprint.clone(), next_pos)),
                        });
                        emitted_lines = true;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    log_msg(
                        LogLevel::Warning,
                        "fail2ban.filter",
                        &format!("Read failed on {:?}: {err}", self.config.path),
                    );
                    break;
                }
            }
        }

        if emitted_lines {
            self.ensure_fingerprint();
            out.push(self.checkpoint_event());
        }
    }

    fn emit_complete_lines(&mut self, path_str: &str, out: &mut Vec<LogEvent>) -> usize {
        let mut start = 0usize;
        let mut checked_fp = false;
        while let Some((line_end, next_start)) =
            self.active_encoding.split_line(&self.pending[start..])
        {
            if !checked_fp {
                self.ensure_fingerprint();
                checked_fp = true;
            }
            let line = self
                .active_encoding
                .decode(&self.pending[start..start + line_end]);
            let next_offset = self.identity.pos + (start + next_start) as u64;
            out.push(LogEvent::Line {
                line,
                preset_date: None,
                log_path: Some(path_str.to_owned()),
                in_operation: self.in_operation,
                checkpoint: Some((self.identity.fingerprint.clone(), next_offset)),
            });
            start += next_start;
        }
        if start > 0 {
            self.pending.drain(..start);
        }
        start
    }

    fn flush_pending_on_reset(&mut self, out: &mut Vec<LogEvent>) {
        if !self.pending.is_empty() {
            let trimmed = strip_trailing_cr(&self.pending, self.active_encoding);
            let line = self.active_encoding.decode(trimmed);
            out.push(LogEvent::Line {
                line,
                preset_date: None,
                log_path: Some(self.config.path.to_string_lossy().into_owned()),
                in_operation: self.in_operation,
                checkpoint: None,
            });
            self.pending.clear();
        }
    }

    fn checkpoint_event(&self) -> LogEvent {
        LogEvent::Checkpoint {
            path: self.config.path.to_string_lossy().into_owned(),
            fingerprint: self.identity.fingerprint.clone(),
            offset: self.identity.pos,
        }
    }
}

fn strip_trailing_cr(bytes: &[u8], enc: LogEncoding) -> &[u8] {
    match enc {
        LogEncoding::Utf16Le | LogEncoding::Utf16 => {
            bytes.strip_suffix(&[b'\r', 0]).unwrap_or(bytes)
        }
        LogEncoding::Utf16Be => bytes.strip_suffix(&[0, b'\r']).unwrap_or(bytes),
        _ => bytes.strip_suffix(b"\r").unwrap_or(bytes),
    }
}

fn resolve_file_utf16_encoding(
    file: &mut File,
    encoding: LogEncoding,
    saved_pos: u64,
) -> io::Result<LogEncoding> {
    if encoding != LogEncoding::Utf16 {
        return Ok(encoding);
    }
    let mut header = [0u8; 2];
    file.seek(SeekFrom::Start(0))?;
    let n = file.read(&mut header)?;
    file.seek(SeekFrom::Start(saved_pos))?;
    if n < 2 {
        return Ok(LogEncoding::Utf16);
    }
    Ok(encoding.resolve_bom(&header).0)
}

/// Binary half-interval seek to the earliest line with timestamp `>= target_time`,
/// matching upstream Fail2Ban 1.1.1 `FileFilter.seekToTime`.
pub fn seek_to_time(
    file: &mut File,
    encoding: LogEncoding,
    start_pos: u64,
    file_size: u64,
    date_detector: &mut DateDetector,
    target_time: f64,
) -> io::Result<u64> {
    if file_size == 0 || start_pos >= file_size {
        return Ok(start_pos);
    }
    let eff_enc = if encoding == LogEncoding::Utf16 {
        LogEncoding::Utf16Le
    } else {
        encoding
    };
    let step_back: u64 = if eff_enc.is_utf16() { 4 } else { 2 };

    let mut minp = start_pos;
    let mut maxp = file_size;
    let mut try_pos = Some(minp);
    let mut last_pos = u64::MAX;
    let mut found_time: Option<f64> = None;
    let mut movecntr: u32 = 3;

    while maxp > minp {
        let mut pos = try_pos.take().unwrap_or_else(|| minp + (maxp - minp) / 2);
        pos = pos.saturating_sub(step_back);
        if eff_enc.is_utf16() {
            pos &= !1;
        }
        let seekpos = seek_line_pos(file, pos, true, eff_enc)?;
        pos = seekpos;

        // Within next 6 lines (`lncntr = 5` retries), look for any parseable timestamp.
        let mut lncntr: u32 = 5;
        let mut matched_time: Option<f64> = None;
        let mut nextp: Option<u64> = None;

        loop {
            let Some((line, after_pos)) = read_probe_line(file, eff_enc)? else {
                break;
            };
            if let Some((ts, _, _)) = date_detector.get_time(&line) {
                matched_time = Some(ts);
                nextp = Some(after_pos);
                break;
            }
            if after_pos > maxp {
                pos = seekpos;
                break;
            }
            pos = after_pos;
            nextp = Some(after_pos);
            if lncntr == 0 {
                break;
            }
            lncntr -= 1;
        }

        if let Some(unix_time) = matched_time {
            if unix_time >= target_time {
                if found_time.is_none_or(|ft| unix_time <= ft) {
                    found_time = Some(unix_time);
                }
                if pos == maxp {
                    pos = seekpos;
                }
                if pos < maxp {
                    maxp = pos;
                }
            } else {
                if found_time.is_none_or(|ft| unix_time >= ft) {
                    found_time = Some(unix_time);
                }
                pos = match nextp {
                    Some(np) => np,
                    None => file.stream_position()?,
                };
                if pos > minp {
                    minp = pos;
                }
            }
        }

        if pos == last_pos {
            movecntr = movecntr.saturating_sub(1);
            if movecntr == 0 {
                break;
            }
            if minp != last_pos {
                last_pos = minp;
                try_pos = Some(minp);
                continue;
            }
            break;
        }
        last_pos = pos;
    }

    seek_line_pos(file, minp, false, eff_enc)
}

fn seek_line_pos(
    file: &mut File,
    offs: u64,
    end_line: bool,
    encoding: LogEncoding,
) -> io::Result<u64> {
    let aligned = if encoding.is_utf16() { offs & !1 } else { offs };
    file.seek(SeekFrom::Start(aligned))?;
    if aligned > 0 && end_line {
        let _ = read_probe_line(file, encoding)?;
    }
    file.stream_position()
}

fn read_probe_line(file: &mut File, encoding: LogEncoding) -> io::Result<Option<(String, u64)>> {
    let line_start = file.stream_position()?;
    let mut buf = Vec::with_capacity(PROBE_CHUNK_SIZE);
    let mut chunk = [0u8; PROBE_CHUNK_SIZE];

    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            let next_pos = line_start + buf.len() as u64;
            let trimmed = strip_trailing_cr(&buf, encoding);
            return Ok(Some((encoding.decode(trimmed), next_pos)));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some((line_end, next_start)) = encoding.split_line(&buf) {
            let next_pos = line_start + next_start as u64;
            file.seek(SeekFrom::Start(next_pos))?;
            return Ok(Some((encoding.decode(&buf[..line_end]), next_pos)));
        }
        if buf.len() >= MAX_PROBE_LINE_BYTES {
            let next_pos = line_start + buf.len() as u64;
            return Ok(Some((encoding.decode(&buf), next_pos)));
        }
    }
}

/// Forward a batch of events through an async mpsc channel, returning `false`
/// if `shutdown` signals `true` or the receiver has closed.
pub(crate) async fn send_events(
    tx: &mpsc::Sender<LogEvent>,
    shutdown: &mut watch::Receiver<bool>,
    events: Vec<LogEvent>,
) -> bool {
    for ev in events {
        if *shutdown.borrow() {
            return false;
        }
        tokio::select! {
            biased;
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    return false;
                }
            }
            send_res = tx.send(ev) => {
                if send_res.is_err() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!(
            "f2b_backend_{tag}_{}_{nanos}.log",
            std::process::id()
        ))
    }

    #[test]
    fn seek_to_time_positions_at_first_matching_line_and_handles_undated_files() {
        let path = temp_path("seek");
        let mut content = String::new();
        for i in 0..200u64 {
            let ts = 1_700_000_000 + i * 10;
            content.push_str(&format!(
                "{ts} sshd[1]: Failed password for root from 192.0.2.1 #{i:03}\n"
            ));
        }
        fs::write(&path, &content).unwrap();

        let mut dd = DateDetector::empty();
        dd.append_template("^EPOCH").unwrap();

        let mut file = File::open(&path).unwrap();
        let size = file.metadata().unwrap().len();

        // Seek to middle (i = 150 -> ts = 1700001500).
        let pos = seek_to_time(
            &mut file,
            LogEncoding::Utf8,
            0,
            size,
            &mut dd,
            1_700_001_500.0,
        )
        .unwrap();
        assert!(pos > 0 && pos < size);
        file.seek(SeekFrom::Start(pos)).unwrap();
        let (line, _) = read_probe_line(&mut file, LogEncoding::Utf8)
            .unwrap()
            .unwrap();
        assert!(line.starts_with("1700001500 "), "got line: {line}");

        // Seek past last timestamp -> EOF.
        let eof_pos = seek_to_time(
            &mut file,
            LogEncoding::Utf8,
            0,
            size,
            &mut dd,
            1_700_099_999.0,
        )
        .unwrap();
        assert_eq!(eof_pos, size);

        // Seek before first timestamp -> 0.
        let zero_pos = seek_to_time(
            &mut file,
            LogEncoding::Utf8,
            0,
            size,
            &mut dd,
            1_600_000_000.0,
        )
        .unwrap();
        assert_eq!(zero_pos, 0);

        // File without dates -> must remain at 0 so no lines are dropped.
        let undated = temp_path("undated");
        fs::write(&undated, "alpha line\nbeta line\ngamma line\n").unwrap();
        let mut uf = File::open(&undated).unwrap();
        let usize_len = uf.metadata().unwrap().len();
        let upos = seek_to_time(
            &mut uf,
            LogEncoding::Utf8,
            0,
            usize_len,
            &mut dd,
            1_700_001_500.0,
        )
        .unwrap();
        assert_eq!(upos, 0);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&undated);
    }

    #[test]
    fn watched_file_handles_utf16_embedded_lf_byte_without_splitting() {
        for enc in [LogEncoding::Utf16Be, LogEncoding::Utf16Le] {
            let path = temp_path(enc.as_str());
            let text = concat!(
                "1700000001 \u{20AC} Failed auth: invalid user Test\u{020A} from 192.0.2.1\n",
                "1700000002 \u{20AC} Failed auth: invalid user TestI from 192.0.2.2\n"
            );
            let encoded: Vec<u8> = match enc {
                LogEncoding::Utf16Be => text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
                _ => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            };
            fs::write(&path, &encoded).unwrap();

            let mut wf = WatchedFile::open(
                FileLogConfig {
                    path: path.clone(),
                    tail: false,
                    resume_fingerprint: None,
                    resume_offset: 0,
                    auto_seek: None,
                },
                enc,
                None,
            )
            .unwrap();
            let mut evs = Vec::new();
            wf.collect_events(&mut evs);
            let lines: Vec<String> = evs
                .into_iter()
                .filter_map(|e| match e {
                    LogEvent::Line { line, .. } => Some(line),
                    LogEvent::Checkpoint { .. } => None,
                })
                .collect();
            assert_eq!(lines.len(), 2, "enc={enc:?}, lines={lines:?}");
            assert!(lines[0].contains("Test\u{020A} from 192.0.2.1"));
            assert!(lines[1].contains("TestI from 192.0.2.2"));

            let _ = fs::remove_file(&path);
        }
    }
}
