//! Log input backends for Fail2Ban (`polling`, Linux `inotify`, systemd `journald`)
//! plus shared [`WatchedFile`] line/checkpoint stream handling.

pub mod inotify;
pub mod polling;
pub mod systemd;

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};

use super::LogEncoding;
use super::file_identity::{FileIdentityState, Reopen};

/// Read chunk size for log tailing (64 KiB).
const READ_CHUNK_SIZE: usize = 64 * 1024;
/// Maximum raw bytes held for a single unterminated log line before force-flushing.
const MAX_PENDING_LINE_BYTES: usize = 1024 * 1024;

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
    },
    Checkpoint {
        path: String,
        fingerprint: String,
        offset: u64,
    },
}

/// Per-file configuration shared by file-tailing backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLogConfig {
    pub path: PathBuf,
    pub tail: bool,
    pub resume_fingerprint: Option<String>,
    pub resume_offset: u64,
}

/// Systemd journal query configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalConfig {
    pub matches: Vec<Vec<String>>,
    pub flags: Option<u32>,
    pub path: Option<PathBuf>,
}

/// Shared open-file reader preserving partial lines across reads and handling
/// rotation and truncation cleanly via [`FileIdentityState`].
#[derive(Debug)]
pub(crate) struct WatchedFile {
    config: FileLogConfig,
    encoding: LogEncoding,
    identity: FileIdentityState,
    file: File,
    pending: Vec<u8>,
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
        let (identity, file) = FileIdentityState::open(
            &config.path,
            tail,
            config.resume_fingerprint.as_deref(),
            config.resume_offset,
        )?;
        Ok(Self {
            config,
            encoding,
            identity,
            file,
            pending: Vec::new(),
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
                Ok(0) => break,
                Ok(n) => {
                    self.pending.extend_from_slice(&buf[..n]);
                    let consumed = self.emit_complete_lines(&path_str, out);
                    if consumed > 0 {
                        self.identity.set_pos(self.identity.pos + consumed as u64);
                        emitted_lines = true;
                    }
                    if self.pending.len() >= MAX_PENDING_LINE_BYTES {
                        let line = self.encoding.decode(&self.pending);
                        self.identity
                            .set_pos(self.identity.pos + self.pending.len() as u64);
                        self.pending.clear();
                        out.push(LogEvent::Line {
                            line,
                            preset_date: None,
                            log_path: Some(path_str.clone()),
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
            if self.identity.fingerprint.is_empty()
                && let Ok(meta) = self.file.metadata()
                && let Ok(fp) =
                    super::file_identity::file_first_line_sha1(&mut self.file, meta.len())
                && !fp.is_empty()
            {
                self.identity.fingerprint = fp;
            }
            out.push(self.checkpoint_event());
        }
    }

    fn emit_complete_lines(&mut self, path_str: &str, out: &mut Vec<LogEvent>) -> usize {
        let mut start = 0usize;
        while let Some(rel) = memchr::memchr(b'\n', &self.pending[start..]) {
            let end = start + rel;
            let raw_line = &self.pending[start..end];
            let trimmed = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            let line = self.encoding.decode(trimmed);
            out.push(LogEvent::Line {
                line,
                preset_date: None,
                log_path: Some(path_str.to_owned()),
            });
            start = end + 1;
        }
        if start > 0 {
            self.pending.drain(..start);
        }
        start
    }

    fn flush_pending_on_reset(&mut self, out: &mut Vec<LogEvent>) {
        if !self.pending.is_empty() {
            let trimmed = self
                .pending
                .strip_suffix(b"\r")
                .unwrap_or(&self.pending);
            let line = self.encoding.decode(trimmed);
            out.push(LogEvent::Line {
                line,
                preset_date: None,
                log_path: Some(self.config.path.to_string_lossy().into_owned()),
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

/// Forward a batch of events through an async mpsc channel, returning `false`
/// if the receiver has closed.
pub(crate) async fn send_events(tx: &mpsc::Sender<LogEvent>, events: Vec<LogEvent>) -> bool {
    for ev in events {
        if tx.send(ev).await.is_err() {
            return false;
        }
    }
    true
}
