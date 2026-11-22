//! Pure-Rust Linux `inotify` log backend matching Fail2Ban 1.1.1
//! `fail2ban/server/filterpyinotify.py`.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};

use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};

use super::super::LogEncoding;
use super::{FileLogConfig, LogEvent, WatchedFile, send_events};

const INOTIFY_FILE_MASK: u32 = nix::libc::IN_MODIFY
    | nix::libc::IN_ATTRIB
    | nix::libc::IN_DELETE_SELF
    | nix::libc::IN_MOVE_SELF;

const INOTIFY_DIR_MASK: u32 =
    nix::libc::IN_MODIFY | nix::libc::IN_ATTRIB | nix::libc::IN_MOVED_TO | nix::libc::IN_CREATE;

const DEFAULT_PENDING_RETRY: Duration = Duration::from_secs(5);
const READ_BUF_BYTES: usize = 32 * 1024;

#[derive(Debug)]
struct InotifyFd(RawFd);

impl InotifyFd {
    fn open() -> io::Result<Self> {
        // SAFETY: `inotify_init1` takes integer flags and returns a new fd or -1 with errno set.
        let fd =
            unsafe { nix::libc::inotify_init1(nix::libc::IN_NONBLOCK | nix::libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    fn add_watch(&self, path: &Path, mask: u32) -> io::Result<i32> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "path contains interior NUL")
        })?;
        // SAFETY: `self.0` is a valid open inotify fd and `c_path.as_ptr()` is a valid NUL-terminated string.
        let wd = unsafe { nix::libc::inotify_add_watch(self.0, c_path.as_ptr(), mask) };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(wd)
    }

    fn remove_watch(&self, wd: i32) {
        // SAFETY: `self.0` is a valid open inotify fd; failures (e.g. already removed via IN_IGNORED) are benign.
        unsafe {
            let _ = nix::libc::inotify_rm_watch(self.0, wd);
        }
    }
}

impl AsRawFd for InotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for InotifyFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: `self.0` was created by `inotify_init1`, owned exclusively by `InotifyFd`, and not closed elsewhere.
            unsafe {
                let _ = nix::libc::close(self.0);
            }
        }
    }
}

#[derive(Debug)]
struct DecodedInotifyEvent {
    wd: i32,
    mask: u32,
    name: Option<PathBuf>,
}

/// Linux inotify log file backend watching both files and their parent directories
/// to seamlessly survive atomic log rotation and file creation.
#[derive(Debug)]
pub struct FilterPyinotify {
    configs: BTreeMap<PathBuf, FileLogConfig>,
    watched: BTreeMap<PathBuf, WatchedFile>,
    pending: BTreeMap<PathBuf, FileLogConfig>,
    encoding: LogEncoding,
    pending_retry: Duration,
    /// `file_wd -> path` and `path -> file_wd`
    file_wds: BTreeMap<i32, PathBuf>,
    path_to_file_wd: BTreeMap<PathBuf, i32>,
    /// `dir_wd -> dir_path`, `dir_path -> dir_wd`, and `dir_path -> tracked file paths`
    dir_wds: BTreeMap<i32, PathBuf>,
    dir_to_wd: BTreeMap<PathBuf, i32>,
    dir_children: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
}

impl FilterPyinotify {
    /// Construct a new [`FilterPyinotify`] monitoring `configs`.
    pub fn new(configs: Vec<FileLogConfig>, encoding: LogEncoding) -> Self {
        Self::with_pending_retry(configs, encoding, DEFAULT_PENDING_RETRY)
    }

    /// Construct a new [`FilterPyinotify`] with a custom retry interval for missing directories.
    pub fn with_pending_retry(
        configs: Vec<FileLogConfig>,
        encoding: LogEncoding,
        pending_retry: Duration,
    ) -> Self {
        let mut cfg_map = BTreeMap::new();
        for cfg in configs {
            cfg_map.insert(cfg.path.clone(), cfg);
        }
        Self {
            configs: cfg_map,
            watched: BTreeMap::new(),
            pending: BTreeMap::new(),
            encoding,
            pending_retry,
            file_wds: BTreeMap::new(),
            path_to_file_wd: BTreeMap::new(),
            dir_wds: BTreeMap::new(),
            dir_to_wd: BTreeMap::new(),
            dir_children: BTreeMap::new(),
        }
    }

    /// Run the async Linux inotify watcher loop until `shutdown` signals `true` or `tx` closes.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<LogEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        if *shutdown.borrow() {
            return Ok(());
        }

        let inotify_fd = InotifyFd::open().map_err(|err| Error::io("inotify_init1 failed", err))?;
        let async_fd = AsyncFd::new(inotify_fd)
            .map_err(|err| Error::io("AsyncFd registration failed", err))?;

        let mut startup_events = Vec::new();
        let initial_configs: Vec<FileLogConfig> = self.configs.values().cloned().collect();
        for cfg in initial_configs {
            self.register_dir_watch(async_fd.get_ref(), &cfg.path);
            self.try_open_file(async_fd.get_ref(), cfg, None, &mut startup_events);
        }
        if !send_events(&tx, &mut shutdown, startup_events).await {
            return Ok(());
        }

        let mut buf = vec![0u8; READ_BUF_BYTES];

        loop {
            if *shutdown.borrow() {
                break;
            }

            let pending_wait = self.pending_retry;
            let has_pending = !self.pending.is_empty();

            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                () = tokio::time::sleep(pending_wait), if has_pending => {
                    let retry_events = self.retry_pending(async_fd.get_ref());
                    if !send_events(&tx, &mut shutdown, retry_events).await {
                        break;
                    }
                }
                ready_res = async_fd.readable() => {
                    let mut guard = match ready_res {
                        Ok(g) => g,
                        Err(err) => {
                            return Err(Error::io("inotify readable wait failed", err));
                        }
                    };

                    let mut batch_events = Vec::new();
                    loop {
                        match read_inotify_batch(guard.get_inner().as_raw_fd(), &mut buf) {
                            Ok(decoded) if decoded.is_empty() => break,
                            Ok(decoded) => {
                                self.handle_kernel_events(
                                    guard.get_inner(),
                                    &decoded,
                                    &mut batch_events,
                                );
                            }
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                                guard.clear_ready();
                                break;
                            }
                            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                            Err(err) => {
                                return Err(Error::io("inotify read failed", err));
                            }
                        }
                    }

                    if !send_events(&tx, &mut shutdown, batch_events).await {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn register_dir_watch(&mut self, fd: &InotifyFd, file_path: &Path) {
        let dir = match file_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        self.dir_children
            .entry(dir.clone())
            .or_default()
            .insert(file_path.to_path_buf());

        if self.dir_to_wd.contains_key(&dir) {
            return;
        }
        match fd.add_watch(&dir, INOTIFY_DIR_MASK) {
            Ok(wd) => {
                self.dir_wds.insert(wd, dir.clone());
                self.dir_to_wd.insert(dir, wd);
            }
            Err(err) => {
                log_msg(
                    LogLevel::Debug,
                    "fail2ban.filter",
                    &format!("Cannot watch parent directory {:?}: {err}", dir),
                );
            }
        }
    }

    fn register_file_watch(&mut self, fd: &InotifyFd, file_path: &Path) {
        match fd.add_watch(file_path, INOTIFY_FILE_MASK) {
            Ok(wd) => {
                if let Some(prev_wd) = self.path_to_file_wd.insert(file_path.to_path_buf(), wd)
                    && prev_wd != wd
                {
                    self.file_wds.remove(&prev_wd);
                    fd.remove_watch(prev_wd);
                }
                self.file_wds.insert(wd, file_path.to_path_buf());
            }
            Err(err) => {
                log_msg(
                    LogLevel::Debug,
                    "fail2ban.filter",
                    &format!("Cannot add inotify watch on {:?}: {err}", file_path),
                );
            }
        }
    }

    fn try_open_file(
        &mut self,
        fd: &InotifyFd,
        cfg: FileLogConfig,
        tail_override: Option<bool>,
        out: &mut Vec<LogEvent>,
    ) {
        let path = cfg.path.clone();
        match WatchedFile::open(cfg.clone(), self.encoding, tail_override) {
            Ok(mut wf) => {
                wf.collect_events(out);
                self.watched.insert(path.clone(), wf);
                self.pending.remove(&path);
                self.register_file_watch(fd, &path);
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    log_msg(
                        LogLevel::Warning,
                        "fail2ban.filter",
                        &format!("Unable to open {:?} for inotify: {err}", path),
                    );
                }
                self.pending.insert(path, cfg);
            }
        }
    }

    fn retry_pending(&mut self, fd: &InotifyFd) -> Vec<LogEvent> {
        let mut events = Vec::new();
        let pending_list: Vec<FileLogConfig> = self.pending.values().cloned().collect();
        for cfg in pending_list {
            self.register_dir_watch(fd, &cfg.path);
            // Newly appeared files read from offset 0 so initial lines are never skipped.
            self.try_open_file(fd, cfg, Some(false), &mut events);
        }
        events
    }

    fn handle_kernel_events(
        &mut self,
        fd: &InotifyFd,
        decoded: &[DecodedInotifyEvent],
        out: &mut Vec<LogEvent>,
    ) {
        let mut touched_paths = BTreeSet::new();
        let mut overflow = false;

        for ev in decoded {
            if (ev.mask & nix::libc::IN_Q_OVERFLOW) != 0 {
                overflow = true;
                continue;
            }
            if let Some(path) = self.file_wds.get(&ev.wd).cloned() {
                if (ev.mask & nix::libc::IN_IGNORED) != 0 {
                    self.file_wds.remove(&ev.wd);
                    if self.path_to_file_wd.get(&path) == Some(&ev.wd) {
                        self.path_to_file_wd.remove(&path);
                    }
                }
                touched_paths.insert((
                    path,
                    (ev.mask & (nix::libc::IN_DELETE_SELF | nix::libc::IN_MOVE_SELF)) != 0,
                ));
                continue;
            }
            if let Some(dir) = self.dir_wds.get(&ev.wd)
                && let Some(ref name) = ev.name
            {
                let candidate = dir.join(name);
                if self
                    .dir_children
                    .get(dir)
                    .is_some_and(|children| children.contains(&candidate))
                {
                    let created = (ev.mask & (nix::libc::IN_CREATE | nix::libc::IN_MOVED_TO)) != 0;
                    touched_paths.insert((candidate, created));
                }
            }
        }

        if overflow {
            log_msg(
                LogLevel::Warning,
                "fail2ban.filter",
                "inotify event queue overflow; rescanning all watched paths",
            );
            let all_paths: Vec<PathBuf> = self.configs.keys().cloned().collect();
            for path in all_paths {
                self.process_path_event(fd, &path, true, out);
            }
            return;
        }

        for (path, refresh_watch) in touched_paths {
            self.process_path_event(fd, &path, refresh_watch, out);
        }
    }

    fn process_path_event(
        &mut self,
        fd: &InotifyFd,
        path: &Path,
        refresh_watch: bool,
        out: &mut Vec<LogEvent>,
    ) {
        if let Some(wf) = self.watched.get_mut(path) {
            wf.collect_events(out);
            if refresh_watch || !self.path_to_file_wd.contains_key(path) {
                self.register_file_watch(fd, path);
            }
        } else if let Some(cfg) = self.pending.get(path).cloned() {
            // File just created after startup -> read from offset 0.
            self.try_open_file(fd, cfg, Some(false), out);
        }
    }
}

fn read_inotify_batch(fd: RawFd, buf: &mut [u8]) -> io::Result<Vec<DecodedInotifyEvent>> {
    // SAFETY: `fd` is a valid non-blocking inotify fd and `buf` is valid writable memory of `buf.len()` bytes.
    let n = unsafe { nix::libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes_read = n as usize;
    decode_inotify_buffer(&buf[..bytes_read])
}

fn decode_inotify_buffer(slice: &[u8]) -> io::Result<Vec<DecodedInotifyEvent>> {
    let hdr_size = std::mem::size_of::<nix::libc::inotify_event>();
    let mut events = Vec::new();
    let mut offset = 0usize;

    while offset + hdr_size <= slice.len() {
        // SAFETY: `offset + hdr_size <= slice.len()` guarantees `hdr_size` readable bytes; `read_unaligned` handles arbitrary alignment.
        let raw = unsafe {
            std::ptr::read_unaligned(
                slice
                    .as_ptr()
                    .add(offset)
                    .cast::<nix::libc::inotify_event>(),
            )
        };
        let name_len = raw.len as usize;
        let Some(total) = hdr_size.checked_add(name_len) else {
            break;
        };
        if offset + total > slice.len() {
            break;
        }
        let name = if name_len > 0 {
            let name_bytes = &slice[offset + hdr_size..offset + total];
            let nul_pos = memchr::memchr(0, name_bytes).unwrap_or(name_bytes.len());
            if nul_pos > 0 {
                Some(PathBuf::from(OsStr::from_bytes(&name_bytes[..nul_pos])))
            } else {
                None
            }
        } else {
            None
        };
        events.push(DecodedInotifyEvent {
            wd: raw.wd,
            mask: raw.mask,
            name,
        });
        offset += total;
    }

    Ok(events)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "f2b_inotify_{name}_{}_{nanos}.log",
            std::process::id()
        ))
    }

    #[test]
    fn decode_inotify_buffer_parses_multiple_events() {
        let hdr_size = std::mem::size_of::<nix::libc::inotify_event>();
        // SAFETY: `inotify_event` is a C POD struct (`wd`, `mask`, `cookie`, `len`, trailing ZST name); zero-init is valid in test setup.
        let mut ev1: nix::libc::inotify_event = unsafe { std::mem::zeroed() };
        ev1.wd = 3;
        ev1.mask = nix::libc::IN_MODIFY;
        // SAFETY: Same C POD zero-init for second synthetic test event.
        let mut ev2: nix::libc::inotify_event = unsafe { std::mem::zeroed() };
        ev2.wd = 4;
        ev2.mask = nix::libc::IN_CREATE;
        ev2.len = 16;

        let mut raw = Vec::new();
        // SAFETY: `ev1` and `ev2` are plain C structs of `hdr_size` bytes with no uninitialized padding assumptions beyond raw serialization in tests.
        unsafe {
            raw.extend_from_slice(std::slice::from_raw_parts(
                (&ev1 as *const nix::libc::inotify_event).cast::<u8>(),
                hdr_size,
            ));
            raw.extend_from_slice(std::slice::from_raw_parts(
                (&ev2 as *const nix::libc::inotify_event).cast::<u8>(),
                hdr_size,
            ));
        }
        let mut name_buf = [0u8; 16];
        name_buf[..8].copy_from_slice(b"auth.log");
        raw.extend_from_slice(&name_buf);

        let parsed = decode_inotify_buffer(&raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].wd, 3);
        assert_eq!(parsed[0].mask, nix::libc::IN_MODIFY);
        assert!(parsed[0].name.is_none());
        assert_eq!(parsed[1].wd, 4);
        assert_eq!(parsed[1].mask, nix::libc::IN_CREATE);
        assert_eq!(parsed[1].name.as_deref(), Some(Path::new("auth.log")));
    }

    #[tokio::test]
    async fn inotify_streams_append_atomic_rotate_and_missing_creation() {
        let active_path = unique_temp_path("active");
        let rotated_old = unique_temp_path("rotated_old");
        let late_path = unique_temp_path("late");
        fs::write(&active_path, b"seed\n").unwrap();

        let backend = FilterPyinotify::with_pending_retry(
            vec![
                FileLogConfig {
                    path: active_path.clone(),
                    tail: false,
                    resume_fingerprint: None,
                    resume_offset: 0,
                    auto_seek: None,
                },
                FileLogConfig {
                    path: late_path.clone(),
                    tail: true,
                    resume_fingerprint: None,
                    resume_offset: 0,
                    auto_seek: None,
                },
            ],
            LogEncoding::Utf8,
            Duration::from_millis(50),
        );

        let (tx, mut rx) = mpsc::channel(64);
        let (shut_tx, shut_rx) = watch::channel(false);
        let task = tokio::spawn(async move { backend.run(tx, shut_rx).await });

        // Wait briefly for initial drain + inotify watches to settle.
        tokio::time::sleep(Duration::from_millis(40)).await;

        // 1. Live append
        {
            let mut f = fs::OpenOptions::new()
                .append(true)
                .open(&active_path)
                .unwrap();
            f.write_all(b"live_append\n").unwrap();
        }
        tokio::time::sleep(Duration::from_millis(40)).await;

        // 2. Atomic logrotate (rename + create new file)
        fs::rename(&active_path, &rotated_old).unwrap();
        fs::write(&active_path, b"after_rotate\n").unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;

        // 3. Create missing file
        fs::write(&late_path, b"late_created\n").unwrap();

        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while seen.len() < 4 && tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
                && let LogEvent::Line { line, .. } = ev
            {
                seen.push(line);
            }
        }

        let _ = shut_tx.send(true);
        task.await.unwrap().unwrap();

        assert!(seen.contains(&"seed".to_owned()), "seen={seen:?}");
        assert!(seen.contains(&"live_append".to_owned()), "seen={seen:?}");
        assert!(seen.contains(&"after_rotate".to_owned()), "seen={seen:?}");
        assert!(seen.contains(&"late_created".to_owned()), "seen={seen:?}");

        let _ = fs::remove_file(&active_path);
        let _ = fs::remove_file(&rotated_old);
        let _ = fs::remove_file(&late_path);
    }
}
