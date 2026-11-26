//! Pure-Rust Linux `inotify` log backend matching Fail2Ban 1.1.1
//! `fail2ban/server/filterpyinotify.py`.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::Interest;
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

const INOTIFY_DIR_MASK: u32 = nix::libc::IN_MODIFY
    | nix::libc::IN_ATTRIB
    | nix::libc::IN_MOVED_TO
    | nix::libc::IN_CREATE
    | nix::libc::IN_MOVE_SELF
    | nix::libc::IN_DELETE_SELF;

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
    /// Round-robin queue of paths with pending bounded read batches (`dirty_flags` tracks watch refresh).
    dirty_queue: VecDeque<PathBuf>,
    dirty_flags: BTreeMap<PathBuf, bool>,
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
            dirty_queue: VecDeque::new(),
            dirty_flags: BTreeMap::new(),
        }
    }

    fn enqueue_dirty(&mut self, path: PathBuf, refresh_watch: bool) {
        if let Some(existing) = self.dirty_flags.get_mut(&path) {
            *existing |= refresh_watch;
        } else {
            self.dirty_flags.insert(path.clone(), refresh_watch);
            self.dirty_queue.push_back(path);
        }
    }

    fn pop_dirty(&mut self) -> Option<(PathBuf, bool)> {
        let path = self.dirty_queue.pop_front()?;
        let refresh = self.dirty_flags.remove(&path).unwrap_or(false);
        Some((path, refresh))
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

        let initial_configs: Vec<FileLogConfig> = self.configs.values().cloned().collect();
        for cfg in initial_configs {
            self.register_dir_watch(async_fd.get_ref(), &cfg.path);
            self.try_open_file(async_fd.get_ref(), cfg, None);
        }

        let mut buf = vec![0u8; READ_BUF_BYTES];
        let pending_sleep = tokio::time::sleep(self.pending_retry);
        tokio::pin!(pending_sleep);
        let mut pending_armed = !self.pending.is_empty();

        loop {
            if *shutdown.borrow() {
                break;
            }

            if self.pending.is_empty() {
                pending_armed = false;
            } else if !pending_armed {
                pending_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + self.pending_retry);
                pending_armed = true;
            }

            if !self.dirty_queue.is_empty() {
                if pending_armed && tokio::time::Instant::now() >= pending_sleep.deadline() {
                    self.retry_pending(async_fd.get_ref());
                    pending_armed = !self.pending.is_empty();
                    if pending_armed {
                        pending_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + self.pending_retry);
                    }
                }
                if let Err(err) = async_fd.try_io(Interest::READABLE, |inner| {
                    loop {
                        match read_inotify_batch(inner.as_raw_fd(), &mut buf) {
                            Ok(decoded) if decoded.is_empty() => return Ok(()),
                            Ok(decoded) => self.handle_kernel_events(inner, &decoded),
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Err(err),
                            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                            Err(err) => return Err(err),
                        }
                    }
                }) && err.kind() != io::ErrorKind::WouldBlock
                {
                    return Err(Error::io("inotify read failed", err));
                }
                if let Some((path, refresh_watch)) = self.pop_dirty() {
                    let mut batch = Vec::new();
                    let has_more = self.collect_path_batch(
                        async_fd.get_ref(),
                        &path,
                        refresh_watch,
                        &mut batch,
                    );
                    if has_more {
                        self.enqueue_dirty(path, refresh_watch);
                    }
                    if !batch.is_empty() && !send_events(&tx, &mut shutdown, batch).await {
                        break;
                    }
                }
                continue;
            }

            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                () = &mut pending_sleep, if pending_armed => {
                    self.retry_pending(async_fd.get_ref());
                    pending_armed = !self.pending.is_empty();
                    if pending_armed {
                        pending_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + self.pending_retry);
                    }
                }
                ready_res = async_fd.readable() => {
                    let mut guard = match ready_res {
                        Ok(g) => g,
                        Err(err) => {
                            return Err(Error::io("inotify readable wait failed", err));
                        }
                    };

                    loop {
                        match read_inotify_batch(guard.get_inner().as_raw_fd(), &mut buf) {
                            Ok(decoded) if decoded.is_empty() => break,
                            Ok(decoded) => {
                                self.handle_kernel_events(guard.get_inner(), &decoded);
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
                }
            }
        }

        Ok(())
    }

    fn register_dir_watch(&mut self, fd: &InotifyFd, file_path: &Path) {
        let dir = watch_parent(file_path).to_owned();
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

    fn register_file_watch(&mut self, fd: &InotifyFd, file_path: &Path) -> bool {
        match fd.add_watch(file_path, INOTIFY_FILE_MASK) {
            Ok(wd) => {
                if let Some(prev_wd) = self.path_to_file_wd.insert(file_path.to_path_buf(), wd)
                    && prev_wd != wd
                {
                    self.file_wds.remove(&prev_wd);
                    fd.remove_watch(prev_wd);
                }
                self.file_wds.insert(wd, file_path.to_path_buf());
                true
            }
            Err(err) => {
                log_msg(
                    LogLevel::Debug,
                    "fail2ban.filter",
                    &format!("Cannot add inotify watch on {:?}: {err}", file_path),
                );
                false
            }
        }
    }

    fn refresh_file_watch(&mut self, fd: &InotifyFd, path: &Path) {
        if self.register_file_watch(fd, path) && self.dir_to_wd.contains_key(watch_parent(path)) {
            self.pending.remove(path);
        } else if let Some(cfg) = self.configs.get(path) {
            self.pending.insert(path.to_owned(), cfg.clone());
        }
    }

    fn try_open_file(
        &mut self,
        fd: &InotifyFd,
        cfg: FileLogConfig,
        tail_override: Option<bool>,
    ) -> bool {
        let path = cfg.path.clone();
        match WatchedFile::open(cfg.clone(), self.encoding, tail_override) {
            Ok(wf) => {
                self.watched.insert(path.clone(), wf);
                self.refresh_file_watch(fd, &path);
                self.enqueue_dirty(path, false);
                true
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
                false
            }
        }
    }

    fn retry_pending(&mut self, fd: &InotifyFd) {
        let pending_list: Vec<FileLogConfig> = self.pending.values().cloned().collect();
        for cfg in pending_list {
            self.register_dir_watch(fd, &cfg.path);
            if self.watched.contains_key(&cfg.path) {
                self.enqueue_dirty(cfg.path, true);
            } else {
                self.try_open_file(fd, cfg, Some(false));
            }
        }
    }

    fn handle_kernel_events(&mut self, fd: &InotifyFd, decoded: &[DecodedInotifyEvent]) {
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
            if ev.mask
                & (nix::libc::IN_MOVE_SELF | nix::libc::IN_DELETE_SELF | nix::libc::IN_IGNORED)
                != 0
                && let Some(dir) = self.dir_wds.remove(&ev.wd)
            {
                self.dir_to_wd.remove(&dir);
                if ev.mask & nix::libc::IN_IGNORED == 0 {
                    fd.remove_watch(ev.wd);
                }
                if let Some(paths) = self.dir_children.get(&dir) {
                    for path in paths {
                        if let Some(cfg) = self.configs.get(path) {
                            self.pending.insert(path.clone(), cfg.clone());
                        }
                    }
                }
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
                self.enqueue_dirty(path, true);
            }
            return;
        }

        for (path, refresh_watch) in touched_paths {
            self.enqueue_dirty(path, refresh_watch);
        }
    }

    fn collect_path_batch(
        &mut self,
        fd: &InotifyFd,
        path: &Path,
        refresh_watch: bool,
        out: &mut Vec<LogEvent>,
    ) -> bool {
        if let Some(wf) = self.watched.get_mut(path) {
            let has_more = wf.collect_events_batch(out);
            if !has_more && (refresh_watch || !self.path_to_file_wd.contains_key(path)) {
                self.refresh_file_watch(fd, path);
            }
            return has_more;
        }
        if let Some(cfg) = self.pending.get(path).cloned() {
            // File just created after startup -> open from offset 0, then drain first bounded batch.
            if self.try_open_file(fd, cfg, Some(false)) {
                // `try_open_file` queued `path`; pop it immediately and drain its first batch.
                let _ = self.dirty_flags.remove(path);
                self.dirty_queue.retain(|p| p != path);
                if let Some(wf) = self.watched.get_mut(path) {
                    return wf.collect_events_batch(out);
                }
            }
        }
        false
    }
}

fn watch_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
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
    async fn follows_replaced_parent_and_drains_old_file_once() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("logs");
        let moved = root.path().join("previous");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("service.log");
        fs::write(&path, "first\n").unwrap();
        let config = FileLogConfig {
            path: path.clone(),
            tail: false,
            resume_fingerprint: None,
            resume_offset: 0,
            auto_seek: None,
        };
        let backend = FilterPyinotify::with_pending_retry(
            vec![config],
            LogEncoding::Utf8,
            Duration::from_millis(30),
        );
        let (tx, mut rx) = mpsc::channel(32);
        let (shutdown, stop) = watch::channel(false);
        let task = tokio::spawn(backend.run(tx, stop));
        async fn next_line(rx: &mut mpsc::Receiver<LogEvent>) -> String {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let LogEvent::Line { line, .. } = rx.recv().await.unwrap() {
                        return line;
                    }
                }
            })
            .await
            .unwrap()
        }
        assert_eq!(next_line(&mut rx).await, "first");
        fs::rename(&parent, &moved).unwrap();
        let mut old = fs::OpenOptions::new()
            .append(true)
            .open(moved.join("service.log"))
            .unwrap();
        writeln!(old, "old tail").unwrap();
        assert_eq!(next_line(&mut rx).await, "old tail");
        fs::create_dir(&parent).unwrap();
        fs::write(&path, "replacement\n").unwrap();
        assert_eq!(next_line(&mut rx).await, "replacement");
        let mut current = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(current, "append").unwrap();
        assert_eq!(next_line(&mut rx).await, "append");
        shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
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

    #[tokio::test]
    async fn inotify_bounds_multi_batch_append_under_slow_consumer_and_resumes_from_checkpoint() {
        let path = unique_temp_path("backpressure");
        fs::write(&path, b"").unwrap();

        let total_lines = 2000usize;
        let expected: Vec<String> = (0..total_lines)
            .map(|i| {
                format!(
                    "1700000100 seq-{i:04}-padding-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                )
            })
            .collect();
        let mut payload = String::new();
        for line in &expected {
            payload.push_str(line);
            payload.push('\n');
        }

        // 1. Single multi-batch append delivered in order through a tiny channel (backpressure).
        let backend = FilterPyinotify::with_pending_retry(
            vec![FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint: None,
                resume_offset: 0,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
            Duration::from_millis(50),
        );
        let (tx, mut rx) = mpsc::channel(4);
        let (shut_tx, shut_rx) = watch::channel(false);
        let task = tokio::spawn(backend.run(tx, shut_rx));

        // Wait for initial empty-file checkpoint before appending all lines in one write.
        let init_ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(init_ev, LogEvent::Checkpoint { offset: 0, .. }));

        {
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(payload.as_bytes()).unwrap();
            f.flush().unwrap();
        }

        let mut received = Vec::with_capacity(total_lines);
        let mut eof_checkpoints = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while received.len() < total_lines && tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
            {
                match ev {
                    LogEvent::Line {
                        line, in_operation, ..
                    } => {
                        assert!(
                            in_operation,
                            "live multi-batch append must stay in_operation"
                        );
                        received.push(line);
                        if received.len() == 1 || received.len() % 500 == 0 {
                            // Slow consumer pacing: verifies producer makes forward progress across batches.
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    LogEvent::Checkpoint { .. } => eof_checkpoints += 1,
                }
            }
        }
        // Drain final EOF checkpoint.
        if let Ok(Some(LogEvent::Checkpoint { .. })) =
            tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
        {
            eof_checkpoints += 1;
        }
        let _ = shut_tx.send(true);
        task.await.unwrap().unwrap();

        assert_eq!(received, expected);
        assert_eq!(
            eof_checkpoints, 1,
            "multi-batch append must emit only one EOF checkpoint"
        );

        // 2. Shutdown mid-backlog under slow consumer, then resume from last consumed line checkpoint.
        let backend2 = FilterPyinotify::with_pending_retry(
            vec![FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint: None,
                resume_offset: 0,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
            Duration::from_millis(50),
        );
        let (tx2, mut rx2) = mpsc::channel(2);
        let (shut_tx2, shut_rx2) = watch::channel(false);
        let task2 = tokio::spawn(backend2.run(tx2, shut_rx2));

        let stop_after = 600usize;
        let mut first_part = Vec::with_capacity(stop_after);
        let mut last_cp: Option<(String, u64)> = None;
        while first_part.len() < stop_after {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
                .await
                .unwrap()
                .unwrap();
            if let LogEvent::Line {
                line,
                in_operation,
                checkpoint,
                ..
            } = ev
            {
                assert!(
                    !in_operation,
                    "cold-start catch-up must keep in_operation=false before EOF"
                );
                first_part.push(line);
                last_cp = checkpoint;
            }
        }
        let _ = shut_tx2.send(true);
        tokio::time::timeout(Duration::from_secs(2), task2)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let (resume_fp, resume_off) = last_cp.unwrap();
        assert!(!resume_fp.is_empty() && resume_off > 0);

        let backend3 = FilterPyinotify::with_pending_retry(
            vec![FileLogConfig {
                path: path.clone(),
                tail: false,
                resume_fingerprint: Some(resume_fp),
                resume_offset: resume_off,
                auto_seek: None,
            }],
            LogEncoding::Utf8,
            Duration::from_millis(50),
        );
        let (tx3, mut rx3) = mpsc::channel(4);
        let (shut_tx3, shut_rx3) = watch::channel(false);
        let task3 = tokio::spawn(backend3.run(tx3, shut_rx3));

        let mut remainder = Vec::with_capacity(total_lines - stop_after);
        while remainder.len() < total_lines - stop_after {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx3.recv())
                .await
                .unwrap()
                .unwrap();
            if let LogEvent::Line { line, .. } = ev {
                remainder.push(line);
            }
        }
        let _ = shut_tx3.send(true);
        task3.await.unwrap().unwrap();

        assert_eq!(first_part, expected[..stop_after]);
        assert_eq!(remainder, expected[stop_after..]);

        let _ = fs::remove_file(&path);
    }
}
