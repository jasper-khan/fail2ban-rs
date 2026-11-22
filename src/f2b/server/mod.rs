//! Fail2Ban server lifecycle and local command socket.

pub mod jail;
mod transmitter;
pub use transmitter::Transmitter;

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::stat::{Mode, umask};
use nix::unistd::{ForkResult, dup2, fork, pipe, setsid};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout};

use crate::VERSION;
use crate::client::beautifier::py_repr;
use crate::client::{CliAction, DumpMode, Fail2banClient, parse_cli};
use crate::error::{Error, Result};
use crate::f2b_log;
use crate::logging::{self, LogLevel};
use crate::protocol::{
    DEFAULT_TIMEOUT, PickleValue, decode_pickle, encode_frame, err_response_kind, ok_response,
    read_frame,
};

pub fn run_cli(args: Vec<String>) -> i32 {
    let Ok(CliAction::Run(opts, command)) = parse_cli(&args) else {
        return crate::client::run_cli_as(args, true);
    };
    if opts.interactive
        || opts.test
        || opts.dump != DumpMode::None
        || (!command.is_empty() && command != ["start"])
    {
        return crate::client::run_cli_as(args, true);
    }
    match launch(Fail2banClient::new(opts), &command) {
        Ok(()) => 0,
        Err(err) => {
            f2b_log!(LogLevel::Error, "fail2ban.server", "{err}");
            255
        }
    }
}

fn launch(mut client: Fail2banClient, command: &[String]) -> Result<()> {
    client.resolve_early(command)?;
    let config = if client.opts.async_mode {
        None
    } else {
        Some(client.read_config(None, false)?)
    };
    let socket =
        std::path::absolute(client.socket_path()).map_err(|e| Error::io("socket path", e))?;
    let pidfile =
        std::path::absolute(client.pidfile_path()).map_err(|e| Error::io("pidfile path", e))?;
    let inherited = inherited_listener().map_err(|e| Error::io("socket activation", e))?;
    umask(Mode::from_bits_truncate(0o077));
    let mut ready = if client.opts.background {
        Some(daemonize().map_err(|e| Error::io("starting in daemon mode", e))?)
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    if let Ok(name) =
        std::ffi::CString::new(client.opts.pname.as_deref().unwrap_or("fail2ban-server"))
    {
        let _ = nix::sys::prctl::set_name(&name);
    }
    if let Err(err) = init_logging(&client) {
        notify_daemon_parent(&mut ready, Err(&err));
        return Err(err);
    }
    f2b_log!(
        LogLevel::Info,
        "fail2ban.server",
        "Starting Fail2ban v{VERSION}"
    );
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    // shortcut: ignore stack sizes below 1 MiB for Tokio workers to prevent Rust regex stack overflows; upgrade if smaller worker stacks are required.
    if let Some(kib) = config.as_deref().and_then(initial_thread_stacksize_kib)
        && kib >= 1024
        && let Some(bytes) = usize::try_from(kib).ok().and_then(|k| k.checked_mul(1024))
    {
        builder.thread_stack_size(bytes);
    }
    let runtime = match builder
        .build()
        .map_err(|e| Error::io("creating server runtime", e))
    {
        Ok(rt) => rt,
        Err(err) => {
            notify_daemon_parent(&mut ready, Err(&err));
            return Err(err);
        }
    };
    runtime.block_on(serve(
        &socket,
        &pidfile,
        client.opts.force,
        inherited,
        config,
        ready,
    ))
}

fn init_logging(client: &Fail2banClient) -> Result<()> {
    logging::set_syslog_socket(client.syslogsocket().to_owned())?;
    logging::set_level(LogLevel::parse(client.loglevel())?);
    logging::set_target(client.logtarget())?;
    Ok(())
}

fn notify_daemon_parent(ready: &mut Option<File>, status: std::result::Result<(), &Error>) {
    if let Some(mut pipe_tx) = ready.take() {
        let _ = match status {
            Ok(()) => pipe_tx.write_all(b"OK"),
            Err(err) => pipe_tx.write_all(err.to_string().as_bytes()),
        };
    }
}

fn initial_thread_stacksize_kib(commands: &[PickleValue]) -> Option<i64> {
    let mut stacksize = None;
    for frame in commands {
        let Some(items) = frame.as_list() else {
            continue;
        };
        if items.first().and_then(PickleValue::as_str) != Some("set")
            || items.get(1).and_then(PickleValue::as_str) != Some("thread")
        {
            continue;
        }
        if let Some(PickleValue::Dict(opts)) = items.get(2) {
            for (k, v) in opts {
                if k.as_str() == Some("stacksize")
                    && let Some(n) = v.as_i64()
                {
                    stacksize = Some(n);
                }
            }
        }
    }
    stacksize
}

#[allow(unsafe_code)]
fn daemonize() -> io::Result<File> {
    let (read_fd, mut write_fd) = pipe().map_err(io::Error::from)?;
    // SAFETY: The process is single-threaded before the Tokio runtime exists.
    if let ForkResult::Parent { .. } = unsafe { fork()? } {
        drop(write_fd);
        let mut msg = Vec::new();
        let _ = File::from(read_fd).read_to_end(&mut msg);
        if msg == b"OK" {
            std::process::exit(0);
        }
        let detail = String::from_utf8_lossy(&msg);
        if !detail.trim().is_empty() {
            f2b_log!(LogLevel::Error, "fail2ban.server", "{detail}");
        }
        std::process::exit(255);
    }
    drop(read_fd);
    setsid()?;
    // SAFETY: The first child has not started any threads since the first fork.
    if let ForkResult::Parent { .. } = unsafe { fork()? } {
        std::process::exit(0);
    }
    if write_fd.as_raw_fd() <= 2 {
        let moved =
            fcntl(write_fd.as_raw_fd(), FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(io::Error::from)?;
        // SAFETY: `F_DUPFD_CLOEXEC` returned a fresh owned descriptor >= 3.
        write_fd = unsafe { OwnedFd::from_raw_fd(moved) };
    } else {
        fcntl(write_fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(io::Error::from)?;
    }
    std::env::set_current_dir("/")?;
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in 0..=2 {
        dup2(null.as_raw_fd(), fd)?;
    }
    Ok(File::from(write_fd))
}

#[allow(unsafe_code)]
fn inherited_listener() -> io::Result<Option<StdUnixListener>> {
    let pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    if pid != Some(std::process::id()) {
        return Ok(None);
    }
    let count = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|s| s.parse::<i32>().ok());
    let Some(count) = count.filter(|count| *count > 0) else {
        return Ok(None);
    };
    let index = std::env::var("LISTEN_FDNAMES")
        .ok()
        .and_then(|names| names.split(':').position(|name| name == "fail2ban"))
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(0)
        .min(count - 1);
    let fd = 3_i32
        .checked_add(index)
        .ok_or(io::ErrorKind::InvalidInput)?;
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    // SAFETY: systemd passed this descriptor and fcntl verified it is open.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if !nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::AcceptConn)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inherited socket is not listening",
        ));
    }
    let listener = StdUnixListener::from(fd);
    listener.local_addr()?;
    listener.set_nonblocking(true)?;
    Ok(Some(listener))
}

async fn serve(
    socket: &Path,
    pidfile: &Path,
    force: bool,
    inherited: Option<StdUnixListener>,
    config: Option<Vec<PickleValue>>,
    mut ready: Option<File>,
) -> Result<()> {
    let mut terminate = signal(SignalKind::terminate()).map_err(|e| Error::io("SIGTERM", e))?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|e| Error::io("SIGINT", e))?;
    let mut reopen_logs =
        signal(SignalKind::user_defined1()).map_err(|e| Error::io("SIGUSR1", e))?;
    let (listener, _socket_guard) = match bind(socket, force, inherited)
        .await
        .map_err(|e| Error::io(format!("opening socket {}", socket.display()), e))
    {
        Ok(pair) => pair,
        Err(err) => {
            notify_daemon_parent(&mut ready, Err(&err));
            return Err(err);
        }
    };
    let _pid_guard = match write_pidfile(pidfile) {
        Ok(guard) => Some(guard),
        Err(err) => {
            f2b_log!(
                LogLevel::Error,
                "fail2ban.server",
                "Unable to create PID file: {err}"
            );
            None
        }
    };

    let mut server = Transmitter::default();
    if let Some(config) = config
        && let Err(err) = server.stream(&config).await
    {
        let _ = server.stop_all().await;
        notify_daemon_parent(&mut ready, Err(&err));
        return Err(err);
    }
    notify_daemon_parent(&mut ready, Ok(()));
    let server = Arc::new(Mutex::new(server));
    let stopped = Arc::new(Notify::new());
    let mut connections = JoinSet::new();
    let mut purge = interval(Duration::from_secs(60));
    let result = loop {
        tokio::select! {
            _ = stopped.notified() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = reopen_logs.recv() => {
                if let Err(err) = logging::flush_logs() {
                    f2b_log!(LogLevel::Error, "fail2ban.server", "{err}");
                }
            }
            _ = purge.tick() => server.lock().await.purge(),
            _ = connections.join_next(), if !connections.is_empty() => {}
            incoming = listener.accept() => match incoming {
                Ok((stream, _)) => {
                    connections.spawn(connection(stream, Arc::clone(&server), Arc::clone(&stopped)));
                }
                Err(err) => break Err(Error::io("accepting socket connection", err)),
            },
        }
    };
    drop(listener);
    let shutdown = server.lock().await.stop_all().await;
    connections.shutdown().await;
    result.and(shutdown)
}

async fn connection(mut stream: UnixStream, server: Arc<Mutex<Transmitter>>, stopped: Arc<Notify>) {
    let mut pending = Vec::new();
    while let Ok(Some(data)) = read_frame(&mut stream, &mut pending, DEFAULT_TIMEOUT).await {
        let (reply, shutting_down) = {
            let mut server = server.lock().await;
            let response = match decode_pickle(&data) {
                Ok(value) => server.dispatch(&value).await,
                Err(error) => Err(error),
            };
            let reply = match response {
                Ok(value) => ok_response(value),
                Err(Error::UnknownJail(name)) => err_response_kind("UnknownJailException", name),
                Err(Error::DuplicateJail(name)) => {
                    err_response_kind("DuplicateJailException", name)
                }
                Err(Error::Value(message)) => err_response_kind("ValueError", message),
                Err(Error::Key(message)) => err_response_kind("KeyError", message),
                Err(Error::Type(message)) => err_response_kind("TypeError", message),
                Err(Error::LogPath { path, source }) => {
                    let kind = match source.kind() {
                        io::ErrorKind::NotFound => "FileNotFoundError",
                        io::ErrorKind::PermissionDenied => "PermissionError",
                        io::ErrorKind::IsADirectory => "IsADirectoryError",
                        _ => "OSError",
                    };
                    let errno = source.raw_os_error().unwrap_or(0);
                    let detail = source.to_string();
                    let detail = detail
                        .strip_suffix(&format!(" (os error {errno})"))
                        .unwrap_or(&detail);
                    let path = py_repr(&PickleValue::Str(path.to_string_lossy().into_owned()));
                    err_response_kind(kind, format!("[Errno {errno}] {detail}: {path}"))
                }
                Err(err) => err_response_kind("Exception", err.to_string()),
            };
            (reply, server.stopping)
        };
        let write = timeout(DEFAULT_TIMEOUT, stream.write_all(&encode_frame(&reply))).await;
        if shutting_down {
            stopped.notify_one();
            break;
        }
        if !matches!(write, Ok(Ok(()))) {
            break;
        }
    }
}

async fn bind(
    path: &Path,
    force: bool,
    inherited: Option<StdUnixListener>,
) -> io::Result<(UnixListener, Option<OwnedPath>)> {
    if let Some(listener) = inherited {
        return Ok((UnixListener::from_std(listener)?, None));
    }
    make_parent(path)?;
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(err) if force && err.kind() == io::ErrorKind::AddrInUse => {
            let prior = fs::symlink_metadata(path)?;
            if !prior.file_type().is_socket()
                || !matches!(
                    timeout(Duration::from_millis(250), UnixStream::connect(path)).await,
                    Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused
                )
                || !same_file(&prior, &fs::symlink_metadata(path)?)
            {
                return Err(err);
            }
            fs::remove_file(path)?;
            UnixListener::bind(path)?
        }
        Err(err) => return Err(err),
    };
    Ok((
        listener,
        Some(OwnedPath(path.to_owned(), fs::symlink_metadata(path)?)),
    ))
}

fn make_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_pidfile(path: &Path) -> io::Result<OwnedPath> {
    make_parent(path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let guard = OwnedPath(path.to_owned(), file.metadata()?);
    writeln!(file, "{}", std::process::id())?;
    Ok(guard)
}

struct OwnedPath(PathBuf, Metadata);

impl Drop for OwnedPath {
    fn drop(&mut self) {
        if let Ok(current) = fs::symlink_metadata(&self.0)
            && same_file(&self.1, &current)
        {
            let _ = fs::remove_file(&self.0);
        }
    }
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
