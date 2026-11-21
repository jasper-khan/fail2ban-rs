//! Unix socket control listener for CLI commands.
//!
//! Protocol: `[4-byte LE length][JSON payload]`
//! Used by the CLI to query status, ban/unban IPs, and trigger reloads.

use std::io;
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};

/// Maximum size of a request payload the daemon will read (64 KiB).
/// Requests are tiny commands; anything larger is malformed or hostile.
pub const MAX_REQUEST_BYTES: u32 = 64 * 1024;

/// Maximum size of a response payload (16 MiB).
///
/// Responses can legitimately be large (`list-bans` grows with every active
/// ban, roughly 120 bytes each, so ~130k bans fit). The client refuses any
/// advertised length above this to bound allocation against a malformed or
/// compromised peer, and the daemon refuses to send a response above it,
/// substituting a clear error instead.
pub const MAX_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;

/// Commands from the CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Get overall status.
    Status,
    /// List all active bans.
    ListBans,
    /// Ban an IP in a specific jail.
    Ban { ip: IpAddr, jail: String },
    /// Unban an IP from a specific jail.
    Unban { ip: IpAddr, jail: String },
    /// Reload configuration.
    Reload,
    /// Get daemon statistics.
    Stats,
}

/// Response from the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self::Ok {
            message: Some(message.into()),
            data: None,
        }
    }

    pub fn ok_data(data: serde_json::Value) -> Self {
        Self::Ok {
            message: None,
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// A control command with a response channel.
pub struct ControlCmd {
    pub request: Request,
    pub respond: oneshot::Sender<Response>,
}

/// Record the filesystem identity of the listener, so shutdown only unlinks
/// the socket this instance acquired, never a replacement at the same path.
pub(crate) struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        if socket_identity(&self.path).ok() == Some(self.identity)
            && let Err(e) = std::fs::remove_file(&self.path)
        {
            debug!(error = %e, "control socket remove failed");
        }
    }
}

fn socket_identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "control path is not a socket owned by the effective user",
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn bind_socket(path: &Path) -> io::Result<BoundSocket> {
    let listener = UnixListener::bind(path)?;
    let socket = BoundSocket {
        listener,
        path: path.to_path_buf(),
        identity: socket_identity(path)?,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(socket)
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    // Don't follow a symlink at the runtime or WAL path, or chmod or
    // migrate an unexpected file out of our way.
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recording runtime and WAL paths must be owner-only (0700) directories",
        ));
    }
    Ok(())
}

/// Compatibility mode acquires the isolated socket before opening the WAL.
/// Binding refuses any existing entry, including stale sockets: an operator
/// must first verify that a previous recording instance is stopped.
pub(crate) fn bind_recording(socket_path: &Path, state_dir: &Path) -> Result<BoundSocket> {
    let parent = socket_path
        .parent()
        .filter(|path| state_dir.parent() == Some(*path))
        .ok_or_else(|| Error::config("recording socket and WAL must share a runtime directory"))?;
    let annotate = |e| Error::io(format!("opening recording runtime {}", parent.display()), e);
    ensure_private_dir(parent).map_err(annotate)?;
    let bound = bind_socket(socket_path).map_err(annotate)?;
    ensure_private_dir(state_dir).map_err(annotate)?;
    Ok(bound)
}

/// Prepare the classic TOML-mode parent as before. Only reclaim an owned
/// socket if a bounded connection probe confirms the listener is gone.
async fn prepare_modern_path(socket_path: &Path) -> io::Result<()> {
    if let Some(parent) = socket_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
        if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)) {
            warn!(phase = "startup", error = %e, "control socket parent dir permissions failed");
        }
    }
    let identity = match socket_identity(socket_path) {
        Ok(identity) => identity,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let probe = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        tokio::net::UnixStream::connect(socket_path),
    )
    .await;
    if matches!(probe, Ok(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionRefused)
        && socket_identity(socket_path)? == identity
    {
        return std::fs::remove_file(socket_path);
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "control socket already exists",
    ))
}

/// Run the control socket listener for a classic TOML configuration.
pub async fn run(socket_path: &Path, tx: mpsc::Sender<ControlCmd>, cancel: CancellationToken) {
    match prepare_modern_path(socket_path)
        .await
        .and_then(|()| bind_socket(socket_path))
    {
        Ok(bound) => run_bound(bound, tx, cancel).await,
        Err(e) => {
            error!(
                phase = "startup",
                path = %socket_path.display(),
                error = %e,
                "control socket bind failed"
            );
        }
    }
}

pub(crate) async fn run_bound(
    socket: BoundSocket,
    tx: mpsc::Sender<ControlCmd>,
    cancel: CancellationToken,
) {
    info!(
        phase = "startup",
        path = %socket.path.display(),
        "control socket listening"
    );
    accept_loop(&socket.listener, &tx, &cancel).await;
    info!(phase = "shutdown", "control socket stopping");
}

/// Accept connections until cancelled, serving each on its own task.
async fn accept_loop(
    listener: &UnixListener,
    tx: &mpsc::Sender<ControlCmd>,
    cancel: &CancellationToken,
) {
    loop {
        let accept = tokio::select! {
            () = cancel.cancelled() => return,
            accept = listener.accept() => accept,
        };
        match accept {
            Ok((stream, _)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, tx).await {
                        warn!(error = %e, "control connection error");
                    }
                });
            }
            Err(e) => warn!(error = %e, "accept error"),
        }
    }
}

/// Reject connections from peers that are neither `root` nor the daemon's own
/// effective UID. Prevents an unprivileged local user with directory access
/// from driving the control socket. Linux-only (uses `SO_PEERCRED`); a no-op on
/// other platforms, where the daemon is not run in production.
#[cfg(target_os = "linux")]
fn check_peer_cred(stream: &tokio::net::UnixStream) -> Result<()> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let cred = getsockopt(stream, PeerCredentials)
        .map_err(|e| Error::protocol(format!("peer credential lookup failed: {e}")))?;
    let peer_uid = cred.uid();
    let my_uid = nix::unistd::geteuid().as_raw();
    if peer_uid != 0 && peer_uid != my_uid {
        warn!(
            peer_uid,
            daemon_uid = my_uid,
            "control socket: rejecting unauthorized peer"
        );
        return Err(Error::protocol(format!(
            "unauthorized control peer uid {peer_uid}"
        )));
    }
    Ok(())
}

/// Serve one control connection: read a request frame, forward it to the
/// daemon, and write the response frame.
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    tx: mpsc::Sender<ControlCmd>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    check_peer_cred(&stream)?;

    let buf = read_frame(&mut stream, MAX_REQUEST_BYTES, "message", "payload").await?;
    let request: Request =
        serde_json::from_slice(&buf).map_err(|e| Error::protocol(format!("parse request: {e}")))?;

    let (resp_tx, resp_rx) = oneshot::channel();
    let cmd = ControlCmd {
        request,
        respond: resp_tx,
    };
    tx.send(cmd)
        .await
        .map_err(|_| Error::protocol("handler channel closed"))?;
    let response = resp_rx
        .await
        .map_err(|_| Error::protocol("response channel dropped"))?;

    let json = encode_response(&response)?;
    write_frame(&mut stream, &json).await
}

/// Read one `[u32 LE length][payload]` frame, rejecting a declared length
/// above `max` before allocating. `what` names the frame in the size error
/// ("{what} too large"); `part` names it in read errors.
async fn read_frame(
    stream: &mut tokio::net::UnixStream,
    max: u32,
    what: &str,
    part: &str,
) -> Result<Vec<u8>> {
    let len = stream
        .read_u32_le()
        .await
        .map_err(|e| Error::protocol(format!("read {part} length: {e}")))?;
    if len > max {
        return Err(Error::protocol(format!("{what} too large: {len}")));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read {part}: {e}")))?;
    Ok(buf)
}

/// Serialize a response, replacing it with an error response when it would
/// exceed [`MAX_RESPONSE_BYTES`] so the client gets a clear message instead
/// of a frame it must reject.
pub(crate) fn encode_response(response: &Response) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(response)
        .map_err(|e| Error::protocol(format!("serialize response: {e}")))?;
    if json.len() <= MAX_RESPONSE_BYTES as usize {
        return Ok(json);
    }
    warn!(
        size = json.len(),
        limit = MAX_RESPONSE_BYTES,
        "control response exceeds size limit, sending error instead"
    );
    let err = Response::error(format!(
        "response too large: {} bytes exceeds limit of {MAX_RESPONSE_BYTES} bytes",
        json.len()
    ));
    serde_json::to_vec(&err).map_err(|e| Error::protocol(format!("serialize response: {e}")))
}

/// Write one `[u32 LE length][payload]` frame.
async fn write_frame(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::protocol(format!("frame too large: {}", payload.len())))?;
    stream
        .write_u32_le(len)
        .await
        .map_err(|e| Error::protocol(format!("write length: {e}")))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| Error::protocol(format!("write payload: {e}")))?;
    Ok(())
}

/// Send a request to the daemon control socket and return the response.
pub async fn send_request(socket_path: &Path, request: &Request) -> Result<Response> {
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| Error::protocol(format!("connect to {}: {e}", socket_path.display())))?;

    let json = serde_json::to_vec(request)
        .map_err(|e| Error::protocol(format!("serialize request: {e}")))?;
    write_frame(&mut stream, &json).await?;

    // Cap the daemon-supplied length so a compromised or buggy daemon cannot
    // make the client allocate unbounded memory. Responses get a larger bound
    // than requests because list-bans scales with the number of active bans.
    let buf = read_frame(&mut stream, MAX_RESPONSE_BYTES, "response", "response").await?;
    serde_json::from_slice(&buf).map_err(|e| Error::protocol(format!("parse response: {e}")))
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "control_test.rs"]
mod control_test;
