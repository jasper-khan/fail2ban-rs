//! Upstream Fail2Ban 1.1.1 Unix socket protocol (`CSocket` pickle framing).
//!
//! Speaks the exact wire format used by upstream `fail2ban-client` (`csocket.py`):
//! - Request: a bounded, data-only subset of Python pickle protocols 2–5 +
//!   `<F2B_END_COMMAND>`. Plain reload rereads this daemon's local configuration;
//!   the client's nested command stream is never interpreted or executed.
//! - Response: Python pickle (protocol 2) of `(0, result)` or `(1, Exception(msg))` + `<F2B_END_COMMAND>`
//! - Close sentinel: `<F2B_CLOSE_COMMAND><F2B_END_COMMAND>`

use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::control::{ControlCmd, Request, Response};
use crate::error::{Error, Result};

const F2B_END: &[u8] = b"<F2B_END_COMMAND>";
const F2B_CLOSE: &[u8] = b"<F2B_CLOSE_COMMAND>";
const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 32;
const MAX_ITEMS: usize = 8_192;
const MAX_DEPTH: u8 = 8;
const MAX_COMMAND_ARGS: usize = 512;
const MAX_COMMAND_TEXT: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// A value that can be encoded into Python pickle protocol 2 for `fail2ban-client`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickleVal {
    None,
    Int(i64),
    Str(String),
    List(Vec<Self>),
    Tuple2(Box<Self>, Box<Self>),
    Exception(String),
}

/// Encode `val` in Python pickle protocol 2 (universally accepted by Python 3 `pickle.loads`).
pub fn encode_pickle_v2(val: &PickleVal) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.push(0x80); // PROTO
    out.push(0x02); // version 2
    write_val(&mut out, val);
    out.push(b'.'); // STOP
    out
}

fn write_val(out: &mut Vec<u8>, val: &PickleVal) {
    match val {
        PickleVal::None => out.push(b'N'),
        PickleVal::Int(n) => {
            if let Ok(u) = u8::try_from(*n) {
                out.push(b'K');
                out.push(u);
            } else if let Ok(u) = u16::try_from(*n) {
                out.push(b'M');
                out.extend_from_slice(&u.to_le_bytes());
            } else if let Ok(i) = i32::try_from(*n) {
                out.push(b'J');
                out.extend_from_slice(&i.to_le_bytes());
            } else {
                // LONG1
                let bytes = n.to_le_bytes();
                out.push(0x8a);
                out.push(bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
        }
        PickleVal::Str(s) => {
            let bytes = s.as_bytes();
            out.push(b'X'); // BINUNICODE (4-byte LE length)
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        PickleVal::List(items) => {
            out.push(b']'); // EMPTY_LIST
            if !items.is_empty() {
                out.push(b'('); // MARK
                for item in items {
                    write_val(out, item);
                }
                out.push(b'e'); // APPENDS
            }
        }
        PickleVal::Tuple2(a, b) => {
            write_val(out, a);
            write_val(out, b);
            out.push(0x86); // TUPLE2
        }
        PickleVal::Exception(msg) => {
            // builtins.Exception(msg)
            out.extend_from_slice(b"cbuiltins\nException\n");
            write_val(out, &PickleVal::Str(msg.clone()));
            out.push(0x85); // TUPLE1
            out.push(b'R'); // REDUCE
        }
    }
}

/// Decode only the data structures needed by the supported client commands.
/// Nested data is accepted only for a whole-daemon options-free reload.
pub fn decode_command_pickle(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::config("legacy frame exceeds byte limit"));
    }
    let mut input = PickleInput { bytes, pos: 0 };
    let mut stack = Vec::new();
    // Memoized scalars share their text instead of cloning it repeatedly.
    // List memo entries occupy their index but cannot be re-referenced.
    let mut memo: Vec<Option<Arc<str>>> = Vec::new();
    if input.byte()? != 0x80 || !matches!(input.byte()?, 2..=5) {
        return Err(Error::config("unsupported legacy pickle protocol"));
    }
    while input.pos < bytes.len() {
        if stack.len() > MAX_ITEMS || memo.len() > MAX_ITEMS {
            return Err(Error::config("legacy pickle exceeds its item limit"));
        }
        let op = input.byte()?;
        match op {
            0x95 => {
                let len = usize::try_from(u64::from_le_bytes(input.array()?))
                    .map_err(|_| Error::config("legacy pickle frame too large"))?;
                if len > bytes.len().saturating_sub(input.pos) {
                    return Err(Error::config("truncated legacy pickle frame"));
                }
            }
            b']' => stack.push(StackItem::List(Vec::new(), 1)),
            b'(' => stack.push(StackItem::Mark),
            b'N' | 0x88 | 0x89 => stack.push(StackItem::Scalar),
            b'K' => {
                input.byte()?;
                stack.push(StackItem::Scalar);
            }
            b'M' => {
                input.take(2)?;
                stack.push(StackItem::Scalar);
            }
            b'J' => {
                input.take(4)?;
                stack.push(StackItem::Scalar);
            }
            b'G' => {
                input.take(8)?;
                stack.push(StackItem::Scalar);
            }
            0x8a => {
                let len = usize::from(input.byte()?);
                input.take(len)?;
                stack.push(StackItem::Scalar);
            }
            0x8c | b'X' | 0x8d => {
                let len = match op {
                    0x8c => usize::from(input.byte()?),
                    b'X' => u32::from_le_bytes(input.array()?) as usize,
                    _ => usize::try_from(u64::from_le_bytes(input.array()?))
                        .map_err(|_| Error::config("legacy pickle string too large"))?,
                };
                let text = std::str::from_utf8(input.take(len)?)
                    .map_err(|_| Error::config("invalid legacy pickle text encoding"))?;
                stack.push(StackItem::Str(Arc::from(text)));
            }
            0x94 | b'q' | b'r' => {
                let index = match op {
                    0x94 => memo.len(),
                    b'q' => usize::from(input.byte()?),
                    _ => u32::from_le_bytes(input.array()?) as usize,
                };
                if index >= MAX_ITEMS {
                    return Err(Error::config("legacy pickle memo index exceeds its bound"));
                }
                let value = match stack.last() {
                    Some(StackItem::Str(text)) => Some(Arc::clone(text)),
                    Some(StackItem::List(..) | StackItem::Scalar) => None,
                    _ => return Err(Error::config("legacy pickle memo has no value")),
                };
                if memo.len() <= index {
                    memo.resize(index + 1, None);
                }
                if let Some(entry) = memo.get_mut(index) {
                    *entry = value;
                }
            }
            b'h' | b'j' => {
                let index = if op == b'h' {
                    usize::from(input.byte()?)
                } else {
                    u32::from_le_bytes(input.array()?) as usize
                };
                let value = memo
                    .get(index)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| Error::config("unsupported legacy pickle memo reference"))?;
                stack.push(StackItem::Str(Arc::clone(value)));
            }
            b'a' | b'e' => {
                let mut data = Vec::new();
                if op == b'a' {
                    let value = stack
                        .pop()
                        .ok_or_else(|| Error::config("empty legacy append"))?;
                    if matches!(value, StackItem::Mark) {
                        return Err(Error::config("legacy pickle append has no value"));
                    }
                    data.push(value);
                } else {
                    let index = stack
                        .iter()
                        .rposition(|v| matches!(v, StackItem::Mark))
                        .ok_or_else(|| Error::config("legacy pickle append group has no marker"))?;
                    data.extend(stack.drain(index + 1..));
                    stack.pop();
                }
                let Some(StackItem::List(items, depth)) = stack.last_mut() else {
                    return Err(Error::config("legacy pickle append target is not a list"));
                };
                *depth = data.iter().fold(*depth, |d, item| match item {
                    StackItem::List(_, nested) => d.max(nested + 1),
                    StackItem::Mark | StackItem::Scalar | StackItem::Str(_) => d,
                });
                if *depth > MAX_DEPTH || items.len().saturating_add(data.len()) > MAX_ITEMS {
                    return Err(Error::config("legacy pickle list exceeds its bounds"));
                }
                items.extend(data);
            }
            b'.' => {
                return match stack.as_slice() {
                    [StackItem::List(list, _)] if input.pos == bytes.len() => command_args(list),
                    _ => Err(Error::config(
                        "legacy pickle must contain exactly one command list",
                    )),
                };
            }
            _ => return Err(Error::config("unsupported legacy pickle value")),
        }
    }
    Err(Error::config("unterminated legacy pickle stream"))
}

fn command_args(list: &[StackItem]) -> Result<Vec<String>> {
    if let [
        StackItem::Str(cmd),
        StackItem::Str(target),
        StackItem::List(options, _),
        StackItem::List(..),
    ] = list
        && cmd.as_ref() == "reload"
    {
        if target.as_ref() == "--all" && options.is_empty() {
            return Ok(vec!["reload".to_owned()]);
        }
        return Err(Error::config(
            "only a whole-daemon reload without options is supported",
        ));
    }
    if list.len() > MAX_COMMAND_ARGS {
        return Err(Error::config("legacy command has too many arguments"));
    }
    let mut total = 0_usize;
    list.iter()
        .map(|item| {
            let StackItem::Str(text) = item else {
                return Err(Error::config("legacy command argument must be text"));
            };
            total = total.saturating_add(text.len());
            if total > MAX_COMMAND_TEXT {
                return Err(Error::config("legacy command exceeds its text limit"));
            }
            Ok(text.to_string())
        })
        .collect()
}

enum StackItem {
    Mark,
    Scalar,
    Str(Arc<str>),
    List(Vec<Self>, u8),
}

struct PickleInput<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PickleInput<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::config("legacy pickle invalid length"))?;
        let field = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| Error::config("truncated legacy pickle"))?;
        self.pos = end;
        Ok(field)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::config("legacy pickle invalid field"))
    }

    fn byte(&mut self) -> Result<u8> {
        self.array::<1>().map(|[one]| one)
    }
}

/// An exclusively bound administrative endpoint with ownership-aware cleanup.
pub(crate) struct BoundLegacySocket {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl Drop for BoundLegacySocket {
    fn drop(&mut self) {
        if socket_identity(&self.path).ok() == Some(self.identity)
            && let Err(error) = fs::remove_file(&self.path)
        {
            warn!(path = %self.path.display(), %error, "legacy socket cleanup failed");
        }
    }
}

fn socket_identity(path: &Path) -> io::Result<(u64, u64)> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "expected an owned socket",
        ));
    }
    Ok((meta.dev(), meta.ino()))
}

fn resolved_endpoint(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "legacy socket requires a filename")
    })?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "legacy socket requires a directory",
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok(fs::canonicalize(parent)?.join(name))
}

/// Fail closed on path collisions, untrusted directories or existing nodes.
/// The operator must explicitly clear an old verified socket before reuse.
pub(crate) fn bind_legacy_socket(path: &Path, native: &Path) -> Result<BoundLegacySocket> {
    let path = validate_legacy_socket_path(path)?;
    let error = |err| {
        Error::io(
            format!("binding legacy control socket {}", path.display()),
            err,
        )
    };
    let parent = path
        .parent()
        .ok_or_else(|| Error::config("legacy socket must have a directory"))?;
    let uid = nix::unistd::geteuid().as_raw();
    let direct = fs::symlink_metadata(parent).map_err(error)?;
    if !direct.is_dir() || direct.uid() != uid || direct.mode() & 0o022 != 0 {
        return Err(Error::config(
            "legacy socket parent must be a service-owned directory not writable by other users",
        ));
    }
    let resolved = resolved_endpoint(&path).map_err(error)?;
    // Check ownership all the way down the resolved path. The only accepted
    // writable ancestors are trusted sticky dirs, e.g. /tmp containing a
    // service-owned, non-writable runtime directory.
    if let Some(parent) = resolved.parent() {
        for ancestor in parent.ancestors() {
            let meta = fs::symlink_metadata(ancestor).map_err(error)?;
            let trusted = meta.uid() == 0 || meta.uid() == uid;
            let protected = meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0;
            if !meta.is_dir() || !trusted || !protected {
                return Err(Error::config(
                    "legacy socket requires trusted runtime-directory ancestors",
                ));
            }
        }
    }
    if path == native || resolved_endpoint(native).is_ok_and(|n| n == resolved) {
        return Err(Error::config(
            "legacy and native control sockets must be distinct",
        ));
    }
    match fs::symlink_metadata(&resolved) {
        Ok(_) => {
            return Err(error(io::Error::new(
                ErrorKind::AddrInUse,
                "legacy control path already exists; it was left untouched",
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(error(err)),
    }
    // Bind is still exclusive if an entry appears after the metadata check.
    let listener = UnixListener::bind(&resolved).map_err(error)?;
    let socket = BoundLegacySocket {
        listener,
        identity: socket_identity(&resolved).map_err(error)?,
        path: resolved,
    };
    fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600)).map_err(error)?;
    Ok(socket)
}

/// Serve an already bound and protected local administrative endpoint.
pub(crate) async fn run_legacy_socket(
    socket: BoundLegacySocket,
    control_tx: mpsc::Sender<ControlCmd>,
    cancel: CancellationToken,
    shutdown_cancel: CancellationToken,
) {
    info!(phase = "startup", path = %socket.path.display(), "legacy Fail2Ban client socket listening");
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = socket.listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        if tasks.len() >= MAX_CONNECTIONS
                            || !peer_authorized(&stream)
                        {
                            continue;
                        }
                        let tx = control_tx.clone();
                        let stop = shutdown_cancel.clone();
                        tasks.spawn(async move {
                            handle_connection(stream, tx, stop).await;
                        });
                    }
                    Err(error) => {
                        debug!(%error, "legacy socket accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
    tasks.shutdown().await;
}

fn peer_id_authorized(peer_uid: u32, service_uid: u32) -> bool {
    peer_uid == 0 || peer_uid == service_uid
}

fn peer_authorized(stream: &UnixStream) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|cred| peer_id_authorized(cred.uid(), nix::unistd::geteuid().as_raw()))
}

async fn read_frame(stream: &mut UnixStream, pending: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let mut chunk = [0_u8; 4096];
    let mut search_offset = 0;
    loop {
        if let Some(offset) = pending
            .get(search_offset..)
            .and_then(|bytes| memchr::memmem::find(bytes, F2B_END))
        {
            let start = search_offset + offset;
            let mut frame: Vec<u8> = pending.drain(..start + F2B_END.len()).collect();
            frame.truncate(start);
            return Ok(frame);
        }
        let room = MAX_FRAME_BYTES.saturating_sub(pending.len());
        if room == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "legacy frame exceeds configured bound",
            ));
        }
        search_offset = pending.len().saturating_sub(F2B_END.len() - 1);
        let input = chunk
            .get_mut(..room.min(4096))
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid legacy frame buffer"))?;
        let received = stream.read(input).await?;
        if received == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "incomplete legacy frame",
            ));
        }
        pending.extend_from_slice(input.get(..received).unwrap_or_default());
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    control_tx: mpsc::Sender<ControlCmd>,
    shutdown_cancel: CancellationToken,
) {
    let mut pending = Vec::with_capacity(1024);
    while let Ok(Ok(payload)) = timeout(IO_TIMEOUT, read_frame(&mut stream, &mut pending)).await {
        if payload == F2B_CLOSE {
            return;
        }
        let reply = match decode_command_pickle(&payload) {
            Ok(cmd) => match timeout(
                COMMAND_TIMEOUT,
                dispatch_legacy_cmd(&cmd, &control_tx, &shutdown_cancel),
            )
            .await
            {
                Ok(reply) => reply,
                Err(_) => {
                    err_reply("control processing deadline exceeded; command outcome is unknown")
                }
            },
            Err(err) => err_reply(&err.to_string()),
        };
        let mut encoded = encode_pickle_v2(&reply);
        encoded.extend_from_slice(F2B_END);
        if !matches!(
            timeout(IO_TIMEOUT, stream.write_all(&encoded)).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

fn ok_reply(val: PickleVal) -> PickleVal {
    PickleVal::Tuple2(Box::new(PickleVal::Int(0)), Box::new(val))
}

fn err_reply(msg: &str) -> PickleVal {
    PickleVal::Tuple2(
        Box::new(PickleVal::Int(1)),
        Box::new(PickleVal::Exception(msg.to_owned())),
    )
}

async fn send_ctrl(control_tx: &mpsc::Sender<ControlCmd>, request: Request) -> Result<Response> {
    let (tx, rx) = oneshot::channel();
    control_tx
        .send(ControlCmd {
            request,
            respond: tx,
        })
        .await
        .map_err(|_| Error::ChannelClosed)?;
    rx.await.map_err(|_| Error::ChannelClosed)
}

async fn dispatch_legacy_cmd(
    cmd: &[String],
    control_tx: &mpsc::Sender<ControlCmd>,
    shutdown_cancel: &CancellationToken,
) -> PickleVal {
    let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["ping"] => ok_reply(PickleVal::Str("pong".to_owned())),
        ["version"] => ok_reply(PickleVal::Str("1.1.1".to_owned())),
        ["stop"] => {
            shutdown_cancel.cancel();
            ok_reply(PickleVal::None)
        }
        ["reload"] => match send_ctrl(control_tx, Request::Reload).await {
            Ok(Response::Ok { .. }) => ok_reply(PickleVal::Str("OK".to_owned())),
            Ok(Response::Error { message }) => err_reply(&message),
            Err(e) => err_reply(&e.to_string()),
        },
        ["status"] => match send_ctrl(control_tx, Request::Stats).await {
            Ok(Response::Ok {
                data: Some(data), ..
            }) => {
                let mut names: Vec<String> = data
                    .get("jails")
                    .and_then(|v| v.as_object())
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default();
                names.sort();
                let list = names.join(", ");
                ok_reply(PickleVal::List(vec![
                    PickleVal::Tuple2(
                        Box::new(PickleVal::Str("Number of jail".to_owned())),
                        Box::new(PickleVal::Int(names.len() as i64)),
                    ),
                    PickleVal::Tuple2(
                        Box::new(PickleVal::Str("Jail list".to_owned())),
                        Box::new(PickleVal::Str(list)),
                    ),
                ]))
            }
            Ok(Response::Error { message }) => err_reply(&message),
            _ => err_reply("unable to read status"),
        },
        ["status", jail] | ["status", jail, ..] => {
            let stats = send_ctrl(control_tx, Request::Stats).await;
            let bans = send_ctrl(control_tx, Request::ListBans).await;
            let (
                Ok(Response::Ok {
                    data: Some(sdata), ..
                }),
                Ok(Response::Ok {
                    data: Some(bdata), ..
                }),
            ) = (stats, bans)
            else {
                return err_reply("unable to read jail status");
            };
            let Some(jail_stats) = sdata.get("jails").and_then(|j| j.get(*jail)) else {
                return err_reply(&format!("NOK: ('{jail}',)"));
            };
            let total_failed = jail_stats
                .get("total_failures")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let total_banned = jail_stats
                .get("total_bans")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let mut ips: Vec<String> = bdata
                .get("bans")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|b| b.get("jail").and_then(|v| v.as_str()) == Some(*jail))
                        .filter_map(|b| b.get("ip").and_then(|v| v.as_str()).map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            ips.sort();
            let cur_banned = ips.len() as i64;
            let ip_vals = ips.into_iter().map(PickleVal::Str).collect();
            ok_reply(PickleVal::List(vec![
                PickleVal::Tuple2(
                    Box::new(PickleVal::Str("Filter".to_owned())),
                    Box::new(PickleVal::List(vec![
                        PickleVal::Tuple2(
                            Box::new(PickleVal::Str("Currently failed".to_owned())),
                            Box::new(PickleVal::Int(0)),
                        ),
                        PickleVal::Tuple2(
                            Box::new(PickleVal::Str("Total failed".to_owned())),
                            Box::new(PickleVal::Int(total_failed)),
                        ),
                        PickleVal::Tuple2(
                            Box::new(PickleVal::Str("File list".to_owned())),
                            Box::new(PickleVal::List(Vec::new())),
                        ),
                    ])),
                ),
                PickleVal::Tuple2(
                    Box::new(PickleVal::Str("Actions".to_owned())),
                    Box::new(PickleVal::List(vec![
                        PickleVal::Tuple2(
                            Box::new(PickleVal::Str("Currently banned".to_owned())),
                            Box::new(PickleVal::Int(cur_banned)),
                        ),
                        PickleVal::Tuple2(
                            Box::new(PickleVal::Str("Total banned".to_owned())),
                            Box::new(PickleVal::Int(total_banned)),
                        ),
                        PickleVal::Tuple2(
                            Box::new(PickleVal::Str("Banned IP list".to_owned())),
                            Box::new(PickleVal::List(ip_vals)),
                        ),
                    ])),
                ),
            ]))
        }
        ["get", jail, "banned"] => match send_ctrl(control_tx, Request::ListBans).await {
            Ok(Response::Ok {
                data: Some(bdata), ..
            }) => {
                let mut ips: Vec<String> = bdata
                    .get("bans")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter(|b| b.get("jail").and_then(|v| v.as_str()) == Some(*jail))
                            .filter_map(|b| b.get("ip").and_then(|v| v.as_str()).map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                ips.sort();
                ok_reply(PickleVal::List(
                    ips.into_iter().map(PickleVal::Str).collect(),
                ))
            }
            _ => err_reply("unable to list bans"),
        },
        ["set", jail, "banip", ip_str] => {
            let Ok(ip) = ip_str.parse() else {
                return err_reply(&format!("invalid IP address: {ip_str}"));
            };
            match send_ctrl(
                control_tx,
                Request::Ban {
                    ip,
                    jail: (*jail).to_owned(),
                },
            )
            .await
            {
                Ok(Response::Ok { .. }) => ok_reply(PickleVal::Int(1)),
                Ok(Response::Error { message }) => err_reply(&message),
                Err(e) => err_reply(&e.to_string()),
            }
        }
        ["set", jail, "unbanip", ip_str] => {
            let Ok(ip) = ip_str.parse() else {
                return err_reply(&format!("invalid IP address: {ip_str}"));
            };
            match send_ctrl(
                control_tx,
                Request::Unban {
                    ip,
                    jail: (*jail).to_owned(),
                },
            )
            .await
            {
                Ok(Response::Ok { .. }) => ok_reply(PickleVal::Int(1)),
                Ok(Response::Error { message }) => err_reply(&message),
                Err(e) => err_reply(&e.to_string()),
            }
        }
        _ => err_reply(&format!("unsupported command: {}", cmd.join(" "))),
    }
}

/// Helper to check whether a legacy socket path is configured and safe to bind.
pub fn validate_legacy_socket_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.as_os_str().as_encoded_bytes().ends_with(b"/")
        || path.as_os_str().as_encoded_bytes().ends_with(b"/.")
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err(Error::config(format!(
            "legacy socket requires an absolute file path without parent traversal: {}",
            path.display()
        )));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_policy_admits_only_root_and_service_uid() {
        assert!(peer_id_authorized(0, 1000));
        assert!(peer_id_authorized(1000, 1000));
        assert!(!peer_id_authorized(1001, 1000));
        assert!(!peer_id_authorized(1000, 0));
    }

    #[test]
    fn socket_admission_preserves_existing_file_and_rejects_native_collision() {
        let scratch = tempfile::tempdir().expect("private scratch directory");
        let root = scratch.path();
        let occupied = root.join("existing");
        let native = root.join("native.sock");
        fs::write(&occupied, "ordinary file").expect("write scratch fixture");
        assert!(bind_legacy_socket(&occupied, &native).is_err());
        assert_eq!(
            fs::read_to_string(&occupied).expect("fixture was not removed"),
            "ordinary file"
        );
        assert!(bind_legacy_socket(&native, &native).is_err());
        assert!(!native.exists());
        assert!(validate_legacy_socket_path(&root.join("../outside.sock")).is_err());
        assert!(validate_legacy_socket_path(&root.join("trailing/.")).is_err());
    }

    fn text(s: &str) -> PickleVal {
        PickleVal::Str(s.to_owned())
    }

    #[test]
    fn restricted_pickle_uses_only_the_plain_local_reload_shape() {
        let encode = |jail, flags| {
            encode_pickle_v2(&PickleVal::List(vec![
                text("reload"),
                text(jail),
                PickleVal::List(flags),
                PickleVal::List(vec![PickleVal::List(vec![text("fixture note")])]),
            ]))
        };
        assert_eq!(
            decode_command_pickle(&encode("--all", vec![])).expect("plain full reload"),
            ["reload"]
        );
        assert!(decode_command_pickle(&encode("example", vec![])).is_err());
        assert!(decode_command_pickle(&encode("--all", vec![text("--restart")])).is_err());
        let ordinary = encode_pickle_v2(&PickleVal::List(vec![text("ping")]));
        assert_eq!(
            decode_command_pickle(&ordinary).expect("stock flat command"),
            ["ping"]
        );
        let mut incomplete = ordinary;
        incomplete.pop();
        assert!(decode_command_pickle(&incomplete).is_err());
    }
}
