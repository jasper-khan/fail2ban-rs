//! Fail2Ban 1.1.1 wire protocol (`<F2B_END_COMMAND>`, `<F2B_CLOSE_COMMAND>`, Python pickle).

pub mod pickle;

use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::error::{Error, Result};
pub use pickle::{PickleValue, decode_pickle, encode_pickle_v2, encode_pickle_v4};

pub const END_COMMAND: &[u8] = b"<F2B_END_COMMAND>";
pub const CLOSE_COMMAND: &[u8] = b"<F2B_CLOSE_COMMAND>";
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Build a success response tuple `(0, value)` matching Fail2Ban's `Transmitter`.
pub fn ok_response(val: PickleValue) -> PickleValue {
    PickleValue::Tuple(vec![PickleValue::Int(0), val])
}

/// Build an error response tuple `(1, Exception(msg))` matching Fail2Ban's `Transmitter`.
pub fn err_response(msg: impl Into<String>) -> PickleValue {
    PickleValue::Tuple(vec![
        PickleValue::Int(1),
        PickleValue::Exception {
            kind: "Exception".to_owned(),
            message: msg.into(),
        },
    ])
}

/// Build a typed Fail2Ban error response tuple `(1, <Kind>(msg))`.
pub fn err_response_kind(kind: &str, msg: impl Into<String>) -> PickleValue {
    PickleValue::Tuple(vec![
        PickleValue::Int(1),
        PickleValue::Exception {
            kind: kind.to_owned(),
            message: msg.into(),
        },
    ])
}

/// Encode a `PickleValue` into a wire frame terminated by `<F2B_END_COMMAND>`.
pub fn encode_frame(val: &PickleValue) -> Vec<u8> {
    let mut frame = encode_pickle_v2(val);
    frame.extend_from_slice(END_COMMAND);
    frame
}

/// Read one `<F2B_END_COMMAND>`-delimited frame from a Unix stream.
/// Returns `Ok(None)` on clean EOF or `<F2B_CLOSE_COMMAND>`.
pub async fn read_frame(
    stream: &mut UnixStream,
    pending: &mut Vec<u8>,
    io_timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 8192];
    loop {
        if let Some(pos) = find_subslice(pending, END_COMMAND) {
            let payload = pending[..pos].to_vec();
            pending.drain(..pos + END_COMMAND.len());
            if payload == CLOSE_COMMAND {
                return Ok(None);
            }
            return Ok(Some(payload));
        }
        if pending.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protocol frame exceeds maximum size",
            ));
        }
        let n = match timeout(io_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "socket read timed out",
                ));
            }
        };
        if n == 0 {
            if pending.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF before <F2B_END_COMMAND>",
            ));
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Send a single command `PickleValue` over a Fail2Ban Unix socket and decode the response.
pub async fn send_command(
    socket: &Path,
    cmd: &PickleValue,
    io_timeout: Duration,
) -> Result<PickleValue> {
    let mut stream = timeout(io_timeout, UnixStream::connect(socket))
        .await
        .map_err(|_| Error::protocol(format!("timed out connecting to {}", socket.display())))?
        .map_err(|e| Error::io(format!("connecting to socket {}", socket.display()), e))?;

    let frame = encode_frame(cmd);
    timeout(io_timeout, stream.write_all(&frame))
        .await
        .map_err(|_| Error::protocol("timed out writing command"))?
        .map_err(|e| Error::io("writing command frame", e))?;
    let _ = stream.flush().await;

    let mut pending = Vec::new();
    let reply_bytes = read_frame(&mut stream, &mut pending, io_timeout)
        .await
        .map_err(|e| Error::io("reading response frame", e))?
        .ok_or_else(|| Error::protocol("server closed connection without response"))?;

    // Send polite close sentinel like upstream CSocket.close().
    let mut close = Vec::with_capacity(CLOSE_COMMAND.len() + END_COMMAND.len());
    close.extend_from_slice(CLOSE_COMMAND);
    close.extend_from_slice(END_COMMAND);
    let _ = stream.write_all(&close).await;

    decode_pickle(&reply_bytes)
}

/// Persistent client connection for sending multiple commands (matching `CSocket`).
pub struct CSocket {
    stream: UnixStream,
    pending: Vec<u8>,
    io_timeout: Duration,
}

impl CSocket {
    pub async fn connect(socket: &Path, io_timeout: Duration) -> Result<Self> {
        let stream = timeout(io_timeout, UnixStream::connect(socket))
            .await
            .map_err(|_| Error::protocol(format!("timed out connecting to {}", socket.display())))?
            .map_err(|e| Error::io(format!("connecting to socket {}", socket.display()), e))?;
        Ok(Self {
            stream,
            pending: Vec::new(),
            io_timeout,
        })
    }

    pub async fn send(&mut self, cmd: &PickleValue) -> Result<PickleValue> {
        let frame = encode_frame(cmd);
        timeout(self.io_timeout, self.stream.write_all(&frame))
            .await
            .map_err(|_| Error::protocol("timed out writing command"))?
            .map_err(|e| Error::io("writing command frame", e))?;
        let _ = self.stream.flush().await;
        let reply = read_frame(&mut self.stream, &mut self.pending, self.io_timeout)
            .await
            .map_err(|e| Error::io("reading response frame", e))?
            .ok_or_else(|| Error::protocol("server closed connection without response"))?;
        decode_pickle(&reply)
    }

    pub async fn close(mut self) {
        let mut close = Vec::with_capacity(CLOSE_COMMAND.len() + END_COMMAND.len());
        close.extend_from_slice(CLOSE_COMMAND);
        close.extend_from_slice(END_COMMAND);
        let _ = self.stream.write_all(&close).await;
        let _ = self.stream.shutdown().await;
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut offset = 0;
    while let Some(rel) = memchr::memchr(first, &haystack[offset..]) {
        let pos = offset + rel;
        if pos + needle.len() > haystack.len() {
            return None;
        }
        if &haystack[pos..pos + needle.len()] == needle {
            return Some(pos);
        }
        offset = pos + 1;
    }
    None
}
