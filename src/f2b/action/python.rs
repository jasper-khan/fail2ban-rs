//! Run configured third-party `.py` actions with the system Python interpreter.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::db::{BridgeSqlResult, Fail2BanDb};
use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};
use crate::protocol::{DEFAULT_TIMEOUT, MAX_FRAME_BYTES, PickleValue, decode_pickle};
use crate::ticket::{ActionContext, TicketId};

#[derive(Debug)]
pub struct PythonAction {
    name: String,
    jail_name: String,
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    ban_time: i64,
    max_ban_time: i64,
    db: Option<Arc<Mutex<Fail2BanDb>>>,
    pub(super) norestored: bool,
    pub(super) prolongable: bool,
    pub(super) flushable: bool,
    pub(super) reloadable: bool,
    pub(super) has_clear_all_params: bool,
    pub(super) checkable: bool,
}

impl PythonAction {
    pub(crate) async fn load(
        jail: &str,
        name: &str,
        path: &str,
        options: &str,
        ban_time: i64,
        max_ban_time: i64,
        db: Option<Arc<Mutex<Fail2BanDb>>>,
    ) -> Result<Self> {
        let options = parse_options(options)?;
        let (db_info, use_memory_bridge) = match db.as_ref() {
            Some(db_arc) => {
                let guard = db_arc
                    .lock()
                    .map_err(|_| Error::database("database lock poisoned"))?;
                let is_mem = guard.filename() == ":memory:";
                (
                    Some(json!({
                        "filename": guard.filename(),
                        "purgeage": guard.purge_age(),
                        "maxmatches": guard.max_matches(),
                    })),
                    is_mem,
                )
            }
            None => (None, false),
        };
        let library = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent()?.parent().map(Path::to_path_buf))
            .map(|prefix| prefix.join("lib/fail2ban-rs/python.zip"))
            .filter(|path| path.is_file())
            .or_else(|| std::env::var_os("FAIL2BAN_111_SOURCE").map(PathBuf::from))
            .unwrap_or_default();
        let mem_bridge_pair = if use_memory_bridge {
            Some(
                StdUnixStream::pair()
                    .map_err(|e| Error::io("creating Python DB bridge socketpair", e))?,
            )
        } else {
            None
        };
        let db_fd_arg = mem_bridge_pair
            .as_ref()
            .map(|(_, child_sock)| child_sock.as_raw_fd().to_string())
            .unwrap_or_default();
        let mut cmd = Command::new("python3");
        cmd.args(["-I", "-u", "-c", include_str!("python_bridge.py")])
            .arg(library)
            .arg(db_fd_arg)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some((_, ref child_sock)) = mem_bridge_pair {
            let child_fd = child_sock.as_raw_fd();
            // SAFETY: `fcntl(F_SETFD, 0)` is async-signal-safe and only clears FD_CLOEXEC
            // on the child end of the socketpair in the forked child before exec.
            #[allow(unsafe_code)]
            unsafe {
                cmd.pre_exec(move || {
                    if nix::libc::fcntl(child_fd, nix::libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::io(format!("starting Python 3 for action {path:?}"), e))?;
        if let Some((parent_sock, child_sock)) = mem_bridge_pair {
            drop(child_sock);
            if let Some(ref db_arc) = db {
                let db_for_thread = Arc::clone(db_arc);
                std::thread::Builder::new()
                    .name("f2b-pydb".to_owned())
                    .spawn(move || serve_memory_db(parent_sock, db_for_thread))
                    .map_err(|e| Error::io("spawning Python DB bridge thread", e))?;
            }
        }
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::action("missing Python action stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::action("missing Python action stdout"))?;
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some((level, logger, message)) = log_fields(&line) {
                        log_msg(level, logger, message);
                    } else {
                        log_msg(LogLevel::Info, "fail2ban.actions", &line);
                    }
                }
            });
        }
        let mut action = Self {
            name: name.to_owned(),
            jail_name: jail.to_owned(),
            child,
            stdin,
            stdout,
            ban_time,
            max_ban_time,
            db,
            norestored: false,
            prolongable: false,
            flushable: false,
            reloadable: false,
            has_clear_all_params: false,
            checkable: false,
        };
        action
            .request(json!({
                "operation": "load",
                "jail": jail,
                "name": name,
                "path": path,
                "options": options,
                "database": db_info
            }))
            .await?;
        Ok(action)
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn jail_name(&self) -> &str {
        &self.jail_name
    }

    pub(crate) fn set_ban_times(&mut self, ban_time: i64, max_ban_time: i64) {
        self.ban_time = ban_time;
        self.max_ban_time = max_ban_time;
    }

    pub(crate) async fn method(&mut self, key: &str, options: Option<&str>) -> Result<PickleValue> {
        let parsed = parse_options(options.unwrap_or("{}"))?;
        self.request(json!({
            "operation": "method",
            "key": key,
            "options": parsed
        }))
        .await
    }

    pub(crate) async fn flush(&mut self) -> Result<bool> {
        let val = self.method("flush", None).await?;
        Ok(is_truthy(&val))
    }

    pub(crate) async fn consistency_check(&mut self) -> Result<bool> {
        if !self.checkable {
            return Ok(true);
        }
        let val = self.method("consistencyCheck", None).await?;
        Ok(is_truthy(&val))
    }

    pub(crate) async fn consistency_check_on_flush(&mut self, on_stop: bool) -> Result<bool> {
        if !self.checkable {
            return Ok(true);
        }
        let val = self
            .request(json!({
                "operation": "consistency_check",
                "for_flush": true,
                "stop": on_stop,
            }))
            .await?;
        Ok(is_truthy(&val))
    }

    pub(crate) async fn event(&mut self, key: &str, ctx: &ActionContext) -> Result<()> {
        self.ban_time = ctx.default_ban_time;
        let ticket = &ctx.ticket;
        self.request(json!({
            "operation": "method",
            "key": key,
            "ticket": {
                "fid": ticket.fid.to_string(),
                "raw_fid": matches!(ticket.fid, TicketId::Raw(_)),
                "ip": ticket.ip.as_ref().map(ToString::to_string),
                "time": ticket.time,
                "matches": ticket.matches,
                "data": ticket.data,
                "attempts": ticket.attempts,
                "bantime": ticket.ban_time,
                "bancount": ticket.ban_count,
                "restored": ticket.restored,
                "ipmatches": ctx.ip_matches.join("\n"),
                "ipjailmatches": ctx.ip_jail_matches.join("\n"),
                "ipfailures": ctx.ip_failures,
                "ipjailfailures": ctx.ip_jail_failures,
                "jail_stats": ctx.jail_stats,
            }
        }))
        .await?;
        Ok(())
    }

    pub(crate) async fn query(
        &mut self,
        operation: &str,
        key: Option<&str>,
    ) -> Result<PickleValue> {
        self.request(json!({"operation": operation, "key": key}))
            .await
    }

    pub(crate) async fn set_or_call(
        &mut self,
        key: &str,
        value: Option<&PickleValue>,
    ) -> Result<PickleValue> {
        let mut request = json!({"operation": "set", "key": key});
        if let Some(value) = value {
            request["value"] = match value {
                PickleValue::None => JsonValue::Null,
                PickleValue::Bool(value) => json!(value),
                PickleValue::Int(value) => json!(value),
                PickleValue::Float(value) => json!(value),
                value => json!(value.to_string_lossy()),
            };
        }
        self.request(request).await
    }

    async fn request(&mut self, mut value: JsonValue) -> Result<PickleValue> {
        value["bantime"] = json!(self.ban_time);
        value["max_bantime"] = json!(self.max_ban_time);
        if let Some(ref db_arc) = self.db
            && let Ok(guard) = db_arc.lock()
        {
            value["db_purge_age"] = json!(guard.purge_age());
            value["db_max_matches"] = json!(guard.max_matches());
        }
        let mut request = serde_json::to_vec(&value).map_err(|e| Error::action(e.to_string()))?;
        request.push(b'\n');
        let action_name = self.name.clone();
        let exchange = timeout(DEFAULT_TIMEOUT, async {
            self.stdin
                .write_all(&request)
                .await
                .map_err(|e| Error::io(format!("Python action {action_name:?}"), e))?;
            self.stdin
                .flush()
                .await
                .map_err(|e| Error::io(format!("Python action {action_name:?}"), e))?;
            let size = self
                .stdout
                .read_u32()
                .await
                .map_err(|e| Error::io(format!("Python action {action_name:?}"), e))?
                as usize;
            if size > MAX_FRAME_BYTES {
                return Err(Error::io(
                    format!("Python action {action_name:?}"),
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Python action response is too large",
                    ),
                ));
            }
            let mut reply = vec![0; size];
            self.stdout
                .read_exact(&mut reply)
                .await
                .map_err(|e| Error::io(format!("Python action {action_name:?}"), e))?;
            let malformed = || Error::action("invalid Python action response");
            let PickleValue::Tuple(tuple) = decode_pickle(&reply)? else {
                return Err(malformed());
            };
            let [status, first, second]: [PickleValue; 3] =
                tuple.try_into().map_err(|_| malformed())?;
            Ok((status, first, second))
        })
        .await;
        let (status, value, flags) = match exchange {
            Ok(Ok(parts)) => parts,
            Ok(Err(e)) => {
                let _ = self.child.start_kill();
                return Err(e);
            }
            Err(_) => {
                let _ = self.child.start_kill();
                return Err(Error::action(format!(
                    "Python action {:?} timed out",
                    self.name
                )));
            }
        };
        let malformed = || Error::action("invalid Python action response");
        if status != PickleValue::Int(0) {
            return Err(Error::action(value.to_string_lossy()));
        }
        let PickleValue::List(flags) = flags else {
            return Err(malformed());
        };
        let [
            norestored,
            prolongable,
            flushable,
            reloadable,
            has_clear,
            checkable,
        ]: [PickleValue; 6] = flags.try_into().map_err(|_| malformed())?;
        self.norestored = norestored == PickleValue::Bool(true);
        self.prolongable = prolongable == PickleValue::Bool(true);
        self.flushable = flushable == PickleValue::Bool(true);
        self.reloadable = reloadable == PickleValue::Bool(true);
        self.has_clear_all_params = has_clear == PickleValue::Bool(true);
        self.checkable = checkable == PickleValue::Bool(true);
        Ok(value)
    }
}

fn is_truthy(val: &PickleValue) -> bool {
    match val {
        PickleValue::None => false,
        PickleValue::Bool(b) => *b,
        PickleValue::Int(i) => *i != 0,
        PickleValue::Float(f) => *f != 0.0,
        PickleValue::Str(s) => !s.is_empty(),
        PickleValue::Bytes(b) => !b.is_empty(),
        PickleValue::List(v) | PickleValue::Tuple(v) => !v.is_empty(),
        PickleValue::Dict(v) => !v.is_empty(),
        PickleValue::Exception { .. } => true,
    }
}

fn parse_options(raw: &str) -> Result<JsonValue> {
    let value: JsonValue = serde_json::from_str(raw)
        .map_err(|e| Error::action(format!("invalid Python action options: {e}")))?;
    if !value.is_object() {
        return Err(Error::action("Python action options must be an object"));
    }
    Ok(value)
}

fn log_fields(line: &str) -> Option<(LogLevel, &str, &str)> {
    let mut words = line.splitn(3, ' ');
    let level = words.next()?.parse::<i64>().ok()?;
    Some((
        LogLevel::parse(&level.to_string()).ok()?,
        words.next()?,
        words.next()?,
    ))
}

#[derive(Deserialize)]
struct DbBridgeRequest {
    op: String,
    #[serde(default)]
    sql: String,
    #[serde(default)]
    params: Vec<JsonValue>,
}

fn db_ok_reply(res: BridgeSqlResult) -> JsonValue {
    json!({
        "ok": true,
        "rows": res.rows,
        "json_cols": res.json_cols,
        "rowcount": res.rowcount,
    })
}

fn db_err_reply(err: impl Into<String>) -> JsonValue {
    json!({ "ok": false, "error": err.into() })
}

fn read_db_frame(stream: &mut StdUnixStream) -> std::io::Result<DbBridgeRequest> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let size = u32::from_be_bytes(hdr) as usize;
    if size > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Python DB bridge request is too large",
        ));
    }
    let mut buf = vec![0u8; size];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn write_db_frame(stream: &mut StdUnixStream, reply: &JsonValue) -> std::io::Result<()> {
    let payload = serde_json::to_vec(reply)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "reply too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()
}

fn serve_memory_db(mut stream: StdUnixStream, db: Arc<Mutex<Fail2BanDb>>) {
    loop {
        let _ = stream.set_read_timeout(None);
        let Ok(req) = read_db_frame(&mut stream) else {
            break;
        };
        match req.op.as_str() {
            "begin" => {
                if !serve_memory_db_tx(&mut stream, &db) {
                    break;
                }
            }
            "exec" => {
                let reply = match db.lock() {
                    Ok(guard) => match guard.execute_bridge_sql(&req.sql, &req.params) {
                        Ok(res) => db_ok_reply(res),
                        Err(err) => db_err_reply(err),
                    },
                    Err(_) => db_err_reply("database lock poisoned"),
                };
                if write_db_frame(&mut stream, &reply).is_err() {
                    break;
                }
            }
            "commit" | "rollback" => {
                if write_db_frame(&mut stream, &json!({ "ok": true })).is_err() {
                    break;
                }
            }
            other => {
                if write_db_frame(
                    &mut stream,
                    &db_err_reply(format!("unknown db bridge op: {other}")),
                )
                .is_err()
                {
                    break;
                }
            }
        }
    }
}

fn serve_memory_db_tx(stream: &mut StdUnixStream, db: &Arc<Mutex<Fail2BanDb>>) -> bool {
    let Ok(guard) = db.lock() else {
        let _ = write_db_frame(stream, &db_err_reply("database lock poisoned"));
        return true;
    };
    let mut keep_alive = true;
    let mut disconnected = false;
    let tx_res = guard.with_bridge_transaction(|tx| {
        if write_db_frame(stream, &json!({ "ok": true })).is_err() {
            keep_alive = false;
            disconnected = true;
            return false;
        }
        let _ = stream.set_read_timeout(Some(DEFAULT_TIMEOUT));
        loop {
            let Ok(req) = read_db_frame(stream) else {
                keep_alive = false;
                disconnected = true;
                return false;
            };
            match req.op.as_str() {
                "exec" => {
                    let reply = match Fail2BanDb::execute_bridge_sql_on(tx, &req.sql, &req.params) {
                        Ok(res) => db_ok_reply(res),
                        Err(err) => db_err_reply(err),
                    };
                    if write_db_frame(stream, &reply).is_err() {
                        keep_alive = false;
                        disconnected = true;
                        return false;
                    }
                }
                "commit" => return true,
                "rollback" => return false,
                other => {
                    if write_db_frame(
                        stream,
                        &db_err_reply(format!("unexpected db bridge op in transaction: {other}")),
                    )
                    .is_err()
                    {
                        keep_alive = false;
                        disconnected = true;
                        return false;
                    }
                }
            }
        }
    });
    drop(guard);
    if disconnected {
        return false;
    }
    let reply = match tx_res {
        Ok(()) => json!({ "ok": true }),
        Err(err) => db_err_reply(err),
    };
    if write_db_frame(stream, &reply).is_err() {
        return false;
    }
    keep_alive
}
