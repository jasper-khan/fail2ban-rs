//! Run configured third-party `.py` actions with the system Python interpreter.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{Value as JsonValue, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg};
use crate::protocol::{DEFAULT_TIMEOUT, MAX_FRAME_BYTES, PickleValue, decode_pickle};
use crate::ticket::{ActionContext, TicketId};

#[derive(Debug)]
pub struct PythonAction {
    name: String,
    jail_name: String,
    path: PathBuf,
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    ban_time: i64,
    pub(super) norestored: bool,
    pub(super) prolongable: bool,
    pub(super) flushable: bool,
    pub(super) reloadable: bool,
    pub(super) checkable: bool,
}

impl PythonAction {
    pub(crate) async fn load(
        jail: &str,
        name: &str,
        path: &str,
        options: &str,
        ban_time: i64,
    ) -> Result<Self> {
        let options = parse_options(options)?;
        let library = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent()?.parent().map(Path::to_path_buf))
            .map(|prefix| prefix.join("lib/fail2ban-rs/python.zip"))
            .filter(|path| path.is_file())
            .or_else(|| std::env::var_os("FAIL2BAN_111_SOURCE").map(PathBuf::from))
            .unwrap_or_default();
        let mut child = Command::new("python3")
            .args(["-I", "-u", "-c", include_str!("python_bridge.py")])
            .arg(library)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::io(format!("starting Python 3 for action {path:?}"), e))?;
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
            path: PathBuf::from(path),
            child,
            stdin,
            stdout,
            ban_time,
            norestored: false,
            prolongable: false,
            flushable: false,
            reloadable: false,
            checkable: false,
        };
        action
            .request(json!({
                "operation": "load",
                "jail": jail,
                "name": name,
                "path": path,
                "options": options
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

    pub(crate) fn set_ban_time(&mut self, ban_time: i64) {
        self.ban_time = ban_time;
    }

    pub(crate) fn can_reload(&self, path: &str) -> bool {
        self.reloadable && self.path == Path::new(path)
    }

    pub(crate) async fn method(&mut self, key: &str, options: Option<&str>) -> Result<PickleValue> {
        self.request(json!({
            "operation": "method",
            "key": key,
            "options": parse_options(options.unwrap_or("{}"))?
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
        let mut request = serde_json::to_vec(&value).map_err(|e| Error::action(e.to_string()))?;
        request.push(b'\n');
        let exchange = timeout(DEFAULT_TIMEOUT, async {
            self.stdin.write_all(&request).await?;
            self.stdin.flush().await?;
            let size = self.stdout.read_u32().await? as usize;
            if size > MAX_FRAME_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Python action response is too large",
                ));
            }
            let mut reply = vec![0; size];
            self.stdout.read_exact(&mut reply).await?;
            Ok(reply)
        })
        .await;
        let reply = match exchange {
            Ok(Ok(reply)) => reply,
            Ok(Err(e)) => {
                let _ = self.child.start_kill();
                return Err(Error::io(format!("Python action {:?}", self.name), e));
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
        let PickleValue::Tuple(reply) = decode_pickle(&reply)? else {
            return Err(malformed());
        };
        let [status, value, flags]: [PickleValue; 3] = reply.try_into().map_err(|_| malformed())?;
        if status != PickleValue::Int(0) {
            return Err(Error::action(value.to_string_lossy()));
        }
        let PickleValue::List(flags) = flags else {
            return Err(malformed());
        };
        let [norestored, prolongable, flushable, reloadable, checkable]: [PickleValue; 5] =
            flags.try_into().map_err(|_| malformed())?;
        self.norestored = norestored == PickleValue::Bool(true);
        self.prolongable = prolongable == PickleValue::Bool(true);
        self.flushable = flushable == PickleValue::Bool(true);
        self.reloadable = reloadable == PickleValue::Bool(true);
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
