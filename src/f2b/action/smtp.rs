//! Pure-Rust Fail2Ban 1.1.1 `SmtpAction` (`config/action.d/smtp.py`).
//!
//! Sends email notifications over SMTP on jail `start`, `stop`, and `ban`
//! using exact upstream templates and a native async RFC 5321/2822 client
//! over `tokio::net::TcpStream` (supporting `AUTH PLAIN` and `AUTH LOGIN`).

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::duration::parse_bool;
use crate::error::{Error, Result};
use crate::f2b_log;
use crate::logging::LogLevel;
use crate::ticket::ActionContext;

use super::tags;

const DEFAULT_SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Pure-Rust implementation of `config/action.d/smtp.py` (`SMTPAction`).
#[derive(Debug, Clone)]
pub struct SmtpAction {
    jail_name: String,
    name: String,
    host: String,
    ssl: bool,
    user: Option<String>,
    password: Option<String>,
    sendername: String,
    sender: String,
    dest: String,
    matches: Option<String>,
    norestored: bool,
    timeout: Duration,
    hostname_override: Option<String>,
}

impl SmtpAction {
    /// Construct an `SmtpAction` with exact upstream defaults from `smtp.py`.
    pub fn new(jail_name: String, name: String) -> Self {
        Self {
            jail_name,
            name,
            host: "localhost:25".to_owned(),
            ssl: false,
            user: None,
            password: None,
            sendername: "Fail2Ban".to_owned(),
            sender: "fail2ban".to_owned(),
            dest: "root".to_owned(),
            matches: None,
            norestored: true,
            timeout: DEFAULT_SMTP_TIMEOUT,
            hostname_override: None,
        }
    }

    /// Construct an `SmtpAction` from a JSON object string (as serialized by `JailReader`).
    pub fn from_json(jail_name: String, name: String, init_json: &str) -> Result<Self> {
        let mut action = Self::new(jail_name, name);
        let trimmed = init_json.trim();
        if trimmed.is_empty() || trimmed == "null" {
            return Ok(action);
        }
        let val: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| Error::action(format!("invalid smtp.py init JSON: {e}")))?;
        let Some(obj) = val.as_object() else {
            return Err(Error::action("smtp.py init options must be a JSON object"));
        };
        for (key, v) in obj {
            match key.as_str() {
                "name" | "actname" => {}
                "host" => action.host = json_as_string(key, v)?,
                "ssl" => action.ssl = json_as_bool(key, v)?,
                "user" => action.user = json_as_opt_string(key, v)?,
                "password" => action.password = json_as_opt_string(key, v)?,
                "sendername" | "fromname" => action.sendername = json_as_string(key, v)?,
                "sender" | "fromaddr" => action.sender = json_as_string(key, v)?,
                "dest" | "toaddr" => action.dest = json_as_string(key, v)?,
                "matches" => {
                    let m = json_as_opt_string(key, v)?;
                    action.set_matches(m.as_deref())?;
                }
                "norestored" => action.norestored = json_as_bool(key, v)?,
                _ => {
                    return Err(Error::action(format!(
                        "unknown smtp.py action parameter {key:?}"
                    )));
                }
            }
        }
        Ok(action)
    }

    pub fn jail_name(&self) -> &str {
        &self.jail_name
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn norestored(&self) -> bool {
        self.norestored
    }

    pub fn prolongable(&self) -> bool {
        false
    }

    pub fn clear_all_params(&mut self) {
        let fresh = Self::new(self.jail_name.clone(), self.name.clone());
        *self = fresh;
    }

    pub fn set_property(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "host" => self.host = value.to_owned(),
            "ssl" => self.ssl = parse_bool(value)?,
            "user" => self.user = non_empty(value),
            "password" => self.password = non_empty(value),
            "sendername" | "fromname" => self.sendername = value.to_owned(),
            "sender" | "fromaddr" => self.sender = value.to_owned(),
            "dest" | "toaddr" => self.dest = value.to_owned(),
            "matches" => self.set_matches(non_empty(value).as_deref())?,
            "norestored" => self.norestored = parse_bool(value)?,
            _ => {
                return Err(Error::action(format!("unknown smtp.py property {key:?}")));
            }
        }
        Ok(())
    }

    pub fn get_property(&self, key: &str) -> Option<String> {
        match key {
            "host" => Some(self.host.clone()),
            "ssl" => Some(self.ssl.to_string()),
            "user" => self.user.clone(),
            "password" => self.password.clone(),
            "sendername" | "fromname" => Some(self.sendername.clone()),
            "sender" | "fromaddr" => Some(self.sender.clone()),
            "dest" | "toaddr" => Some(self.dest.clone()),
            "matches" => self.matches.clone(),
            "norestored" => Some(self.norestored.to_string()),
            _ => None,
        }
    }

    pub fn del_property(&mut self, key: &str) {
        match key {
            "host" => self.host = "localhost:25".to_owned(),
            "ssl" => self.ssl = false,
            "user" => self.user = None,
            "password" => self.password = None,
            "sendername" | "fromname" => self.sendername = "Fail2Ban".to_owned(),
            "sender" | "fromaddr" => self.sender = "fail2ban".to_owned(),
            "dest" | "toaddr" => self.dest = "root".to_owned(),
            "matches" => self.matches = None,
            "norestored" => self.norestored = true,
            _ => {}
        }
    }

    pub fn property_names(&self) -> Vec<String> {
        [
            "fromaddr",
            "fromname",
            "host",
            "matches",
            "message_values",
            "norestored",
            "password",
            "ssl",
            "toaddr",
            "user",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    pub fn methods(&self) -> Vec<String> {
        ["ban", "reban", "start", "stop", "unban"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// Format `(subject, body)` for jail startup matching `smtp.py` verbatim.
    pub fn format_start_message(&self) -> (String, String) {
        let hostname = self.hostname();
        let subject = format!("[Fail2Ban] {}: started on {hostname}", self.jail_name);
        let body = format!(
            "Hi,\n\nThe jail {} has been started successfully.\n\nRegards,\nFail2Ban",
            self.jail_name
        );
        (subject, body)
    }

    /// Format `(subject, body)` for jail shutdown matching `smtp.py` verbatim.
    pub fn format_stop_message(&self) -> (String, String) {
        let hostname = self.hostname();
        let subject = format!("[Fail2Ban] {}: stopped on {hostname}", self.jail_name);
        let body = format!(
            "Hi,\n\nThe jail {} has been stopped.\n\nRegards,\nFail2Ban",
            self.jail_name
        );
        (subject, body)
    }

    /// Format `(subject, body)` for ban notification matching `smtp.py` verbatim.
    pub fn format_ban_message(&self, ctx: &ActionContext) -> (String, String) {
        let hostname = self.hostname();
        let ip = ctx.ticket.target_ip().to_string();
        let bantime = ctx.ticket.effective_ban_time(ctx.default_ban_time);
        let failures = ctx.ticket.attempts;
        let jailname = &self.jail_name;

        let subject = format!("[Fail2Ban] {jailname}: banned {ip} from {hostname}");
        let head = format!(
            "Hi,\n\nThe IP {ip} has just been banned for {bantime} seconds\n\
            by Fail2Ban after {failures} attempts against {jailname}.\n"
        );
        let middle = match self.matches.as_deref() {
            Some("matches") => format!(
                "\nMatches for this ban:\n{}\n",
                ctx.ticket.matches.join("\n")
            ),
            Some("ipmatches") => format!("\nMatches for {ip}:\n{}\n", ctx.ip_matches.join("\n")),
            Some("ipjailmatches") => format!(
                "\nMatches for {ip} for jail {jailname}:\n{}\n",
                ctx.ip_jail_matches.join("\n")
            ),
            _ => String::new(),
        };
        let body = format!("{head}{middle}\nRegards,\nFail2Ban");
        (subject, body)
    }

    pub async fn start(&mut self) -> Result<()> {
        let (subject, body) = self.format_start_message();
        self.send_message(&subject, &body).await
    }

    pub async fn stop(&mut self) -> Result<()> {
        let (subject, body) = self.format_stop_message();
        self.send_message(&subject, &body).await
    }

    pub async fn ban(&mut self, ctx: &ActionContext) -> Result<()> {
        if self.norestored && ctx.ticket.restored {
            return Ok(());
        }
        let (subject, body) = self.format_ban_message(ctx);
        self.send_message(&subject, &body).await
    }

    pub async fn reban(&mut self, ctx: &ActionContext) -> Result<()> {
        self.ban(ctx).await
    }

    pub async fn unban(&mut self, _ctx: &ActionContext) -> Result<()> {
        Ok(())
    }

    fn set_matches(&mut self, val: Option<&str>) -> Result<()> {
        match val {
            None | Some("") => self.matches = None,
            Some(m @ ("matches" | "ipmatches" | "ipjailmatches")) => {
                self.matches = Some(m.to_owned());
            }
            Some(other) => {
                return Err(Error::action(format!(
                    "invalid smtp.py matches option {other:?}; expected matches, ipmatches, or ipjailmatches"
                )));
            }
        }
        Ok(())
    }

    fn hostname(&self) -> &str {
        self.hostname_override
            .as_deref()
            .unwrap_or_else(|| tags::system_hostnames().1.as_str())
    }

    /// Send an email over SMTP (`tokio::net::TcpStream`).
    ///
    /// TLS (`ssl=true`) is explicitly rejected because no TLS crate is linked.
    pub async fn send_message(&self, subject: &str, body: &str) -> Result<()> {
        if self.ssl {
            return Err(Error::action("smtp ssl=true requires TLS support"));
        }

        let (smtp_host, smtp_port) = parse_host_port(&self.host)?;
        let recipients = parse_recipients(&self.dest)?;
        let from_addr = sanitize_envelope_addr(&self.sender);
        let ehlo_host = sanitize_header(self.hostname());
        let ehlo_name = if ehlo_host.is_empty() {
            "localhost"
        } else {
            ehlo_host.as_str()
        };

        let stream = tokio::time::timeout(
            self.timeout,
            TcpStream::connect((smtp_host.as_str(), smtp_port)),
        )
        .await
        .map_err(|_| Error::action(format!("timed out connecting to SMTP '{}'", self.host)))?
        .map_err(|e| Error::action(format!("Error connecting to host '{}': {e}", self.host)))?;

        let (read_half, mut writer) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // Greeting: 220
        let (code, greeting) = read_smtp_reply(&mut reader, self.timeout).await?;
        if code != 220 {
            return Err(Error::action(format!(
                "SMTP '{}' unexpected greeting {code}: {greeting}",
                self.host
            )));
        }
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.smtp",
            "Connected to SMTP '{}', response: {code}: {}",
            self.host,
            greeting.trim()
        );

        // EHLO / HELO fallback
        send_line(&mut writer, &format!("EHLO {ehlo_name}"), self.timeout).await?;
        let (ehlo_code, mut ehlo_text) = read_smtp_reply(&mut reader, self.timeout).await?;
        if matches!(ehlo_code, 500 | 502) {
            send_line(&mut writer, &format!("HELO {ehlo_name}"), self.timeout).await?;
            let (helo_code, helo_text) = read_smtp_reply(&mut reader, self.timeout).await?;
            if helo_code != 250 {
                return Err(Error::action(format!(
                    "SMTP HELO failed with {helo_code}: {helo_text}"
                )));
            }
            ehlo_text = helo_text;
        } else if ehlo_code != 250 {
            return Err(Error::action(format!(
                "SMTP EHLO failed with {ehlo_code}: {ehlo_text}"
            )));
        }

        // AUTH PLAIN / AUTH LOGIN when credentials are provided
        if let (Some(user), Some(pass)) = (
            self.user.as_deref().filter(|s| !s.is_empty()),
            self.password.as_deref().filter(|s| !s.is_empty()),
        ) {
            smtp_auth(
                &mut reader,
                &mut writer,
                user,
                pass,
                &ehlo_text,
                self.timeout,
            )
            .await?;
        }

        // MAIL FROM
        send_line(
            &mut writer,
            &format!("MAIL FROM:<{from_addr}>"),
            self.timeout,
        )
        .await?;
        expect_code(&mut reader, &[250], "MAIL FROM", self.timeout).await?;

        // RCPT TO for every recipient
        let mut accepted = 0usize;
        let mut failed_rcpts = Vec::new();
        for rcpt in &recipients {
            let clean = sanitize_envelope_addr(rcpt);
            if clean.is_empty() {
                continue;
            }
            send_line(&mut writer, &format!("RCPT TO:<{clean}>"), self.timeout).await?;
            let (rc, msg) = read_smtp_reply(&mut reader, self.timeout).await?;
            if matches!(rc, 250 | 251) {
                accepted += 1;
            } else {
                failed_rcpts.push(format!("{clean}: {rc} {}", msg.trim()));
            }
        }
        if accepted == 0 {
            let _ = send_quit(&mut reader, &mut writer, self.timeout).await;
            return Err(Error::action(format!(
                "SMTP all recipients rejected: {}",
                failed_rcpts.join("; ")
            )));
        }
        if !failed_rcpts.is_empty() {
            f2b_log!(
                LogLevel::Warning,
                "fail2ban.smtp",
                "Email to '{}' failed for recipients: {}",
                self.dest,
                failed_rcpts.join("; ")
            );
        }

        // DATA
        send_line(&mut writer, "DATA", self.timeout).await?;
        expect_code(&mut reader, &[354], "DATA", self.timeout).await?;

        let message_bytes =
            build_rfc2822_message(subject, &self.sendername, &from_addr, &self.dest, body);
        tokio::time::timeout(self.timeout, writer.write_all(&message_bytes))
            .await
            .map_err(|_| Error::action("timed out writing SMTP DATA body"))?
            .map_err(|e| Error::action(format!("writing SMTP DATA body failed: {e}")))?;
        tokio::time::timeout(self.timeout, writer.flush())
            .await
            .map_err(|_| Error::action("timed out flushing SMTP DATA"))?
            .map_err(|e| Error::action(format!("flushing SMTP DATA failed: {e}")))?;

        expect_code(&mut reader, &[250], "DATA end", self.timeout).await?;
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.smtp",
            "Email '{}' successfully sent",
            sanitize_header(subject)
        );

        let _ = send_quit(&mut reader, &mut writer, self.timeout).await;
        Ok(())
    }
}

async fn smtp_auth<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    user: &str,
    pass: &str,
    ehlo_text: &str,
    io_timeout: Duration,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (supports_plain, supports_login) = advertised_auth_mechs(ehlo_text);
    if supports_login && !supports_plain {
        return auth_login(reader, writer, user, pass, io_timeout).await;
    }

    let mut plain_payload = Vec::with_capacity(user.len() + pass.len() + 2);
    plain_payload.push(0);
    plain_payload.extend_from_slice(user.as_bytes());
    plain_payload.push(0);
    plain_payload.extend_from_slice(pass.as_bytes());
    let encoded = base64_encode(&plain_payload);

    send_line(writer, &format!("AUTH PLAIN {encoded}"), io_timeout).await?;
    let (code, msg) = read_smtp_reply(reader, io_timeout).await?;
    if code == 235 {
        return Ok(());
    }
    if code == 504 && supports_login {
        return auth_login(reader, writer, user, pass, io_timeout).await;
    }
    Err(Error::action(format!(
        "Failed to authenticate with SMTP user '{user}': {code} {}",
        msg.trim()
    )))
}

async fn auth_login<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    user: &str,
    pass: &str,
    io_timeout: Duration,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    send_line(writer, "AUTH LOGIN", io_timeout).await?;
    expect_code(reader, &[334], "AUTH LOGIN", io_timeout).await?;
    send_line(writer, &base64_encode(user.as_bytes()), io_timeout).await?;
    expect_code(reader, &[334], "AUTH LOGIN user", io_timeout).await?;
    send_line(writer, &base64_encode(pass.as_bytes()), io_timeout).await?;
    expect_code(reader, &[235], "AUTH LOGIN password", io_timeout).await?;
    Ok(())
}

fn advertised_auth_mechs(ehlo_text: &str) -> (bool, bool) {
    let mut plain = false;
    let mut login = false;
    for line in ehlo_text.lines() {
        let upper = line.trim().to_ascii_uppercase();
        if let Some(rest) = upper
            .strip_prefix("AUTH ")
            .or_else(|| upper.strip_prefix("AUTH="))
        {
            for tok in rest.split_whitespace() {
                match tok {
                    "PLAIN" => plain = true,
                    "LOGIN" => login = true,
                    _ => {}
                }
            }
        }
    }
    (plain, login)
}

async fn send_quit<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    io_timeout: Duration,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    send_line(writer, "QUIT", io_timeout).await?;
    let _ = read_smtp_reply(reader, io_timeout).await;
    Ok(())
}

async fn send_line<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
    io_timeout: Duration,
) -> Result<()> {
    let mut bytes = Vec::with_capacity(line.len() + 2);
    bytes.extend_from_slice(line.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    tokio::time::timeout(io_timeout, writer.write_all(&bytes))
        .await
        .map_err(|_| Error::action("timed out writing SMTP command"))?
        .map_err(|e| Error::action(format!("writing SMTP command failed: {e}")))?;
    tokio::time::timeout(io_timeout, writer.flush())
        .await
        .map_err(|_| Error::action("timed out flushing SMTP command"))?
        .map_err(|e| Error::action(format!("flushing SMTP command failed: {e}")))
}

async fn expect_code<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    allowed: &[u16],
    stage: &str,
    io_timeout: Duration,
) -> Result<(u16, String)> {
    let (code, msg) = read_smtp_reply(reader, io_timeout).await?;
    if allowed.contains(&code) {
        Ok((code, msg))
    } else {
        Err(Error::action(format!(
            "SMTP {stage} failed with {code}: {}",
            msg.trim()
        )))
    }
}

async fn read_smtp_reply<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    io_timeout: Duration,
) -> Result<(u16, String)> {
    let mut full_text = String::new();
    let mut reply_code: Option<u16> = None;
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(io_timeout, reader.read_line(&mut line))
            .await
            .map_err(|_| Error::action("timed out waiting for SMTP server response"))?
            .map_err(|e| Error::action(format!("reading SMTP server response failed: {e}")))?;
        if n == 0 {
            return Err(Error::action("SMTP server closed connection unexpectedly"));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 {
            return Err(Error::action(format!(
                "malformed SMTP reply line: {trimmed:?}"
            )));
        }
        let code: u16 = trimmed[..3]
            .parse()
            .map_err(|_| Error::action(format!("invalid SMTP reply code in {trimmed:?}")))?;
        if let Some(prev) = reply_code
            && prev != code
        {
            return Err(Error::action(format!(
                "mismatched multiline SMTP reply code: expected {prev}, got {code}"
            )));
        }
        reply_code = Some(code);
        let sep = trimmed.as_bytes().get(3).copied();
        let body_part = trimmed.get(4..).unwrap_or("");
        if !full_text.is_empty() {
            full_text.push('\n');
        }
        full_text.push_str(body_part);
        if sep != Some(b'-') {
            return Ok((code, full_text));
        }
    }
}

fn build_rfc2822_message(
    subject: &str,
    sendername: &str,
    sender: &str,
    dest: &str,
    body: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 256);
    let clean_subject = sanitize_header(subject);
    let clean_from = format_addr(sendername, sender);
    let clean_to = sanitize_header(dest);
    let date = chrono::Local::now().to_rfc2822();

    out.extend_from_slice(format!("Subject: {clean_subject}\r\n").as_bytes());
    out.extend_from_slice(format!("From: {clean_from}\r\n").as_bytes());
    out.extend_from_slice(format!("To: {clean_to}\r\n").as_bytes());
    out.extend_from_slice(format!("Date: {date}\r\n").as_bytes());
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(b"Content-Type: text/plain; charset=\"utf-8\"\r\n");
    out.extend_from_slice(b"\r\n");

    // Normalize line endings to CRLF and apply RFC 5321 Section 4.5.2 dot-stuffing.
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    for line in normalized.split('\n') {
        if line.starts_with('.') {
            out.push(b'.');
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn format_addr(display: &str, addr: &str) -> String {
    let clean_display = sanitize_header(display).trim().to_owned();
    let clean_addr = sanitize_envelope_addr(addr);
    if clean_display.is_empty() {
        return clean_addr;
    }
    let needs_quotes = clean_display
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, ' ' | '-' | '_' | '.'));
    if needs_quotes {
        let escaped = clean_display.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\" <{clean_addr}>")
    } else {
        format!("{clean_display} <{clean_addr}>")
    }
}

fn sanitize_header(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

fn sanitize_envelope_addr(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '<' && c != '>')
        .collect::<String>()
        .trim()
        .to_owned()
}

fn parse_host_port(raw: &str) -> Result<(String, u16)> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(Error::action("smtp host cannot be empty"));
    }
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        return Ok((sock.ip().to_string(), sock.port()));
    }
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, port_part)) = rest.split_once("]:") {
            let port: u16 = port_part
                .parse()
                .map_err(|_| Error::action(format!("invalid SMTP port in {raw:?}")))?;
            return Ok((host.to_owned(), port));
        }
        if let Some(host) = rest.strip_suffix(']') {
            return Ok((host.to_owned(), 25));
        }
        return Err(Error::action(format!(
            "invalid bracketed SMTP host {raw:?}"
        )));
    }
    if let Some((host, port_part)) = s.rsplit_once(':')
        && !host.contains(':')
    {
        if host.is_empty() {
            return Err(Error::action(format!("empty SMTP host in {raw:?}")));
        }
        let port: u16 = port_part
            .parse()
            .map_err(|_| Error::action(format!("invalid SMTP port in {raw:?}")))?;
        return Ok((host.to_owned(), port));
    }
    Ok((s.to_owned(), 25))
}

fn parse_recipients(dest: &str) -> Result<Vec<String>> {
    let rcpts: Vec<String> = dest
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if rcpts.is_empty() {
        return Err(Error::action(
            "smtp dest must contain at least one recipient",
        ));
    }
    Ok(rcpts)
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn json_as_string(key: &str, v: &serde_json::Value) -> Result<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(Error::action(format!(
            "smtp.py parameter {key:?} must be a string"
        ))),
    }
}

fn json_as_opt_string(key: &str, v: &serde_json::Value) -> Result<Option<String>> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) if s.is_empty() => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s.clone())),
        _ => Err(Error::action(format!(
            "smtp.py parameter {key:?} must be a string or null"
        ))),
    }
}

fn json_as_bool(key: &str, v: &serde_json::Value) -> Result<bool> {
    match v {
        serde_json::Value::Bool(b) => Ok(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(Error::action(format!(
                "smtp.py parameter {key:?} must be a boolean"
            ))),
        },
        serde_json::Value::String(s) => parse_bool(s),
        _ => Err(Error::action(format!(
            "smtp.py parameter {key:?} must be a boolean"
        ))),
    }
}

/// Pure-Rust RFC 4648 Base64 encoder (used for SMTP `AUTH PLAIN` / `AUTH LOGIN`).
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if input.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ticket::{Ticket, TicketId};
    use tokio::net::TcpListener;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"\0alice\0secret"), "AGFsaWNlAHNlY3JldA==");
    }

    #[test]
    fn templates_match_upstream_smtp_py() {
        let mut act = SmtpAction::from_json(
            "sshd".to_owned(),
            "smtp".to_owned(),
            r#"{"dest":"sec@example.com","matches":"ipjailmatches"}"#,
        )
        .unwrap();
        act.hostname_override = Some("mx01".to_owned());

        let (start_sub, start_body) = act.format_start_message();
        assert_eq!(start_sub, "[Fail2Ban] sshd: started on mx01");
        assert_eq!(
            start_body,
            "Hi,\n\nThe jail sshd has been started successfully.\n\nRegards,\nFail2Ban"
        );

        let (stop_sub, stop_body) = act.format_stop_message();
        assert_eq!(stop_sub, "[Fail2Ban] sshd: stopped on mx01");
        assert_eq!(
            stop_body,
            "Hi,\n\nThe jail sshd has been stopped.\n\nRegards,\nFail2Ban"
        );

        let mut ticket = Ticket::new(TicketId::parse("198.51.100.7"), 1_700_000_000.0);
        ticket.attempts = 4;
        ticket.matches = vec!["failed pass".to_owned()];
        let ctx = ActionContext {
            jail_name: "sshd".to_owned(),
            ticket,
            default_ban_time: 600,
            ip_failures: 8,
            ip_jail_failures: 4,
            ip_matches: vec!["all1".to_owned()],
            ip_jail_matches: vec!["jail1".to_owned(), ".dotline".to_owned()],
        };
        let (ban_sub, ban_body) = act.format_ban_message(&ctx);
        assert_eq!(ban_sub, "[Fail2Ban] sshd: banned 198.51.100.7 from mx01");
        assert_eq!(
            ban_body,
            "Hi,\n\nThe IP 198.51.100.7 has just been banned for 600 seconds\n\
            by Fail2Ban after 4 attempts against sshd.\n\n\
            Matches for 198.51.100.7 for jail sshd:\njail1\n.dotline\n\n\
            Regards,\nFail2Ban"
        );
    }

    #[tokio::test]
    async fn ssl_true_returns_clear_error() {
        let mut act =
            SmtpAction::from_json("sshd".to_owned(), "smtp".to_owned(), r#"{"ssl":"true"}"#)
                .unwrap();
        let err = act.start().await.unwrap_err();
        assert!(err.to_string().contains("TLS"));
    }

    #[tokio::test]
    async fn smtp_client_sends_auth_plain_multi_rcpt_and_dot_stuffed_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rh, mut wh) = stream.into_split();
            let mut reader = BufReader::new(rh);
            wh.write_all(b"220 mock.smtp ESMTP\r\n").await.unwrap();

            let mut transcript = Vec::new();
            let mut in_data = false;
            let mut data_buf = String::new();
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
                if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        wh.write_all(b"250 2.0.0 Ok\r\n").await.unwrap();
                    } else {
                        data_buf.push_str(&line);
                    }
                    continue;
                }
                let cmd = line.trim_end_matches(['\r', '\n']).to_owned();
                transcript.push(cmd.clone());
                if cmd.starts_with("EHLO ") {
                    wh.write_all(b"250-mock.smtp\r\n250 AUTH PLAIN LOGIN\r\n")
                        .await
                        .unwrap();
                } else if cmd.starts_with("AUTH PLAIN ") {
                    wh.write_all(b"235 2.7.0 Authentication successful\r\n")
                        .await
                        .unwrap();
                } else if cmd.starts_with("MAIL FROM:") || cmd.starts_with("RCPT TO:") {
                    wh.write_all(b"250 2.1.0 Ok\r\n").await.unwrap();
                } else if cmd == "DATA" {
                    in_data = true;
                    wh.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await
                        .unwrap();
                } else if cmd == "QUIT" {
                    wh.write_all(b"221 2.0.0 Bye\r\n").await.unwrap();
                    break;
                }
            }
            (transcript, data_buf)
        });

        let init = serde_json::json!({
            "host": addr.to_string(),
            "user": "alice",
            "password": "secret",
            "sendername": "Fail2Ban Bot",
            "sender": "f2b@example.com",
            "dest": "a@example.com, b@example.com",
            "matches": "matches",
            "norestored": "true"
        })
        .to_string();

        let mut act = SmtpAction::from_json("sshd".to_owned(), "smtp".to_owned(), &init).unwrap();
        act.hostname_override = Some("node1".to_owned());

        // Restored ticket must be skipped by default `norestored=true`.
        let mut restored_ticket = Ticket::new(TicketId::parse("192.0.2.1"), 1_700_000_000.0);
        restored_ticket.restored = true;
        let restored_ctx = ActionContext {
            jail_name: "sshd".to_owned(),
            ticket: restored_ticket,
            default_ban_time: 600,
            ip_failures: 1,
            ip_jail_failures: 1,
            ip_matches: vec![],
            ip_jail_matches: vec![],
        };
        act.ban(&restored_ctx).await.unwrap();

        let mut ticket = Ticket::new(TicketId::parse("192.0.2.9"), 1_700_000_000.0);
        ticket.attempts = 3;
        ticket.matches = vec![".leading-dot-log-line".to_owned()];
        let ctx = ActionContext {
            jail_name: "sshd".to_owned(),
            ticket,
            default_ban_time: 600,
            ip_failures: 3,
            ip_jail_failures: 3,
            ip_matches: vec![],
            ip_jail_matches: vec![],
        };
        act.ban(&ctx).await.unwrap();

        let (transcript, data) = server.await.unwrap();
        assert_eq!(
            transcript,
            vec![
                "EHLO node1",
                "AUTH PLAIN AGFsaWNlAHNlY3JldA==",
                "MAIL FROM:<f2b@example.com>",
                "RCPT TO:<a@example.com>",
                "RCPT TO:<b@example.com>",
                "DATA",
                "QUIT",
            ]
        );
        assert!(data.contains("Subject: [Fail2Ban] sshd: banned 192.0.2.9 from node1\r\n"));
        assert!(data.contains("From: Fail2Ban Bot <f2b@example.com>\r\n"));
        assert!(data.contains("To: a@example.com, b@example.com\r\n"));
        assert!(data.contains("\r\n..leading-dot-log-line\r\n"));
    }

    #[tokio::test]
    async fn smtp_client_supports_auth_login_when_plain_absent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rh, mut wh) = stream.into_split();
            let mut reader = BufReader::new(rh);
            wh.write_all(b"220 login.smtp\r\n").await.unwrap();

            let mut cmds = Vec::new();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        wh.write_all(b"250 Ok\r\n").await.unwrap();
                    }
                    continue;
                }
                let cmd = line.trim_end_matches(['\r', '\n']).to_owned();
                cmds.push(cmd.clone());
                if cmd.starts_with("EHLO ") {
                    wh.write_all(b"250-login.smtp\r\n250 AUTH LOGIN\r\n")
                        .await
                        .unwrap();
                } else if cmd == "AUTH LOGIN" {
                    wh.write_all(b"334 VXNlcm5hbWU6\r\n").await.unwrap();
                } else if cmd == "YWxpY2U=" {
                    wh.write_all(b"334 UGFzc3dvcmQ6\r\n").await.unwrap();
                } else if cmd == "c2VjcmV0" {
                    wh.write_all(b"235 Ok\r\n").await.unwrap();
                } else if cmd.starts_with("MAIL FROM:") || cmd.starts_with("RCPT TO:") {
                    wh.write_all(b"250 Ok\r\n").await.unwrap();
                } else if cmd == "DATA" {
                    in_data = true;
                    wh.write_all(b"354 Go\r\n").await.unwrap();
                } else if cmd == "QUIT" {
                    wh.write_all(b"221 Bye\r\n").await.unwrap();
                    break;
                }
            }
            cmds
        });

        let mut act = SmtpAction::new("postfix".to_owned(), "smtp".to_owned());
        act.set_property("host", &addr.to_string()).unwrap();
        act.set_property("user", "alice").unwrap();
        act.set_property("password", "secret").unwrap();
        act.hostname_override = Some("mx".to_owned());
        act.start().await.unwrap();

        let cmds = server.await.unwrap();
        assert_eq!(
            cmds,
            vec![
                "EHLO mx",
                "AUTH LOGIN",
                "YWxpY2U=",
                "c2VjcmV0",
                "MAIL FROM:<fail2ban>",
                "RCPT TO:<root>",
                "DATA",
                "QUIT",
            ]
        );
    }
}
