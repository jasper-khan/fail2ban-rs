//! Fail2Ban 1.1.1 CLI client (`fail2bancmdline.py` + `fail2banclient.py` + `fail2ban-client`).

pub mod beautifier;

pub use beautifier::{Beautifier, beautify, beautify_error};

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::VERSION;
use crate::config::{Configurator, EarlyOptions, shlex_split};
use crate::duration::str2seconds;
use crate::error::{Error, Result};
use crate::logging::{LogLevel, log_msg, set_level};
use crate::protocol::{CSocket, DEFAULT_TIMEOUT, PickleValue};

const PROMPT: &str = "fail2ban> ";
const DEFAULT_CONF_DIR: &str = "/etc/fail2ban";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpMode {
    None,
    Raw,
    Pretty,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientOptions {
    pub conf_dir: PathBuf,
    pub conf_explicit: bool,
    pub socket: Option<PathBuf>,
    pub pidfile: Option<PathBuf>,
    pub pname: Option<String>,
    pub loglevel: Option<String>,
    pub logtarget: Option<String>,
    pub syslogsocket: Option<String>,
    pub dump: DumpMode,
    pub test: bool,
    pub interactive: bool,
    pub verbose: i32,
    pub force: bool,
    pub background: bool,
    pub async_mode: bool,
    pub timeout: f64,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            conf_dir: PathBuf::from(DEFAULT_CONF_DIR),
            conf_explicit: false,
            socket: None,
            pidfile: None,
            pname: None,
            loglevel: None,
            logtarget: None,
            syslogsocket: None,
            dump: DumpMode::None,
            test: false,
            interactive: false,
            verbose: 1,
            force: false,
            background: true,
            async_mode: false,
            timeout: DEFAULT_TIMEOUT.as_secs_f64(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CliAction {
    Help,
    Version { short: bool },
    Str2Sec(String),
    Run(ClientOptions, Vec<String>),
}

/// Parse `fail2ban-client` command-line arguments using upstream `getopt.getopt` rules
/// (option parsing stops at `--` or at the first non-option command argument).
pub fn parse_cli(args: &[String]) -> Result<CliAction> {
    let mut opts = ClientOptions::default();
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--" {
            idx += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }

        if let Some(long_body) = arg.strip_prefix("--") {
            let (name, inline_val) = match long_body.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long_body, None),
            };
            match name {
                "help" => {
                    reject_unexpected_value(name, inline_val)?;
                    return Ok(CliAction::Help);
                }
                "version" => {
                    reject_unexpected_value(name, inline_val)?;
                    return Ok(CliAction::Version { short: false });
                }
                "test" => {
                    reject_unexpected_value(name, inline_val)?;
                    opts.test = true;
                }
                "async" => {
                    reject_unexpected_value(name, inline_val)?;
                    opts.async_mode = true;
                }
                "dp" | "dump-pretty" => {
                    reject_unexpected_value(name, inline_val)?;
                    opts.dump = DumpMode::Pretty;
                }
                "conf" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.conf_dir = PathBuf::from(v);
                    opts.conf_explicit = true;
                }
                "socket" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.socket = Some(PathBuf::from(v));
                }
                "pidfile" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.pidfile = Some(PathBuf::from(v));
                }
                "pname" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.pname = Some(v);
                }
                "loglevel" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.loglevel = Some(v);
                }
                "logtarget" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.logtarget = Some(v);
                }
                "syslogsocket" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    opts.syslogsocket = Some(v);
                }
                "timeout" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    let secs = str2seconds(&v)?;
                    if !secs.is_finite() || secs < 0.0 {
                        return Err(Error::invalid_command(format!(
                            "invalid --timeout value: {v:?}"
                        )));
                    }
                    opts.timeout = secs;
                }
                "str2sec" => {
                    let v = take_long_val(name, inline_val, args, &mut idx)?;
                    return Ok(CliAction::Str2Sec(v));
                }
                _ => {
                    return Err(Error::invalid_command(format!("option --{name} not recognized")));
                }
            }
            idx += 1;
            continue;
        }

        // Short option cluster (e.g. `-vvd`, `-c/etc/fail2ban`, `-s /path`)
        let rest = &arg[1..];
        let chars = rest.char_indices();
        for (byte_off, ch) in chars {
            match ch {
                'h' => return Ok(CliAction::Help),
                'V' => return Ok(CliAction::Version { short: true }),
                'x' => opts.force = true,
                'f' => opts.background = false,
                'b' => opts.background = true,
                'd' => opts.dump = DumpMode::Raw,
                't' => opts.test = true,
                'v' => opts.verbose = opts.verbose.saturating_add(1),
                'i' => opts.interactive = true,
                'q' => opts.verbose = opts.verbose.saturating_sub(1),
                'c' | 's' | 'p' => {
                    let after = &rest[byte_off + ch.len_utf8()..];
                    let val = if !after.is_empty() {
                        after.to_owned()
                    } else {
                        idx += 1;
                        args.get(idx).cloned().ok_or_else(|| {
                            Error::invalid_command(format!("option -{ch} requires argument"))
                        })?
                    };
                    match ch {
                        'c' => {
                            opts.conf_dir = PathBuf::from(val);
                            opts.conf_explicit = true;
                        }
                        's' => opts.socket = Some(PathBuf::from(val)),
                        'p' => opts.pidfile = Some(PathBuf::from(val)),
                        _ => {}
                    }
                    break;
                }
                _ => {
                    return Err(Error::invalid_command(format!("option -{ch} not recognized")));
                }
            }
        }
        idx += 1;
    }

    Ok(CliAction::Run(opts, args[idx..].to_vec()))
}

fn reject_unexpected_value(name: &str, inline_val: Option<&str>) -> Result<()> {
    if inline_val.is_some() {
        return Err(Error::invalid_command(format!(
            "option --{name} must not have an argument"
        )));
    }
    Ok(())
}

fn take_long_val(
    name: &str,
    inline_val: Option<&str>,
    args: &[String],
    idx: &mut usize,
) -> Result<String> {
    if let Some(v) = inline_val {
        return Ok(v.to_owned());
    }
    *idx += 1;
    args.get(*idx).cloned().ok_or_else(|| {
        Error::invalid_command(format!("option --{name} requires argument"))
    })
}

/// Parse `reload [--restart] [--unban] [--if-exists] [--all | <jail>]` arguments.
pub fn parse_reload_args(args: &[String]) -> Result<(String, Vec<String>)> {
    let mut reload_opts = Vec::new();
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--restart" | "--unban" | "--if-exists" => {
                reload_opts.push(args[idx].clone());
                idx += 1;
            }
            other if other.starts_with('-') && other != "--all" => {
                return Err(Error::invalid_command(format!(
                    "Unexpected argument(s) for reload: {:?}",
                    &args[idx..]
                )));
            }
            _ => break,
        }
    }
    let tail = &args[idx..];
    let target = match tail {
        [] => "--all".to_owned(),
        [one] => one.clone(),
        _ => {
            return Err(Error::invalid_command(format!(
                "Unexpected argument(s) for reload: {tail:?}"
            )));
        }
    };
    Ok((target, reload_opts))
}

/// Frame `["reload", target, opts, config_stream]` matching upstream `Fail2banClient`.
pub fn build_reload_command(args: &[String], stream: Vec<PickleValue>) -> Result<PickleValue> {
    let (target, reload_opts) = parse_reload_args(args)?;
    Ok(PickleValue::List(vec![
        PickleValue::Str("reload".to_owned()),
        PickleValue::Str(target),
        PickleValue::str_list(reload_opts),
        PickleValue::List(stream),
    ]))
}

/// High-level `fail2ban-client` controller matching `Fail2banCmdLine` + `Fail2banClient`.
pub struct Fail2banClient {
    pub opts: ClientOptions,
    early: EarlyOptions,
    cli_overrides: BTreeMap<String, String>,
    beautifier: Beautifier,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Fail2banClient {
    pub fn new(opts: ClientOptions) -> Self {
        let mut cli_overrides = BTreeMap::new();
        if let Some(v) = &opts.loglevel {
            cli_overrides.insert("loglevel".to_owned(), v.clone());
        }
        if let Some(v) = &opts.logtarget {
            cli_overrides.insert("logtarget".to_owned(), v.clone());
        }
        if let Some(v) = &opts.syslogsocket {
            cli_overrides.insert("syslogsocket".to_owned(), v.clone());
        }
        Self {
            opts,
            early: EarlyOptions::default(),
            cli_overrides,
            beautifier: Beautifier::new(),
            runtime: None,
        }
    }

    pub fn socket_path(&self) -> PathBuf {
        self.opts
            .socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.early.socket))
    }

    pub fn pidfile_path(&self) -> PathBuf {
        self.opts
            .pidfile
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.early.pidfile))
    }

    pub fn loglevel(&self) -> &str {
        self.opts
            .loglevel
            .as_deref()
            .unwrap_or(&self.early.loglevel)
    }

    pub fn logtarget(&self) -> &str {
        self.opts
            .logtarget
            .as_deref()
            .unwrap_or(&self.early.logtarget)
    }

    pub fn syslogsocket(&self) -> &str {
        self.opts
            .syslogsocket
            .as_deref()
            .unwrap_or(&self.early.syslogsocket)
    }

    pub fn resolve_early(&mut self, args: &[String]) -> Result<()> {
        let all_set = self.opts.socket.is_some()
            && self.opts.pidfile.is_some()
            && self.opts.loglevel.is_some()
            && self.opts.logtarget.is_some()
            && self.opts.syslogsocket.is_some();
        if !all_set {
            let mut cfg = Configurator::new(&self.opts.conf_dir, false);
            match cfg.read_early() {
                Ok(()) => {
                    self.early = cfg.get_early_options()?;
                }
                Err(err) => {
                    let can_fallback = !self.opts.conf_explicit
                        && self.opts.socket.is_some()
                        && self.opts.dump == DumpMode::None
                        && !self.opts.test
                        && !command_requires_config(args);
                    if !can_fallback {
                        return Err(err);
                    }
                    log_msg(
                        LogLevel::Debug,
                        "fail2ban",
                        &format!("Skipping default config read because -s was provided: {err}"),
                    );
                }
            }
        }
        let _ = LogLevel::parse(self.loglevel())?;
        log_msg(
            LogLevel::Info,
            "fail2ban",
            &format!("Using socket file {}", self.socket_path().display()),
        );
        log_msg(
            LogLevel::Info,
            "fail2ban",
            &format!(
                "Using pid file {}, [{}] logging to {}",
                self.pidfile_path().display(),
                self.loglevel(),
                self.logtarget()
            ),
        );
        Ok(())
    }

    pub fn read_config(
        &self,
        jail: Option<&str>,
        allow_no_files: bool,
    ) -> Result<Vec<PickleValue>> {
        let mut cfg = Configurator::new(&self.opts.conf_dir, false);
        cfg.read_all()?;
        let ignore_wrong = !self.opts.test;
        let ok = cfg.get_options(jail, Some(&self.cli_overrides), ignore_wrong)?;
        if !ok {
            return Err(Error::config(match jail {
                Some(j) => format!("Failed during configuration for jail {j:?}"),
                None => "Failed during configuration".to_owned(),
            }));
        }
        cfg.convert_to_protocol(allow_no_files)?;
        Ok(cfg.get_config_stream())
    }

    pub fn execute_command(&mut self, args: &[String]) -> bool {
        let Some(head) = args.first().map(String::as_str) else {
            return false;
        };

        match head {
            "start" if args.len() == 1 => self.cmd_start(),
            "restart" => self.cmd_restart(args),
            "reload" => self.cmd_reload(args),
            "configure" if args.len() == 1 => self.cmd_configure(),
            "ping" if args.len() > 1 => match args[1].trim().parse::<f64>() {
                Ok(secs) if secs.is_finite() && (secs >= 0.0 || (secs + 1.0).abs() < f64::EPSILON) => {
                    let tout = if (secs + 1.0).abs() < f64::EPSILON {
                        None
                    } else {
                        Some(Duration::from_secs_f64(secs))
                    };
                    self.send_single(args, true, tout)
                }
                Ok(_) => {
                    log_msg(
                        LogLevel::Error,
                        "fail2ban",
                        &format!("Invalid ping timeout: {:?}", args[1]),
                    );
                    false
                }
                Err(e) => {
                    log_msg(
                        LogLevel::Error,
                        "fail2ban",
                        &format!("could not convert string to float: {:?} ({e})", args[1]),
                    );
                    false
                }
            },
            _ => self.send_single(args, true, None),
        }
    }

    fn cmd_configure(&mut self) -> bool {
        let stream = match self.read_config(None, false) {
            Ok(s) => s,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };
        self.send_config_stream(stream)
    }

    fn send_config_stream(&mut self, stream: Vec<PickleValue>) -> bool {
        let cmds = [
            (
                vec!["server-stream".to_owned()],
                PickleValue::List(vec![
                    PickleValue::Str("server-stream".to_owned()),
                    PickleValue::List(stream),
                ]),
            ),
            (
                vec!["server-status".to_owned()],
                PickleValue::str_list(["server-status"]),
            ),
        ];
        self.send_batch(&cmds, false, None)
    }

    fn cmd_start(&mut self) -> bool {
        if self.ping_silent(Duration::from_millis(100)) {
            log_msg(LogLevel::Error, "fail2ban", "Server already running");
            return false;
        }

        let stream = match self.read_config(None, false) {
            Ok(s) => s,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };

        let sock = self.socket_path();
        if !self.opts.force && std::fs::symlink_metadata(&sock).is_ok() {
            log_msg(
                LogLevel::Error,
                "fail2ban",
                "Fail2ban seems to be in unexpected state (not running but the socket exists)",
            );
            return false;
        }

        let mut child = match self.spawn_server() {
            Ok(c) => c,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };

        if let Err(e) = self.wait_on_server(true, Some(&mut child)) {
            log_msg(LogLevel::Error, "fail2ban", &e.to_string());
            if !self.opts.background {
                let _ = child.kill();
                let _ = child.wait();
            }
            return false;
        }

        if !self.send_config_stream(stream) {
            if !self.opts.background {
                let _ = child.kill();
                let _ = child.wait();
            }
            return false;
        }

        if !self.opts.background {
            match child.wait() {
                Ok(status) => status.success(),
                Err(e) => {
                    log_msg(
                        LogLevel::Error,
                        "fail2ban",
                        &format!("Waiting on foreground fail2ban-server failed: {e}"),
                    );
                    false
                }
            }
        } else {
            true
        }
    }

    fn cmd_restart(&mut self, args: &[String]) -> bool {
        if args.len() > 1 {
            let mut reload_args = Vec::with_capacity(args.len() + 1);
            reload_args.push("reload".to_owned());
            reload_args.push("--restart".to_owned());
            reload_args.extend(args[1..].iter().cloned());
            return self.cmd_reload(&reload_args);
        }

        if self.opts.interactive {
            output("  ## stop ... ");
        }
        let _ = self.send_single(&["stop".to_owned()], true, None);
        if self.wait_on_server(false, None).is_err() {
            log_msg(LogLevel::Error, "fail2ban", "Could not stop server");
            return false;
        }
        if self.opts.interactive {
            output("  ## load configuration ... ");
            if let Err(e) = self.resolve_early(&["start".to_owned()]) {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
            output("  ## start ... ");
        }
        self.cmd_start()
    }

    fn cmd_reload(&mut self, args: &[String]) -> bool {
        let (target, _) = match parse_reload_args(args) {
            Ok(parsed) => parsed,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };

        if !self.ping_silent(self.effective_timeout(None)) {
            log_msg(LogLevel::Error, "fail2ban", "Could not find server");
            return false;
        }

        let jail_filter = if target == "--all" {
            None
        } else {
            Some(target.as_str())
        };
        let stream = match self.read_config(jail_filter, false) {
            Ok(s) => s,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };

        if self.opts.interactive {
            output("  ## reload ... ");
        }

        let cmd_val = match build_reload_command(args, stream) {
            Ok(v) => v,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };
        let cmd_strs = vec!["reload".to_owned()];
        self.send_batch(&[(cmd_strs, cmd_val)], true, None)
    }

    fn spawn_server(&self) -> Result<Child> {
        let exe = resolve_server_binary();
        let mut cmd = Command::new(&exe);
        cmd.arg("--async");
        cmd.arg(if self.opts.background { "-b" } else { "-f" });
        cmd.arg("-c").arg(&self.opts.conf_dir);
        cmd.arg("-s").arg(self.socket_path());
        cmd.arg("-p").arg(self.pidfile_path());
        if let Some(pname) = &self.opts.pname {
            cmd.arg("--pname").arg(pname);
        }
        if self.opts.force {
            cmd.arg("-x");
        }
        if self.opts.verbose > 1 {
            let count = usize::try_from((self.opts.verbose - 1).min(10)).unwrap_or(0);
            if count > 0 {
                cmd.arg(format!("-{}", "v".repeat(count)));
            }
        }
        cmd.arg("--loglevel").arg(self.loglevel());
        cmd.arg("--logtarget").arg(self.logtarget());
        cmd.arg("--syslogsocket").arg(self.syslogsocket());

        cmd.stdin(Stdio::null());
        if self.opts.background {
            // Detach stdio in background mode so parent pipes never hang on spawn.
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
        } else {
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());
        }

        cmd.spawn()
            .map_err(|e| Error::io(format!("starting {}", exe.display()), e))
    }

    fn wait_on_server(&mut self, alive: bool, mut child: Option<&mut Child>) -> Result<()> {
        let sock = self.socket_path();
        let max_wait = Duration::from_secs_f64(self.opts.timeout.max(0.0));
        let started = Instant::now();
        let mut sleep_secs = 0.0125_f64 / 2.0;

        loop {
            let is_up = std::fs::symlink_metadata(&sock).is_ok()
                && self.ping_silent(Duration::from_secs_f64(sleep_secs));
            if is_up == alive {
                return Ok(());
            }
            if alive
                && let Some(proc) = child.as_deref_mut()
                && let Ok(Some(status)) = proc.try_wait()
                && !status.success()
            {
                return Err(Error::config(format!(
                    "Failed to start server (exited with {status})"
                )));
            }
            let elapsed = started.elapsed();
            if elapsed >= max_wait {
                return Err(Error::config("Failed to start server"));
            }
            let cap = if elapsed.as_secs_f64() > 0.2 {
                0.5
            } else {
                0.1
            };
            sleep_secs = (sleep_secs * 2.0).min(cap);
            std::thread::sleep(Duration::from_secs_f64(sleep_secs));
        }
    }

    fn ping_silent(&mut self, io_timeout: Duration) -> bool {
        let cmds = [(
            vec!["ping".to_owned()],
            PickleValue::List(vec![
                PickleValue::Str("ping".to_owned()),
                PickleValue::Float(io_timeout.as_secs_f64()),
            ]),
        )];
        self.send_batch(&cmds, false, Some(io_timeout))
    }

    fn send_single(
        &mut self,
        args: &[String],
        show_ret: bool,
        timeout_override: Option<Duration>,
    ) -> bool {
        let cmd_val = PickleValue::str_list(args);
        self.send_batch(&[(args.to_vec(), cmd_val)], show_ret, timeout_override)
    }

    fn send_batch(
        &mut self,
        cmds: &[(Vec<String>, PickleValue)],
        show_ret: bool,
        timeout_override: Option<Duration>,
    ) -> bool {
        let sock = self.socket_path();
        let io_timeout = self.effective_timeout(timeout_override);
        let verbose = self.opts.verbose;
        let rt = match self.ensure_runtime() {
            Ok(rt) => rt,
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                return false;
            }
        };

        let results: Vec<(usize, Result<PickleValue>)> = rt.block_on(async {
            let mut client = match CSocket::connect(&sock, io_timeout).await {
                Ok(c) => c,
                Err(e) => return vec![(0, Err(e))],
            };
            let mut out = Vec::with_capacity(cmds.len());
            for (i, (_, cmd_val)) in cmds.iter().enumerate() {
                if verbose > 2 {
                    log_msg(
                        LogLevel::HeavyDebug,
                        "fail2ban",
                        &format!("CMD: {}", beautifier::py_repr(cmd_val)),
                    );
                }
                let res = client.send(cmd_val).await;
                let failed = res.is_err();
                out.push((i, res));
                if failed {
                    break;
                }
            }
            client.close().await;
            out
        });

        let mut all_ok = true;
        for (idx, res) in results {
            let cmd_strs = &cmds[idx].0;
            let head = cmd_strs.first().map(String::as_str).unwrap_or("");
            match res {
                Ok(PickleValue::Tuple(pair)) if pair.len() >= 2 => {
                    let code = pair[0].as_i64().unwrap_or(1);
                    if code == 0 {
                        if show_ret || matches!(head, "echo" | "server-status") {
                            self.beautifier.set_input_cmd(cmd_strs.clone());
                            output(&self.beautifier.beautify(&pair[1]));
                        }
                    } else {
                        all_ok = false;
                        match &pair[1] {
                            PickleValue::Exception { kind, message } => {
                                log_msg(
                                    LogLevel::Error,
                                    "fail2ban",
                                    &format!("NOK: ({},)", beautifier::py_repr(&PickleValue::Str(message.clone()))),
                                );
                                if show_ret {
                                    self.beautifier.set_input_cmd(cmd_strs.clone());
                                    output(&self.beautifier.beautify_error(kind, message));
                                }
                            }
                            other => {
                                let msg = beautifier::py_str(other);
                                log_msg(
                                    LogLevel::Error,
                                    "fail2ban",
                                    &format!("NOK: ({},)", beautifier::py_repr(other)),
                                );
                                if show_ret {
                                    output(&msg);
                                }
                            }
                        }
                    }
                }
                Ok(other) => {
                    log_msg(
                        LogLevel::Error,
                        "fail2ban",
                        &format!("Unexpected server response: {}", beautifier::py_repr(&other)),
                    );
                    return false;
                }
                Err(e) => {
                    let is_ping = head == "ping";
                    if show_ret || (!is_ping && verbose > 1) {
                        log_socket_error(&sock, &e, is_ping);
                    } else if verbose > 2 {
                        log_msg(
                            LogLevel::HeavyDebug,
                            "fail2ban",
                            &format!(" -- {cmd_strs:?} failed -- {e}"),
                        );
                    }
                    return false;
                }
            }
        }
        all_ok
    }

    fn effective_timeout(&self, override_tout: Option<Duration>) -> Duration {
        override_tout.unwrap_or_else(|| Duration::from_secs_f64(self.opts.timeout.max(0.001)))
    }

    fn ensure_runtime(&mut self) -> Result<&tokio::runtime::Runtime> {
        if self.runtime.is_none() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::io("creating tokio runtime", e))?;
            self.runtime = Some(rt);
        }
        self.runtime
            .as_ref()
            .ok_or_else(|| Error::config("tokio runtime unavailable"))
    }
}

/// Entrypoint called by `src/bin/fail2ban-client.rs` (returns process exit code `0` or `255`).
pub fn run_cli(args: Vec<String>) -> i32 {
    let action = match parse_cli(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ERROR: {e}");
            disp_usage();
            return 255;
        }
    };

    match action {
        CliAction::Help => {
            disp_usage();
            0
        }
        CliAction::Version { short } => {
            if short {
                output(&norm_version());
            } else {
                output(&format!("Fail2Ban v{VERSION}"));
            }
            0
        }
        CliAction::Str2Sec(expr) => match str2seconds(&expr) {
            Ok(secs) => {
                if secs == 0.0 {
                    output("0");
                } else {
                    output(&format!("{secs}"));
                }
                0
            }
            Err(e) => {
                output(&format!("ERROR: {e}"));
                255
            }
        },
        CliAction::Run(opts, cmd_args) => {
            configure_client_logging(opts.verbose);
            if cmd_args.is_empty()
                && !opts.interactive
                && !opts.test
                && opts.dump == DumpMode::None
            {
                disp_usage();
                return 255;
            }
            let mut client = Fail2banClient::new(opts);

            if let Err(e) = client.resolve_early(&cmd_args) {
                output(&format!("ERROR: {e}"));
                return 255;
            }

            let mut preloaded_stream: Option<Result<Vec<PickleValue>>> = None;

            if client.opts.dump != DumpMode::None {
                let res = client.read_config(None, true);
                let ok = match &res {
                    Ok(stream) => {
                        let pretty = client.opts.dump == DumpMode::Pretty;
                        dump_config(stream, pretty);
                        true
                    }
                    Err(e) => {
                        log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                        output("ERROR: The configuration stream failed because of the invalid syntax.");
                        false
                    }
                };
                if !client.opts.test {
                    return if ok { 0 } else { 255 };
                }
                preloaded_stream = Some(res);
            }

            if client.opts.test {
                let res = preloaded_stream.unwrap_or_else(|| client.read_config(None, false));
                let ok = match res {
                    Ok(_) => true,
                    Err(e) => {
                        log_msg(LogLevel::Error, "fail2ban", &e.to_string());
                        false
                    }
                };
                if cmd_args.is_empty() {
                    if ok {
                        output("OK: configuration test is successful");
                        return 0;
                    }
                    output("ERROR: test configuration failed");
                    return 255;
                }
                if !ok {
                    log_msg(LogLevel::Error, "fail2ban", "ERROR: test configuration failed");
                    return 255;
                }
            }

            if client.opts.interactive {
                if !cmd_args.is_empty() && !client.execute_command(&cmd_args) {
                    return 255;
                }
                run_interactive(&mut client);
                0
            } else {
                if cmd_args.is_empty() {
                    disp_usage();
                    return 255;
                }
                if client.execute_command(&cmd_args) {
                    0
                } else {
                    255
                }
            }
        }
    }
}

fn run_interactive(client: &mut Fail2banClient) {
    output(&format!(
        "Fail2Ban v{VERSION} reads log file that contains password failure report"
    ));
    output("and bans the corresponding IP addresses using firewall rules.");
    output("");

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    loop {
        {
            let mut stdout = io::stdout().lock();
            if let Err(e) = stdout.write_all(PROMPT.as_bytes()).and_then(|()| stdout.flush())
                && e.kind() == io::ErrorKind::BrokenPipe
            {
                return;
            }
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                output("");
                return;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    return;
                }
                if trimmed == "help" {
                    disp_usage();
                } else if !trimmed.is_empty() {
                    let parts = shlex_split(trimmed);
                    if !parts.is_empty() {
                        let _ = client.execute_command(&parts);
                    }
                }
            }
            Err(e) => {
                log_msg(LogLevel::Error, "fail2ban", &format!("Reading stdin: {e}"));
                return;
            }
        }
    }
}

fn configure_client_logging(verbose: i32) {
    let lvl = match verbose {
        ..=0 => LogLevel::Error,
        1 => LogLevel::Warning,
        2 => LogLevel::Info,
        3 => LogLevel::Debug,
        _ => LogLevel::HeavyDebug,
    };
    set_level(lvl);
}

fn dump_config(stream: &[PickleValue], pretty: bool) {
    for cmd in stream {
        if pretty {
            output(&beautifier::py_pformat(cmd, 1000, 2));
        } else {
            output(&beautifier::py_repr(cmd));
        }
    }
}

fn command_requires_config(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("start" | "reload" | "restart" | "configure")
    )
}

fn resolve_server_binary() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("fail2ban-server");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("fail2ban-server")
}

fn log_socket_error(sock: &Path, err: &Error, error_only: bool) {
    if let Error::Io { source, .. } = err
        && source.kind() == io::ErrorKind::PermissionDenied
    {
        log_msg(
            LogLevel::Error,
            "fail2ban",
            &format!(
                "Permission denied to socket: {}, (you must be root)",
                sock.display()
            ),
        );
        return;
    }
    if std::fs::symlink_metadata(sock).is_err() {
        log_msg(
            LogLevel::Error,
            "fail2ban",
            &format!(
                "Failed to access socket path: {}. Is fail2ban running?",
                sock.display()
            ),
        );
    } else if error_only {
        log_msg(LogLevel::Error, "fail2ban", &err.to_string());
    } else {
        log_msg(
            LogLevel::Error,
            "fail2ban",
            &format!("[{err}] Unable to contact server. Is it running?"),
        );
    }
}

fn norm_version() -> String {
    VERSION.replace(".fix", "").replace(".dev", ".")
}

fn output(s: &str) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{s}");
    let _ = stdout.flush();
}

fn disp_usage() {
    output("Usage: fail2ban-client [OPTIONS] <COMMAND>");
    output("");
    output(&format!(
        "Fail2Ban v{VERSION} reads log file that contains password failure report"
    ));
    output("and bans the corresponding IP addresses using firewall rules.");
    output("");
    output("Options:");
    output("    -c, --conf <DIR>        configuration directory");
    output("    -s, --socket <FILE>     socket path");
    output("    -p, --pidfile <FILE>    pidfile path");
    output("    --pname <NAME>          name of the process (main thread) to identify instance (default fail2ban-server)");
    output("    --loglevel <LEVEL>      logging level");
    output("    --logtarget <TARGET>    logging target, use file-name or stdout, stderr, syslog or sysout.");
    output("    --syslogsocket auto|<FILE>");
    output("    -d                      dump configuration. For debugging");
    output("    --dp, --dump-pretty     dump the configuration using more human readable representation");
    output("    -t, --test              test configuration (can be also specified with start parameters)");
    output("    -i                      interactive mode");
    output("    -v                      increase verbosity");
    output("    -q                      decrease verbosity");
    output("    -x                      force execution of the server (remove socket file)");
    output("    -b                      start server in background (default)");
    output("    -f                      start server in foreground");
    output("    --async                 start server in async mode (for internal usage only, don't read configuration)");
    output("    --timeout               timeout to wait for the server (for internal usage only, don't read configuration)");
    output("    --str2sec <STRING>      convert time abbreviation format to seconds");
    output("    -h, --help              display this help message");
    output("    -V, --version           print the version (-V returns machine-readable short format)");
    output("");
    output("Command:");
    print_protocol_formatted();
    output("");
    output("Report bugs to https://github.com/fail2ban/fail2ban/issues");
}

const PROTOCOL_HELP: &[(&str, &str)] = &[
    ("", "BASIC"),
    ("start", "starts the server and the jails"),
    ("restart", "restarts the server"),
    (
        "restart [--unban] [--if-exists] <JAIL>",
        "restarts the jail <JAIL> (alias for 'reload --restart ... <JAIL>')",
    ),
    (
        "reload [--restart] [--unban] [--all]",
        "reloads the configuration without restarting of the server, the option '--restart' activates completely restarting of affected jails, thereby can unban IP addresses (if option '--unban' specified)",
    ),
    (
        "reload [--restart] [--unban] [--if-exists] <JAIL>",
        "reloads the jail <JAIL>, or restarts it (if option '--restart' specified)",
    ),
    ("stop", "stops all jails and terminate the server"),
    ("unban --all", "unbans all IP addresses (in all jails and database)"),
    ("unban <IP> ... <IP>", "unbans <IP> (in all jails and database)"),
    ("banned", "return jails with banned IPs as dictionary"),
    (
        "banned <IP> ... <IP>]",
        "return list(s) of jails where given IP(s) are banned",
    ),
    ("status", "gets the current status of the server"),
    (
        "status --all [FLAVOR]",
        "gets the current status of all jails, with optional output style [FLAVOR]. Flavors: 'basic' (default), 'cymru', 'short', 'stats'",
    ),
    ("stat[istic]s", "gets the current statistics of all jails as table"),
    ("ping", "tests if the server is alive"),
    ("echo", "for internal usage, returns back and outputs a given string"),
    ("version", "return the server version"),
    ("", "LOGGING"),
    (
        "set loglevel <LEVEL>",
        "sets logging level to <LEVEL>. Levels: CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG, TRACEDEBUG, HEAVYDEBUG or corresponding numeric value (50-5)",
    ),
    ("get loglevel", "gets the logging level"),
    (
        "set logtarget <TARGET>",
        "sets logging target to <TARGET>. Can be STDOUT, STDERR, SYSLOG, SYSTEMD-JOURNAL or a file",
    ),
    ("get logtarget", "gets logging target"),
    (
        "set syslogsocket auto|<SOCKET>",
        "sets the syslog socket path to auto or <SOCKET>. Only used if logtarget is SYSLOG",
    ),
    ("get syslogsocket", "gets syslog socket path"),
    (
        "flushlogs",
        "flushes the logtarget if a file and reopens it. For log rotation.",
    ),
    ("", "DATABASE"),
    (
        "set dbfile <FILE>",
        "set the location of fail2ban persistent datastore. Set to \"None\" to disable",
    ),
    ("get dbfile", "get the location of fail2ban persistent datastore"),
    (
        "set dbmaxmatches <INT>",
        "sets the max number of matches stored in database per ticket",
    ),
    (
        "get dbmaxmatches",
        "gets the max number of matches stored in database per ticket",
    ),
    (
        "set dbpurgeage <SECONDS>",
        "sets the max age in <SECONDS> that history of bans will be kept",
    ),
    (
        "get dbpurgeage",
        "gets the max age in seconds that history of bans will be kept",
    ),
    ("", "JAIL CONTROL"),
    ("add <JAIL> <BACKEND>", "creates <JAIL> using <BACKEND>"),
    ("start <JAIL>", "starts the jail <JAIL>"),
    ("stop <JAIL>", "stops the jail <JAIL>. The jail is removed"),
    (
        "status <JAIL> [FLAVOR]",
        "gets the current status of <JAIL>, with optional output style [FLAVOR]. Flavors: 'basic' (default), 'cymru', 'short', 'stats'",
    ),
    ("", "JAIL CONFIGURATION"),
    ("set <JAIL> idle on|off", "sets the idle state of <JAIL>"),
    (
        "set <JAIL> ignoreself true|false",
        "allows the ignoring of own IP addresses",
    ),
    (
        "set <JAIL> addignoreip <IP>",
        "adds <IP> to the ignore list of <JAIL>",
    ),
    (
        "set <JAIL> delignoreip <IP>",
        "removes <IP> from the ignore list of <JAIL>",
    ),
    ("set <JAIL> ignorecommand <VALUE>", "sets ignorecommand of <JAIL>"),
    ("set <JAIL> ignorecache <VALUE>", "sets ignorecache of <JAIL>"),
    (
        "set <JAIL> addlogpath <FILE> ['tail']",
        "adds <FILE> to the monitoring list of <JAIL>, optionally starting at the 'tail' of the file (default 'head').",
    ),
    (
        "set <JAIL> dellogpath <FILE>",
        "removes <FILE> from the monitoring list of <JAIL>",
    ),
    (
        "set <JAIL> logencoding <ENCODING>",
        "sets the <ENCODING> of the log files for <JAIL>",
    ),
    (
        "set <JAIL> addjournalmatch <MATCH>",
        "adds <MATCH> to the journal filter of <JAIL>",
    ),
    (
        "set <JAIL> deljournalmatch <MATCH>",
        "removes <MATCH> from the journal filter of <JAIL>",
    ),
    (
        "set <JAIL> addfailregex <REGEX>",
        "adds the regular expression <REGEX> which must match failures for <JAIL>",
    ),
    (
        "set <JAIL> delfailregex <INDEX>",
        "removes the regular expression at <INDEX> for failregex",
    ),
    (
        "set <JAIL> addignoreregex <REGEX>",
        "adds the regular expression <REGEX> which should match pattern to exclude for <JAIL>",
    ),
    (
        "set <JAIL> delignoreregex <INDEX>",
        "removes the regular expression at <INDEX> for ignoreregex",
    ),
    (
        "set <JAIL> findtime <TIME>",
        "sets the number of seconds <TIME> for which the filter will look back for <JAIL>",
    ),
    (
        "set <JAIL> bantime <TIME>",
        "sets the number of seconds <TIME> a host will be banned for <JAIL>",
    ),
    (
        "set <JAIL> datepattern <PATTERN>",
        "sets the <PATTERN> used to match date/times for <JAIL>",
    ),
    ("set <JAIL> usedns <VALUE>", "sets the usedns mode for <JAIL>"),
    (
        "set <JAIL> attempt <IP> [<failure1> ... <failureN>]",
        "manually notify about <IP> failure",
    ),
    (
        "set <JAIL> banip <IP> ... <IP>",
        "manually Ban <IP> for <JAIL>",
    ),
    (
        "set <JAIL> unbanip [--report-absent] <IP> ... <IP>",
        "manually Unban <IP> in <JAIL>",
    ),
    (
        "set <JAIL> maxretry <RETRY>",
        "sets the number of failures <RETRY> before banning the host for <JAIL>",
    ),
    (
        "set <JAIL> maxmatches <INT>",
        "sets the max number of matches stored in memory per ticket in <JAIL>",
    ),
    (
        "set <JAIL> maxlines <LINES>",
        "sets the number of <LINES> to buffer for regex search for <JAIL>",
    ),
    (
        "set <JAIL> addaction <ACT>[ <PYTHONFILE> <JSONKWARGS>]",
        "adds a new action named <ACT> for <JAIL>. Optionally for a Python based action, a <PYTHONFILE> and <JSONKWARGS> can be specified, else will be a Command Action",
    ),
    ("set <JAIL> delaction <ACT>", "removes the action <ACT> from <JAIL>"),
    ("", "COMMAND ACTION CONFIGURATION"),
    (
        "set <JAIL> action <ACT> actionstart <CMD>",
        "sets the start command <CMD> of the action <ACT> for <JAIL>",
    ),
    (
        "set <JAIL> action <ACT> actionstop <CMD>",
        "sets the stop command <CMD> of the action <ACT> for <JAIL>",
    ),
    (
        "set <JAIL> action <ACT> actioncheck <CMD>",
        "sets the check command <CMD> of the action <ACT> for <JAIL>",
    ),
    (
        "set <JAIL> action <ACT> actionban <CMD>",
        "sets the ban command <CMD> of the action <ACT> for <JAIL>",
    ),
    (
        "set <JAIL> action <ACT> actionunban <CMD>",
        "sets the unban command <CMD> of the action <ACT> for <JAIL>",
    ),
    (
        "set <JAIL> action <ACT> timeout <TIMEOUT>",
        "sets <TIMEOUT> as the command timeout in seconds for the action <ACT> for <JAIL>",
    ),
    ("", "GENERAL ACTION CONFIGURATION"),
    (
        "set <JAIL> action <ACT> <PROPERTY> <VALUE>",
        "sets the <VALUE> of <PROPERTY> for the action <ACT> for <JAIL>",
    ),
    (
        "set <JAIL> action <ACT> <METHOD>[ <JSONKWARGS>]",
        "calls the <METHOD> with <JSONKWARGS> for the action <ACT> for <JAIL>",
    ),
    ("", "JAIL INFORMATION"),
    ("get <JAIL> banned", "return banned IPs of <JAIL>"),
    (
        "get <JAIL> banned <IP> ... <IP>]",
        "return 1 if IP is banned in <JAIL> otherwise 0, or a list of 1/0 for multiple IPs",
    ),
    ("get <JAIL> logpath", "gets the list of the monitored files for <JAIL>"),
    (
        "get <JAIL> logencoding",
        "gets the encoding of the log files for <JAIL>",
    ),
    (
        "get <JAIL> journalmatch",
        "gets the journal filter match for <JAIL>",
    ),
    (
        "get <JAIL> ignoreself",
        "gets the current value of the ignoring the own IP addresses",
    ),
    (
        "get <JAIL> ignoreip",
        "gets the list of ignored IP addresses for <JAIL>",
    ),
    ("get <JAIL> ignorecommand", "gets ignorecommand of <JAIL>"),
    (
        "get <JAIL> failregex",
        "gets the list of regular expressions which matches the failures for <JAIL>",
    ),
    (
        "get <JAIL> ignoreregex",
        "gets the list of regular expressions which matches patterns to ignore for <JAIL>",
    ),
    (
        "get <JAIL> findtime",
        "gets the time for which the filter will look back for failures for <JAIL>",
    ),
    ("get <JAIL> bantime", "gets the time a host is banned for <JAIL>"),
    (
        "get <JAIL> datepattern",
        "gets the pattern used to match date/times for <JAIL>",
    ),
    ("get <JAIL> usedns", "gets the usedns setting for <JAIL>"),
    (
        "get <JAIL> banip [<SEP>|--with-time]",
        "gets the list of of banned IP addresses for <JAIL>. Optionally the separator character ('<SEP>', default is space) or the option '--with-time' (printing the times of ban) may be specified. The IPs are ordered by end of ban.",
    ),
    (
        "get <JAIL> maxretry",
        "gets the number of failures allowed for <JAIL>",
    ),
    (
        "get <JAIL> maxmatches",
        "gets the max number of matches stored in memory per ticket in <JAIL>",
    ),
    (
        "get <JAIL> maxlines",
        "gets the number of lines to buffer for <JAIL>",
    ),
    ("get <JAIL> actions", "gets a list of actions for <JAIL>"),
    ("", "COMMAND ACTION INFORMATION"),
    (
        "get <JAIL> action <ACT> actionstart",
        "gets the start command for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> action <ACT> actionstop",
        "gets the stop command for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> action <ACT> actioncheck",
        "gets the check command for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> action <ACT> actionban",
        "gets the ban command for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> action <ACT> actionunban",
        "gets the unban command for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> action <ACT> timeout",
        "gets the command timeout in seconds for the action <ACT> for <JAIL>",
    ),
    ("", "GENERAL ACTION INFORMATION"),
    (
        "get <JAIL> actionproperties <ACT>",
        "gets a list of properties for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> actionmethods <ACT>",
        "gets a list of methods for the action <ACT> for <JAIL>",
    ),
    (
        "get <JAIL> action <ACT> <PROPERTY>",
        "gets the value of <PROPERTY> for the action <ACT> for <JAIL>",
    ),
];

fn print_protocol_formatted() {
    const INDENT: usize = 4;
    const MARGIN: usize = 41;
    const WIDTH: usize = 34;

    let mut first_heading = false;
    for &(cmd, desc) in PROTOCOL_HELP {
        if cmd.is_empty() && first_heading {
            output("");
        }
        first_heading = true;
        if cmd.len() >= MARGIN {
            output(&format!("{}{cmd}", " ".repeat(INDENT)));
            for line in wrap_text(desc, WIDTH) {
                output(&format!("{}{line}", " ".repeat(INDENT + MARGIN)));
            }
        } else {
            let wrapped = wrap_text(desc, WIDTH);
            let pad = " ".repeat(MARGIN - cmd.len());
            if let Some((first, rest)) = wrapped.split_first() {
                output(&format!("{}{cmd}{pad}{first}", " ".repeat(INDENT)));
                for line in rest {
                    output(&format!("{}{line}", " ".repeat(INDENT + MARGIN)));
                }
            }
        }
    }
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if cur.is_empty() {
            cur.push_str(word);
        } else if cur.len() + 1 + word.len() <= width {
            cur.push(' ');
            cur.push_str(word);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parse_flags_and_stop_before_command_args() {
        let act = parse_cli(&argv(&[
            "-c",
            "/tmp/f2b",
            "-s/tmp/f2b.sock",
            "-p",
            "/tmp/f2b.pid",
            "-vvd",
            "-x",
            "-f",
            "--timeout",
            "1m",
            "reload",
            "--restart",
            "--unban",
            "sshd",
        ]))
        .unwrap();
        let CliAction::Run(opts, cmd) = act else {
            panic!("expected CliAction::Run");
        };
        assert_eq!(opts.conf_dir, PathBuf::from("/tmp/f2b"));
        assert!(opts.conf_explicit);
        assert_eq!(opts.socket, Some(PathBuf::from("/tmp/f2b.sock")));
        assert_eq!(opts.pidfile, Some(PathBuf::from("/tmp/f2b.pid")));
        assert_eq!(opts.verbose, 3);
        assert_eq!(opts.dump, DumpMode::Raw);
        assert!(opts.force);
        assert!(!opts.background);
        assert!((opts.timeout - 60.0).abs() < f64::EPSILON);
        assert_eq!(cmd, argv(&["reload", "--restart", "--unban", "sshd"]));
    }

    #[test]
    fn parse_special_flags_dp_test_str2sec_version() {
        assert_eq!(
            parse_cli(&argv(&["--str2sec", "1d12h30m"])).unwrap(),
            CliAction::Str2Sec("1d12h30m".to_owned())
        );
        assert_eq!(
            parse_cli(&argv(&["-V"])).unwrap(),
            CliAction::Version { short: true }
        );
        assert_eq!(
            parse_cli(&argv(&["-vq", "--version"])).unwrap(),
            CliAction::Version { short: false }
        );
        let CliAction::Run(opts, cmd) =
            parse_cli(&argv(&["--dp", "-t", "-c", "/etc/fail2ban"])).unwrap()
        else {
            panic!("expected CliAction::Run");
        };
        assert_eq!(opts.dump, DumpMode::Pretty);
        assert!(opts.test);
        assert!(cmd.is_empty());
    }

    #[test]
    fn parse_rejects_unknown_options_before_command() {
        assert!(parse_cli(&argv(&["--unknown", "status"])).is_err());
        assert!(parse_cli(&argv(&["-z", "status"])).is_err());
        assert!(parse_cli(&argv(&["-c"])).is_err());
    }

    #[test]
    fn reload_command_framing_matches_upstream() {
        let stream = vec![PickleValue::str_list(["add", "sshd", "auto"])];
        let framed = build_reload_command(
            &argv(&["reload", "--restart", "--unban", "--if-exists", "sshd"]),
            stream.clone(),
        )
        .unwrap();
        assert_eq!(
            framed,
            PickleValue::List(vec![
                PickleValue::Str("reload".to_owned()),
                PickleValue::Str("sshd".to_owned()),
                PickleValue::str_list(["--restart", "--unban", "--if-exists"]),
                PickleValue::List(stream.clone()),
            ])
        );

        let all_framed = build_reload_command(&argv(&["reload"]), stream.clone()).unwrap();
        assert_eq!(
            all_framed,
            PickleValue::List(vec![
                PickleValue::Str("reload".to_owned()),
                PickleValue::Str("--all".to_owned()),
                PickleValue::List(Vec::new()),
                PickleValue::List(stream),
            ])
        );

        assert!(build_reload_command(&argv(&["reload", "--bad", "sshd"]), Vec::new()).is_err());
        assert!(build_reload_command(&argv(&["reload", "sshd", "extra"]), Vec::new()).is_err());
    }
}
