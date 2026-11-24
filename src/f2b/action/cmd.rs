//! Subprocess runner for Fail2Ban 1.1.1 command actions (`sh -c`).
//!
//! Each child process runs as the leader of its own process group so a timed-out
//! script (including backgrounded grandchildren holding stdout/stderr open) is
//! terminated atomically with `SIGKILL` via `killpg`.

use std::ffi::OsStr;
use std::os::unix::process::ExitStatusExt;
use std::process::{Output, Stdio};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};
use crate::f2b_log;
use crate::logging::LogLevel;

/// Default upper bound on how long a command may run when no action timeout is given.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound for full stdout capture in [`output`] / [`output_with_timeout`].
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
/// Retain a bounded diagnostic prefix while draining the rest of the stream.
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const TRUNCATED: &[u8] = b"\n[output truncated]\n";

/// Run `program args...` under [`COMMAND_TIMEOUT`] and capture its output.
///
/// Spawn failures and timeouts return `Err`; non-zero exits return `Ok(Output)`.
pub async fn output<P, S>(program: P, label: &str, args: &[S]) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    output_with_timeout(program, label, args, COMMAND_TIMEOUT).await
}

/// Like [`output`], with an explicit timeout.
pub async fn output_with_timeout<P, S>(
    program: P,
    label: &str,
    args: &[S],
    limit: Duration,
) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    execute(program, label, args, limit, true, false).await
}

/// Run a command under [`COMMAND_TIMEOUT`], treating a non-zero exit as an error.
pub async fn run<P, S>(program: P, label: &str, args: &[S]) -> Result<()>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    let out = execute(program, label, args, COMMAND_TIMEOUT, false, false).await?;
    check_status(label, &out)
}

/// Execute `sh -c <command>` in its own process group under `timeout`.
///
/// Returns `(ok, exit_code)` where `ok` is `true` iff the child exited normally
/// with a status present in `success_codes`. On signal termination, `exit_code`
/// is `-signal` and `ok` is `false`. Spawn failures and timeouts return `Err`.
pub async fn run_shell_cmd(
    command: &str,
    timeout: Duration,
    success_codes: &[i32],
) -> Result<(bool, i32)> {
    run_shell_cmd_args(command, &[], timeout, success_codes).await
}

/// Execute `sh -c <command> <arg0> <arg1> ...` in its own process group under `timeout`.
///
/// In POSIX `sh -c`, the first positional argument after `<command>` is bound to `$0`,
/// the second to `$1`, etc., matching Fail2Ban 1.1.1's `Utils.buildShellCmd`.
pub async fn run_shell_cmd_args(
    command: &str,
    positional_args: &[String],
    timeout: Duration,
    success_codes: &[i32],
) -> Result<(bool, i32)> {
    let mut argv: Vec<&str> = Vec::with_capacity(2 + positional_args.len());
    argv.push("-c");
    argv.push(command);
    for arg in positional_args {
        argv.push(arg.as_str());
    }
    let out = execute("sh", "sh", &argv, timeout, true, true).await?;
    let code = out
        .status
        .code()
        .or_else(|| out.status.signal().map(|sig| -sig))
        .unwrap_or(-1);
    let ok = out
        .status
        .code()
        .is_some_and(|c| success_codes.contains(&c));

    if ok {
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.utils",
            "cmd {:?} returned successfully ({code})",
            command
        );
        log_stream(LogLevel::Debug, "stdout", &out.stdout);
        log_stream(LogLevel::Debug, "stderr", &out.stderr);
    } else {
        f2b_log!(
            LogLevel::Error,
            "fail2ban.utils",
            "cmd {:?} failed with exit code {code}",
            command
        );
        log_stream(LogLevel::Error, "stdout", &out.stdout);
        log_stream(LogLevel::Error, "stderr", &out.stderr);
    }

    Ok((ok, code))
}

fn log_stream(level: LogLevel, name: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        f2b_log!(level, "fail2ban.utils", "  {name}: {line}");
    }
}

/// Map a non-zero exit status to `Error::Action` carrying the trimmed stderr.
pub fn check_status(label: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(Error::action(format!(
        "{label} exit {}: {}",
        output.status,
        stderr.trim()
    )))
}

async fn execute<P, S>(
    program: P,
    label: &str,
    args: &[S],
    limit: Duration,
    capture_stdout: bool,
    truncate_stdout: bool,
) -> Result<Output>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    let mut child = spawn_in_group(program, label, args)?;
    let pgid = child.id();
    let result = tokio::time::timeout(
        limit,
        collect(&mut child, label, capture_stdout, truncate_stdout),
    )
    .await;
    let error = match result {
        Ok(Ok(out)) => return Ok(out),
        Ok(Err(error)) => error,
        Err(_) => Error::action(format!(
            "{label} command timed out after {}s and was killed",
            limit.as_secs_f64()
        )),
    };
    abort_and_reap(&mut child, pgid, label).await;
    Err(error)
}

async fn collect(
    child: &mut tokio::process::Child,
    label: &str,
    capture_stdout: bool,
    truncate_stdout: bool,
) -> Result<Output> {
    let stdout_max = if !capture_stdout {
        0
    } else if truncate_stdout {
        MAX_DIAGNOSTIC_BYTES
    } else {
        MAX_STDOUT_BYTES
    };
    let (stdout, stderr) = tokio::try_join!(
        read_bounded(
            child.stdout.take(),
            stdout_max,
            !capture_stdout || truncate_stdout,
            label,
            "stdout"
        ),
        read_bounded(
            child.stderr.take(),
            MAX_DIAGNOSTIC_BYTES,
            true,
            label,
            "stderr"
        ),
    )?;
    let status = child
        .wait()
        .await
        .map_err(|e| Error::action(format!("{label} command failed: {e}")))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

async fn abort_and_reap(child: &mut tokio::process::Child, pgid: Option<u32>, label: &str) {
    kill_group(pgid, label);
    if let Err(e) = child.start_kill() {
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.utils",
            "direct kill of aborted {label} command failed: {e}"
        );
    }
    if let Err(e) = child.wait().await {
        f2b_log!(
            LogLevel::Warning,
            "fail2ban.utils",
            "failed to reap aborted {label} command: {e}"
        );
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(
    pipe: Option<R>,
    max_bytes: usize,
    truncate: bool,
    label: &str,
    stream: &'static str,
) -> Result<Vec<u8>> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    let mut chunk = Box::new([0u8; 8192]);
    let mut truncated = false;
    loop {
        let n = pipe
            .read(&mut *chunk)
            .await
            .map_err(|e| Error::action(format!("{label} {stream} read failed: {e}")))?;
        let Some(data) = chunk.get(..n).filter(|d| !d.is_empty()) else {
            break;
        };
        if !append_bounded(&mut bytes, data, max_bytes) {
            if !truncate {
                return Err(Error::action(format!(
                    "{label} {stream} exceeds {max_bytes} byte output limit"
                )));
            }
            truncated = true;
        }
    }
    if truncated && max_bytes > 0 {
        mark_truncated(&mut bytes, max_bytes);
    }
    Ok(bytes)
}

fn append_bounded(bytes: &mut Vec<u8>, data: &[u8], max_bytes: usize) -> bool {
    let remaining = max_bytes.saturating_sub(bytes.len());
    bytes.extend_from_slice(data.get(..data.len().min(remaining)).unwrap_or_default());
    data.len() <= remaining
}

fn mark_truncated(bytes: &mut Vec<u8>, max_bytes: usize) {
    bytes.truncate(max_bytes.saturating_sub(TRUNCATED.len()));
    bytes.extend_from_slice(TRUNCATED.get(..max_bytes).unwrap_or(TRUNCATED));
}

fn spawn_in_group<P, S>(program: P, label: &str, args: &[S]) -> Result<tokio::process::Child>
where
    P: AsRef<OsStr>,
    S: AsRef<OsStr>,
{
    // `.process_group(0)` places the child in its own process group (`setpgid(0, 0)`).
    tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()
        .map_err(|e| Error::action(format!("{label} command failed: {e}")))
}

fn kill_group(pgid: Option<u32>, label: &str) {
    let Some(raw) = pgid.and_then(|p| i32::try_from(p).ok()) else {
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.utils",
            "timed-out {label} command already reaped; no process group to kill"
        );
        return;
    };
    match killpg(Pid::from_raw(raw), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(e) => {
            f2b_log!(
                LogLevel::Warning,
                "fail2ban.utils",
                "failed to kill timed-out {label} process group {raw}: {e}"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn alive(pid: i32) -> bool {
        nix::sys::signal::kill(Pid::from_raw(pid), None).is_ok()
    }

    #[tokio::test]
    async fn run_shell_cmd_respects_success_codes() {
        assert_eq!(
            run_shell_cmd("exit 0", Duration::from_secs(5), &[0])
                .await
                .unwrap(),
            (true, 0)
        );
        assert_eq!(
            run_shell_cmd("exit 3", Duration::from_secs(5), &[0])
                .await
                .unwrap(),
            (false, 3)
        );
        assert_eq!(
            run_shell_cmd("exit 3", Duration::from_secs(5), &[0, 3])
                .await
                .unwrap(),
            (true, 3)
        );
    }

    #[tokio::test]
    async fn run_shell_cmd_kills_hung_process_group_on_timeout() {
        let dir = tempfile::TempDir::new().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 60 & echo $! > '{}'; exit 0", pid_file.display());
        let start = Instant::now();
        let err = run_shell_cmd(&script, Duration::from_millis(250), &[0])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {err}");
        assert!(start.elapsed() < Duration::from_secs(10));

        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(pid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!alive(pid), "background grandchild {pid} must be killed");
    }

    #[tokio::test]
    async fn output_returns_nonzero_without_error_and_run_errors() {
        let out = output("sh", "sh", &["-c", "printf ok; exit 2"])
            .await
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(out.stdout, b"ok");

        let err = run("sh", "demo", &["-c", "echo boom >&2; exit 2"])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("demo exit"));
        assert!(err.to_string().contains("boom"));
    }
}
