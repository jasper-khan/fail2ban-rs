//! Stock `filter.d/ignorecommands/apache-fakegooglebot` executable.

use std::env;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use fail2ban_rs::filter::ipdns::{dns_to_ip, ip_to_name, parse_ticket_ip_or_net};
use fail2ban_rs::ticket::TicketId;

fn check(args: &[String]) -> Result<bool, String> {
    let (program, args) = args.split_first().ok_or("Missing command name")?;
    let (raw_ip, raw_timeout) = match args {
        [ip] => (ip, "55"),
        [ip, timeout] => (ip, timeout.as_str()),
        _ => return Err(format!("Usage {program} ip ?timeout?. Got: {args:?}")),
    };
    let id = parse_ticket_ip_or_net(raw_ip)
        .ok_or_else(|| format!("Argument must be a single valid IP. Got: {raw_ip}"))?;
    let timeout = if raw_timeout.is_empty() {
        0.0
    } else {
        raw_timeout
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("Invalid timeout: {raw_timeout}"))?
    };
    if !timeout.is_finite() {
        return Err(format!("Invalid timeout: {raw_timeout}"));
    }
    let TicketId::Ip(ip) = id else {
        return Ok(false);
    };
    let verify = move || {
        ip_to_name(&ip).is_some_and(|name| {
            (name.ends_with(".google.com") || name.ends_with(".googlebot.com"))
                && dns_to_ip(&name).contains(&id)
        })
    };
    let matched = if timeout == 0.0 {
        verify()
    } else {
        let limit = Duration::try_from_secs_f64(timeout.max(0.0))
            .map_err(|_| format!("Invalid timeout: {raw_timeout}"))?;
        let (send, receive) = mpsc::sync_channel(1);
        thread::Builder::new()
            .spawn(move || {
                let _ = send.send(verify());
            })
            .map_err(|err| err.to_string())?;
        receive.recv_timeout(limit).unwrap_or(false)
    };
    Ok(matched)
}

fn main() -> ExitCode {
    match check(&env::args().collect::<Vec<_>>()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}
