//! Fail2Ban 1.1.1 `action.d` execution backend (`actionstart`, `actionban`,
//! `actionunban`, `actionstop`).
//!
//! Executes already-resolved shell commands from `action.d/<name>.conf` with
//! per-event `<ip>` / `<name>` / `<port>` / `<protocol>` substitution using
//! the bounded-timeout subprocess runner (`enforce::cmd`).

use std::net::IpAddr;

use async_trait::async_trait;
use tracing::{debug, info};

use crate::enforce::FirewallBackend;
use crate::enforce::cmd;
use crate::error::Result;

/// Firewall backend executing resolved Fail2Ban 1.1.1 `action.d` lifecycle commands.
pub struct LegacyActionBackend {
    start: Option<String>,
    ban: String,
    unban: String,
    stop: Option<String>,
}

impl LegacyActionBackend {
    pub fn new(start: Option<String>, ban: String, unban: String, stop: Option<String>) -> Self {
        Self {
            start,
            ban,
            unban,
            stop,
        }
    }

    fn expand_event(template: &str, ip: &IpAddr, jail: &str) -> String {
        template
            .replace("<ip>", &ip.to_string())
            .replace("<IP>", &ip.to_string())
            .replace("<name>", jail)
            .replace("<JAIL>", jail)
    }

    fn expand_lifecycle(template: &str, jail: &str, ports: &[String], protocol: &str) -> String {
        let port = ports.join(",");
        template
            .replace("<name>", jail)
            .replace("<JAIL>", jail)
            .replace("<port>", &port)
            .replace("<protocol>", protocol)
    }
}

#[async_trait]
impl FirewallBackend for LegacyActionBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        if let Some(tpl) = self.start.as_deref().filter(|s| !s.trim().is_empty()) {
            let command = Self::expand_lifecycle(tpl, jail, ports, protocol);
            debug!(jail, command = %command, "running legacy actionstart");
            run_shell("legacy actionstart", &command).await?;
            info!(
                jail,
                backend = "legacy_action",
                "legacy actionstart complete"
            );
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        if let Some(tpl) = self.stop.as_deref().filter(|s| !s.trim().is_empty()) {
            let command = Self::expand_lifecycle(tpl, jail, &[], "tcp");
            debug!(jail, command = %command, "running legacy actionstop");
            run_shell("legacy actionstop", &command).await?;
            info!(
                jail,
                backend = "legacy_action",
                "legacy actionstop complete"
            );
        }
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let command = Self::expand_event(&self.ban, ip, jail);
        debug!(%ip, jail, command = %command, "running legacy actionban");
        run_shell("legacy actionban", &command).await?;
        Ok(())
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        let command = Self::expand_event(&self.unban, ip, jail);
        debug!(%ip, jail, command = %command, "running legacy actionunban");
        run_shell("legacy actionunban", &command).await?;
        Ok(())
    }

    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }

    fn can_verify(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "legacy_action"
    }
}

async fn run_shell(label: &str, command: &str) -> Result<()> {
    let out = cmd::output("sh", label, &["-c", command]).await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(crate::error::Error::firewall(format!(
            "{label} exited with {}: {}",
            out.status,
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_backend_does_not_claim_it_can_verify_active_bans() {
        let backend = LegacyActionBackend::new(None, String::new(), String::new(), None);
        assert!(!backend.can_verify());
    }
}
