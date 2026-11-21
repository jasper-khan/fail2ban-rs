//! Fail2Ban 1.1.1 `action.d` execution backend (`actionstart`, `actioncheck`,
//! `actionrepair`, `actionban`, `actionunban`, `actionflush`, `actionstop`).
//!
//! Supports multiple actions per jail, independent IPv4/IPv6 (`?family=inet6`)
//! command templates, `actionstart_on_demand`, `actioncheck` + `actionrepair`
//! (or `stop`+`start` fallback), `actionflush` on shutdown, per-action
//! timeouts, and dynamic Fail2Ban ticket tag substitution.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::config::{LegacyActionFamilyCmds, LegacyActionSpec};
use crate::enforce::FirewallBackend;
use crate::enforce::cmd;
use crate::error::Result;

struct RuntimeAction {
    spec: LegacyActionSpec,
    started_v4: AtomicBool,
    started_v6: AtomicBool,
}

impl RuntimeAction {
    fn new(spec: LegacyActionSpec) -> Self {
        Self {
            spec,
            started_v4: AtomicBool::new(false),
            started_v6: AtomicBool::new(false),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.spec.timeout_secs.max(1))
    }

    fn family_cmds(&self, ip: &IpAddr) -> (&LegacyActionFamilyCmds, &AtomicBool, &'static str) {
        if ip.is_ipv6() {
            (&self.spec.ipv6, &self.started_v6, "inet6")
        } else {
            (&self.spec.ipv4, &self.started_v4, "inet4")
        }
    }

    fn expand_event(&self, template: &str, ip: &IpAddr, jail: &str, family: &str) -> String {
        let ip_str = ip.to_string();
        let ip_rev = reverse_ip(ip);
        let now = chrono::Utc::now().timestamp().to_string();
        let ban_time = self.spec.ban_time.to_string();
        template
            .replace("<ip>", &ip_str)
            .replace("<IP>", &ip_str)
            .replace("<ip-rev>", &ip_rev)
            .replace("<family>", family)
            .replace("<name>", jail)
            .replace("<JAIL>", jail)
            .replace("<time>", &now)
            .replace("<bantime>", &ban_time)
            .replace("<failures>", "1")
            .replace("<ipfailures>", "1")
            .replace("<ipjailfailures>", "1")
            .replace("<matches>", "")
            .replace("<ipmatches>", "")
            .replace("<ipjailmatches>", "")
    }

    fn expand_lifecycle(
        template: &str,
        jail: &str,
        ports: &[String],
        protocol: &str,
        family: &str,
    ) -> String {
        let port = ports.join(",");
        template
            .replace("<name>", jail)
            .replace("<JAIL>", jail)
            .replace("<port>", &port)
            .replace("<protocol>", protocol)
            .replace("<family>", family)
    }

    async fn run_start_if_needed(
        &self,
        cmds: &LegacyActionFamilyCmds,
        started: &AtomicBool,
        jail: &str,
        ports: &[String],
        protocol: &str,
        family: &str,
    ) -> Result<()> {
        if started.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(tpl) = cmds.start.as_deref().filter(|s| !s.trim().is_empty()) {
            let command = Self::expand_lifecycle(tpl, jail, ports, protocol, family);
            debug!(
                jail,
                action = %self.spec.name,
                family,
                command = %command,
                "running legacy actionstart"
            );
            run_shell("legacy actionstart", &command, self.timeout()).await?;
        }
        started.store(true, Ordering::Release);
        Ok(())
    }

    async fn check_and_repair(
        &self,
        cmds: &LegacyActionFamilyCmds,
        jail: &str,
        family: &str,
    ) -> Result<bool> {
        let Some(check_tpl) = cmds.check.as_deref().filter(|s| !s.trim().is_empty()) else {
            return Ok(false);
        };
        let check_cmd = Self::expand_lifecycle(check_tpl, jail, &[], "tcp", family);
        let out = cmd::output_with_timeout(
            "sh",
            "legacy actioncheck",
            &["-c", &check_cmd],
            self.timeout(),
        )
        .await?;
        if out.status.success() {
            return Ok(false);
        }
        warn!(
            jail,
            action = %self.spec.name,
            family,
            "legacy actioncheck failed; running repair"
        );
        if let Some(repair_tpl) = cmds.repair.as_deref().filter(|s| !s.trim().is_empty()) {
            let repair_cmd = Self::expand_lifecycle(repair_tpl, jail, &[], "tcp", family);
            run_shell("legacy actionrepair", &repair_cmd, self.timeout()).await?;
        } else {
            if let Some(stop_tpl) = cmds.stop.as_deref().filter(|s| !s.trim().is_empty()) {
                let stop_cmd = Self::expand_lifecycle(stop_tpl, jail, &[], "tcp", family);
                let _ = run_shell("legacy actionstop (repair)", &stop_cmd, self.timeout()).await;
            }
            if let Some(start_tpl) = cmds.start.as_deref().filter(|s| !s.trim().is_empty()) {
                let start_cmd = Self::expand_lifecycle(start_tpl, jail, &[], "tcp", family);
                run_shell("legacy actionstart (repair)", &start_cmd, self.timeout()).await?;
            }
        }
        Ok(true)
    }

    async fn stop_family(
        &self,
        cmds: &LegacyActionFamilyCmds,
        jail: &str,
        family: &str,
    ) -> Result<()> {
        if let Some(flush_tpl) = cmds.flush.as_deref().filter(|s| !s.trim().is_empty()) {
            let flush_cmd = Self::expand_lifecycle(flush_tpl, jail, &[], "tcp", family);
            debug!(jail, action = %self.spec.name, family, command = %flush_cmd, "running legacy actionflush");
            if let Err(err) = run_shell("legacy actionflush", &flush_cmd, self.timeout()).await {
                warn!(jail, action = %self.spec.name, family, error = %err, "legacy actionflush failed; continuing to actionstop");
            }
        }
        if let Some(stop_tpl) = cmds.stop.as_deref().filter(|s| !s.trim().is_empty()) {
            let stop_cmd = Self::expand_lifecycle(stop_tpl, jail, &[], "tcp", family);
            debug!(jail, action = %self.spec.name, family, command = %stop_cmd, "running legacy actionstop");
            run_shell("legacy actionstop", &stop_cmd, self.timeout()).await?;
        }
        Ok(())
    }
}

/// Firewall backend executing resolved Fail2Ban 1.1.1 `action.d` lifecycle commands.
pub struct LegacyActionBackend {
    actions: Vec<RuntimeAction>,
}

impl LegacyActionBackend {
    pub fn new(specs: Vec<LegacyActionSpec>) -> Self {
        Self {
            actions: specs.into_iter().map(RuntimeAction::new).collect(),
        }
    }
}

#[async_trait]
impl FirewallBackend for LegacyActionBackend {
    async fn init(&self, jail: &str, ports: &[String], protocol: &str) -> Result<()> {
        for action in &self.actions {
            if action.spec.start_on_demand {
                debug!(
                    jail,
                    action = %action.spec.name,
                    "deferring legacy actionstart (actionstart_on_demand=true)"
                );
                continue;
            }
            action
                .run_start_if_needed(
                    &action.spec.ipv4,
                    &action.started_v4,
                    jail,
                    ports,
                    protocol,
                    "inet4",
                )
                .await?;
            // Only invoke a separate IPv6 start when the inet6 template differs
            // from inet4 (e.g. [Init?family=inet6] defines a separate ip6 set/chain).
            if action.spec.ipv6.start != action.spec.ipv4.start {
                action
                    .run_start_if_needed(
                        &action.spec.ipv6,
                        &action.started_v6,
                        jail,
                        ports,
                        protocol,
                        "inet6",
                    )
                    .await?;
            }
            info!(
                jail,
                action = %action.spec.name,
                backend = "legacy_action",
                "legacy actionstart complete"
            );
        }
        Ok(())
    }

    async fn teardown(&self, jail: &str) -> Result<()> {
        // Stop in reverse order, matching upstream Actions.stopActions.
        for action in self.actions.iter().rev() {
            let v6_distinct = action.spec.ipv6.stop != action.spec.ipv4.stop
                || action.spec.ipv6.flush != action.spec.ipv4.flush;
            if action.started_v6.swap(false, Ordering::AcqRel) && v6_distinct {
                action.stop_family(&action.spec.ipv6, jail, "inet6").await?;
            }
            if action.started_v4.swap(false, Ordering::AcqRel) || !action.spec.start_on_demand {
                action.stop_family(&action.spec.ipv4, jail, "inet4").await?;
            }
            info!(
                jail,
                action = %action.spec.name,
                backend = "legacy_action",
                "legacy actionstop complete"
            );
        }
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        for action in &self.actions {
            let (cmds, started, family) = action.family_cmds(ip);
            if action.spec.start_on_demand && !started.load(Ordering::Acquire) {
                action
                    .run_start_if_needed(cmds, started, jail, &[], "tcp", family)
                    .await?;
            }
            let command = action.expand_event(&cmds.ban, ip, jail, family);
            debug!(%ip, jail, action = %action.spec.name, family, command = %command, "running legacy actionban");
            if let Err(first_err) = run_shell("legacy actionban", &command, action.timeout()).await
            {
                // Upstream CommandAction runs actioncheck/repair on error and retries once.
                if action.check_and_repair(cmds, jail, family).await? {
                    run_shell("legacy actionban (retry)", &command, action.timeout()).await?;
                } else {
                    return Err(first_err);
                }
            }
        }
        Ok(())
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        for action in self.actions.iter().rev() {
            let (cmds, _, family) = action.family_cmds(ip);
            let command = action.expand_event(&cmds.unban, ip, jail, family);
            debug!(%ip, jail, action = %action.spec.name, family, command = %command, "running legacy actionunban");
            if let Err(first_err) =
                run_shell("legacy actionunban", &command, action.timeout()).await
            {
                if action.spec.repair_on_unban
                    && action.check_and_repair(cmds, jail, family).await?
                {
                    run_shell("legacy actionunban (retry)", &command, action.timeout()).await?;
                } else {
                    return Err(first_err);
                }
            }
        }
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

/// Format `<ip-rev>` matching Fail2Ban 1.1.1 (`IPAddr.ip_rev`):
/// - IPv4 `1.2.3.4` -> `4.3.2.1.`
/// - IPv6 -> reversed hex nibbles separated by `.` with trailing `.`
fn reverse_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.")
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(64);
            for byte in v6.octets().iter().rev() {
                use std::fmt::Write;
                let _ = write!(out, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            out
        }
    }
}

async fn run_shell(label: &str, command: &str, timeout: Duration) -> Result<()> {
    let out = cmd::output_with_timeout("sh", label, &["-c", command], timeout).await?;
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
        let backend = LegacyActionBackend::new(Vec::new());
        assert!(!backend.can_verify());
    }

    #[test]
    fn reverse_ip_matches_fail2ban_111() {
        assert_eq!(
            reverse_ip(&"198.51.100.42".parse().expect("v4")),
            "42.100.51.198."
        );
        assert_eq!(
            reverse_ip(&"2001:db8::1".parse().expect("v6")),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2."
        );
    }
}
