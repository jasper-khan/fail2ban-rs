//! Fail2Ban 1.1.1 `CommandAction` (`fail2ban/server/action.py`).
//!
//! Executes shell commands for action lifecycle (`actionstart`, `actionstop`,
//! `actionflush`, `actionreload`, `actioncheck`, `actionrepair`, `actionban`,
//! `actionreban`, `actionprolong`, `actionunban`) with per-family state tracking,
//! `actionstart_on_demand`, command deduplication across families, static and
//! dynamic tag substitution, and invariant-check / repair recovery.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::duration::{parse_bool, str2seconds};
use crate::error::{Error, Result};
use crate::f2b_log;
use crate::logging::LogLevel;
use crate::ticket::{ActionContext, Ticket, TicketId};

use super::cmd;
use super::policy::{self, ActionPolicy, Family};
use super::tags;

const STATE_STARTED: u8 = 1;
const STATE_HAS_ITEMS: u8 = 2;

const DEFAULT_EMPTY_PROPS: &[&str] = &[
    "actionstart",
    "actionban",
    "actionreban",
    "actionunban",
    "actioncheck",
    "actionrepair",
    "actionflush",
    "actionstop",
    "actionreload",
];

/// Global lock serializing shell command execution across all actions (`action._cmd_lock`).
fn cmd_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpMode {
    Start,
    Flush,
    Stop,
    Reload,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InvariantOutcome {
    Ok,
    SkippedRepair,
    Failed,
}

/// Fail2Ban 1.1.1 `CommandAction` executing OS shell commands.
#[derive(Debug, Clone)]
pub struct CommandAction {
    jail_name: String,
    name: String,
    properties: BTreeMap<String, String>,
    timeout: Duration,
    norestored: bool,
    actionrepair_on_unban: bool,
    allow_ipv6: bool,
    started: BTreeMap<Family, u8>,
    subst_cache: BTreeMap<(String, Family), String>,
    executed_ops: BTreeMap<(String, Family), String>,
    ban_epoch: u64,
}

impl CommandAction {
    /// Construct a new `CommandAction` with upstream default empty commands and 60s timeout.
    pub fn new(jail_name: String, name: String) -> Self {
        let mut action = Self {
            jail_name,
            name,
            properties: BTreeMap::new(),
            timeout: Duration::from_secs(60),
            norestored: false,
            actionrepair_on_unban: false,
            allow_ipv6: true,
            started: BTreeMap::new(),
            subst_cache: BTreeMap::new(),
            executed_ops: BTreeMap::new(),
            ban_epoch: 0,
        };
        action.clear_all_params();
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.action",
            "Created CommandAction {}/{}",
            action.jail_name,
            action.name
        );
        action
    }

    pub fn jail_name(&self) -> &str {
        &self.jail_name
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn ban_epoch(&self) -> u64 {
        self.ban_epoch
    }

    pub fn invalidate_ban_epoch(&mut self) {
        self.ban_epoch = self.ban_epoch.saturating_add(1);
    }

    pub async fn execute_raw_cmd(
        &self,
        real_cmd: &str,
        timeout_override: Option<Duration>,
    ) -> Result<bool> {
        if real_cmd.trim().is_empty() {
            return Ok(true);
        }
        let _guard = cmd_lock().lock().await;
        let (ok, _) =
            cmd::run_shell_cmd(real_cmd, timeout_override.unwrap_or(self.timeout), &[0]).await?;
        Ok(ok)
    }

    pub fn norestored(&self) -> bool {
        self.norestored
    }

    pub fn prolongable(&self) -> bool {
        self.properties.iter().any(|(k, v)| {
            (k == "actionprolong" || k.starts_with("actionprolong?family=")) && !v.trim().is_empty()
        })
    }

    pub fn supports_flush(&self) -> bool {
        self.properties.iter().any(|(k, v)| {
            (k == "actionflush" || k.starts_with("actionflush?family=")) && !v.trim().is_empty()
        })
    }

    /// Clear all parameters back to defaults (used during config reload).
    ///
    /// Preserves runtime `started` family state and `ban_epoch` so live bans stay tracked.
    pub fn clear_all_params(&mut self) {
        self.properties.clear();
        for &key in DEFAULT_EMPTY_PROPS {
            self.properties.insert(key.to_owned(), String::new());
        }
        self.properties
            .insert("timeout".to_owned(), "60".to_owned());
        self.timeout = Duration::from_secs(60);
        self.norestored = false;
        self.actionrepair_on_unban = false;
        self.subst_cache.clear();
        self.executed_ops.clear();
    }

    /// Set an action property, applying `WRAP_CMD_PARAMS` (`timeout`, `bantime`)
    /// and invalidating cached substitutions.
    pub fn set_property(&mut self, key: &str, value: &str) -> Result<()> {
        if key.starts_with('_') {
            return Err(Error::action(format!(
                "cannot set private action property {key:?}"
            )));
        }
        match key {
            // `bantime` is dynamic per-ticket/jail and ignored on CommandAction (`WRAP_CMD_PARAMS`).
            "bantime" => return Ok(()),
            "timeout" => {
                let secs = str2seconds(value)?;
                if !secs.is_finite() || secs < 0.0 {
                    return Err(Error::config(format!(
                        "invalid action timeout value {value:?}"
                    )));
                }
                self.timeout = Duration::from_secs_f64(secs);
                let formatted = if secs.fract() == 0.0 && secs < (u64::MAX as f64) {
                    format!("{}", secs as u64)
                } else {
                    secs.to_string()
                };
                self.properties.insert("timeout".to_owned(), formatted);
            }
            "norestored" => {
                self.norestored = parse_action_bool(value)?;
                self.properties.insert(key.to_owned(), value.to_owned());
            }
            "actionrepair_on_unban" => {
                self.actionrepair_on_unban = parse_action_bool(value)?;
                self.properties.insert(key.to_owned(), value.to_owned());
            }
            _ => {
                self.properties.insert(key.to_owned(), value.to_owned());
            }
        }
        self.subst_cache.clear();
        self.executed_ops.clear();
        f2b_log!(
            LogLevel::Debug,
            "fail2ban.action",
            "  Set {} = {:?}",
            key,
            value
        );
        Ok(())
    }

    pub fn get_property(&self, key: &str) -> Option<String> {
        if key == "banEpoch" {
            return Some(self.ban_epoch.to_string());
        }
        self.properties.get(key).cloned()
    }

    pub fn del_property(&mut self, key: &str) {
        self.properties.remove(key);
        match key {
            "timeout" => self.timeout = Duration::from_secs(60),
            "norestored" => self.norestored = false,
            "actionrepair_on_unban" => self.actionrepair_on_unban = false,
            _ => {}
        }
        self.subst_cache.clear();
        self.executed_ops.clear();
        f2b_log!(LogLevel::Debug, "fail2ban.action", "  Unset {}", key);
    }

    pub fn property_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .properties
            .keys()
            .filter(|k| !k.starts_with('_'))
            .cloned()
            .collect();
        for builtin in ["ESCAPE_CRE", "ESCAPE_VN_CRE", "banEpoch"] {
            if !names.iter().any(|n| n == builtin) {
                names.push(builtin.to_owned());
            }
        }
        names.sort();
        names
    }

    pub fn methods(&self) -> Vec<String> {
        [
            "ban",
            "clearAllParams",
            "consistencyCheck",
            "escapeTag",
            "executeCmd",
            "flush",
            "invalidateBanEpoch",
            "prolong",
            "reban",
            "reload",
            "replaceDynamicTags",
            "replaceTag",
            "start",
            "stop",
            "unban",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    /// Return whether `family` is currently marked started.
    pub fn is_started(&self, family: Family) -> bool {
        self.started.get(&family).copied().unwrap_or(0) != 0
    }

    /// Return whether `family` currently holds banned items (bit 2).
    pub fn has_items(&self, family: Family) -> bool {
        self.started.get(&family).copied().unwrap_or(0) & STATE_HAS_ITEMS != 0
    }

    /// Execute `actionstart` for configured families unless `actionstart_on_demand` defers it.
    pub async fn start(&mut self, allow_ipv6: bool) -> Result<()> {
        self.allow_ipv6 = allow_ipv6;
        let policy = self.policy()?;
        if policy.start_on_demand {
            return Ok(());
        }
        self.execute_operation("<actionstart>", &policy.families, OpMode::Start)
            .await
    }

    /// Execute `actionban` for `ctx`'s target family, respecting `norestored` and
    /// `actionstart_on_demand`, and recovering via `actioncheck`/`actionrepair` on error.
    pub async fn ban(&mut self, ctx: &ActionContext) -> Result<()> {
        if self.norestored && ctx.ticket.restored {
            return Ok(());
        }
        let family = Family::from_ticket_id(ctx.ticket.target_ip());
        self.ban_with_tag("<actionban>", ctx, family).await
    }

    /// Execute `actionreban` if non-empty for `ctx`'s family, otherwise `actionban`.
    pub async fn reban(&mut self, ctx: &ActionContext) -> Result<()> {
        let family = Family::from_ticket_id(ctx.ticket.target_ip());
        let has_reban = !self
            .get_operation("<actionreban>", family)?
            .trim()
            .is_empty();
        let tag = if has_reban {
            "<actionreban>"
        } else {
            "<actionban>"
        };
        self.ban_with_tag(tag, ctx, family).await
    }

    /// Execute `actionprolong` for `ctx`.
    pub async fn prolong(&mut self, ctx: &ActionContext) -> Result<()> {
        if self.norestored && ctx.ticket.restored {
            return Ok(());
        }
        let family = Family::from_ticket_id(ctx.ticket.target_ip());
        self.process_cmd("<actionprolong>", Some(ctx), family).await
    }

    /// Execute `actionunban` if `ctx`'s family is marked as holding banned items.
    pub async fn unban(&mut self, ctx: &ActionContext) -> Result<()> {
        let family = Family::from_ticket_id(ctx.ticket.target_ip());
        if !self.has_items(family) {
            return Ok(());
        }
        self.process_cmd("<actionunban>", Some(ctx), family).await
    }

    /// Execute `actionflush` on started families containing banned items and clear their item bit.
    pub async fn flush(&mut self) -> Result<()> {
        let families: Vec<Family> = self
            .started
            .iter()
            .filter_map(|(&fam, &state)| {
                ((state & (STATE_STARTED | STATE_HAS_ITEMS)) == (STATE_STARTED | STATE_HAS_ITEMS))
                    .then_some(fam)
            })
            .collect();
        if families.is_empty() {
            return Ok(());
        }
        self.execute_operation("<actionflush>", &families, OpMode::Flush)
            .await
    }

    /// Execute `actionstop` on all started families and clear started state.
    pub async fn stop(&mut self) -> Result<()> {
        let families: Vec<Family> = self
            .started
            .iter()
            .filter_map(|(&fam, &state)| (state != 0).then_some(fam))
            .collect();
        if families.is_empty() {
            return Ok(());
        }
        self.started.clear();
        self.execute_operation("<actionstop>", &families, OpMode::Stop)
            .await
    }

    /// Execute `actionreload` on all currently started families.
    pub async fn reload(&mut self) -> Result<()> {
        let families: Vec<Family> = self
            .started
            .iter()
            .filter_map(|(&fam, &state)| (state != 0).then_some(fam))
            .collect();
        if families.is_empty() {
            return Ok(());
        }
        self.execute_operation("<actionreload>", &families, OpMode::Reload)
            .await
    }

    /// Run `actioncheck` (and repair if needed) for every started family.
    ///
    /// Returns `Ok(true)` if all started families are healthy (or repaired), or
    /// `Ok(false)` if any started family could not be restored.
    pub async fn consistency_check(&mut self) -> Result<bool> {
        self.consistency_check_inner(true, "").await
    }

    /// Run `consistencyCheck` after a failed `flush()`, skipping repair during stop/reload
    /// unless `actionrepair_on_unban` is enabled (matching upstream `actions.py:665-672`).
    pub async fn consistency_check_on_flush(&mut self, on_stop: bool) -> Result<bool> {
        let allow_repair = !on_stop || self.actionrepair_on_unban;
        self.consistency_check_inner(allow_repair, "Invariant check failed. Flush is impossible.")
            .await
    }

    async fn consistency_check_inner(
        &mut self,
        allow_repair: bool,
        skip_msg: &str,
    ) -> Result<bool> {
        let started_families: Vec<(Family, u8)> =
            self.started.iter().map(|(&f, &s)| (f, s)).collect();
        let mut all_ok = true;
        for (family, state) in started_families {
            if state == 0 {
                continue;
            }
            if self
                .get_operation("<actioncheck>", family)?
                .trim()
                .is_empty()
            {
                continue;
            }
            if self
                .invariant_check(family, allow_repair, true, skip_msg)
                .await?
                == InvariantOutcome::Failed
            {
                self.started.insert(family, 0);
                self.clear_operation_executed("<actionstart>", family);
                all_ok = false;
            }
        }
        Ok(all_ok)
    }

    fn policy(&self) -> Result<ActionPolicy> {
        policy::project(
            self.properties.keys().map(String::as_str),
            self.properties
                .get("actionstart_on_demand")
                .map(String::as_str),
            self.properties.get("families").map(String::as_str),
            self.allow_ipv6,
        )
    }

    fn get_operation(&mut self, tag_query: &str, family: Family) -> Result<String> {
        let key = (tag_query.to_owned(), family);
        if let Some(cached) = self.subst_cache.get(&key) {
            return Ok(cached.clone());
        }
        let expanded = tags::expand(tag_query, &self.properties, family)?.into_string();
        let with_family = tags::replace_family_tag(&expanded, family.as_str());
        self.subst_cache.insert(key, with_family.clone());
        Ok(with_family)
    }

    fn op_is_already_executed(&self, tag: &str, family: Family, cmd_str: &str) -> bool {
        self.executed_ops
            .iter()
            .any(|((t, f), prev)| t == tag && *f != family && prev == cmd_str)
    }

    fn record_operation_executed(&mut self, tag: &str, family: Family, cmd_str: String) {
        self.executed_ops.insert((tag.to_owned(), family), cmd_str);
    }

    fn clear_operation_executed(&mut self, tag: &str, family: Family) {
        if let Some(prev) = self.executed_ops.remove(&(tag.to_owned(), family)) {
            self.executed_ops.retain(|(t, _), v| t != tag || *v != prev);
        }
    }

    async fn start_one(&mut self, family: Family) -> Result<()> {
        self.execute_operation("<actionstart>", &[family], OpMode::Start)
            .await
    }

    async fn ban_with_tag(&mut self, tag: &str, ctx: &ActionContext, family: Family) -> Result<()> {
        let policy = self.policy()?;
        if policy.start_on_demand && !self.is_started(family) {
            self.start_one(family).await?;
        }
        self.process_cmd(tag, Some(ctx), family).await?;
        *self.started.entry(family).or_insert(0) |= STATE_STARTED | STATE_HAS_ITEMS;
        Ok(())
    }

    async fn execute_operation(
        &mut self,
        tag: &str,
        families: &[Family],
        mode: OpMode,
    ) -> Result<()> {
        let mut first_err: Option<Error> = None;

        for &family in families {
            let cmd_str = match self.get_operation(tag, family) {
                Ok(c) => c,
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    continue;
                }
            };

            let succeeded = if cmd_str.trim().is_empty()
                || self.op_is_already_executed(tag, family, &cmd_str)
            {
                true
            } else {
                match self.execute_with_empty_ctx(&cmd_str, family).await {
                    Ok(true) => true,
                    Ok(false) => {
                        if first_err.is_none() {
                            first_err = Some(Error::action(format!(
                                "Error running {tag} for {}/{}: non-zero exit",
                                self.jail_name, self.name
                            )));
                        }
                        false
                    }
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                        false
                    }
                }
            };

            if succeeded {
                match mode {
                    OpMode::Start => {
                        self.clear_operation_executed("<actionstop>", family);
                        self.started.insert(family, STATE_STARTED);
                    }
                    OpMode::Flush => {
                        if let Some(st) = self.started.get_mut(&family) {
                            *st &= !STATE_HAS_ITEMS;
                        }
                    }
                    OpMode::Stop => {
                        self.clear_operation_executed("<actionstart>", family);
                    }
                    OpMode::Reload => {}
                }
                if !cmd_str.trim().is_empty() {
                    self.record_operation_executed(tag, family, cmd_str);
                }
            } else {
                self.clear_operation_executed(tag, family);
            }
        }

        if matches!(mode, OpMode::Flush | OpMode::Reload) {
            // Deduplicate identical flush/reload commands across families only within a single call.
            self.executed_ops.retain(|(t, _), _| t != tag);
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn process_cmd(
        &mut self,
        tag: &str,
        ctx: Option<&ActionContext>,
        family: Family,
    ) -> Result<()> {
        let initial = self.get_operation(tag, family)?;
        if initial.trim().is_empty() {
            f2b_log!(LogLevel::Debug, "fail2ban.action", "Nothing to do");
            return Ok(());
        }

        let mut repcnt = 0u8;
        loop {
            if repcnt > 0
                && !self
                    .get_operation("<actioncheck>", family)?
                    .trim()
                    .is_empty()
            {
                let is_unban = tag == "<actionunban>";
                let allow_repair = !is_unban || self.actionrepair_on_unban;
                let force_start = !is_unban;
                if self
                    .invariant_check(
                        family,
                        allow_repair,
                        force_start,
                        "Invariant check failed. Unban is impossible.",
                    )
                    .await?
                    != InvariantOutcome::Ok
                {
                    return Err(Error::action(format!(
                        "Error executing {tag} in {}/{}: invariant check failed",
                        self.jail_name, self.name
                    )));
                }
            }

            let static_cmd = self.get_operation(tag, family)?;
            let shell_cmd = match ctx {
                Some(c) if static_cmd.contains("<ip-host>") => {
                    let resolved_host = match c.ticket.target_ip().ip() {
                        Some(ip) => tokio::task::spawn_blocking(move || {
                            crate::filter::ipdns::ip_to_name(&ip)
                        })
                        .await
                        .ok()
                        .flatten(),
                        None => None,
                    };
                    tags::build_shell_command(&static_cmd, c, family.as_str(), None, &|_| {
                        resolved_host.clone()
                    })
                }
                Some(c) => tags::build_shell_command(
                    &static_cmd,
                    c,
                    family.as_str(),
                    None,
                    &tags::default_reverse_dns,
                ),
                None => tags::ShellCommand {
                    script: static_cmd,
                    args: Vec::new(),
                },
            };

            let (ok, code) = self.execute_cmd(&shell_cmd).await?;
            repcnt += 1;
            if ok {
                return Ok(());
            }
            if repcnt > 1 {
                return Err(Error::action(format!(
                    "Error executing {tag} for {}/{}: exited with {code}",
                    self.jail_name, self.name
                )));
            }
        }
    }

    async fn invariant_check(
        &mut self,
        family: Family,
        allow_repair: bool,
        force_start: bool,
        skip_msg: &str,
    ) -> Result<InvariantOutcome> {
        if !force_start && !self.is_started(family) {
            return Ok(InvariantOutcome::Ok);
        }
        let check_cmd = self.get_operation("<actioncheck>", family)?;
        if check_cmd.trim().is_empty()
            || self
                .execute_with_empty_ctx(&check_cmd, family)
                .await
                .unwrap_or(false)
        {
            return Ok(InvariantOutcome::Ok);
        }
        if !allow_repair {
            f2b_log!(LogLevel::Error, "fail2ban.action", "{skip_msg}");
            return Ok(InvariantOutcome::SkippedRepair);
        }

        f2b_log!(
            LogLevel::Error,
            "fail2ban.action",
            "Invariant check failed. Trying to restore a sane environment"
        );
        self.ban_epoch += 1;

        let repair_cmd = self.get_operation("<actionrepair>", family)?;
        if !repair_cmd.trim().is_empty() {
            let repaired = self
                .execute_with_empty_ctx(&repair_cmd, family)
                .await
                .unwrap_or(false);
            if !repaired {
                self.started.insert(family, 0);
                self.clear_operation_executed("<actionstart>", family);
                f2b_log!(
                    LogLevel::Critical,
                    "fail2ban.action",
                    "Unable to restore environment"
                );
                return Ok(InvariantOutcome::Failed);
            }
            self.started.insert(family, STATE_STARTED);
        } else {
            if self.is_started(family) {
                self.started.insert(family, 0);
                let _ = self
                    .execute_operation("<actionstop>", &[family], OpMode::Stop)
                    .await;
            }
            self.clear_operation_executed("<actionstart>", family);
            let policy = self.policy()?;
            if (force_start || !policy.start_on_demand) && self.start_one(family).await.is_err() {
                return Ok(InvariantOutcome::Failed);
            }
        }

        if self.is_started(family)
            && !self
                .execute_with_empty_ctx(&check_cmd, family)
                .await
                .unwrap_or(false)
        {
            f2b_log!(
                LogLevel::Critical,
                "fail2ban.action",
                "Unable to restore environment"
            );
            return Ok(InvariantOutcome::Failed);
        }

        Ok(InvariantOutcome::Ok)
    }

    async fn execute_with_empty_ctx(&self, static_cmd: &str, family: Family) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let ctx = ActionContext {
            jail_name: self.jail_name.clone(),
            ticket: Ticket::new(TicketId::Raw(String::new()), now),
            default_ban_time: 0,
            ip_failures: 0,
            ip_jail_failures: 0,
            ip_matches: Vec::new(),
            ip_jail_matches: Vec::new(),
            jail_stats: Default::default(),
        };
        let shell_cmd = tags::build_shell_command(
            static_cmd,
            &ctx,
            family.as_str(),
            None,
            &tags::default_reverse_dns,
        );
        let (ok, _) = self.execute_cmd(&shell_cmd).await?;
        Ok(ok)
    }

    async fn execute_cmd(&self, shell_cmd: &tags::ShellCommand) -> Result<(bool, i32)> {
        if shell_cmd.script.trim().is_empty() {
            f2b_log!(LogLevel::Debug, "fail2ban.action", "Nothing to do");
            return Ok((true, 0));
        }
        let _guard = cmd_lock().lock().await;
        cmd::run_shell_cmd_args(&shell_cmd.script, &shell_cmd.args, self.timeout, &[0]).await
    }
}

fn parse_action_bool(raw: &str) -> Result<bool> {
    if raw.trim().is_empty() {
        return Ok(false);
    }
    parse_bool(raw)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ctx_for(ip: &str, jail: &str, restored: bool) -> ActionContext {
        let mut ticket = Ticket::new(TicketId::parse(ip), 1_700_000_000.0);
        ticket.restored = restored;
        ticket.matches = vec!["auth failed".to_owned()];
        ActionContext {
            jail_name: jail.to_owned(),
            ticket,
            default_ban_time: 600,
            ip_failures: 3,
            ip_jail_failures: 2,
            ip_matches: vec!["auth failed".to_owned()],
            ip_jail_matches: vec!["auth failed".to_owned()],
            jail_stats: Default::default(),
        }
    }

    fn read_log(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn properties_wrap_timeout_ignore_bantime_and_track_flags() {
        let mut act = CommandAction::new("sshd".to_owned(), "iptables".to_owned());
        assert_eq!(act.timeout(), Duration::from_secs(60));
        assert!(!act.norestored());
        assert!(!act.prolongable());

        act.set_property("timeout", "2m 5s").unwrap();
        assert_eq!(act.timeout(), Duration::from_secs(125));
        assert_eq!(act.get_property("timeout").as_deref(), Some("125"));

        // `bantime` must be ignored per `WRAP_CMD_PARAMS`.
        act.set_property("bantime", "999").unwrap();
        assert_eq!(act.get_property("bantime"), None);

        act.set_property("norestored", "yes").unwrap();
        assert!(act.norestored());

        act.set_property("actionprolong", "echo prolong <ip>")
            .unwrap();
        assert!(act.prolongable());

        let names = act.property_names();
        assert!(names.contains(&"actionban".to_owned()));
        assert!(names.contains(&"timeout".to_owned()));
        assert!(!names.contains(&"bantime".to_owned()));

        act.del_property("norestored");
        assert!(!act.norestored());

        act.clear_all_params();
        assert_eq!(act.timeout(), Duration::from_secs(60));
        assert!(!act.prolongable());
    }

    #[tokio::test]
    async fn start_on_demand_and_family_dedup_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        let log = dir.path().join("events.log");
        let log_s = log.display().to_string();

        let mut act = CommandAction::new("sshd".to_owned(), "nft".to_owned());
        // Shared start/flush/stop commands across inet4 and inet6:
        act.set_property("actionstart", &format!("echo start >> '{log_s}'"))
            .unwrap();
        act.set_property(
            "actionstart?family=inet6",
            &format!("echo start >> '{log_s}'"),
        )
        .unwrap();
        act.set_property("actionban", &format!("echo ban4:<ip> >> '{log_s}'"))
            .unwrap();
        act.set_property(
            "actionban?family=inet6",
            &format!("echo ban6:<ip> >> '{log_s}'"),
        )
        .unwrap();
        act.set_property(
            "actionunban",
            &format!("echo unban:<family>:<ip> >> '{log_s}'"),
        )
        .unwrap();
        act.set_property("actionflush", &format!("echo flush >> '{log_s}'"))
            .unwrap();
        act.set_property("actionstop", &format!("echo stop >> '{log_s}'"))
            .unwrap();
        act.set_property("norestored", "1").unwrap();

        // Eager start does nothing when `?family=` sets `start_on_demand=true`.
        act.start(true).await.unwrap();
        assert!(read_log(&log).is_empty());

        // Restored ticket is skipped by `norestored=1`.
        act.ban(&ctx_for("192.0.2.1", "sshd", true)).await.unwrap();
        assert!(read_log(&log).is_empty());

        // Unban on family with no banned items is a no-op.
        act.unban(&ctx_for("2001:db8::1", "sshd", false))
            .await
            .unwrap();
        assert!(read_log(&log).is_empty());

        // Ban IPv6 triggers start once + ban6; subsequent IPv4 ban deduplicates identical start!
        act.ban(&ctx_for("2001:db8::1", "sshd", false))
            .await
            .unwrap();
        act.ban(&ctx_for("192.0.2.2", "sshd", false)).await.unwrap();
        act.unban(&ctx_for("2001:db8::1", "sshd", false))
            .await
            .unwrap();
        act.flush().await.unwrap();
        // After flush cleared bit 2, unban is a no-op.
        act.unban(&ctx_for("192.0.2.2", "sshd", false))
            .await
            .unwrap();
        act.stop().await.unwrap();

        assert_eq!(
            read_log(&log),
            vec![
                "start",
                "ban6:2001:db8::1",
                "ban4:192.0.2.2",
                "unban:inet6:2001:db8::1",
                "flush",
                "stop",
            ]
        );
    }

    #[tokio::test]
    async fn ban_repairs_via_actioncheck_and_actionrepair_and_reban_prolong() {
        let dir = tempfile::TempDir::new().unwrap();
        let healthy = dir.path().join("healthy");
        let log = dir.path().join("ops.log");
        let h_s = healthy.display().to_string();
        let l_s = log.display().to_string();

        let mut act = CommandAction::new("sshd".to_owned(), "fw".to_owned());
        act.set_property(
            "actionstart",
            &format!("echo start >> '{l_s}'; touch '{h_s}'"),
        )
        .unwrap();
        act.set_property(
            "actioncheck",
            &format!("echo check >> '{l_s}'; test -f '{h_s}'"),
        )
        .unwrap();
        act.set_property(
            "actionrepair",
            &format!("echo repair >> '{l_s}'; touch '{h_s}'"),
        )
        .unwrap();
        act.set_property(
            "actionban",
            &format!("echo ban:<ip> >> '{l_s}'; test -f '{h_s}'"),
        )
        .unwrap();
        act.set_property("actionreban", &format!("echo reban:<ip> >> '{l_s}'"))
            .unwrap();
        act.set_property("actionprolong", &format!("echo prolong:<ip> >> '{l_s}'"))
            .unwrap();
        act.set_property("actionreload", &format!("echo reload >> '{l_s}'"))
            .unwrap();
        act.set_property(
            "actionunban",
            &format!("echo unban:<ip> >> '{l_s}'; test -f '{h_s}'"),
        )
        .unwrap();

        act.start(false).await.unwrap();
        // Simulate external firewall flush removing chain marker file.
        std::fs::remove_file(&healthy).unwrap();

        act.ban(&ctx_for("192.0.2.5", "sshd", false)).await.unwrap();
        assert_eq!(act.ban_epoch(), 1);
        act.reban(&ctx_for("192.0.2.5", "sshd", false))
            .await
            .unwrap();
        act.prolong(&ctx_for("192.0.2.5", "sshd", false))
            .await
            .unwrap();
        act.reload().await.unwrap();

        // Break marker again: unban with `actionrepair_on_unban=false` must NOT run repair.
        std::fs::remove_file(&healthy).unwrap();
        let err = act
            .unban(&ctx_for("192.0.2.5", "sshd", false))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invariant check failed"));

        // Enable `actionrepair_on_unban` and verify repair + retry succeeds.
        act.set_property("actionrepair_on_unban", "true").unwrap();
        act.unban(&ctx_for("192.0.2.5", "sshd", false))
            .await
            .unwrap();

        assert_eq!(
            read_log(&log),
            vec![
                "start",
                "ban:192.0.2.5",
                "check",
                "repair",
                "check",
                "ban:192.0.2.5",
                "reban:192.0.2.5",
                "prolong:192.0.2.5",
                "reload",
                "unban:192.0.2.5",
                "check",
                "unban:192.0.2.5",
                "check",
                "repair",
                "check",
                "unban:192.0.2.5",
            ]
        );
    }

    #[tokio::test]
    async fn consistency_check_falls_back_to_stop_and_start_without_actionrepair() {
        let dir = tempfile::TempDir::new().unwrap();
        let healthy = dir.path().join("ok");
        let log = dir.path().join("trace.log");
        let h_s = healthy.display().to_string();
        let l_s = log.display().to_string();

        let mut act = CommandAction::new("nginx".to_owned(), "fw".to_owned());
        act.set_property(
            "actionstart",
            &format!("echo start >> '{l_s}'; touch '{h_s}'"),
        )
        .unwrap();
        act.set_property(
            "actionstop",
            &format!("echo stop >> '{l_s}'; rm -f '{h_s}'"),
        )
        .unwrap();
        act.set_property(
            "actioncheck",
            &format!("echo check >> '{l_s}'; test -f '{h_s}'"),
        )
        .unwrap();

        act.start(false).await.unwrap();
        std::fs::remove_file(&healthy).unwrap();

        assert!(act.consistency_check().await.unwrap());
        assert_eq!(act.ban_epoch(), 1);
        assert!(healthy.exists());
        assert_eq!(
            read_log(&log),
            vec!["start", "check", "stop", "start", "check"]
        );
    }

    #[tokio::test]
    async fn shared_dual_stack_flush_and_reload_execute_again_on_subsequent_calls() {
        let dir = tempfile::TempDir::new().unwrap();
        let log = dir.path().join("trace.log");
        let l_s = log.display().to_string();

        let mut act = CommandAction::new("sshd".to_owned(), "fw".to_owned());
        act.set_property("actionstart", &format!("echo start >> '{l_s}'"))
            .unwrap();
        act.set_property("actionban", &format!("echo ban:<ip> >> '{l_s}'"))
            .unwrap();
        act.set_property("actionflush", &format!("echo flush >> '{l_s}'"))
            .unwrap();
        act.set_property("actionreload", &format!("echo reload >> '{l_s}'"))
            .unwrap();

        act.start(true).await.unwrap();
        act.ban(&ctx_for("192.0.2.1", "sshd", false)).await.unwrap();
        act.ban(&ctx_for("2001:db8::1", "sshd", false))
            .await
            .unwrap();
        // First flush covers both families and deduplicates identical flush command to once.
        act.flush().await.unwrap();
        // Re-banning IPv4 only and flushing again must NOT be skipped by stale IPv6 dedup.
        act.ban(&ctx_for("192.0.2.2", "sshd", false)).await.unwrap();
        act.flush().await.unwrap();
        // Two reloads each deduplicate across families within the call, running twice total.
        act.reload().await.unwrap();
        act.reload().await.unwrap();

        assert_eq!(
            read_log(&log),
            vec![
                "start",
                "ban:192.0.2.1",
                "ban:2001:db8::1",
                "flush",
                "ban:192.0.2.2",
                "flush",
                "reload",
                "reload",
            ]
        );
    }
}
