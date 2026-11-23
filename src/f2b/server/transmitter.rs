//! Commands exchanged between Fail2Ban clients and the service.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::jail::{Jail, JailState, current_unix_seconds};
use super::make_parent;
use crate::VERSION;
use crate::action::{ActionKind, Family, escape_tag, replace_dynamic_tags, tags};
use crate::client::beautifier::py_repr;
use crate::db::{DEFAULT_MAX_MATCHES, DEFAULT_PURGE_AGE, Fail2BanDb};
use crate::duration::{parse_bool, str2seconds_i64};
use crate::error::{Error, Result};
use crate::f2b_log;
use crate::filter::ipdns::{allow_ipv6, clear_dns_caches, set_allow_ipv6_str};
use crate::logging::{self, LogLevel};
use crate::protocol::PickleValue::{
    self as Value, Bool, Dict, Float, Int, List, None as Null, Tuple,
};
use crate::ticket::{ActionContext, Ticket, TicketId};

struct PendingReloadJail {
    untouched: bool,
    force_restart: bool,
}

#[derive(Default)]
pub struct Transmitter {
    jails: BTreeMap<String, Jail>,
    jail_order: Vec<String>,
    db: Option<Arc<Mutex<Fail2BanDb>>>,
    pending_reload: Option<BTreeMap<String, PendingReloadJail>>,
    reload_replacing_all: bool,
    staged_db: Option<Option<Arc<Mutex<Fail2BanDb>>>>,
    staged_jails: BTreeMap<String, Jail>,
    staged_order: Vec<String>,
    staged_to_start: BTreeSet<String>,
    stacksize: i64,
    pub(super) stopping: bool,
}

impl Transmitter {
    pub async fn dispatch(&mut self, value: &Value) -> Result<Value> {
        if self.stopping {
            return Err(Error::invalid_command("Server is stopping"));
        }
        self.command(list(value)?, false).await
    }

    pub(super) async fn stream(&mut self, commands: &[Value]) -> Result<Value> {
        for frame in commands {
            Box::pin(self.command(list(frame)?, true)).await?;
        }
        Ok(Null)
    }

    async fn command(&mut self, command: &[Value], quiet: bool) -> Result<Value> {
        let (head, args) = command.split_first().ok_or_else(invalid)?;
        let name = head.as_str().ok_or_else(invalid)?;
        match name {
            "ping" => Ok(text("pong")),
            "version" => Ok(text(VERSION)),
            "echo" => Ok(List(args.to_vec())),
            "server-status" => Ok(text("Server ready")),
            "server-stream" => self.stream(list(arg(args, 0)?)?).await,
            "flushlogs" => Ok(text(logging::flush_logs()?)),
            "status" => self.status(args).await,
            "stats" | "statistic" | "statistics" => Ok(self.all_status("stats").await),
            "add" => {
                let name = string(args, 0)?;
                let backend = args.get(1).and_then(Value::as_str).unwrap_or("auto");
                self.add_jail(name, backend).await?;
                Ok(text(name))
            }
            "start" => {
                let name = string(args, 0)?;
                if self.pending_reload.is_some() && self.staged_jails.contains_key(name) {
                    self.staged_to_start.insert(name.to_owned());
                    if let Some(pending) = &mut self.pending_reload {
                        pending.remove(name);
                    }
                    return Ok(Null);
                }
                self.jail(name)?.start().await?;
                if let Some(pending) = &mut self.pending_reload {
                    pending.remove(name);
                }
                Ok(Null)
            }
            "stop" => {
                match args.first() {
                    None => {
                        self.stop_all().await?;
                        self.stopping = true;
                    }
                    Some(value) if value.as_str() == Some("--all") => self.stop_all().await?,
                    Some(value) => {
                        self.remove_jail(value.as_str().ok_or_else(invalid)?)
                            .await?
                    }
                }
                Ok(Null)
            }
            "reload" => self.reload(args).await,
            "get" => self.get(args).await,
            "multi-set" | "set" => self.set(args, name == "multi-set", quiet).await,
            "unban" if !args.is_empty() => {
                let ips = strings(args)?;
                let ips = if ips == ["--all"] {
                    None
                } else {
                    Some(ips.as_slice())
                };
                Ok(integer(self.unban(ips).await?))
            }
            "banned" => self.banned(&strings(args)?).await,
            "config-error" => {
                f2b_log!(
                    LogLevel::Error,
                    "fail2ban.transmitter",
                    "{}",
                    string(args, 0)?
                );
                Ok(Null)
            }
            "sleep" => {
                let secs = arg(args, 0)?.as_f64().ok_or_else(invalid)?;
                let duration = Duration::try_from_secs_f64(secs).map_err(|_| invalid())?;
                tokio::time::sleep(duration).await;
                Ok(Null)
            }
            _ => Err(invalid()),
        }
    }

    fn jail(&self, name: &str) -> Result<&Jail> {
        self.staged_jails
            .get(name)
            .or_else(|| self.jails.get(name))
            .ok_or_else(|| Error::unknown_jail(name))
    }

    async fn add_jail(&mut self, name: &str, backend: &str) -> Result<()> {
        if name == "--all" {
            return Err(Error::invalid_command("Reserved name '--all'"));
        }
        if self.staged_jails.contains_key(name) {
            return Err(Error::duplicate_jail(name));
        }
        if let Some(jail) = self.jails.get(name) {
            let pending = self
                .pending_reload
                .as_mut()
                .and_then(|jails| jails.get_mut(name));
            let Some(entry) = pending.filter(|e| e.untouched) else {
                return Err(Error::duplicate_jail(name));
            };
            entry.untouched = false;
            let force_restart = entry.force_restart;
            let old_backend = jail.state.lock().await.backend_spec.clone();
            if !force_restart && old_backend == backend {
                f2b_log!(LogLevel::Info, "fail2ban.server", "Reload jail {name:?}");
                return Ok(());
            }
            if force_restart {
                f2b_log!(
                    LogLevel::Info,
                    "fail2ban.server",
                    "Restart jail {name:?} (reason: --restart)"
                );
            } else {
                f2b_log!(
                    LogLevel::Info,
                    "fail2ban.server",
                    "Restart jail {name:?} (reason: {old_backend:?} != {backend:?})"
                );
            }
            let candidate = Jail::new(name, backend, self.effective_db().cloned())?;
            self.staged_jails.insert(name.to_owned(), candidate);
            self.staged_order.push(name.to_owned());
            return Ok(());
        }
        let jail = Jail::new(name, backend, self.effective_db().cloned())?;
        if self.pending_reload.is_some() {
            self.staged_jails.insert(name.to_owned(), jail);
            self.staged_order.push(name.to_owned());
            return Ok(());
        }
        self.with_db(|db| db.add_jail(name))?;
        self.jails.insert(name.to_owned(), jail);
        self.jail_order.push(name.to_owned());
        Ok(())
    }

    async fn remove_jail(&mut self, name: &str) -> Result<()> {
        let jail = self
            .jails
            .remove(name)
            .ok_or_else(|| Error::unknown_jail(name))?;
        self.jail_order.retain(|existing| existing != name);
        let stopped = jail.stop().await;
        stopped.and(self.with_db(|db| db.del_jail(name)).map(|_| ()))
    }

    pub(super) async fn stop_all(&mut self) -> Result<()> {
        let mut result = Ok(());
        for name in self.jails.keys().cloned().collect::<Vec<_>>() {
            result = result.and(self.remove_jail(&name).await);
        }
        result
    }

    async fn reload(&mut self, args: &[Value]) -> Result<Value> {
        if self.pending_reload.is_some() {
            return Err(Error::invalid_command("Reload already in progress"));
        }
        let target = string(args, 0)?;
        let options = strings(list(arg(args, 1)?)?)?;
        let commands = list(arg(args, 2)?)?;
        let has = |flag| options.iter().any(|option| option == flag);
        let names = if target == "--all" {
            clear_dns_caches();
            self.jails.keys().cloned().collect::<Vec<_>>()
        } else if has("--if-exists") && !self.jails.contains_key(target) {
            Vec::new()
        } else {
            self.jail(target)?;
            vec![target.to_owned()]
        };
        if let Err(err) = validate_config_stream(commands) {
            f2b_log!(LogLevel::Info, "fail2ban.server", "Reload finished.");
            return Err(err);
        }
        if has("--unban") {
            for name in &names {
                let jail = self.jail(name)?;
                jail.state.lock().await.unban_ip(None, true).await?;
            }
        }
        let replacing_all =
            has("--restart") && (target == "--all" || names.len() == self.jails.len());
        let mut pending = BTreeMap::new();
        for name in names {
            if has("--restart") {
                pending.insert(
                    name,
                    PendingReloadJail {
                        untouched: true,
                        force_restart: true,
                    },
                );
            } else {
                let jail = self.jail(&name)?;
                jail.reload_begin().await;
                pending.insert(
                    name,
                    PendingReloadJail {
                        untouched: true,
                        force_restart: false,
                    },
                );
            }
        }
        self.pending_reload = Some(pending);
        self.reload_replacing_all = replacing_all;
        self.staged_db = None;
        self.staged_jails.clear();
        self.staged_order.clear();
        self.staged_to_start.clear();

        let mut result = self.stream(commands).await.map(|_| ());
        let leftover = self.pending_reload.take().unwrap_or_default();
        self.reload_replacing_all = false;
        let staged_db = self.staged_db.take();
        let staged_order = std::mem::take(&mut self.staged_order);
        let mut staged_jails = std::mem::take(&mut self.staged_jails);
        let staged_to_start = std::mem::take(&mut self.staged_to_start);

        if result.is_ok() {
            for name in &staged_order {
                if let Some(candidate) = staged_jails.get(name) {
                    let st = candidate.state.lock().await;
                    if let Err(err) = st.validate_backend().await {
                        result = Err(err);
                        break;
                    }
                }
            }
        }
        if result.is_ok() {
            for (name, jail) in &self.jails {
                if staged_jails.contains_key(name) {
                    continue;
                }
                if jail.state.lock().await.is_reloading()
                    && let Err(err) = jail.reload_commit().await
                {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok()
            && let Some(new_db) = staged_db
        {
            if let Err(err) = self.stop_all().await {
                result = Err(err);
            } else {
                self.db = new_db;
                if let Err(err) = self.with_db(|db| db.del_all_jails()) {
                    result = Err(err);
                }
            }
        }
        if result.is_ok() {
            for name in staged_order {
                let Some(candidate) = staged_jails.remove(&name) else {
                    continue;
                };
                if self.jails.contains_key(&name)
                    && let Err(err) = self.remove_jail(&name).await
                {
                    result = Err(err);
                    break;
                }
                if let Err(err) = self.with_db(|db| db.add_jail(&name)) {
                    result = Err(err);
                    break;
                }
                self.jails.insert(name.clone(), candidate);
                if !self.jail_order.iter().any(|existing| existing == &name) {
                    self.jail_order.push(name.clone());
                }
                if staged_to_start.contains(&name)
                    && let Err(err) = self.jails[&name].start().await
                {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok() {
            for (name, state) in leftover {
                if state.untouched && self.jails.contains_key(&name) {
                    result = result.and(self.remove_jail(&name).await);
                }
            }
        } else {
            drop(staged_jails);
            for jail in self.jails.values() {
                if jail.state.lock().await.is_reloading() {
                    jail.reload_abort().await;
                }
            }
        }
        f2b_log!(LogLevel::Info, "fail2ban.server", "Reload finished.");
        result.map(|_| text("OK"))
    }

    fn effective_db(&self) -> Option<&Arc<Mutex<Fail2BanDb>>> {
        match &self.staged_db {
            Some(staged) => staged.as_ref(),
            None => self.db.as_ref(),
        }
    }

    fn with_db<T>(&self, op: impl FnOnce(&mut Fail2BanDb) -> Result<T>) -> Result<Option<T>> {
        self.db
            .as_ref()
            .map(|db| {
                let mut db = db
                    .lock()
                    .map_err(|_| Error::database("database lock poisoned"))?;
                op(&mut db)
            })
            .transpose()
    }

    fn with_effective_db<T>(
        &self,
        op: impl FnOnce(&mut Fail2BanDb) -> Result<T>,
    ) -> Result<Option<T>> {
        self.effective_db()
            .map(|db| {
                let mut db = db
                    .lock()
                    .map_err(|_| Error::database("database lock poisoned"))?;
                op(&mut db)
            })
            .transpose()
    }

    fn set_database(&mut self, filename: &str) -> Result<()> {
        let prior = self.with_effective_db(|db| Ok(db.filename().to_owned()))?;
        let disabled = filename.eq_ignore_ascii_case("none");
        if prior.as_deref() == Some(filename) || (prior.is_none() && disabled) {
            return Ok(());
        }
        let stage_switch = self.pending_reload.is_some()
            && (self.jails.is_empty() || self.reload_replacing_all)
            && self.staged_jails.is_empty();
        if !stage_switch && (!self.jails.is_empty() || !self.staged_jails.is_empty()) {
            return Err(Error::database(
                "Cannot change database when there are jails present",
            ));
        }
        if !disabled && filename != ":memory:" {
            make_parent(Path::new(filename))
                .map_err(|e| Error::io("creating database directory", e))?;
        }
        let opened = Fail2BanDb::open_optional(filename, DEFAULT_PURGE_AGE, DEFAULT_MAX_MATCHES)?
            .map(|db| Arc::new(Mutex::new(db)));
        if stage_switch {
            self.staged_db = Some(opened);
            return Ok(());
        }
        if let Some(ref db_arc) = opened {
            let db = db_arc
                .lock()
                .map_err(|_| Error::database("database lock poisoned"))?;
            db.del_all_jails()?;
        }
        self.db = opened;
        Ok(())
    }

    pub(super) fn purge(&self) {
        if let Err(err) = self.with_db(|db| db.purge(current_unix_seconds() as i64)) {
            f2b_log!(LogLevel::Error, "fail2ban.database", "{err}");
        }
    }

    async fn status(&self, args: &[Value]) -> Result<Value> {
        let names = || {
            [
                field("Number of jail", integer(self.jails.len())),
                field(
                    "Jail list",
                    text(self.jails.keys().cloned().collect::<Vec<_>>().join(", ")),
                ),
            ]
        };
        match args {
            [] => Ok(List(Vec::from(names()))),
            [target] | [target, _] => {
                let target = target.as_str().ok_or_else(invalid)?;
                let flavor = args.get(1).and_then(Value::as_str).unwrap_or("basic");
                if target == "--all" {
                    let all = self.all_status(flavor).await;
                    if flavor == "stats" {
                        return Ok(all);
                    }
                    let mut result = Vec::from(names());
                    result.push(all);
                    Ok(List(result))
                } else {
                    Ok(self.jail(target)?.state.lock().await.status(flavor))
                }
            }
            _ => Err(invalid()),
        }
    }

    async fn all_status(&self, flavor: &str) -> Value {
        let mut statuses = Vec::new();
        for (name, jail) in &self.jails {
            statuses.push((text(name), jail.state.lock().await.status(flavor)));
        }
        Dict(statuses)
    }

    async fn unban(&self, ips: Option<&[String]>) -> Result<usize> {
        let mut count = 0;
        for name in &self.jail_order {
            if let Some(jail) = self.jails.get(name) {
                count += jail.state.lock().await.unban_ip(ips, true).await?;
            }
        }
        Ok(count)
    }

    async fn banned(&self, ips: &[String]) -> Result<Value> {
        let mut result = Vec::new();
        if ips.is_empty() {
            for name in &self.jail_order {
                if let Some(jail) = self.jails.get(name) {
                    let banned = jail.state.lock().await.get_banned(&[]);
                    result.push(Dict(vec![(text(name), banned)]));
                }
            }
        } else {
            for ip in ips {
                let mut names = Vec::new();
                for name in &self.jail_order {
                    if let Some(jail) = self.jails.get(name)
                        && jail.state.lock().await.get_banned(std::slice::from_ref(ip)) == Int(1)
                    {
                        names.push(text(name));
                    }
                }
                result.push(List(names));
            }
        }
        Ok(List(result))
    }

    fn global(&self, key: &str) -> Result<Option<Value>> {
        Ok(Some(match key {
            "loglevel" => text(logging::get_level().as_str()),
            "logtarget" => text(logging::get_target()),
            "syslogsocket" => text(logging::get_syslog_socket()),
            "thread" => Dict(vec![(text("stacksize"), Int(self.stacksize))]),
            "dbfile" => self
                .with_effective_db(|db| Ok(text(db.filename())))?
                .unwrap_or(Null),
            "dbmaxmatches" => self
                .with_effective_db(|db| Ok(integer(db.max_matches())))?
                .unwrap_or(Null),
            "dbpurgeage" => self
                .with_effective_db(|db| Ok(Int(db.purge_age())))?
                .unwrap_or(Null),
            _ => return Ok(None),
        }))
    }

    async fn get(&self, args: &[Value]) -> Result<Value> {
        let name = string(args, 0)?;
        if let Some(value) = self.global(name)? {
            return Ok(value);
        }
        let jail = self.jail(name)?;
        let mut jail = jail.state.lock().await;
        jail_property(
            &mut jail,
            string(args, 1)?,
            args.get(2..).unwrap_or_default(),
        )
        .await
    }

    fn set_global(&mut self, key: &str, args: &[Value]) -> Result<Option<Value>> {
        match key {
            "loglevel" => logging::set_level(LogLevel::parse(&scalar(args, 0)?)?),
            "logtarget" => logging::set_target(string(args, 0)?)?,
            "syslogsocket" => logging::set_syslog_socket(string(args, 0)?.to_owned())?,
            "allowipv6" => {
                set_allow_ipv6_str(&scalar(args, 0)?)?;
                return Ok(Some(arg(args, 0)?.clone()));
            }
            "dbfile" => self.set_database(string(args, 0)?)?,
            "dbmaxmatches" => {
                self.with_effective_db(|db| {
                    db.set_max_matches(nonnegative(args, 0)?);
                    Ok(())
                })?;
            }
            "dbpurgeage" => {
                self.with_effective_db(|db| {
                    db.set_purge_age(str2seconds_i64(&scalar(args, 0)?)?);
                    Ok(())
                })?;
            }
            "thread" => {
                let Dict(opts) = arg(args, 0)? else {
                    return Err(invalid());
                };
                for (key, value) in opts {
                    if key.as_str() != Some("stacksize") {
                        return Err(Error::Key(format!("unknown option {}", py_repr(key))));
                    }
                    let size = value.as_i64().ok_or_else(|| {
                        Error::Value(format!(
                            "invalid literal for int() with base 10: {}",
                            py_repr(value)
                        ))
                    })?;
                    let bytes = size.checked_mul(1024);
                    if size < 0 || (size != 0 && size < 32) || bytes.is_none() {
                        let shown = bytes.unwrap_or(size);
                        return Err(Error::Value(format!("size not valid: {shown} bytes")));
                    }
                    self.stacksize = size;
                }
                return Ok(Some(Null));
            }
            _ => return Ok(None),
        }
        self.global(key)
    }

    async fn set(&mut self, args: &[Value], multiple: bool, quiet: bool) -> Result<Value> {
        let name = string(args, 0)?;
        if let Some(value) = self.set_global(name, args.get(1..).unwrap_or_default())? {
            return Ok(if quiet { Null } else { value });
        }
        let jail = self.jail(name)?;
        let key = string(args, 1)?;
        let args = args.get(2..).ok_or_else(invalid)?;
        if key == "idle" {
            let idle = match string(args, 0)? {
                "on" => true,
                "off" => false,
                _ => {
                    return Err(Error::invalid_command(
                        "Invalid idle option, must be 'on' or 'off'",
                    ));
                }
            };
            jail.set_idle(idle).await;
            return Ok(if quiet { Null } else { Bool(idle) });
        }
        let mut state = jail.state.lock().await;
        let get_key = match key {
            "ignoreself" => {
                state.filter.set_ignore_self_str(&scalar(args, 0)?)?;
                key
            }
            "addignoreip" => {
                for ip in strings(args)? {
                    state.filter.add_ignore_ip(&ip);
                }
                "ignoreip"
            }
            "delignoreip" => {
                state.filter.del_ignore_ip(Some(string(args, 0)?));
                "ignoreip"
            }
            "ignorecommand" => {
                state
                    .filter
                    .set_ignore_command(optional_string(arg(args, 0)?));
                key
            }
            "ignorecache" => {
                state
                    .filter
                    .set_ignore_cache(optional_string(arg(args, 0)?))?;
                key
            }
            "addlogpath" => {
                let path = PathBuf::from(string(args, 0)?);
                if args.len() > 2 {
                    return Err(Error::Value(
                        "Only one file can be added at a time".to_owned(),
                    ));
                }
                let tail = if args.len() == 2 {
                    match string(args, 1)?.to_ascii_lowercase().as_str() {
                        "head" => false,
                        "tail" => true,
                        _ => {
                            return Err(Error::Value(
                                "File option must be 'head' or 'tail'".to_owned(),
                            ));
                        }
                    }
                } else {
                    false
                };
                state.add_log_path(path, tail)?;
                "logpath"
            }
            "dellogpath" => {
                state.del_log_path(Path::new(string(args, 0)?));
                "logpath"
            }
            "logencoding" => {
                state.filter.set_log_encoding_str(string(args, 0)?)?;
                key
            }
            "addjournalmatch" => {
                state.add_journal_match(&strings(args)?).await?;
                "journalmatch"
            }
            "deljournalmatch" => {
                state.del_journal_match(&strings(args)?).await?;
                "journalmatch"
            }
            "prefregex" => {
                state.filter.set_prefregex(optional_string(arg(args, 0)?))?;
                key
            }
            "addfailregex" | "addignoreregex" => {
                let values = if multiple {
                    list(arg(args, 0)?)?
                } else {
                    args.get(..1).ok_or_else(invalid)?
                };
                for pattern in strings(values)? {
                    if key == "addfailregex" {
                        state.filter.add_fail_regex(&pattern)?;
                    } else {
                        state.filter.add_ignore_regex(&pattern)?;
                    }
                }
                if multiple {
                    return Ok(Bool(true));
                }
                key.trim_start_matches("add")
            }
            "delfailregex" | "delignoreregex" => {
                let index = arg(args, 0)?.as_i64().ok_or_else(invalid)?;
                if key == "delfailregex" {
                    state.filter.del_fail_regex(Some(index));
                } else {
                    state.filter.del_ignore_regex(Some(index));
                }
                key.trim_start_matches("del")
            }
            "usedns" => {
                state.filter.set_use_dns_str(string(args, 0)?)?;
                key
            }
            "findtime" => {
                let secs = state.filter.set_find_time_str(&scalar(args, 0)?)?;
                state.fail_manager.set_max_time(secs);
                key
            }
            "datepattern" => {
                state
                    .filter
                    .set_date_pattern(optional_string(arg(args, 0)?))?;
                key
            }
            "logtimezone" => {
                state
                    .filter
                    .set_log_timezone(optional_string(arg(args, 0)?))?;
                key
            }
            "maxmatches" => {
                state.fail_manager.set_max_matches(nonnegative(args, 0)?);
                key
            }
            "maxretry" => {
                state
                    .fail_manager
                    .set_max_retry(nonnegative(args, 0)? as u64);
                key
            }
            "maxlines" => {
                state.filter.set_max_lines(nonnegative(args, 0)?)?;
                key
            }
            "bantime" => {
                let time = str2seconds_i64(&scalar(args, 0)?)?;
                state.ban_manager.set_ban_time(time);
                state.sync_python_ban_times();
                key
            }
            "banip" => return Ok(integer(state.ban_ip(&strings(args)?).await?)),
            "unbanip" => {
                let ips = strings(args)?;
                let report_absent = ips.first().is_some_and(|ip| ip == "--report-absent");
                let ips = if report_absent { &ips[1..] } else { &ips };
                return Ok(integer(state.unban_ip(Some(ips), !report_absent).await?));
            }
            "attempt" => {
                let ip = string(args, 0)?;
                return Ok(Int(state.add_attempt(ip, &strings(&args[1..])?).await?));
            }
            "addaction" => {
                let action = string(args, 0)?;
                let path = args.get(1).and_then(Value::as_str);
                let init = if path.is_some() {
                    Some(string(args, 2)?)
                } else {
                    None
                };
                state.add_action(action, path, init).await?;
                return Ok(if quiet { Null } else { text(action) });
            }
            "delaction" => {
                state.del_action(string(args, 0)?)?;
                return Ok(Null);
            }
            "action" => {
                let action_name = string(args, 0)?;
                let default_ban_time = state.ban_manager.ban_time();
                let action = state
                    .get_action_mut(action_name)
                    .ok_or_else(|| unknown_action(action_name))?;
                if multiple {
                    for spec in list(arg(args, 1)?)? {
                        change_action(action, list(spec)?, default_ban_time).await?;
                    }
                    return Ok(Bool(true));
                }
                let result = change_action(action, &args[1..], default_ban_time).await?;
                return Ok(if quiet { Null } else { result });
            }
            key if key.starts_with("bantime.") => {
                state
                    .ban_extra
                    .set_opt_value(&key["bantime.".len()..], arg(args, 0)?)?;
                state.sync_python_ban_times();
                key
            }
            _ => {
                return Err(Error::invalid_command(format!(
                    "Invalid command {key:?} (no set action or not yet implemented)"
                )));
            }
        };
        let restart =
            matches!(get_key, "logpath" | "logencoding" | "journalmatch") && !state.is_reloading();
        let response = if quiet {
            Null
        } else {
            jail_property(&mut state, get_key, &[]).await?
        };
        drop(state);
        if restart {
            jail.restart_backend_if_alive().await;
        }
        Ok(response)
    }
}

async fn jail_property(jail: &mut JailState, key: &str, args: &[Value]) -> Result<Value> {
    let filter = &jail.filter;
    Ok(match key {
        "logpath" => Value::str_list(jail.get_log_paths()),
        "logencoding" => text(filter.log_encoding_name()),
        "journalmatch" => List(
            jail.journal_matches
                .iter()
                .cloned()
                .map(Value::str_list)
                .collect(),
        ),
        "ignoreself" => Bool(filter.ignore_self()),
        "ignoreip" => Value::str_list(filter.ignore_ips()),
        "ignorecommand" => filter.ignore_command().map_or(Bool(false), text),
        "ignorecache" => filter.ignore_cache().map_or(Null, |cache| {
            Dict(vec![
                (text("key"), text(cache.key_template())),
                (text("max-count"), integer(cache.max_count())),
                (text("max-time"), Float(cache.max_time())),
            ])
        }),
        "prefregex" => text(filter.prefregex().unwrap_or_default()),
        "failregex" => Value::str_list(filter.fail_regexes()),
        "ignoreregex" => Value::str_list(filter.ignore_regexes()),
        "usedns" => text(filter.use_dns().as_str()),
        "findtime" => Int(filter.find_time() as i64),
        "datepattern" => {
            let (pattern, description) = filter
                .date_pattern()
                .unwrap_or_else(|| (None, "Default Detectors".to_owned()));
            Tuple(vec![pattern.map_or(Null, text), text(description)])
        }
        "logtimezone" => filter.log_timezone().map_or(Null, text),
        "maxmatches" => integer(jail.fail_manager.max_matches()),
        "maxretry" => Int(jail.fail_manager.max_retry() as i64),
        "maxlines" => integer(filter.max_lines()),
        "bantime" => Int(jail.ban_manager.ban_time()),
        "banip" => Value::str_list(
            jail.get_ban_list(args.first().and_then(Value::as_str) == Some("--with-time")),
        ),
        "banned" => jail.get_banned(&strings(args)?),
        "actions" => Value::str_list(jail.actions.iter().map(|(name, _)| name)),
        "action" | "actionproperties" | "actionmethods" => {
            let name = string(args, 0)?;
            let action = jail
                .get_action_mut(name)
                .ok_or_else(|| unknown_action(name))?;
            match key {
                "actionproperties" => action.property_names().await?,
                "actionmethods" => action.methods().await?,
                _ => {
                    let property = string(args, 1)?;
                    action.get_property(property).await?.ok_or_else(|| {
                        Error::invalid_command(format!("Action has no attribute {property:?}"))
                    })?
                }
            }
        }
        key if key.starts_with("bantime.") => jail
            .ban_extra
            .get_opt(&key["bantime.".len()..])
            .unwrap_or(Null),
        _ => {
            return Err(Error::invalid_command(
                "Invalid command (no get action or not yet implemented)",
            ));
        }
    })
}

async fn change_action(
    action: &mut ActionKind,
    args: &[Value],
    default_ban_time: i64,
) -> Result<Value> {
    let key = string(args, 0)?;
    let cls = match action {
        ActionKind::Python(py) => return py.set_or_call(key, args.get(1)).await,
        ActionKind::Command(a) if a.methods().iter().any(|m| m == key) => Some("CommandAction"),
        ActionKind::Smtp(a) if a.methods().iter().any(|m| m == key) => Some("SMTPAction"),
        ActionKind::Command(_) | ActionKind::Smtp(_) => None,
    };
    if let Some(cls) = cls {
        let kwargs = parse_action_kwargs(args.get(1), cls, key)?;
        return call_action_method(action, cls, key, &kwargs, default_ban_time).await;
    }
    let value = scalar(args, 1)?;
    action.set_property(key, &value).await?;
    Ok(action.get_property(key).await?.unwrap_or(Null))
}

fn parse_action_kwargs(
    raw: Option<&Value>,
    cls: &str,
    method: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let Some(val) = raw else {
        return Ok(serde_json::Map::new());
    };
    let json_str = val.as_str().ok_or_else(|| {
        Error::Type(format!(
            "{cls}.{method}() arguments must be a JSON object string"
        ))
    })?;
    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| Error::Value(format!("Invalid JSON arguments for {method}: {e}")))?;
    match parsed {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(Error::Type(format!(
            "{cls}.{method}() argument after ** must be a mapping"
        ))),
    }
}

fn reject_unknown_kwargs(
    kwargs: &serde_json::Map<String, serde_json::Value>,
    cls: &str,
    method: &str,
    allowed: &[&str],
) -> Result<()> {
    for k in kwargs.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(Error::Type(format!(
                "{cls}.{method}() got an unexpected keyword argument '{k}'"
            )));
        }
    }
    Ok(())
}

fn require_str_kwarg(
    kwargs: &serde_json::Map<String, serde_json::Value>,
    cls: &str,
    method: &str,
    param: &str,
) -> Result<String> {
    let Some(val) = kwargs.get(param) else {
        return Err(Error::Type(format!(
            "{cls}.{method}() missing 1 required positional argument: '{param}'"
        )));
    };
    Ok(match val {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

fn action_context_from_json(
    jail_name: &str,
    info: &serde_json::Map<String, serde_json::Value>,
    default_ban_time: i64,
) -> ActionContext {
    let id_str = info
        .get("fid")
        .or_else(|| info.get("ip"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let time = info
        .get("time")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or_else(current_unix_seconds);
    let mut ticket = Ticket::new(TicketId::parse(id_str), time);
    if let Some(ip) = info.get("ip").and_then(serde_json::Value::as_str) {
        ticket.ip = Some(TicketId::parse(ip));
    }
    if let Some(bt) = info.get("bantime").and_then(serde_json::Value::as_i64) {
        ticket.ban_time = Some(bt);
    }
    if let Some(att) = info.get("failures").and_then(serde_json::Value::as_u64) {
        ticket.attempts = att;
    }
    if let Some(m) = info.get("matches").and_then(serde_json::Value::as_str) {
        ticket.matches = m.lines().map(str::to_owned).collect();
    }
    for (k, v) in info {
        if let Some(s) = v.as_str() {
            ticket.data.insert(k.clone(), s.to_owned());
        }
    }
    let ip_failures = info
        .get("ipfailures")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(ticket.attempts);
    let ip_jail_failures = info
        .get("ipjailfailures")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(ticket.attempts);
    ActionContext {
        jail_name: jail_name.to_owned(),
        ticket,
        default_ban_time,
        ip_failures,
        ip_jail_failures,
        ip_matches: Vec::new(),
        ip_jail_matches: Vec::new(),
        jail_stats: Default::default(),
    }
}

async fn call_action_method(
    action: &mut ActionKind,
    cls: &str,
    method: &str,
    kwargs: &serde_json::Map<String, serde_json::Value>,
    default_ban_time: i64,
) -> Result<Value> {
    match method {
        "start" => {
            reject_unknown_kwargs(kwargs, cls, method, &[])?;
            action.start(allow_ipv6()).await?;
            Ok(Null)
        }
        "stop" => {
            reject_unknown_kwargs(kwargs, cls, method, &[])?;
            action.stop().await?;
            Ok(Null)
        }
        "reload" => {
            action.reload(None).await?;
            Ok(Null)
        }
        "flush" => {
            reject_unknown_kwargs(kwargs, cls, method, &[])?;
            let _ = action.flush().await?;
            Ok(Null)
        }
        "clearAllParams" => {
            reject_unknown_kwargs(kwargs, cls, method, &[])?;
            action.clear_all_params().await?;
            Ok(Null)
        }
        "invalidateBanEpoch" => {
            reject_unknown_kwargs(kwargs, cls, method, &[])?;
            action.invalidate_ban_epoch();
            Ok(Null)
        }
        "consistencyCheck" => {
            reject_unknown_kwargs(kwargs, cls, method, &["beforeRepair"])?;
            Ok(Bool(action.consistency_check().await?))
        }
        "escapeTag" => {
            reject_unknown_kwargs(kwargs, cls, method, &["value"])?;
            let val = require_str_kwarg(kwargs, cls, method, "value")?;
            Ok(text(escape_tag(&val)))
        }
        "replaceTag" => {
            reject_unknown_kwargs(
                kwargs,
                cls,
                method,
                &["query", "aInfo", "conditional", "addrepl", "cache"],
            )?;
            let query = require_str_kwarg(kwargs, cls, method, "query")?;
            let Some(serde_json::Value::Object(info)) = kwargs.get("aInfo") else {
                return Err(Error::Type(format!(
                    "{cls}.{method}() missing 1 required positional argument: 'aInfo'"
                )));
            };
            let props: BTreeMap<String, String> = info
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str().map_or_else(|| v.to_string(), str::to_owned),
                    )
                })
                .collect();
            let fam = match kwargs
                .get("conditional")
                .and_then(serde_json::Value::as_str)
            {
                Some("family=inet6") => Family::Ipv6,
                Some("family=inet4") => Family::Ipv4,
                _ => Family::Common,
            };
            Ok(text(tags::expand(&query, &props, fam)?.into_string()))
        }
        "replaceDynamicTags" => {
            reject_unknown_kwargs(kwargs, cls, method, &["realCmd", "aInfo", "escapeVal"])?;
            let real_cmd = require_str_kwarg(kwargs, cls, method, "realCmd")?;
            let Some(serde_json::Value::Object(info)) = kwargs.get("aInfo") else {
                return Err(Error::Type(format!(
                    "{cls}.{method}() missing 1 required positional argument: 'aInfo'"
                )));
            };
            let ctx = action_context_from_json(action.jail_name(), info, default_ban_time);
            let fam = Family::from_ticket_id(ctx.ticket.target_ip()).as_str();
            Ok(text(replace_dynamic_tags(
                &real_cmd,
                &ctx,
                fam,
                None,
                &tags::default_reverse_dns,
            )))
        }
        "executeCmd" => {
            reject_unknown_kwargs(kwargs, cls, method, &["realCmd", "timeout"])?;
            let real_cmd = require_str_kwarg(kwargs, cls, method, "realCmd")?;
            let tout = kwargs
                .get("timeout")
                .and_then(serde_json::Value::as_f64)
                .filter(|s| s.is_finite() && *s >= 0.0)
                .map(Duration::from_secs_f64);
            Ok(Bool(action.execute_raw_cmd(&real_cmd, tout).await?))
        }
        "ban" | "unban" | "reban" | "prolong" => {
            let allowed: &[&str] = if method == "ban" {
                &["aInfo", "cmd"]
            } else {
                &["aInfo"]
            };
            reject_unknown_kwargs(kwargs, cls, method, allowed)?;
            let Some(serde_json::Value::Object(info)) = kwargs.get("aInfo") else {
                return Err(Error::Type(format!(
                    "{cls}.{method}() missing 1 required positional argument: 'aInfo'"
                )));
            };
            let ctx = action_context_from_json(action.jail_name(), info, default_ban_time);
            match method {
                "ban" => action.ban(&ctx).await?,
                "unban" => action.unban(&ctx).await?,
                "reban" => action.reban(&ctx).await?,
                _ => action.prolong(&ctx).await?,
            }
            Ok(Null)
        }
        _ => Err(Error::invalid_command(format!(
            "Unsupported action method {method:?}"
        ))),
    }
}

fn list(value: &Value) -> Result<&[Value]> {
    value.as_list().ok_or_else(invalid)
}

fn arg(values: &[Value], index: usize) -> Result<&Value> {
    values.get(index).ok_or_else(invalid)
}

fn string(values: &[Value], index: usize) -> Result<&str> {
    arg(values, index)?.as_str().ok_or_else(invalid)
}

fn optional_string(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.is_empty())
}

fn scalar(values: &[Value], index: usize) -> Result<String> {
    Ok(arg(values, index)?.to_string_lossy())
}

fn nonnegative(values: &[Value], index: usize) -> Result<usize> {
    arg(values, index)?
        .as_i64()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(invalid)
}

fn strings(values: &[Value]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid))
        .collect()
}

fn field(key: &str, value: Value) -> Value {
    Tuple(vec![text(key), value])
}

fn integer(value: usize) -> Value {
    Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn text(value: impl Into<String>) -> Value {
    Value::Str(value.into())
}

fn invalid() -> Error {
    Error::invalid_command("Invalid command")
}

fn unknown_action(name: &str) -> Error {
    Error::invalid_command(format!("Invalid Action name: {name}"))
}

fn is_global_set_key(key: &str) -> bool {
    matches!(
        key,
        "loglevel"
            | "logtarget"
            | "syslogsocket"
            | "allowipv6"
            | "dbfile"
            | "dbmaxmatches"
            | "dbpurgeage"
            | "thread"
    )
}

/// Validate a protocol command stream (used by both `reload` preflight and `fail2ban-client -t`).
pub fn validate_config_stream(commands: &[Value]) -> Result<()> {
    let mut filters: BTreeMap<String, crate::filter::Filter> = BTreeMap::new();
    let mut extras: BTreeMap<String, crate::observer::BanTimeExtra> = BTreeMap::new();

    for frame in commands {
        let cmd = list(frame)?;
        let Some((head, args)) = cmd.split_first() else {
            return Err(invalid());
        };
        let name = head.as_str().ok_or_else(invalid)?;
        if name == "add" {
            let _ = string(args, 0)?;
            let backend = args.get(1).and_then(Value::as_str).unwrap_or("auto");
            super::jail::validate_backend_spec(backend)?;
            continue;
        }
        if !matches!(name, "set" | "multi-set") || args.len() < 2 {
            continue;
        }
        let jail = string(args, 0)?;
        if is_global_set_key(jail) {
            continue;
        }
        let multiple = name == "multi-set";
        let key = string(args, 1)?;
        let rest = &args[2..];
        let filter = filters
            .entry(jail.to_owned())
            .or_insert_with(|| crate::filter::Filter::new(jail));
        match key {
            "ignoreself" => {
                let _ = parse_bool(&scalar(rest, 0)?)?;
            }
            "ignorecache" => {
                filter.set_ignore_cache(optional_string(arg(rest, 0)?))?;
            }
            "addlogpath" => {
                let _ = string(rest, 0)?;
                if rest.len() > 2 {
                    return Err(Error::Value(
                        "Only one file can be added at a time".to_owned(),
                    ));
                }
                if rest.len() == 2
                    && !matches!(
                        string(rest, 1)?.to_ascii_lowercase().as_str(),
                        "head" | "tail"
                    )
                {
                    return Err(Error::Value(
                        "File option must be 'head' or 'tail'".to_owned(),
                    ));
                }
            }
            "logencoding" => {
                filter.set_log_encoding_str(string(rest, 0)?)?;
            }
            "addjournalmatch" => {
                crate::filter::backend::systemd::validate_journal_match_tokens(&strings(rest)?)?;
            }
            "prefregex" => {
                filter.set_prefregex(optional_string(arg(rest, 0)?))?;
            }
            "addfailregex" | "addignoreregex" => {
                let values = if multiple {
                    list(arg(rest, 0)?)?
                } else {
                    rest.get(..1).ok_or_else(invalid)?
                };
                for pattern in strings(values)? {
                    if key == "addfailregex" {
                        filter.add_fail_regex(&pattern)?;
                    } else {
                        filter.add_ignore_regex(&pattern)?;
                    }
                }
            }
            "usedns" => {
                filter.set_use_dns_str(string(rest, 0)?)?;
            }
            "findtime" => {
                filter.set_find_time_str(&scalar(rest, 0)?)?;
            }
            "datepattern" => {
                filter.set_date_pattern(optional_string(arg(rest, 0)?))?;
            }
            "logtimezone" => {
                filter.set_log_timezone(optional_string(arg(rest, 0)?))?;
            }
            "maxmatches" | "maxretry" => {
                let _ = nonnegative(rest, 0)?;
            }
            "maxlines" => {
                filter.set_max_lines(nonnegative(rest, 0)?)?;
            }
            "bantime" => {
                let _ = str2seconds_i64(&scalar(rest, 0)?)?;
            }
            key if key.starts_with("bantime.") => {
                extras
                    .entry(jail.to_owned())
                    .or_default()
                    .set_opt_value(&key["bantime.".len()..], arg(rest, 0)?)?;
            }
            _ => {}
        }
    }
    Ok(())
}
