//! Failure handling — count failures and ban on threshold.

use std::collections::HashMap;

#[cfg(not(feature = "maxmind"))]
use tracing::info;
use tracing::{debug, warn};

use crate::detect::watcher::Failure;
use crate::track::ban_calc::calc_ban_time;
use crate::track::circular::CircularTimestamps;
use crate::track::execute::{execute_ban, execute_ban_at, prolong_ban};
use crate::track::legacy_fail_manager::LegacyFailManager;
use crate::track::tracker_state::{FailKey, FailState, TrackerState};

/// Record a failure and, if the jail's threshold is reached, trigger a ban.
pub(super) async fn handle_failure(failure: Failure, s: &mut TrackerState) {
    s.counters.total_failures += 1;
    incr_jail_counter(&mut s.counters.jail_failures, &failure.jail_id);

    if s.jail_params
        .get(&failure.jail_id)
        .is_some_and(|params| params.compat_mode)
    {
        handle_legacy_failure(failure, s).await;
        return;
    }

    // Build the (ip, jail) key once and reuse it for the membership check and
    // the failures-map entry. The common case (not banned, below threshold)
    // takes no store lock — `banned_keys` mirrors the persisted ban set.
    let key: FailKey = (failure.ip, failure.jail_id.clone());
    if s.index.banned_keys.contains(&key) {
        debug!(
            ip = %failure.ip,
            jail = %failure.jail_id,
            reason = "already_banned",
            "failure ignored"
        );
        return;
    }

    if record_failure(&failure, key, s) {
        ban_on_threshold(failure, s).await;
    }
}

/// Push the failure into its (ip, jail) window; returns whether the jail's
/// threshold is now reached. Unknown jails are logged and ignored.
fn record_failure(failure: &Failure, key: FailKey, s: &mut TrackerState) -> bool {
    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        warn!(
            jail = %failure.jail_id,
            reason = "unknown_jail",
            "failure ignored"
        );
        return false;
    };
    let (max_retry, find_time) = (params.max_retry, params.find_time);
    let fail_state = s.failures.entry(key).or_insert_with(|| FailState {
        timestamps: CircularTimestamps::new(max_retry as usize),
    });
    fail_state.timestamps.push(failure.timestamp);
    debug!(
        ip = %failure.ip,
        jail = %failure.jail_id,
        find_time,
        max_retry,
        win_len = fail_state.timestamps.len(),
        win_cap = fail_state.timestamps.capacity(),
        oldest = ?fail_state.timestamps.oldest(),
        newest = ?fail_state.timestamps.newest(),
        "failure window pushed"
    );
    fail_state.timestamps.threshold_reached(find_time)
}

/// Execute a threshold-triggered ban: read and increment the escalation count,
/// compute the effective ban time, log (with optional GeoIP enrichment), and ban.
async fn ban_on_threshold(failure: Failure, s: &mut TrackerState) {
    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        return;
    };
    let base_ban_time = params.ban_time;
    let count = s
        .store
        .read()
        .ban_counts
        .get(&failure.ip)
        .map_or(0, |bc| bc.count);
    let effective_ban_time = calc_ban_time(base_ban_time, count, params);

    log_threshold_ban(&failure, effective_ban_time, count + 1, s);
    execute_ban(
        failure.ip,
        &failure.jail_id,
        effective_ban_time,
        Some(count + 1),
        s,
    )
    .await;
}

/// Log a threshold ban, GeoIP-enriched when the `maxmind` feature is on.
#[cfg_attr(not(feature = "maxmind"), allow(unused_variables))]
fn log_threshold_ban(failure: &Failure, ban_time: i64, ban_count: u32, s: &TrackerState) {
    #[cfg(feature = "maxmind")]
    {
        let enrichment = s.maxmind.enrich(failure.ip, &failure.jail_id);
        crate::track::maxmind::log_ban_event(failure, ban_time, ban_count, &enrichment);
    }
    #[cfg(not(feature = "maxmind"))]
    info!(
        ip = %failure.ip,
        jail = %failure.jail_id,
        ban_time,
        ban_count,
        reason = "threshold",
        "banned"
    );
}

/// Increment a per-jail counter without cloning the key on the common (hit) path.
fn incr_jail_counter(map: &mut HashMap<String, u64>, jail_id: &str) {
    if let Some(v) = map.get_mut(jail_id) {
        *v += 1;
    } else {
        map.insert(jail_id.to_string(), 1);
    }
}

/// Handle a failure for a Fail2Ban 1.1.1 compatibility jail using the
/// parity-proven `LegacyFailManager` (rate-adjusted sliding estimation) and
/// `LegacyBanManager` timing (bans anchored to `ticket.time`, stale tickets
/// rejected as expired, prolongations extended without re-banning).
async fn handle_legacy_failure(failure: Failure, s: &mut TrackerState) {
    let Some(params) = s.jail_params.get(&failure.jail_id) else {
        return;
    };
    let max_retry = u64::from(params.max_retry);
    let find_time = params.find_time.max(0) as u64;
    let base_ban_time = params.ban_time;
    let ignore_command = params.ignore_command.clone();

    let fm = s
        .legacy_failures
        .entry(failure.jail_id.clone())
        .or_insert_with(|| LegacyFailManager::new(max_retry, find_time));
    fm.record(failure.ip, failure.timestamp);
    let Some(ticket) = fm.take_for_ban(Some(failure.ip)) else {
        return;
    };
    if let Some(cmd_tpl) = ignore_command.as_deref() {
        let ip_str = ticket.ip.to_string();
        let command = cmd_tpl.replace("<ip>", &ip_str).replace("<IP>", &ip_str);
        if let Ok(out) = crate::enforce::cmd::output_with_timeout(
            "sh",
            "ignorecommand",
            &["-c", &command],
            std::time::Duration::from_secs(5),
        )
        .await
            && out.status.success()
        {
            tracing::info!(
                ip = %ticket.ip,
                jail = %failure.jail_id,
                "IP ignored by ignorecommand; not banning"
            );
            return;
        }
    }

    let observed_at = chrono::Utc::now().timestamp();
    let incoming_end = (base_ban_time >= 0).then(|| ticket.time.saturating_add(base_ban_time));
    if let Some(end) = incoming_end
        && i128::from(end) < i128::from(observed_at)
    {
        debug!(
            ip = %ticket.ip,
            jail = %failure.jail_id,
            ticket_time = ticket.time,
            ban_time = base_ban_time,
            observed_at,
            reason = "expired_ticket",
            "legacy qualifying ticket already expired; not banning"
        );
        return;
    }

    let key: FailKey = (ticket.ip, failure.jail_id.clone());
    if s.index.banned_keys.contains(&key) {
        let existing = s.store.read().bans.get(&key).cloned();
        if let Some(current) = existing {
            let current_cmp = current.expires_at.map_or(i128::MAX, i128::from);
            let incoming_cmp = incoming_end.map_or(i128::MAX, i128::from);
            if incoming_cmp > current_cmp {
                let prolonged_end = (base_ban_time >= 0).then(|| {
                    ticket
                        .time
                        .max(current.banned_at)
                        .saturating_add(base_ban_time)
                });
                prolong_ban(ticket.ip, &failure.jail_id, prolonged_end, s);
            }
        }
        return;
    }

    let count = s
        .store
        .read()
        .ban_counts
        .get(&ticket.ip)
        .map_or(0, |bc| bc.count);
    let effective_ban_time = s
        .jail_params
        .get(&failure.jail_id)
        .map_or(base_ban_time, |p| calc_ban_time(base_ban_time, count, p));
    let ban_failure = Failure {
        ip: ticket.ip,
        jail_id: failure.jail_id,
        timestamp: ticket.time,
    };
    log_threshold_ban(&ban_failure, effective_ban_time, count + 1, s);
    execute_ban_at(
        ticket.ip,
        &ban_failure.jail_id,
        ticket.time,
        effective_ban_time,
        Some(count + 1),
        s,
    )
    .await;
}
