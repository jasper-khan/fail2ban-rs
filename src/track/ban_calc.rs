//! Ban time calculation with optional escalation.
//!
//! Extracted from the tracker module to keep it under the 500-line limit.

use std::collections::HashMap;

use crate::config::JailConfig;

/// Per-jail parameters relevant to ban calculations.
pub(crate) struct JailParams {
    pub(crate) max_retry: u32,
    pub(crate) find_time: i64,
    pub(crate) ban_time: i64,
    pub(crate) webhook: Option<String>,
    pub(crate) bantime_increment: bool,
    pub(crate) bantime_factor: f64,
    pub(crate) bantime_multipliers: Vec<u32>,
    pub(crate) bantime_maxtime: i64,
    pub(crate) bantime_rndtime: i64,
    pub(crate) ignore_command: Option<String>,
    pub(crate) compat_mode: bool,
}

/// Calculate effective ban time with optional escalation.
pub(crate) fn calc_ban_time(base: i64, count: u32, params: &JailParams) -> i64 {
    if base < 0 {
        return base;
    }
    let mut effective = if params.bantime_increment {
        let multiplier = if params.bantime_multipliers.is_empty() {
            let exp = count.min(20);
            2_f64.powi(exp as i32)
        } else {
            let idx = (count as usize).min(params.bantime_multipliers.len() - 1);
            params
                .bantime_multipliers
                .get(idx)
                .copied()
                .map_or(1.0, f64::from)
        };
        (base as f64 * multiplier * params.bantime_factor) as i64
    } else {
        base
    };
    if params.bantime_rndtime > 0 && effective > 0 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_i64(effective);
        hasher.write_u32(count);
        let span = u64::try_from(params.bantime_rndtime)
            .unwrap_or(0)
            .saturating_add(1);
        let jitter = i64::try_from(hasher.finish() % span).unwrap_or(0);
        effective = effective.saturating_add(jitter);
    }
    if params.bantime_increment && params.bantime_maxtime > 0 {
        effective.min(params.bantime_maxtime)
    } else {
        effective
    }
}

/// Build per-jail parameter maps from configuration.
pub(crate) fn build_jail_params(
    configs: &HashMap<String, JailConfig>,
) -> HashMap<String, JailParams> {
    configs
        .iter()
        .map(|(name, cfg)| {
            (
                name.clone(),
                JailParams {
                    max_retry: cfg.max_retry,
                    find_time: cfg.find_time,
                    ban_time: cfg.ban_time,
                    webhook: cfg.webhook.clone(),
                    bantime_increment: cfg.bantime_increment,
                    bantime_factor: cfg.bantime_factor,
                    bantime_multipliers: cfg.bantime_multipliers.clone(),
                    bantime_maxtime: cfg.bantime_maxtime,
                    bantime_rndtime: cfg.bantime_rndtime,
                    ignore_command: cfg.ignore_command.clone(),
                    compat_mode: cfg.compat_mode,
                },
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "ban_calc_test.rs"]
mod ban_calc_test;
