//! Original Fail2Ban 1.1.1 per-jail restore projection over decoded v4 bips rows.
//!
//! This module does not read SQLite, migrate databases, query history, open
//! logs or execute actions. The caller supplies one clock and the jail's
//! restore policy, not the daemon's live tracker state. Input is a normalized
//! snapshot: absent or null metadata is allowed, null object fields are
//! ignored, and invalid data/match shapes and duplicate rows are errors. Raw
//! database repair and JSON byte-decoding behavior are not modeled here.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

const PERMANENT: f64 = -1.0;
const UNKNOWN_DURATION: f64 = -2.0;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LegacyBanRow {
    pub(crate) jail: String,
    pub(crate) ip: String,
    pub(crate) time_of_ban: f64,
    pub(crate) ban_time: f64,
    pub(crate) ban_count: i64,
    pub(crate) data: Option<Value>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RestoreRequest<'a> {
    pub(crate) jail: &'a str,
    pub(crate) now: f64,
    /// Search window. None and the original -1 sentinel disable the window.
    pub(crate) age_window: Option<f64>,
    /// Used for migrated v1/v2 rows with unknown duration.
    pub(crate) base_ban_time: f64,
    /// An optional positive correction cap. Zero and negatives disable it.
    pub(crate) max_ban_time: Option<f64>,
    pub(crate) max_matches: usize,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub(crate) struct RestoredBan {
    /// Canonical IP host form where recognized, otherwise stored identifier.
    /// CIDR/mask spelling and jail ignore rules are outside this slice.
    pub(crate) ip: String,
    pub(crate) time_of_ban: f64,
    pub(crate) ban_time: f64,
    pub(crate) ban_count: i64,
    pub(crate) data: Map<String, Value>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum RestoreError {
    #[error("restore clock or jail duration is not finite")]
    NonFiniteRequest,
    #[error("ban time or duration is not finite for restored identifier {0:?}")]
    NonFiniteRow(String),
    #[error("duplicate bips row for restored identifier {0:?}")]
    DuplicateRow(String),
    #[error("row data is not a JSON object for restored identifier {0:?}")]
    InvalidData(String),
    #[error("row matches have an unsupported JSON shape for restored identifier {0:?}")]
    InvalidMatches(String),
}

/// Mirrors the per-jail selection branch of `Fail2BanDb.getCurrentBans`.
/// Input rows model the SQLite bips primary key, not historical bans.
#[allow(clippy::float_cmp)] // The original SQL/Python tests exact flag sentinels.
pub(crate) fn restore_current(
    rows: &[LegacyBanRow],
    request: &RestoreRequest<'_>,
) -> Result<Vec<RestoredBan>, RestoreError> {
    if ![
        Some(request.now),
        Some(request.base_ban_time),
        request.age_window,
        request.max_ban_time,
    ]
    .into_iter()
    .flatten()
    .all(f64::is_finite)
    {
        return Err(RestoreError::NonFiniteRequest);
    }
    let age_window = request.age_window.filter(|&window| window != PERMANENT);
    let cap = request.max_ban_time.filter(|&cap| cap > 0.0);
    let mut selected = rows
        .iter()
        .filter(|row| row.jail == request.jail && !row.ip.is_empty())
        .collect::<Vec<_>>();
    // SQLite orders by stored text before Ticket canonicalizes addresses.
    selected.sort_unstable_by(|a, b| a.ip.cmp(&b.ip));
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for row in selected {
        if !seen.insert(row.ip.as_str()) {
            return Err(RestoreError::DuplicateRow(row.ip.clone()));
        }
        let (start, duration) = (row.time_of_ban, row.ban_time);
        if !start.is_finite() || !duration.is_finite() {
            return Err(RestoreError::NonFiniteRow(row.ip.clone()));
        }
        if (duration > PERMANENT && start + duration <= request.now)
            || age_window.is_some_and(|window| start <= request.now - window)
        {
            continue;
        }
        let duration = if duration == UNKNOWN_DURATION {
            // Legacy unknown is substituted, not subsequently capped.
            request.base_ban_time
        } else if let Some(cap) = cap
            && (duration == PERMANENT || duration > cap)
        {
            cap
        } else {
            duration
        };
        if duration != PERMANENT && start + duration <= request.now {
            continue;
        }
        output.push(RestoredBan {
            ip: display_id(&row.ip),
            time_of_ban: start,
            ban_time: duration,
            ban_count: row.ban_count.max(0),
            data: current_data(row, request.max_matches)?,
        });
    }
    Ok(output)
}

fn display_id(raw: &str) -> String {
    let id = raw
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .filter(|value| !value.is_empty())
        .unwrap_or(raw);
    match id.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return mapped.to_string();
            }
            // inet_ntop renders the old IPv4-compatible form with a dotted
            // suffix when its low 32 bits use both 16-bit groups.
            if let [0, 0, 0, 0, 0, 0, high, _] = ip.segments()
                && high != 0
                && let Some(v4) = ip.to_ipv4()
            {
                return format!("::{v4}");
            }
            ip.to_string()
        }
        Ok(ip) => ip.to_string(),
        Err(_) => id.to_owned(),
    }
}

fn current_data(
    row: &LegacyBanRow,
    max_matches: usize,
) -> Result<Map<String, Value>, RestoreError> {
    let mut data = Map::new();
    data.insert("matches".to_owned(), Value::Array(Vec::new()));
    data.insert("failures".to_owned(), Value::from(0));
    match row.data.as_ref() {
        None | Some(Value::Null) => {}
        Some(Value::Object(stored)) => {
            data.extend(
                stored
                    .iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k.clone(), v.clone())),
            );
        }
        Some(_) => return Err(RestoreError::InvalidData(row.ip.clone())),
    }
    if max_matches == 0 {
        data.remove("matches");
        return Ok(data);
    }
    let Some(Value::Array(matches)) = data.get_mut("matches") else {
        return Err(RestoreError::InvalidMatches(row.ip.clone()));
    };
    if matches.iter().any(|line| {
        line.as_array()
            .is_some_and(|parts| parts.iter().any(|part| !part.is_string()))
    }) {
        return Err(RestoreError::InvalidMatches(row.ip.clone()));
    }
    if matches.len() > max_matches {
        matches.drain(..matches.len() - max_matches);
        // Upstream replaces the data with getMatches' representation only
        // when truncating. Nested tuple/list lines then become joined text.
        for line in matches {
            if let Value::Array(parts) = line {
                let text: String = parts.iter().filter_map(Value::as_str).collect();
                *line = Value::String(text);
            }
        }
    }
    Ok(data)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(ip: &str, start: f64, duration: f64) -> LegacyBanRow {
        LegacyBanRow {
            jail: "example".to_owned(),
            ip: ip.to_owned(),
            time_of_ban: start,
            ban_time: duration,
            ban_count: 2,
            data: Some(json!({
                "matches": ["earlier", "middle", "last"],
                "failures": 4,
                "annotation": "archive",
                "nil": null
            })),
        }
    }

    fn request() -> RestoreRequest<'static> {
        RestoreRequest {
            jail: "example",
            now: 1000.0,
            age_window: None,
            base_ban_time: 200.0,
            max_ban_time: Some(300.0),
            max_matches: 2,
        }
    }

    fn durations(rows: &[RestoredBan]) -> Vec<(&str, f64)> {
        rows.iter()
            .map(|row| (row.ip.as_str(), row.ban_time))
            .collect()
    }

    #[test]
    fn filters_exact_windows_caps_permanent_and_uses_unknown_base() {
        let rows = [
            row("192.0.2.7", 1005.0, 120.0),
            row("192.0.2.6", 800.0, 300.0),
            row("192.0.2.5", 950.0, PERMANENT),
            row("192.0.2.4", 950.0, UNKNOWN_DURATION),
            row("192.0.2.3", 600.0, PERMANENT),
            row("192.0.2.2", 900.0, 100.0),
            row("192.0.2.1", 950.0, 300.0),
        ];
        let restored = restore_current(&rows, &request()).unwrap();
        assert_eq!(
            durations(&restored),
            [
                ("192.0.2.1", 300.0),
                ("192.0.2.4", 200.0),
                ("192.0.2.5", 300.0),
                ("192.0.2.6", 300.0),
                ("192.0.2.7", 120.0)
            ]
        );
        let restored = restore_current(
            &rows,
            &RestoreRequest {
                max_ban_time: Some(100.0),
                ..request()
            },
        )
        .unwrap();
        assert_eq!(
            durations(&restored),
            [
                ("192.0.2.1", 100.0),
                ("192.0.2.4", 200.0),
                ("192.0.2.5", 100.0),
                ("192.0.2.7", 100.0)
            ]
        );
        let restored = restore_current(
            &rows,
            &RestoreRequest {
                age_window: Some(200.0),
                max_ban_time: None,
                max_matches: 0,
                ..request()
            },
        )
        .unwrap();
        assert_eq!(
            durations(&restored),
            [
                ("192.0.2.1", 300.0),
                ("192.0.2.4", 200.0),
                ("192.0.2.5", PERMANENT),
                ("192.0.2.7", 120.0)
            ]
        );
        assert!(restored.iter().all(|row| !row.data.contains_key("matches")));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn retains_fractional_source_times_and_applies_strict_expiry() {
        let rows = [row("192.0.2.4", 950.259_323, 50.25)];
        let source = rows.first().unwrap();
        let end = source.time_of_ban + source.ban_time;
        let live = restore_current(
            &rows,
            &RestoreRequest {
                now: end - 0.000_001,
                ..request()
            },
        )
        .unwrap();
        assert_eq!(live.first().unwrap().time_of_ban, 950.259_323);
        assert_eq!(durations(&live), [("192.0.2.4", 50.25)]);
        assert!(
            restore_current(
                &rows,
                &RestoreRequest {
                    now: end,
                    ..request()
                }
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn separates_jails_keeps_tail_metadata_and_preserves_uncut_matches() {
        let mut a = row("192.0.2.4", 950.0, PERMANENT);
        a.data = Some(
            json!({"matches": ["first", ["two", " parts"]], "annotation": "archive", "nil": null}),
        );
        let mut other = a.clone();
        other.jail = "other".to_owned();
        let rows = [other, a];
        let live = restore_current(
            &rows,
            &RestoreRequest {
                age_window: Some(PERMANENT),
                max_ban_time: Some(0.0),
                ..request()
            },
        )
        .unwrap();
        let ban = live.first().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(durations(&live), [("192.0.2.4", PERMANENT)]);
        assert_eq!(ban.ban_count, 2);
        assert_eq!(
            ban.data.get("matches"),
            Some(&json!(["first", ["two", " parts"]]))
        );
        assert_eq!(ban.data.get("failures"), Some(&json!(0)));
        assert_eq!(ban.data.get("annotation"), Some(&json!("archive")));
        assert!(!ban.data.contains_key("nil"));
        let trimmed = restore_current(
            &rows,
            &RestoreRequest {
                max_matches: 1,
                ..request()
            },
        )
        .unwrap();
        assert_eq!(
            trimmed.first().unwrap().data.get("matches"),
            Some(&json!(["two parts"]))
        );
    }

    #[test]
    fn migrated_unknown_can_be_permanent_and_null_metadata_defaults() {
        let mut legacy = row("192.0.2.4", 950.0, UNKNOWN_DURATION);
        legacy.data = Some(Value::Null);
        legacy.ban_count = -1;
        let restored = restore_current(
            &[legacy],
            &RestoreRequest {
                base_ban_time: PERMANENT,
                max_ban_time: Some(1.0),
                ..request()
            },
        )
        .unwrap();
        assert_eq!(durations(&restored), [("192.0.2.4", PERMANENT)]);
        let ban = restored.first().unwrap();
        assert_eq!(ban.ban_count, 0);
        assert_eq!(ban.data.get("matches"), Some(&json!([])));
        assert_eq!(ban.data.get("failures"), Some(&json!(0)));
    }

    #[test]
    fn renders_ip_hosts_after_sorting_by_raw_sql_identifier() {
        let rows = [
            row("2001:0db8::10", 950.0, PERMANENT),
            row("2001:aaaa::1", 950.0, PERMANENT),
            row("::ffff:192.0.2.1", 950.0, PERMANENT),
            row("::c000:201", 950.0, PERMANENT),
            row("[2001:db8::20]", 950.0, PERMANENT),
            row("raw:identifier", 950.0, PERMANENT),
        ];
        let restored = restore_current(&rows, &request()).unwrap();
        let ids = restored
            .iter()
            .map(|row| row.ip.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "2001:db8::10",
                "2001:aaaa::1",
                "::192.0.2.1",
                "192.0.2.1",
                "2001:db8::20",
                "raw:identifier"
            ]
        );
    }

    #[test]
    fn rejects_invalid_normalized_input_without_fabricating_empty_restore() {
        let a = row("192.0.2.4", 950.0, PERMANENT);
        assert_eq!(
            restore_current(&[a.clone(), a], &request()),
            Err(RestoreError::DuplicateRow("192.0.2.4".to_owned()))
        );
        assert_eq!(
            restore_current(
                &[],
                &RestoreRequest {
                    now: f64::NAN,
                    ..request()
                }
            ),
            Err(RestoreError::NonFiniteRequest)
        );
        let mut a = row("192.0.2.4", 950.0, PERMANENT);
        a.data = Some(json!({"matches": [[42]]}));
        assert_eq!(
            restore_current(&[a], &request()),
            Err(RestoreError::InvalidMatches("192.0.2.4".to_owned()))
        );
    }
}
