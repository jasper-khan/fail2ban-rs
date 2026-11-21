//! Control-socket request dispatch.
//!
//! Requests that only need the tracker (list/ban/unban/stats) are answered on
//! a spawned task so the daemon's main select loop never blocks on a tracker
//! or firewall response — a slow manual ban cannot delay SIGTERM/SIGHUP
//! handling. `Reload` mutates the daemon's config and watchers, so it runs
//! inline.

use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

use crate::config::Config;
use crate::control::{ControlCmd, Request, Response};
use crate::track::TrackerCmd;

use super::reload::{ReloadContext, apply_config_change, reload_config};

/// A control request answered purely by the tracker.
pub(super) enum TrackerRequest {
    /// List active bans.
    ListBans,
    /// Manually ban `ip` in `jail` for `ban_time` seconds.
    Ban {
        ip: IpAddr,
        jail: String,
        ban_time: i64,
    },
    /// Manually unban `ip` from `jail`.
    Unban { ip: IpAddr, jail: String },
    /// Runtime statistics.
    Stats,
}

/// How a control request is to be served.
pub(super) enum Dispatch {
    /// Already answered (status, or a request rejected up front).
    Immediate(Response),
    /// A config reload, which needs mutable daemon state.
    Reload,
    /// Live runtime update of a single jail parameter.
    SetJailParam {
        jail: String,
        param: String,
        value: i64,
    },
    /// Enable or disable a single jail at runtime.
    SetJailEnabled { jail: String, enabled: bool },
    /// Mutate a jail's `logpath` or `ignoreip` list at runtime.
    MutateJailList {
        jail: String,
        list: String,
        add: bool,
        value: String,
    },
    /// Forward to the tracker.
    Tracker(TrackerRequest),
}

/// Classify a request, resolving anything that needs the daemon config (the
/// manual ban time) so the tracker leg can run without borrowing it.
pub(super) fn classify_request(request: Request, config: &Config) -> Dispatch {
    match request {
        Request::Status => Dispatch::Immediate(Response::ok("fail2ban-rs is running")),
        Request::ListBans => Dispatch::Tracker(TrackerRequest::ListBans),
        Request::Ban { ip, jail } => match resolve_ban_time(config, &jail) {
            Ok(ban_time) => Dispatch::Tracker(TrackerRequest::Ban { ip, jail, ban_time }),
            Err(msg) => Dispatch::Immediate(Response::error(msg)),
        },
        Request::Unban { ip, jail } => Dispatch::Tracker(TrackerRequest::Unban { ip, jail }),
        Request::Reload => Dispatch::Reload,
        Request::Stats => Dispatch::Tracker(TrackerRequest::Stats),
        Request::ConfigSnapshot => Dispatch::Immediate(build_config_snapshot(config)),
        Request::SetJailParam { jail, param, value } => {
            Dispatch::SetJailParam { jail, param, value }
        }
        Request::SetJailEnabled { jail, enabled } => Dispatch::SetJailEnabled { jail, enabled },
        Request::MutateJailList {
            jail,
            list,
            add,
            value,
        } => Dispatch::MutateJailList {
            jail,
            list,
            add,
            value,
        },
    }
}

/// Serve one control command from the main loop without blocking it on the
/// tracker: tracker requests are answered on a spawned task.
pub(super) async fn dispatch_control(
    ctrl: ControlCmd,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) {
    match classify_request(ctrl.request, ctx.config) {
        Dispatch::Immediate(response) => send_response(ctrl.respond, response),
        Dispatch::Reload => {
            let response = handle_reload_request(tracker_cmd_tx, ctx).await;
            send_response(ctrl.respond, response);
        }
        Dispatch::SetJailParam { jail, param, value } => {
            let response = handle_set_jail_param(tracker_cmd_tx, ctx, &jail, &param, value).await;
            send_response(ctrl.respond, response);
        }
        Dispatch::SetJailEnabled { jail, enabled } => {
            let response = handle_set_jail_enabled(tracker_cmd_tx, ctx, &jail, enabled).await;
            send_response(ctrl.respond, response);
        }
        Dispatch::MutateJailList {
            jail,
            list,
            add,
            value,
        } => {
            let response =
                handle_mutate_jail_list(tracker_cmd_tx, ctx, &jail, &list, add, &value).await;
            send_response(ctrl.respond, response);
        }
        Dispatch::Tracker(req) => {
            let tx = tracker_cmd_tx.clone();
            tokio::spawn(async move {
                send_response(ctrl.respond, forward_to_tracker(req, &tx).await);
            });
        }
    }
}

/// Serve a control request to completion (awaiting any tracker response).
///
/// Test seam: exercises the same classify/forward path as [`dispatch_control`]
/// but returns the response directly instead of spawning.
#[cfg(test)]
pub(super) async fn handle_control_request(
    request: Request,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) -> Response {
    match classify_request(request, ctx.config) {
        Dispatch::Immediate(response) => response,
        Dispatch::Reload => handle_reload_request(tracker_cmd_tx, ctx).await,
        Dispatch::SetJailParam { jail, param, value } => {
            handle_set_jail_param(tracker_cmd_tx, ctx, &jail, &param, value).await
        }
        Dispatch::SetJailEnabled { jail, enabled } => {
            handle_set_jail_enabled(tracker_cmd_tx, ctx, &jail, enabled).await
        }
        Dispatch::MutateJailList {
            jail,
            list,
            add,
            value,
        } => handle_mutate_jail_list(tracker_cmd_tx, ctx, &jail, &list, add, &value).await,
        Dispatch::Tracker(req) => forward_to_tracker(req, tracker_cmd_tx).await,
    }
}

/// Reply to the control client; a disconnected client is not an error.
fn send_response(respond: oneshot::Sender<Response>, response: Response) {
    if respond.send(response).is_err() {
        debug!("control client disconnected before response");
    }
}

/// Send a tracker command built around a fresh reply channel and await it.
async fn ask_tracker<T>(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    build: impl FnOnce(oneshot::Sender<T>) -> TrackerCmd,
) -> Result<T, Response> {
    let (tx, rx) = oneshot::channel();
    if tracker_cmd_tx.send(build(tx)).await.is_err() {
        return Err(Response::error("tracker unavailable"));
    }
    rx.await
        .map_err(|_| Response::error("tracker did not respond"))
}

/// Forward a tracker request and translate the reply into a [`Response`].
pub(super) async fn forward_to_tracker(
    req: TrackerRequest,
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
) -> Response {
    let result = match req {
        TrackerRequest::ListBans => list_bans(tracker_cmd_tx).await,
        TrackerRequest::Ban { ip, jail, ban_time } => {
            manual_ban(tracker_cmd_tx, ip, jail, ban_time).await
        }
        TrackerRequest::Unban { ip, jail } => manual_unban(tracker_cmd_tx, ip, jail).await,
        TrackerRequest::Stats => stats(tracker_cmd_tx).await,
    };
    result.unwrap_or_else(|response| response)
}

/// Ask the tracker for a manual ban; it answers only once the firewall has
/// applied (or failed/timed out applying) the ban.
async fn manual_ban(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ip: IpAddr,
    jail: String,
    ban_time: i64,
) -> Result<Response, Response> {
    let ok_message = format!("banned {ip} in {jail}");
    let result = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::ManualBan {
        ip,
        jail_id: jail,
        ban_time,
        respond,
    })
    .await?;
    Ok(mutation_response(result, ok_message))
}

async fn manual_unban(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ip: IpAddr,
    jail: String,
) -> Result<Response, Response> {
    let ok_message = format!("unbanned {ip} from {jail}");
    let result = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::ManualUnban {
        ip,
        jail_id: jail,
        respond,
    })
    .await?;
    Ok(mutation_response(result, ok_message))
}

/// Map a ban/unban result to an ok-with-message or error response.
fn mutation_response(result: crate::error::Result<()>, ok_message: String) -> Response {
    match result {
        Ok(()) => Response::ok(ok_message),
        Err(e) => Response::error(e.to_string()),
    }
}

async fn list_bans(tracker_cmd_tx: &mpsc::Sender<TrackerCmd>) -> Result<Response, Response> {
    let bans = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::QueryBans { respond }).await?;
    let data: Vec<serde_json::Value> = bans
        .iter()
        .map(|b| {
            serde_json::json!({
                "ip": b.ip.to_string(),
                "jail": b.jail_id,
                "banned_at": b.banned_at,
                "expires_at": b.expires_at,
            })
        })
        .collect();
    Ok(Response::ok_data(serde_json::json!({ "bans": data })))
}

async fn stats(tracker_cmd_tx: &mpsc::Sender<TrackerCmd>) -> Result<Response, Response> {
    let stats = ask_tracker(tracker_cmd_tx, |respond| TrackerCmd::GetStats { respond }).await?;
    Ok(match serde_json::to_value(&stats) {
        Ok(v) => Response::ok_data(v),
        Err(e) => Response::error(format!("serialize stats: {e}")),
    })
}

/// Run a config reload requested over the control socket.
async fn handle_reload_request(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
) -> Response {
    info!(
        phase = "reload",
        trigger = "control_socket",
        "config reload starting"
    );
    let result = reload_config(
        ctx.source,
        ctx.executor_tx,
        tracker_cmd_tx,
        ctx.config,
        ctx.watchers,
        ctx.failure_tx,
        ctx.logger,
    )
    .await;
    match result {
        Ok(()) => {
            info!(phase = "reload", "config reload complete");
            Response::ok("config reloaded")
        }
        Err(e) => {
            error!(phase = "reload", error = %e, "config reload failed");
            Response::error(format!("reload failed: {e}"))
        }
    }
}

/// Resolve the configured ban time (seconds) for a manual ban on `jail`.
///
/// Returns an error message string when the jail is unknown or disabled, so
/// the caller can reject the request instead of applying a bogus default.
pub(super) fn resolve_ban_time(config: &Config, jail: &str) -> std::result::Result<i64, String> {
    match config.jail.get(jail) {
        Some(cfg) if cfg.enabled => Ok(cfg.ban_time),
        Some(_) => Err(format!("jail '{jail}' is not enabled")),
        None => Err(format!("unknown jail '{jail}'")),
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "control_dispatch_test.rs"]
mod control_dispatch_test;

fn build_config_snapshot(config: &Config) -> Response {
    let mut jails = serde_json::Map::new();
    for (name, cfg) in &config.jail {
        if !cfg.enabled {
            continue;
        }
        let mut log_paths: Vec<String> = cfg
            .log_paths
            .iter()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.display().to_string())
            .collect();
        if log_paths.is_empty() && !cfg.log_path.as_os_str().is_empty() {
            log_paths.push(cfg.log_path.display().to_string());
        }
        let actions: Vec<String> = match &cfg.backend {
            crate::config::Backend::LegacyAction { actions } => {
                actions.iter().map(|a| a.name.clone()).collect()
            }
            crate::config::Backend::Script { .. } => vec!["record".to_owned()],
            crate::config::Backend::Nftables => vec!["nftables".to_owned()],
            crate::config::Backend::Iptables => vec!["iptables".to_owned()],
            crate::config::Backend::Ipset { .. } => vec!["ipset".to_owned()],
        };
        jails.insert(
            name.clone(),
            serde_json::json!({
                "maxretry": cfg.max_retry,
                "findtime": cfg.find_time,
                "bantime": cfg.ban_time,
                "ignoreip": cfg.ignoreip,
                "log_paths": log_paths,
                "actions": actions,
            }),
        );
    }
    Response::ok_data(serde_json::json!({
        "dbfile": config
            .global
            .legacy_sqlite_rw_path
            .as_ref()
            .map(|p| p.display().to_string()),
        "dbpurgeage": config.global.legacy_sqlite_purge_age,
        "jails": jails,
    }))
}

async fn handle_set_jail_param(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
    jail: &str,
    param: &str,
    value: i64,
) -> Response {
    let Some(cfg) = ctx.config.jail.get_mut(jail) else {
        return Response::error(format!("NOK: ('{jail}',)"));
    };
    match param {
        "maxretry" => {
            let Ok(v) = u32::try_from(value) else {
                return Response::error(format!("invalid maxretry: {value}"));
            };
            if v == 0 {
                return Response::error("maxretry must be >= 1");
            }
            cfg.max_retry = v;
        }
        "findtime" => {
            if value <= 0 {
                return Response::error("findtime must be > 0");
            }
            cfg.find_time = value;
        }
        "bantime" => {
            cfg.ban_time = value;
        }
        other => return Response::error(format!("unsupported parameter {other:?}")),
    }
    let enabled: std::collections::HashMap<String, crate::config::JailConfig> = ctx
        .config
        .jail
        .iter()
        .filter(|(_, j)| j.enabled)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (tx, rx) = oneshot::channel();
    if tracker_cmd_tx
        .send(TrackerCmd::UpdateConfig {
            global: ctx.config.global.clone(),
            jails: enabled,
            respond: tx,
        })
        .await
        .is_err()
    {
        return Response::error("tracker unavailable");
    }
    match rx.await {
        Ok(()) => Response::ok_data(serde_json::json!({ "value": value })),
        Err(_) => Response::error("tracker did not acknowledge parameter update"),
    }
}

async fn handle_set_jail_enabled(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
    jail: &str,
    enabled: bool,
) -> Response {
    let mut next_config = ctx.config.clone();
    let Some(cfg) = next_config.jail.get_mut(jail) else {
        return Response::error(format!("NOK: ('{jail}',)"));
    };
    cfg.enabled = enabled;
    match apply_config_change(
        next_config,
        ctx.executor_tx,
        tracker_cmd_tx,
        ctx.config,
        ctx.watchers,
        ctx.failure_tx,
    )
    .await
    {
        Ok(()) => Response::ok(if enabled { "started" } else { "stopped" }),
        Err(e) => Response::error(format!("jail state change failed: {e}")),
    }
}

async fn handle_mutate_jail_list(
    tracker_cmd_tx: &mpsc::Sender<TrackerCmd>,
    ctx: &mut ReloadContext<'_>,
    jail: &str,
    list: &str,
    add: bool,
    value: &str,
) -> Response {
    let mut next_config = ctx.config.clone();
    let Some(cfg) = next_config.jail.get_mut(jail) else {
        return Response::error(format!("NOK: ('{jail}',)"));
    };
    let updated_items: Vec<String> = match list {
        "logpath" => {
            let path = std::path::PathBuf::from(value);
            if add {
                if !cfg.log_paths.contains(&path) {
                    cfg.log_paths.push(path.clone());
                }
                if cfg.log_path.as_os_str().is_empty() {
                    cfg.log_path = path;
                }
            } else {
                cfg.log_paths.retain(|p| p != &path);
                if cfg.log_path == path {
                    cfg.log_path = cfg.log_paths.first().cloned().unwrap_or_default();
                }
            }
            cfg.log_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect()
        }
        "ignoreip" => {
            if add {
                if crate::detect::ignore::parse_entry(value).is_err() {
                    return Response::error(format!("invalid ignoreip entry: {value}"));
                }
                if !cfg.ignoreip.iter().any(|e| e == value) {
                    cfg.ignoreip.push(value.to_owned());
                }
            } else {
                cfg.ignoreip.retain(|e| e != value);
            }
            cfg.ignoreip.clone()
        }
        other => return Response::error(format!("unsupported list {other:?}")),
    };
    match apply_config_change(
        next_config,
        ctx.executor_tx,
        tracker_cmd_tx,
        ctx.config,
        ctx.watchers,
        ctx.failure_tx,
    )
    .await
    {
        Ok(()) => Response::ok_data(serde_json::json!({ "items": updated_items })),
        Err(e) => Response::error(format!("updating {list} failed: {e}")),
    }
}
