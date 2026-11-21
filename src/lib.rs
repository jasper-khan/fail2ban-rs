//! fail2ban-rs — A pure-Rust replacement for fail2ban.
//!
//! Single static binary, fast two-phase matching, nftables/iptables firewall backends.

pub mod config;
pub mod control;
pub mod detect;
pub mod duration;
pub mod enforce;
pub mod error;
pub mod log_format;
pub mod logging;
pub mod regex_tool;
pub mod server;
pub mod text;
pub mod track;
pub mod webhook;

// Offline parity helpers; the user-facing client and wire protocol are unchanged.
#[allow(dead_code)]
mod legacy_client;
#[allow(dead_code)]
mod legacy_client_bans;
#[cfg(test)]
mod legacy_client_bans_parity_test;
#[cfg(test)]
mod legacy_client_parity_test;
#[allow(dead_code)]
mod legacy_client_render;
#[cfg(test)]
mod legacy_file_replay_parity_test;
#[cfg(all(test, unix))]
mod legacy_file_rotation_parity_test;
#[allow(dead_code)]
mod legacy_jail_file;
#[allow(dead_code)]
mod legacy_jail_queued;
#[allow(dead_code)]
mod legacy_jail_replay;
#[cfg(test)]
mod legacy_jail_replay_parity_test;
#[allow(dead_code)]
mod legacy_queued_file;
#[cfg(test)]
mod legacy_queued_file_parity_test;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod security_test;
