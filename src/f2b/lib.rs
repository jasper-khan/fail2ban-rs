//! Pure-Rust drop-in replacement for Fail2Ban 1.1.1.

pub mod action;
pub mod banmanager;
pub mod client;
pub mod config;
pub mod date;
pub mod db;
pub mod duration;
pub mod error;
pub mod failmanager;
pub mod filter;
pub mod logging;
pub mod observer;
pub mod protocol;
pub mod regex_tool;
pub mod ticket;

pub const VERSION: &str = "1.1.1";
