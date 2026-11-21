//! TOML configuration loading and validation.

mod backend;
// The original-format reader feeds the compatibility daemon entry; the TOML
// entry point is unchanged.
#[allow(dead_code)]
pub mod compat;
#[allow(dead_code)]
pub mod legacy_filter;
#[cfg(test)]
mod legacy_filter_parity_test;
#[allow(dead_code)]
mod legacy_filter_spec;
#[allow(dead_code)]
mod legacy_ini;
#[allow(dead_code)]
mod legacy_interp;
#[allow(dead_code)]
pub(crate) mod legacy_jail_plan;
#[allow(dead_code)]
mod legacy_layers;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod legacy_parity_test;
#[cfg(test)]
mod legacy_stock_test;
#[allow(dead_code)]
pub(crate) mod legacy_tags;
mod load;
mod types;
mod validate;

use std::path::PathBuf;

pub use types::{
    Backend, Config, GlobalConfig, JailConfig, LegacyActionFamilyCmds, LegacyActionSpec,
    LogBackend, LogEncoding, LoggingConfig, MaxmindField,
};

use crate::error::Result;

/// Where the daemon loads and reloads its configuration from.
#[derive(Debug, Clone)]
pub enum Source {
    /// The TOML configuration file, with optional `config.d/` overlays.
    Toml(PathBuf),
    /// An original Fail2Ban configuration tree run with the decision
    /// recording action backend (stage-one compatibility mode).
    Fail2BanIni { dir: PathBuf, record: PathBuf },
    /// An original Fail2Ban configuration tree executing resolved `action.d`
    /// commands (`--legacy-execute-actions`).
    Fail2BanIniLive { dir: PathBuf },
}

impl Source {
    /// Load the current configuration.
    pub fn load(&self) -> Result<Config> {
        match self {
            Self::Toml(path) => Config::from_file(path),
            Self::Fail2BanIni { dir, record } => compat::load(dir, record),
            Self::Fail2BanIniLive { dir } => compat::load_with_actions(dir),
        }
    }

    /// The original Fail2Ban configuration directory, if running in compat mode.
    pub fn legacy_dir(&self) -> Option<&std::path::Path> {
        match self {
            Self::Fail2BanIni { dir, .. } | Self::Fail2BanIniLive { dir } => Some(dir.as_path()),
            Self::Toml(_) => None,
        }
    }
}
