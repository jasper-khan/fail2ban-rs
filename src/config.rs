//! TOML configuration loading and validation.

mod backend;
// The original-format reader is tested independently until the daemon can
// consume its effective jail settings. The TOML entry point is unchanged.
#[allow(dead_code)]
pub(crate) mod legacy_filter;
#[cfg(test)]
mod legacy_filter_parity_test;
#[allow(dead_code)]
mod legacy_filter_spec;
#[allow(dead_code)]
mod legacy_ini;
#[allow(dead_code)]
mod legacy_interp;
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

pub use types::{
    Backend, Config, GlobalConfig, JailConfig, LogBackend, LoggingConfig, MaxmindField,
};
