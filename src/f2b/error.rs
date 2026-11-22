//! Error types for fail2ban-rs (Fail2Ban 1.1.1 Rust replacement).

use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Regex(String),

    #[error("{0}")]
    Date(String),

    #[error("{0}")]
    Action(String),

    #[error("{0}")]
    Database(String),

    #[error("{0}")]
    Protocol(String),

    #[error("{0}")]
    UnknownJail(String),

    #[error("{0}")]
    DuplicateJail(String),

    #[error("{0}")]
    InvalidCommand(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn regex(msg: impl Into<String>) -> Self {
        Self::Regex(msg.into())
    }

    pub fn date(msg: impl Into<String>) -> Self {
        Self::Date(msg.into())
    }

    pub fn action(msg: impl Into<String>) -> Self {
        Self::Action(msg.into())
    }

    pub fn database(msg: impl Into<String>) -> Self {
        Self::Database(msg.into())
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    pub fn unknown_jail(name: &str) -> Self {
        Self::UnknownJail(format!("Sorry but the jail '{name}' does not exist"))
    }

    pub fn duplicate_jail(name: &str) -> Self {
        Self::DuplicateJail(format!("The jail '{name}' already exists"))
    }

    pub fn invalid_command(msg: impl Into<String>) -> Self {
        Self::InvalidCommand(msg.into())
    }

    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}
