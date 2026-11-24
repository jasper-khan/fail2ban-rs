//! Fail2Ban 1.1.1 shell and built-in SMTP actions.

pub mod cmd;
pub mod command_action;
pub mod policy;
pub mod smtp;
pub mod tags;

pub use command_action::CommandAction;
pub use policy::{ActionPolicy, Family};
pub use smtp::SmtpAction;
pub use tags::{
    ShellCommand, StaticTemplate, build_shell_command, escape_tag, replace_dynamic_tags,
};

use crate::error::{Error, Result};
use crate::protocol::PickleValue;
use crate::ticket::ActionContext;

/// Unified runtime action wrapper (`CommandAction` or built-in `SmtpAction`).
#[derive(Debug)]
pub enum ActionKind {
    Command(CommandAction),
    Smtp(SmtpAction),
}

impl ActionKind {
    /// Construct a standard shell-command action (`CommandAction`).
    pub fn command(jail_name: String, name: String) -> Self {
        Self::Command(CommandAction::new(jail_name, name))
    }

    /// Wrap an existing [`SmtpAction`].
    pub fn smtp(action: SmtpAction) -> Self {
        Self::Smtp(action)
    }

    /// Instantiate a `.py` action module spec (`addaction <name> <path> <init_json>`).
    ///
    /// Only the stock Fail2Ban 1.1.1 `smtp.py` action is supported (implemented natively in Rust).
    pub fn from_python_spec(
        jail_name: &str,
        act_name: &str,
        path: &str,
        init_json: &str,
    ) -> Result<ActionKind> {
        if SmtpAction::is_stock_module(path) {
            let smtp = SmtpAction::from_json(jail_name.to_owned(), act_name.to_owned(), init_json)?;
            return Ok(Self::Smtp(smtp));
        }
        Err(Error::action(format!(
            "Custom Python actions are not supported in fail2ban-rs (only stock smtp.py is supported): {path}"
        )))
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Command(a) => a.name(),
            Self::Smtp(a) => a.name(),
        }
    }

    pub fn jail_name(&self) -> &str {
        match self {
            Self::Command(a) => a.jail_name(),
            Self::Smtp(a) => a.jail_name(),
        }
    }

    pub fn norestored(&self) -> bool {
        match self {
            Self::Command(a) => a.norestored(),
            Self::Smtp(a) => a.norestored(),
        }
    }

    pub fn prolongable(&self) -> bool {
        match self {
            Self::Command(a) => a.prolongable(),
            Self::Smtp(a) => a.prolongable(),
        }
    }

    pub fn ban_epoch(&self) -> u64 {
        match self {
            Self::Command(a) => a.ban_epoch(),
            Self::Smtp(_) => 0,
        }
    }

    pub fn invalidate_ban_epoch(&mut self) {
        if let Self::Command(a) = self {
            a.invalidate_ban_epoch();
        }
    }

    pub async fn execute_raw_cmd(
        &self,
        real_cmd: &str,
        timeout_override: Option<std::time::Duration>,
    ) -> Result<bool> {
        match self {
            Self::Command(a) => a.execute_raw_cmd(real_cmd, timeout_override).await,
            Self::Smtp(_) => Err(Error::action("executeCmd is not supported on smtp.py")),
        }
    }

    pub fn supports_flush(&self) -> bool {
        match self {
            Self::Command(a) => a.supports_flush(),
            Self::Smtp(_) => false,
        }
    }

    pub fn has_reload(&self) -> bool {
        matches!(self, Self::Command(_))
    }

    pub fn has_clear_all_params(&self) -> bool {
        matches!(self, Self::Command(_))
    }

    pub async fn clear_all_params(&mut self) -> Result<()> {
        match self {
            Self::Command(a) => a.clear_all_params(),
            Self::Smtp(a) => a.clear_all_params(),
        }
        Ok(())
    }

    pub async fn set_property(&mut self, key: &str, value: &str) -> Result<()> {
        match self {
            Self::Command(a) => a.set_property(key, value),
            Self::Smtp(a) => a.set_property(key, value),
        }
    }

    pub async fn get_property(&mut self, key: &str) -> Result<Option<PickleValue>> {
        Ok(match self {
            Self::Command(a) => a.get_property(key),
            Self::Smtp(a) => a.get_property(key),
        }
        .map(PickleValue::Str))
    }

    pub async fn property_names(&mut self) -> Result<PickleValue> {
        Ok(PickleValue::str_list(match self {
            Self::Command(a) => a.property_names(),
            Self::Smtp(a) => a.property_names(),
        }))
    }

    pub async fn methods(&mut self) -> Result<PickleValue> {
        Ok(PickleValue::str_list(match self {
            Self::Command(a) => a.methods(),
            Self::Smtp(a) => a.methods(),
        }))
    }

    pub async fn start(&mut self, allow_ipv6: bool) -> Result<()> {
        match self {
            Self::Command(a) => a.start(allow_ipv6).await,
            Self::Smtp(a) => a.start().await,
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        match self {
            Self::Command(a) => a.stop().await,
            Self::Smtp(a) => a.stop().await,
        }
    }

    pub async fn ban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.ban(ctx).await,
            Self::Smtp(a) => a.ban(ctx).await,
        }
    }

    pub async fn reban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.reban(ctx).await,
            Self::Smtp(a) => a.reban(ctx).await,
        }
    }

    pub async fn prolong(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.prolong(ctx).await,
            Self::Smtp(_) => Ok(()),
        }
    }

    pub async fn unban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.unban(ctx).await,
            Self::Smtp(a) => a.unban(ctx).await,
        }
    }

    pub async fn flush(&mut self) -> Result<bool> {
        match self {
            Self::Command(a) => a.flush().await.map(|()| true),
            Self::Smtp(_) => Ok(false),
        }
    }

    pub async fn reload(&mut self, _options: Option<&str>) -> Result<()> {
        match self {
            Self::Command(a) => a.reload().await,
            Self::Smtp(_) => Ok(()),
        }
    }

    pub fn has_consistency_check(&self) -> bool {
        matches!(self, Self::Command(_))
    }

    pub async fn consistency_check(&mut self) -> Result<bool> {
        match self {
            Self::Command(a) => a.consistency_check().await,
            Self::Smtp(_) => Ok(true),
        }
    }

    pub async fn consistency_check_on_flush(&mut self, on_stop: bool) -> Result<bool> {
        match self {
            Self::Command(a) => a.consistency_check_on_flush(on_stop).await,
            Self::Smtp(_) => Ok(true),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loads_stock_smtp_natively_and_rejects_custom_python_actions() {
        let Some(reference) = std::env::var_os("FAIL2BAN_111_SOURCE") else {
            return;
        };
        let reference = std::path::PathBuf::from(reference);
        let stock = reference.join("config/action.d/smtp.py");
        let mut smtp = ActionKind::from_python_spec(
            "sshd",
            "smtp",
            stock.to_str().unwrap(),
            r#"{"dest":"ops@example.com","matches":"matches"}"#,
        )
        .unwrap();
        assert!(matches!(smtp, ActionKind::Smtp(_)));
        assert_eq!(smtp.name(), "smtp");
        assert!(smtp.norestored());
        assert!(!smtp.prolongable());
        assert_eq!(
            smtp.get_property("dest").await.unwrap(),
            Some(PickleValue::Str("ops@example.com".to_owned()))
        );

        let layout = tempfile::tempdir().unwrap();
        let other_smtp = layout.path().join("smtp.py");
        std::fs::copy(
            reference.join("fail2ban/tests/files/action.d/action.py"),
            &other_smtp,
        )
        .unwrap();
        let err = ActionKind::from_python_spec(
            "sshd",
            "example",
            other_smtp.to_str().unwrap(),
            r#"{"opt1":"world"}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported"),
            "unexpected error for custom python action: {err}"
        );
    }
}
