//! Fail2Ban 1.1.1 action execution subsystem (`CommandAction` & `SmtpAction`).

pub mod cmd;
pub mod command_action;
pub mod policy;
pub mod smtp;
pub mod tags;

pub use command_action::CommandAction;
pub use policy::{ActionPolicy, Family};
pub use smtp::SmtpAction;
pub use tags::{StaticTemplate, escape_tag, replace_dynamic_tags};

use crate::error::{Error, Result};
use crate::ticket::ActionContext;

/// Unified runtime action wrapper (`CommandAction` or built-in pure-Rust `SmtpAction`).
#[derive(Debug, Clone)]
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

    /// Instantiate a Python action module spec (`addaction <name> <path> <init_json>`).
    ///
    /// Built-in `smtp.py` is supported natively in pure Rust; any other custom
    /// `.py` action returns an explicit unsupported error.
    pub fn from_python_spec(
        jail_name: &str,
        act_name: &str,
        path: &str,
        init_json: &str,
    ) -> Result<ActionKind> {
        let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
        if basename == "smtp.py" {
            let smtp = SmtpAction::from_json(jail_name.to_owned(), act_name.to_owned(), init_json)?;
            return Ok(Self::Smtp(smtp));
        }
        Err(Error::action(format!(
            "custom Python action {path:?} is not supported in pure-Rust fail2ban-rs (only built-in smtp.py is supported)"
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

    pub fn clear_all_params(&mut self) {
        match self {
            Self::Command(a) => a.clear_all_params(),
            Self::Smtp(a) => a.clear_all_params(),
        }
    }

    pub fn set_property(&mut self, key: &str, value: &str) -> Result<()> {
        match self {
            Self::Command(a) => a.set_property(key, value),
            Self::Smtp(a) => a.set_property(key, value),
        }
    }

    pub fn get_property(&self, key: &str) -> Option<String> {
        match self {
            Self::Command(a) => a.get_property(key),
            Self::Smtp(a) => a.get_property(key),
        }
    }

    pub fn del_property(&mut self, key: &str) {
        match self {
            Self::Command(a) => a.del_property(key),
            Self::Smtp(a) => a.del_property(key),
        }
    }

    pub fn property_names(&self) -> Vec<String> {
        match self {
            Self::Command(a) => a.property_names(),
            Self::Smtp(a) => a.property_names(),
        }
    }

    pub fn methods(&self) -> Vec<String> {
        match self {
            Self::Command(a) => a.methods(),
            Self::Smtp(a) => a.methods(),
        }
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
            Self::Smtp(_a) => {
                let _ = ctx;
                Ok(())
            }
        }
    }

    pub async fn unban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.unban(ctx).await,
            Self::Smtp(a) => a.unban(ctx).await,
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        match self {
            Self::Command(a) => a.flush().await,
            Self::Smtp(_) => Ok(()),
        }
    }

    pub async fn reload(&mut self) -> Result<()> {
        match self {
            Self::Command(a) => a.reload().await,
            Self::Smtp(_) => Ok(()),
        }
    }

    pub async fn consistency_check(&mut self) -> Result<bool> {
        match self {
            Self::Command(a) => a.consistency_check().await,
            Self::Smtp(_) => Ok(true),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn from_python_spec_accepts_smtp_and_rejects_custom_scripts() {
        let smtp = ActionKind::from_python_spec(
            "sshd",
            "smtp",
            "/etc/fail2ban/action.d/smtp.py",
            r#"{"dest":"ops@example.com","matches":"matches"}"#,
        )
        .unwrap();
        assert!(matches!(smtp, ActionKind::Smtp(_)));
        assert_eq!(smtp.name(), "smtp");
        assert!(smtp.norestored());
        assert!(!smtp.prolongable());
        assert_eq!(
            smtp.get_property("dest").as_deref(),
            Some("ops@example.com")
        );

        let err = ActionKind::from_python_spec(
            "sshd",
            "custom",
            "/etc/fail2ban/action.d/my_custom.py",
            "{}",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not supported"));
        assert!(
            err.to_string()
                .contains("only built-in smtp.py is supported")
        );

        let decoy = ActionKind::from_python_spec(
            "sshd",
            "decoy",
            "/etc/fail2ban/action.d/not_smtp.py",
            "{}",
        )
        .unwrap_err();
        assert!(decoy.to_string().contains("not supported"));
    }
}
