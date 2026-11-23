//! Fail2Ban 1.1.1 shell, SMTP, and Python actions.

pub mod cmd;
pub mod command_action;
pub mod policy;
pub mod python;
pub mod smtp;
pub mod tags;

pub use command_action::CommandAction;
pub use policy::{ActionPolicy, Family};
pub use smtp::SmtpAction;
pub use tags::{StaticTemplate, escape_tag, replace_dynamic_tags};

use crate::error::{Error, Result};
use crate::protocol::PickleValue;
use crate::ticket::ActionContext;
use python::PythonAction;

/// Unified runtime action wrapper (`CommandAction`, built-in `SmtpAction`, or custom `PythonAction`).
#[derive(Debug)]
pub enum ActionKind {
    Command(CommandAction),
    Smtp(SmtpAction),
    Python(PythonAction),
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
    /// Stock Fail2Ban 1.1.1 `smtp.py` runs natively in Rust; customized `smtp.py`
    /// and any third-party `.py` action run through the Python 3 action bridge.
    pub async fn from_python_spec(
        jail_name: &str,
        act_name: &str,
        path: &str,
        init_json: &str,
        ban_time: i64,
    ) -> Result<ActionKind> {
        if SmtpAction::is_stock_module(path) {
            let smtp = SmtpAction::from_json(jail_name.to_owned(), act_name.to_owned(), init_json)?;
            return Ok(Self::Smtp(smtp));
        }
        Ok(Self::Python(
            PythonAction::load(jail_name, act_name, path, init_json, ban_time).await?,
        ))
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Command(a) => a.name(),
            Self::Smtp(a) => a.name(),
            Self::Python(a) => a.name(),
        }
    }

    pub fn jail_name(&self) -> &str {
        match self {
            Self::Command(a) => a.jail_name(),
            Self::Smtp(a) => a.jail_name(),
            Self::Python(a) => a.jail_name(),
        }
    }

    pub fn norestored(&self) -> bool {
        match self {
            Self::Command(a) => a.norestored(),
            Self::Smtp(a) => a.norestored(),
            Self::Python(a) => a.norestored,
        }
    }

    pub fn prolongable(&self) -> bool {
        match self {
            Self::Command(a) => a.prolongable(),
            Self::Smtp(a) => a.prolongable(),
            Self::Python(a) => a.prolongable,
        }
    }

    pub fn ban_epoch(&self) -> u64 {
        match self {
            Self::Command(a) => a.ban_epoch(),
            Self::Smtp(_) | Self::Python(_) => 0,
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
            Self::Python(_) => Err(Error::action(
                "executeCmd is not supported directly on Python actions",
            )),
        }
    }

    pub fn supports_flush(&self) -> bool {
        match self {
            Self::Command(a) => a.supports_flush(),
            Self::Smtp(_) => false,
            Self::Python(a) => a.flushable,
        }
    }

    pub fn shares_firewall_state(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Command(a), Self::Command(b)) => a.shares_firewall_state(b),
            (Self::Python(a), Self::Python(b)) => a.path() == b.path(),
            _ => false,
        }
    }

    pub async fn clear_all_params(&mut self) -> Result<()> {
        match self {
            Self::Command(a) => a.clear_all_params(),
            Self::Smtp(a) => a.clear_all_params(),
            Self::Python(a) if a.has_clear_all_params => {
                a.method("clearAllParams", None).await?;
            }
            Self::Python(_) => {}
        }
        Ok(())
    }

    pub async fn set_property(&mut self, key: &str, value: &str) -> Result<()> {
        match self {
            Self::Command(a) => a.set_property(key, value),
            Self::Smtp(a) => a.set_property(key, value),
            Self::Python(a) => a
                .set_or_call(key, Some(&PickleValue::Str(value.to_owned())))
                .await
                .map(|_| ()),
        }
    }

    pub async fn get_property(&mut self, key: &str) -> Result<Option<PickleValue>> {
        Ok(match self {
            Self::Command(a) => a.get_property(key),
            Self::Smtp(a) => a.get_property(key),
            Self::Python(a) => return a.query("get", Some(key)).await.map(Some),
        }
        .map(PickleValue::Str))
    }

    pub async fn property_names(&mut self) -> Result<PickleValue> {
        Ok(PickleValue::str_list(match self {
            Self::Command(a) => a.property_names(),
            Self::Smtp(a) => a.property_names(),
            Self::Python(a) => return a.query("properties", None).await,
        }))
    }

    pub async fn methods(&mut self) -> Result<PickleValue> {
        Ok(PickleValue::str_list(match self {
            Self::Command(a) => a.methods(),
            Self::Smtp(a) => a.methods(),
            Self::Python(a) => return a.query("methods", None).await,
        }))
    }

    pub async fn start(&mut self, allow_ipv6: bool) -> Result<()> {
        match self {
            Self::Command(a) => a.start(allow_ipv6).await,
            Self::Smtp(a) => a.start().await,
            Self::Python(a) => a.method("start", None).await.map(|_| ()),
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        match self {
            Self::Command(a) => a.stop().await,
            Self::Smtp(a) => a.stop().await,
            Self::Python(a) => a.method("stop", None).await.map(|_| ()),
        }
    }

    pub async fn ban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.ban(ctx).await,
            Self::Smtp(a) => a.ban(ctx).await,
            Self::Python(a) => a.event("ban", ctx).await,
        }
    }

    pub async fn reban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.reban(ctx).await,
            Self::Smtp(a) => a.reban(ctx).await,
            Self::Python(a) => a.event("reban", ctx).await,
        }
    }

    pub async fn prolong(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.prolong(ctx).await,
            Self::Smtp(_) => Ok(()),
            Self::Python(a) => a.event("prolong", ctx).await,
        }
    }

    pub async fn unban(&mut self, ctx: &ActionContext) -> Result<()> {
        match self {
            Self::Command(a) => a.unban(ctx).await,
            Self::Smtp(a) => a.unban(ctx).await,
            Self::Python(a) => a.event("unban", ctx).await,
        }
    }

    pub async fn flush(&mut self) -> Result<bool> {
        match self {
            Self::Command(a) => a.flush().await.map(|()| true),
            Self::Smtp(_) => Ok(false),
            Self::Python(a) => a.flush().await,
        }
    }

    pub async fn reload(&mut self, options: Option<&str>) -> Result<()> {
        match self {
            Self::Command(a) => a.reload().await,
            Self::Smtp(_) => Ok(()),
            Self::Python(a) if a.reloadable => a.method("reload", options).await.map(|_| ()),
            Self::Python(_) => Ok(()),
        }
    }

    pub async fn consistency_check(&mut self) -> Result<bool> {
        match self {
            Self::Command(a) => a.consistency_check().await,
            Self::Smtp(_) => Ok(true),
            Self::Python(a) => a.consistency_check().await,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loads_stock_smtp_natively_and_custom_smtp_filename_in_python() {
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
            600,
        )
        .await
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
        let action = ActionKind::from_python_spec(
            "sshd",
            "example",
            other_smtp.to_str().unwrap(),
            r#"{"opt1":"world"}"#,
            600,
        )
        .await
        .unwrap();
        let ActionKind::Python(mut action) = action else {
            panic!("expected Python action");
        };
        assert_eq!(
            action
                .set_or_call(
                    "testmethod",
                    Some(&PickleValue::Str(r#"{"text":"there"}"#.to_owned())),
                )
                .await
                .unwrap(),
            PickleValue::Str("Hello there world".to_owned())
        );

        // Invalid Python action modules must fail with clear upstream errors.
        let no_action = reference.join("fail2ban/tests/files/action.d/action_noAction.py");
        assert!(
            ActionKind::from_python_spec("sshd", "bad1", no_action.to_str().unwrap(), "{}", 600)
                .await
                .is_err()
        );
        let no_method = reference.join("fail2ban/tests/files/action.d/action_nomethod.py");
        assert!(
            ActionKind::from_python_spec("sshd", "bad2", no_method.to_str().unwrap(), "{}", 600)
                .await
                .is_err()
        );
    }
}
