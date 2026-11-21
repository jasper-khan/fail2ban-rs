//! fail2ban-rs — A pure-Rust replacement for fail2ban.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use fail2ban_rs::config::{Config, Source};
use fail2ban_rs::control::{self, Request, Response};

mod dry_run;
mod output;
use output::{print_bans_jsonl, print_bans_table, print_response};

const HELP_TEMPLATE: &str = "\
{name} {version}
{about}

{usage-heading} {usage}

{all-args}";

#[derive(Parser)]
#[command(
    name = "fail2ban-rs",
    version,
    about = "A pure-Rust replacement for fail2ban",
    help_template = HELP_TEMPLATE
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to the configuration file
    #[arg(
        short,
        long,
        global = true,
        default_value = "/etc/fail2ban-rs/config.toml"
    )]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Run the fail2ban-rs daemon
    Run {
        /// Original Fail2Ban configuration tree (jail.conf + filter.d) to
        /// load instead of the TOML configuration file
        #[arg(long)]
        legacy_dir: Option<PathBuf>,

        /// Decision record file used with --legacy-dir: ban and unban
        /// decisions are appended here, no firewall is touched
        #[arg(long)]
        record_decisions: Option<PathBuf>,

        /// Also bind an upstream Fail2Ban 1.1.1 (`fail2ban-client`) Unix socket
        #[arg(long)]
        legacy_socket: Option<PathBuf>,

        /// Execute real action.d/*.conf commands with --legacy-dir instead of
        /// --record-decisions
        #[arg(long)]
        legacy_execute_actions: bool,

        /// Mirror bans, unbans, and log checkpoints directly into Fail2Ban 1.1.1's
        /// v4 SQLite database (`dbfile` from fail2ban.conf/local)
        #[arg(long)]
        legacy_sqlite_rw: bool,
    },

    /// Show daemon status
    Status,

    /// List active bans
    ListBans {
        /// Output as JSONL (one JSON object per line)
        #[arg(long)]
        json: bool,
    },

    /// Show daemon statistics
    Stats,

    /// Ban an IP address
    Ban {
        /// IP address to ban
        ip: IpAddr,
        /// Jail name
        #[arg(short, long)]
        jail: String,
    },

    /// Unban an IP address
    Unban {
        /// IP address to unban
        ip: IpAddr,
        /// Jail name
        #[arg(short, long)]
        jail: String,
    },

    /// Reload daemon configuration
    Reload,

    /// Test a regex pattern against a log line
    Regex {
        /// The pattern (with <HOST> placeholder)
        #[arg(short, long)]
        pattern: String,
        /// The log line to test against
        #[arg(short, long)]
        line: String,
    },

    /// Analyze a log file without banning (dry run)
    DryRun {
        /// Log file to analyze
        log: PathBuf,
        /// Filter to specific jail
        #[arg(short, long)]
        jail: Option<String>,
    },

    /// Generate a jail configuration for a service
    GenConfig {
        /// Service name (sshd, nginx-auth, nginx-botsearch, postfix, dovecot, vsftpd, asterisk, mysqld)
        service: String,
    },

    /// List available built-in filter templates
    ListFilters,

    /// Show configured MaxMind databases
    #[cfg(feature = "maxmind")]
    ListMaxmind,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { command, config } = Cli::parse();
    let path = config.as_path();
    match command {
        Command::Run {
            legacy_dir,
            record_decisions,
            legacy_socket,
            legacy_execute_actions,
            legacy_sqlite_rw,
        } => {
            run_daemon(
                path,
                legacy_dir,
                record_decisions,
                legacy_socket,
                legacy_execute_actions,
                legacy_sqlite_rw,
            )
            .await?;
        }
        Command::Status => print_response(&send_control(path, Request::Status).await?),
        Command::ListBans { json } => list_bans(path, json).await?,
        Command::Stats => print_response(&send_control(path, Request::Stats).await?),
        Command::Ban { ip, jail } => {
            print_response(&send_control(path, Request::Ban { ip, jail }).await?);
        }
        Command::Unban { ip, jail } => {
            print_response(&send_control(path, Request::Unban { ip, jail }).await?);
        }
        Command::Reload => print_response(&send_control(path, Request::Reload).await?),
        Command::Regex { pattern, line } => fail2ban_rs::regex_tool::test_pattern(&pattern, &line),
        Command::DryRun { log, jail } => {
            let config = Config::from_file(path).context("loading config")?;
            dry_run::run(&config, &log, jail.as_deref())?;
        }
        Command::GenConfig { service } => gen_config(&service),
        Command::ListFilters => list_filters(),
        #[cfg(feature = "maxmind")]
        Command::ListMaxmind => list_maxmind(path)?,
    }
    Ok(())
}

/// Load the config, set up tracing, and run the daemon until shutdown.
async fn run_daemon(
    toml_path: &Path,
    legacy_dir: Option<PathBuf>,
    record_decisions: Option<PathBuf>,
    legacy_socket: Option<PathBuf>,
    legacy_execute_actions: bool,
    legacy_sqlite_rw: bool,
) -> Result<()> {
    if legacy_sqlite_rw && !legacy_execute_actions {
        anyhow::bail!(
            "--legacy-sqlite-rw requires --legacy-execute-actions; recording must not write the upstream database"
        );
    }
    let source = match (legacy_dir, record_decisions, legacy_execute_actions) {
        (None, None, false) => Source::Toml(toml_path.to_path_buf()),
        (Some(dir), Some(record), false) => Source::Fail2BanIni { dir, record },
        (Some(dir), None, true) => Source::Fail2BanIniLive { dir },
        (Some(_), Some(_), true) => {
            anyhow::bail!("--record-decisions and --legacy-execute-actions are mutually exclusive")
        }
        _ => anyhow::bail!(
            "--legacy-dir requires either --record-decisions or --legacy-execute-actions"
        ),
    };
    let mut config = source.load().context("failed to load configuration")?;
    if legacy_sqlite_rw {
        let Some(dir) = source.legacy_dir() else {
            anyhow::bail!("--legacy-sqlite-rw requires --legacy-dir");
        };
        let dbfile = fail2ban_rs::config::compat::dbfile_of(dir)
            .context("reading dbfile from legacy fail2ban.conf")?;
        config.global.legacy_sqlite_rw_path = Some(dbfile);
    }
    #[cfg(unix)]
    if let Some(sock) = legacy_socket {
        config.global.legacy_socket_path = Some(
            fail2ban_rs::legacy_protocol::validate_legacy_socket_path(&sock)
                .context("validating --legacy-socket")?,
        );
    }
    #[cfg(not(unix))]
    let _ = legacy_socket;
    init_tracing(
        config.logging.level.as_deref(),
        config.logging.format.as_deref(),
    );
    fail2ban_rs::server::run(config, source)
        .await
        .context("daemon error")
}

/// Send one request to the daemon's control socket (path from the config).
async fn send_control(path: &Path, request: Request) -> Result<Response> {
    let config = Config::from_file(path).context("loading config for socket path")?;
    control::send_request(&config.global.socket_path, &request)
        .await
        .context("connecting to daemon")
}

/// Print the daemon's active bans as JSON lines or a table.
async fn list_bans(path: &Path, json: bool) -> Result<()> {
    let response = send_control(path, Request::ListBans).await?;
    if json {
        print_bans_jsonl(&response);
    } else {
        print_bans_table(&response);
    }
    Ok(())
}

/// Print a jail config template for `service`, or exit 1 if it is unknown.
fn gen_config(service: &str) {
    if let Some(template) = fail2ban_rs::detect::filters::find(service) {
        print!("{}", fail2ban_rs::detect::filters::gen_config(template));
        return;
    }
    eprintln!("Unknown service: {service}");
    eprintln!("Available: {}", available_filters());
    std::process::exit(1);
}

/// Print every built-in filter template with its description.
fn list_filters() {
    for f in fail2ban_rs::detect::filters::FILTERS {
        println!("{:20} {}", f.name, f.description);
    }
}

/// Print each configured MaxMind database and whether it loads.
#[cfg(feature = "maxmind")]
fn list_maxmind(path: &Path) -> Result<()> {
    let config = Config::from_file(path).context("failed to load configuration")?;
    println!("MaxMind databases:");
    for (label, db) in [
        ("ASN", &config.global.maxmind_asn),
        ("Country", &config.global.maxmind_country),
        ("City", &config.global.maxmind_city),
    ] {
        match db {
            Some(p) => match fail2ban_rs::track::maxmind::load_db(p, label) {
                Some(_) => println!("  {label:8} {:<50} OK", p.display()),
                None => println!("  {label:8} {:<50} FAILED", p.display()),
            },
            None => println!("  {label:8} Not configured"),
        }
    }
    Ok(())
}

fn available_filters() -> String {
    fail2ban_rs::detect::filters::FILTERS
        .iter()
        .map(|f| f.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn init_tracing(level: Option<&str>, format: Option<&str>) {
    let filter = level.unwrap_or("info");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    // Whole payload lands in journald MESSAGE (logfmt or JSON).
    // Under systemd, each line gets a `<N>` prefix so journald sets PRIORITY
    // per-entry (stripped before MESSAGE is stored). Service name comes from
    // the unit's SyslogIdentifier. No custom journald layer, no structured
    // journald metadata — consumers (journalctl, rsyslog, witness) read and
    // parse MESSAGE as the source of truth.
    let systemd = std::env::var_os("JOURNAL_STREAM").is_some();
    let log_format = fail2ban_rs::log_format::LogFormat::parse(format);
    let formatter = fail2ban_rs::log_format::StructuredFormatter::new(log_format, systemd);

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .event_format(formatter)
        .with_env_filter(env_filter)
        .init();
}
