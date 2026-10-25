#![forbid(unsafe_code)]
//! `agent-auth-hostd`: pair the host, enroll its TOTP secrets, run the
//! daemon, and the desktop helper (daemons-hostd spec §3.4, §7, §13).
//!
//! Without a config file the daemon only connects and reports: no tier is
//! enabled, so it runs nothing for anyone.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;

use agent_auth_core::hostd::totp::SecretName;
use agent_auth_crypto::daemon::{DaemonName, PublicKey, load_or_create_key};
use agent_auth_crypto::totp::otpauth_uri;
use agent_auth_daemon::BrokerUrl;
use agent_auth_hostd::config::{CONFIG_ENV, HostConfig, darwin, default_state_dir};
use agent_auth_hostd::executor::darwin::{DarwinExecutor, run_asuser};
use agent_auth_hostd::executor::linux::{LinuxConfig, SystemdExecutor};
use agent_auth_hostd::totp_store::TotpStore;
use agent_auth_hostd::{effective_uid, fsutil, identity};
use clap::{Parser, Subcommand};

const PAIRING_CODE_ENV: &str = "AGENT_AUTH_HOSTD_PAIRING_CODE";

#[derive(Parser, Debug)]
#[command(name = "agent-auth-hostd", about = "agent-auth host daemon")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(clap::Args, Debug, Clone)]
struct Common {
    /// hostd's config and local policy (JSON, from the NixOS module).
    #[arg(long, env = CONFIG_ENV)]
    config: Option<PathBuf>,
    #[arg(long, env = "AGENT_AUTH_HOSTD_BROKER_URL")]
    broker_url: Option<String>,
    /// The broker's pinned public key (ed25519:…).
    #[arg(long, env = "AGENT_AUTH_HOSTD_BROKER_KEY")]
    broker_key: Option<String>,
    /// Default: the first label of the hostname.
    #[arg(long, env = "AGENT_AUTH_HOSTD_NAME")]
    name: Option<String>,
    #[arg(long, env = "AGENT_AUTH_HOSTD_STATE_DIR")]
    state_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pair this host with the broker using a one-time code from
    /// `agent-auth admin daemon-pair <name>`. `-` reads the code from stdin;
    /// otherwise AGENT_AUTH_HOSTD_PAIRING_CODE or a prompt. Never argv.
    Pair {
        #[arg(value_name = "-")]
        source: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Print this host's public key and fingerprint (creating the key).
    Key {
        #[command(flatten)]
        common: Common,
    },
    /// Create this host's TOTP secrets and show each ONCE (as a QR code).
    TotpEnroll {
        /// Replace one secret: user-arm, user-direct, root-arm, root-direct.
        #[arg(long)]
        rotate: Option<String>,
        #[arg(long)]
        qrencode: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// The daemon (the systemd service's, or launchd daemon's, entry point).
    Run {
        #[command(flatten)]
        common: Common,
    },
    /// The desktop helper (a user service).
    User {
        #[arg(long, env = CONFIG_ENV)]
        config: Option<PathBuf>,
    },
    /// macOS: the last step before a user-tier job runs (internal).
    #[command(hide = true)]
    Asuser { spec: String },
}

fn fail(msg: &str, code: u8) -> ExitCode {
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[31m{msg}\x1b[0m");
    } else {
        eprintln!("{msg}");
    }
    ExitCode::from(code)
}

fn default_name() -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .unwrap_or_default();
    host.trim().split('.').next().unwrap_or("").to_lowercase()
}

/// The config file if there is one; else a connect-only config from the
/// options (no tiers: nothing can run).
fn load(common: &Common) -> Result<HostConfig, ExitCode> {
    if let Some(path) = &common.config {
        return HostConfig::load(path)
            .map_err(|e| fail(&format!("invalid config {}: {e}", path.display()), 2));
    }
    let (Some(url), Some(key)) = (&common.broker_url, &common.broker_key) else {
        return Err(fail("need --config, or --broker-url and --broker-key", 2));
    };
    let url = BrokerUrl::parse(url).map_err(|e| fail(&format!("invalid --broker-url: {e}"), 2))?;
    let key = PublicKey::parse(key).map_err(|e| fail(&format!("invalid --broker-key: {e}"), 2))?;
    let name_text = common.name.clone().unwrap_or_else(default_name);
    let name = DaemonName::parse(&name_text)
        .ok_or_else(|| fail(&format!("invalid name {name_text:?}"), 2))?;
    Ok(HostConfig::connect_only(
        url,
        key,
        name,
        common.state_dir.clone().unwrap_or_else(default_state_dir),
    ))
}

/// Read a line without echo (`stty -echo` on the terminal; no libc).
fn read_hidden(prompt: &str) -> String {
    eprint!("{prompt}: ");
    let _ = std::io::stderr().flush();
    let stty = |arg: &str| {
        let _ = std::process::Command::new("stty")
            .arg(arg)
            .stdin(Stdio::inherit())
            .status();
    };
    stty("-echo");
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    stty("echo");
    eprintln!();
    line
}

fn read_pairing_code(source: Option<&str>) -> Result<String, ExitCode> {
    let code = match source {
        None => std::env::var(PAIRING_CODE_ENV)
            .ok()
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| read_hidden("pairing code")),
        Some("-") => {
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            line
        }
        Some(_) => {
            return Err(fail(
                &format!(
                    "the pairing code is not accepted on the command line (it lands in shell \
                     history and process listings). Issue a fresh code with `agent-auth admin \
                     daemon-pair`, then run `agent-auth-hostd pair` and enter it at the prompt \
                     (or pipe it to `pair -`, or set {PAIRING_CODE_ENV})."
                ),
                2,
            ));
        }
    };
    let code = code.trim().to_owned();
    if code.is_empty() {
        return Err(fail("no pairing code given", 2));
    }
    Ok(code)
}

async fn pair(source: Option<String>, common: Common) -> ExitCode {
    let config = match load(&common) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let ident = match identity(&config) {
        Ok(i) => i,
        Err(e) => return fail(&e.to_string(), 1),
    };
    let code = match read_pairing_code(source.as_deref()) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let tls = match agent_auth_tls::default_client_config() {
        Ok(t) => Arc::new(t),
        Err(e) => return fail(&e.to_string(), 1),
    };
    if let Err(e) = agent_auth_daemon::pair::pair(&ident, &code, tls).await {
        return fail(&e.to_string(), 1);
    }
    let record = serde_json::json!({
        "role": "host",
        "name": config.name.as_str(),
        "broker_url": config.broker_url.as_str(),
        "broker_public_key": config.broker_public_key.to_text(),
        "paired_at": time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });
    let text = serde_json::to_string_pretty(&record).unwrap_or_default() + "\n";
    if let Err(e) = fsutil::write_atomic(
        &config.state_dir.join("paired.json"),
        text.as_bytes(),
        0o600,
    ) {
        return fail(&format!("paired, but could not write paired.json: {e}"), 1);
    }
    println!("paired as {}", ident.principal());
    println!("  this host's key: {}", ident.public_key().fingerprint());
    println!(
        "  broker key:      {}",
        config.broker_public_key.fingerprint()
    );
    println!("Compare with `agent-auth admin daemons`. Restart agent-auth-hostd to connect.");
    ExitCode::SUCCESS
}

fn totp_enroll(rotate: Option<String>, qrencode: Option<String>, common: Common) -> ExitCode {
    let config = match &common.config {
        Some(path) => match HostConfig::load(path) {
            Ok(c) => Some(c),
            Err(e) => return fail(&format!("invalid config {}: {e}", path.display()), 2),
        },
        None => None,
    };
    if effective_uid() != 0 {
        return fail("run as root: the secrets are root-only", 1);
    }
    let state_dir = config
        .as_ref()
        .map(|c| c.state_dir.clone())
        .or(common.state_dir)
        .unwrap_or_else(default_state_dir);
    let host = config
        .as_ref()
        .map_or_else(default_name, |c| c.name.as_str().to_owned());
    let store = TotpStore::new(state_dir.join("totp"));
    let names: Vec<SecretName> = match &rotate {
        Some(n) => match SecretName::parse(n) {
            Some(n) => vec![n],
            None => return fail(&format!("unknown TOTP secret {n:?}"), 1),
        },
        None => SecretName::ALL
            .into_iter()
            .filter(|n| !store.enrolled(*n))
            .collect(),
    };
    if names.is_empty() {
        println!("all four secrets are enrolled; use --rotate <name> to replace one");
        return ExitCode::SUCCESS;
    }
    let qr = qrencode
        .or_else(|| config.as_ref().map(|c| c.qrencode.clone()))
        .unwrap_or_else(|| "qrencode".to_owned());
    for name in names {
        let secret = match store.enroll(name, rotate.is_some()) {
            Ok(s) => s,
            Err(e) => return fail(&e.to_string(), 1),
        };
        let uri = otpauth_uri(&secret, &host, name.as_str());
        println!("\n== {host} {name} ==");
        let shown = std::process::Command::new(&qr)
            .args(["-t", "ANSIUTF8", uri.expose()])
            .status()
            .is_ok_and(|s| s.success());
        if !shown {
            println!("(no qrencode: add it by hand)");
        }
        println!("secret: {}", secret.to_base32().expose());
        println!("{}", uri.expose());
    }
    println!("\nScan them now: they are not shown again. Restart is not needed.");
    ExitCode::SUCCESS
}

fn init_logging() {
    let filter = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_owned());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter.to_lowercase()))
        .with_target(true)
        .try_init();
}

async fn run(common: Common) -> ExitCode {
    init_logging();
    let config = match load(&common) {
        Ok(c) => c,
        Err(code) => return code,
    };
    if let Err(e) = load_or_create_key(&config.key_path()) {
        return fail(&e.to_string(), 2);
    }
    if !config.state_dir.join("paired.json").exists() {
        tracing::warn!(
            "host:{} has not been paired on this machine; the broker will refuse it until \
             `agent-auth-hostd pair` succeeds",
            config.name
        );
    }
    if config.privileged() && effective_uid() != 0 {
        tracing::error!(
            "tiers or a VM are configured but hostd is not root: jobs will fail to start"
        );
    }
    let result = if darwin() {
        // What systemd's StateDirectory= and RuntimeDirectory= do on Linux.
        if let Err(e) = prepare_dirs(&config) {
            return fail(&e.to_string(), 1);
        }
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-auth-hostd"));
        let exec = DarwinExecutor::new(config.job_path.clone(), config.user.clone(), exe);
        agent_auth_hostd::run(config, exec).await
    } else {
        let exec = SystemdExecutor::new(LinuxConfig {
            systemd_run: config.systemd_run.clone(),
            systemctl: config.systemctl.clone(),
            pkcheck: config.pkcheck.clone(),
            job_path: config.job_path.clone(),
            user: config.user.clone(),
        });
        agent_auth_hostd::run(config, exec).await
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e.to_string(), 1),
    }
}

/// The state private to hostd, the sockets' directory reachable by the
/// user (each socket checks who is calling).
fn prepare_dirs(config: &HostConfig) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fsutil::private_dir(&config.state_dir, 0o700)?;
    std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
    fsutil::private_dir(&config.runtime_dir, 0o755)?;
    std::fs::set_permissions(&config.runtime_dir, std::fs::Permissions::from_mode(0o755))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Cmd::Asuser { spec } = &cli.command {
        // Only returns on failure.
        eprintln!("{}", run_asuser(spec));
        return ExitCode::from(127);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string(), 1),
    };
    runtime.block_on(async move {
        match cli.command {
            Cmd::Pair { source, common } => pair(source, common).await,
            Cmd::Key { common } => {
                let state_dir = common.state_dir.unwrap_or_else(default_state_dir);
                match load_or_create_key(&state_dir.join("key")) {
                    Ok(k) => {
                        println!("{}", k.public_key().to_text());
                        println!("{}", k.public_key().fingerprint());
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(&e.to_string(), 1),
                }
            }
            Cmd::TotpEnroll {
                rotate,
                qrencode,
                common,
            } => totp_enroll(rotate, qrencode, common),
            Cmd::Run { common } => run(common).await,
            Cmd::User { config } => {
                init_logging();
                let Some(path) = config else {
                    return fail(&format!("need --config (or {CONFIG_ENV})"), 2);
                };
                match HostConfig::load(&path) {
                    Ok(c) => {
                        agent_auth_hostd::user::run(c).await;
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(&format!("invalid config {}: {e}", path.display()), 2),
                }
            }
            Cmd::Asuser { .. } => ExitCode::from(127),
        }
    })
}
