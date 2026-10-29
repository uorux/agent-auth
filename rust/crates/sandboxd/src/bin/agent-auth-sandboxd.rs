#![forbid(unsafe_code)]
//! `agent-auth-sandboxd`: run the agent VM's daemon, or pair it with the
//! broker (sandboxd spec §4.1).

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;

use agent_auth_sandboxd::config::{CONFIG_ENV, Config};
use clap::{Parser, Subcommand};

const PAIRING_CODE_ENV: &str = "AGENT_AUTH_SANDBOXD_PAIRING_CODE";

#[derive(Parser, Debug)]
#[command(
    name = "agent-auth-sandboxd",
    about = "agent-auth sandbox daemon (agent VM)"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// The daemon (the systemd service's entry point).
    Run {
        #[arg(long, env = CONFIG_ENV)]
        config: Option<PathBuf>,
    },
    /// Pair this agent VM with the broker (code from `agent-auth admin
    /// daemon-pair --role sandbox <host>`). `-` reads the code from stdin;
    /// otherwise AGENT_AUTH_SANDBOXD_PAIRING_CODE or a prompt. Never argv.
    Pair {
        #[arg(value_name = "-")]
        source: Option<String>,
        #[arg(long, env = CONFIG_ENV)]
        config: Option<PathBuf>,
    },
}

fn fail(msg: &str, code: u8) -> ExitCode {
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[31m{msg}\x1b[0m");
    } else {
        eprintln!("{msg}");
    }
    ExitCode::from(code)
}

fn load(path: Option<PathBuf>) -> Result<Config, ExitCode> {
    let path = Config::path(path);
    Config::load(&path).map_err(|e| fail(&format!("invalid config {}: {e}", path.display()), 2))
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

async fn pair(source: Option<String>, config: Option<PathBuf>) -> ExitCode {
    if source.as_deref().is_some_and(|s| s != "-") {
        return fail(
            "the pairing code is not accepted as an argument; enter it at the prompt",
            2,
        );
    }
    let cfg = match load(config) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let code = if source.as_deref() == Some("-") {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        line
    } else {
        match std::env::var(PAIRING_CODE_ENV)
            .ok()
            .filter(|c| !c.is_empty())
        {
            Some(c) => c,
            None => read_hidden("pairing code"),
        }
    };
    let code = code.trim().to_owned();
    let ident = match agent_auth_sandboxd::identity(&cfg) {
        Ok(i) => i,
        Err(e) => return fail(&e.to_string(), 1),
    };
    let tls = match agent_auth_tls::default_client_config() {
        Ok(t) => Arc::new(t),
        Err(e) => return fail(&e.to_string(), 1),
    };
    if let Err(e) = agent_auth_daemon::pair::pair(&ident, &code, tls).await {
        return fail(&e.to_string(), 1);
    }
    println!("paired as {}", ident.principal());
    println!("  this VM's key: {}", ident.public_key().fingerprint());
    println!("  broker key:    {}", cfg.broker_public_key.fingerprint());
    println!("Restart agent-auth-sandboxd; the broker then delivers the orchestrator's key.");
    ExitCode::SUCCESS
}

fn init_logging() {
    let filter = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_owned());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter.to_lowercase()))
        .with_target(true)
        .try_init();
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string(), 1),
    };
    runtime.block_on(async move {
        match cli.command {
            Cmd::Run { config } => {
                init_logging();
                let cfg = match load(config) {
                    Ok(c) => c,
                    Err(e) => return e,
                };
                if agent_auth_sandboxd::effective_uid() != 0 {
                    tracing::error!("sandboxd is not root: it cannot create users or start units");
                }
                match agent_auth_sandboxd::run(cfg).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(&e.to_string(), 1),
                }
            }
            Cmd::Pair { source, config } => pair(source, config).await,
        }
    })
}
