#![forbid(unsafe_code)]
//! sandboxd: the daemon inside an agent VM (sandboxd spec §4), and its
//! two clients, sandboxctl (the operator's) and the sandbox MCP server
//! (the agents').
//!
//! - [`daemon::Sandboxd`]: keys, projects, conversations, routing, holds.
//! - [`store`]: its state, local to the VM (file-backed, atomic writes).
//! - [`host`]: users, directories, ACLs and units ([`host::LinuxHost`]);
//!   [`fsops`]: root's file operations that never follow a path an agent
//!   controls.
//! - [`runtime`]: claude and codex.
//! - [`api`]: the agent and operator sockets; [`mcp`] and [`ctl`]: their
//!   clients.
//!
//! The hold decisions (lockdown and containment, what to freeze and when
//! to thaw) are `agent_auth_core::sandbox` (pure, model checked).

pub mod api;
pub mod config;
pub mod ctl;
pub mod daemon;
pub mod fsops;
pub mod host;
pub mod mcp;
pub mod names;
pub mod runtime;
pub mod store;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
pub(crate) mod testdir;

use std::sync::Arc;

use agent_auth_crypto::daemon::{DaemonId, Role, load_or_create_key};
use agent_auth_daemon::channel::{Channel, Identity};

use crate::config::Config;
use crate::daemon::Sandboxd;
use crate::host::LinuxHost;

/// The agent socket's environment variable (clients).
pub const AGENT_SOCKET_ENV: &str = "AGENT_AUTH_SANDBOX_SOCKET";
/// The conversation token's environment variable (clients).
pub const TOKEN_ENV: &str = "AGENT_AUTH_SANDBOX_TOKEN";
/// The operator socket override (clients).
pub const OPERATOR_SOCKET_ENV: &str = "AGENT_AUTH_SANDBOXD_OPERATOR";
pub const DEFAULT_AGENT_SOCKET: &str = "/run/sandboxd-agent/agent.sock";
pub const DEFAULT_OPERATOR_SOCKET: &str = "/run/sandboxd/operator.sock";

/// This process's effective uid, without libc: `/proc/self/status`.
/// `u32::MAX` if it can't be told (never root).
#[must_use]
pub fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().nth(1))
                    .and_then(|u| u.parse().ok())
            })
        })
        .unwrap_or(u32::MAX)
}

/// The channel identity of this VM (creating its key on first use).
pub fn identity(config: &Config) -> anyhow::Result<Identity> {
    let key = load_or_create_key(&config.key_path())?;
    Ok(Identity::new(
        DaemonId::new(Role::Sandbox, config.name.clone()),
        key,
        config.broker_url.clone(),
        config.broker_public_key,
    ))
}

/// Run sandboxd until SIGTERM/SIGINT: the broker channel, the agent socket
/// (0666; each call checks its caller) and the operator socket (0600,
/// root only).
pub async fn run(config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let tls = Arc::new(agent_auth_tls::default_client_config()?);
    let identity = identity(&config)?;
    let channel = Channel::new(identity, daemon::VERSION, tls);
    let sbx = Sandboxd::new(Arc::clone(&config), LinuxHost::new(Arc::clone(&config)))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let agent_listener = agent_auth_daemon::localsock::bind(&config.agent_socket, 0o666)?;
    let operator_listener = agent_auth_daemon::localsock::bind(&config.operator_socket(), 0o600)?;
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(agent_auth_daemon::localsock::serve(
        agent_listener,
        Arc::new(api::AgentApi(Arc::clone(&sbx))),
    ));
    tasks.spawn(agent_auth_daemon::localsock::serve(
        operator_listener,
        Arc::new(api::OperatorApi(Arc::clone(&sbx))),
    ));
    {
        let sbx = Arc::clone(&sbx);
        tasks.spawn(async move {
            if let Err(e) = sbx.run(channel).await {
                tracing::error!("sandboxd stopped: {e}");
            }
        });
    }
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = tasks.join_next() => {}
    }
    tracing::info!("stopping");
    sbx.shutdown().await;
    tasks.abort_all();
    Ok(())
}
