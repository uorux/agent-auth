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

/// `fs.protected_hardlinks`: without it a project could hard-link files it
/// cannot write into its tree, and root's ownership and ACL changes there
/// would reach them.
pub const PROTECTED_HARDLINKS: &str = "/proc/sys/fs/protected_hardlinks";

/// Whether the sysctl file at `path` says 1.
#[must_use]
pub fn protected_hardlinks_on(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|v| v.trim() == "1")
}

/// The runtime directories, created with their modes set through a handle
/// on each (never by path after the fact) before any socket is bound:
/// `runtime_dir` 0711 (root's: the operator socket, the env files under
/// `env/` 0700), and the agent socket's directory 0755 (every agent unit
/// reaches the socket, which checks each caller).
pub fn prepare_runtime_dirs(config: &Config) -> std::io::Result<()> {
    fn ensure(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt as _;
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("no parent directory"))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| std::io::Error::other("not a directory name"))?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(parent)?;
        let dir = fsops::Dir::open_trusted(parent)?.ensure_child(name, mode)?;
        dir.set_owner_mode(None, mode)
    }
    ensure(&config.runtime_dir, 0o711)?;
    ensure(&config.runtime_dir.join("env"), 0o700)?;
    if let Some(agent_dir) = config.agent_socket.parent() {
        ensure(agent_dir, 0o755)?;
    }
    Ok(())
}

/// Run sandboxd until SIGTERM/SIGINT: the broker channel, the agent socket
/// (0666; each call checks its caller) and the operator socket (0600,
/// root only).
pub async fn run(config: Config) -> anyhow::Result<()> {
    if !protected_hardlinks_on(std::path::Path::new(PROTECTED_HARDLINKS)) {
        anyhow::bail!(
            "fs.protected_hardlinks is not 1: refusing to run (a project could hard-link files \
             it cannot write into its own tree)"
        );
    }
    prepare_runtime_dirs(&config)?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn runtime_dirs_get_their_modes_and_hardlinks_must_be_protected() {
        let d = crate::testdir::TestDir::new("rundirs");
        let key = crate::config::tests::key();
        let cfg = Config::from_json(
            &serde_json::json!({"broker_url": "https://b.example", "broker_public_key": key,
                "name": "excelsior", "runtime_dir": d.path().join("run"),
                "agent_socket": d.path().join("agent/agent.sock")})
            .to_string(),
        )
        .unwrap();
        // An existing directory with a wider mode is narrowed.
        std::fs::create_dir_all(d.path().join("run")).unwrap();
        std::fs::set_permissions(d.path().join("run"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        prepare_runtime_dirs(&cfg).unwrap();
        let mode = |p: &str| {
            std::fs::metadata(d.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("run"), 0o711);
        assert_eq!(mode("run/env"), 0o700);
        assert_eq!(mode("agent"), 0o755);
        // A symlink in place of the runtime directory is refused.
        std::fs::remove_dir_all(d.path().join("run")).unwrap();
        std::os::unix::fs::symlink("/tmp", d.path().join("run")).unwrap();
        assert!(prepare_runtime_dirs(&cfg).is_err());
        std::fs::write(d.path().join("on"), "1\n").unwrap();
        std::fs::write(d.path().join("off"), "0\n").unwrap();
        assert!(protected_hardlinks_on(&d.path().join("on")));
        assert!(!protected_hardlinks_on(&d.path().join("off")));
        assert!(!protected_hardlinks_on(&d.path().join("missing")));
    }
}
