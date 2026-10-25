#![forbid(unsafe_code)]
//! hostd: the per-host daemon that decides what runs on its host for the
//! broker (daemons-hostd spec §7-§13), and hostctl, its local control.
//!
//! - [`daemon::Hostd`]: state, the broker messages, the journal.
//! - [`config`]: the host's config file and local policy.
//! - [`totp_store`]: the four TOTP secrets and their state.
//! - [`executor`]: how jobs run (systemd units on Linux, process groups
//!   on macOS, a direct test double).
//! - [`ctl`]: the hostctl socket; [`desk`]: the desktop helper's socket;
//!   [`user`]: the desktop helper itself.
//! - [`spool`]: results kept until the broker acknowledges them.
//!
//! The decisions themselves are `agent_auth_core::hostd` (pure, model
//! checked).

pub mod config;
pub mod ctl;
pub mod daemon;
pub mod desk;
pub mod executor;
pub mod fsutil;
pub mod peers;
pub mod presence;
pub mod spool;
pub mod totp_store;
pub mod user;

use std::sync::Arc;

use agent_auth_crypto::daemon::{DaemonId, Role, load_or_create_key};
use agent_auth_daemon::channel::{Channel, Identity};

use crate::config::HostConfig;
use crate::daemon::{Hostd, VERSION};
use crate::executor::Executor;

/// This process's effective uid, without libc: `/proc/self/status` on
/// Linux, `id -u` elsewhere. `u32::MAX` if it can't be told (never root).
#[must_use]
pub fn effective_uid() -> u32 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                return rest
                    .split_whitespace()
                    .nth(1)
                    .and_then(|u| u.parse().ok())
                    .unwrap_or(u32::MAX);
            }
        }
    }
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(u32::MAX)
}

/// The channel identity of this host (creating its key on first use).
pub fn identity(config: &HostConfig) -> anyhow::Result<Identity> {
    let key = load_or_create_key(&config.key_path())?;
    Ok(Identity::new(
        DaemonId::new(Role::Host, config.name.clone()),
        key,
        config.broker_url.clone(),
        config.broker_public_key,
    ))
}

/// Run hostd until SIGTERM/SIGINT: the broker channel, the local sockets,
/// result resending and the VM watcher. Running jobs are killed on the way
/// out (their results say hostd stopped).
pub async fn run<E: Executor>(config: HostConfig, executor: E) -> anyhow::Result<()> {
    let tls = Arc::new(agent_auth_tls::default_client_config()?);
    let identity = identity(&config)?;
    let channel = Channel::new(identity, VERSION, tls);
    let ctl_path = config.ctl_socket();
    let user_path = config.user_socket();
    let serve_ctl = config.privileged() || config.desktop.enable;
    let desktop = config.desktop.enable;
    let hostd = Hostd::new(config, executor);
    hostd.attach(channel.clone());
    hostd.recover().await;
    let mut tasks = tokio::task::JoinSet::new();
    if serve_ctl {
        let listener = agent_auth_daemon::localsock::bind(&ctl_path, 0o666)?;
        tasks.spawn(agent_auth_daemon::localsock::serve_with(
            listener,
            Arc::new(ctl::Ctl(Arc::clone(&hostd))),
            agent_auth_daemon::localsock::Limits::control(),
        ));
    }
    if desktop {
        // Anyone may connect; only the configured user is listened to.
        let listener = agent_auth_daemon::localsock::bind(&user_path, 0o666)?;
        tasks.spawn(desk::serve(listener, Arc::clone(&hostd)));
    }
    {
        let h = Arc::clone(&hostd);
        tasks.spawn(async move { h.resend_loop().await });
        let h = Arc::clone(&hostd);
        tasks.spawn(async move { h.watch_vm().await });
        let h = Arc::clone(&hostd);
        let c = channel.clone();
        tasks.spawn(async move { c.run(h).await });
    }
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("stopping");
    hostd.shutdown().await;
    tasks.abort_all();
    Ok(())
}
