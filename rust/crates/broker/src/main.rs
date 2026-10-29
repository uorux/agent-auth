#![forbid(unsafe_code)]
//! `agent-auth-server`: the broker.

use agent_auth_broker::config::Env;
use tracing_subscriber::EnvFilter;

fn main() -> std::process::ExitCode {
    let env = Env::load();
    let level = env.string("LOG_LEVEL", "INFO").to_lowercase();
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "starting the runtime failed");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(agent_auth_broker::server::run(env)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            eprintln!("agent-auth-server: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
