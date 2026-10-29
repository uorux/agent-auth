#![forbid(unsafe_code)]
//! `agent-auth-server`: the broker. `agent-auth-server import-python
//! [--dry-run] <export.json>` carries a Python deployment's agents and host
//! pairings into a new database (`agent_auth_broker::import_python`).

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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let done = match args.split_first() {
        Some((cmd, rest)) if cmd == "import-python" => runtime
            .block_on(agent_auth_broker::import_python::main(&env, rest))
            .map(|summary| print!("{summary}")),
        _ => runtime.block_on(agent_auth_broker::server::run(env)),
    };
    match done {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            eprintln!("agent-auth-server: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
