#![forbid(unsafe_code)]
//! `agent-auth-sandboxctl`: the operator's CLI inside the agent VM (root).

use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let cli = agent_auth_sandboxd::ctl::Cli::parse();
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(agent_auth_sandboxd::ctl::main(cli)),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
