#![forbid(unsafe_code)]
//! `agent-auth`: see the library crate.

use std::io::IsTerminal;
use std::process::ExitCode;

use agent_auth_cli::{Cli, Io, run};
use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let color = err.is_terminal();
    let stdout_tty = out.is_terminal();
    let mut prompt = |text: &str| rpassword::prompt_password(text);
    let env = |name: &str| std::env::var(name).ok();
    let mut io = Io {
        out: &mut out,
        err: &mut err,
        color,
        stdout_tty,
        prompt: &mut prompt,
        config: agent_auth_client::Config::from_env(),
        env: &env,
    };
    ExitCode::from(run(cli, &mut io).await)
}
