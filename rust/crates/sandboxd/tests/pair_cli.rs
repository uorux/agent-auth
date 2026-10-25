//! INV-24: `pair` never takes the pairing code from argv (it would land in
//! shell history and process listings).
#![allow(clippy::unwrap_used)]

use std::process::Command;

#[test]
fn inv24_a_code_on_the_command_line_is_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_agent-auth-sandboxd"))
        .args(["pair", "ABCD-EFGH-IJKL"])
        .env_remove("AGENT_AUTH_SANDBOXD_PAIRING_CODE")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not accepted as an argument"), "{err}");
}

#[test]
fn the_other_binaries_start() {
    let out = Command::new(env!("CARGO_BIN_EXE_agent-auth-sandboxctl"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("secret-set"));
    // The hook with nothing to collect (no daemon) prints nothing.
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-auth-sandbox-mcp"))
        .arg("hook")
        .env("AGENT_AUTH_SANDBOX_SOCKET", "/nonexistent/agent.sock")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(br#"{"hook_event_name": "PostToolUse"}"#).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}
