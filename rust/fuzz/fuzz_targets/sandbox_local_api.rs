//! sandboxd's local API from arbitrary bytes (sandboxd spec §4.12): the
//! line framing every local socket shares, then the agent's and the
//! operator's calls. No input panics; a call that parses names a known
//! method and keeps every string within its bound.
#![no_main]

use agent_auth_wire::daemon::local::{AgentCall, MAX_NAME, MAX_WHY, OperatorCall, parse_request};
use libfuzzer_sys::fuzz_target;

fn bounded(s: &str, max: usize) {
    assert!(s.chars().count() <= max);
}

fuzz_target!(|data: &[u8]| {
    let Ok(req) = parse_request(data) else {
        return;
    };
    if let Some(t) = &req.token {
        assert!(!t.is_null());
    }
    if let Ok(call) = AgentCall::parse(&req.method, &req.params) {
        assert_eq!(call.method(), req.method);
        match &call {
            AgentCall::ProjectCreate { name } | AgentCall::ProjectSeal { name } => {
                bounded(name, MAX_NAME);
                assert!(call.orchestrator_only());
            }
            AgentCall::AgentMint { runtime, project, why } => {
                bounded(runtime, MAX_NAME);
                bounded(project, MAX_NAME);
                bounded(why, MAX_WHY);
                assert!(call.orchestrator_only());
            }
            AgentCall::AgentSpawn { agent, .. } => {
                bounded(agent, MAX_NAME);
                assert!(call.orchestrator_only());
            }
            AgentCall::Whoami | AgentCall::ProjectList | AgentCall::Conversations
            | AgentCall::Inbox { .. } => assert!(!call.orchestrator_only()),
        }
    }
    if let Ok(call) = OperatorCall::parse(&req.method, &req.params) {
        match call {
            OperatorCall::SecretSet { name, .. } => bounded(&name, MAX_NAME),
            OperatorCall::Mint { runtime, project, why } => {
                bounded(&runtime, MAX_NAME);
                bounded(&project, MAX_NAME);
                assert!(!why.is_empty());
            }
            OperatorCall::Conversations { project: Some(p), .. } => {
                assert!(!p.is_empty());
                bounded(&p, MAX_NAME);
            }
            _ => {}
        }
    }
});
