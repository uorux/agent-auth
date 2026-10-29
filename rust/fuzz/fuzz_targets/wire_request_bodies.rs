//! Every request body the broker parses, from arbitrary bytes: no input
//! panics, and a body that parses re-serializes to one that parses to the
//! same value.
#![no_main]

use agent_auth_wire::parse_body;
use libfuzzer_sys::fuzz_target;

macro_rules! each {
    ($data:expr; $($t:ty),* $(,)?) => {$(
        if let Ok(v) = parse_body::<$t>($data) {
            let again = serde_json::to_vec(&v).expect("a parsed body serializes");
            let back = parse_body::<$t>(&again).expect("a serialized body parses");
            assert_eq!(back, v, "{}", stringify!($t));
        }
    )*};
}

fuzz_target!(|data: &[u8]| {
    use agent_auth_wire::{a2a, admin, agent, chat, containment, daemon, hostexec, wiki};
    each!(data;
        agent::AttentionBody,
        agent::RequestCreate,
        agent::RetryBody,
        a2a::SessionCreate,
        a2a::ThreadOpenBody,
        a2a::ThreadMessageBody,
        a2a::ThreadCloseBody,
        wiki::PageWrite,
        wiki::PageDelete,
        containment::ContainBody,
        containment::LiftBody,
        hostexec::ShellExecBody,
        admin::AgentCreate,
        admin::AgentAttributesBody,
        admin::AgentRenameBody,
        admin::SetKindBody,
        admin::SetWebhookBody,
        admin::DecideBody,
        admin::PairingCodeCreate,
        admin::ArmBody,
        admin::LockdownBody,
        admin::UnlockBody,
        chat::ChatOpen,
        chat::ChatSend,
        chat::ChatClose,
        daemon::pairing::PairBody,
    );
    if let Ok(p) = parse_body::<admin::PairingCodeCreate>(data) {
        let _ = p.identity();
    }
});
