//! The policy file parser and validator on arbitrary text: never panics,
//! and a policy that loads evaluates without panicking.
#![no_main]

use agent_auth_core::authority::Authority;
use agent_auth_core::platform::Platform;
use agent_auth_core::policy::{AgentRef, Delegation, Policy, PolicyInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = agent_auth_core::policy::parse_yaml(text);
    let Ok(policy) = Policy::from_yaml(text) else {
        return;
    };
    let scope = serde_json::Map::new();
    for (platform, capability) in [
        (Platform::A2a, "talk"),
        (Platform::Kubernetes, "view"),
        (Platform::Models, "use"),
    ] {
        let Ok(authority) = Authority::from_wire(platform, capability, &scope) else {
            continue;
        };
        let input = PolicyInput {
            agent: AgentRef::named("claude-x"),
            delegation: Delegation::None,
            resource: "x",
            authority: &authority,
        };
        let decision = policy.evaluate(&input, &[], time::OffsetDateTime::UNIX_EPOCH);
        let _ = policy.cap_duration(decision.max_duration, Some(decision.max_duration));
    }
});
