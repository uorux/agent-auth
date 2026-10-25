//! Reachability (a2a spec §3.2): one pure definition for the catalog, the
//! check route, the panel's peer list and the open itself, so they never
//! disagree. Keyed on `last_listen_at` (only the inbound surfaces record
//! it), not `last_seen_at`: an agent busy making requests is not thereby
//! reading its threads.

use agent_auth_core::containment::AgentKind;
use agent_auth_core::pyfmt::repr;
use agent_auth_store::agents::AgentRow;
use agent_auth_wire::a2a::{PeerEntry, Reach};
use agent_auth_wire::common::AgentKind as WireKind;
use agent_auth_wire::timestamp;
use time::{Duration, OffsetDateTime};

pub(crate) fn wire_kind(kind: AgentKind) -> WireKind {
    match kind {
        AgentKind::Service => WireKind::Service,
        AgentKind::Ephemeral => WireKind::Ephemeral,
        AgentKind::Operator => WireKind::Operator,
    }
}

/// Whether a thread opened to `agent` now has a chance of being answered.
/// `description` is left `None`; callers that show it fill it in.
#[must_use]
pub fn reachability(
    agent: &AgentRow,
    listen_threshold: Duration,
    now: OffsetDateTime,
) -> PeerEntry {
    let (addressable, reachable, why) = if agent.kind != AgentKind::Service {
        (false, false, Reach::Ephemeral)
    } else if agent.webhook_url.is_some() {
        (true, true, Reach::Webhook)
    } else {
        let listening = agent
            .last_listen_at
            .is_some_and(|l| now.saturating_sub(listen_threshold) <= l);
        (
            true,
            listening,
            if listening {
                Reach::Polling
            } else {
                Reach::Idle
            },
        )
    };
    PeerEntry {
        name: agent.name.clone(),
        description: None,
        kind: wire_kind(agent.kind),
        addressable,
        reachable,
        why,
        last_seen_at: agent.last_seen_at,
        last_listen_at: agent.last_listen_at,
        has_webhook: agent.webhook_url.is_some(),
    }
}

/// The caller-facing reason a peer will not answer (verbatim from the
/// Python; `'name'` is Python's repr).
#[must_use]
pub fn unreachable_detail(reach: &PeerEntry) -> String {
    let name = repr(&reach.name);
    if reach.why == Reach::Ephemeral {
        return format!(
            "{name} is ephemeral (initiate-only) and cannot receive threads; \
             it reaches out to you, not the other way around"
        );
    }
    let listened = reach
        .last_listen_at
        .and_then(|t| timestamp::format(t).ok())
        .unwrap_or_else(|| "never".to_owned());
    format!(
        "{name} is registered but not listening for threads (no webhook, last polled \
         {listened}); opening one now would sit unanswered until it times out. Pick a \
         peer that reports reachable, or retry once it is back — list_capabilities and \
         the a2a check both report peer reachability."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_auth_core::AgentId;
    use agent_auth_core::containment::Placement;

    fn agent(kind: AgentKind, webhook: bool, listen: Option<OffsetDateTime>) -> AgentRow {
        AgentRow {
            id: AgentId::new(),
            name: "svc-x".to_owned(),
            description: String::new(),
            key_id: String::new(),
            api_key_hash: String::new(),
            webhook_url: webhook.then(|| "https://h.test/x".to_owned()),
            webhook_secret: None,
            lldap_username: None,
            lldap_password_encrypted: None,
            disabled: false,
            kind,
            last_seen_at: None,
            last_listen_at: listen,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: None,
            project: None,
            host: None,
            placement: Placement::Host,
            lease_expires_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// a2a INV-21: a service agent without a webhook is reachable exactly
    /// while its last listen is within the threshold (inclusive).
    #[test]
    fn listening_window_is_inclusive() {
        let now = OffsetDateTime::now_utc();
        let t = Duration::seconds(300);
        let at = |secs| {
            reachability(
                &agent(
                    AgentKind::Service,
                    false,
                    Some(now - Duration::seconds(secs)),
                ),
                t,
                now,
            )
        };
        assert!(at(300).reachable && at(300).why == Reach::Polling);
        assert!(!at(301).reachable && at(301).why == Reach::Idle && at(301).addressable);
        let never = reachability(&agent(AgentKind::Service, false, None), t, now);
        assert!(!never.reachable);
        assert!(unreachable_detail(&never).contains("last polled never"));
        assert!(unreachable_detail(&never).starts_with("'svc-x' is registered but not listening"));
        let hook = reachability(&agent(AgentKind::Service, true, None), t, now);
        assert!(hook.reachable && hook.why == Reach::Webhook && hook.has_webhook);
        for kind in [AgentKind::Ephemeral, AgentKind::Operator] {
            let r = reachability(&agent(kind, false, Some(now)), t, now);
            assert!(!r.addressable && !r.reachable && r.why == Reach::Ephemeral);
            assert_eq!(
                unreachable_detail(&r),
                "'svc-x' is ephemeral (initiate-only) and cannot receive threads; it reaches out to you, not the other way around"
            );
        }
    }
}
