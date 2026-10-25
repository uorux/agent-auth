//! The kill switch (spec §10.7): revoke grants, disarm hosts, kill jobs and
//! shells, freeze (or stop) agent VMs; and lifting the broker's side of
//! it. A host's own lock is lifted only with its root-unlock code (or by root
//! on the host): nothing the broker says alone can (INV-26).

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_auth_core::AgentId;
use agent_auth_crypto::daemon::Role;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::daemons::{self, DaemonRole, DaemonRow};
use agent_auth_store::lockdown::{self as containment, ContainmentSource, NewEntry};
use agent_auth_store::{StoreError, flags, grants};
use agent_auth_wire::admin::{LockdownResult, LockdownScope, UnlockResult};
use serde_json::{Map, Value, json};

use super::{CALL_TIMEOUT, HostExec, HostExecError, SANDBOX_LOCKDOWN_TIMEOUT};
use crate::notify::Notify as _;
use crate::state::AppState;

fn role_of(row: &DaemonRow) -> Role {
    match row.role {
        DaemonRole::Host => Role::Host,
        DaemonRole::Sandbox => Role::Sandbox,
    }
}

fn scope_word(scope: LockdownScope) -> &'static str {
    match scope {
        LockdownScope::Sandboxes => "sandboxes",
        LockdownScope::All => "all",
        LockdownScope::Host => "host",
    }
}

/// `scope` "sandboxes": every agent VM's agents lose their grants, every
/// host disarms, kills its jobs and freezes its VM. "all": the grants of
/// every agent. "host": one host and its VM's agents.
pub async fn lockdown(
    st: &AppState,
    hostexec: &Arc<HostExec>,
    scope: LockdownScope,
    host: Option<&str>,
    kill_vm: bool,
    by: &str,
) -> Result<LockdownResult, HostExecError> {
    let host = host.map(str::to_owned);
    if scope == LockdownScope::Host && host.is_none() {
        return Err(HostExecError(
            "scope: all | sandboxes | host (with a host name)".into(),
        ));
    }
    let now = st.now();
    let internal = |e: StoreError| HostExecError(format!("lockdown: {e}"));
    let (daemon_rows, all_agents) = async {
        let tx = st.store.begin().await?;
        let previous = flags::get_for_update(&tx, flags::LOCKDOWN, &json!({}), now).await?;
        let mut hosts: Vec<String> = previous
            .get("hosts")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let add = if scope == LockdownScope::Host {
            host.clone().unwrap_or_default()
        } else {
            "*".to_owned()
        };
        if !hosts.contains(&add) {
            hosts.push(add);
        }
        hosts.sort();
        let at = agent_auth_wire::timestamp::format(now).unwrap_or_default();
        flags::set(
            &tx,
            flags::LOCKDOWN,
            &json!({"hosts": hosts, "by": by, "at": at, "scope": scope_word(scope)}),
            now,
        )
        .await?;
        let d = daemons::list(&tx).await?;
        let a = agents::list(&tx).await?;
        tx.commit().await?;
        Ok::<_, StoreError>((d, a))
    }
    .await
    .map_err(internal)?;
    let targets: Vec<DaemonRow> = daemon_rows
        .into_iter()
        .filter(|d| scope != LockdownScope::Host || Some(&d.name) == host.as_ref())
        .collect();
    let sandbox_ids: Vec<_> = targets
        .iter()
        .filter(|d| d.role == DaemonRole::Sandbox)
        .map(|d| d.id)
        .collect();
    let affected: Vec<AgentRow> = all_agents
        .into_iter()
        .filter(|a| {
            scope == LockdownScope::All || a.sandbox_id.is_some_and(|s| sandbox_ids.contains(&s))
        })
        .collect();

    // Held first (as containment does): a request approved while the
    // grants below are revoked finds the hold and gets nothing; the same
    // agents are refused new requests until it is lifted (review 2026-10).
    let r#match = match scope {
        LockdownScope::All => json!({}),
        LockdownScope::Sandboxes => json!({"placement": "sandbox"}),
        LockdownScope::Host => json!({"host": host}),
    };
    let reason = format!(
        "lockdown ({}{})",
        scope_word(scope),
        host.as_deref().map(|h| format!(" {h}")).unwrap_or_default()
    );
    let entry = record_entry(st, &r#match, &reason, by).await;
    if let Err(e) = &entry {
        tracing::error!(error = %e, "lockdown: containment entry not recorded");
    }

    // Stop what runs before tidying the records. Hosts and agent VMs are
    // told at once, each within its own timeout: a host never waits on a
    // VM (review 2026-10: one VM that stopped reading its connection held
    // every host back). A VM gets its held list (the entry above holds its
    // agents, as a containment does), then the lockdown; a host may freeze
    // the VM meanwhile, and the report says so.
    let hub = &hostexec.hub;
    let tell = |d: &DaemonRow, timeout| {
        let role = role_of(d);
        let name = d.name.clone();
        async move {
            let mut payload = Map::new();
            payload.insert("type".into(), json!("lockdown"));
            payload.insert("kill_vm".into(), json!(kill_vm));
            let r = hub.call(role, &name, payload, timeout).await;
            (role, name, r)
        }
    };
    let to_hosts = futures::future::join_all(
        targets
            .iter()
            .filter(|d| d.role != DaemonRole::Sandbox)
            .map(|d| tell(d, CALL_TIMEOUT)),
    );
    let to_sandboxes = async {
        tell_sandboxes(st).await;
        futures::future::join_all(
            targets
                .iter()
                .filter(|d| d.role == DaemonRole::Sandbox)
                .map(|d| tell(d, SANDBOX_LOCKDOWN_TIMEOUT)),
        )
        .await
    };
    let (hosts, sandboxes) = tokio::join!(to_hosts, to_sandboxes);
    let frozen: Vec<String> = hosts
        .iter()
        .filter(|(_, _, r)| {
            r.as_ref()
                .is_ok_and(|d| d.get("vm").is_some_and(|v| !v.is_null()))
        })
        .map(|(_, n, _)| n.clone())
        .collect();
    let mut reports = BTreeMap::new();
    for (role, name, r) in sandboxes.iter().chain(hosts.iter()) {
        let key = format!("{role}:{name}");
        let text = match r {
            Ok(data) => match data.get("vm").and_then(Value::as_str) {
                Some(vm) => format!(
                    "locked · vm {}",
                    agent_auth_core::pyfmt::escape_unprintable(
                        &vm.chars().take(200).collect::<String>()
                    )
                ),
                None => "locked".to_owned(),
            },
            Err(_) if *role == Role::Sandbox && frozen.contains(name) => {
                "did not answer; its VM is stopped by its host, and it is locked when it reconnects"
                    .to_owned()
            }
            Err(e) => format!("NOT reached ({e}); it is locked when it reconnects"),
        };
        reports.insert(key, text);
    }
    let unreached: Vec<&String> = reports
        .iter()
        .filter(|(_, t)| t.starts_with("NOT reached"))
        .map(|(k, _)| k)
        .collect();
    if !unreached.is_empty() {
        tracing::error!(
            ?unreached,
            "lockdown: daemons not reached; each is locked when it reconnects"
        );
    }

    // Revoke the affected agents' grants (falling back to expiring them
    // now, for the scheduler), orphan their inbound threads.
    let ids: Vec<AgentId> = affected.iter().map(|a| a.id).collect();
    let denied = match crate::service::deny_pending(st, &ids, &reason, by).await {
        Ok(n) => u32::try_from(n).unwrap_or(u32::MAX),
        Err(e) => {
            tracing::error!(error = %e, "lockdown: denying waiting requests failed");
            0
        }
    };
    let grant_ids = if ids.is_empty() {
        Vec::new()
    } else {
        async {
            let tx = st.store.begin().await?;
            let g = grants::active_of_agents(&tx, &ids).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(g)
        }
        .await
        .map_err(internal)?
    };
    let mut revoked = 0u32;
    for g in grant_ids {
        match crate::service::revoke_grant(st, g, "lockdown", by).await {
            Ok(_) => revoked = revoked.saturating_add(1),
            Err(e) => {
                tracing::warn!(grant = %g, error = %e, "lockdown: revoke failed; expiring now");
                let done = async {
                    let tx = st.store.begin().await?;
                    grants::expire_now(&tx, g, st.now()).await?;
                    tx.commit().await
                }
                .await;
                if let Err(e) = done {
                    tracing::error!(grant = %g, error = %e, "could not expire a grant at lockdown");
                }
            }
        }
    }
    let mut closed = 0u32;
    for a in affected.iter().filter(|a| a.sandbox_id.is_some()) {
        match crate::a2a::orphan_inbound(st, a.id).await {
            Ok(n) => closed = closed.saturating_add(u32::try_from(n).unwrap_or(u32::MAX)),
            Err(e) => tracing::error!(agent = %a.name, error = %e, "orphaning threads failed"),
        }
    }
    tracing::warn!(
        "LOCKDOWN ({}{}) by {by}: {revoked} grants revoked",
        scope_word(scope),
        host.as_deref().map(|h| format!(" {h}")).unwrap_or_default()
    );
    let out = LockdownResult {
        scope,
        host: host.clone(),
        daemons: reports,
        grants_revoked: revoked,
        requests_denied: denied,
        threads_closed: closed,
    };
    if let Ok(entry) = entry {
        {
            let mut event = serde_json::to_value(&out).unwrap_or_else(|_| json!({}));
            if let Value::Object(m) = &mut event {
                m.insert("id".into(), json!(entry));
                m.insert("match".into(), r#match.clone());
                m.insert("reason".into(), json!(reason));
                m.insert("by".into(), json!(by));
                m.insert("source".into(), json!("lockdown"));
                m.insert(
                    "agents".into(),
                    json!(affected.iter().map(|a| a.name.clone()).collect::<Vec<_>>()),
                );
            }
            st.notifier.contained(&event).await;
        }
    }
    Ok(out)
}

/// Tell every agent VM its held agents (the spine's `tell_sandboxes`
/// hook; nothing when agent VMs are not served).
async fn tell_sandboxes(st: &AppState) {
    if let Some(hook) = &st.spine.hooks.tell_sandboxes {
        let reports = hook(st.clone(), Vec::new()).await;
        tracing::info!(?reports, "agent VMs told their held agents");
    }
}

async fn record_entry(
    st: &AppState,
    r#match: &Value,
    reason: &str,
    by: &str,
) -> Result<String, String> {
    let id = crate::random::token_hex(4).map_err(|_| "no randomness".to_owned())?;
    let tx = st.store.begin().await.map_err(|e| e.to_string())?;
    let recorded = containment::record(
        &tx,
        &NewEntry {
            id: &id,
            r#match,
            reason,
            evidence: "",
            by,
            source: ContainmentSource::Lockdown,
            at: st.now(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(recorded.id)
}

/// Without a host: clear the broker's side (and tell sandboxes). With a
/// host and its root-unlock code: also unlock that host's hostd first (its
/// refusal aborts everything).
pub async fn unlock(
    st: &AppState,
    hostexec: &Arc<HostExec>,
    host: Option<&str>,
    totp: Option<&str>,
    by: &str,
) -> Result<UnlockResult, HostExecError> {
    let mut reports = BTreeMap::new();
    if let (Some(h), Some(code)) = (host, totp.filter(|c| !c.is_empty())) {
        hostexec
            .call(h, json!({"type": "unlock", "totp": code}), CALL_TIMEOUT)
            .await?;
        reports.insert(format!("host:{h}"), "unlocked".to_owned());
    }
    let now = st.now();
    let internal = |e: StoreError| HostExecError(format!("unlock: {e}"));
    let (sandboxes, still) = async {
        let tx = st.store.begin().await?;
        // The entries lockdown recorded first: the containment lock comes
        // before any row (the store's lock order); a containment made for
        // agents (not a lockdown) is lifted on its own.
        containment::lift_lockdown(&tx, host).await?;
        let flag = flags::get_for_update(&tx, flags::LOCKDOWN, &json!({}), now).await?;
        let mut hosts: Vec<String> = flag
            .get("hosts")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        match host {
            None => hosts.clear(),
            Some(h) => hosts.retain(|x| x != h),
        }
        if hosts.is_empty() {
            flags::delete(&tx, flags::LOCKDOWN).await?;
        } else {
            let mut updated = flag.as_object().cloned().unwrap_or_default();
            updated.insert("hosts".into(), json!(hosts));
            flags::set(&tx, flags::LOCKDOWN, &Value::Object(updated), now).await?;
        }
        let sandboxes = daemons::list_role(&tx, DaemonRole::Sandbox).await?;
        tx.commit().await?;
        Ok::<_, StoreError>((sandboxes, hosts))
    }
    .await
    .map_err(internal)?;
    // The entries just lifted: the VMs' held lists change too.
    tell_sandboxes(st).await;
    for d in sandboxes {
        // Only a VM the remaining flag no longer locks (`*` or its own name).
        let still_locked = still.iter().any(|h| h == "*" || *h == d.name);
        if host.is_none_or(|h| h == d.name) && !still_locked {
            let mut msg = Map::new();
            msg.insert("type".into(), json!("unlock"));
            if hostexec
                .hub
                .send_default(Role::Sandbox, &d.name, &msg)
                .await
            {
                reports.insert(format!("sandbox:{}", d.name), "unlocked".to_owned());
            }
        }
    }
    tracing::warn!("UNLOCK ({}) by {by}", host.unwrap_or("broker"));
    Ok(UnlockResult {
        host: host.map(str::to_owned),
        daemons: reports,
        broker_locked: still,
    })
}
