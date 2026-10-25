//! The periodic ticks (core-lifecycle-policy §8.4).
//!
//! Each tick, in order, every step's failures logged and the tick going on:
//! 1. reap PROVISIONING grants (any age on the first tick after boot, then
//!    older than 15 minutes);
//! 2. expire grants past their end, then revoke any active grant of an
//!    agent a containment holds;
//! 3. LLM evaluations lost by a restart or stalled (core B-3): at boot
//!    every LLM_EVALUATING request, later those untouched for 15 minutes;
//! 4. the a2a sweep (when a2a is on), then revoke delegated grants of closed threads;
//! 5. minted agents past their lease: disabled with their descendants
//!    (their grants then expire on the next tick);
//! 6. the hostexec and agent-VM hooks.
//!
//! The first tick ([`boot`]) runs to completion before the HTTP listener
//! and the Discord bot start (catch-up for what lapsed while down).

use std::time::Duration as StdDuration;

use agent_auth_store::{agents, requests, sandboxes};
use time::Duration;
use tokio::sync::watch;

use crate::service;
use crate::state::AppState;

/// Between ticks.
pub const INTERVAL: StdDuration = StdDuration::from_secs(30);
/// A PROVISIONING grant older than this was interrupted.
pub const REAP_AGE: Duration = Duration::minutes(15);
/// An LLM evaluation untouched this long was lost.
pub const LLM_STALL: Duration = Duration::minutes(15);

/// What one tick did (for tests and logs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    pub reaped: usize,
    pub expired: usize,
    /// Active grants of held agents revoked (containment's backstop).
    pub held_revoked: usize,
    pub llm_resumed: usize,
    pub delegated_revoked: usize,
    pub leases_ended: usize,
}

/// One tick. `boot`: the first one after startup.
pub async fn tick(st: &AppState, boot: bool) -> TickReport {
    let mut report = TickReport {
        reaped: service::reap_stale_provisioning(st, if boot { Duration::ZERO } else { REAP_AGE })
            .await,
        expired: service::expire_due_grants(st).await,
        held_revoked: crate::containment::sweep_held(st).await,
        ..TickReport::default()
    };
    report.llm_resumed = resume_llm(st, boot).await;
    if st.a2a.config.enabled {
        match crate::a2a::sweep(st, st.now()).await {
            Ok(counts) => {
                if counts != crate::a2a::SweepCounts::default() {
                    tracing::info!(?counts, "a2a sweep");
                }
            }
            Err(e) => tracing::error!(error = %e, "a2a sweep failed"),
        }
    }
    report.delegated_revoked = service::revoke_delegated_for_closed_threads(st).await;
    report.leases_ended = sweep_leases(st).await;
    if let Some(hook) = &st.spine.hooks.hostexec_tick {
        hook(st.clone()).await;
    }
    if let Some(hook) = &st.spine.hooks.sandboxes_tick {
        hook(st.clone()).await;
    }
    report
}

async fn resume_llm(st: &AppState, boot: bool) -> usize {
    let cutoff = if boot {
        st.now()
    } else {
        st.now().saturating_sub(LLM_STALL)
    };
    let ids = async {
        let tx = st.store.begin().await?;
        requests::stale_llm_evaluating(&tx, cutoff).await
    }
    .await;
    match ids {
        Ok(ids) => {
            let n = ids.len();
            if n > 0 {
                tracing::warn!(n, "resuming LLM evaluations lost or stalled");
                if let Err(e) = service::resume(st, &ids).await {
                    tracing::error!(error = %e, "resuming LLM evaluations failed");
                }
            }
            n
        }
        Err(e) => {
            tracing::error!(error = %e, "listing stalled LLM evaluations failed");
            0
        }
    }
}

/// Minted agents past their lease are disabled, with their descendants.
pub async fn sweep_leases(st: &AppState) -> usize {
    let swept = async {
        let now = st.now();
        let tx = st.store.begin().await?;
        let mut disabled = Vec::new();
        for id in agents::lease_expired(&tx, now).await? {
            disabled.extend(
                sandboxes::disable_tree(
                    &tx,
                    id,
                    now,
                    agent_auth_store::agents::DisableReason::Lease,
                )
                .await?,
            );
        }
        tx.commit().await?;
        Ok::<_, agent_auth_store::StoreError>(disabled)
    }
    .await;
    match swept {
        Ok(names) => {
            if !names.is_empty() {
                tracing::info!("lease expired: disabled {}", names.join(", "));
                after_disable(st, &names).await;
            }
            names.len()
        }
        Err(e) => {
            tracing::error!(error = %e, "lease sweep failed");
            0
        }
    }
}

/// After agents were disabled (committed): their a2a threads end (a2a B7).
pub async fn after_disable(st: &AppState, names: &[String]) {
    for name in names {
        let found = async {
            let tx = st.store.begin().await?;
            agents::by_name(&tx, name).await
        }
        .await;
        match found {
            Ok(Some(a)) => {
                if let Err(e) = crate::a2a::on_agent_disabled(st, a.id).await {
                    tracing::error!(agent = %name, error = %e, "closing a disabled agent's threads failed");
                }
            }
            Ok(None) => {}
            Err(e) => tracing::error!(agent = %name, error = %e, "loading a disabled agent failed"),
        }
    }
}

/// The first tick, run to completion before anything else starts (the
/// HTTP listener, the Discord bot): catch-up for what lapsed while down.
pub async fn boot(st: &AppState) {
    let report = tick(st, true).await;
    tracing::info!(?report, "scheduler boot tick");
}

/// After [`boot`]: tick every [`INTERVAL`] until `stop` turns true.
pub async fn run(st: AppState, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(INTERVAL) => {}
            _ = stop.changed() => return,
        }
        if *stop.borrow() {
            return;
        }
        let report = tick(&st, false).await;
        if report != TickReport::default() {
            tracing::info!(?report, "scheduler tick");
        }
    }
}
