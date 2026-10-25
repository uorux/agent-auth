//! Approving, provisioning in two phases, and ending grants (spec §4.7-4.9).
//!
//! Phase one ([`begin_provision`]) runs inside the deciding transaction and
//! only writes rows: the request moves to PROVISIONING and the grant row is
//! inserted PROVISIONING (`store::grants::begin`, which needs a `NotHeld`
//! proof). Phase two ([`finish_provision`]) runs after that commit, in its
//! own transaction: containment again, the provisioner, then
//! `store::grants::activate` (another `NotHeld`). A crash between the two
//! leaves a PROVISIONING row for the reaper (INV-21).

use agent_auth_core::lifecycle::{CanMoveTo, state};
use agent_auth_core::{GrantId, GrantStatus, RequestId};
use agent_auth_store::grants::{self, GrantEnd, GrantRow};
use agent_auth_store::requests::{self, AnyRequest, Enter, ProvisionFailure, Request, RequestRow};
use agent_auth_store::{StoreError, Tx, lockdown};
use time::{Duration, OffsetDateTime};

use super::{ServiceError, ServiceResult};
use crate::notify::Notify;
use crate::provisioners::{Provisioner, not_enabled};
use crate::state::AppState;

pub(crate) const CONCURRENT: &str = "request changed state concurrently";

/// Move a request by compare-and-swap; a lost race is the Python's
/// `request changed state concurrently`.
pub(crate) async fn step<F, T>(
    tx: &Tx<'_>,
    request: Request<F>,
    data: T::Data,
    now: OffsetDateTime,
) -> ServiceResult<Request<T>>
where
    F: CanMoveTo<T>,
    T: Enter,
{
    requests::transition::<F, T>(tx, request, data, now)
        .await?
        .map_err(|_| ServiceError::transition(CONCURRENT))
}

/// Phase one, inside the deciding transaction: PROVISIONING, then (unless
/// the agent is held or the delegation is gone) the grant row. Returns the
/// grant to finish after commit.
pub(crate) async fn begin_provision(
    tx: &Tx<'_>,
    request: Request<state::Approved>,
    now: OffsetDateTime,
) -> ServiceResult<Option<GrantId>> {
    let request = step::<_, state::Provisioning>(tx, request, (), now).await?;
    let not_held = match lockdown::check(tx, request.agent_id(), now).await? {
        Ok(n) => n,
        Err(held) => {
            step::<_, state::ProvisionFailed>(
                tx,
                request,
                ProvisionFailure { why: held.text() },
                now,
            )
            .await?;
            return Ok(None);
        }
    };
    match grants::begin(tx, &request, &not_held, GrantId::new(), now).await? {
        Ok(grant) => Ok(Some(grant.grant().id)),
        Err(refused) => {
            step::<_, state::ProvisionFailed>(
                tx,
                request,
                ProvisionFailure {
                    why: refused.to_string(),
                },
                now,
            )
            .await?;
            Ok(None)
        }
    }
}

/// PROVISIONING → PROVISION_FAILED for the request of a grant, if it is
/// still there.
async fn fail_request(
    tx: &Tx<'_>,
    id: RequestId,
    why: &str,
    now: OffsetDateTime,
) -> ServiceResult<()> {
    if let Some(AnyRequest::Provisioning(r)) = requests::get(tx, id).await? {
        step::<_, state::ProvisionFailed>(
            tx,
            r,
            ProvisionFailure {
                why: why.to_owned(),
            },
            now,
        )
        .await?;
    }
    Ok(())
}

async fn grant_succeeded(tx: &Tx<'_>, id: RequestId, now: OffsetDateTime) -> ServiceResult<()> {
    if let Some(AnyRequest::Provisioning(r)) = requests::get(tx, id).await? {
        step::<_, state::Granted>(tx, r, (), now).await?;
    }
    Ok(())
}

/// Phase two, after the decision committed. Never fails its caller:
/// whatever goes wrong is recorded on the grant and request, or left for
/// the reaper.
pub(crate) async fn finish_provision(st: &AppState, grant_id: GrantId) {
    if let Err(e) = finish_inner(st, grant_id).await {
        tracing::error!(grant = %grant_id, error = %e, "finishing provisioning failed; the reaper will revert it");
    }
    // A containment (or disable) that landed while the provisioner ran
    // found no ACTIVE grant to revoke: this one is revoked here (INV-2).
    if let Err(e) = revoke_if_held(st, grant_id).await {
        tracing::error!(grant = %grant_id, error = %e, "revoking a held agent's new grant failed");
    }
}

async fn revoke_if_held(st: &AppState, grant_id: GrantId) -> ServiceResult<()> {
    let now = st.now();
    let held = {
        let tx = st.store.begin().await?;
        let Some(grant) = grants::get(&tx, grant_id).await? else {
            return Ok(());
        };
        if grant.status != GrantStatus::Active {
            return Ok(());
        }
        let held = lockdown::check(&tx, grant.agent_id, now).await?.err();
        tx.rollback().await?;
        held
    };
    if let Some(held) = held {
        match revoke_grant(st, grant_id, &held.text(), "containment").await {
            Ok(_) | Err(ServiceError::Transition(_)) => {}
            Err(e) => {
                // Retried by expiry: the grant's end moves to now.
                tracing::error!(grant = %grant_id, error = %e, "revoke failed; expiring it instead");
                let tx = st.store.begin().await?;
                grants::expire_now(&tx, grant_id, now).await?;
                tx.commit().await?;
            }
        }
    }
    Ok(())
}

async fn finish_inner(st: &AppState, grant_id: GrantId) -> ServiceResult<()> {
    let now = st.now();
    let tx = st.store.begin().await?;
    let Some(row) = grants::get(&tx, grant_id).await? else {
        return Ok(());
    };
    if row.status != GrantStatus::Provisioning {
        return Ok(());
    }
    // Lock order: containment and the agent, then the grant, then the
    // request.
    let held = lockdown::check(&tx, row.agent_id, now).await?;
    let Some(grant) = grants::load_provisioning(&tx, grant_id).await? else {
        return Ok(());
    };
    let not_held = match held {
        Ok(n) => n,
        Err(held) => {
            let why = held.text();
            let _ = grants::fail_provisioning(&tx, grant, &why, None).await?;
            fail_request(&tx, row.request_id, &why, now).await?;
            tx.commit().await?;
            notify_request(st, row.request_id);
            return Ok(());
        }
    };
    let Some(provisioner) = st.registry.get(row.platform) else {
        let why = not_enabled(row.platform);
        let _ = grants::fail_provisioning(&tx, grant, &why, None).await?;
        fail_request(&tx, row.request_id, &why, now).await?;
        tx.commit().await?;
        return Ok(());
    };
    match provisioner.provision(&tx, &grant, now).await {
        Err(e) => {
            let why = e.to_string();
            tracing::error!(request = %row.request_id, error = %why, "provisioning failed");
            let recorded = async {
                let _ = grants::fail_provisioning(&tx, grant, &why, None).await?;
                fail_request(&tx, row.request_id, &why, now).await
            }
            .await;
            match recorded {
                Ok(()) => tx.commit().await?,
                Err(e2) => {
                    // The provisioner's own writes broke the transaction:
                    // record the failure in a fresh one.
                    tracing::warn!(error = %e2, "recording the failure in a new transaction");
                    tx.rollback().await?;
                    let tx = st.store.begin().await?;
                    if let Some(grant) = grants::load_provisioning(&tx, grant_id).await? {
                        let _ = grants::fail_provisioning(&tx, grant, &why, None).await?;
                    }
                    fail_request(&tx, row.request_id, &why, now).await?;
                    tx.commit().await?;
                }
            }
        }
        Ok(provisioner_state) => {
            let snapshot = grant.grant().clone();
            match grants::activate(&tx, grant, &not_held, &provisioner_state).await? {
                Ok(_) => {
                    grant_succeeded(&tx, row.request_id, now).await?;
                    tx.commit().await?;
                }
                Err(_) => {
                    // Ended while the provisioner ran: undo what it did.
                    tracing::warn!(grant = %grant_id, "grant ended while it was provisioned; reverting");
                    if let Err(e) = provisioner.revoke(&tx, &snapshot, now).await {
                        tracing::error!(grant = %grant_id, error = %e, "reverting failed");
                    }
                    tx.commit().await?;
                }
            }
        }
    }
    Ok(())
}

fn notify_request(st: &AppState, id: RequestId) {
    st.request_events.notify(&id);
}

/// The reaper (spec §4.8): PROVISIONING grants older than `max_age` (zero
/// at boot: the broker is one process, so nothing is in flight then) are
/// reverted through their provisioner and failed. A revert that fails
/// leaves the row for the next tick. Returns how many were reaped.
pub async fn reap_stale_provisioning(st: &AppState, max_age: Duration) -> usize {
    let now = st.now();
    let stale = async {
        let tx = st.store.begin().await?;
        grants::stale_provisioning(&tx, now.saturating_sub(max_age)).await
    }
    .await;
    let stale = match stale {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "listing stale provisioning failed");
            return 0;
        }
    };
    let mut reaped = 0usize;
    for id in stale {
        match reap_one(st, id, now).await {
            Ok(Some(request)) => {
                reaped = reaped.saturating_add(1);
                tracing::warn!(grant = %id, "reaped interrupted provisioning");
                notify_request(st, request);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(grant = %id, error = %e, "failed to reap stale provisioning; will retry");
            }
        }
    }
    reaped
}

async fn reap_one(
    st: &AppState,
    id: GrantId,
    now: OffsetDateTime,
) -> ServiceResult<Option<RequestId>> {
    let tx = st.store.begin().await?;
    let Some(grant) = grants::load_provisioning(&tx, id).await? else {
        return Ok(None);
    };
    let request_id = grant.grant().request_id;
    let platform = grant.grant().platform;
    let provisioner = st
        .registry
        .get(platform)
        .ok_or(ServiceError::NotEnabled(platform))?;
    provisioner.revoke(&tx, grant.grant(), now).await?;
    if grants::fail_provisioning(
        &tx,
        grant,
        "provisioning interrupted; external state reverted",
        Some(now),
    )
    .await?
    .is_err()
    {
        return Ok(None);
    }
    fail_request(
        &tx,
        request_id,
        "interrupted (broker restarted mid-provision)",
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(request_id))
}

async fn request_row(st: &AppState, id: RequestId) -> Result<Option<RequestRow>, StoreError> {
    let tx = st.store.begin().await?;
    Ok(requests::get(&tx, id).await?.map(AnyRequest::into_row))
}

/// After a grant ended: wake the request's long-polls, update its card.
async fn grant_ended(st: &AppState, grant: &GrantRow) {
    notify_request(st, grant.request_id);
    match request_row(st, grant.request_id).await {
        Ok(Some(request)) => st.notifier.update_grant_ended(&request, grant).await,
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "loading the request of an ended grant"),
    }
}

/// End an ACTIVE grant through its provisioner (spec §4.9). The
/// provisioner's error leaves the grant active and is returned.
pub async fn revoke_grant(
    st: &AppState,
    grant_id: GrantId,
    reason: &str,
    revoked_by: &str,
) -> ServiceResult<GrantRow> {
    let now = st.now();
    let tx = st.store.begin().await?;
    let grant = match grants::get_for_update(&tx, grant_id).await? {
        Some(g) if g.status == GrantStatus::Active => g,
        _ => return Err(ServiceError::transition("grant is not active")),
    };
    let provisioner = st
        .registry
        .get(grant.platform)
        .ok_or(ServiceError::NotEnabled(grant.platform))?;
    provisioner.revoke(&tx, &grant, now).await?;
    let reason = if revoked_by.is_empty() {
        reason.to_owned()
    } else {
        format!("{reason} ({revoked_by})")
    };
    let ended = grants::end(&tx, grant_id, GrantEnd::Revoked { reason }, now)
        .await?
        .map_err(|_| ServiceError::transition("grant is not active"))?;
    tx.commit().await?;
    grant_ended(st, &ended).await;
    Ok(ended)
}

async fn expire_one(st: &AppState, id: GrantId) -> ServiceResult<Option<GrantRow>> {
    let now = st.now();
    let tx = st.store.begin().await?;
    let grant = match grants::get_for_update(&tx, id).await? {
        Some(g) if g.status == GrantStatus::Active && g.expires_at <= now => g,
        _ => return Ok(None),
    };
    let provisioner = st
        .registry
        .get(grant.platform)
        .ok_or(ServiceError::NotEnabled(grant.platform))?;
    provisioner.revoke(&tx, &grant, now).await?;
    let ended = grants::end(&tx, id, GrantEnd::Expired, now).await?.ok();
    tx.commit().await?;
    Ok(ended)
}

/// One expiry pass: every ACTIVE grant past its end is revoked through its
/// provisioner and marked EXPIRED. Failures stay ACTIVE for the next pass.
pub async fn expire_due_grants(st: &AppState) -> usize {
    let now = st.now();
    let due = async {
        let tx = st.store.begin().await?;
        grants::due(&tx, now).await
    }
    .await;
    let due = match due {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "listing due grants failed");
            return 0;
        }
    };
    let mut expired = 0usize;
    for id in due {
        match expire_one(st, id).await {
            Ok(Some(grant)) => {
                expired = expired.saturating_add(1);
                grant_ended(st, &grant).await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(grant = %id, error = %e, "failed to expire grant; will retry")
            }
        }
    }
    expired
}

/// Delegated grants die with their thread (INV-12): every ACTIVE grant
/// whose delegation thread is closed is revoked.
pub async fn revoke_delegated_for_closed_threads(st: &AppState) -> usize {
    let rows = async {
        let tx = st.store.begin().await?;
        grants::delegated_on_closed_threads(&tx).await
    }
    .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "listing delegated grants of closed threads failed");
            return 0;
        }
    };
    let mut revoked = 0usize;
    for (id, close_reason) in rows {
        let reason = format!(
            "delegation thread closed ({})",
            close_reason.as_deref().unwrap_or("closed")
        );
        match revoke_grant(st, id, &reason, "scheduler").await {
            Ok(_) => revoked = revoked.saturating_add(1),
            Err(ServiceError::Transition(_)) => {}
            Err(e) => {
                tracing::error!(grant = %id, error = %e, "failed to revoke delegated grant; will retry")
            }
        }
    }
    revoked
}
