//! Pool leases (platform `pool`): which grant holds which slot of which
//! item. Both limits are unique constraints (`(pool, item, slot)` for an
//! item's capacity, `(pool, agent_id, agent_slot)` for `max_per_agent`), so
//! no race passes them; [`lock_pool`] keeps concurrent provisions of one
//! pool from contending at all.

use agent_auth_core::{AgentId, GrantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{StoreError, Tx};

/// One lease held now, with its grant's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub item: String,
    pub slot: u32,
    pub agent_id: AgentId,
    pub agent_slot: u32,
    pub grant_id: GrantId,
    pub expires_at: OffsetDateTime,
}

/// A lease to take.
#[derive(Debug, Clone, Copy)]
pub struct NewLease<'a> {
    pub pool: &'a str,
    pub item: &'a str,
    pub slot: u32,
    pub agent_slot: u32,
    pub grant_id: GrantId,
    pub agent_id: AgentId,
    pub now: OffsetDateTime,
}

/// Advisory-lock class of pools (two-key form, its own key space): "pool".
const POOL_CLASS: i32 = 0x706f_6f6c;

/// Serialize the provisions of one pool until the transaction ends: the
/// read of the leases and the insert then see one another. Lock order:
/// after the grant being provisioned (level 4 in the crate docs). Revokes
/// do not take it (deleting a lease never waits for it).
pub async fn lock_pool(tx: &Tx<'_>, pool: &str) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "SELECT pg_advisory_xact_lock($1, hashtext($2))",
        POOL_CLASS,
        pool
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

fn to_u32(table_col: &str, v: i32) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::corrupt("pool_leases", table_col))
}

fn to_i32(v: u32) -> Result<i32, StoreError> {
    i32::try_from(v).map_err(|_| StoreError::OutOfRange(format!("slot {v}")))
}

/// The leases of `pool`, oldest first.
pub async fn leases(tx: &Tx<'_>, pool: &str) -> Result<Vec<LeaseRow>, StoreError> {
    let mut c = tx.conn().await;
    let rows = sqlx::query!(
        "SELECT l.item, l.slot, l.agent_id, l.agent_slot, l.grant_id, g.expires_at
         FROM pool_leases l JOIN grants g ON g.id = l.grant_id
         WHERE l.pool = $1
         ORDER BY l.created_at, l.id",
        pool
    )
    .fetch_all(&mut **c)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(LeaseRow {
                item: r.item,
                slot: to_u32("slot", r.slot)?,
                agent_id: AgentId::from_uuid(r.agent_id),
                agent_slot: to_u32("agent_slot", r.agent_slot)?,
                grant_id: GrantId::from_uuid(r.grant_id),
                expires_at: r.expires_at,
            })
        })
        .collect()
}

/// Drop the leases of `pool` whose grant has ended without its revoke
/// running (a lease must never outlive its grant; this keeps a missed one
/// from holding a slot forever). Returns how many went.
pub async fn clear_ended(tx: &Tx<'_>, pool: &str) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    let done = sqlx::query!(
        "DELETE FROM pool_leases l USING grants g
         WHERE l.grant_id = g.id AND l.pool = $1
           AND g.status NOT IN ('provisioning', 'active')",
        pool
    )
    .execute(&mut **c)
    .await?;
    Ok(done.rows_affected())
}

/// Take a lease. `false`: a unique constraint refused it (that slot of the
/// item, or that agent slot, is held, or the grant holds one already).
pub async fn take(tx: &Tx<'_>, lease: &NewLease<'_>) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let id = sqlx::query_scalar!(
        "INSERT INTO pool_leases (id, pool, item, slot, grant_id, agent_id, agent_slot, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT DO NOTHING
         RETURNING id",
        Uuid::new_v4(),
        lease.pool,
        lease.item,
        to_i32(lease.slot)?,
        Uuid::from(lease.grant_id),
        Uuid::from(lease.agent_id),
        to_i32(lease.agent_slot)?,
        lease.now,
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(id.is_some())
}

/// Give back a grant's lease (if any). Returns how many rows went.
pub async fn release(tx: &Tx<'_>, grant: GrantId) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    let done = sqlx::query!(
        "DELETE FROM pool_leases WHERE grant_id = $1",
        Uuid::from(grant)
    )
    .execute(&mut **c)
    .await?;
    Ok(done.rows_affected())
}

/// The item of `pool` this agent held most recently (any grant status),
/// leaving out grant `exclude`.
pub async fn last_held(
    tx: &Tx<'_>,
    agent: AgentId,
    pool: &str,
    exclude: Option<GrantId>,
) -> Result<Option<String>, StoreError> {
    let mut c = tx.conn().await;
    let item = sqlx::query_scalar!(
        r#"SELECT provisioner_state->>'item' AS "item!"
           FROM grants
           WHERE agent_id = $1 AND platform = 'pool' AND resource = $2
             AND ($3::uuid IS NULL OR id <> $3)
             AND jsonb_typeof(provisioner_state->'item') = 'string'
           ORDER BY granted_at DESC, id DESC
           LIMIT 1"#,
        Uuid::from(agent),
        pool,
        exclude.map(Uuid::from),
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(item)
}
