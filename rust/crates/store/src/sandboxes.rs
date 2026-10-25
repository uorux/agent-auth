//! Agent VMs, broker side: `pending_key_deliveries` (the one place a
//! minted agent's plaintext key can be recovered, encrypted, until its
//! sandbox daemon acknowledges it) and the disable cascade over minted
//! agents.

use std::fmt;

use agent_auth_core::{AgentId, DaemonId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::agents::DisableReason;
use crate::{StoreError, Tx};

/// A key waiting for its sandbox daemon, with the agent it is for.
/// `Debug` leaves out the ciphertext.
#[derive(Clone)]
pub struct PendingKey {
    pub id: Uuid,
    pub agent_id: AgentId,
    pub sandbox_id: DaemonId,
    /// Which key this is (sent with the key; the ack names it: sandboxd B-6).
    pub key_id: String,
    /// At-rest ciphertext of the full API key.
    pub key_encrypted: String,
    pub created_at: OffsetDateTime,
    pub agent_name: String,
    pub runtime: Option<String>,
    pub project: Option<String>,
}

impl fmt::Debug for PendingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingKey")
            .field("agent_id", &self.agent_id)
            .field("sandbox_id", &self.sandbox_id)
            .field("key_id", &self.key_id)
            .field("agent_name", &self.agent_name)
            .finish_non_exhaustive()
    }
}

/// Queue a key for the agent's sandbox, replacing any older pending key of
/// the agent.
pub async fn queue(
    tx: &Tx<'_>,
    id: Uuid,
    agent: AgentId,
    sandbox: DaemonId,
    key_id: &str,
    key_encrypted: &str,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "DELETE FROM pending_key_deliveries WHERE agent_id = $1",
        Uuid::from(agent)
    )
    .execute(&mut **c)
    .await?;
    sqlx::query!(
        "INSERT INTO pending_key_deliveries (id, agent_id, sandbox_id, key_id, key_encrypted, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
        id,
        Uuid::from(agent),
        Uuid::from(sandbox),
        key_id,
        key_encrypted,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// Keys waiting for one sandbox daemon.
pub async fn pending_for(tx: &Tx<'_>, sandbox: DaemonId) -> Result<Vec<PendingKey>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query!(
        "SELECT p.id, p.agent_id, p.sandbox_id, p.key_id, p.key_encrypted, p.created_at,
                a.name, a.runtime, a.project
         FROM pending_key_deliveries p JOIN agents a ON a.id = p.agent_id
         WHERE p.sandbox_id = $1
         ORDER BY p.created_at",
        Uuid::from(sandbox)
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out
        .into_iter()
        .map(|r| PendingKey {
            id: r.id,
            agent_id: AgentId::from_uuid(r.agent_id),
            sandbox_id: DaemonId::from_uuid(r.sandbox_id),
            key_id: r.key_id,
            key_encrypted: r.key_encrypted,
            created_at: r.created_at,
            agent_name: r.name,
            runtime: r.runtime,
            project: r.project,
        })
        .collect())
}

/// The sandbox `sandbox` acknowledged the key `key_id` of `agent`: delete
/// that delivery only (an ack from another daemon, or for an older key,
/// deletes nothing).
pub async fn ack(
    tx: &Tx<'_>,
    agent: AgentId,
    sandbox: DaemonId,
    key_id: &str,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "DELETE FROM pending_key_deliveries WHERE agent_id = $1 AND sandbox_id = $2 AND key_id = $3",
        Uuid::from(agent),
        Uuid::from(sandbox),
        key_id
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Disable an agent and everything minted under it (transitively): each
/// is disabled, its active grants expire now (the next expiry pass revokes
/// them through their provisioners), and its pending key is dropped.
/// `reason` is recorded on every agent of the tree; an agent already
/// disabled keeps its reason unless the operator disables it now (a lease
/// running out never turns an operator's disable into a renewable one).
/// Returns the names, sorted.
pub async fn disable_tree(
    tx: &Tx<'_>,
    root: AgentId,
    now: OffsetDateTime,
    reason: DisableReason,
) -> Result<Vec<String>, StoreError> {
    // Lock order: the containment lock (exclusive: waits for in-flight
    // checks), then agents in id order, then their grants in id order.
    crate::lockdown::lock_exclusive(tx).await?;
    let mut c = tx.conn().await;
    let tree = sqlx::query_scalar!(
        r#"WITH RECURSIVE tree AS (
               SELECT id FROM agents WHERE id = $1
               UNION
               SELECT a.id FROM agents a JOIN tree t ON a.parent_agent_id = t.id
           )
           SELECT a.id AS "id!" FROM agents a JOIN tree t ON t.id = a.id
           ORDER BY a.id FOR NO KEY UPDATE OF a"#,
        Uuid::from(root)
    )
    .fetch_all(&mut **c)
    .await?;
    let disabled = sqlx::query!(
        "UPDATE agents SET disabled = true,
             disabled_reason = CASE WHEN $2 = 'operator' THEN 'operator'
                                    WHEN disabled THEN COALESCE(disabled_reason, 'operator')
                                    ELSE $2 END
         WHERE id = ANY($1) RETURNING name",
        &tree,
        reason.as_str()
    )
    .fetch_all(&mut **c)
    .await?;
    sqlx::query!(
        "UPDATE grants SET expires_at = LEAST(expires_at, $2)
         WHERE id IN (SELECT id FROM grants WHERE agent_id = ANY($1) AND status = 'active'
                      ORDER BY id FOR NO KEY UPDATE)",
        &tree,
        now
    )
    .execute(&mut **c)
    .await?;
    sqlx::query!(
        "DELETE FROM pending_key_deliveries WHERE agent_id = ANY($1)",
        &tree
    )
    .execute(&mut **c)
    .await?;
    let mut names: Vec<String> = disabled.into_iter().map(|r| r.name).collect();
    names.sort();
    Ok(names)
}

/// An agent VM's agents that are not disabled yet (to disable them, with
/// what they minted, when the VM is unpaired: sandboxd B-10).
pub async fn enabled_in(tx: &Tx<'_>, sandbox: DaemonId) -> Result<Vec<AgentId>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT id FROM agents WHERE sandbox_id = $1 AND NOT disabled ORDER BY id",
        Uuid::from(sandbox)
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(AgentId::from_uuid).collect())
}

/// The project grants (active or being provisioned) of the agents of one
/// agent VM: what the VM is told on connect, so it revokes anything else.
pub async fn live_project_grants(
    tx: &Tx<'_>,
    sandbox: DaemonId,
) -> Result<Vec<agent_auth_core::GrantId>, StoreError> {
    let mut c = tx.conn().await;
    let ids = sqlx::query_scalar!(
        "SELECT g.id FROM grants g JOIN agents a ON a.id = g.agent_id
         WHERE g.platform = 'sandbox' AND g.status IN ('active', 'provisioning')
           AND a.sandbox_id = $1
         ORDER BY g.id",
        Uuid::from(sandbox)
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(ids
        .into_iter()
        .map(agent_auth_core::GrantId::from_uuid)
        .collect())
}
