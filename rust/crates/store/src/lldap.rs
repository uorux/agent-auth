//! LLDAP accounts on agent rows (provisioners spec §3.4).

use agent_auth_core::AgentId;
use uuid::Uuid;

use crate::{StoreError, Tx};

/// Agents other than `except` whose LLDAP account is `username`, compared
/// case-insensitively (LLDAP user ids are): `(id, name)`.
pub async fn holders(
    tx: &Tx<'_>,
    username: &str,
    except: AgentId,
) -> Result<Vec<(AgentId, String)>, StoreError> {
    let mut c = tx.conn().await;
    let rows = sqlx::query!(
        "SELECT id, name FROM agents
         WHERE lower(lldap_username) = lower($1) AND id <> $2
         ORDER BY name",
        username,
        Uuid::from(except)
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (AgentId::from_uuid(r.id), r.name))
        .collect())
}

/// Advisory-lock class of LLDAP memberships (two-key form, its own key
/// space): "ldap".
const MEMBERSHIP_CLASS: i32 = 0x6c64_6170;

/// Serialize everything that adds or removes one agent's membership of one
/// LLDAP group, until the transaction ends. Provision and revoke take it
/// before reading the sibling grants, so of two concurrent revokes the
/// second sees the first one's outcome (no write skew keeping the
/// membership forever). Lock order: after the grant row it acts for
/// (level 4 in the crate docs), before any a2a thread.
pub async fn lock_membership(tx: &Tx<'_>, agent: AgentId, group: &str) -> Result<(), StoreError> {
    let key = format!("{agent}\n{group}");
    let mut c = tx.conn().await;
    sqlx::query!(
        "SELECT pg_advisory_xact_lock($1, hashtext($2))",
        MEMBERSHIP_CLASS,
        key
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}
