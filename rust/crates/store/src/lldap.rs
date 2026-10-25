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
