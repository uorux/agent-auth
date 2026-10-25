//! `credentials`: cached, encrypted credentials of a grant (e.g. GitHub
//! installation tokens), newest wins.

use agent_auth_core::{CredentialId, GrantId};

use crate::grants::IssuableGrant;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{StoreError, Tx};

/// `Debug` leaves out the ciphertext.
#[derive(Clone)]
pub struct CredentialRow {
    pub id: CredentialId,
    pub grant_id: GrantId,
    pub kind: String,
    /// At-rest ciphertext.
    pub value_encrypted: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for CredentialRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRow")
            .field("id", &self.id)
            .field("grant_id", &self.grant_id)
            .field("kind", &self.kind)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The newest cached credential of a grant.
pub async fn latest(tx: &Tx<'_>, grant: GrantId) -> Result<Option<CredentialRow>, StoreError> {
    let mut c = tx.conn().await;
    let r = sqlx::query!(
        "SELECT * FROM credentials WHERE grant_id = $1 ORDER BY created_at DESC, id LIMIT 1",
        Uuid::from(grant)
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(r.map(|r| CredentialRow {
        id: CredentialId::from_uuid(r.id),
        grant_id: GrantId::from_uuid(r.grant_id),
        kind: r.kind,
        value_encrypted: r.value_encrypted,
        expires_at: r.expires_at,
        created_at: r.created_at,
    }))
}

/// Replace a grant's cached credentials with one, while issuing for it
/// (the [`IssuableGrant`] must come from this transaction).
pub async fn replace(
    tx: &Tx<'_>,
    id: CredentialId,
    issuing: &IssuableGrant<'_>,
    kind: &str,
    value_encrypted: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    if !issuing.belongs_to(tx) {
        return Err(StoreError::WrongProof);
    }
    let grant = issuing.grant().id;
    let mut c = tx.conn().await;
    sqlx::query!(
        "DELETE FROM credentials WHERE grant_id = $1",
        Uuid::from(grant)
    )
    .execute(&mut **c)
    .await?;
    sqlx::query!(
        "INSERT INTO credentials (id, grant_id, kind, value_encrypted, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
        Uuid::from(id),
        Uuid::from(grant),
        kind,
        value_encrypted,
        expires_at,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// Forget a grant's cached credentials (revocation).
pub async fn delete_for(tx: &Tx<'_>, grant: GrantId) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "DELETE FROM credentials WHERE grant_id = $1",
        Uuid::from(grant)
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}
