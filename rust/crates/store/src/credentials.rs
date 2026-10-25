//! `credentials`: cached, encrypted credentials of a grant (e.g. GitHub
//! installation tokens), newest wins.
//!
//! Every credential minted for a grant is recorded until it has run out, so
//! revoking the grant can revoke each one ([`live`]), and minting is
//! serialized per grant ([`lock_minting`]), so two concurrent fetches make
//! one token, not two.

use std::marker::PhantomData;

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

/// Advisory-lock class of credential minting (two-key form, its own key
/// space): "cred".
const MINT_CLASS: i32 = 0x6372_6564;

/// Proof that this transaction holds a grant's mint lock (from
/// [`lock_minting`], so for a grant cleared by [`crate::grants::issuable`]
/// in this transaction). Only [`record`] takes it.
#[derive(Debug)]
pub struct MintLock<'t> {
    tx: usize,
    grant: GrantId,
    borrow: PhantomData<&'t ()>,
}

impl MintLock<'_> {
    #[must_use]
    pub fn grant(&self) -> GrantId {
        self.grant
    }
}

/// Serialize minting for one grant until the transaction ends: a fetch
/// takes it, then reads the cache ([`latest`]), and mints only if nothing
/// usable is there; a concurrent fetch waits here and then finds the first
/// one's token. Lock order: last of all, after everything `issuable`
/// locked (containment, agent, grant, thread); its holder locks nothing
/// more (it inserts a `credentials` row, whose foreign key needs only the
/// grant share lock it already holds).
pub async fn lock_minting<'t>(
    tx: &'t Tx<'_>,
    issuing: &IssuableGrant<'t>,
) -> Result<MintLock<'t>, StoreError> {
    if !issuing.belongs_to(tx) {
        return Err(StoreError::WrongProof);
    }
    let grant = issuing.grant().id;
    let key = grant.to_string();
    let mut c = tx.conn().await;
    sqlx::query!(
        "SELECT pg_advisory_xact_lock($1, hashtext($2))",
        MINT_CLASS,
        key
    )
    .execute(&mut **c)
    .await?;
    Ok(MintLock {
        tx: tx.addr(),
        grant,
        borrow: PhantomData,
    })
}

/// Record a credential just minted under `lock` (taken in this
/// transaction). Earlier ones stay recorded until they have run out, so a
/// revoke reaches them too; those already run out are dropped here.
pub async fn record(
    tx: &Tx<'_>,
    lock: &MintLock<'_>,
    id: CredentialId,
    kind: &str,
    value_encrypted: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    if lock.tx != tx.addr() {
        return Err(StoreError::WrongProof);
    }
    let grant = lock.grant;
    let mut c = tx.conn().await;
    sqlx::query!(
        "DELETE FROM credentials WHERE grant_id = $1 AND expires_at <= $2",
        Uuid::from(grant),
        now
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

/// Every recorded credential of a grant that has not run out yet, oldest
/// first: what a revoke must revoke.
pub async fn live(
    tx: &Tx<'_>,
    grant: GrantId,
    now: OffsetDateTime,
) -> Result<Vec<CredentialRow>, StoreError> {
    let mut c = tx.conn().await;
    let rows = sqlx::query!(
        "SELECT * FROM credentials WHERE grant_id = $1 AND expires_at > $2
         ORDER BY created_at, id",
        Uuid::from(grant),
        now
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| CredentialRow {
            id: CredentialId::from_uuid(r.id),
            grant_id: GrantId::from_uuid(r.grant_id),
            kind: r.kind,
            value_encrypted: r.value_encrypted,
            expires_at: r.expires_at,
            created_at: r.created_at,
        })
        .collect())
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
