//! `daemons` and `daemon_pairing_codes`: paired hostd/sandboxd instances.
//!
//! Pairing-code use is a pair of single conditional UPDATEs (daemons
//! INV-7): spending an attempt (`failed_attempts < max`) before the proof is
//! checked, and claiming the code (`used_at IS NULL`). Only one unused code
//! per daemon exists (a partial unique index).

use std::fmt;

use agent_auth_core::DaemonId;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::{self, text_enum};
use crate::{StoreError, Tx};

text_enum! {
    DaemonRole { Host = "host", Sandbox = "sandbox" }
}

#[derive(Debug, Clone)]
pub struct DaemonRow {
    pub id: DaemonId,
    pub role: DaemonRole,
    pub name: String,
    /// The daemon's signing key (its only credential).
    pub public_key: String,
    pub paired_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    pub version: Option<String>,
    /// Daemon-reported heartbeat; informational only, never an
    /// authorization input (daemons INV-34).
    pub last_status: Option<Value>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

struct RawDaemon {
    id: Uuid,
    role: String,
    name: String,
    public_key: String,
    paired_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    version: Option<String>,
    last_status: Option<Value>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

fn role(table: &'static str, s: &str) -> Result<DaemonRole, StoreError> {
    DaemonRole::parse(s).ok_or_else(|| StoreError::corrupt(table, format!("role {s:?}")))
}

impl TryFrom<RawDaemon> for DaemonRow {
    type Error = StoreError;
    fn try_from(r: RawDaemon) -> Result<DaemonRow, StoreError> {
        Ok(DaemonRow {
            id: DaemonId::from_uuid(r.id),
            role: role("daemons", &r.role)?,
            name: r.name,
            public_key: r.public_key,
            paired_at: r.paired_at,
            last_seen_at: r.last_seen_at,
            version: r.version,
            last_status: r.last_status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

fn rows(raw: Vec<RawDaemon>) -> Result<Vec<DaemonRow>, StoreError> {
    raw.into_iter().map(DaemonRow::try_from).collect()
}

/// A pairing code row. `Debug` leaves out the pairing key (an HMAC key).
#[derive(Clone)]
pub struct PairingCodeRow {
    pub id: Uuid,
    pub role: DaemonRole,
    pub name: String,
    /// The HMAC key derived from the code, hex. Secret.
    pub pairing_key: String,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub failed_attempts: u32,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for PairingCodeRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCodeRow")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("name", &self.name)
            .field("expires_at", &self.expires_at)
            .field("used_at", &self.used_at)
            .field("failed_attempts", &self.failed_attempts)
            .finish_non_exhaustive()
    }
}

pub async fn list(tx: &Tx<'_>) -> Result<Vec<DaemonRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(RawDaemon, "SELECT * FROM daemons ORDER BY role, name")
        .fetch_all(&mut **c)
        .await?;
    rows(raw)
}

pub async fn list_role(tx: &Tx<'_>, r: DaemonRole) -> Result<Vec<DaemonRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawDaemon,
        "SELECT * FROM daemons WHERE role = $1 ORDER BY name",
        r.as_str()
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

pub async fn get(tx: &Tx<'_>, id: DaemonId) -> Result<Option<DaemonRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawDaemon,
        "SELECT * FROM daemons WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    raw.map(DaemonRow::try_from).transpose()
}

pub async fn by_name(
    tx: &Tx<'_>,
    r: DaemonRole,
    name: &str,
) -> Result<Option<DaemonRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawDaemon,
        "SELECT * FROM daemons WHERE role = $1 AND name = $2",
        r.as_str(),
        name
    )
    .fetch_optional(&mut **c)
    .await?;
    raw.map(DaemonRow::try_from).transpose()
}

/// Issue a code: every unused code of the daemon is burnt, then the new one
/// stored (only the newest code is live).
pub async fn issue_code(
    tx: &Tx<'_>,
    id: Uuid,
    r: DaemonRole,
    name: &str,
    pairing_key: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    burn_codes(tx, r, name, now).await?;
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO daemon_pairing_codes (id, role, name, pairing_key, expires_at, created_at,
             updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
        id,
        r.as_str(),
        name,
        pairing_key,
        expires_at,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// Mark every unused code of a daemon used (re-issue, unpair).
pub async fn burn_codes(
    tx: &Tx<'_>,
    r: DaemonRole,
    name: &str,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "UPDATE daemon_pairing_codes SET used_at = $3, updated_at = $3
         WHERE role = $1 AND name = $2 AND used_at IS NULL",
        r.as_str(),
        name,
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}

/// The newest unused, unexpired, not burnt-out code of a daemon.
pub async fn live_code(
    tx: &Tx<'_>,
    r: DaemonRole,
    name: &str,
    now: OffsetDateTime,
    max_attempts: u32,
) -> Result<Option<PairingCodeRow>, StoreError> {
    let mut c = tx.conn().await;
    let row = sqlx::query!(
        "SELECT * FROM daemon_pairing_codes
         WHERE role = $1 AND name = $2 AND used_at IS NULL AND expires_at > $3
           AND failed_attempts < $4
         ORDER BY created_at DESC LIMIT 1",
        r.as_str(),
        name,
        now,
        values::to_i32(max_attempts)?
    )
    .fetch_optional(&mut **c)
    .await?;
    row.map(|p| {
        Ok(PairingCodeRow {
            id: p.id,
            role: role("daemon_pairing_codes", &p.role)?,
            name: p.name,
            pairing_key: p.pairing_key,
            expires_at: p.expires_at,
            used_at: p.used_at,
            failed_attempts: values::unsigned("daemon_pairing_codes", p.failed_attempts)?,
            created_at: p.created_at,
        })
    })
    .transpose()
}

/// Spend one attempt before checking a proof. `false`: the code is used or
/// burnt out (refuse without evaluating the proof).
pub async fn spend_attempt(tx: &Tx<'_>, code: Uuid, max_attempts: u32) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE daemon_pairing_codes SET failed_attempts = failed_attempts + 1, updated_at = now()
         WHERE id = $1 AND used_at IS NULL AND failed_attempts < $2",
        code,
        values::to_i32(max_attempts)?
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Claim a code after a correct proof. `false`: someone else claimed it.
pub async fn claim_code(tx: &Tx<'_>, code: Uuid, now: OffsetDateTime) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE daemon_pairing_codes SET used_at = $2, updated_at = $2
         WHERE id = $1 AND used_at IS NULL",
        code,
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Record a pairing: a new daemon gets `id`; a re-paired one keeps its id
/// and gets the new key, `paired_at = now` and no status.
pub async fn upsert_paired(
    tx: &Tx<'_>,
    id: DaemonId,
    r: DaemonRole,
    name: &str,
    public_key: &str,
    now: OffsetDateTime,
) -> Result<DaemonRow, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawDaemon,
        "INSERT INTO daemons (id, role, name, public_key, paired_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5, $5)
         ON CONFLICT (role, name) DO UPDATE SET public_key = EXCLUDED.public_key,
             paired_at = EXCLUDED.paired_at, last_status = NULL, updated_at = EXCLUDED.updated_at
         RETURNING *",
        Uuid::from(id),
        r.as_str(),
        name,
        public_key,
        now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

/// Delete a daemon and burn its unused codes (a leaked code cannot
/// re-pair). Its pending key deliveries go with it; its agents keep
/// running with `sandbox_id` NULL (sandboxd B-10, see `sandboxes`).
pub async fn unpair(
    tx: &Tx<'_>,
    id: DaemonId,
    now: OffsetDateTime,
) -> Result<Option<DaemonRow>, StoreError> {
    let raw = {
        let mut c = tx.conn().await;
        sqlx::query_as!(
            RawDaemon,
            "DELETE FROM daemons WHERE id = $1 RETURNING *",
            Uuid::from(id)
        )
        .fetch_optional(&mut **c)
        .await?
    };
    let Some(row) = raw.map(DaemonRow::try_from).transpose()? else {
        return Ok(None);
    };
    burn_codes(tx, row.role, &row.name, now).await?;
    Ok(Some(row))
}

/// A verified hello: `last_seen_at`, and the version if one was sent.
pub async fn hello(
    tx: &Tx<'_>,
    id: DaemonId,
    now: OffsetDateTime,
    version: Option<&str>,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE daemons SET last_seen_at = $2, version = COALESCE($3, version), updated_at = $2
         WHERE id = $1",
        Uuid::from(id),
        now,
        version
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// A heartbeat from the connection authenticated with `public_key`;
/// ignored (`false`) if the daemon was re-paired with another key since.
pub async fn heartbeat(
    tx: &Tx<'_>,
    id: DaemonId,
    public_key: &str,
    status: &Value,
    version: Option<&str>,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE daemons SET last_seen_at = $3, last_status = $4, version = COALESCE($5, version),
             updated_at = $3
         WHERE id = $1 AND public_key = $2",
        Uuid::from(id),
        public_key,
        now,
        status,
        version
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}
