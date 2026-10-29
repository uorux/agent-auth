//! `broker_flags`: small durable switches of the broker. Today: the
//! hostexec lockdown (`{"hosts": [...], "by", "at", "scope"}`, owned by the
//! hostexec code). Read-modify-write goes through [`get_for_update`] so two
//! concurrent changes cannot lose one (core B-8).

use serde_json::Value;
use time::OffsetDateTime;

use crate::{StoreError, Tx};

/// The hostexec lockdown flag's key.
pub const LOCKDOWN: &str = "lockdown";

pub async fn get(tx: &Tx<'_>, key: &str) -> Result<Option<Value>, StoreError> {
    let mut c = tx.conn().await;
    Ok(
        sqlx::query_scalar!("SELECT value FROM broker_flags WHERE key = $1", key)
            .fetch_optional(&mut **c)
            .await?,
    )
}

/// Read and lock the flag until the transaction ends. A missing flag is
/// created first (as `initial`) so that concurrent first writers serialize
/// on the row as well.
pub async fn get_for_update(
    tx: &Tx<'_>,
    key: &str,
    initial: &Value,
    now: OffsetDateTime,
) -> Result<Value, StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO broker_flags (key, value, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO NOTHING",
        key,
        initial,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(sqlx::query_scalar!(
        "SELECT value FROM broker_flags WHERE key = $1 FOR UPDATE",
        key
    )
    .fetch_one(&mut **c)
    .await?)
}

pub async fn set(
    tx: &Tx<'_>,
    key: &str,
    value: &Value,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO broker_flags (key, value, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
        key,
        value,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

pub async fn delete(tx: &Tx<'_>, key: &str) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!("DELETE FROM broker_flags WHERE key = $1", key)
        .execute(&mut **c)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// Is the broker locked down for `host` (the flag's hosts hold `"*"` or it)?
pub async fn locked(tx: &Tx<'_>, host: &str) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (
               SELECT 1 FROM broker_flags
               WHERE key = 'lockdown' AND (value -> 'hosts' ? '*' OR value -> 'hosts' ? $1)
           ) AS "locked!""#,
        host
    )
    .fetch_one(&mut **c)
    .await?)
}
