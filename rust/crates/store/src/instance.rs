//! One broker per database. Wake-ups, the a2a activity stamps, the
//! security log and the daemon hub live in the process, so two brokers on
//! one database would be wrong (core B-19). The running broker holds a
//! session-level advisory lock on a connection of its own for its whole
//! life; a second one fails to take it and must exit.

use std::fmt;

use sqlx::Connection;
use sqlx::postgres::PgConnection;

use crate::{Store, StoreError};

/// The advisory lock key ("aainstnc").
const INSTANCE_LOCK: i64 = 0x6161_696e_7374_6e63;

/// Held while the broker runs; dropping it (or the process ending) closes
/// its connection, which releases the lock.
pub struct InstanceLock {
    conn: Option<PgConnection>,
}

impl fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceLock").finish_non_exhaustive()
    }
}

impl InstanceLock {
    /// Is the lock still ours? Its session must be alive (the lock lives as
    /// long as it) and must still hold the lock. An error means the
    /// session is gone (terminated, Postgres restarted, failed over) or
    /// unusable: another broker may hold the lock now.
    pub async fn check(&mut self) -> Result<(), StoreError> {
        let conn = self.conn.as_mut().ok_or(StoreError::WrongProof)?;
        let held = sqlx::query_scalar!(
            r#"SELECT EXISTS (
                   SELECT 1 FROM pg_locks
                   WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
                     AND classid = (($1::bigint >> 32) & 4294967295)::oid
                     AND objid = ($1::bigint & 4294967295)::oid
               ) AS "held!""#,
            INSTANCE_LOCK
        )
        .fetch_one(&mut *conn)
        .await?;
        if held {
            Ok(())
        } else {
            Err(StoreError::WrongProof)
        }
    }

    /// The lock session's backend process id (tests terminate it).
    pub async fn backend_pid(&mut self) -> Result<i32, StoreError> {
        let conn = self.conn.as_mut().ok_or(StoreError::WrongProof)?;
        Ok(sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
            .fetch_one(&mut *conn)
            .await?)
    }

    /// Release the lock now (closing its connection).
    pub async fn release(mut self) -> Result<(), StoreError> {
        if let Some(conn) = self.conn.take() {
            conn.close().await?;
        }
        Ok(())
    }
}

/// Take the instance lock on a dedicated connection. `None`: another
/// broker holds it.
pub async fn try_lock(store: &Store) -> Result<Option<InstanceLock>, StoreError> {
    let mut conn = store.pool().acquire().await?.detach();
    let got = sqlx::query_scalar!(
        r#"SELECT pg_try_advisory_lock($1) AS "got!""#,
        INSTANCE_LOCK
    )
    .fetch_one(&mut conn)
    .await?;
    if got {
        // Server-side keepalives on the lock's session: a broker that
        // vanished without closing it (a dead node) loses the lock within
        // about a minute instead of the kernel's two hours.
        sqlx::query_scalar!(
            r#"SELECT set_config('tcp_keepalives_idle', '30', false) || set_config('tcp_keepalives_interval', '10', false) || set_config('tcp_keepalives_count', '3', false) AS "set!""#
        )
        .fetch_one(&mut conn)
        .await?;
        Ok(Some(InstanceLock { conn: Some(conn) }))
    } else {
        conn.close().await?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn a_second_broker_cannot_start(pool: sqlx::PgPool) {
        let store = Store::from_pool(pool);
        let first = try_lock(&store).await.unwrap().unwrap();
        assert!(try_lock(&store).await.unwrap().is_none());
        let mut first = first;
        first.check().await.unwrap();
        first.release().await.unwrap();
        let again = try_lock(&store).await.unwrap();
        assert!(again.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_terminated_lock_session_is_noticed(pool: sqlx::PgPool) {
        let store = Store::from_pool(pool.clone());
        let mut lock = try_lock(&store).await.unwrap().unwrap();
        let pid = lock.backend_pid().await.unwrap();
        let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(killed);
        assert!(lock.check().await.is_err());
        // And the lock is free for the next broker.
        assert!(try_lock(&store).await.unwrap().is_some());
    }
}
