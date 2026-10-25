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
        first.release().await.unwrap();
        let again = try_lock(&store).await.unwrap();
        assert!(again.is_some());
    }
}
