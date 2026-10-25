use std::fmt;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::{Mutex, MutexGuard};

use crate::StoreError;

/// The database.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Connect with a pool of at most `max_connections`.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Store, StoreError> {
        let options: PgConnectOptions = url.parse()?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await?;
        Ok(Store { pool })
    }

    #[must_use]
    pub fn from_pool(pool: PgPool) -> Store {
        Store { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply pending migrations.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        crate::MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Open a transaction (READ COMMITTED). Dropped without `commit`, it
    /// rolls back.
    pub async fn begin(&self) -> Result<Tx<'static>, StoreError> {
        Ok(Tx {
            inner: Mutex::new(self.pool.begin().await?),
        })
    }
}

/// One transaction. Query functions take `&Tx`; statements are serialized
/// through an internal lock (a transaction is one connection), which lets
/// proofs such as [`crate::lockdown::NotHeld`] borrow the transaction while
/// it keeps being used. Committing consumes it, so no proof outlives it.
pub struct Tx<'c> {
    inner: Mutex<Transaction<'c, Postgres>>,
}

impl fmt::Debug for Tx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tx").finish_non_exhaustive()
    }
}

impl<'c> Tx<'c> {
    pub async fn commit(self) -> Result<(), StoreError> {
        self.inner.into_inner().commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<(), StoreError> {
        self.inner.into_inner().rollback().await?;
        Ok(())
    }

    /// The connection, for one statement: `&mut **tx.conn().await`.
    pub(crate) async fn conn(&self) -> MutexGuard<'_, Transaction<'c, Postgres>> {
        self.inner.lock().await
    }

    /// This transaction's identity while it lives (proofs record it).
    pub(crate) fn addr(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}
