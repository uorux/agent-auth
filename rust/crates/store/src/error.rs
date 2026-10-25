/// A failure of the storage layer (as opposed to a domain outcome such as a
/// lost compare-and-swap, which the kernel returns as `Ok(Err(..))`).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A stored value this version would not have written. Never defaulted.
    #[error("corrupt row in {table}: {detail}")]
    Corrupt { table: &'static str, detail: String },
    /// A value does not fit its column (refused, never truncated).
    #[error("{0} is out of range for its column")]
    OutOfRange(String),
    /// A proof (containment check) from another transaction or for another
    /// agent was presented. A programming error; refused, never trusted.
    #[error("proof does not belong to this transaction or agent")]
    WrongProof,
}

impl StoreError {
    pub(crate) fn corrupt(table: &'static str, detail: impl Into<String>) -> StoreError {
        StoreError::Corrupt {
            table,
            detail: detail.into(),
        }
    }

    fn db_code(&self) -> Option<String> {
        match self {
            StoreError::Db(sqlx::Error::Database(e)) => e.code().map(|c| c.into_owned()),
            _ => None,
        }
    }

    /// A unique constraint refused the write (e.g. a session-name clash).
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        self.db_code().as_deref() == Some("23505")
    }

    /// A CHECK constraint or a status-guard trigger refused the write.
    #[must_use]
    pub fn is_check_violation(&self) -> bool {
        self.db_code().as_deref() == Some("23514")
    }

    /// A foreign key refused the write (e.g. a session of another agent).
    #[must_use]
    pub fn is_foreign_key_violation(&self) -> bool {
        self.db_code().as_deref() == Some("23503")
    }
}
