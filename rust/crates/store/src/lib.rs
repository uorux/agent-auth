#![forbid(unsafe_code)]
//! Postgres: the schema (`migrations/`), typed rows, every SQL statement of
//! the broker, and the state-transition kernel.
//!
//! # Shape
//!
//! - [`Store`] owns the pool; [`Store::begin`] opens a [`Tx`]. Every query
//!   function takes `&Tx` (shared: the transaction serializes its own
//!   statements), so a proof borrowed from a transaction (a
//!   [`lockdown::NotHeld`]) can be held while the same transaction is used,
//!   and cannot outlive it: `Tx::commit` takes the transaction by value.
//! - One module per domain. Each has `XxxRow` types (domain types: typed ids,
//!   parsed enums, `Authority`), built from the database row at the boundary;
//!   a row that does not convert is [`StoreError::Corrupt`], never a default.
//! - The kernel: [`requests::transition`] (compare-and-swap over the typed
//!   request state machine), [`lockdown::check`] (containment inside the
//!   acting transaction), [`grants::begin`] / [`grants::activate`] (grant
//!   rows only for a `Provisioning` request of an agent proven not held), and
//!   [`grants::issuable`] (the only way to an [`grants::IssuableGrant`]).
//!
//! # Adding a query
//!
//! Write it with `sqlx::query!`/`query_as!` in the module of its domain,
//! then refresh the offline data: `scripts/pg.sh start`, apply the
//! migrations (`sqlx migrate run --source crates/store/migrations`), and run
//! `SQLX_OFFLINE=false cargo sqlx prepare --workspace` with `DATABASE_URL`
//! set. Commit `rust/.sqlx/` with the change.

pub mod a2a;
pub mod agents;
pub mod credentials;
pub mod daemons;
mod error;
pub mod flags;
pub mod grants;
pub mod hostexec;
pub mod llm;
pub mod lockdown;
pub mod oauth;
pub mod requests;
pub mod rules;
pub mod sandboxes;
pub mod sessions;
mod tx;
mod values;

pub use error::StoreError;
pub use tx::{Store, Tx};
pub use values::Delegation;

/// The schema's migrations, embedded.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Result of an operation whose domain outcome (`Ok(Err(_))`: lost a race,
/// refused) is distinct from an infrastructure failure (`Err(_)`).
pub type Outcome<T, E> = Result<Result<T, E>, StoreError>;
