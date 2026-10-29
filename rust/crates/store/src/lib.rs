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
//! - Approvals carry proofs: `requests::Approval` is built only from a
//!   routing clearance (`AutoClearance`, `LlmClearance`) or a human's
//!   `HumanApproval`, each naming its request (and, for clearances, the
//!   authority); [`requests::transition`] refuses a mismatch. Entering LLM
//!   review needs the `LlmClearance` too.
//! - Provisioning carries a proof: [`grants::ProvisioningGrant`] (from
//!   `begin` or `load_provisioning`) is what `activate` and
//!   `fail_provisioning` consume.
//!
//! # Lock order
//!
//! Every function takes row locks in this order, and code composing them
//! in one transaction must too (Postgres aborts one side of a deadlock, so
//! a violation is an error, not a hang, but it is a bug):
//!
//! 1. **access request** rows (the transition CAS of the request being
//!    decided) — except that the finishing phase and the reaper move a
//!    request after locking its own grant, which is safe because that
//!    grant's lock already serializes every path to that request;
//! 2. the **containment lock** (a transaction-scoped advisory lock): shared
//!    by `lockdown::check`/`check_pair` (and so `grants::issuable`), held to
//!    commit; exclusive for `lockdown::record`/`lift*`, `agents::set_disabled`
//!    and `sandboxes::disable_tree`. A transaction holding it exclusively
//!    never locks a request;
//! 3. **agents**, ascending id when several are locked at once (the
//!    checked agent first, then a delegator, are both share locks; the only
//!    multi-row exclusive writers, the disable paths, hold the containment
//!    lock exclusively, so they cannot interleave with share lockers). Do
//!    not write an agent row (e.g. `touch_seen`) and then call
//!    `lockdown::check` in the same transaction: touch liveness in its own
//!    transaction;
//! 4. **grants**, ascending id when several are locked at once (multi-row
//!    writers lock `ORDER BY id FOR NO KEY UPDATE` first);
//!    Then the **LLDAP membership lock** (`lldap::lock_membership`, an
//!    advisory lock per agent and group), after the grant it acts for;
//!    likewise the **pool lock** (`pool::lock_pool`, an advisory lock per
//!    pool), after the grant being provisioned; and the **mint lock**
//!    (`credentials::lock_minting`, an advisory lock per grant), last of
//!    all: a credential fetch takes it after everything `grants::issuable`
//!    locked (a delegation's thread included), and its holder locks nothing
//!    more, so waiting on it closes no cycle;
//!    A **shell scope** (`shell_scopes`) after its grant: a command
//!    share-locks the grant (`issuable`), then its scope; closing a scope
//!    locks only scope rows;
//! 5. **a2a threads** (a thread is locked after the grants it depends on;
//!    look the backing grant id up without a lock, lock the grant, then the
//!    thread);
//! 6. everything else (sessions, messages, jobs, tokens, flags).
//!
//! So: provisioning is `transition` → `lockdown::check` → `grants::begin`;
//! finishing is `lockdown::check` → `grants::load_provisioning` →
//! `grants::activate` → the request's `transition`. Finishing and the
//! reaper thus lock their grant before its own request, which is safe: the
//! only grant locks taken while holding a request are the insert of a new
//! grant and `FOR SHARE` on a delegation's backing grant (another
//! request's), and no exclusive grant locker (revoke, expiry, containment,
//! the admin rename) ever locks a request.
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
pub mod evals;
pub mod flags;
pub mod grants;
pub mod hostexec;
pub mod instance;
pub mod lldap;
pub mod llm;
pub mod lockdown;
pub mod mail;
pub mod oauth;
pub mod pool;
pub mod requests;
pub mod rules;
pub mod sandboxes;
pub mod sessions;
pub mod shell_scopes;
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
