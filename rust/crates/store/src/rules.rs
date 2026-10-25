//! `rules`: saved rules ("DB rules"), created from human decisions and
//! hostexec approve-all windows. Matching (globs, `rule_covers`) is core's;
//! this module stores and orders them (newest first, ties broken by
//! insertion order: core B-22).

use agent_auth_core::{Authority, Platform, RuleId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::{self, text_enum};
use crate::{StoreError, Tx};

const T: &str = "rules";

text_enum! {
    RuleAction { AutoApprove = "auto_approve", AutoDeny = "auto_deny" }
}

#[derive(Debug, Clone)]
pub struct RuleRow {
    pub id: RuleId,
    pub action: RuleAction,
    /// Glob on the agent's name.
    pub agent_pattern: String,
    /// Glob on the delegator's name; `None` = written without delegation
    /// (still denies delegated requests, never approves them).
    pub delegator_pattern: Option<String>,
    pub platform: Platform,
    pub resource_pattern: String,
    /// `None` = any privilege (never counts as pinned).
    pub authority: Option<Authority>,
    pub max_duration_secs: Option<u32>,
    pub enabled: bool,
    pub created_by: String,
    pub notes: String,
    /// Windows: past it the rule matches nothing.
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl RuleRow {
    /// Enabled and not past its expiry.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.enabled && self.expires_at.is_none_or(|e| e > now)
    }
}

struct RawRule {
    id: Uuid,
    action: String,
    agent_pattern: String,
    delegator_pattern: Option<String>,
    platform: String,
    resource_pattern: String,
    authority: Option<serde_json::Value>,
    max_duration_secs: Option<i32>,
    enabled: bool,
    created_by: String,
    notes: String,
    expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

impl TryFrom<RawRule> for RuleRow {
    type Error = StoreError;
    fn try_from(r: RawRule) -> Result<RuleRow, StoreError> {
        let platform = values::platform(T, &r.platform)?;
        Ok(RuleRow {
            id: RuleId::from_uuid(r.id),
            action: RuleAction::parse(&r.action)
                .ok_or_else(|| StoreError::corrupt(T, format!("action {:?}", r.action)))?,
            agent_pattern: r.agent_pattern,
            delegator_pattern: r.delegator_pattern,
            authority: r
                .authority
                .as_ref()
                .map(|a| values::authority(T, platform, a))
                .transpose()?,
            platform,
            resource_pattern: r.resource_pattern,
            max_duration_secs: values::opt_unsigned(T, r.max_duration_secs)?,
            enabled: r.enabled,
            created_by: r.created_by,
            notes: r.notes,
            expires_at: r.expires_at,
            created_at: r.created_at,
        })
    }
}

fn rows(raw: Vec<RawRule>) -> Result<Vec<RuleRow>, StoreError> {
    raw.into_iter().map(RuleRow::try_from).collect()
}

#[derive(Debug, Clone)]
pub struct NewRule<'a> {
    pub id: RuleId,
    pub action: RuleAction,
    pub agent_pattern: &'a str,
    pub delegator_pattern: Option<&'a str>,
    pub platform: Platform,
    pub resource_pattern: &'a str,
    /// Must be of `platform` (refused otherwise).
    pub authority: Option<&'a Authority>,
    pub max_duration_secs: Option<u32>,
    pub created_by: &'a str,
    pub notes: &'a str,
    pub expires_at: Option<OffsetDateTime>,
    pub now: OffsetDateTime,
}

pub async fn insert(tx: &Tx<'_>, n: &NewRule<'_>) -> Result<RuleRow, StoreError> {
    if n.authority.is_some_and(|a| a.platform() != n.platform) {
        return Err(StoreError::OutOfRange(
            "a rule authority of another platform".to_owned(),
        ));
    }
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRule,
        "INSERT INTO rules (id, action, agent_pattern, delegator_pattern, platform, resource_pattern,
             authority, max_duration_secs, enabled, created_by, notes, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9, $10, $11, $12)
         RETURNING id, action, agent_pattern, delegator_pattern, platform, resource_pattern,
                   authority, max_duration_secs, enabled, created_by, notes, expires_at, created_at",
        Uuid::from(n.id),
        n.action.as_str(),
        n.agent_pattern,
        n.delegator_pattern,
        n.platform.as_str(),
        n.resource_pattern,
        n.authority.map(Authority::to_json),
        values::opt_to_i32(n.max_duration_secs)?,
        n.created_by,
        n.notes,
        n.expires_at,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

pub async fn get(tx: &Tx<'_>, id: RuleId) -> Result<Option<RuleRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRule,
        "SELECT id, action, agent_pattern, delegator_pattern, platform, resource_pattern,
                authority, max_duration_secs, enabled, created_by, notes, expires_at, created_at
         FROM rules WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    raw.map(RuleRow::try_from).transpose()
}

/// Enabled, unexpired rules of a platform, newest first: the policy
/// engine's candidates.
pub async fn live_for(
    tx: &Tx<'_>,
    platform: Platform,
    now: OffsetDateTime,
) -> Result<Vec<RuleRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRule,
        "SELECT id, action, agent_pattern, delegator_pattern, platform, resource_pattern,
                authority, max_duration_secs, enabled, created_by, notes, expires_at, created_at
         FROM rules
         WHERE enabled AND platform = $1 AND (expires_at IS NULL OR expires_at > $2)
         ORDER BY created_at DESC, seq DESC",
        platform.as_str(),
        now
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Every rule, newest first (admin, Discord).
pub async fn list(tx: &Tx<'_>) -> Result<Vec<RuleRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawRule,
        "SELECT id, action, agent_pattern, delegator_pattern, platform, resource_pattern,
                authority, max_duration_secs, enabled, created_by, notes, expires_at, created_at
         FROM rules ORDER BY created_at DESC, seq DESC"
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

pub async fn set_enabled(tx: &Tx<'_>, id: RuleId, enabled: bool) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE rules SET enabled = $2 WHERE id = $1",
        Uuid::from(id),
        enabled
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub async fn delete(tx: &Tx<'_>, id: RuleId) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!("DELETE FROM rules WHERE id = $1", Uuid::from(id))
        .execute(&mut **c)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// How many rules an agent rename rewrote, per pattern.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Renamed {
    pub agent_pattern: u64,
    pub delegator_pattern: u64,
    pub a2a_resource_pattern: u64,
}

/// Rewrite the patterns that are exactly the old name.
pub async fn rename_agent(tx: &Tx<'_>, old: &str, new: &str) -> Result<Renamed, StoreError> {
    let mut c = tx.conn().await;
    let agent_pattern = sqlx::query!(
        "UPDATE rules SET agent_pattern = $2 WHERE agent_pattern = $1",
        old,
        new
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    let delegator_pattern = sqlx::query!(
        "UPDATE rules SET delegator_pattern = $2 WHERE delegator_pattern = $1",
        old,
        new
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    let a2a_resource_pattern = sqlx::query!(
        "UPDATE rules SET resource_pattern = $2 WHERE platform = 'a2a' AND resource_pattern = $1",
        old,
        new
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(Renamed {
        agent_pattern,
        delegator_pattern,
        a2a_resource_pattern,
    })
}
