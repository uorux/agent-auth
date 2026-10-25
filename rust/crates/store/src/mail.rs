//! The mail gateway's items (`mail_items`): one per grant and message the
//! gateway screened (inbound), or message an agent wanted sent (outbound).
//! The table's trigger allows only the gateway's transitions; held items
//! are claimed with a compare-and-swap so a double release sends once.

use agent_auth_core::{AgentId, GrantId, MailItemId};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::grants::ProvisioningGrant;
use crate::{StoreError, Tx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }

    fn parse(s: &str) -> Option<Direction> {
        match s {
            "in" => Some(Direction::In),
            "out" => Some(Direction::Out),
            _ => None,
        }
    }
}

/// Where an item stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemStatus {
    /// Not for this grant (another address, outside the correspondents).
    Ignored,
    /// Out of scope: counted, never shown.
    Withheld,
    /// Waiting for the operator.
    Held,
    /// The screen could not run; judged again on the next list.
    Error,
    Delivered,
    /// Held, then let through by the operator.
    Released,
    Discarded,
    Sending,
    Sent,
    Failed,
    Refused,
}

impl ItemStatus {
    pub const ALL: [ItemStatus; 11] = [
        ItemStatus::Ignored,
        ItemStatus::Withheld,
        ItemStatus::Held,
        ItemStatus::Error,
        ItemStatus::Delivered,
        ItemStatus::Released,
        ItemStatus::Discarded,
        ItemStatus::Sending,
        ItemStatus::Sent,
        ItemStatus::Failed,
        ItemStatus::Refused,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ItemStatus::Ignored => "ignored",
            ItemStatus::Withheld => "withheld",
            ItemStatus::Held => "held",
            ItemStatus::Error => "error",
            ItemStatus::Delivered => "delivered",
            ItemStatus::Released => "released",
            ItemStatus::Discarded => "discarded",
            ItemStatus::Sending => "sending",
            ItemStatus::Sent => "sent",
            ItemStatus::Failed => "failed",
            ItemStatus::Refused => "refused",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<ItemStatus> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MailItemRow {
    pub id: MailItemId,
    pub grant_id: GrantId,
    pub agent_id: AgentId,
    pub address: String,
    pub direction: Direction,
    pub message_key: Option<String>,
    pub thread_key: Option<String>,
    pub summary: Map<String, Value>,
    pub verdict: Option<String>,
    pub injection: Option<String>,
    pub reason: String,
    pub status: ItemStatus,
    /// A held draft, sealed (`SecretBox`, bound to this row).
    pub payload_encrypted: Option<String>,
    pub decided_by: Option<String>,
    pub decided_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    /// When the whole text was made available to the operator.
    pub shown_at: Option<OffsetDateTime>,
}

struct RawItem {
    id: Uuid,
    grant_id: Uuid,
    agent_id: Uuid,
    address: String,
    direction: String,
    message_key: Option<String>,
    thread_key: Option<String>,
    summary: Value,
    verdict: Option<String>,
    injection: Option<String>,
    reason: String,
    status: String,
    payload_encrypted: Option<String>,
    decided_by: Option<String>,
    decided_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    shown_at: Option<OffsetDateTime>,
}

impl TryFrom<RawItem> for MailItemRow {
    type Error = StoreError;
    fn try_from(r: RawItem) -> Result<MailItemRow, StoreError> {
        let bad = |what: &str| StoreError::corrupt("mail_items", what.to_owned());
        Ok(MailItemRow {
            id: MailItemId::from_uuid(r.id),
            grant_id: GrantId::from_uuid(r.grant_id),
            agent_id: AgentId::from_uuid(r.agent_id),
            address: r.address,
            direction: Direction::parse(&r.direction).ok_or_else(|| bad("direction"))?,
            message_key: r.message_key,
            thread_key: r.thread_key,
            summary: match r.summary {
                Value::Object(m) => m,
                _ => return Err(bad("summary")),
            },
            verdict: r.verdict,
            injection: r.injection,
            reason: r.reason,
            status: ItemStatus::parse(&r.status).ok_or_else(|| bad("status"))?,
            payload_encrypted: r.payload_encrypted,
            decided_by: r.decided_by,
            decided_at: r.decided_at,
            created_at: r.created_at,
            shown_at: r.shown_at,
        })
    }
}

fn rows(raw: Vec<RawItem>) -> Result<Vec<MailItemRow>, StoreError> {
    raw.into_iter().map(TryInto::try_into).collect()
}

/// A `create` grant's alias: the grant is for it from now on (while it is
/// being provisioned; the table allows this one move only).
pub async fn set_created_alias(
    tx: &Tx<'_>,
    grant: &ProvisioningGrant<'_>,
    alias: &str,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "UPDATE grants SET resource = $2 WHERE id = $1 AND status = 'provisioning'",
        Uuid::from(grant.grant().id),
        alias
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// The inbound items of a grant for these message keys.
pub async fn inbound_for_keys(
    tx: &Tx<'_>,
    grant: GrantId,
    keys: &[String],
) -> Result<Vec<MailItemRow>, StoreError> {
    let mut c = tx.conn().await;
    rows(
        sqlx::query_as!(
            RawItem,
            "SELECT * FROM mail_items
         WHERE grant_id = $1 AND direction = 'in' AND message_key = ANY($2)",
            Uuid::from(grant),
            keys
        )
        .fetch_all(&mut **c)
        .await?,
    )
}

/// Items of a grant an agent saw or sent (delivered, released, sent): the
/// thread context the judge gets.
pub async fn context(tx: &Tx<'_>, grant: GrantId) -> Result<Vec<MailItemRow>, StoreError> {
    let mut c = tx.conn().await;
    rows(
        sqlx::query_as!(
            RawItem,
            "SELECT * FROM mail_items
         WHERE grant_id = $1 AND status IN ('delivered', 'released', 'sent')
         ORDER BY created_at, id",
            Uuid::from(grant)
        )
        .fetch_all(&mut **c)
        .await?,
    )
}

/// A screening result for one inbound message.
#[derive(Debug, Clone)]
pub struct Screened<'a> {
    pub grant: GrantId,
    pub agent: AgentId,
    pub address: &'a str,
    pub message_key: &'a str,
    pub thread_key: Option<&'a str>,
    pub summary: &'a Map<String, Value>,
    pub verdict: Option<&'a str>,
    pub injection: Option<&'a str>,
    pub status: ItemStatus,
    pub reason: &'a str,
    /// A held message's whole text, sealed.
    pub payload_encrypted: Option<&'a str>,
}

/// Record a screening: a new item, or the item judged again. An item the
/// operator already released or discarded is left as it is (`None`).
pub async fn record_screened(
    tx: &Tx<'_>,
    s: &Screened<'_>,
    now: OffsetDateTime,
) -> Result<Option<MailItemId>, StoreError> {
    let mut c = tx.conn().await;
    let id = sqlx::query_scalar!(
        "INSERT INTO mail_items (id, grant_id, agent_id, address, direction, message_key,
                                 thread_key, summary, verdict, injection, reason, status, created_at,
                                 payload_encrypted)
         VALUES ($1, $2, $3, $4, 'in', $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (grant_id, direction, message_key) DO UPDATE
         SET thread_key = EXCLUDED.thread_key, summary = EXCLUDED.summary,
             verdict = EXCLUDED.verdict, injection = EXCLUDED.injection,
             reason = EXCLUDED.reason, status = EXCLUDED.status,
             payload_encrypted = EXCLUDED.payload_encrypted, shown_at = NULL
         WHERE mail_items.status NOT IN ('released', 'discarded')
         RETURNING id",
        Uuid::new_v4(),
        Uuid::from(s.grant),
        Uuid::from(s.agent),
        s.address,
        s.message_key,
        s.thread_key,
        Value::Object(s.summary.clone()),
        s.verdict,
        s.injection,
        s.reason,
        s.status.as_str(),
        now,
        s.payload_encrypted
    )
    .fetch_optional(&mut **c)
    .await?;
    Ok(id.map(MailItemId::from_uuid))
}

/// A message an agent wants sent.
#[derive(Debug, Clone)]
pub struct Outbound<'a> {
    pub id: MailItemId,
    pub grant: GrantId,
    pub agent: AgentId,
    pub address: &'a str,
    pub thread_key: Option<&'a str>,
    pub summary: &'a Map<String, Value>,
    pub verdict: &'a str,
    pub reason: &'a str,
    /// Sending, Held or Refused.
    pub status: ItemStatus,
    pub payload_encrypted: Option<&'a str>,
}

pub async fn insert_outbound(
    tx: &Tx<'_>,
    o: &Outbound<'_>,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO mail_items (id, grant_id, agent_id, address, direction, thread_key, summary,
                                 verdict, reason, status, payload_encrypted, created_at)
         VALUES ($1, $2, $3, $4, 'out', $5, $6, $7, $8, $9, $10, $11)",
        Uuid::from(o.id),
        Uuid::from(o.grant),
        Uuid::from(o.agent),
        o.address,
        o.thread_key,
        Value::Object(o.summary.clone()),
        o.verdict,
        o.reason,
        o.status.as_str(),
        o.payload_encrypted,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

pub async fn get(tx: &Tx<'_>, id: MailItemId) -> Result<Option<MailItemRow>, StoreError> {
    let mut c = tx.conn().await;
    sqlx::query_as!(
        RawItem,
        "SELECT * FROM mail_items WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?
    .map(TryInto::try_into)
    .transpose()
}

/// Every held item, oldest first.
pub async fn held(tx: &Tx<'_>) -> Result<Vec<MailItemRow>, StoreError> {
    let mut c = tx.conn().await;
    rows(
        sqlx::query_as!(
            RawItem,
            "SELECT * FROM mail_items WHERE status = 'held' ORDER BY created_at, id"
        )
        .fetch_all(&mut **c)
        .await?,
    )
}

/// `_claim`: held → `to`, once. False when it was not held (decided
/// meanwhile: a double click, Discord and the CLI at once). The draft is
/// kept only for sending.
pub async fn claim(
    tx: &Tx<'_>,
    id: MailItemId,
    to: ItemStatus,
    by: &str,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let done = sqlx::query!(
        "UPDATE mail_items SET status = $2, decided_by = $3, decided_at = $4,
                payload_encrypted = CASE WHEN $2 = 'sending' THEN payload_encrypted END
         WHERE id = $1 AND status = 'held'",
        Uuid::from(id),
        to.as_str(),
        by,
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// A sending item's outcome: sent (with the backend's id) or failed (with
/// why). The draft is dropped either way.
pub async fn finish_send(
    tx: &Tx<'_>,
    id: MailItemId,
    status: ItemStatus,
    reason: Option<&str>,
    sent_key: Option<&str>,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let done = sqlx::query!(
        "UPDATE mail_items SET status = $2, payload_encrypted = NULL,
                reason = COALESCE($3, reason), message_key = COALESCE($4, message_key)
         WHERE id = $1 AND status = 'sending'",
        Uuid::from(id),
        status.as_str(),
        reason,
        sent_key
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Drop a decided item's draft (and say why, when given).
pub async fn drop_payload(
    tx: &Tx<'_>,
    id: MailItemId,
    reason: Option<&str>,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "UPDATE mail_items SET payload_encrypted = NULL, reason = COALESCE($2, reason)
         WHERE id = $1",
        Uuid::from(id),
        reason
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// The whole text of an item was made available to the operator.
pub async fn mark_shown(
    tx: &Tx<'_>,
    id: MailItemId,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "UPDATE mail_items SET shown_at = $2 WHERE id = $1 AND shown_at IS NULL",
        Uuid::from(id),
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}
