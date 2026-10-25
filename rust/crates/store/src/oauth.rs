//! `oauth_clients` and `oauth_tokens`: the OAuth server for web-UI
//! connectors (surfaces spec §C).
//!
//! Codes and refresh tokens are single use through [`consume`], one
//! conditional UPDATE (`used_at IS NULL`), so two concurrent exchanges of
//! the same token cannot both succeed (Bug-C2); a second presentation
//! revokes the whole family in the same transaction (INV-C4). Tokens are
//! stored only as sha256 hex.

use std::fmt;

use agent_auth_core::AgentId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::values::{self, text_enum};
use crate::{StoreError, Tx};

/// Longest redirect URI registration accepts (Bug-C7: the column is text;
/// the limit is the registration code's to enforce).
pub const MAX_REDIRECT_URI_LEN: usize = 512;

text_enum! {
    TokenKind { Code = "code", Access = "access", Refresh = "refresh" }
}

/// `Debug` leaves out the secret hash.
#[derive(Clone)]
pub struct ClientRow {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// sha256 hex of the client secret; `None` for a public client.
    pub secret_hash: Option<String>,
    /// The web agent it acts as, once someone authorized it.
    pub agent_id: Option<AgentId>,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for ClientRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("agent_id", &self.agent_id)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

struct RawClient {
    id: String,
    name: String,
    redirect_uris: serde_json::Value,
    secret_hash: Option<String>,
    agent_id: Option<Uuid>,
    last_used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

impl TryFrom<RawClient> for ClientRow {
    type Error = StoreError;
    fn try_from(r: RawClient) -> Result<ClientRow, StoreError> {
        Ok(ClientRow {
            id: r.id,
            name: r.name,
            redirect_uris: values::string_list("oauth_clients", r.redirect_uris)?,
            secret_hash: r.secret_hash,
            agent_id: r.agent_id.map(AgentId::from_uuid),
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
            created_at: r.created_at,
        })
    }
}

/// `Debug` leaves out the token hash.
#[derive(Clone)]
pub struct TokenRow {
    pub id: Uuid,
    pub kind: TokenKind,
    pub token_hash: String,
    pub client_id: String,
    pub agent_id: AgentId,
    /// One authorization's tokens share a family.
    pub family: Uuid,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    /// Codes only.
    pub code_challenge: Option<String>,
    /// Codes only.
    pub redirect_uri: Option<String>,
    pub authorized_by: String,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for TokenRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRow")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("client_id", &self.client_id)
            .field("agent_id", &self.agent_id)
            .field("family", &self.family)
            .field("expires_at", &self.expires_at)
            .field("used_at", &self.used_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

struct RawToken {
    id: Uuid,
    kind: String,
    token_hash: String,
    client_id: String,
    agent_id: Uuid,
    family: Uuid,
    expires_at: OffsetDateTime,
    used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    code_challenge: Option<String>,
    redirect_uri: Option<String>,
    authorized_by: String,
    created_at: OffsetDateTime,
}

impl TryFrom<RawToken> for TokenRow {
    type Error = StoreError;
    fn try_from(r: RawToken) -> Result<TokenRow, StoreError> {
        Ok(TokenRow {
            id: r.id,
            kind: TokenKind::parse(&r.kind)
                .ok_or_else(|| StoreError::corrupt("oauth_tokens", format!("kind {:?}", r.kind)))?,
            token_hash: r.token_hash,
            client_id: r.client_id,
            agent_id: AgentId::from_uuid(r.agent_id),
            family: r.family,
            expires_at: r.expires_at,
            used_at: r.used_at,
            revoked_at: r.revoked_at,
            code_challenge: r.code_challenge,
            redirect_uri: r.redirect_uri,
            authorized_by: r.authorized_by,
            created_at: r.created_at,
        })
    }
}

// --------------------------------------------------------------- clients

/// Clients not revoked (the registration cap counts these).
pub async fn count_live_clients(tx: &Tx<'_>) -> Result<i64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM oauth_clients WHERE revoked_at IS NULL"#
    )
    .fetch_one(&mut **c)
    .await?)
}

/// Deletes clients nobody authorized (unbound, unrevoked, no tokens)
/// registered before `before` (surfaces Bug-C6: registration is open, so
/// unused registrations must not fill the cap for good). Returns how many.
pub async fn delete_unbound_clients(
    tx: &Tx<'_>,
    before: OffsetDateTime,
) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "DELETE FROM oauth_clients c
         WHERE c.agent_id IS NULL AND c.revoked_at IS NULL AND c.created_at < $1
           AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.id)",
        before
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}

#[derive(Debug, Clone)]
pub struct NewClient<'a> {
    pub id: &'a str,
    pub name: &'a str,
    /// Already validated (https, allowed host, at most
    /// [`MAX_REDIRECT_URI_LEN`] characters).
    pub redirect_uris: &'a [String],
    pub secret_hash: Option<&'a str>,
    pub now: OffsetDateTime,
}

pub async fn insert_client(tx: &Tx<'_>, n: &NewClient<'_>) -> Result<ClientRow, StoreError> {
    let uris = serde_json::to_value(n.redirect_uris)
        .map_err(|e| StoreError::OutOfRange(format!("redirect uris: {e}")))?;
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawClient,
        "INSERT INTO oauth_clients (id, name, redirect_uris, secret_hash, created_at)
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
        n.id,
        n.name,
        uris,
        n.secret_hash,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

pub async fn get_client(tx: &Tx<'_>, id: &str) -> Result<Option<ClientRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(RawClient, "SELECT * FROM oauth_clients WHERE id = $1", id)
        .fetch_optional(&mut **c)
        .await?;
    raw.map(ClientRow::try_from).transpose()
}

/// Bind a client to its agent (once; `false` if bound to another).
pub async fn bind_client(tx: &Tx<'_>, id: &str, agent: AgentId) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE oauth_clients SET agent_id = $2
         WHERE id = $1 AND revoked_at IS NULL AND (agent_id IS NULL OR agent_id = $2)",
        id,
        Uuid::from(agent)
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub async fn touch_client(tx: &Tx<'_>, id: &str, now: OffsetDateTime) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "UPDATE oauth_clients SET last_used_at = $2 WHERE id = $1",
        id,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(())
}

/// Every client, newest first (operator view).
pub async fn list_clients(tx: &Tx<'_>) -> Result<Vec<ClientRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawClient,
        "SELECT * FROM oauth_clients ORDER BY created_at DESC, id"
    )
    .fetch_all(&mut **c)
    .await?;
    raw.into_iter().map(ClientRow::try_from).collect()
}

/// Live authorizations per client: unrevoked, unused, unexpired refresh
/// tokens.
pub async fn live_authorizations(
    tx: &Tx<'_>,
    now: OffsetDateTime,
) -> Result<Vec<(String, i64)>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query!(
        r#"SELECT client_id, count(*) AS "n!" FROM oauth_tokens
           WHERE kind = 'refresh' AND revoked_at IS NULL AND used_at IS NULL AND expires_at > $1
           GROUP BY client_id"#,
        now
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(|r| (r.client_id, r.n)).collect())
}

/// Revoke a client (kept if already revoked) and every token of it.
/// `false`: no such client.
pub async fn revoke_client(tx: &Tx<'_>, id: &str, now: OffsetDateTime) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE oauth_clients SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1",
        id,
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    sqlx::query!(
        "UPDATE oauth_tokens SET revoked_at = $2 WHERE client_id = $1 AND revoked_at IS NULL",
        id,
        now
    )
    .execute(&mut **c)
    .await?;
    Ok(n == 1)
}

// ---------------------------------------------------------------- tokens

#[derive(Debug, Clone)]
pub struct NewToken<'a> {
    pub id: Uuid,
    pub kind: TokenKind,
    pub token_hash: &'a str,
    pub client_id: &'a str,
    pub agent_id: AgentId,
    pub family: Uuid,
    pub expires_at: OffsetDateTime,
    /// Codes only (a CHECK refuses them on other kinds).
    pub code_challenge: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub authorized_by: &'a str,
    pub now: OffsetDateTime,
}

pub async fn insert_token(tx: &Tx<'_>, n: &NewToken<'_>) -> Result<TokenRow, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawToken,
        "INSERT INTO oauth_tokens (id, kind, token_hash, client_id, agent_id, family, expires_at,
             code_challenge, redirect_uri, authorized_by, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *",
        n.id,
        n.kind.as_str(),
        n.token_hash,
        n.client_id,
        Uuid::from(n.agent_id),
        n.family,
        n.expires_at,
        n.code_challenge,
        n.redirect_uri,
        n.authorized_by,
        n.now
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

/// A live token of `kind` by hash: unrevoked, unexpired, of an unrevoked
/// client (any use state).
pub async fn find_live(
    tx: &Tx<'_>,
    token_hash: &str,
    kind: TokenKind,
    now: OffsetDateTime,
) -> Result<Option<TokenRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawToken,
        "SELECT t.* FROM oauth_tokens t JOIN oauth_clients c ON c.id = t.client_id
         WHERE t.token_hash = $1 AND t.kind = $2 AND t.revoked_at IS NULL AND t.expires_at > $3
           AND c.revoked_at IS NULL",
        token_hash,
        kind.as_str(),
        now
    )
    .fetch_optional(&mut **c)
    .await?;
    raw.map(TokenRow::try_from).transpose()
}

/// The agent behind a live access token of a live client (bearer auth on
/// `/v1` and `/mcp`); the caller still checks the agent is enabled.
pub async fn agent_for_access(
    tx: &Tx<'_>,
    token_hash: &str,
    now: OffsetDateTime,
) -> Result<Option<AgentId>, StoreError> {
    Ok(find_live(tx, token_hash, TokenKind::Access, now)
        .await?
        .map(|t| t.agent_id))
}

/// The result of presenting a code or refresh token.
#[derive(Debug, Clone)]
pub enum Consumed {
    /// First use: marked used now; issue from it.
    Fresh(Box<TokenRow>),
    /// Used before: its whole family was revoked in this transaction.
    /// Commit, then refuse (the revocation must be durable).
    Replayed { family: Uuid, revoked: u64 },
    /// No such live token of this kind for this client.
    Unknown,
}

/// Consume a code or refresh token of `client` atomically.
pub async fn consume(
    tx: &Tx<'_>,
    token_hash: &str,
    kind: TokenKind,
    client: &str,
    now: OffsetDateTime,
) -> Result<Consumed, StoreError> {
    if kind == TokenKind::Access {
        return Ok(Consumed::Unknown);
    }
    let fresh = {
        let mut c = tx.conn().await;
        sqlx::query_as!(
            RawToken,
            "UPDATE oauth_tokens SET used_at = $4
             WHERE token_hash = $1 AND kind = $2 AND client_id = $3
               AND revoked_at IS NULL AND expires_at > $4 AND used_at IS NULL
             RETURNING *",
            token_hash,
            kind.as_str(),
            client,
            now
        )
        .fetch_optional(&mut **c)
        .await?
    };
    if let Some(raw) = fresh {
        return Ok(Consumed::Fresh(Box::new(raw.try_into()?)));
    }
    let used = {
        let mut c = tx.conn().await;
        sqlx::query_scalar!(
            "SELECT family FROM oauth_tokens
             WHERE token_hash = $1 AND kind = $2 AND client_id = $3
               AND revoked_at IS NULL AND expires_at > $4 AND used_at IS NOT NULL",
            token_hash,
            kind.as_str(),
            client,
            now
        )
        .fetch_optional(&mut **c)
        .await?
    };
    match used {
        None => Ok(Consumed::Unknown),
        Some(family) => {
            let revoked = revoke_family(tx, family, now).await?;
            Ok(Consumed::Replayed { family, revoked })
        }
    }
}

/// Revoke every unrevoked token of a family; returns how many.
pub async fn revoke_family(
    tx: &Tx<'_>,
    family: Uuid,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "UPDATE oauth_tokens SET revoked_at = $2 WHERE family = $1 AND revoked_at IS NULL",
        family,
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}
