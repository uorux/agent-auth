//! Pairing (spec §3): one-time codes issued by the admin, redeemed by the
//! daemon with an HMAC proof over its key. The code itself is never stored
//! (only the HMAC key derived from it), every refusal is the same 403, an
//! attempt is spent (and committed) before a proof is checked, and only the
//! newest unused code of a daemon is live (INV-7).

use agent_auth_core::DaemonId;
use agent_auth_crypto::Secret;
use agent_auth_crypto::daemon::{
    DaemonId as ChannelId, DaemonName, PairingKey, PublicKey, Role, generate_pairing_code,
};
use agent_auth_store::daemons::{self, DaemonRole, DaemonRow};
use agent_auth_wire::daemon::pairing::{PAIRING_REFUSED, PairBody};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::DaemonHub;

/// Pairing failed: the HTTP status and detail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// 503: `BROKER_SIGNING_KEY` not configured.
    #[error("BROKER_SIGNING_KEY not configured")]
    Disabled,
    /// 400: a bad role, name or key.
    #[error("{0}")]
    Invalid(String),
    /// 403, always the same text.
    #[error(transparent)]
    Refused(#[from] PairingRefused),
    #[error("{0}")]
    Internal(String),
}

/// The one refusal (403) for every pairing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", PAIRING_REFUSED)]
pub struct PairingRefused;

impl From<agent_auth_store::StoreError> for PairingError {
    fn from(e: agent_auth_store::StoreError) -> Self {
        PairingError::Internal(e.to_string())
    }
}

pub(crate) fn store_role(role: Role) -> DaemonRole {
    match role {
        Role::Host => DaemonRole::Host,
        Role::Sandbox => DaemonRole::Sandbox,
    }
}

/// `validate_identity`: the Python's 400 texts.
pub fn identity(role: &str, name: &str) -> Result<ChannelId, PairingError> {
    let role = Role::parse(role)
        .ok_or_else(|| PairingError::Invalid("role must be one of host, sandbox".into()))?;
    let name = DaemonName::parse(name).ok_or_else(|| {
        PairingError::Invalid("name must be a lowercase hostname label ([a-z0-9-], ≤63)".into())
    })?;
    Ok(ChannelId::new(role, name))
}

/// A code just issued.
#[derive(Debug)]
pub struct IssuedCode {
    pub code: Secret<String>,
    pub expires_at: OffsetDateTime,
}

/// The broker's answer to a successful pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    pub broker_public_key: String,
    pub proof: String,
    pub fingerprint: String,
}

impl DaemonHub {
    /// Issue a code for (role, name): every unused one burns, this one is
    /// the only live one, for `DAEMON_PAIRING_CODE_TTL_SECS`.
    pub async fn create_pairing_code(&self, id: &ChannelId) -> Result<IssuedCode, PairingError> {
        if !self.enabled() {
            return Err(PairingError::Disabled);
        }
        let code = generate_pairing_code().map_err(|e| PairingError::Internal(e.to_string()))?;
        let key = PairingKey::from_code(code.expose());
        let now = OffsetDateTime::now_utc();
        let expires_at = now.saturating_add(Duration::seconds(i64::from(
            self.config.pairing_code_ttl_secs,
        )));
        let tx = self.store.begin().await?;
        daemons::issue_code(
            &tx,
            Uuid::new_v4(),
            store_role(id.role),
            id.name.as_str(),
            key.to_hex().expose(),
            expires_at,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedCode { code, expires_at })
    }

    /// `POST /v1/daemons/pair`. A wrong selector spends nothing; a wrong
    /// proof spends one attempt, committed before the refusal; a right one
    /// claims the code and binds the key, and any connection authenticated
    /// with an older key is closed.
    pub async fn pair(&self, body: &PairBody) -> Result<Paired, PairingError> {
        let Some(signing) = self.config.signing_key.as_ref() else {
            return Err(PairingError::Disabled);
        };
        let id = identity(body.role.as_str(), body.name.as_str())?;
        let daemon_key = PublicKey::parse(body.public_key.as_str())
            .map_err(|e| PairingError::Invalid(e.to_string()))?;
        let now = OffsetDateTime::now_utc();
        let max = self.config.pairing_max_attempts;
        let role = store_role(id.role);
        let name = id.name.as_str();

        // 1. Find the live code and spend an attempt, in a transaction of
        //    its own that commits whatever the proof turns out to be.
        let tx = self.store.begin().await?;
        let Some(code) = daemons::live_code(&tx, role, name, now, max).await? else {
            return Err(PairingRefused.into());
        };
        let Some(key) = PairingKey::from_hex(&code.pairing_key) else {
            return Err(PairingError::Internal(
                "stored pairing key is not hex".into(),
            ));
        };
        // Without the code there is no matching selector, so attempts that
        // don't have it can't burn it.
        if !key.selector_matches(body.selector.as_str()) {
            return Err(PairingRefused.into());
        }
        let spent = daemons::spend_attempt(&tx, code.id, max).await?;
        tx.commit().await?;
        if !spent {
            return Err(PairingRefused.into());
        }
        if !key.verify_daemon_proof(&id, &daemon_key, body.proof.as_str()) {
            tracing::warn!(daemon = %id.principal(), "pairing proof did not verify");
            return Err(PairingRefused.into());
        }

        // 2. Claim the code and bind the key.
        let tx = self.store.begin().await?;
        if !daemons::claim_code(&tx, code.id, now).await? {
            return Err(PairingRefused.into());
        }
        let row =
            daemons::upsert_paired(&tx, DaemonId::new(), role, name, &daemon_key.to_text(), now)
                .await?;
        tx.commit().await?;

        // A connection authenticated with the old key must not outlive it.
        self.kick(id.role, name, "re-paired");
        tracing::info!(daemon = %id.principal(), fingerprint = %daemon_key.fingerprint(), "paired");
        let hooks: Vec<_> = self.hooks().on_paired.clone();
        for hook in hooks {
            hook(id.role, name.to_owned(), row.id).await;
        }
        let broker_key = signing.public_key();
        Ok(Paired {
            broker_public_key: broker_key.to_text(),
            proof: key.broker_proof(&id, &daemon_key, &broker_key),
            fingerprint: daemon_key.fingerprint(),
        })
    }

    /// Delete a daemon, burn its unused codes, close its connection.
    pub async fn unpair(&self, id: DaemonId) -> Result<bool, PairingError> {
        Ok(self.unpair_disabling(id).await?.is_some())
    }

    /// [`DaemonHub::unpair`], also disabling (in the same transaction) every
    /// agent of an agent VM, with what they minted (sandboxd B-10: their
    /// keys must not outlive the VM's pairing). `None`: no such daemon;
    /// else the names disabled (for `scheduler::after_disable`).
    pub async fn unpair_disabling(
        &self,
        id: DaemonId,
    ) -> Result<Option<Vec<String>>, PairingError> {
        let now = OffsetDateTime::now_utc();
        let tx = self.store.begin().await?;
        let mut disabled = Vec::new();
        for agent in agent_auth_store::sandboxes::enabled_in(&tx, id).await? {
            disabled.extend(
                agent_auth_store::sandboxes::disable_tree(
                    &tx,
                    agent,
                    now,
                    agent_auth_store::agents::DisableReason::Unpaired,
                )
                .await?,
            );
        }
        let row = daemons::unpair(&tx, id, now).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        disabled.sort();
        disabled.dedup();
        let role = match row.role {
            DaemonRole::Host => Role::Host,
            DaemonRole::Sandbox => Role::Sandbox,
        };
        self.kick(role, &row.name, "unpaired");
        tracing::info!(daemon = %format!("{role}:{}", row.name), "unpaired");
        if !disabled.is_empty() {
            tracing::warn!(
                "unpaired {role}:{}: disabled {}",
                row.name,
                disabled.join(", ")
            );
        }
        Ok(Some(disabled))
    }

    /// Every paired daemon, by role and name.
    pub async fn list(&self) -> Result<Vec<DaemonRow>, PairingError> {
        let tx = self.store.begin().await?;
        let rows = daemons::list(&tx).await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Whether a stored row's daemon is connected.
    #[must_use]
    pub fn row_online(&self, row: &DaemonRow) -> bool {
        let role = match row.role {
            DaemonRole::Host => Role::Host,
            DaemonRole::Sandbox => Role::Sandbox,
        };
        self.is_online(role, &row.name)
    }
}
