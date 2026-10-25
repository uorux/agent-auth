//! The model gateway (sandboxd spec §4.8): each agent's own key for the
//! broker's gateway (`platforms.models`), asked for once and reused until
//! shortly before it ends. A gateway with no key for an agent (refused,
//! contained, waiting for a human, or a broker that answered with an
//! error) means the process does not start: falling back to the VM's
//! logins then would undo a containment (INV-18). Only a broker that
//! cannot be reached, or one without a gateway, leaves the VM's logins.

use agent_auth_client::{BrokerClient, ClientError};
use agent_auth_core::{Platform, RequestStatus};
use agent_auth_crypto::Secret;

use super::{Sandboxd, locked};
use crate::host::Host;
use crate::runtime::{GATEWAY_KEY_ENV, SpawnContext};
use crate::store::AgentRecord;

/// How long a gateway grant is asked for.
pub const GATEWAY_GRANT: &str = "24h";
/// A key this close to its end is replaced.
pub const GATEWAY_MARGIN_SECS: f64 = 2.0 * 3600.0;

/// An agent's gateway key. `Debug` leaves the key out.
#[derive(Clone)]
pub struct GatewayKey {
    pub url: String,
    pub key: Secret<String>,
    pub expires: f64,
}

impl std::fmt::Debug for GatewayKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayKey")
            .field("url", &self.url)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// The broker has a gateway but no key for this agent: the process must
/// not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NoModelKey(pub String);

/// Seconds since the epoch, as the Python's `datetime.timestamp()`.
fn epoch(t: time::OffsetDateTime) -> f64 {
    // The difference of two valid datetimes always fits a Duration.
    #[allow(clippy::arithmetic_side_effects)]
    let since = t - time::OffsetDateTime::UNIX_EPOCH;
    since.as_seconds_f64()
}

impl<H: Host> Sandboxd<H> {
    /// A broker client acting as `rec` (with `session`, if given).
    pub(crate) fn client(&self, rec: &AgentRecord, session: Option<&str>) -> BrokerClient {
        BrokerClient::with_http(
            self.http.clone(),
            agent_auth_client::Config {
                base_url: Some(self.config.broker_url.as_str().to_owned()),
                api_key: Some(rec.api_key.expose().clone()),
                admin_token: None,
                session_id: session.map(str::to_owned),
            },
        )
    }

    /// The gateway and this agent's key for it; `None`: no gateway (or the
    /// broker is unreachable), so the VM's own logins.
    pub(crate) async fn gateway(
        &self,
        rec: &AgentRecord,
    ) -> Result<Option<GatewayKey>, NoModelKey> {
        let now = crate::store::now();
        if let Some(held) = locked(&self.gateway_keys).get(&rec.name).cloned()
            && held.expires - now > GATEWAY_MARGIN_SECS
        {
            return Ok(Some(held));
        }
        let client = self.client(rec, None);
        let catalog = match client.catalog().await {
            Ok(c) => c,
            // The broker answered and refused this agent (a disabled key):
            // not a reason to run it on the VM's logins.
            Err(e @ ClientError::Broker { .. }) => return Err(NoModelKey(e.to_string())),
            Err(e) => {
                tracing::warn!(
                    "model gateway for {}: broker unreachable ({e}); using the VM's logins",
                    rec.name
                );
                return Ok(None);
            }
        };
        let Some(gw) = catalog
            .platforms
            .iter()
            .find(|p| p.platform == Platform::Models)
            .and_then(|p| p.gateway.clone())
            .filter(|g| !g.url.is_empty())
        else {
            return Ok(None);
        };
        let key = self
            .gateway_key(&client, rec, &gw.name, now)
            .await
            .map_err(|e| match e {
                Fetch::NoKey(n) => n,
                Fetch::Client(e) => NoModelKey(e.to_string()),
            })?;
        locked(&self.gateway_keys).insert(rec.name.clone(), key.clone());
        Ok(Some(key))
    }

    async fn gateway_key(
        &self,
        client: &BrokerClient,
        rec: &AgentRecord,
        name: &str,
        now: f64,
    ) -> Result<GatewayKey, Fetch> {
        let grants = client.grants("active").await?;
        let found = grants.iter().find(|g| {
            g.platform == Platform::Models
                && g.resource == name
                && epoch(g.expires_at) - now > GATEWAY_MARGIN_SECS
        });
        let grant_id = match found {
            Some(g) => g.id,
            None => {
                let justification = format!(
                    "Model calls for {}'s conversations in the agent VM on {}.",
                    rec.name, self.config.name
                );
                let mut made = client
                    .request_access(
                        "models",
                        "use",
                        name,
                        &justification,
                        GATEWAY_GRANT,
                        None,
                        None,
                    )
                    .await?;
                if agent_auth_client::poll::is_waiting(made.status) {
                    made = client.wait(&made.id.to_string(), 20.0).await?;
                }
                match (made.status, made.grant_id) {
                    (RequestStatus::Granted, Some(g)) => g,
                    (status, _) => {
                        return Err(Fetch::NoKey(NoModelKey(format!(
                            "request {} is {}: {}",
                            made.id,
                            status.as_str(),
                            made.decision_reason.unwrap_or_default()
                        ))));
                    }
                }
            }
        };
        let cred = client.credential(&grant_id.to_string()).await?;
        let (Some(value), Some(url)) = (cred.value, cred.url) else {
            return Err(Fetch::NoKey(NoModelKey(
                "the broker gave no key".to_owned(),
            )));
        };
        Ok(GatewayKey {
            url,
            key: Secret::new(value.expose().to_owned()),
            expires: cred.expires_at.map_or(now + 3600.0, epoch),
        })
    }

    /// Point a process at the gateway with the agent's key. `Ok(false)`: no
    /// gateway, the VM's logins. `Err`: the process must not start.
    pub(crate) async fn use_gateway(
        &self,
        ctx: &mut SpawnContext,
        rec: &AgentRecord,
    ) -> Result<bool, NoModelKey> {
        if self.contained(&rec.name) {
            return Err(NoModelKey(format!("{} is contained", rec.name)));
        }
        let Some(gw) = self.gateway(rec).await? else {
            return Ok(false);
        };
        gateway_env(&mut ctx.env, &gw);
        ctx.model_gateway = Some(gw.url.clone());
        Ok(true)
    }
}

/// Calls go to the gateway with the agent's key, not the VM's logins.
pub(crate) fn gateway_env(env: &mut std::collections::BTreeMap<String, String>, gw: &GatewayKey) {
    env.remove("CLAUDE_CODE_OAUTH_TOKEN");
    env.insert("ANTHROPIC_BASE_URL".to_owned(), gw.url.clone());
    env.insert("ANTHROPIC_AUTH_TOKEN".to_owned(), gw.key.expose().clone());
    env.insert(GATEWAY_KEY_ENV.to_owned(), gw.key.expose().clone());
}

enum Fetch {
    NoKey(NoModelKey),
    Client(ClientError),
}

impl From<ClientError> for Fetch {
    fn from(e: ClientError) -> Self {
        Fetch::Client(e)
    }
}
