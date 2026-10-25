//! Which a2a grant lets one agent talk to another (a2a spec §3.3).

use agent_auth_core::{AgentId, Authority};
use agent_auth_store::grants::{self, GrantRow};
use agent_auth_store::{StoreError, Tx};
use time::OffsetDateTime;

/// Does this grant's topic glob admit `topic`? An unscoped grant (`*`)
/// admits anything, including no topic; a scoped one only an explicit
/// topic matching its glob, so omitting the topic never widens a grant.
#[must_use]
pub(crate) fn admits(grant: &GrantRow, topic: Option<&str>) -> bool {
    let Authority::A2a { topic: pattern } = &grant.authority else {
        return false;
    };
    match (pattern, topic) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(glob), Some(t)) => glob.matches(t),
    }
}

/// The first active, unexpired a2a grant of `sender` to talk to the agent
/// named `recipient` whose topic glob admits `topic` (`any_topic`: any
/// grant at all, for the informational check).
pub async fn check_grant(
    tx: &Tx<'_>,
    sender: AgentId,
    recipient: &str,
    topic: Option<&str>,
    any_topic: bool,
    now: OffsetDateTime,
) -> Result<Option<GrantRow>, StoreError> {
    let live = grants::live_a2a(tx, sender, recipient, now).await?;
    Ok(live.into_iter().find(|g| any_topic || admits(g, topic)))
}
