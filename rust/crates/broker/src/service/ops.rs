//! The spine as the Discord bot sees it (`discord::ops`): decisions,
//! revocations and containment, each for a [`HumanDecider`].

use agent_auth_core::{GrantId, HumanApproval, RequestId};
use agent_auth_store::lockdown::{ContainmentEntry, ContainmentSource};
use agent_auth_store::requests::RequestRow;
use futures::future::BoxFuture;
use serde_json::Value;

use super::{HumanDecider, HumanDecision, RuleFromDecision};
use crate::containment;
use crate::discord::ops::{
    Contained, ContainmentOps, HostsOps, HumanDecision as BotDecision, OpError, RequestOps,
};
use crate::state::AppState;

/// The services the bot is attached to.
#[derive(Debug, Clone)]
pub struct SpineOps {
    state: AppState,
}

impl SpineOps {
    #[must_use]
    pub fn new(state: AppState) -> SpineOps {
        SpineOps { state }
    }
}

fn decision(d: BotDecision) -> HumanDecision {
    HumanDecision {
        approve: d.approve,
        reason: d.reason,
        duration_secs: d.duration_secs.map(|s| s.get()),
        resource_override: d.resource_override,
        scope_override: d.scope_override,
        rule: d.rule_action.map(|action| RuleFromDecision {
            action,
            resource_pattern: d.rule_resource_pattern,
            any_authority: d.rule_any_authority,
        }),
        totp: d.totp,
    }
}

fn op_error(e: impl std::fmt::Display) -> OpError {
    OpError(e.to_string())
}

impl RequestOps for SpineOps {
    fn decide<'a>(
        &'a self,
        who: &'a HumanDecider,
        request: RequestId,
        d: BotDecision,
        approval: Option<HumanApproval>,
    ) -> BoxFuture<'a, Result<RequestRow, OpError>> {
        Box::pin(async move {
            super::decide_attested(&self.state, request, who, decision(d), approval)
                .await
                .map_err(op_error)
        })
    }

    fn revoke_grant<'a>(
        &'a self,
        who: &'a HumanDecider,
        grant: GrantId,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), OpError>> {
        Box::pin(async move {
            super::revoke_grant(&self.state, grant, reason, who.label())
                .await
                .map(|_| ())
                .map_err(op_error)
        })
    }
}

impl ContainmentOps for SpineOps {
    fn contain<'a>(
        &'a self,
        who: &'a HumanDecider,
        r#match: Value,
        reason: &'a str,
        allow_all: bool,
    ) -> BoxFuture<'a, Result<Contained, OpError>> {
        Box::pin(async move {
            if !allow_all
                && containment::holds_everyone(&self.state, &r#match)
                    .await
                    .map_err(op_error)?
            {
                return Err(OpError(
                    "that holds every agent: choose the everyone option to mean it".to_owned(),
                ));
            }
            let out = containment::contain(
                &self.state,
                r#match,
                reason,
                "",
                who.label(),
                ContainmentSource::Operator,
            )
            .await
            .map_err(op_error)?;
            Ok(Contained {
                id: out.entry.id,
                agents: out.agents.len(),
                grants_revoked: usize::try_from(out.grants_revoked).unwrap_or(usize::MAX),
            })
        })
    }

    fn lift<'a>(
        &'a self,
        who: &'a HumanDecider,
        entry: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<ContainmentEntry>, OpError>> {
        Box::pin(async move {
            containment::lift_entries(&self.state, entry, who.label())
                .await
                .map_err(op_error)
        })
    }
}

/// hostexec is not part of this broker yet: no host line on cards.
impl HostsOps for SpineOps {
    fn host(&self, _name: &str) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async { None })
    }
}
