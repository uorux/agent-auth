//! The approval gate (spec §10.3): before a human's approval of a hostexec
//! request takes effect, would the host accept it? With a TOTP code, the
//! host verifies and spends it here, for this exact request (its digest and
//! tier). A refusal leaves the request pending (INV-29, INV-30).
//!
//! The spine's `decide` calls [`HostExec::approval_gate`] for platform
//! hostexec, with the final (possibly edited) resource and authority and
//! the duration it will approve; the code is relayed and never stored.

use agent_auth_core::authority::HostexecAuthority;
use agent_auth_core::hostexec::{CommandSpec, JobSpec, ShellSpec};
use agent_auth_core::{Authority, RequestId};
use agent_auth_crypto::digest::digest;
use serde_json::json;

use super::{CALL_TIMEOUT, HostExec};

/// Why the gate refused: the text becomes the decision's error (the
/// Python's `TransitionError`), and the request stays where it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct GateRefusal(pub String);

/// The longest a human may approve (`HUMAN_MAX_DURATION_SECS`): a shell's
/// duration is capped by it here and in `decide` alike.
pub const HUMAN_MAX_DURATION_SECS: u32 = 365 * 86400;

impl HostExec {
    /// The spec a human approval would be for, normalized exactly as the
    /// grant will be started with: the same validate → spec path as
    /// provisioning, so the digests match.
    pub async fn final_spec(
        &self,
        resource: &str,
        authority: &Authority,
        approved_duration_secs: u32,
    ) -> Result<JobSpec, GateRefusal> {
        let validated = async {
            let tx = self.store.begin().await?;
            let v = self.validate(&tx, resource, authority).await?;
            tx.commit().await?;
            Ok::<_, agent_auth_store::StoreError>(v)
        }
        .await
        .map_err(|e| GateRefusal(format!("rejected by validator: {e}")))?
        .map_err(|r| GateRefusal(format!("rejected by validator: {}", r.0)))?;
        let host = validated.resource;
        let Authority::Hostexec(h) = &validated.authority else {
            return Err(GateRefusal(
                "rejected by validator: not a host command".into(),
            ));
        };
        match h {
            HostexecAuthority::Shell { tier, .. } => {
                let duration = approved_duration_secs.min(HUMAN_MAX_DURATION_SECS);
                ShellSpec::new(&host, *tier, duration)
                    .map(JobSpec::Shell)
                    .map_err(|e| GateRefusal(format!("rejected by validator: {e}")))
            }
            _ => CommandSpec::from_authority(&host, h)
                .map(JobSpec::Command)
                .map_err(|e| GateRefusal(format!("rejected by validator: {e}"))),
        }
    }

    /// The gate. `totp`: the code the human typed (relayed to the host's
    /// `<tier>-direct` secret with this request's digest, or for a shell
    /// its shell or arm secret; never stored). `at_its_desk`: the host's own
    /// desk answered Allow and that hostd recorded it as its own approval
    /// (a shell then needs no code: `shell.open` finds that approval).
    pub async fn approval_gate(
        &self,
        request: RequestId,
        resource: &str,
        authority: &Authority,
        approved_duration_secs: u32,
        totp: Option<&str>,
        at_its_desk: bool,
    ) -> Result<(), GateRefusal> {
        let spec = self
            .final_spec(resource, authority, approved_duration_secs)
            .await?;
        let host = spec.host().to_owned();
        let shell = matches!(spec, JobSpec::Shell(_));
        let totp = totp.filter(|c| !c.is_empty());
        if shell && totp.is_none() && !at_its_desk {
            return Err(GateRefusal(
                "a shell is approved with a TOTP code (Approve with TOTP) or at its host's desk"
                    .into(),
            ));
        }
        let value = spec.to_json();
        let host_err = |e: crate::daemons::CallError| GateRefusal(format!("{host}: {e}"));
        match &spec {
            JobSpec::Shell(s) => {
                // Everything the host would refuse, before a code is spent.
                self.call(
                    &host,
                    json!({"type": "hostexec.precheck", "kind": "shell",
                           "tier": s.tier().as_str(), "duration": s.duration()}),
                    CALL_TIMEOUT,
                )
                .await
                .map_err(host_err)?;
            }
            JobSpec::Command(_) => {
                self.call(
                    &host,
                    json!({"type": "hostexec.precheck", "job_id": request.to_string(),
                           "spec": value, "source": "human", "totp": totp.is_some()}),
                    CALL_TIMEOUT,
                )
                .await
                .map_err(host_err)?;
            }
        }
        if let Some(code) = totp {
            let d = digest(&value).map_err(|e| GateRefusal(format!("{host}: {e}")))?;
            self.call(
                &host,
                json!({"type": "hostexec.authorize", "job_id": request.to_string(),
                       "tier": spec.tier().as_str(), "digest": d, "totp": code,
                       "shell": shell}),
                CALL_TIMEOUT,
            )
            .await
            .map_err(host_err)?;
        }
        Ok(())
    }
}

/// The spine's approval gate for platform hostexec: the final resource and
/// authority as `decide` will validate them (the human's edits applied),
/// the duration it will approve, and the TOTP code to relay.
#[must_use]
pub fn approval_gate_hook(hostexec: std::sync::Arc<HostExec>) -> crate::service::ApprovalGate {
    std::sync::Arc::new(move |st, request, _agent, decision| {
        let hostexec = std::sync::Arc::clone(&hostexec);
        Box::pin(async move {
            let current = request
                .authority
                .clone()
                .ok_or_else(|| "request has no authority".to_owned())?;
            let resource = decision
                .resource_override
                .clone()
                .unwrap_or_else(|| request.resource.clone());
            let authority = match &decision.scope_override {
                Some(scope) => Authority::from_wire(request.platform, &current.capability(), scope)
                    .map_err(|e| format!("edited approval rejected by validator: {e}"))?,
                None => current,
            };
            // As `decide` computes the approved duration.
            let max = agent_auth_core::DurationSecs::MAX.get();
            let duration = match decision.duration_secs {
                Some(d) => d,
                None => st
                    .policy
                    .cap_duration(
                        agent_auth_core::DurationSecs::from_secs(i64::from(
                            request.requested_duration_secs.clamp(1, max),
                        ))
                        .unwrap_or(agent_auth_core::DurationSecs::MAX),
                        None,
                    )
                    .get(),
            }
            .clamp(1, HUMAN_MAX_DURATION_SECS);
            hostexec
                .approval_gate(
                    request.id,
                    &resource,
                    &authority,
                    duration,
                    decision.totp.as_deref(),
                    decision.desk_host.as_deref() == Some(request.resource.as_str()),
                )
                .await
                .map_err(|e| e.0)
        })
    })
}
