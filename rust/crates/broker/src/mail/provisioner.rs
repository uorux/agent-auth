//! Platform "mail" (upstream `provisioners/mail.py`): an address the broker
//! reads and sends on for the agent (`crate::mail`). Nothing is handed
//! out: the credential says how to use the gateway.
//!
//! capability `read` | `send` | `read+send`, resource = a SimpleLogin alias
//! or a mailbox's own address (only with `direct: true`, and only with
//! correspondents), scope `{"topic", "correspondents", "since"}`.
//! capability `create`, resource = a domain in `simplelogin.create_domains`,
//! scope `{"prefix"?, ...}`: a new alias, read and sent on by this grant
//! (the grant's resource becomes the alias).
//!
//! Unlike the other validators, this one may call SimpleLogin (to tell an
//! alias that exists from one that does not, as the Python did); its
//! answers are cached for an hour.

use std::sync::Arc;

use agent_auth_core::mail::{MailAction, server_term};
use agent_auth_core::{Authority, Platform};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::{MailCatalog, PlatformCatalog};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{Mail, Mode};
use crate::provisioners::common::repr;
use crate::provisioners::{
    Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

#[derive(Debug, Clone)]
pub struct MailProvisioner {
    pub gateway: Arc<Mail>,
}

fn refuse(text: impl Into<String>) -> Result<Result<Validated, Refused>, StoreError> {
    Ok(Err(Refused(text.into())))
}

impl Provisioner for MailProvisioner {
    fn platform(&self) -> Platform {
        Platform::Mail
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let Authority::Mail(scope) = &spec.authority else {
            return refuse("mail capability is one of read, send, read+send, create");
        };
        let config = self.gateway.config();
        let mut resource = spec.resource.trim().to_lowercase();
        let (mode, address) = if scope.action == MailAction::Create {
            let domains = config
                .simplelogin
                .as_ref()
                .map(|sl| sl.create_domains.clone())
                .unwrap_or_default();
            if domains.is_empty() {
                return refuse("creating aliases is not enabled on this broker");
            }
            if !domains.contains(&resource) {
                return refuse(format!(
                    "aliases are created on {} (the resource is the domain)",
                    domains.join(", ")
                ));
            }
            (Mode::Alias, None)
        } else {
            match self.gateway.resolve(&resource).await {
                Ok(target) => {
                    resource = target.address.clone();
                    (target.mode, Some(target.address))
                }
                Err(e) => return refuse(e),
            }
        };
        // A new alias's name isn't known until it exists (without a
        // prefix): the restrictions on it apply from then on, in the
        // gateway.
        let probe = address
            .clone()
            .or_else(|| scope.prefix.as_ref().map(|p| format!("{p}@{resource}")));
        let restrictions = probe
            .as_deref()
            .map(|p| config.restrictions_for(p))
            .unwrap_or_default();
        for r in &restrictions {
            if let Some(caps) = &r.capabilities
                && !caps.contains(&scope.action)
            {
                let allowed: Vec<&str> = caps.iter().map(|c| c.as_str()).collect();
                return refuse(format!(
                    "{}: the operator allows only {} on it",
                    probe.as_deref().unwrap_or(""),
                    if allowed.is_empty() {
                        "nothing".to_owned()
                    } else {
                        allowed.join(", ")
                    }
                ));
            }
        }
        let has_topics = scope.topic.is_some() || restrictions.iter().any(|r| r.topic.is_some());
        let has_layers = !scope.correspondents.is_empty()
            || restrictions.iter().any(|r| !r.correspondents.is_empty());
        if has_topics && !self.gateway.has_judge() {
            return refuse(
                "a topic needs the mail judge, and this broker has no model (OPENROUTER_API_KEY)",
            );
        }
        if mode == Mode::Mailbox {
            let address = address.as_deref().unwrap_or("");
            if !has_layers {
                return refuse(format!(
                    "{address} is a mailbox: name its correspondents (scope correspondents, e.g. [\"*@airline.com\"])"
                ));
            }
            let loose: Vec<&String> = scope
                .correspondents
                .iter()
                .filter(|g| server_term(g).is_none())
                .collect();
            if !loose.is_empty() {
                return refuse(format!(
                    "a mailbox grant's correspondents each need a domain without wildcards: {}",
                    agent_auth_core::mail::repr_list(&loose)
                ));
            }
        }
        let what = match scope.action {
            MailAction::Read => "reads",
            MailAction::Send => "sends as",
            MailAction::ReadSend => "reads and sends as",
            MailAction::Create => "creates a new alias, then reads and sends as it,",
        };
        let place = match (mode, &address) {
            (Mode::Mailbox, Some(a)) => format!("the mailbox {a} itself (filtered)"),
            (_, Some(a)) => format!("a SimpleLogin alias {a}"),
            (_, None) => format!("a new SimpleLogin alias on {resource}"),
        };
        let mut notes = vec![format!(
            "the broker {what} {place}; the agent never holds a mailbox credential"
        )];
        for r in &restrictions {
            let mut bits = Vec::new();
            if let Some(t) = &r.topic {
                bits.push(format!("topic {}", repr(t)));
            }
            if !r.correspondents.is_empty() {
                bits.push(format!("only with {}", r.correspondents.join(", ")));
            }
            if !bits.is_empty() {
                notes.push(format!(
                    "operator's restriction on {}: {}",
                    r.address,
                    bits.join("; ")
                ));
            }
        }
        if self.gateway.has_judge() {
            notes.push(format!(
                "each message is screened by the mail judge {}{}",
                if has_topics {
                    "(topic and prompt injection)"
                } else {
                    "(prompt injection)"
                },
                if scope.action.sends() {
                    "; each send is reviewed"
                } else {
                    ""
                }
            ));
        } else {
            notes.push(
                "no mail judge: prompt-injection screening is heuristic only, and every send waits for a human"
                    .to_owned(),
            );
        }
        Ok(Ok(Validated {
            resource,
            authority: spec.authority,
            notes,
        }))
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let g = grant.grant();
        let Authority::Mail(authority) = &g.authority else {
            return Err(ProvisionError::failed("not a mail grant"));
        };
        if authority.action != MailAction::Create {
            let target =
                self.gateway.resolve(&g.resource).await.map_err(|e| {
                    ProvisionError::failed(format!("cannot grant {}: {e}", g.resource))
                })?;
            return Ok(json!({"mode": target.mode.as_str(), "address": target.address}));
        }
        let config = self.gateway.config();
        let (Some(sl_config), Some(sl)) = (&config.simplelogin, self.gateway.simplelogin()) else {
            return Err(ProvisionError::failed(
                "creating aliases is not enabled on this broker",
            ));
        };
        let mailbox = config
            .mailboxes
            .get(&sl_config.mailbox)
            .map(|b| b.address.clone())
            .unwrap_or_default();
        let agent = agents::get(tx, g.agent_id)
            .await
            .map_err(|e| ProvisionError::failed(format!("database: {e}")))?;
        let name = agent.map_or_else(|| "?".to_owned(), |a| a.name);
        let alias = sl
            .create(
                &g.resource,
                authority.prefix.as_deref(),
                &format!("made for agent {name} by agent-auth (grant {})", g.id),
                &mailbox,
            )
            .await
            .map_err(|e| ProvisionError::failed(e.0))?;
        // The grant is for the alias from now on.
        agent_auth_store::mail::set_created_alias(tx, grant, &alias.email)
            .await
            .map_err(|e| ProvisionError::failed(format!("database: {e}")))?;
        Ok(
            json!({"mode": "alias", "address": alias.email, "created_on": g.resource,
                  "alias_id": alias.id}),
        )
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        // Nothing exists outside the broker. A created alias stays (things
        // were signed up with it); the gateway stops reading and sending.
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let g = issuable.grant();
        let Authority::Mail(authority) = &g.authority else {
            return Err(ProvisionError::failed("not a mail grant"));
        };
        let c = self.gateway.constraints(&g.resource, authority);
        let mut limits = Vec::new();
        if !c.topics.is_empty() {
            let topics: Vec<String> = c.topics.iter().map(|t| repr(t)).collect();
            limits.push(format!("only mail about: {}", topics.join(" AND ")));
        }
        if !c.layers.is_empty() {
            let layers: Vec<String> = c
                .layers
                .iter()
                .map(|l| format!("({})", l.join(", ")))
                .collect();
            limits.push(format!("only with: {}", layers.join(" AND ")));
        }
        if let Some(since) = c.since {
            limits.push(format!(
                "since {}",
                agent_auth_core::mail::format_date(since)
            ));
        }
        let doing = match (c.ops.read, c.ops.send) {
            (true, true) => "read and send",
            (true, false) => "read",
            (false, true) => "send",
            (false, false) => "nothing (the operator's restrictions now allow neither)",
        };
        let note = format!(
            "No credential: the broker {doing} on {r} for you. Use mail_list / mail_read / mail_send / mail_attachment with grant_id {id} (HTTP: /v1/mail/{id}/...). {limits}Messages outside them never reach you; some are held for the operator.",
            r = g.resource,
            id = g.id,
            limits = if limits.is_empty() {
                String::new()
            } else {
                format!("Limits: {}. ", limits.join("; "))
            }
        );
        Ok(Credential {
            kind: crate::provisioners::CredentialKind::MailGateway,
            value: None,
            username: Some(g.resource.clone()),
            url: None,
            expires_at: Some(g.expires_at),
            note: Some(note),
            properties: None,
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let config = self.gateway.config();
        let sl = config.simplelogin.as_ref();
        let create = sl.is_some_and(|s| !s.create_domains.is_empty());
        let mut c = PlatformCatalog::new(
            Platform::Mail,
            "read | send | read+send (scope {\"topic\"?, \"correspondents\"?, \"since\"?}); create (a new alias; resource = a domain below)",
            "<SimpleLogin alias address>, or a mailbox listed under direct (correspondents required)",
        );
        let mut caps: Vec<String> = ["read", "send", "read+send"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        if create {
            caps.push("create".to_owned());
        }
        c.capabilities = Some(caps);
        let mut direct: Vec<String> = config
            .mailboxes
            .values()
            .filter(|b| b.direct)
            .map(|b| b.address.clone())
            .collect();
        direct.sort();
        c.mail = Some(MailCatalog {
            simplelogin: sl.is_some(),
            create_domains: sl.map(|s| s.create_domains.clone()).unwrap_or_default(),
            direct,
            screened_by_model: self.gateway.has_judge(),
        });
        serde_json::to_value(c).ok()
    }
}
