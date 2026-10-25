//! sandboxd's local APIs: JSON lines over unix sockets (sandboxd spec
//! §4.12), served by `agent_auth_daemon::localsock` with the caller's uid
//! from the kernel.
//!
//! - The agent socket (any uid may connect): the sandbox MCP's backend. A
//!   caller is the conversation whose token it presents, AND must be that
//!   conversation's unix user (INV-14): a token leaked to another project
//!   is useless. Orchestrator calls check it is the orchestrator.
//! - The operator socket (root only): `avm` and sandboxctl (INV-15).

use std::sync::Arc;

use agent_auth_daemon::localsock::{LocalApi, LocalError, Peer};
use agent_auth_wire::daemon::local::{AgentCall, OperatorCall};
use serde_json::{Map, Value, json};

use crate::daemon::{Sandboxd, SbxError};
use crate::host::Host;
use crate::names::ConvId;

/// The two secrets an operator may set.
pub const SECRETS: [&str; 2] = ["claude-oauth-token", "codex-auth.json"];

/// How long a mint asked for through the local APIs waits.
pub const MINT_WAIT: f64 = 120.0;

fn projects_json<H: Host>(s: &Sandboxd<H>) -> Value {
    Value::Array(
        s.store
            .projects()
            .into_iter()
            .map(|p| json!({"name": p.name, "uid": p.uid, "sealed": p.sealed, "created_at": p.created_at}))
            .collect(),
    )
}

/// The agent socket.
pub struct AgentApi<H: Host>(pub Arc<Sandboxd<H>>);

impl<H: Host> std::fmt::Debug for AgentApi<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentApi").finish_non_exhaustive()
    }
}

impl<H: Host> AgentApi<H> {
    /// One call, as the conversation `token` names, from `uid`.
    pub async fn handle(
        &self,
        method: &str,
        params: &Map<String, Value>,
        token: Option<&str>,
        uid: u32,
    ) -> Result<Value, String> {
        let s = &self.0;
        let conv = token
            .filter(|t| !t.is_empty())
            .and_then(|t| s.conversation_by_token(t))
            .ok_or_else(|| "unknown conversation token".to_owned())?;
        let rec = s
            .store
            .agent(&conv.agent)
            .ok_or_else(|| "unknown conversation token".to_owned())?;
        let is_orch = rec.name == s.orchestrator;
        let project = if is_orch { None } else { rec.project.clone() };
        let owner = s
            .project_uid(project.as_deref())
            .map_err(|e| e.api_text())?;
        if uid != owner {
            return Err("this token belongs to another user's conversation".to_owned());
        }
        let call = AgentCall::parse(method, params)?;
        if call.orchestrator_only() && !is_orch {
            return Err(format!("{} is for the orchestrator", call.method()));
        }
        let out = match call {
            AgentCall::Whoami => json!({
                "agent": rec.name,
                "conversation": conv.id.as_str(),
                "project": project,
                "host": s.config.name.as_str(),
                "orchestrator": is_orch,
            }),
            AgentCall::ProjectList => projects_json(s),
            AgentCall::Conversations => Value::Array(
                s.store
                    .conversations(Some(&rec.name), false)
                    .iter()
                    .map(crate::store::Conversation::public)
                    .collect(),
            ),
            AgentCall::Inbox { drain } => {
                let items = if drain {
                    s.store.drain(&conv.id)
                } else {
                    s.store.peek(&conv.id)
                }
                .map_err(|e| SbxError::from(e).api_text())?;
                json!(items)
            }
            AgentCall::ProjectCreate { name } => {
                let out = s.create_project(&name).map_err(|e| e.api_text())?;
                let created = out
                    .get("project")
                    .and_then(Value::as_str)
                    .unwrap_or(&name)
                    .to_owned();
                s.open_project_for_setup(&created)
                    .await
                    .map_err(|e| e.api_text())?;
                out
            }
            AgentCall::ProjectSeal { name } => {
                s.seal_project(&name).await.map_err(|e| e.api_text())?;
                json!({"sealed": name})
            }
            AgentCall::AgentMint {
                runtime,
                project,
                why,
            } => s
                .mint(&runtime, &project, &why, MINT_WAIT)
                .await
                .map_err(|e| e.api_text())?,
            AgentCall::AgentSpawn { agent, prompt } => s
                .spawn_conversation(&agent, &prompt, &format!("spawn:{}", rec.name), "")
                .await
                .map_err(|e| e.api_text())?
                .public(),
        };
        Ok(out)
    }
}

impl<H: Host> LocalApi for AgentApi<H> {
    async fn call(
        &self,
        method: &str,
        params: Map<String, Value>,
        token: Option<Value>,
        peer: Peer,
    ) -> Result<Value, LocalError> {
        let token = token.as_ref().and_then(Value::as_str);
        self.handle(method, &params, token, peer.uid)
            .await
            .map_err(LocalError)
    }
}

/// The operator socket.
pub struct OperatorApi<H: Host>(pub Arc<Sandboxd<H>>);

impl<H: Host> std::fmt::Debug for OperatorApi<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorApi").finish_non_exhaustive()
    }
}

fn conv_id(text: &str) -> Result<ConvId, String> {
    ConvId::parse(text).ok_or_else(|| format!("no open conversation {text}"))
}

impl<H: Host> OperatorApi<H> {
    pub async fn handle(
        &self,
        method: &str,
        params: &Map<String, Value>,
        uid: u32,
    ) -> Result<Value, String> {
        if uid != 0 {
            return Err("operators only".to_owned());
        }
        let s = &self.0;
        let text = |e: SbxError| e.api_text();
        let out = match OperatorCall::parse(method, params)? {
            OperatorCall::Status => Value::Object(s.status()),
            OperatorCall::Agents => Value::Array(
                s.store
                    .agents()
                    .into_iter()
                    .map(|a| json!({"name": a.name, "runtime": a.runtime, "project": a.project}))
                    .collect(),
            ),
            OperatorCall::Projects => projects_json(s),
            OperatorCall::Conversations { all, project } => {
                let mut convs = s.store.conversations(None, all);
                if let Some(p) = project {
                    let names: Vec<String> = s
                        .store
                        .agents()
                        .into_iter()
                        .filter(|a| a.project.as_deref() == Some(p.as_str()))
                        .map(|a| a.name)
                        .collect();
                    convs.retain(|c| names.contains(&c.agent));
                }
                Value::Array(
                    convs
                        .iter()
                        .map(crate::store::Conversation::public)
                        .collect(),
                )
            }
            OperatorCall::ProjectCreate { name, sealed } => {
                let out = s.create_project(&name).map_err(text)?;
                if sealed {
                    s.seal_project(&name).await.map_err(text)?;
                } else {
                    s.open_project_for_setup(&name).await.map_err(text)?;
                }
                out
            }
            OperatorCall::Mint {
                runtime,
                project,
                why,
            } => s
                .mint(&runtime, &project, &why, MINT_WAIT)
                .await
                .map_err(text)?,
            OperatorCall::New {
                agent,
                prompt,
                title,
                attach,
            } => {
                if s.store.agent(&agent).is_none() {
                    return Err(format!("no key for {agent} in this VM (mint it first)"));
                }
                let conv = s
                    .new_conversation(&agent, "operator", &title, "headless")
                    .await
                    .map_err(text)?;
                if let Some(prompt) = prompt {
                    s.deliver(&conv.id, &prompt).await.map_err(text)?;
                }
                let now = s.store.conversation(&conv.id).unwrap_or(conv);
                if attach {
                    let info = s.attach(&now.id, false).await.map_err(text)?;
                    json!({"conversation": now.public(), "attach": info})
                } else {
                    json!({"conversation": now.public()})
                }
            }
            OperatorCall::Attach { conversation, now } => s
                .attach(&conv_id(&conversation)?, now)
                .await
                .map_err(text)?,
            OperatorCall::Send {
                conversation,
                text: t,
            } => {
                s.deliver(&conv_id(&conversation)?, &t)
                    .await
                    .map_err(text)?;
                json!({"sent": true})
            }
            OperatorCall::Stop { conversation } => {
                s.stop(&conv_id(&conversation)?).await;
                json!({"parked": conversation})
            }
            OperatorCall::Close { conversation } => {
                s.close(&conv_id(&conversation)?).await.map_err(text)?;
                json!({"closed": conversation})
            }
            OperatorCall::LogPath { conversation } => {
                json!(s.log_path(&conv_id(&conversation)?).display().to_string())
            }
            OperatorCall::Shell { project } => {
                let uid = s.project_uid(Some(&project)).map_err(text)?;
                let (work, _, _) = s.paths(Some(&project));
                json!({"uid": uid, "workdir": work.display().to_string()})
            }
            OperatorCall::SecretSet { name, value } => {
                if !SECRETS.contains(&name.as_str()) {
                    return Err(format!("secrets: {}", SECRETS.join(", ")));
                }
                let dir = s.config.secrets_dir();
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)
                    .map_err(|e| e.to_string())?;
                crate::store::write_atomic(&dir.join(&name), value.as_bytes())
                    .map_err(|e| format!("internal error: {e}"))?;
                json!({"stored": name})
            }
        };
        Ok(out)
    }
}

use std::os::unix::fs::DirBuilderExt as _;

impl<H: Host> LocalApi for OperatorApi<H> {
    async fn call(
        &self,
        method: &str,
        params: Map<String, Value>,
        _token: Option<Value>,
        peer: Peer,
    ) -> Result<Value, LocalError> {
        self.handle(method, &params, peer.uid)
            .await
            .map_err(LocalError)
    }
}
