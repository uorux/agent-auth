//! The daemons' local unix-socket APIs (daemons-hostd spec §12.1,
//! sandboxd spec §4.12): one JSON object per line,
//! `{"method": str, "params": object, "token": str|null}`, and sandboxd's
//! calls parsed into types.
//!
//! Stricter than the Python: parameters must have their JSON types (the
//! Python called `str()` on whatever came, so `{"name": 5}` was project
//! `"5"`), unknown parameters are refused, and strings are bounded. A
//! missing parameter still answers as the Python's `KeyError` did
//! (`internal error: 'name'`).

use serde_json::{Map, Value};

/// One request line, framed.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalRequest {
    pub method: String,
    pub params: Map<String, Value>,
    /// Anything but null (an agent API token is a string).
    pub token: Option<Value>,
}

/// Read one request line: `bad request` for anything but an object with a
/// string `method`; `params must be an object` (null is `{}`).
pub fn parse_request(line: &[u8]) -> Result<LocalRequest, String> {
    let req: Value = serde_json::from_slice(line).map_err(|_| "bad request".to_owned())?;
    let Value::Object(mut req) = req else {
        return Err("bad request".to_owned());
    };
    let Some(Value::String(method)) = req.remove("method") else {
        return Err("bad request".to_owned());
    };
    let params = match req.remove("params") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(p)) => p,
        Some(_) => return Err("params must be an object".to_owned()),
    };
    let token = req.remove("token").filter(|t| !t.is_null());
    Ok(LocalRequest {
        method,
        params,
        token,
    })
}

/// The longest name-like parameter (projects, agents, runtimes, ids).
pub const MAX_NAME: usize = 256;
/// The longest `why`.
pub const MAX_WHY: usize = 4000;

struct Params<'a> {
    params: &'a Map<String, Value>,
}

impl Params<'_> {
    fn check_known(&self, known: &[&str]) -> Result<(), String> {
        match self.params.keys().find(|k| !known.contains(&k.as_str())) {
            Some(k) => Err(format!(
                "unknown parameter '{}'",
                k.chars().take(64).collect::<String>()
            )),
            None => Ok(()),
        }
    }

    fn opt_str(&self, key: &str, max: usize) -> Result<Option<String>, String> {
        match self.params.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.chars().count() <= max => Ok(Some(s.clone())),
            Some(Value::String(_)) => Err(format!("{key} is longer than {max} characters")),
            Some(_) => Err(format!("{key} must be a string")),
        }
    }

    fn str(&self, key: &str, max: usize) -> Result<String, String> {
        if !self.params.contains_key(key) {
            return Err(format!("internal error: '{key}'"));
        }
        self.opt_str(key, max)?
            .ok_or_else(|| format!("{key} must be a string"))
    }

    fn flag(&self, key: &str, default: bool) -> Result<bool, String> {
        match self.params.get(key) {
            None => Ok(default),
            Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(format!("{key} must be true or false")),
        }
    }
}

/// What an agent may ask over the agent socket (as its conversation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCall {
    Whoami,
    ProjectList,
    Conversations,
    Inbox {
        drain: bool,
    },
    ProjectCreate {
        name: String,
    },
    ProjectSeal {
        name: String,
    },
    AgentMint {
        runtime: String,
        project: String,
        why: String,
    },
    AgentSpawn {
        agent: String,
        prompt: String,
    },
}

impl AgentCall {
    /// Parse a method and its params.
    pub fn parse(method: &str, params: &Map<String, Value>) -> Result<AgentCall, String> {
        let p = Params { params };
        let call = match method {
            "whoami" => {
                p.check_known(&[])?;
                AgentCall::Whoami
            }
            "project_list" => {
                p.check_known(&[])?;
                AgentCall::ProjectList
            }
            "conversations" => {
                p.check_known(&[])?;
                AgentCall::Conversations
            }
            "inbox" => {
                p.check_known(&["drain"])?;
                AgentCall::Inbox {
                    drain: p.flag("drain", false)?,
                }
            }
            "project_create" => {
                p.check_known(&["name"])?;
                AgentCall::ProjectCreate {
                    name: p.str("name", MAX_NAME)?,
                }
            }
            "project_seal" => {
                p.check_known(&["name"])?;
                AgentCall::ProjectSeal {
                    name: p.str("name", MAX_NAME)?,
                }
            }
            "agent_mint" => {
                p.check_known(&["runtime", "project", "why"])?;
                AgentCall::AgentMint {
                    runtime: p.str("runtime", MAX_NAME)?,
                    project: p.str("project", MAX_NAME)?,
                    why: p.opt_str("why", MAX_WHY)?.unwrap_or_default(),
                }
            }
            "agent_spawn" => {
                p.check_known(&["agent", "prompt"])?;
                AgentCall::AgentSpawn {
                    agent: p.str("agent", MAX_NAME)?,
                    prompt: p.str("prompt", usize::MAX)?,
                }
            }
            other => return Err(format!("unknown method '{}'", short(other))),
        };
        Ok(call)
    }

    /// The method's name.
    #[must_use]
    pub fn method(&self) -> &'static str {
        match self {
            AgentCall::Whoami => "whoami",
            AgentCall::ProjectList => "project_list",
            AgentCall::Conversations => "conversations",
            AgentCall::Inbox { .. } => "inbox",
            AgentCall::ProjectCreate { .. } => "project_create",
            AgentCall::ProjectSeal { .. } => "project_seal",
            AgentCall::AgentMint { .. } => "agent_mint",
            AgentCall::AgentSpawn { .. } => "agent_spawn",
        }
    }

    /// Only the VM's orchestrator may make it (INV-14).
    #[must_use]
    pub fn orchestrator_only(&self) -> bool {
        matches!(
            self,
            AgentCall::ProjectCreate { .. }
                | AgentCall::ProjectSeal { .. }
                | AgentCall::AgentMint { .. }
                | AgentCall::AgentSpawn { .. }
        )
    }
}

fn short(s: &str) -> String {
    s.chars().take(64).collect()
}

/// The operator's calls (root only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorCall {
    Status,
    Agents,
    Projects,
    Conversations {
        all: bool,
        project: Option<String>,
    },
    ProjectCreate {
        name: String,
        sealed: bool,
    },
    Mint {
        runtime: String,
        project: String,
        why: String,
    },
    New {
        agent: String,
        prompt: Option<String>,
        title: String,
        attach: bool,
    },
    Attach {
        conversation: String,
        now: bool,
    },
    Send {
        conversation: String,
        text: String,
    },
    Stop {
        conversation: String,
    },
    Close {
        conversation: String,
    },
    LogPath {
        conversation: String,
    },
    Shell {
        project: String,
    },
    SecretSet {
        name: String,
        value: String,
    },
}

impl OperatorCall {
    pub fn parse(method: &str, params: &Map<String, Value>) -> Result<OperatorCall, String> {
        let p = Params { params };
        let conv = |p: &Params<'_>| p.str("conversation", MAX_NAME);
        let call = match method {
            "status" => {
                p.check_known(&[])?;
                OperatorCall::Status
            }
            "agents" => {
                p.check_known(&[])?;
                OperatorCall::Agents
            }
            "projects" => {
                p.check_known(&[])?;
                OperatorCall::Projects
            }
            "conversations" => {
                p.check_known(&["all", "project"])?;
                OperatorCall::Conversations {
                    all: p.flag("all", false)?,
                    project: p.opt_str("project", MAX_NAME)?.filter(|s| !s.is_empty()),
                }
            }
            "project_create" => {
                p.check_known(&["name", "sealed"])?;
                OperatorCall::ProjectCreate {
                    name: p.str("name", MAX_NAME)?,
                    sealed: p.flag("sealed", true)?,
                }
            }
            "mint" => {
                p.check_known(&["runtime", "project", "why"])?;
                OperatorCall::Mint {
                    runtime: p.str("runtime", MAX_NAME)?,
                    project: p.str("project", MAX_NAME)?,
                    why: p
                        .opt_str("why", MAX_WHY)?
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "operator request".to_owned()),
                }
            }
            "new" => {
                p.check_known(&["agent", "prompt", "title", "attach"])?;
                OperatorCall::New {
                    agent: p.str("agent", MAX_NAME)?,
                    prompt: p.opt_str("prompt", usize::MAX)?.filter(|s| !s.is_empty()),
                    title: p.opt_str("title", MAX_WHY)?.unwrap_or_default(),
                    attach: p.flag("attach", true)?,
                }
            }
            "attach" => {
                p.check_known(&["conversation", "now"])?;
                OperatorCall::Attach {
                    conversation: conv(&p)?,
                    now: p.flag("now", false)?,
                }
            }
            "send" => {
                p.check_known(&["conversation", "text"])?;
                OperatorCall::Send {
                    conversation: conv(&p)?,
                    text: p.str("text", usize::MAX)?,
                }
            }
            "stop" => {
                p.check_known(&["conversation"])?;
                OperatorCall::Stop {
                    conversation: conv(&p)?,
                }
            }
            "close" => {
                p.check_known(&["conversation"])?;
                OperatorCall::Close {
                    conversation: conv(&p)?,
                }
            }
            "log_path" => {
                p.check_known(&["conversation"])?;
                OperatorCall::LogPath {
                    conversation: conv(&p)?,
                }
            }
            "shell" => {
                p.check_known(&["project"])?;
                OperatorCall::Shell {
                    project: p.str("project", MAX_NAME)?,
                }
            }
            "secret_set" => {
                p.check_known(&["name", "value"])?;
                OperatorCall::SecretSet {
                    name: p.str("name", MAX_NAME)?,
                    value: p.str("value", usize::MAX)?,
                }
            }
            other => return Err(format!("unknown method '{}'", short(other))),
        };
        Ok(call)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => Map::new(),
        }
    }

    #[test]
    fn framing() {
        assert_eq!(parse_request(b"[1]").unwrap_err(), "bad request");
        assert_eq!(
            parse_request(b"{\"method\": 3}").unwrap_err(),
            "bad request"
        );
        assert_eq!(
            parse_request(b"{\"method\":\"x\",\"params\":[]}").unwrap_err(),
            "params must be an object"
        );
        let r = parse_request(b"{\"method\":\"whoami\",\"params\":null,\"token\":null}").unwrap();
        assert!(r.params.is_empty() && r.token.is_none());
    }

    #[test]
    fn agent_calls() {
        assert_eq!(
            AgentCall::parse("whoami", &Map::new()).unwrap(),
            AgentCall::Whoami
        );
        assert_eq!(
            AgentCall::parse("inbox", &obj(json!({"drain": true}))).unwrap(),
            AgentCall::Inbox { drain: true }
        );
        assert_eq!(
            AgentCall::parse("project_create", &Map::new()).unwrap_err(),
            "internal error: 'name'"
        );
        assert!(AgentCall::parse("project_create", &obj(json!({"name": 5}))).is_err());
        assert!(AgentCall::parse("whoami", &obj(json!({"x": 1}))).is_err());
        assert_eq!(
            AgentCall::parse("rm", &Map::new()).unwrap_err(),
            "unknown method 'rm'"
        );
        let mint = AgentCall::parse(
            "agent_mint",
            &obj(json!({"runtime": "claude", "project": "p"})),
        )
        .unwrap();
        assert!(mint.orchestrator_only());
        assert!(!AgentCall::Whoami.orchestrator_only());
    }

    #[test]
    fn operator_calls() {
        assert_eq!(
            OperatorCall::parse("project_create", &obj(json!({"name": "p"}))).unwrap(),
            OperatorCall::ProjectCreate {
                name: "p".into(),
                sealed: true
            }
        );
        assert_eq!(
            OperatorCall::parse(
                "mint",
                &obj(json!({"runtime": "claude", "project": "p", "why": null}))
            )
            .unwrap(),
            OperatorCall::Mint {
                runtime: "claude".into(),
                project: "p".into(),
                why: "operator request".into()
            }
        );
        assert_eq!(
            OperatorCall::parse("new", &obj(json!({"agent": "a"}))).unwrap(),
            OperatorCall::New {
                agent: "a".into(),
                prompt: None,
                title: String::new(),
                attach: true
            }
        );
    }
}
