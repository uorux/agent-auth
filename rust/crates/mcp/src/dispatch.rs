//! What each tool does (mcp_server.py), for any [`Caller`].
//!
//! Every tool answers one string: the broker's answer as Python's
//! `json.dumps(result, indent=2)` would print it, or on a broker refusal
//! `{"error": <detail>, "status_code": <status>}` (compact). Anything else
//! (the broker unreachable, an answer that does not parse, a file that
//! cannot be written) is a tool error.

use std::future::Future;

use agent_auth_client::{BrokerClient, ClientError, poll, pyjson};
use agent_auth_wire::agent::RequestOut;
use agent_auth_wire::hostexec::JobOut;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::caller::{Caller, client_for};
use crate::to_file;
use crate::tools::{Args, find};

/// A tool's answer: its text (`Ok`), or a tool error's message.
pub type ToolResult = Result<String, String>;

/// Why a tool call failed outright.
#[derive(Debug)]
enum Failure {
    Client(ClientError),
    Other(String),
}

impl From<ClientError> for Failure {
    fn from(e: ClientError) -> Self {
        Failure::Client(e)
    }
}

/// Run tool `name` with `args` for `caller`.
pub async fn call<C: Caller>(
    caller: &C,
    name: &str,
    args: Option<&Map<String, Value>>,
) -> ToolResult {
    let Some(tool) = find(name) else {
        return Err(format!("Unknown tool: {name}"));
    };
    let args = Args::parse(tool, args).map_err(|e| {
        format!("Error executing tool {name}: 1 validation error for {name}Arguments\n{e}")
    })?;
    run(caller, name, &args)
        .await
        .map_err(|e| format!("Error executing tool {name}: {e}"))
}

/// The Python's `_safe`: run `f`; if it fails because a session this
/// caller minted was closed by the broker, run it once more (it mints a new
/// one). A refusal becomes the error JSON.
async fn safe<C, T, F, Fut>(caller: &C, f: F) -> Result<String, String>
where
    C: Caller,
    T: Serialize,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, Failure>>,
{
    let out = match f().await {
        Err(Failure::Client(e)) if e.is_stale_session() && caller.minted_session_gone().await => {
            f().await
        }
        other => other,
    };
    match out {
        Ok(value) => pyjson::dumps_indent(&value).map_err(|e| e.to_string()),
        Err(Failure::Client(ClientError::Broker { status, detail })) => {
            pyjson::dumps(&json!({"error": detail, "status_code": status}))
                .map_err(|e| e.to_string())
        }
        Err(Failure::Client(e)) => Err(e.to_string()),
        Err(Failure::Other(e)) => Err(e),
    }
}

/// `{"request": ..., "job": ...}` (host_run).
#[derive(Debug, Serialize)]
struct HostRun {
    request: RequestOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    job: Option<JobOut>,
}

/// What mail_attachment answers: the attachment's description and where
/// it was saved (its content stays out of the conversation).
#[derive(Debug, Serialize)]
struct SavedAttachment {
    index: u64,
    filename: String,
    content_type: String,
    size: u64,
    notice: String,
    file: String,
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// The longest wait host_run spends on a decision, then on the job.
const HOST_RUN_MAX_WAIT: f64 = 300.0;

#[allow(clippy::too_many_lines)]
async fn run<C: Caller>(caller: &C, name: &str, a: &Args) -> Result<String, String> {
    let key = a.opt_str("session_key");
    let plain = || caller.client();
    let sessioned = || async { client_for(caller, key).await.map_err(Failure::from) };
    match name {
        "whoami" => safe(caller, || async { Ok(plain().me().await?) }).await,
        "list_capabilities" => safe(caller, || async { Ok(plain().catalog().await?) }).await,
        "request_access" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .request_access(
                        a.str("platform"),
                        a.str("capability"),
                        a.str("resource"),
                        a.str("justification"),
                        a.str("duration"),
                        a.obj("scope"),
                        a.opt_str("on_behalf_of_thread"),
                    )
                    .await?)
            })
            .await
        }
        "wait_for_decision" => {
            safe(caller, || async {
                Ok(plain()
                    .wait(a.str("request_id"), a.num("timeout_secs"))
                    .await?)
            })
            .await
        }
        "check_status" => {
            safe(caller, || async {
                Ok(plain().get_request(a.str("request_id")).await?)
            })
            .await
        }
        "retry_request" => {
            safe(caller, || async {
                Ok(plain()
                    .retry(a.str("request_id"), a.str("justification"))
                    .await?)
            })
            .await
        }
        "escalate_request" => {
            safe(caller, || async {
                Ok(plain().escalate(a.str("request_id")).await?)
            })
            .await
        }
        "list_grants" => {
            safe(caller, || async {
                Ok(plain().grants(a.str("status")).await?)
            })
            .await
        }
        "get_credential" => {
            safe(caller, || async {
                let grant = a.str("grant_id");
                let out = plain().credential(grant).await?;
                if !a.bool("to_file") {
                    return Ok(to_file::Delivered::Inline(out));
                }
                let dir = caller
                    .credential_dir()
                    .map_err(|e| Failure::Other(e.to_string()))?;
                to_file::deliver(&dir, grant, out).map_err(|e| Failure::Other(e.to_string()))
            })
            .await
        }
        "mail_list" => {
            safe(caller, || async {
                Ok(plain()
                    .mail_list(
                        a.str("grant_id"),
                        a.int("limit"),
                        a.opt_str("page"),
                        a.opt_str("search"),
                    )
                    .await?)
            })
            .await
        }
        "mail_read" => {
            safe(caller, || async {
                Ok(plain()
                    .mail_read(a.str("grant_id"), a.str("message_id"))
                    .await?)
            })
            .await
        }
        "mail_attachment" => {
            safe(caller, || async {
                let message = a.str("message_id");
                let index = u64::try_from(a.int("index")).unwrap_or(u64::MAX);
                let out = plain()
                    .mail_attachment(a.str("grant_id"), message, index)
                    .await?;
                let bytes = base64_decode(&out.content_base64)
                    .ok_or_else(|| Failure::Other("the attachment did not decode".to_owned()))?;
                let dir = caller
                    .credential_dir()
                    .map_err(|e| Failure::Other(e.to_string()))?;
                let dir = dir.parent().map_or_else(|| dir.clone(), |p| p.join("mail"));
                let name: String = out
                    .filename
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
                    .take(100)
                    .collect();
                let name = if name.is_empty() {
                    "attachment".to_owned()
                } else {
                    name
                };
                let prefix: String = message
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .take(8)
                    .collect();
                let path =
                    to_file::write_private(&dir, &format!("{prefix}-{index}-{name}"), &bytes)
                        .map_err(|e| Failure::Other(e.to_string()))?;
                Ok(SavedAttachment {
                    index: out.index,
                    filename: out.filename,
                    content_type: out.content_type,
                    size: out.size,
                    notice: out.notice,
                    file: path.to_string_lossy().into_owned(),
                })
            })
            .await
        }
        "mail_send" => {
            safe(caller, || async {
                let to = a.opt_list("to");
                Ok(plain()
                    .mail_send(
                        a.str("grant_id"),
                        a.str("body"),
                        to.as_deref(),
                        a.opt_str("subject"),
                        a.opt_str("reply_to"),
                    )
                    .await?)
            })
            .await
        }
        "release_grant" => {
            safe(caller, || async {
                Ok(plain().release(a.str("grant_id")).await?)
            })
            .await
        }
        "create_session" => {
            // A client of its own: minting must not change the session other
            // calls use (conversations may share this server). The caller's
            // own credentials (the Python used the environment's even in
            // remote mode).
            safe(caller, || async {
                Ok(plain()
                    .with_session(None)
                    .create_session(a.str("label"))
                    .await?)
            })
            .await
        }
        "close_session" => {
            safe(caller, || async {
                Ok(plain()
                    .with_session(Some(a.str("session_key")))
                    .close_session()
                    .await?)
            })
            .await
        }
        "check_a2a" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_check(a.str("peer"), a.str("direction"), a.opt_str("topic"))
                    .await?)
            })
            .await
        }
        "a2a_open" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_open(
                        a.str("to"),
                        a.obj("payload").unwrap_or_default(),
                        a.opt_str("topic"),
                    )
                    .await?)
            })
            .await
        }
        "a2a_send" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_send(a.str("thread_id"), a.obj("payload").unwrap_or_default())
                    .await?)
            })
            .await
        }
        "a2a_poll" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_poll(a.str("thread_id"), a.int("after_seq"), a.num("wait"))
                    .await?)
            })
            .await
        }
        "a2a_threads" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_threads(a.opt_str("state"), None)
                    .await?)
            })
            .await
        }
        "a2a_accept" => {
            safe(caller, || async {
                Ok(sessioned().await?.a2a_accept(a.str("thread_id")).await?)
            })
            .await
        }
        "a2a_reject" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_reject(a.str("thread_id"), a.opt_str("reason"))
                    .await?)
            })
            .await
        }
        "a2a_close" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_close(a.str("thread_id"), a.opt_str("reason"))
                    .await?)
            })
            .await
        }
        "a2a_events" => {
            safe(caller, || async {
                Ok(sessioned()
                    .await?
                    .a2a_events(a.num("wait"), a.opt_str("after"))
                    .await?)
            })
            .await
        }
        "wiki_search" => {
            safe(caller, || async {
                Ok(plain().wiki_search(a.str("query"), a.int("limit")).await?)
            })
            .await
        }
        "wiki_read" => {
            safe(caller, || async {
                Ok(plain().wiki_read(a.str("path")).await?)
            })
            .await
        }
        "wiki_list" => {
            safe(caller, || async {
                Ok(plain().wiki_list(a.str("prefix")).await?)
            })
            .await
        }
        "wiki_write" => {
            safe(caller, || async {
                Ok(plain()
                    .wiki_write(
                        a.str("path"),
                        a.str("content"),
                        a.str("summary"),
                        a.opt_str("base_sha"),
                    )
                    .await?)
            })
            .await
        }
        "wiki_delete" => {
            safe(caller, || async {
                Ok(plain()
                    .wiki_delete(a.str("path"), a.str("summary"), a.opt_str("base_sha"))
                    .await?)
            })
            .await
        }
        "notify_operator" => {
            safe(caller, || async {
                Ok(plain()
                    .attention(a.str("message"), a.str("urgency"))
                    .await?)
            })
            .await
        }
        "host_run" => safe(caller, || async { host_run(sessioned().await?, a).await }).await,
        "host_job" => {
            safe(caller, || async {
                Ok(plain()
                    .host_job(a.str("job_id"), a.num("wait_secs"))
                    .await?)
            })
            .await
        }
        "host_shell_exec" => {
            safe(caller, || async {
                let argv = a.str_list("argv");
                Ok(plain()
                    .host_shell_exec(
                        a.str("grant_id"),
                        &argv,
                        a.opt_str("cwd"),
                        a.opt_str("stdin"),
                        a.opt_int("timeout_secs"),
                        a.num("wait_secs"),
                        a.opt_str("scope_id"),
                    )
                    .await?)
            })
            .await
        }
        "host_shell_close" => {
            safe(caller, || async {
                // Either way the answer is {"closed": bool}.
                // A scope_id given (even empty) closes only a scope, never
                // the whole shell by accident.
                let closed = match a.opt_str("scope_id") {
                    Some(scope) => {
                        plain()
                            .host_shell_close_scope(a.str("grant_id"), scope)
                            .await?
                            .closed
                    }
                    None => plain().host_shell_close(a.str("grant_id")).await?.closed,
                };
                Ok(json!({"closed": closed}))
            })
            .await
        }
        "host_shell_scope" => {
            safe(caller, || async {
                Ok(plain()
                    .host_shell_scope(a.str("grant_id"), a.str("purpose"))
                    .await?)
            })
            .await
        }
        other => Err(format!("Unknown tool: {other}")),
    }
}

/// `request_access("hostexec", "run", host, ...)` with the command as its
/// scope, wait for the decision, and once granted for the job (whose id is
/// the request's).
async fn host_run(client: BrokerClient, a: &Args) -> Result<HostRun, Failure> {
    let mut scope = Map::new();
    scope.insert("tier".into(), json!(a.str("tier")));
    scope.insert("argv".into(), json!(a.str_list("argv")));
    scope.insert("timeout".into(), json!(a.int("timeout_secs")));
    if let Some(cwd) = a.opt_str("cwd").filter(|c| !c.is_empty()) {
        scope.insert("cwd".into(), json!(cwd));
    }
    if let Some(env) = a.obj("env").filter(|e| !e.is_empty()) {
        scope.insert("env".into(), Value::Object(env));
    }
    if let Some(stdin) = a.opt_str("stdin") {
        scope.insert("stdin".into(), json!(stdin));
    }
    let wait = a.num("wait_secs");
    let mut request = client
        .request_access(
            "hostexec",
            "run",
            a.str("host"),
            a.str("justification"),
            "1h",
            Some(scope),
            a.opt_str("on_behalf_of_thread"),
        )
        .await?;
    if poll::is_waiting(request.status) && wait > 0.0 {
        request = client
            .wait(&request.id.to_string(), wait.min(HOST_RUN_MAX_WAIT))
            .await?;
    }
    let job = if request.status == agent_auth_core::RequestStatus::Granted {
        Some(
            client
                .host_job(&request.id.to_string(), wait.min(HOST_RUN_MAX_WAIT))
                .await?,
        )
    } else {
        None
    };
    Ok(HostRun { request, job })
}
