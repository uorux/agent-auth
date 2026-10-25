//! Running a parsed command line: the calls, and the output as the Python
//! printed it.
//!
//! - Success: `json.dumps(result, indent=2)` on stdout.
//! - A broker refusal: `[{status}] {detail}` on stderr (red on a
//!   terminal), exit 1.
//! - The broker unreachable: `could not reach the broker: {error}`, exit 1.
//! - A bad value (`BadParameter`): the usage error, exit 2.

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use agent_auth_client::{BrokerClient, ClientError, Config, pyjson};
use clap::CommandFactory;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::args::{A2aCommand, AdminCommand, Cli, Command, ServeArgs, SessionCommand};
use crate::serve;

/// Where the command reads and writes (the terminal, or buffers in tests).
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    /// Whether stderr takes colors (a terminal).
    pub color: bool,
    /// Whether stdout is a terminal (`gen-signing-key` refuses otherwise).
    pub stdout_tty: bool,
    /// Read a secret without echo, after showing `prompt`.
    pub prompt: &'a mut dyn FnMut(&str) -> io::Result<String>,
    /// The environment (`AGENT_AUTH_URL`, keys, session).
    pub config: Config,
    /// An environment variable (`a2a serve --hmac-env`).
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

impl std::fmt::Debug for Io<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Io")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

const RED: &str = "31";
const GREEN: &str = "32";
const YELLOW: &str = "33";

impl Io<'_> {
    fn styled(&mut self, color: &str, text: &str) {
        let _ = if self.color {
            writeln!(self.err, "\x1b[{color}m{text}\x1b[0m")
        } else {
            writeln!(self.err, "{text}")
        };
    }

    fn line(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
    }

    fn json<T: Serialize>(&mut self, value: &T) -> u8 {
        match pyjson::dumps_indent(value) {
            Ok(text) => {
                self.line(&text);
                0
            }
            Err(e) => {
                self.styled(RED, &e.to_string());
                1
            }
        }
    }

    fn failed(&mut self, e: &ClientError) -> u8 {
        let text = match e {
            ClientError::Transport(t) => format!("could not reach the broker: {t}"),
            other => other.to_string(),
        };
        self.styled(RED, &text);
        1
    }

    /// A value the command cannot use: clap's usage error, exit 2.
    fn bad_parameter(&mut self, path: &[&str], message: &str) -> u8 {
        let mut cmd = Cli::command();
        for name in path {
            let Some(sub) = cmd.find_subcommand(name).cloned() else {
                break;
            };
            cmd = sub;
        }
        let err = cmd.error(
            clap::error::ErrorKind::ValueValidation,
            format!("Invalid value: {message}"),
        );
        let _ = write!(self.err, "{}", err.render());
        2
    }

    fn secret(&mut self, prompt: &str) -> Result<String, u8> {
        match (self.prompt)(&format!("{prompt}: ")) {
            Ok(code) => Ok(code.trim().to_owned()),
            Err(e) => {
                self.styled(RED, &format!("Aborted: {e}"));
                Err(1)
            }
        }
    }
}

/// Run `cli`; the exit code.
pub async fn run(cli: Cli, io: &mut Io<'_>) -> u8 {
    let client = match BrokerClient::new(io.config.clone()) {
        Ok(c) => c,
        Err(e) => return io.failed(&e),
    };
    match cli.command {
        Command::Admin(cmd) => admin(cmd, &client, io).await,
        Command::A2a(cmd) => a2a(cmd, &client, io).await,
        Command::Session(cmd) => session(cmd, &client, io).await,
        cmd => agent(cmd, &client, io).await,
    }
}

/// Print the answer, or the failure.
fn show<T: Serialize>(io: &mut Io<'_>, result: Result<T, ClientError>) -> u8 {
    match result {
        Ok(v) => io.json(&v),
        Err(e) => io.failed(&e),
    }
}

/// A JSON object option (`--scope`, `--payload`); the usage error if it is
/// not one.
fn json_object(
    io: &mut Io<'_>,
    path: &[&str],
    option: &str,
    text: &str,
) -> Result<Map<String, Value>, u8> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(io.bad_parameter(path, &format!("{option}: a JSON object"))),
        Err(e) => Err(io.bad_parameter(path, &format!("{option}: not JSON ({e})"))),
    }
}

async fn agent(cmd: Command, client: &BrokerClient, io: &mut Io<'_>) -> u8 {
    match cmd {
        Command::Me => show(io, client.me().await),
        Command::Catalog => show(io, client.catalog().await),
        Command::Request {
            platform,
            capability,
            resource,
            justification,
            duration,
            scope,
            on_behalf_of_thread,
            wait,
        } => {
            let scope = match json_object(io, &["request"], "--scope", &scope) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let result = async {
                let req = client
                    .request_access(
                        &platform,
                        &capability,
                        &resource,
                        &justification,
                        &duration,
                        Some(scope),
                        on_behalf_of_thread.as_deref(),
                    )
                    .await?;
                if wait && agent_auth_client::poll::is_waiting(req.status) {
                    return client.wait(&req.id.to_string(), 300.0).await;
                }
                Ok(req)
            }
            .await;
            show(io, result)
        }
        Command::Status { request_id } => show(io, client.get_request(&request_id).await),
        Command::Wait {
            request_id,
            timeout,
        } => show(io, client.wait(&request_id, timeout).await),
        Command::Retry {
            request_id,
            justification,
        } => show(io, client.retry(&request_id, &justification).await),
        Command::Escalate { request_id } => show(io, client.escalate(&request_id).await),
        Command::Grants { status } => show(io, client.grants(&status).await),
        Command::Cred { grant_id } => show(io, client.credential(&grant_id).await),
        Command::Release { grant_id } => show(io, client.release(&grant_id).await),
        Command::Session(_) | Command::A2a(_) | Command::Admin(_) => 2,
    }
}

async fn session(cmd: SessionCommand, client: &BrokerClient, io: &mut Io<'_>) -> u8 {
    match cmd {
        SessionCommand::Create { label } => {
            let label = label.unwrap_or_else(agent_auth_client::default_session_label);
            match client.create_session(&label).await {
                Ok(out) => {
                    io.styled(
                        GREEN,
                        &format!("export AGENT_AUTH_SESSION={}", out.session_id),
                    );
                    io.json(&out)
                }
                Err(e) => io.failed(&e),
            }
        }
        SessionCommand::Close => show(io, client.close_session().await),
    }
}

async fn a2a(cmd: A2aCommand, client: &BrokerClient, io: &mut Io<'_>) -> u8 {
    match cmd {
        A2aCommand::Check {
            peer,
            direction,
            topic,
        } => show(
            io,
            client.a2a_check(&peer, &direction, topic.as_deref()).await,
        ),
        A2aCommand::Open { to, payload, topic } => {
            let payload = match json_object(io, &["a2a", "open"], "--payload", &payload) {
                Ok(p) => p,
                Err(code) => return code,
            };
            show(io, client.a2a_open(&to, payload, topic.as_deref()).await)
        }
        A2aCommand::Send { thread_id, payload } => {
            let payload = match json_object(io, &["a2a", "send"], "--payload", &payload) {
                Ok(p) => p,
                Err(code) => return code,
            };
            show(io, client.a2a_send(&thread_id, payload).await)
        }
        A2aCommand::Poll {
            thread_id,
            after_seq,
            wait,
        } => show(io, client.a2a_poll(&thread_id, after_seq, wait).await),
        A2aCommand::Threads { state, role } => show(
            io,
            client.a2a_threads(state.as_deref(), role.as_deref()).await,
        ),
        A2aCommand::Show { thread_id } => show(io, client.a2a_thread(&thread_id).await),
        A2aCommand::Accept { thread_id } => show(io, client.a2a_accept(&thread_id).await),
        A2aCommand::Reject { thread_id, reason } => {
            show(io, client.a2a_reject(&thread_id, reason.as_deref()).await)
        }
        A2aCommand::Close { thread_id, reason } => {
            show(io, client.a2a_close(&thread_id, reason.as_deref()).await)
        }
        A2aCommand::Events { wait, after } => {
            show(io, client.a2a_events(wait, after.as_deref()).await)
        }
        A2aCommand::Serve(args) => a2a_serve(args, client, io).await,
    }
}

async fn a2a_serve(args: ServeArgs, client: &BrokerClient, io: &mut Io<'_>) -> u8 {
    let secret = if args.insecure_no_sign {
        io.styled(
            RED,
            "WARNING: --insecure-no-sign — dispatch POSTs are UNSIGNED; the receiver cannot \
             authenticate them. Loopback/testing only.",
        );
        None
    } else {
        match (io.env)(&args.hmac_env).filter(|s| !s.is_empty()) {
            Some(s) => Some(s),
            None => {
                io.styled(
                    RED,
                    &format!(
                        "{} is not set. Set it to the shared webhook secret, or pass \
                         --insecure-no-sign for loopback testing.",
                        args.hmac_env
                    ),
                );
                return 1;
            }
        }
    };
    let poster = match serve::HttpPoster::new() {
        Ok(p) => p,
        Err(e) => {
            io.styled(RED, &e);
            return 1;
        }
    };
    let cfg = serve::ServeConfig {
        on_open_url: args.on_open_url,
        secret,
        wait: args.wait,
        redeliver_interval: args.redeliver_interval,
        failure_backoff: args.failure_backoff,
        include_activity: args.include_activity && !args.no_include_activity,
        sig_header: args.sig_header,
    };
    let state = args.state.unwrap_or_else(serve::default_state_path);
    serve::serve_loop(client, &poster, &cfg, &state, args.poll_interval).await;
    0
}

/// The JSON object a value serializes to, in its field order, without its
/// null fields (the Python's `response_model_exclude_none` routes).
fn without_nulls<T: Serialize>(value: &T) -> Result<Ordered, ClientError> {
    let text = serde_json::to_string(value).map_err(|e| ClientError::Decode(e.to_string()))?;
    let mut map: Ordered =
        serde_json::from_str(&text).map_err(|e| ClientError::Decode(e.to_string()))?;
    map.0.retain(|(_, v)| !v.is_null());
    Ok(map)
}

/// A JSON object keeping its keys in order.
#[derive(Debug, Default)]
struct Ordered(Vec<(String, Value)>);

impl Serialize for Ordered {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Ordered, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = access.next_entry::<String, Value>()? {
                    out.push((k, v));
                }
                Ok(Ordered(out))
            }
        }
        d.deserialize_map(V)
    }
}

fn sparse<T: Serialize>(io: &mut Io<'_>, result: Result<T, ClientError>) -> u8 {
    show(io, result.and_then(|v| without_nulls(&v)))
}

#[allow(clippy::too_many_lines)]
async fn admin(cmd: AdminCommand, client: &BrokerClient, io: &mut Io<'_>) -> u8 {
    match cmd {
        AdminCommand::GenKey => match agent_auth_crypto::secretbox::SecretBox::generate_key() {
            Ok(key) => {
                io.line(key.expose());
                0
            }
            Err(e) => {
                io.styled(RED, &e.to_string());
                1
            }
        },
        AdminCommand::AgentCreate {
            name,
            description,
            kind,
            webhook_url,
            lldap_username,
            runtime,
            project,
            host,
        } => {
            if kind == "service" && webhook_url.is_none() {
                // The common misregistration: a CLI agent left on the default
                // kind is advertised as a peer, and threads to it go unread.
                io.styled(
                    YELLOW,
                    &format!(
                        "warning: {name} is 'service' with no --webhook-url, so it will be advertised \
                         as an a2a peer and must keep an a2a_events long-poll running to be reachable. \
                         For a CLI agent, pass --kind ephemeral."
                    ),
                );
            }
            let result = client
                .admin_create_agent(
                    &name,
                    &description,
                    webhook_url.as_deref(),
                    lldap_username.as_deref(),
                    &kind,
                    runtime.as_deref(),
                    project.as_deref(),
                    host.as_deref(),
                )
                .await;
            sparse(io, result)
        }
        AdminCommand::AgentSet {
            agent,
            runtime,
            project,
            host,
        } => {
            if runtime.is_none() && project.is_none() && host.is_none() {
                return io.bad_parameter(
                    &["admin", "agent-set"],
                    "nothing to set: pass --runtime, --project or --host",
                );
            }
            let result = client
                .admin_set_attributes(
                    &agent,
                    runtime.as_deref(),
                    project.as_deref(),
                    host.as_deref(),
                )
                .await;
            show(io, result)
        }
        AdminCommand::AgentRename { agent, name } => {
            show(io, client.admin_rename_agent(&agent, &name).await)
        }
        AdminCommand::RotateLldapPassword { agent_id } => {
            sparse(io, client.admin_rotate_lldap_password(&agent_id).await)
        }
        AdminCommand::RotateWebhookSecret { agent_id } => {
            sparse(io, client.admin_rotate_webhook_secret(&agent_id).await)
        }
        AdminCommand::SetWebhook { agent_id, url } => sparse(
            io,
            client.admin_set_webhook(&agent_id, url.as_deref()).await,
        ),
        AdminCommand::SetKind { agent_id, kind } => {
            if kind != "service" && kind != "ephemeral" {
                return io.bad_parameter(
                    &["admin", "set-kind"],
                    "kind must be 'service' or 'ephemeral'",
                );
            }
            sparse(io, client.admin_set_kind(&agent_id, &kind).await)
        }
        AdminCommand::Agents => show(io, client.admin_list_agents().await),
        AdminCommand::AgentDisable { agent_id } => {
            show(io, client.admin_disable_agent(&agent_id).await)
        }
        AdminCommand::RotateKey { agent_id } => show(io, client.admin_rotate_key(&agent_id).await),
        AdminCommand::Rules => show(io, client.admin_list_rules().await),
        AdminCommand::RuleDelete { rule_id } => show(io, client.admin_delete_rule(&rule_id).await),
        AdminCommand::Requests { limit } => show(io, client.admin_list_requests(limit).await),
        AdminCommand::Decide {
            request_id,
            approve,
            deny: _,
            reason,
            duration,
            totp,
        } => {
            let code = if totp && approve {
                match io.secret("TOTP code") {
                    Ok(c) => Some(c),
                    Err(code) => return code,
                }
            } else {
                None
            };
            let result = client
                .admin_decide(
                    &request_id,
                    approve,
                    &reason,
                    duration.as_deref(),
                    code.as_deref(),
                )
                .await;
            show(io, result)
        }
        AdminCommand::Revoke { grant_id, reason } => {
            show(io, client.admin_revoke_grant(&grant_id, &reason).await)
        }
        AdminCommand::GoogleConsent {
            client_secret_file,
            scopes,
            out,
            no_browser,
            port,
        } => google_consent(io, &client_secret_file, &scopes, &out, !no_browser, port).await,
        AdminCommand::GenSigningKey { out, to_stdout } => {
            gen_signing_key(io, out.as_deref(), to_stdout)
        }
        AdminCommand::DaemonPair { name, role } => {
            match client.admin_create_pairing_code(&role, &name).await {
                Ok(res) => {
                    let fingerprint =
                        agent_auth_crypto::daemon::PublicKey::parse(&res.broker_public_key)
                            .map(|k| k.fingerprint())
                            .unwrap_or_else(|e| format!("(unreadable key: {e:?})"));
                    let expires =
                        agent_auth_wire::timestamp::format(res.expires_at).unwrap_or_default();
                    io.line(&format!(
                        "pairing code for {role}:{name}: {}",
                        res.code.expose()
                    ));
                    io.line(&format!("expires: {expires}"));
                    io.line(&format!(
                        "broker key fingerprint (the daemon prints it too): {fingerprint}"
                    ));
                    io.line(
                    "on the host: `sudo agent-auth-hostd pair`, then enter the code at the prompt \
                     (not as an argument — it would land in shell history)",
                );
                    0
                }
                Err(e) => io.failed(&e),
            }
        }
        AdminCommand::Daemons => show(io, client.admin_list_daemons().await),
        AdminCommand::DaemonUnpair { daemon_id } => {
            show(io, client.admin_unpair_daemon(&daemon_id).await)
        }
        AdminCommand::BrokerKey => show(io, client.admin_broker_key().await),
        AdminCommand::Hosts => show(io, client.admin_hosts().await),
        AdminCommand::Arm {
            host,
            tier,
            duration,
        } => {
            let code = match io.secret(&format!("{host} {tier}-arm code")) {
                Ok(c) => c,
                Err(code) => return code,
            };
            show(io, client.admin_arm(&host, &tier, &duration, &code).await)
        }
        AdminCommand::Disarm { host, tier } => {
            show(io, client.admin_disarm(&host, tier.as_deref()).await)
        }
        AdminCommand::Lockdown {
            mut scope,
            host,
            kill_vm,
        } => {
            if host.is_some() && scope == "sandboxes" {
                scope = "host".into();
            }
            show(
                io,
                client
                    .admin_lockdown(&scope, host.as_deref(), kill_vm)
                    .await,
            )
        }
        AdminCommand::Unlock { host } => {
            let code = match &host {
                Some(h) => match io.secret(&format!("{h} root-unlock code")) {
                    Ok(c) => Some(c),
                    Err(code) => return code,
                },
                None => None,
            };
            show(
                io,
                client.admin_unlock(host.as_deref(), code.as_deref()).await,
            )
        }
        AdminCommand::Contain {
            reason,
            name,
            project,
            host,
            runtime,
            everyone,
        } => {
            let mut matches = Map::new();
            for (key, value) in [
                ("name", name),
                ("project", project),
                ("host", host),
                ("runtime", runtime),
            ] {
                if let Some(v) = value.filter(|v| !v.is_empty()) {
                    matches.insert(key.into(), Value::String(v));
                }
            }
            if matches.is_empty() && !everyone {
                return io.bad_parameter(
                    &["admin", "contain"],
                    "say which agents (--name/--project/--host/--runtime) or --all",
                );
            }
            show(io, client.admin_contain(matches, &reason, "").await)
        }
        AdminCommand::ContainList => show(io, client.admin_containment().await),
        AdminCommand::ContainLift { entry } => {
            show(io, client.admin_contain_lift(entry.as_deref()).await)
        }
        AdminCommand::Connectors => show(io, client.admin_connectors().await),
        AdminCommand::ConnectorRevoke { client_id } => {
            show(io, client.admin_connector_revoke(&client_id).await)
        }
    }
}

/// `admin gen-signing-key`: never the seed on a non-terminal stdout without
/// `--stdout`; `--out` makes a new 0600 file and never overwrites or
/// follows a link (`O_CREAT|O_EXCL`).
async fn google_consent(
    io: &mut Io<'_>,
    client_secret_file: &Path,
    scopes: &str,
    out: &Path,
    open_browser: bool,
    port: u16,
) -> u8 {
    use crate::google_consent::{ConsentOptions, consent};
    let opts = ConsentOptions {
        client_secret_file: client_secret_file.to_string_lossy().into_owned(),
        scopes: scopes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        out: out.to_string_lossy().into_owned(),
        port,
    };
    let result = consent(&opts, |url| {
        io.line(&format!(
            "Open this URL and sign in as the account to broker:\n\n  {url}\n"
        ));
        let _ = io.out.flush();
        if open_browser {
            crate::google_consent::open_browser(url);
        }
    })
    .await;
    match result {
        Ok(result) => {
            let code = io.json(&result);
            if !result.missing.is_empty() {
                io.styled(
                    YELLOW,
                    &format!(
                        "not granted on the consent screen: {}",
                        result.missing.join(", ")
                    ),
                );
            }
            code
        }
        Err(e) => {
            io.styled(RED, &e.0);
            1
        }
    }
}

fn gen_signing_key(io: &mut Io<'_>, out: Option<&Path>, to_stdout: bool) -> u8 {
    if out.is_none() && !to_stdout && !io.stdout_tty {
        // Piped or captured output (agent transcripts, logs) would keep it.
        io.styled(
            RED,
            "refusing to print the private signing key to a non-terminal stdout. Use --out FILE \
             to write it to a new 0600 file, or --stdout to print anyway.",
        );
        return 2;
    }
    let key = match agent_auth_crypto::daemon::SigningKey::generate() {
        Ok(k) => k,
        Err(e) => {
            io.styled(RED, &e.to_string());
            return 1;
        }
    };
    let public = key.public_key();
    let line = format!("BROKER_SIGNING_KEY={}", key.to_text().expose());
    match out {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path);
            let written = file.and_then(|mut f| {
                f.write_all(line.as_bytes())?;
                f.write_all(b"\n")
            });
            if let Err(e) = written {
                io.styled(
                    RED,
                    &format!("cannot create {}: {}", path.display(), strerror(&e)),
                );
                return 1;
            }
            io.line(&format!("# wrote BROKER_SIGNING_KEY to {}", path.display()));
        }
        None => io.line(&line),
    }
    io.line(&format!(
        "# public key (pin in daemons): {}",
        public.to_text()
    ));
    io.line(&format!("# fingerprint: {}", public.fingerprint()));
    0
}

/// The OS's message without Rust's ` (os error N)`.
fn strerror(e: &io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(i) => text.get(..i).unwrap_or(&text).to_owned(),
        None => text,
    }
}
