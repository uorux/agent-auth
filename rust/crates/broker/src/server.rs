//! Startup (core-lifecycle-policy §9.2): configuration, the database, the
//! policy, the provisioners, the scheduler and the HTTP server, stopped
//! together on SIGTERM or Ctrl-C.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::{AgentId, Policy};
use agent_auth_store::{Store, agents};
use anyhow::Context;
use tokio::sync::watch;

use crate::auth::AuthConfig;
use crate::config::{Config, Env};
use crate::discord::Services;
use crate::llm::{LlmReviewer, RiskSummarizer};
use crate::notify::Notifier;
use agent_auth_crypto::daemon::SigningKey;
use agent_auth_crypto::secretbox::SecretBox;

use crate::provisioners::setup::{self, Keys, PlatformServices};
use crate::provisioners::{AnyProvisioner, Registry};
use crate::service::Spine;
use crate::service::SpineOps;
use crate::state::AppState;

/// How long shutdown waits for background LLM evaluations.
const SETTLE: Duration = Duration::from_secs(10);
/// How long requests still open at a signal may run on (long-polls hold
/// theirs up to 300 s). DRAIN + SETTLE stays inside Kubernetes' default
/// 30 s grace period.
pub const DRAIN: Duration = Duration::from_secs(10);

/// The enabled provisioners (provisioners spec §1.3) and the provisioners'
/// shared services: a2a always, the others when configured
/// (`provisioners::setup::build`).
pub fn register_provisioners(
    env: &Env,
    config: &Config,
    policy: &Arc<Policy>,
) -> anyhow::Result<(Registry, PlatformServices)> {
    let secret_box = match &config.encryption_key {
        Some(k) => Some(Arc::new(
            SecretBox::from_base64(k.expose())
                .map_err(|e| anyhow::anyhow!("ENCRYPTION_KEY: {e}"))?,
        )),
        None => None,
    };
    let signing_key = match env.get("BROKER_SIGNING_KEY") {
        Some(k) => {
            Some(SigningKey::from_text(k).map_err(|e| anyhow::anyhow!("BROKER_SIGNING_KEY: {e}"))?)
        }
        None => None,
    };
    let lookup = |k: &str| env.get(k).map(str::to_owned);
    let built = setup::build(
        &setup::Env::new(&lookup),
        policy,
        Keys {
            secret_box: secret_box.as_ref(),
            signing_key: signing_key.as_ref(),
        },
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut registry = Registry::default();
    registry.register(AnyProvisioner::A2a(crate::a2a::provisioner::A2aProvisioner));
    for p in built.provisioners {
        registry.register(p);
    }
    Ok((registry, built.services))
}

/// The mail gateway (`mail::setup`), when mail is configured.
fn mail_gateway(
    env: &Env,
    config: &Config,
    policy: &Arc<Policy>,
    store: &Store,
    services: &PlatformServices,
) -> anyhow::Result<Option<Arc<crate::mail::Mail>>> {
    let secret_box = match &config.encryption_key {
        Some(k) => Some(Arc::new(
            SecretBox::from_base64(k.expose())
                .map_err(|e| anyhow::anyhow!("ENCRYPTION_KEY: {e}"))?,
        )),
        None => None,
    };
    let extra_ca_pem = match env.get("MAIL_CA_FILE") {
        Some(path) => Some(std::fs::read(path).with_context(|| format!("MAIL_CA_FILE {path}"))?),
        None => None,
    };
    let settings = crate::mail::setup::MailSettings {
        secret_box,
        openrouter_api_key: config
            .openrouter_api_key
            .as_ref()
            .map(|k| k.expose().clone()),
        openrouter_base_url: config.openrouter_base_url.clone(),
        extra_ca_pem,
        gmail_api: env.get("GMAIL_API_URL").map(str::to_owned),
    };
    crate::mail::setup::build(policy, store, &settings, services.google_tokens.as_ref())
}

/// The spine's own state: the LLM reviewer and the risk summarizer.
pub fn spine(config: &Config, policy: &Policy) -> anyhow::Result<Spine> {
    let mut spine = Spine::default();
    spine.limits = crate::limits::Limits::new(config.max_waits_per_agent, config.requests_per_hour);
    if let Some(key) = &config.openrouter_api_key {
        spine.llm = Some(LlmReviewer::new(
            agent_auth_crypto::Secret::new(key.expose().clone()),
            &config.openrouter_base_url,
            Duration::from_secs(u64::from(policy.llm().timeout_secs)),
        )?);
        if config.daemons_enabled && policy.platforms().hostexec.risk_summary {
            let model = policy
                .platforms()
                .hostexec
                .risk_model
                .clone()
                .unwrap_or_else(|| policy.llm().model.clone());
            spine.risk = Some(RiskSummarizer::new(
                agent_auth_crypto::Secret::new(key.expose().clone()),
                &config.openrouter_base_url,
                model,
            )?);
        }
    } else {
        tracing::warn!("OPENROUTER_API_KEY not set: llm-routed requests go to a human");
    }
    Ok(spine)
}

/// Paired daemons, commands on hosts, desk prompts and attention
/// (`BROKER_SIGNING_KEY`, `DAEMON_*`; the watcher with OpenRouter and
/// `platforms.hostexec.watch`).
fn hostd_part(
    config: &Config,
    store: &Store,
    policy: &Arc<Policy>,
) -> anyhow::Result<crate::daemons::HostdPart> {
    let daemons = crate::daemons::DaemonsConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    let hx = &policy.platforms().hostexec;
    let watcher = match &config.openrouter_api_key {
        Some(key) if hx.watch && daemons.signing_key.is_some() => {
            let model = hx
                .risk_model
                .clone()
                .unwrap_or_else(|| policy.llm().model.clone());
            Some(
                crate::hostexec::watcher::Watcher::new(
                    agent_auth_crypto::Secret::new(key.expose().clone()),
                    &config.openrouter_base_url,
                    &model,
                )
                .map_err(|e| anyhow::anyhow!("watcher: {e}"))?,
            )
        }
        _ => None,
    };
    crate::daemons::HostdPart::build(store.clone(), daemons, Arc::clone(policy), watcher)
        .map_err(|e| anyhow::anyhow!("daemons: {e}"))
}

/// The operator's row (the panel's chat identity), created once.
async fn ensure_operator(store: &Store) -> anyhow::Result<()> {
    let tx = store.begin().await?;
    let key_id = crate::random::token_hex(6).context("random key id")?;
    let row = agents::ensure_operator(
        &tx,
        AgentId::new(),
        &key_id,
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    tx.commit().await?;
    if row.is_none() {
        tracing::warn!("an agent named 'operator' exists: the admin panel's chat has no identity");
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "listening for Ctrl-C failed");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "listening for SIGTERM failed");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutting down");
}

/// Serve `app` until `signal`, then let open requests finish for at most
/// `drain`; then return, leaving requests still open (long-polls) to end
/// with the runtime when `main` returns. Without the bound, one agent's long-poll held the
/// shutdown for up to 300 s.
pub async fn serve_until(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    signal: impl std::future::Future<Output = ()> + Send + 'static,
    drain: Duration,
) -> std::io::Result<()> {
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let served = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        signal.await;
        let _ = signalled_tx.send(());
    });
    let drained = async move {
        if signalled_rx.await.is_ok() {
            tokio::time::sleep(drain).await;
        } else {
            // The server ended without a signal: its own branch finishes.
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        served = served.into_future() => served,
        () = drained => {
            tracing::warn!(?drain, "requests still open after the signal (long-polls); closing them");
            Ok(())
        }
    }
}

/// Run the broker until a signal (or the server failing).
/// Saved rules for google made while it was a stub (nothing was issued, so
/// approving was harmless) would auto-approve real, account-wide tokens
/// once accounts are configured: said loudly at every start until they
/// are reviewed (flagged upstream).
async fn warn_stub_era_google_rules(store: &Store, policy: &Policy) -> anyhow::Result<()> {
    if policy.platforms().google.accounts.is_empty() {
        return Ok(());
    }
    let tx = store.begin().await?;
    let rules = agent_auth_store::rules::live_for(
        &tx,
        agent_auth_core::Platform::Google,
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    tx.rollback().await?;
    let approving = rules
        .iter()
        .filter(|r| r.action == agent_auth_store::rules::RuleAction::AutoApprove)
        .count();
    if approving > 0 {
        tracing::warn!(
            rules = approving,
            "!!! google accounts are configured and {approving} saved rule(s) auto-approve \
             google requests. Rules saved while google was a stub (nothing was issued) now \
             approve real, account-wide Calendar/Drive tokens: review them with \
             `agent-auth admin rules` and delete any you did not mean for real accounts !!!"
        );
    }
    Ok(())
}

pub async fn run(env: Env) -> anyhow::Result<()> {
    let config = Config::from_env(&env)?;
    let policy = config.load_policy()?;
    let store = Store::connect(config.database_url.expose(), 20)
        .await
        .context("connecting to PostgreSQL")?;
    // One broker per database (wake-ups and more are in-process): a second
    // replica stops here.
    let Some(instance) = agent_auth_store::instance::try_lock(&store).await? else {
        anyhow::bail!(
            "another agent-auth broker is running on this database; \
             run exactly one (replicas: 1, strategy: Recreate)"
        );
    };
    store.migrate().await.context("migrating the database")?;
    ensure_operator(&store).await?;
    warn_stub_era_google_rules(&store, &policy).await?;

    let policy = Arc::new(policy);
    let (mut registry, platform_services) = register_provisioners(&env, &config, &policy)?;
    let mail = mail_gateway(&env, &config, &policy, &store, &platform_services)?;
    if let Some(m) = &mail {
        registry.register(AnyProvisioner::Mail(
            crate::mail::provisioner::MailProvisioner {
                gateway: Arc::clone(m),
            },
        ));
    }
    let mut spine = spine(&config, &policy)?;
    let hostd = hostd_part(&config, &store, &policy)?;
    if let Some(p) = hostd.provisioner() {
        registry.register(p);
    }
    hostd.install_hooks(&mut spine.hooks);
    // `env` (the process environment over `./.env`), not the process
    // environment alone: the quick start puts DISCORD_TOKEN in `.env`.
    let lookup = |k: &str| env.get(k).map(str::to_owned);
    let a2a = crate::a2a::A2a::new(
        crate::a2a::A2aConfig::from_lookup(lookup).map_err(|e| anyhow::anyhow!("a2a: {e}"))?,
    );
    let web = crate::webui::Web::from_policy(
        &policy,
        config.encryption_key.as_ref().map(|k| k.expose().as_str()),
    )
    .map_err(|e| anyhow::anyhow!("web UI: {e}"))?;
    let discord = match crate::discord::DiscordConfig::from_vars(lookup)
        .map_err(|e| anyhow::anyhow!("discord: {e}"))?
    {
        Some(cfg) => Some(
            crate::discord::Discord::new(cfg, store.clone())
                .map_err(|e| anyhow::anyhow!("discord: {e}"))?,
        ),
        None => {
            tracing::warn!("DISCORD_TOKEN not set: requests await a human via the admin API only");
            None
        }
    };
    let auth = AuthConfig {
        admin_token: config
            .admin_token
            .as_ref()
            .map(|t| agent_auth_crypto::Secret::new(t.expose().clone())),
        oauth_enabled: false,
        trust_x_real_ip: config.trust_proxy_headers,
    };
    if auth.admin_token.is_none() {
        tracing::warn!("ADMIN_TOKEN not set: the admin API is disabled");
    }
    let mut state = AppState::new(store, Policy::clone(&policy), auth);
    state.policy = policy;
    state.registry = Arc::new(registry);
    state.platform_services = Arc::new(platform_services);
    state.spine = Arc::new(spine);
    state.a2a = Arc::new(a2a);
    if let Some(d) = &discord {
        state.notifier = Arc::new(Notifier::Discord(d.notifier()));
    }
    let primary = Arc::try_unwrap(state.notifier).unwrap_or_default();
    state.notifier = Arc::new(hostd.wrap_notifier(primary));
    if let Some(m) = &mail {
        m.set_notifier(Arc::clone(&state.notifier));
    }
    state.mail = mail.clone();
    let hostd = Arc::new(hostd);
    state.hostd = Some(Arc::clone(&hostd));
    let state = crate::webui::install(state, web);
    hostd.bind(&state);
    crate::scheduler::boot(&state).await;

    let mut tasks = Vec::new();
    if let Some(d) = discord {
        let ops = Arc::new(SpineOps::new(state.clone()));
        let hosts: Arc<dyn crate::discord::HostsOps> = match &hostd.hostexec {
            Some(h) => h.clone(),
            None => ops.clone(),
        };
        d.attach(Services {
            requests: Some(ops.clone()),
            containment: Some(ops),
            hosts: Some(hosts),
            app: Some(state.clone()),
            mail: mail.clone().map(|m| -> Arc<dyn crate::mail::MailOps> { m }),
        });
        tasks.push(tokio::spawn(d.run()));
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let scheduler = tokio::spawn(crate::scheduler::run(state.clone(), stop_rx));

    let addr: SocketAddr = format!("{}:{}", config.listen_host, config.listen_port)
        .parse()
        .with_context(|| {
            format!(
                "listen address {}:{}",
                config.listen_host, config.listen_port
            )
        })?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "agent-auth broker listening");
    let app = crate::http::router(state.clone());
    let served = serve_until(listener, app, shutdown_signal(), DRAIN).await;

    let _ = stop_tx.send(true);
    if let Err(e) = scheduler.await {
        tracing::error!(error = %e, "scheduler task failed");
    }
    for t in tasks {
        t.abort();
    }
    if tokio::time::timeout(SETTLE, state.spine.settle())
        .await
        .is_err()
    {
        tracing::warn!("LLM evaluations still running at shutdown; they resume at the next start");
    }
    if let Err(e) = instance.release().await {
        tracing::warn!(error = %e, "releasing the instance lock");
    }
    served.context("HTTP server")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server(
        drain: Duration,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let app = axum::Router::new()
            .route(
                "/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    "late"
                }),
            )
            .route("/fast", axum::routing::get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve_until(
            listener,
            app,
            async {
                let _ = rx.await;
            },
            drain,
        ));
        (addr, tx, task)
    }

    #[tokio::test]
    async fn a_long_poll_does_not_hold_the_shutdown() {
        let (addr, stop, task) = server(Duration::from_millis(300)).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        stop.send(()).unwrap();
        let served = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(served.is_ok());
        assert!(started.elapsed() >= Duration::from_millis(300));
        // (Its connection task ends with the runtime, when main returns.)
    }

    #[tokio::test]
    async fn finished_requests_stop_at_once() {
        let (addr, stop, task) = server(Duration::from_secs(30)).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /fast HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        conn.read_to_end(&mut answer).await.unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        stop.send(()).unwrap();
        let served = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(served.is_ok());
    }
}
