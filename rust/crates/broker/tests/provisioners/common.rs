//! Fixtures: fake upstreams (a local axum server per test that records
//! every call), agents and grants in a real database, and the lifecycle
//! steps the spine runs around a provisioner.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_auth_broker::provisioners::{
    Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::lifecycle::state;
use agent_auth_core::{AgentId, Authority, GrantId, HumanApproval, Platform, RequestId};
use agent_auth_crypto::secretbox::SecretBox;
use agent_auth_store::agents::{self, AgentRow, NewAgent};
use agent_auth_store::grants::{self, GrantEnd, GrantRow, NotIssuable};
use agent_auth_store::requests::{self, AnyRequest, Approval, Escalation, NewRequest, Request};
use agent_auth_store::{Store, lockdown};
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn secret_box() -> Arc<SecretBox> {
    Arc::new(SecretBox::from_bytes(&[7u8; 32]).unwrap())
}

// ---------------------------------------------------------------- fakes

/// One request a fake upstream received.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

impl Call {
    pub fn is(&self, method: &str, path: &str) -> bool {
        self.method == method && self.path == path
    }
    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }
}

/// What a fake answers: status, JSON body (`Null`: empty), delay.
#[derive(Debug, Clone)]
pub struct R(pub u16, pub Value, pub u64);

pub fn r(status: u16, body: Value) -> R {
    R(status, body, 0)
}

type Handler = Arc<dyn Fn(&Call) -> R + Send + Sync>;

/// A local HTTP server answering with a handler, recording every call.
#[derive(Clone)]
pub struct Fake {
    pub url: String,
    calls: Arc<Mutex<Vec<Call>>>,
    handler: Arc<Mutex<Handler>>,
}

impl Fake {
    pub async fn start(handler: impl Fn(&Call) -> R + Send + Sync + 'static) -> Fake {
        let calls: Arc<Mutex<Vec<Call>>> = Arc::default();
        let handler: Arc<Mutex<Handler>> = Arc::new(Mutex::new(Arc::new(handler)));
        let (c, h) = (calls.clone(), handler.clone());
        let app = axum::Router::new().fallback(
            move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                let (c, h) = (c.clone(), h.clone());
                async move {
                    let call = Call {
                        method: method.to_string(),
                        path: uri.path().to_owned(),
                        query: uri.query().unwrap_or("").to_owned(),
                        headers: headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned())
                            })
                            .collect(),
                        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
                    };
                    c.lock().unwrap().push(call.clone());
                    let handler = h.lock().unwrap().clone();
                    let R(status, body, delay) = handler(&call);
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let status = StatusCode::from_u16(status).unwrap();
                    if body.is_null() {
                        status.into_response()
                    } else {
                        (status, axum::Json(body)).into_response()
                    }
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Fake {
            url: format!("http://{addr}"),
            calls,
            handler,
        }
    }

    pub fn set(&self, handler: impl Fn(&Call) -> R + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Arc::new(handler);
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }

    pub fn count(&self, method: &str, path: &str) -> usize {
        self.calls().iter().filter(|c| c.is(method, path)).count()
    }

    pub fn find(&self, method: &str, path: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.is(method, path))
            .collect()
    }
}

// ------------------------------------------------------------ database

#[derive(Debug, Clone)]
pub struct AgentSpec<'a> {
    pub name: &'a str,
    pub lldap_username: Option<&'a str>,
    pub runtime: Option<&'a str>,
    pub project: Option<&'a str>,
}

impl<'a> AgentSpec<'a> {
    pub fn named(name: &'a str) -> Self {
        AgentSpec {
            name,
            lldap_username: None,
            runtime: Some("claude"),
            project: Some("agent-auth"),
        }
    }
}

pub async fn agent(store: &Store, name: &str) -> AgentRow {
    agent_with(store, AgentSpec::named(name)).await
}

pub async fn agent_with(store: &Store, a: AgentSpec<'_>) -> AgentRow {
    let tx = store.begin().await.unwrap();
    let id = AgentId::new();
    let key_id = id.to_string()[..12].to_owned();
    let row = agents::insert(
        &tx,
        &NewAgent {
            id,
            name: a.name,
            description: "",
            key_id: &key_id,
            api_key_hash: &"0".repeat(64),
            kind: AgentKind::Service,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: a.lldap_username,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: a.runtime,
            project: a.project,
            host: Some("excelsior"),
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    row
}

pub async fn reload(store: &Store, id: AgentId) -> AgentRow {
    let tx = store.begin().await.unwrap();
    let a = agents::get(&tx, id).await.unwrap().unwrap();
    tx.rollback().await.unwrap();
    a
}

/// A committed PROVISIONING grant for `resource`/`authority`, lasting `secs`.
pub async fn provisioning(
    store: &Store,
    agent: AgentId,
    authority: &Authority,
    resource: &str,
    secs: u32,
) -> GrantRow {
    let tx = store.begin().await.unwrap();
    let id = RequestId::new();
    let r = requests::insert(
        &tx,
        &NewRequest {
            id,
            agent_id: agent,
            session_id: None,
            delegation: None,
            platform: authority.platform(),
            resource,
            requested_capability: "x",
            requested_scope: &json!({}),
            authority: Some(authority),
            justification: "testing",
            requested_duration_secs: secs,
            risk_notes: &[],
            now: now(),
        },
    )
    .await
    .unwrap();
    let r = requests::transition::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now())
        .await
        .unwrap()
        .unwrap();
    let r = requests::transition::<_, state::Approved>(
        &tx,
        r,
        Approval::human(HumanApproval::attest(id, "jrt"), "ok", secs),
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    let r: Request<state::Provisioning> = requests::transition(&tx, r, (), now())
        .await
        .unwrap()
        .unwrap();
    let nh = lockdown::check(&tx, agent, now()).await.unwrap().unwrap();
    let g = grants::begin(&tx, &r, &nh, GrantId::new(), now())
        .await
        .unwrap()
        .unwrap()
        .grant()
        .clone();
    drop(nh);
    tx.commit().await.unwrap();
    g
}

/// What the spine's finish-provisioning does: provision in a transaction
/// of its own, then activate (or record the failure). Writes the
/// provisioner made are committed either way.
pub async fn provision<P: Provisioner>(
    store: &Store,
    p: &P,
    grant: &GrantRow,
) -> Result<GrantRow, String> {
    let tx = store.begin().await.unwrap();
    let nh = lockdown::check(&tx, grant.agent_id, now())
        .await
        .unwrap()
        .unwrap();
    let pg = grants::load_provisioning(&tx, grant.id)
        .await
        .unwrap()
        .unwrap();
    let out = p.provision(&tx, &pg, now()).await;
    let res = match out {
        Ok(state) => {
            let g = grants::activate(&tx, pg, &nh, &state)
                .await
                .unwrap()
                .unwrap();
            drop(nh);
            if let Some(AnyRequest::Provisioning(r)) =
                requests::get(&tx, g.request_id).await.unwrap()
            {
                requests::transition::<_, state::Granted>(&tx, r, (), now())
                    .await
                    .unwrap()
                    .unwrap();
            }
            Ok(g)
        }
        Err(e) => {
            drop(nh);
            grants::fail_provisioning(&tx, pg, &e.to_string(), None)
                .await
                .unwrap()
                .unwrap();
            Err(e.to_string())
        }
    };
    tx.commit().await.unwrap();
    res
}

/// A provisioned, active grant (panics if provisioning fails).
pub async fn granted<P: Provisioner>(
    store: &Store,
    p: &P,
    agent: AgentId,
    authority: &Authority,
    resource: &str,
) -> GrantRow {
    let g = provisioning(store, agent, authority, resource, 3600).await;
    provision(store, p, &g).await.unwrap()
}

#[derive(Debug)]
pub enum CredErr {
    NotIssuable(NotIssuable),
    Provision(ProvisionError),
}

impl CredErr {
    pub fn text(&self) -> String {
        match self {
            CredErr::NotIssuable(n) => n.detail(),
            CredErr::Provision(p) => p.to_string(),
        }
    }
}

/// What the credential route does: the store's issuance check, then the
/// provisioner.
pub async fn credential<P: Provisioner>(
    store: &Store,
    p: &P,
    grant: &GrantRow,
) -> Result<Credential, CredErr> {
    let tx = store.begin().await.unwrap();
    let res = match grants::issuable(&tx, grant.agent_id, grant.id, now())
        .await
        .unwrap()
    {
        Err(n) => Err(CredErr::NotIssuable(n)),
        Ok(issuable) => p
            .credential(&tx, &issuable, now())
            .await
            .map_err(CredErr::Provision),
    };
    tx.commit().await.unwrap();
    res
}

/// The expiry pass for one grant: move its expiry to now, revoke, mark it
/// EXPIRED. A revoke failure leaves it ACTIVE.
pub async fn expire<P: Provisioner>(store: &Store, p: &P, grant: GrantId) -> Result<(), String> {
    let tx = store.begin().await.unwrap();
    grants::expire_now(&tx, grant, now()).await.unwrap();
    tx.commit().await.unwrap();
    revoke_due(store, p, grant).await
}

/// Revoke and end a grant whose expiry already passed.
pub async fn revoke_due<P: Provisioner>(
    store: &Store,
    p: &P,
    grant: GrantId,
) -> Result<(), String> {
    let tx = store.begin().await.unwrap();
    let row = grants::get_for_update(&tx, grant).await.unwrap().unwrap();
    match p.revoke(&tx, &row, now()).await {
        Ok(()) => {
            grants::end(&tx, grant, GrantEnd::Expired, now())
                .await
                .unwrap()
                .unwrap();
            tx.commit().await.unwrap();
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// An operator's revoke of an active, unexpired grant.
pub async fn revoke_now<P: Provisioner>(
    store: &Store,
    p: &P,
    grant: GrantId,
) -> Result<(), String> {
    let tx = store.begin().await.unwrap();
    let row = grants::get_for_update(&tx, grant).await.unwrap().unwrap();
    p.revoke(&tx, &row, now())
        .await
        .map_err(|e| e.to_string())?;
    grants::end(
        &tx,
        grant,
        GrantEnd::Revoked {
            reason: "test (jrt)".into(),
        },
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    Ok(())
}

/// The reaper's revoke of a PROVISIONING grant.
pub async fn reap<P: Provisioner>(store: &Store, p: &P, grant: &GrantRow) -> Result<(), String> {
    let tx = store.begin().await.unwrap();
    let _ = lockdown::check(&tx, grant.agent_id, now()).await.unwrap();
    let pg = grants::load_provisioning(&tx, grant.id)
        .await
        .unwrap()
        .unwrap();
    p.revoke(&tx, pg.grant(), now())
        .await
        .map_err(|e| e.to_string())?;
    grants::fail_provisioning(
        &tx,
        pg,
        "provisioning interrupted; external state reverted",
        Some(now()),
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    Ok(())
}

pub async fn grant(store: &Store, id: GrantId) -> GrantRow {
    let tx = store.begin().await.unwrap();
    let g = grants::get(&tx, id).await.unwrap().unwrap();
    tx.rollback().await.unwrap();
    g
}

/// Validate as the request service does: parse the wire capability/scope,
/// then the platform's validator.
pub async fn validate<P: Provisioner>(
    store: &Store,
    p: &P,
    agent: &AgentRow,
    platform: Platform,
    capability: &str,
    scope: Value,
    resource: &str,
) -> Result<Validated, String> {
    let scope: Map<String, Value> = match scope {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let authority =
        Authority::from_wire(platform, capability, &scope).map_err(|e| format!("wire: {e}"))?;
    let tx = store.begin().await.unwrap();
    let out = p
        .validate(
            &tx,
            RequestSpec {
                agent,
                resource: resource.to_owned(),
                authority,
            },
            now(),
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    out.map_err(|Refused(m)| m)
}

pub fn expose(c: &Credential) -> &str {
    c.value.as_ref().map_or("", |v| v.expose().as_str())
}

/// Record a containment entry holding agents that match `m`.
pub async fn contain(store: &Store, id: &str, m: Value) {
    use agent_auth_store::lockdown::{ContainmentSource, NewEntry};
    let tx = store.begin().await.unwrap();
    lockdown::record(
        &tx,
        &NewEntry {
            id,
            r#match: &m,
            reason: "testing",
            evidence: "",
            by: "jrt",
            source: ContainmentSource::Operator,
            at: now(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
}

pub async fn lift_all(store: &Store) {
    sqlx::query("DELETE FROM containment_entries")
        .execute(store.pool())
        .await
        .unwrap();
}
