//! Kubernetes access through per-grant ServiceAccounts (provisioners spec
//! §4): provision creates a ServiceAccount and a binding to an allowlisted
//! ClusterRole (a RoleBinding in the namespace, or cluster-wide for
//! resource `"*"`); a credential is a short-lived TokenRequest token; revoke
//! deletes the binding(s) and then the ServiceAccount, which kills every
//! token minted for it.
//!
//! Raw HTTP to the API server with the broker's own ServiceAccount token
//! (re-read on every call) and the cluster's CA. A provision that fails
//! half-way removes what it made, and a revoke with no recorded state (the
//! reaper) derives the names from the grant (B10).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::authority::KubernetesAuthority;
use agent_auth_core::policy::Policy;
use agent_auth_core::policy::schema::KubernetesConfig;
use agent_auth_core::{Authority, Glob, Platform, zones};
use agent_auth_crypto::Secret;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::{CatalogEntry, PlatformCatalog};
use reqwest::Method;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::common::{
    agent_ref, at, parse_time, py_isoformat, repr, repr_list, secs_until, store_failed,
};
use super::http::{Http, MAX_BODY, Reply};
use super::setup::{ConfigError, Env};
use super::{Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated};

const IN_CLUSTER_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const IN_CLUSTER_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
/// TokenRequest refuses expirations under 10 minutes.
const MIN_TOKEN_SECS: i64 = 600;
const MAX_TOKEN_SECS: i64 = 3600;
/// The resource that means "cluster-wide".
pub const CLUSTER: &str = "*";
const TIMEOUT: Duration = Duration::from_secs(20);
const RBAC: &str = "/apis/rbac.authorization.k8s.io/v1";

/// `aa-<≤22-char sanitized agent>-<full grant id>`, at most 63 characters
/// (INV-K1).
#[must_use]
pub fn sa_name(agent_name: &str, grant_id: &str) -> String {
    let mut base = String::new();
    let mut in_run = false;
    for c in agent_name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            base.push(c);
            in_run = false;
        } else if !in_run {
            base.push('-');
            in_run = true;
        }
    }
    let base: String = base.trim_matches('-').chars().take(22).collect();
    let base = base.trim_end_matches('-');
    let name: String = format!("aa-{base}-{grant_id}").chars().take(63).collect();
    name.trim_end_matches('-').to_owned()
}

fn namespace_ok(ns: &str) -> bool {
    let b = ns.as_bytes();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    match (b.first(), b.last()) {
        (Some(f), Some(l)) => edge(f) && edge(l) && b.iter().all(|c| edge(c) || *c == b'-'),
        _ => false,
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Accepts any server certificate (`KUBERNETES_INSECURE_SKIP_VERIFY`).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn insecure_tls() -> Result<rustls::ClientConfig, ConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(
        rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| ConfigError(format!("kubernetes TLS: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth(),
    )
}

/// How the broker authenticates to the API server.
#[derive(Debug)]
enum Bearer {
    /// Re-read on every call (projected tokens rotate).
    File(PathBuf),
    Fixed(Secret<String>),
    None,
}

#[derive(Debug)]
pub struct KubernetesProvisioner {
    /// The preferred endpoint first (the last one that answered).
    endpoints: Mutex<Vec<String>>,
    bearer: Bearer,
    http: Http,
    config: KubernetesConfig,
    /// For the restricted zones (namespaces a cluster-wide grant leaves out).
    policy: Arc<Policy>,
}

impl KubernetesProvisioner {
    /// `KUBERNETES_API_URL` (`in-cluster` or a comma-separated list; none:
    /// off), `KUBERNETES_TOKEN`, `KUBERNETES_TOKEN_FILE`,
    /// `KUBERNETES_CA_FILE`, `KUBERNETES_INSECURE_SKIP_VERIFY`.
    pub fn from_env(
        env: &Env<'_>,
        config: &KubernetesConfig,
        policy: Arc<Policy>,
    ) -> Result<Option<KubernetesProvisioner>, ConfigError> {
        let api = env.get("KUBERNETES_API_URL");
        if api.is_empty() {
            return Ok(None);
        }
        let mut token_file = env.get("KUBERNETES_TOKEN_FILE");
        let mut ca_file = env.get("KUBERNETES_CA_FILE");
        let urls: Vec<String> = if api == "in-cluster" {
            let host = env.get_or("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc");
            let port = env.get_or("KUBERNETES_SERVICE_PORT", "443");
            if token_file.is_empty() {
                IN_CLUSTER_TOKEN.clone_into(&mut token_file);
            }
            if ca_file.is_empty() {
                IN_CLUSTER_CA.clone_into(&mut ca_file);
            }
            vec![format!("https://{host}:{port}")]
        } else {
            api.split(',')
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(str::to_owned)
                .collect()
        };
        if urls.is_empty() {
            return Err(ConfigError("kubernetes api_url is empty".to_owned()));
        }
        let tls = if env.flag("KUBERNETES_INSECURE_SKIP_VERIFY")? {
            tracing::warn!(
                "KUBERNETES_INSECURE_SKIP_VERIFY: the API server's certificate is not checked"
            );
            insecure_tls()?
        } else if ca_file.is_empty() {
            agent_auth_tls::default_client_config()
                .map_err(|e| ConfigError(format!("kubernetes TLS: {e}")))?
        } else {
            let pem = std::fs::read(&ca_file)
                .map_err(|e| ConfigError(format!("KUBERNETES_CA_FILE {ca_file}: {e}")))?;
            let roots = agent_auth_tls::root_store_with(&pem)
                .map_err(|e| ConfigError(format!("KUBERNETES_CA_FILE {ca_file}: {e}")))?;
            agent_auth_tls::client_config(roots)
                .map_err(|e| ConfigError(format!("kubernetes TLS: {e}")))?
        };
        let token = env.get("KUBERNETES_TOKEN");
        let bearer = if !token_file.is_empty() {
            Bearer::File(PathBuf::from(token_file))
        } else if !token.is_empty() {
            Bearer::Fixed(Secret::new(token))
        } else {
            Bearer::None
        };
        Ok(Some(KubernetesProvisioner::new(
            urls,
            bearer_parts(bearer),
            config.clone(),
            policy,
            Http::with_tls(tls)?,
        )))
    }

    /// `token_file` wins over `token`.
    #[must_use]
    pub fn new(
        urls: Vec<String>,
        (token_file, token): (Option<PathBuf>, Option<Secret<String>>),
        config: KubernetesConfig,
        policy: Arc<Policy>,
        http: Http,
    ) -> KubernetesProvisioner {
        let bearer = match (token_file, token) {
            (Some(f), _) => Bearer::File(f),
            (None, Some(t)) => Bearer::Fixed(t),
            (None, None) => Bearer::None,
        };
        KubernetesProvisioner {
            endpoints: Mutex::new(
                urls.into_iter()
                    .map(|u| u.trim_end_matches('/').to_owned())
                    .collect(),
            ),
            bearer,
            http,
            config,
            policy,
        }
    }

    /// The endpoint currently preferred.
    #[must_use]
    pub fn api_url(&self) -> String {
        lock(&self.endpoints).first().cloned().unwrap_or_default()
    }

    fn bearer(&self) -> Result<Secret<String>, ProvisionError> {
        match &self.bearer {
            Bearer::File(path) => std::fs::read_to_string(path)
                .map(|t| Secret::new(t.trim().to_owned()))
                .map_err(|e| {
                    tracing::error!(error = %e, file = %path.display(), "kubernetes token file");
                    ProvisionError::failed("cannot read kubernetes token file (see broker logs)")
                }),
            Bearer::Fixed(t) => Ok(t.clone()),
            Bearer::None => Err(ProvisionError::failed(
                "no kubernetes credentials configured",
            )),
        }
    }

    /// Try each endpoint in turn; a transport failure moves on, any HTTP
    /// answer is the caller's. The endpoint that answered becomes first.
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Reply, ProvisionError> {
        let bearer = self.bearer()?;
        let endpoints = lock(&self.endpoints).clone();
        for (i, base) in endpoints.iter().enumerate() {
            let mut rb = self
                .http
                .request(method.clone(), &format!("{base}{path}"))
                .header("Authorization", format!("Bearer {}", bearer.expose()));
            if let Some(b) = body {
                rb = rb.json(b);
            }
            match self.http.send(rb, TIMEOUT, MAX_BODY).await {
                Ok(r) => {
                    if i > 0 {
                        let mut rotated = endpoints.get(i..).unwrap_or_default().to_vec();
                        rotated.extend_from_slice(endpoints.get(..i).unwrap_or_default());
                        *lock(&self.endpoints) = rotated;
                    }
                    return Ok(r);
                }
                Err(e) => {
                    tracing::warn!(endpoint = %base, error = %e, "kubernetes API unreachable");
                }
            }
        }
        Err(ProvisionError::failed(
            "kubernetes API unreachable (see broker logs)",
        ))
    }

    async fn create(&self, path: &str, body: &Value) -> Result<(), ProvisionError> {
        let kind = at(body, &["kind"]).as_str().unwrap_or("object");
        let r = self.request(Method::POST, path, Some(body)).await?;
        match r.status {
            200 | 201 => Ok(()),
            409 => self.verify_ours(path, body).await,
            status => {
                tracing::error!(kind, path, status, body = %r.head(300), "kubernetes create failed");
                Err(ProvisionError::failed(format!(
                    "create {kind} failed ({status})"
                )))
            }
        }
    }

    /// AlreadyExists is success only for this grant's own object (INV-K3).
    async fn verify_ours(&self, collection: &str, body: &Value) -> Result<(), ProvisionError> {
        let kind = at(body, &["kind"]).as_str().unwrap_or("object");
        let name = at(body, &["metadata", "name"]).as_str().unwrap_or("");
        let r = self
            .request(Method::GET, &format!("{collection}/{name}"), None)
            .await?;
        if r.status != 200 {
            return Err(ProvisionError::failed(format!(
                "{kind} {} already exists but could not be verified ({}); refusing to adopt it",
                repr(name),
                r.status
            )));
        }
        let existing = r.json();
        let want = at(body, &["metadata", "annotations", "agent-auth/grant-id"])
            .as_str()
            .unwrap_or("");
        let have = at(
            &existing,
            &["metadata", "annotations", "agent-auth/grant-id"],
        )
        .as_str();
        let mut differ = Vec::new();
        if want.is_empty() || have != Some(want) {
            differ.push("grant-id annotation");
        }
        if let Some(rr) = body.get("roleRef")
            && existing.get("roleRef") != Some(rr)
        {
            differ.push("roleRef");
        }
        if let Some(s) = body.get("subjects")
            && existing.get("subjects") != Some(s)
        {
            differ.push("subjects");
        }
        if differ.is_empty() {
            return Ok(());
        }
        tracing::error!(kind, name, differ = %differ.join(", "), "existing object is not this grant's");
        Err(ProvisionError::failed(format!(
            "{kind} {} already exists and belongs to something else ({} differ); refusing to adopt it",
            repr(name),
            differ.join(", ")
        )))
    }

    async fn delete(&self, path: &str) -> Result<(), ProvisionError> {
        let r = self.request(Method::DELETE, path, None).await?;
        match r.status {
            200 | 202 | 404 => Ok(()),
            status => {
                tracing::error!(path, status, body = %r.head(300), "kubernetes delete failed");
                Err(ProvisionError::failed(format!("delete failed ({status})")))
            }
        }
    }

    /// Cleanup after a failed provision: logged, never masks the cause.
    async fn undo(&self, path: &str) {
        if let Err(e) = self.delete(path).await {
            tracing::error!(path, error = %e, "cleanup after a failed provision failed");
        }
    }

    async fn namespaces(&self) -> Result<Vec<String>, ProvisionError> {
        let r = self
            .request(Method::GET, "/api/v1/namespaces", None)
            .await?;
        if r.status != 200 {
            // Fail closed: without the list no grant leaves the zones out.
            return Err(ProvisionError::failed(format!(
                "listing namespaces failed ({})",
                r.status
            )));
        }
        let mut names: Vec<String> = at(&r.json(), &["items"])
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|i| at(i, &["metadata", "name"]).as_str().map(str::to_owned))
            .collect();
        names.sort();
        Ok(names)
    }

    fn excluded(&self, agent: &AgentRow) -> Vec<String> {
        zones::excluded_namespaces(&self.policy, &agent_ref(agent))
    }

    async fn provision_grant(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
    ) -> Result<Value, ProvisionError> {
        let agent = agents::get(tx, grant.agent_id)
            .await
            .map_err(|e| store_failed(&e))?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        let Authority::Kubernetes(KubernetesAuthority { role, .. }) = &grant.authority else {
            return Err(ProvisionError::failed("not a kubernetes grant"));
        };
        let name = sa_name(&agent.name, &grant.id.to_string());
        let cluster = grant.resource == CLUSTER;
        // Every grant's ServiceAccount lives in the grant namespace, which
        // no grant may target: nobody with rights in the target namespace
        // can run a pod as it.
        let sa_ns = self.config.grant_namespace.clone();
        if !cluster && grant.resource == sa_ns {
            return Err(ProvisionError::failed(self.grant_namespace_refusal()));
        }
        let labels = json!({"app.kubernetes.io/managed-by": "agent-auth"});
        let annotations = json!({
            "agent-auth/agent": agent.name,
            "agent-auth/grant-id": grant.id.to_string(),
            "agent-auth/expires-at": py_isoformat(grant.expires_at),
        });
        let sa_path = format!("/api/v1/namespaces/{sa_ns}/serviceaccounts");
        self.create(
            &sa_path,
            &json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": name, "namespace": sa_ns, "labels": labels, "annotations": annotations},
            }),
        )
        .await?;
        let binding = Binding {
            name: &name,
            sa_ns: &sa_ns,
            role,
            labels: &labels,
            annotations: &annotations,
        };
        let excluded = if cluster {
            self.excluded(&agent)
        } else {
            Vec::new()
        };
        let bound = if cluster && !excluded.is_empty() {
            self.bind_around_zones(&binding, &excluded).await.map(Some)
        } else if cluster {
            self.create(&format!("{RBAC}/clusterrolebindings"), &binding.cluster())
                .await
                .map(|()| None)
        } else {
            let target = &grant.resource;
            self.create(
                &format!("{RBAC}/namespaces/{target}/rolebindings"),
                &binding.namespaced(target),
            )
            .await
            .map(|()| None)
        };
        let bound = match bound {
            Ok(b) => b,
            Err(e) => {
                // No state is saved for a failed grant: undo it here (B10).
                self.undo(&format!("{sa_path}/{name}")).await;
                return Err(e);
            }
        };
        let mut state =
            json!({"namespace": sa_ns, "service_account": name, "role": role, "cluster": cluster});
        if let Value::Object(map) = &mut state {
            if let Some(bound) = bound {
                map.insert("bound_namespaces".into(), json!(bound));
                map.insert("excluded".into(), json!(excluded));
            } else if !cluster {
                map.insert("binding_namespace".into(), json!(grant.resource));
            }
        }
        Ok(state)
    }

    /// A cluster-wide grant past a zone: a RoleBinding in every namespace
    /// that matches no excluded glob, never a ClusterRoleBinding (INV-K5).
    /// On failure the bindings made so far are removed.
    async fn bind_around_zones(
        &self,
        b: &Binding<'_>,
        excluded: &[String],
    ) -> Result<Vec<String>, ProvisionError> {
        let globs: Vec<Glob> = excluded.iter().map(|g| Glob::new(g)).collect();
        let bound: Vec<String> = self
            .namespaces()
            .await?
            .into_iter()
            .filter(|ns| !globs.iter().any(|g| g.matches(ns)))
            // Never a binding where the grants' ServiceAccounts live.
            .filter(|ns| *ns != self.config.grant_namespace)
            .collect();
        let mut made: Vec<&str> = Vec::new();
        for ns in &bound {
            if let Err(e) = self
                .create(
                    &format!("{RBAC}/namespaces/{ns}/rolebindings"),
                    &b.namespaced(ns),
                )
                .await
            {
                for done in made {
                    self.undo(&format!("{RBAC}/namespaces/{done}/rolebindings/{}", b.name))
                        .await;
                }
                return Err(e);
            }
            made.push(ns);
        }
        Ok(bound)
    }

    async fn revoke_grant(&self, tx: &Tx<'_>, grant: &GrantRow) -> Result<(), ProvisionError> {
        let state = &grant.provisioner_state;
        let recorded = (
            state
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
            state
                .get("service_account")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
        );
        if let (Some(ns), Some(name)) = recorded {
            if let Some(bound) = state.get("bound_namespaces").filter(|b| !b.is_null()) {
                for b in bound
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    self.delete(&format!("{RBAC}/namespaces/{b}/rolebindings/{name}"))
                        .await?;
                }
            } else if state.get("cluster").and_then(Value::as_bool) == Some(true) {
                self.delete(&format!("{RBAC}/clusterrolebindings/{name}"))
                    .await?;
            } else {
                let target = state
                    .get("binding_namespace")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(ns);
                self.delete(&format!("{RBAC}/namespaces/{target}/rolebindings/{name}"))
                    .await?;
            }
            // Deleting the ServiceAccount invalidates every token minted for it.
            return self
                .delete(&format!("/api/v1/namespaces/{ns}/serviceaccounts/{name}"))
                .await;
        }
        // No recorded state: an interrupted provision (the reaper). What it
        // may have made is named after the grant, so remove that (B10).
        let Some(agent) = agents::get(tx, grant.agent_id)
            .await
            .map_err(|e| store_failed(&e))?
        else {
            return Ok(());
        };
        let name = sa_name(&agent.name, &grant.id.to_string());
        let cluster = grant.resource == CLUSTER;
        let sa_ns = self.config.grant_namespace.clone();
        if cluster {
            self.delete(&format!("{RBAC}/clusterrolebindings/{name}"))
                .await?;
            if !self.excluded(&agent).is_empty() {
                for ns in self.namespaces().await? {
                    self.delete(&format!("{RBAC}/namespaces/{ns}/rolebindings/{name}"))
                        .await?;
                }
            }
        } else {
            let target = &grant.resource;
            self.delete(&format!("{RBAC}/namespaces/{target}/rolebindings/{name}"))
                .await?;
        }
        self.delete(&format!(
            "/api/v1/namespaces/{sa_ns}/serviceaccounts/{name}"
        ))
        .await
    }

    async fn credential_for(
        &self,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let state = &grant.provisioner_state;
        let (Some(ns), Some(name)) = (
            state
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
            state
                .get("service_account")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
        ) else {
            return Err(ProvisionError::failed(
                "grant has no provisioned service account",
            ));
        };
        let remaining = secs_until(grant.expires_at, now);
        let expiration = remaining.clamp(MIN_TOKEN_SECS, MAX_TOKEN_SECS);
        let r = self
            .request(
                Method::POST,
                &format!("/api/v1/namespaces/{ns}/serviceaccounts/{name}/token"),
                Some(&json!({
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "TokenRequest",
                    "spec": {"expirationSeconds": expiration},
                })),
            )
            .await?;
        if !matches!(r.status, 200 | 201) {
            tracing::error!(ns, name, status = r.status, body = %r.head(300), "TokenRequest failed");
            return Err(ProvisionError::failed(format!(
                "TokenRequest failed ({})",
                r.status
            )));
        }
        let body = r.json();
        let status = &at(&body, &["status"]);
        let role = match state.get("role") {
            Some(Value::String(s)) => s.clone(),
            _ => "None".to_owned(),
        };
        let bound = if state.get("cluster").and_then(Value::as_bool) == Some(true) {
            "cluster-wide".to_owned()
        } else {
            let target = state
                .get("binding_namespace")
                .and_then(Value::as_str)
                .unwrap_or(ns);
            format!("in namespace {target}")
        };
        Ok(Credential {
            kind: "kubernetes_token".to_owned(),
            value: at(status, &["token"])
                .as_str()
                .map(|t| Secret::new(t.to_owned())),
            expires_at: at(status, &["expirationTimestamp"])
                .as_str()
                .and_then(parse_time),
            note: Some(format!(
                "bearer token for ServiceAccount {ns}/{name} ({role} {bound}) against {}; re-fetch rather than caching — the account is deleted when the grant ends",
                self.api_url()
            )),
            ..Credential::default()
        })
    }

    fn grant_namespace_refusal(&self) -> String {
        format!(
            "namespace {} holds the grants' ServiceAccounts and is never brokered",
            repr(&self.config.grant_namespace)
        )
    }

    fn validate_spec(&self, spec: &RequestSpec<'_>) -> Result<Validated, Refused> {
        let Authority::Kubernetes(k) = &spec.authority else {
            return Err(Refused("kubernetes capability is the role name".to_owned()));
        };
        let role = k.role.trim().to_owned();
        let namespace = spec.resource.trim().to_lowercase();
        let cfg = &self.config;
        if namespace == CLUSTER {
            if cfg.cluster_role_allowlist.is_empty() {
                return Err(Refused("cluster-wide grants are not enabled".to_owned()));
            }
            if !cfg.cluster_role_allowlist.contains(&role) {
                return Err(Refused(format!(
                    "role {} is not grantable cluster-wide; allowed: {}",
                    repr(&role),
                    repr_list(&cfg.cluster_role_allowlist)
                )));
            }
            let note = format!(
                "binds role {} CLUSTER-WIDE across all namespaces — very broad; always human-reviewed",
                repr(&role)
            );
            return Ok(Validated {
                resource: CLUSTER.to_owned(),
                authority: Authority::Kubernetes(KubernetesAuthority {
                    role,
                    cluster: true,
                }),
                notes: vec![note],
            });
        }
        if !cfg.role_allowlist.contains(&role) {
            return Err(Refused(format!(
                "role {} is not grantable; allowed: {}",
                repr(&role),
                repr_list(&cfg.role_allowlist)
            )));
        }
        if !namespace_ok(&namespace) {
            return Err(Refused(format!(
                "invalid namespace name {}",
                repr(&namespace)
            )));
        }
        // Whatever the allowlist says (like LLDAP's admin groups).
        if namespace == cfg.grant_namespace {
            return Err(Refused(self.grant_namespace_refusal()));
        }
        if !cfg
            .namespace_allowlist
            .iter()
            .any(|g| g.matches(&namespace))
        {
            return Err(Refused(format!(
                "namespace {} is not brokered (allowlist)",
                repr(&namespace)
            )));
        }
        let mut notes = vec![format!(
            "binds role {} in namespace {} (namespace-scoped)",
            repr(&role),
            repr(&namespace)
        )];
        if role == "edit" || role == "admin" {
            notes.push(format!(
                "{role} can run pods as any ServiceAccount in {namespace} — broad"
            ));
        }
        if cfg.namespace_is_sensitive(&namespace) {
            notes.push(format!(
                "{namespace} is a sensitive namespace (its ServiceAccounts are the cluster's own or back other grants) — always human-reviewed"
            ));
        }
        Ok(Validated {
            resource: namespace,
            authority: Authority::Kubernetes(KubernetesAuthority {
                role,
                cluster: false,
            }),
            notes,
        })
    }
}

fn bearer_parts(b: Bearer) -> (Option<PathBuf>, Option<Secret<String>>) {
    match b {
        Bearer::File(f) => (Some(f), None),
        Bearer::Fixed(t) => (None, Some(t)),
        Bearer::None => (None, None),
    }
}

/// What every binding of one grant shares.
struct Binding<'a> {
    name: &'a str,
    sa_ns: &'a str,
    role: &'a str,
    labels: &'a Value,
    annotations: &'a Value,
}

impl Binding<'_> {
    fn role_ref(&self) -> Value {
        json!({"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": self.role})
    }
    fn subjects(&self) -> Value {
        json!([{"kind": "ServiceAccount", "name": self.name, "namespace": self.sa_ns}])
    }
    fn metadata(&self, ns: Option<&str>) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), json!(self.name));
        if let Some(ns) = ns {
            m.insert("namespace".into(), json!(ns));
        }
        m.insert("labels".into(), self.labels.clone());
        m.insert("annotations".into(), self.annotations.clone());
        Value::Object(m)
    }
    fn namespaced(&self, ns: &str) -> Value {
        json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": self.metadata(Some(ns)),
            "roleRef": self.role_ref(),
            "subjects": self.subjects(),
        })
    }
    fn cluster(&self) -> Value {
        json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": self.metadata(None),
            "roleRef": self.role_ref(),
            "subjects": self.subjects(),
        })
    }
}

impl Provisioner for KubernetesProvisioner {
    fn platform(&self) -> Platform {
        Platform::Kubernetes
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        Ok(self.validate_spec(&spec))
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let grant = grant.grant();
        self.provision_grant(tx, grant).await
    }

    async fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        self.revoke_grant(tx, grant).await
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        self.credential_for(issuable.grant(), now).await
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let cfg = &self.config;
        let mut c = PlatformCatalog::new(
            Platform::Kubernetes,
            "<role name>",
            "<namespace>, or \"*\" for cluster-wide",
        );
        c.namespace_allowlist = Some(
            cfg.namespace_allowlist
                .iter()
                .map(|g| g.as_str().to_owned())
                .collect(),
        );
        // `typical_disposition` is the catalog route's (policy engine).
        c.roles = Some(
            cfg.role_allowlist
                .iter()
                .map(|r| CatalogEntry {
                    name: r.clone(),
                    description: cfg.role_descriptions.get(r).cloned(),
                    typical_disposition: None,
                })
                .collect(),
        );
        if !cfg.cluster_role_allowlist.is_empty() {
            c.cluster_roles = Some(cfg.cluster_role_allowlist.clone());
        }
        serde_json::to_value(c).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sa_names() {
        let id = "0b3c9a4e-1111-4222-8333-444455556666";
        assert_eq!(
            sa_name("homelab-agent", id),
            format!("aa-homelab-agent-{id}")
        );
        assert_eq!(sa_name("My_Agent.X", id), format!("aa-my-agent-x-{id}"));
        let long = sa_name("a-very-long-agent-name-that-goes-on", id);
        assert!(long.len() <= 63, "{long}");
        assert!(long.ends_with(id));
        assert_eq!(long, format!("aa-a-very-long-agent-name-{id}"));
        assert_eq!(sa_name("__", id), format!("aa--{id}"));
    }

    #[test]
    fn namespaces() {
        for ok in ["apps", "a", "apps-cactus", "x1"] {
            assert!(namespace_ok(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "A", "a.b", "a_b"] {
            assert!(!namespace_ok(bad), "{bad}");
        }
    }
}
