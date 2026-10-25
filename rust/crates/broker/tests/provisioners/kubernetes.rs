//! Kubernetes (provisioners spec §4, §14), against a fake API server that
//! keeps objects by path.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agent_auth_broker::provisioners::Provisioner;
use agent_auth_broker::provisioners::http::Http;
use agent_auth_broker::provisioners::kubernetes::{KubernetesProvisioner, sa_name};
use agent_auth_core::authority::KubernetesAuthority;
use agent_auth_core::policy::Policy;
use agent_auth_core::policy::schema::KubernetesConfig;
use agent_auth_core::{Authority, Glob, Platform};
use agent_auth_store::Store;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::common::*;

#[derive(Debug, Default)]
pub struct K8s {
    objects: BTreeMap<String, Value>,
    namespaces: Vec<String>,
    /// POSTs to a path starting with this fail with 500.
    fail_post: Option<String>,
}

fn k8s_handler(s: &Arc<Mutex<K8s>>, c: &Call) -> R {
    let mut st = s.lock().unwrap();
    if !c.header("authorization").starts_with("Bearer sa-token") {
        return r(401, json!({}));
    }
    match c.method.as_str() {
        "POST" if c.path.ends_with("/token") => r(
            201,
            json!({"status": {"token": "k8s-tok", "expirationTimestamp": "2030-01-01T00:00:00Z"}}),
        ),
        "POST" => {
            if st
                .fail_post
                .as_deref()
                .is_some_and(|f| c.path.starts_with(f))
            {
                return r(500, json!({"message": "internal detail"}));
            }
            let key = format!(
                "{}/{}",
                c.path,
                c.body["metadata"]["name"].as_str().unwrap()
            );
            if st.objects.contains_key(&key) {
                return r(409, json!({"reason": "AlreadyExists"}));
            }
            st.objects.insert(key, c.body.clone());
            r(201, c.body.clone())
        }
        "GET" if c.path == "/api/v1/namespaces" => r(
            200,
            json!({"items": st.namespaces.iter().map(|n| json!({"metadata": {"name": n}})).collect::<Vec<_>>()}),
        ),
        "GET" => match st.objects.get(&c.path) {
            Some(o) => r(200, o.clone()),
            None => r(404, json!({})),
        },
        "DELETE" => match st.objects.remove(&c.path) {
            Some(_) => r(200, json!({})),
            None => r(404, json!({})),
        },
        _ => r(405, json!({})),
    }
}

pub struct K {
    store: Store,
    fake: Fake,
    state: Arc<Mutex<K8s>>,
    p: KubernetesProvisioner,
    token_file: PathBuf,
}

fn config() -> KubernetesConfig {
    let mut c = KubernetesConfig::default();
    c.namespace_allowlist = vec![Glob::new("apps-*"), Glob::new("kube-system")];
    c.role_allowlist = vec!["view".into(), "edit".into()];
    c.cluster_role_allowlist = vec!["view".into()];
    c
}

async fn setup_with(pool: PgPool, cfg: KubernetesConfig, policy: Policy) -> K {
    let state = Arc::new(Mutex::new(K8s {
        namespaces: vec!["apps-a".into(), "apps-b".into(), "soc-x".into()],
        ..K8s::default()
    }));
    let s2 = state.clone();
    let fake = Fake::start(move |c| k8s_handler(&s2, c)).await;
    let token_file = std::env::temp_dir().join(format!("aa-k8s-{}", uuid::Uuid::new_v4()));
    std::fs::write(&token_file, "sa-token-1\n").unwrap();
    let p = KubernetesProvisioner::new(
        vec![format!("{}/", fake.url)],
        (Some(token_file.clone()), None),
        cfg,
        Arc::new(policy),
        Http::new().unwrap(),
    );
    K {
        store: Store::from_pool(pool),
        fake,
        state,
        p,
        token_file,
    }
}

async fn setup(pool: PgPool) -> K {
    setup_with(pool, config(), Policy::default()).await
}

fn role(r: &str, cluster: bool) -> Authority {
    Authority::Kubernetes(KubernetesAuthority {
        role: r.into(),
        cluster,
    })
}

impl K {
    fn objects(&self) -> Vec<String> {
        self.state.lock().unwrap().objects.keys().cloned().collect()
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn validation(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    let v = |cap: &'static str, res: &'static str| {
        let (store, p, a) = (t.store.clone(), &t.p, a.clone());
        async move { validate(&store, p, &a, Platform::Kubernetes, cap, json!({}), res).await }
    };
    let ok = v("view", " APPS-cactus ").await.unwrap();
    assert_eq!(ok.resource, "apps-cactus");
    assert_eq!(ok.authority, role("view", false));
    assert_eq!(
        ok.notes,
        ["binds role 'view' in namespace 'apps-cactus' (namespace-scoped)"]
    );
    let edit = v("edit", "apps-x").await.unwrap();
    assert_eq!(
        edit.notes[1],
        "edit can run pods as any ServiceAccount in apps-x — broad"
    );
    let sens = v("view", "kube-system").await.unwrap();
    assert_eq!(
        sens.notes[1],
        "kube-system is a sensitive namespace (its ServiceAccounts are the cluster's own or back other grants) — always human-reviewed"
    );
    assert_eq!(
        v("view", "other").await.unwrap_err(),
        "namespace 'other' is not brokered (allowlist)"
    );
    assert_eq!(
        v("admin", "apps-x").await.unwrap_err(),
        "role 'admin' is not grantable; allowed: ['view', 'edit']"
    );
    assert_eq!(
        v("view", "apps_x").await.unwrap_err(),
        "invalid namespace name 'apps_x'"
    );
    let cluster = v("view", "*").await.unwrap();
    assert_eq!(
        (cluster.resource.as_str(), &cluster.authority),
        ("*", &role("view", true))
    );
    assert_eq!(
        cluster.notes,
        [
            "binds role 'view' CLUSTER-WIDE across all namespaces — very broad; always human-reviewed"
        ]
    );
    assert_eq!(
        v("edit", "*").await.unwrap_err(),
        "role 'edit' is not grantable cluster-wide; allowed: ['view']"
    );
    // A namespaced request drops `cluster`.
    let s = validate(
        &t.store,
        &t.p,
        &a,
        Platform::Kubernetes,
        "view",
        json!({"cluster": true}),
        "apps-a",
    )
    .await
    .unwrap();
    assert_eq!(s.authority, role("view", false));

    let off = setup_with(
        t.store.pool().clone(),
        KubernetesConfig::default(),
        Policy::default(),
    )
    .await;
    assert_eq!(
        validate(
            &off.store,
            &off.p,
            &a,
            Platform::Kubernetes,
            "view",
            json!({}),
            "*"
        )
        .await
        .unwrap_err(),
        "cluster-wide grants are not enabled"
    );
    assert_eq!(
        validate(
            &off.store,
            &off.p,
            &a,
            Platform::Kubernetes,
            "view",
            json!({}),
            "anything"
        )
        .await
        .unwrap_err(),
        "namespace 'anything' is not brokered (allowlist)"
    );
    let mut star = config();
    star.namespace_allowlist = vec![Glob::new("*")];
    let star = setup_with(t.store.pool().clone(), star, Policy::default()).await;
    assert!(
        validate(
            &star.store,
            &star.p,
            &a,
            Platform::Kubernetes,
            "view",
            json!({}),
            "whatever"
        )
        .await
        .is_ok()
    );
    assert!(
        validate(
            &star.store,
            &star.p,
            &a,
            Platform::Kubernetes,
            "admin",
            json!({}),
            "whatever"
        )
        .await
        .is_err()
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn full_cycle(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    let g = granted(&t.store, &t.p, a.id, &role("view", false), "apps-a").await;
    let name = sa_name("k8s-agent", &g.id.to_string());
    assert_eq!(name, format!("aa-k8s-agent-{}", g.id));
    let sa = t
        .fake
        .find("POST", "/api/v1/namespaces/apps-a/serviceaccounts");
    assert_eq!(
        sa[0].body["metadata"]["annotations"]["agent-auth/grant-id"],
        json!(g.id.to_string())
    );
    assert_eq!(
        sa[0].body["metadata"]["labels"],
        json!({"app.kubernetes.io/managed-by": "agent-auth"})
    );
    let rb = t.fake.find(
        "POST",
        "/apis/rbac.authorization.k8s.io/v1/namespaces/apps-a/rolebindings",
    );
    assert_eq!(
        rb[0].body["roleRef"],
        json!({"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"})
    );
    assert_eq!(
        rb[0].body["subjects"],
        json!([{"kind": "ServiceAccount", "name": name, "namespace": "apps-a"}])
    );
    assert_eq!(
        g.provisioner_state,
        json!({"namespace": "apps-a", "service_account": name, "role": "view", "cluster": false})
    );

    // The token file is re-read on every call.
    std::fs::write(&t.token_file, "sa-token-2").unwrap();
    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(
        (c.kind.as_str(), expose(&c)),
        ("kubernetes_token", "k8s-tok")
    );
    let tr = t.fake.find(
        "POST",
        &format!("/api/v1/namespaces/apps-a/serviceaccounts/{name}/token"),
    );
    assert_eq!(tr[0].header("authorization"), "Bearer sa-token-2");
    let secs = tr[0].body["spec"]["expirationSeconds"].as_i64().unwrap();
    assert!((3500..=3600).contains(&secs), "{secs}");
    assert_eq!(tr[0].body["kind"], "TokenRequest");
    assert!(c.note.unwrap().starts_with(&format!(
        "bearer token for ServiceAccount apps-a/{name} (view) against {}",
        t.fake.url
    )));

    expire(&t.store, &t.p, g.id).await.unwrap();
    let deletes: Vec<String> = t
        .fake
        .calls()
        .into_iter()
        .filter(|c| c.method == "DELETE")
        .map(|c| c.path)
        .collect();
    assert_eq!(
        deletes,
        [
            format!("/apis/rbac.authorization.k8s.io/v1/namespaces/apps-a/rolebindings/{name}"),
            format!("/api/v1/namespaces/apps-a/serviceaccounts/{name}"),
        ]
    );
    assert!(t.objects().is_empty());
    assert_eq!(
        credential(&t.store, &t.p, &g).await.unwrap_err().text(),
        "grant is not active; refusing to mint a token"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_short_grant_gets_the_minimum_token(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    let g = provisioning(&t.store, a.id, &role("view", false), "apps-a", 120).await;
    let g = provision(&t.store, &t.p, &g).await.unwrap();
    credential(&t.store, &t.p, &g).await.unwrap();
    let tr = t
        .fake
        .calls()
        .into_iter()
        .find(|c| c.path.ends_with("/token"))
        .unwrap();
    assert_eq!(tr.body["spec"]["expirationSeconds"], json!(600));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn existing_objects_are_adopted_only_when_they_are_this_grants(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    // Our own leftover (a retried provision): proceeds.
    let g = provisioning(&t.store, a.id, &role("view", false), "apps-a", 3600).await;
    let name = sa_name("k8s-agent", &g.id.to_string());
    t.state.lock().unwrap().objects.insert(
        format!("/api/v1/namespaces/apps-a/serviceaccounts/{name}"),
        json!({"metadata": {"name": name, "annotations": {"agent-auth/grant-id": g.id.to_string()}}}),
    );
    provision(&t.store, &t.p, &g).await.unwrap();

    // Someone else's object under the name: refused, nothing bound.
    let g = provisioning(&t.store, a.id, &role("view", false), "apps-b", 3600).await;
    let name = sa_name("k8s-agent", &g.id.to_string());
    t.state.lock().unwrap().objects.insert(
        format!("/api/v1/namespaces/apps-b/serviceaccounts/{name}"),
        json!({"metadata": {"name": name, "annotations": {"agent-auth/grant-id": "someone-else"}}}),
    );
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(
        err,
        format!(
            "ServiceAccount '{name}' already exists and belongs to something else (grant-id annotation differ); refusing to adopt it"
        )
    );
    assert!(
        !t.objects()
            .iter()
            .any(|o| o.contains("apps-b/rolebindings"))
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_cluster_wide_grant_binds_a_cluster_role_binding(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    let g = granted(&t.store, &t.p, a.id, &role("view", true), "*").await;
    let name = sa_name("k8s-agent", &g.id.to_string());
    assert_eq!(
        t.fake
            .count("POST", "/api/v1/namespaces/default/serviceaccounts"),
        1
    );
    let crb = t.fake.find(
        "POST",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    );
    assert_eq!(
        crb[0].body["subjects"],
        json!([{"kind": "ServiceAccount", "name": name, "namespace": "default"}])
    );
    assert!(crb[0].body["metadata"].get("namespace").is_none());
    assert_eq!(g.provisioner_state["cluster"], json!(true));
    expire(&t.store, &t.p, g.id).await.unwrap();
    assert!(t.objects().is_empty());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_zone_keeps_cluster_wide_grants_out(pool: PgPool) {
    let policy = Policy::from_value(
        json!({"restricted": {"soc": {"members": ["soc-*"], "kubernetes": ["soc-*"]}}}),
    )
    .unwrap();
    let t = setup_with(pool, config(), policy).await;
    let a = agent(&t.store, "k8s-agent").await;
    let g = granted(&t.store, &t.p, a.id, &role("view", true), "*").await;
    // INV-K5: no ClusterRoleBinding; RoleBindings outside the zone only.
    assert_eq!(
        t.fake.count(
            "POST",
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
        ),
        0
    );
    assert_eq!(
        g.provisioner_state["bound_namespaces"],
        json!(["apps-a", "apps-b"])
    );
    assert_eq!(g.provisioner_state["excluded"], json!(["soc-*"]));
    assert_eq!(
        t.fake.count(
            "POST",
            "/apis/rbac.authorization.k8s.io/v1/namespaces/soc-x/rolebindings"
        ),
        0
    );
    expire(&t.store, &t.p, g.id).await.unwrap();
    assert!(t.objects().is_empty());

    // A failure half-way removes the bindings made and the SA.
    t.state.lock().unwrap().fail_post =
        Some("/apis/rbac.authorization.k8s.io/v1/namespaces/apps-b/".into());
    let g = provisioning(&t.store, a.id, &role("view", true), "*", 3600).await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "create RoleBinding failed (500)"
    );
    assert!(t.objects().is_empty(), "{:?}", t.objects());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_half_made_provision_leaves_nothing_behind(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    t.state.lock().unwrap().fail_post = Some("/apis/".into());
    for (r, res) in [(role("view", false), "apps-a"), (role("view", true), "*")] {
        let g = provisioning(&t.store, a.id, &r, res, 3600).await;
        let err = provision(&t.store, &t.p, &g).await.unwrap_err();
        assert!(err.starts_with("create "), "{err}");
        assert!(t.objects().is_empty(), "{:?}", t.objects());
    }
    // The reaper, for a provision that died with objects made: derives
    // the names from the grant and removes them (B10).
    t.state.lock().unwrap().fail_post = None;
    let g = provisioning(&t.store, a.id, &role("view", false), "apps-a", 3600).await;
    let tx = t.store.begin().await.unwrap();
    let _ = t.p.provision(&tx, &g, now()).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(t.objects().len(), 2);
    reap(&t.store, &t.p, &g).await.unwrap();
    assert!(t.objects().is_empty());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn endpoints_fail_over_and_the_answering_one_is_preferred(pool: PgPool) {
    let t = setup(pool).await;
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        format!("http://{a}")
    };
    let p = KubernetesProvisioner::new(
        vec![dead.clone(), t.fake.url.clone()],
        (Some(t.token_file.clone()), None),
        config(),
        Arc::new(Policy::default()),
        Http::new().unwrap(),
    );
    assert_eq!(p.api_url(), dead);
    let a = agent(&t.store, "k8s-agent").await;
    granted(&t.store, &p, a.id, &role("view", false), "apps-a").await;
    assert_eq!(p.api_url(), t.fake.url);

    let down = KubernetesProvisioner::new(
        vec![dead.clone(), dead],
        (Some(t.token_file.clone()), None),
        config(),
        Arc::new(Policy::default()),
        Http::new().unwrap(),
    );
    let g = provisioning(&t.store, a.id, &role("view", false), "apps-b", 3600).await;
    let err = provision(&t.store, &down, &g).await.unwrap_err();
    assert!(err.starts_with("kubernetes API unreachable: "), "{err}");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_catalog_shows_roles_and_cluster_roles(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "k8s-agent").await;
    let c = t.p.catalog(&a).unwrap();
    assert_eq!(c["namespace_allowlist"], json!(["apps-*", "kube-system"]));
    assert_eq!(c["roles"], json!([{"name": "view"}, {"name": "edit"}]));
    assert_eq!(c["cluster_roles"], json!(["view"]));
    assert_eq!(c["resource_hint"], "<namespace>, or \"*\" for cluster-wide");
}
