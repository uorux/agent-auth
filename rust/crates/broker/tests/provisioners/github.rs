//! GitHub: repo tokens and repo creation (provisioners spec §2, §14).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_auth_broker::provisioners::Provisioner;
use agent_auth_broker::provisioners::github::{GithubApp, GithubProvisioner};
use agent_auth_broker::provisioners::http::Http;
use agent_auth_core::authority::{GithubAccess, GithubAuthority, Visibility};
use agent_auth_core::policy::schema::GithubConfig;
use agent_auth_core::{Authority, Glob, Platform};
use agent_auth_store::{Store, grants, lockdown};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::format_description::well_known::Rfc3339;

use crate::common::*;

pub fn key_file() -> PathBuf {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crypto/tests/vectors/python.json"
    ))
    .unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    let pem = v["github_app"]["pkcs1_pem"].as_str().unwrap();
    let path = std::env::temp_dir().join(format!("aa-gh-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, pem).unwrap();
    path
}

fn later() -> String {
    (now() + time::Duration::hours(1)).format(&Rfc3339).unwrap()
}

/// GitHub as the tests expect it, with numbered installation tokens.
pub fn github_default(c: &Call, n: &AtomicUsize) -> R {
    // The real API refuses requests without a User-Agent.
    if c.header("user-agent").is_empty() {
        return r(
            403,
            json!({"message": "Request forbidden by administrative rules."}),
        );
    }
    let path = c.path.as_str();
    match (c.method.as_str(), path) {
        ("GET", "/app/installations/7") => r(200, json!({"id": 7, "account": {"login": "JRT"}})),
        ("GET", p) if p.starts_with("/repos/") && p.ends_with("/installation") => {
            r(200, json!({"id": 42}))
        }
        ("GET", "/orgs/acme/installation") => r(200, json!({"id": 9})),
        ("POST", p) if p.ends_with("/access_tokens") => {
            if c.body.get("repositories").is_none() {
                r(201, json!({"token": "ghs_admin", "expires_at": later()}))
            } else {
                let i = n.fetch_add(1, Ordering::SeqCst) + 1;
                r(
                    201,
                    json!({"token": format!("ghs_{i}"), "expires_at": later()}),
                )
            }
        }
        ("POST", "/orgs/acme/repos") => {
            let name = c.body["name"].as_str().unwrap_or("");
            r(
                201,
                json!({"id": 1001, "html_url": format!("https://github.com/acme/{name}"), "visibility": c.body["visibility"]}),
            )
        }
        ("DELETE", "/installation/token") => r(204, Value::Null),
        _ => r(404, json!({"message": "Not Found"})),
    }
}

pub fn config() -> GithubConfig {
    let mut cfg = GithubConfig::default();
    cfg.repo_allowlist = vec![
        Glob::new("jrt/*"),
        Glob::new("acme/*"),
        Glob::new("other-org/*"),
    ];
    cfg.repo_denylist = vec![Glob::new("jrt/nixos-dots")];
    for (k, v) in [
        ("contents", "write"),
        ("pull_requests", "write"),
        ("metadata", "read"),
    ] {
        cfg.permission_ceiling.insert(k.to_owned(), v.to_owned());
    }
    cfg.create_owners = vec!["acme".to_owned()];
    cfg
}

pub struct Gh {
    pub store: Store,
    pub fake: Fake,
    pub p: GithubProvisioner,
    pub n: Arc<AtomicUsize>,
}

pub async fn setup_with(pool: PgPool, cfg: GithubConfig, pinned: Option<&str>) -> Gh {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let fake = Fake::start(move |c| github_default(c, &n2)).await;
    let app = GithubApp::new(
        "12345",
        key_file(),
        &format!("{}/", fake.url),
        pinned.map(str::to_owned),
        Http::new().unwrap(),
    );
    let p = GithubProvisioner::new(Arc::new(app), &cfg, Some(secret_box())).unwrap();
    Gh {
        store: Store::from_pool(pool),
        fake,
        p,
        n,
    }
}

async fn setup(pool: PgPool) -> Gh {
    setup_with(pool, config(), None).await
}

fn repo(perms: &[(&str, GithubAccess)]) -> Authority {
    Authority::Github(GithubAuthority::Repo {
        permissions: perms.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
    })
}

fn create(v: Visibility) -> Authority {
    Authority::Github(GithubAuthority::Create { visibility: v })
}

async fn credential_rows(store: &Store, g: &agent_auth_store::grants::GrantRow) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM credentials WHERE grant_id = $1")
        .bind(uuid::Uuid::from(g.id))
        .fetch_one(store.pool())
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../store/migrations")]
async fn validation_denials_through_the_wire(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let v = |cap: &'static str, scope: Value, res: &'static str| {
        let (store, p, a) = (t.store.clone(), &t.p, a.clone());
        async move { validate(&store, p, &a, Platform::Github, cap, scope, res).await }
    };
    let ok = v(
        "repo",
        json!({"permissions": {"contents": "write"}}),
        " JRT/Cactus/ ",
    )
    .await
    .unwrap();
    assert_eq!(ok.resource, "jrt/cactus");
    assert_eq!(ok.notes, ["grants contents:write on jrt/cactus"]);
    assert_eq!(
        v(
            "repo",
            json!({"permissions": {"contents": "write"}}),
            "zz/x"
        )
        .await
        .unwrap_err(),
        "repo 'zz/x' is not in the allowlist"
    );
    assert_eq!(
        v(
            "repo",
            json!({"permissions": {"contents": "write"}}),
            "jrt/nixos-dots"
        )
        .await
        .unwrap_err(),
        "repo 'jrt/nixos-dots' is never brokered (denylist)"
    );
    assert_eq!(
        v(
            "repo",
            json!({"permissions": {"contents": "admin"}}),
            "jrt/x"
        )
        .await
        .unwrap_err(),
        "permission contents:admin exceeds policy ceiling contents:write"
    );
    assert_eq!(
        v("repo", json!({"permissions": {"secrets": "read"}}), "jrt/x")
            .await
            .unwrap_err(),
        "permission 'secrets' is not grantable by policy"
    );
    assert_eq!(
        v("repo", json!({}), "jrt/x").await.unwrap_err(),
        "scope.permissions is required, e.g. {\"contents\": \"write\"}"
    );
    let c = v("create", json!({"visibility": "public"}), "Acme/New")
        .await
        .unwrap();
    assert_eq!(c.resource, "acme/new");
    assert_eq!(
        c.notes,
        [
            "creates a new public repo acme/new",
            "PUBLIC: everything pushed to it is visible to anyone"
        ]
    );
    assert_eq!(
        v("create", json!({}), "jrt/x").await.unwrap_err(),
        "repos can't be created under 'jrt' (platforms.github.create_owners)"
    );
    assert_eq!(
        v("create", json!({}), "acme/x.git").await.unwrap_err(),
        "invalid repository name 'x.git'"
    );
    assert!(
        v("create", json!({"visibility": "internal"}), "acme/x")
            .await
            .unwrap_err()
            .starts_with("wire: ")
    );
    assert!(
        v("create", json!({"bogus": 1}), "acme/x")
            .await
            .unwrap_err()
            .starts_with("wire: ")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_repo_grant_mints_caches_and_stops_when_it_ends(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Write)]),
        "jrt/cactus",
    )
    .await;
    assert_eq!(
        g.provisioner_state,
        json!({"repo": "jrt/cactus", "permissions": {"contents": "write"}})
    );

    // The provisioning mint proves coverage and is revoked at once.
    let mints = t.fake.find("POST", "/app/installations/42/access_tokens");
    assert_eq!(mints.len(), 1);
    assert_eq!(
        mints[0].body,
        json!({"repositories": ["cactus"], "permissions": {"contents": "write"}})
    );
    assert!(mints[0].header("authorization").starts_with("Bearer ey"));
    assert_eq!(mints[0].header("accept"), "application/vnd.github+json");
    assert_eq!(mints[0].header("x-github-api-version"), "2022-11-28");
    assert!(
        mints[0]
            .header("user-agent")
            .starts_with("agent-auth-broker/")
    );
    let revokes = t.fake.find("DELETE", "/installation/token");
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].header("authorization"), "token ghs_1");
    assert_eq!(credential_rows(&t.store, &g).await, 0);

    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(
        (kind_name(&c).as_str(), expose(&c)),
        ("github_installation_token", "ghs_2")
    );
    assert!(c.expires_at.is_some() && c.username.is_none() && c.url.is_none() && c.note.is_none());
    assert_eq!(credential_rows(&t.store, &g).await, 1);
    let sealed: String =
        sqlx::query_scalar("SELECT value_encrypted FROM credentials WHERE grant_id = $1")
            .bind(uuid::Uuid::from(g.id))
            .fetch_one(t.store.pool())
            .await
            .unwrap();
    assert!(!sealed.contains("ghs_2"));

    // Served from the cache: no new mint.
    let c2 = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(expose(&c2), "ghs_2");
    assert_eq!(
        t.fake.count("POST", "/app/installations/42/access_tokens"),
        2
    );
    // The installation was looked up once.
    assert_eq!(t.fake.count("GET", "/repos/jrt/cactus/installation"), 1);

    expire(&t.store, &t.p, g.id).await.unwrap();
    let revokes = t.fake.find("DELETE", "/installation/token");
    assert_eq!(
        revokes.last().unwrap().header("authorization"),
        "token ghs_2"
    );
    assert_eq!(credential_rows(&t.store, &g).await, 0);
    let err = credential(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(err.text(), "grant is not active; refusing to mint a token");
    assert_eq!(
        t.fake.count("POST", "/app/installations/42/access_tokens"),
        2
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_app_that_is_not_installed_fails_the_grant(pool: PgPool) {
    let t = setup(pool).await;
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("GET", "/repos/jrt/elsewhere/installation") {
            r(404, json!({}))
        } else {
            github_default(c, &n)
        }
    });
    let a = agent(&t.store, "gh-agent").await;
    let g = provisioning(
        &t.store,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/elsewhere",
        3600,
    )
    .await;
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(
        err,
        "the GitHub App is not installed on 'jrt/elsewhere' (install it on that account/repo, then retry)"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_pinned_installation_covers_only_its_account(pool: PgPool) {
    let t = setup_with(pool, config(), Some("7")).await;
    let a = agent(&t.store, "gh-agent").await;
    granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/one",
    )
    .await;
    granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/two",
    )
    .await;
    assert_eq!(t.fake.count("GET", "/app/installations/7"), 1);
    assert_eq!(
        t.fake.count("POST", "/app/installations/7/access_tokens"),
        2
    );
    // INV-G4: no mint for another owner.
    let g = provisioning(
        &t.store,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "other-org/x",
        3600,
    )
    .await;
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert!(
        err.contains("not covered by the pinned installation"),
        "{err}"
    );
    assert_eq!(
        t.fake.count("POST", "/app/installations/7/access_tokens"),
        2
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_private_create_end_to_end(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    let admin = t.fake.find("POST", "/app/installations/9/access_tokens");
    assert_eq!(admin.len(), 1);
    assert_eq!(
        admin[0].body,
        json!({"permissions": {"administration": "write", "metadata": "read"}})
    );
    let made = t.fake.find("POST", "/orgs/acme/repos");
    assert_eq!(
        made[0].body,
        json!({"name": "new", "visibility": "private", "private": true})
    );
    assert_eq!(made[0].header("authorization"), "token ghs_admin");
    let revokes = t.fake.find("DELETE", "/installation/token");
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].header("authorization"), "token ghs_admin");
    // INV-G5: never stored.
    assert!(!g.provisioner_state.to_string().contains("ghs_admin"));
    assert_eq!(credential_rows(&t.store, &g).await, 0);
    assert_eq!(g.provisioner_state["created"], json!(true));
    assert_eq!(g.provisioner_state["repo_id"], json!(1001));

    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(kind_name(&c), "github_repo");
    assert_eq!(expose(&c), "https://github.com/acme/new");
    assert_eq!(
        c.note.as_deref(),
        Some("created: acme/new (private). Request a 'repo' grant on it for access.")
    );
    // The broker never deletes a repo.
    expire(&t.store, &t.p, g.id).await.unwrap();
    assert!(
        t.fake
            .calls()
            .iter()
            .all(|c| !(c.method == "DELETE" && c.path.starts_with("/repos/")))
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_retried_create_adopts_the_brokers_own_repo(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    granted(
        &t.store,
        &t.p,
        a.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    let n = t.n.clone();
    t.fake.set(move |c| match (c.method.as_str(), c.path.as_str()) {
        ("POST", "/orgs/acme/repos") => r(422, json!({"message": "name already exists on this account"})),
        ("GET", "/repos/acme/new") => r(200, json!({"id": 1001, "html_url": "https://github.com/acme/new", "visibility": "private"})),
        _ => github_default(c, &n),
    });
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    assert_eq!(g.provisioner_state["created"], json!(false));
    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert!(
        c.note
            .unwrap()
            .starts_with("already existed: acme/new (private).")
    );
    assert_eq!(t.fake.count("DELETE", "/installation/token"), 2);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn adoption_is_refused_unless_it_is_this_agents_repo(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let b = agent(&t.store, "other-agent").await;
    let taken = |id: i64, vis: &'static str| {
        let n = t.n.clone();
        move |c: &Call| match (c.method.as_str(), c.path.as_str()) {
            ("POST", "/orgs/acme/repos") => r(422, json!({"message": "exists"})),
            ("GET", "/repos/acme/new") => {
                r(200, json!({"id": id, "visibility": vis, "html_url": "u"}))
            }
            _ => github_default(c, &n),
        }
    };
    // Never created by the broker: no lookup at all.
    t.fake.set(taken(1001, "private"));
    let g = provisioning(
        &t.store,
        a.id,
        &create(Visibility::Private),
        "acme/new",
        3600,
    )
    .await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "repository already exists (not created by the broker)"
    );
    assert_eq!(t.fake.count("GET", "/repos/acme/new"), 0);
    assert_eq!(t.fake.count("DELETE", "/installation/token"), 1);

    // The broker created it for agent b: a still may not adopt it.
    let n = t.n.clone();
    t.fake.set(move |c| github_default(c, &n));
    granted(
        &t.store,
        &t.p,
        b.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    t.fake.set(taken(1001, "private"));
    let g = provisioning(
        &t.store,
        a.id,
        &create(Visibility::Private),
        "acme/new",
        3600,
    )
    .await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "repository already exists (not created by the broker)"
    );

    // Same agent, but the name now belongs to another repo.
    t.fake.set(taken(2002, "private"));
    let g = provisioning(
        &t.store,
        b.id,
        &create(Visibility::Private),
        "acme/new",
        3600,
    )
    .await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "repository already exists (not created by the broker)"
    );

    // Same repo, other visibility.
    t.fake.set(taken(1001, "public"));
    let g = provisioning(
        &t.store,
        b.id,
        &create(Visibility::Private),
        "acme/new",
        3600,
    )
    .await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "repository already exists as public, not the requested private"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_failed_create_still_revokes_the_admin_token(pool: PgPool) {
    let t = setup(pool).await;
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("POST", "/orgs/acme/repos") {
            r(403, json!({"message": "secret detail"}))
        } else {
            github_default(c, &n)
        }
    });
    let a = agent(&t.store, "gh-agent").await;
    let g = provisioning(
        &t.store,
        a.id,
        &create(Visibility::Private),
        "acme/new",
        3600,
    )
    .await;
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(err, "GitHub repo create failed (403)");
    assert_eq!(t.fake.count("DELETE", "/installation/token"), 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_refused_admin_revoke_does_not_fail_the_grant(pool: PgPool) {
    let t = setup(pool).await;
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("DELETE", "/installation/token") {
            r(401, json!({}))
        } else {
            github_default(c, &n)
        }
    });
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    assert_eq!(g.provisioner_state["created"], json!(true));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_uncovered_new_repo_is_reported(pool: PgPool) {
    let t = setup(pool).await;
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("GET", "/repos/acme/new/installation") {
            r(404, json!({}))
        } else {
            github_default(c, &n)
        }
    });
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    assert_eq!(g.provisioner_state["installation_covers"], json!(false));
    let note = credential(&t.store, &t.p, &g).await.unwrap().note.unwrap();
    assert!(note.ends_with("does not cover it yet, so repo grants on it will fail until it is added to the installation."), "{note}");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_cancelled_create_still_revokes_the_admin_token(pool: PgPool) {
    let t = setup(pool).await;
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("POST", "/orgs/acme/repos") {
            R(201, json!({"id": 1}), 60_000)
        } else {
            github_default(c, &n)
        }
    });
    let a = agent(&t.store, "gh-agent").await;
    let g = provisioning(
        &t.store,
        a.id,
        &create(Visibility::Private),
        "acme/new",
        3600,
    )
    .await;
    let tx = t.store.begin().await.unwrap();
    let _held = lockdown::check(&tx, a.id, now()).await.unwrap().unwrap();
    let pg = grants::load_provisioning(&tx, g.id).await.unwrap().unwrap();
    // Cancelled once the create is in flight (not after a guessed time:
    // under load, minting the admin token alone can take longer).
    let create_sent = async {
        while t.fake.count("POST", "/orgs/acme/repos") == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let out = tokio::select! {
        out = t.p.provision(&tx, &pg, now()) => Some(out),
        () = create_sent => None,
    };
    drop(pg);
    assert!(out.is_none(), "the create should still be pending");
    drop(_held);
    tx.rollback().await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while t.fake.count("DELETE", "/installation/token") < 1 && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let revokes = t.fake.find("DELETE", "/installation/token");
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].header("authorization"), "token ghs_admin");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_tightened_policy_stops_minting_for_old_grants(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Write)]),
        "jrt/cactus",
    )
    .await;
    let mut cfg = config();
    cfg.repo_denylist.push(Glob::new("jrt/cactus"));
    let app = t.p.app().clone();
    let tightened = GithubProvisioner::new(app, &cfg, Some(secret_box())).unwrap();
    let err = credential(&t.store, &tightened, &g)
        .await
        .unwrap_err()
        .text();
    assert_eq!(
        err,
        "policy no longer allows this grant (repo 'jrt/cactus' is never brokered (denylist)); refusing to mint a token"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_catalog_lists_what_may_be_asked(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let c = t.p.catalog(&a).unwrap();
    assert_eq!(c["platform"], "github");
    assert_eq!(c["capability_hint"], "repo");
    assert_eq!(c["create_owners"], json!(["acme"]));
    assert_eq!(
        c["repo_allowlist"],
        json!(["jrt/*", "acme/*", "other-org/*"])
    );
    // INV-C1: the denylist is never shown.
    assert!(!c.to_string().contains("nixos-dots"));
    let mut open = config();
    open.repo_allowlist.clear();
    open.create_owners.clear();
    let p = GithubProvisioner::new(t.p.app().clone(), &open, Some(secret_box())).unwrap();
    let c = p.catalog(&a).unwrap();
    assert_eq!(c["repo_allowlist"], json!(["<any>"]));
    assert!(c.get("create_owners").is_none());
}

#[test]
fn github_needs_the_encryption_key() {
    let app = GithubApp::new(
        "1",
        PathBuf::from("/nonexistent"),
        "http://x",
        None,
        Http::new().unwrap(),
    );
    let err = GithubProvisioner::new(Arc::new(app), &config(), None).unwrap_err();
    assert_eq!(err.0, "ENCRYPTION_KEY is required when GitHub is enabled");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn globs_with_capitals_still_match(pool: PgPool) {
    let mut cfg = config();
    cfg.repo_denylist = vec![Glob::new("JRT/NixOS-*")];
    cfg.repo_allowlist = vec![Glob::new("JRT/*")];
    let t = setup_with(pool, cfg, None).await;
    let a = agent(&t.store, "gh-agent").await;
    let v = |res: &'static str| {
        let (store, p, a) = (t.store.clone(), &t.p, a.clone());
        async move {
            validate(
                &store,
                p,
                &a,
                Platform::Github,
                "repo",
                json!({"permissions": {"contents": "read"}}),
                res,
            )
            .await
        }
    };
    assert_eq!(
        v("jrt/nixos-dots").await.unwrap_err(),
        "repo 'jrt/nixos-dots' is never brokered (denylist)"
    );
    assert!(v("jrt/cactus").await.is_ok());
}

/// The wiki's repo is never brokered, whether or not the operator listed
/// it (upstream review 2026-10): the policy puts it on the denylist the
/// provisioner reads.
#[sqlx::test(migrations = "../store/migrations")]
async fn the_wiki_repo_is_never_brokered(pool: PgPool) {
    let policy = agent_auth_core::Policy::from_value(json!({
        "wiki": {"repo": "jrt/Agent-Wiki"},
        "platforms": {"github": {
            "repo_allowlist": ["jrt/*"],
            "permission_ceiling": {"contents": "write"},
        }},
    }))
    .unwrap();
    let t = setup_with(pool, policy.platforms().github.clone(), None).await;
    let a = agent(&t.store, "gh-agent").await;
    let err = validate(
        &t.store,
        &t.p,
        &a,
        Platform::Github,
        "repo",
        json!({"permissions": {"contents": "write"}}),
        "JRT/agent-wiki",
    )
    .await
    .unwrap_err();
    assert_eq!(err, "repo 'jrt/agent-wiki' is never brokered (denylist)");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_token_github_did_not_revoke_keeps_the_grant_for_a_retry(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/cactus",
    )
    .await;
    credential(&t.store, &t.p, &g).await.unwrap();
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("DELETE", "/installation/token") {
            r(502, json!({}))
        } else {
            github_default(c, &n)
        }
    });
    let err = expire(&t.store, &t.p, g.id).await.unwrap_err();
    assert_eq!(err, "GitHub token revoke failed (502)");
    assert_eq!(
        grant(&t.store, g.id).await.status,
        agent_auth_core::GrantStatus::Active
    );
    assert_eq!(
        credential_rows(&t.store, &g).await,
        1,
        "kept to revoke again"
    );
    // 401: the token is already dead, which is what revoking wanted.
    let n = t.n.clone();
    t.fake.set(move |c| {
        if c.is("DELETE", "/installation/token") {
            r(401, json!({}))
        } else {
            github_default(c, &n)
        }
    });
    revoke_due(&t.store, &t.p, g.id).await.unwrap();
    assert_eq!(credential_rows(&t.store, &g).await, 0);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_slow_platform_is_cut_off(pool: PgPool) {
    use agent_auth_broker::provisioners::{FakeProvisioner, PROVISION_DEADLINE, provision_within};
    assert!(agent_auth_broker::provisioners::http::CALL_TIMEOUT <= Duration::from_secs(15));
    assert!(PROVISION_DEADLINE <= Duration::from_secs(60));
    // Each call is capped...
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let fake = Fake::start(move |c| {
        if c.path.ends_with("/installation") {
            R(200, json!({"id": 42}), 3000)
        } else {
            github_default(c, &n2)
        }
    })
    .await;
    let app = GithubApp::new(
        "1",
        key_file(),
        &fake.url,
        None,
        Http::new().unwrap().with_cap(Duration::from_millis(200)),
    );
    let p = GithubProvisioner::new(Arc::new(app), &config(), Some(secret_box())).unwrap();
    let store = Store::from_pool(pool);
    let a = agent(&store, "gh-agent").await;
    let g = provisioning(
        &store,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/slow",
        3600,
    )
    .await;
    let started = std::time::Instant::now();
    assert_eq!(
        provision(&store, &p, &g).await.unwrap_err(),
        "GitHub API unreachable (see broker logs)"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // ...and so is a whole provision.
    let mut slow = FakeProvisioner::new(Platform::Github);
    slow.delay = Some(Duration::from_secs(5));
    let g = provisioning(
        &store,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/slower",
        3600,
    )
    .await;
    let tx = store.begin().await.unwrap();
    let _nh = lockdown::check(&tx, a.id, now()).await.unwrap().unwrap();
    let pg = agent_auth_store::grants::load_provisioning(&tx, g.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        provision_within(&slow, &tx, &pg, now(), Duration::from_millis(100))
            .await
            .is_none()
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_credential_route_serves_tokens_and_created_repos(pool: PgPool) {
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let token = granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Write)]),
        "jrt/cactus",
    )
    .await;
    let made = granted(
        &t.store,
        &t.p,
        a.id,
        &create(Visibility::Private),
        "acme/new",
    )
    .await;
    let out = credentials_over_http(
        &t.store,
        agent_auth_broker::provisioners::AnyProvisioner::Github(t.p),
        &[&token, &made],
    )
    .await;
    assert_eq!(out[0].0, axum::http::StatusCode::OK, "{}", out[0].1);
    assert_eq!(out[0].1["kind"], "github_installation_token");
    assert_eq!(out[0].1["value"], "ghs_2");
    assert_eq!(out[1].0, axum::http::StatusCode::OK, "{}", out[1].1);
    assert_eq!(out[1].1["kind"], "github_repo");
    assert_eq!(out[1].1["value"], "https://github.com/acme/new");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_fetches_mint_one_token(pool: PgPool) {
    // B8: two fetches racing used to mint a token each (the grant is only
    // share-locked); the revoke then reached only the newest. Minting is
    // serialized per grant now: the second fetch waits and finds the
    // first one's token.
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/cactus",
    )
    .await;
    let mints = || t.fake.count("POST", "/app/installations/42/access_tokens");
    let before = mints();
    // A slow mint, so both fetches are past their cache read before the
    // first token could be recorded (without the lock).
    let n = t.n.clone();
    t.fake.set(move |c| {
        let R(status, body, _) = github_default(c, &n);
        if c.path.ends_with("/access_tokens") {
            R(status, body, 300)
        } else {
            R(status, body, 0)
        }
    });
    let (c1, c2) = tokio::join!(
        credential(&t.store, &t.p, &g),
        credential(&t.store, &t.p, &g)
    );
    let (c1, c2) = (c1.unwrap(), c2.unwrap());
    assert_eq!(mints() - before, 1, "one mint for two fetches");
    assert_eq!(expose(&c1), expose(&c2));
    assert_eq!(credential_rows(&t.store, &g).await, 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_revoke_reaches_every_live_token_of_the_grant(pool: PgPool) {
    // Tokens recorded for a grant stay recorded until they run out (two
    // left by a race before the fix, or the old one after a refresh), and
    // revoking the grant revokes each of them, not only the newest.
    let t = setup(pool).await;
    let a = agent(&t.store, "gh-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &repo(&[("contents", GithubAccess::Read)]),
        "jrt/cactus",
    )
    .await;
    let first = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(expose(&first), "ghs_2");
    // Make the cached token look about to run out (4 minutes left): the
    // next fetch mints a fresh one, and the old one is still alive.
    sqlx::query(
        "UPDATE credentials SET expires_at = now() + interval '4 minutes' WHERE grant_id = $1",
    )
    .bind(uuid::Uuid::from(g.id))
    .execute(t.store.pool())
    .await
    .unwrap();
    let second = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(expose(&second), "ghs_3");
    assert_eq!(credential_rows(&t.store, &g).await, 2);
    // A recorded token that has already run out needs no revoking.
    sqlx::query("INSERT INTO credentials (id, grant_id, kind, value_encrypted, expires_at, created_at) VALUES ($1, $2, 'github_installation_token', 'x', now() - interval '1 minute', now() - interval '61 minutes')")
        .bind(uuid::Uuid::new_v4())
        .bind(uuid::Uuid::from(g.id))
        .execute(t.store.pool())
        .await
        .unwrap();
    // One revoke fails: the grant stays for a retry, and the retry sends
    // both again (a 401 for the one already dead counts as done).
    let n = t.n.clone();
    let failed_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f2 = failed_once.clone();
    t.fake.set(move |c| {
        if c.is("DELETE", "/installation/token")
            && c.header("authorization") == "token ghs_3"
            && !f2.swap(true, Ordering::SeqCst)
        {
            r(502, json!({}))
        } else {
            github_default(c, &n)
        }
    });
    let before = t.fake.find("DELETE", "/installation/token").len();
    assert_eq!(
        expire(&t.store, &t.p, g.id).await.unwrap_err(),
        "GitHub token revoke failed (502)"
    );
    assert_eq!(
        grant(&t.store, g.id).await.status,
        agent_auth_core::GrantStatus::Active
    );
    revoke_due(&t.store, &t.p, g.id).await.unwrap();
    let sent: Vec<String> = t.fake.find("DELETE", "/installation/token")[before..]
        .iter()
        .map(|c| c.header("authorization").to_owned())
        .collect();
    assert_eq!(
        sent,
        ["token ghs_2", "token ghs_3", "token ghs_2", "token ghs_3"]
    );
    assert_eq!(credential_rows(&t.store, &g).await, 0);
}
