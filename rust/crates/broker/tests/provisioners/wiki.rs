//! The wiki against a fake GitHub repo (a2a-wiki-desktop spec §7, §11).

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use agent_auth_broker::auth::AuthConfig;
use agent_auth_broker::provisioners::PlatformServices;
use agent_auth_broker::provisioners::github::GithubApp;
use agent_auth_broker::provisioners::http::Http;
use agent_auth_broker::state::AppState;
use agent_auth_broker::wiki::{self, Wiki};
use agent_auth_core::AgentId;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::Policy;
use agent_auth_crypto::api_key;
use agent_auth_store::Store;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_wire::wiki::WikiWritten;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

use crate::common::*;

#[derive(Debug, Default)]
struct Repo {
    /// path → (sha, content)
    files: BTreeMap<String, (String, Vec<u8>)>,
    /// path → commits, newest last: (author, message)
    commits: BTreeMap<String, Vec<(String, String)>>,
    empty: bool,
}

fn sha_of(data: &[u8]) -> String {
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[derive(Clone, Default)]
struct Flags {
    down: Arc<AtomicBool>,
    commits_down: Arc<AtomicBool>,
}

fn repo_handler(repo: &Arc<Mutex<Repo>>, flags: &Flags, c: &Call) -> R {
    let mut st = repo.lock().unwrap();
    let path = c.path.as_str();
    if c.is("GET", "/repos/jrt/wiki/installation") {
        return r(200, json!({"id": 42}));
    }
    if c.is("POST", "/app/installations/42/access_tokens") {
        let exp = (now() + time::Duration::hours(1)).format(&Rfc3339).unwrap();
        return r(201, json!({"token": "ghs_wiki", "expires_at": exp}));
    }
    if c.header("authorization") != "token ghs_wiki" {
        return r(401, json!({}));
    }
    if flags.down.load(Ordering::SeqCst) {
        return r(500, json!({}));
    }
    if c.is("GET", "/repos/jrt/wiki/git/trees/main") {
        if st.empty {
            return r(409, json!({"message": "Git Repository is empty."}));
        }
        let mut tree: Vec<Value> = st
            .files
            .iter()
            .map(|(p, (sha, _))| json!({"path": p, "type": "blob", "sha": sha}))
            .collect();
        tree.push(json!({"path": "projects", "type": "tree", "sha": "t1"}));
        return r(
            200,
            json!({"sha": "root", "tree": tree, "truncated": false}),
        );
    }
    if let Some(sha) = path.strip_prefix("/repos/jrt/wiki/git/blobs/") {
        return match st.files.values().find(|(s, _)| s == sha) {
            Some((_, data)) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(data);
                // GitHub wraps the base64 at 60 columns.
                let wrapped: Vec<String> = b64
                    .as_bytes()
                    .chunks(60)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect();
                r(
                    200,
                    json!({"content": wrapped.join("\n"), "encoding": "base64"}),
                )
            }
            None => r(404, json!({})),
        };
    }
    if let Some(p) = path.strip_prefix("/repos/jrt/wiki/contents/") {
        let current = st.files.get(p).map(|(s, _)| s.clone());
        if c.body["sha"].as_str().map(str::to_owned) != current || c.body["branch"] != "main" {
            return r(409, json!({"message": "sha mismatch"}));
        }
        let author = c.body["author"]["name"].as_str().unwrap_or("").to_owned();
        let message = c.body["message"].as_str().unwrap_or("").to_owned();
        st.commits
            .entry(p.to_owned())
            .or_default()
            .push((author, message));
        if c.method == "DELETE" {
            st.files.remove(p);
            return r(200, json!({"commit": {}}));
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(c.body["content"].as_str().unwrap())
            .unwrap();
        let sha = sha_of(&data);
        st.files.insert(p.to_owned(), (sha.clone(), data));
        return r(
            if current.is_some() { 200 } else { 201 },
            json!({"content": {"sha": sha}}),
        );
    }
    if c.is("GET", "/repos/jrt/wiki/commits") {
        if flags.commits_down.load(Ordering::SeqCst) {
            return r(500, json!({}));
        }
        let p = c
            .query
            .split('&')
            .find_map(|kv| kv.strip_prefix("path="))
            .unwrap_or("")
            .replace("%2F", "/");
        return match st.commits.get(&p).and_then(|v| v.last()) {
            Some((author, message)) => r(
                200,
                json!([{"commit": {"author": {"name": author, "date": "2026-10-25T12:00:00Z"}, "message": message}}]),
            ),
            None => r(200, json!([])),
        };
    }
    r(404, json!({}))
}

struct W {
    store: Store,
    fake: Fake,
    repo: Arc<Mutex<Repo>>,
    flags: Flags,
    wiki: Arc<Wiki>,
    policy: Policy,
    app: Arc<GithubApp>,
}

fn policy(refresh: u32) -> Policy {
    Policy::from_value(json!({
        "wiki": {"repo": "jrt/wiki", "editors": ["editor"], "refresh_secs": refresh, "max_page_bytes": 200},
        "restricted": {"soc": {"members": ["soc-*"]}},
    }))
    .unwrap()
}

async fn setup_with(pool: PgPool, refresh: u32) -> W {
    let repo: Arc<Mutex<Repo>> = Arc::default();
    let flags = Flags::default();
    let (r2, f2) = (repo.clone(), flags.clone());
    let fake = Fake::start(move |c| repo_handler(&r2, &f2, c)).await;
    let app = Arc::new(GithubApp::new(
        "12345",
        crate::github::key_file(),
        &fake.url,
        None,
        Http::new().unwrap(),
    ));
    let policy = policy(refresh);
    let wiki = Arc::new(Wiki::new(app.clone(), Arc::new(policy.clone())));
    W {
        store: Store::from_pool(pool),
        fake,
        repo,
        flags,
        wiki,
        policy,
        app,
    }
}

async fn setup(pool: PgPool) -> W {
    setup_with(pool, 0).await
}

impl W {
    fn seed(&self, path: &str, text: &str, author: &str) {
        let mut st = self.repo.lock().unwrap();
        st.files.insert(
            path.into(),
            (sha_of(text.as_bytes()), text.as_bytes().to_vec()),
        );
        st.commits
            .entry(path.into())
            .or_default()
            .push((author.into(), format!("seeded {path}\n\nAgent: {author}")));
    }
}

async fn project_agent(store: &Store, name: &str, project: Option<&str>) -> AgentRow {
    agent_with(
        store,
        AgentSpec {
            project,
            ..AgentSpec::named(name)
        },
    )
    .await
}

fn written(w: WikiWritten) -> (String, bool) {
    match w {
        WikiWritten::Written { sha, created, .. } => (sha, created),
        WikiWritten::Unchanged { .. } => panic!("unchanged"),
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_agent_writes_its_own_projects_pages_and_everyone_reads_them(pool: PgPool) {
    let t = setup(pool).await;
    let a = project_agent(&t.store, "writer", Some("agent-auth")).await;
    let b = project_agent(&t.store, "reader", Some("other")).await;
    let (sha, created) = written(
        t.wiki
            .write(
                &a,
                "projects/agent-auth/notes.md",
                "# Notes\n\nhello wiki",
                "first  notes\nmore",
                None,
                now(),
            )
            .await
            .unwrap(),
    );
    assert!(created);
    let put = &t.fake.find(
        "PUT",
        "/repos/jrt/wiki/contents/projects/agent-auth/notes.md",
    )[0];
    assert_eq!(
        put.body["author"],
        json!({"name": "writer", "email": "writer@agents.invalid"})
    );
    assert_eq!(
        put.body["message"],
        "first notes more\n\nAgent: writer (project agent-auth)"
    );
    assert_eq!(put.body["branch"], "main");
    assert!(put.body.get("sha").is_none());
    let mint = &t.fake.find("POST", "/app/installations/42/access_tokens")[0];
    assert_eq!(
        mint.body,
        json!({"repositories": ["wiki"], "permissions": {"contents": "write", "metadata": "read"}})
    );

    let page = t
        .wiki
        .read("projects/agent-auth/notes.md", now())
        .await
        .unwrap();
    assert_eq!(
        (
            page.sha.as_str(),
            page.project.as_deref(),
            page.content.as_str()
        ),
        (sha.as_str(), Some("agent-auth"), "# Notes\n\nhello wiki")
    );
    let change = page.last_change.unwrap();
    assert_eq!(
        (change.author.as_str(), change.summary.as_str()),
        ("writer", "first notes more")
    );

    let list = t.wiki.list(&b, "", now()).await.unwrap();
    assert_eq!(list.repo, "jrt/wiki");
    assert_eq!(list.you_may_write, ["projects/other/"]);
    assert_eq!(list.pages.len(), 1);
    assert_eq!(
        (list.pages[0].title.as_str(), list.pages[0].bytes),
        ("Notes", 19)
    );
    assert!(
        t.wiki
            .list(&b, "shared/", now())
            .await
            .unwrap()
            .pages
            .is_empty()
    );

    let found = t.wiki.search("HELLO notes", 8, now()).await.unwrap();
    assert_eq!(found.matches, 1);
    assert_eq!(found.results[0].lines, ["# Notes", "hello wiki"]);
    assert_eq!(
        t.wiki.search("  ", 8, now()).await.unwrap_err().detail,
        "an empty search"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_agent_cannot_write_outside_its_project(pool: PgPool) {
    let t = setup(pool).await;
    t.seed("shared/hosts.md", "# Hosts", "editor");
    t.seed("projects/other/x.md", "# X", "someone");
    let a = project_agent(&t.store, "writer", Some("agent-auth")).await;
    let want = "you may write under projects/agent-auth/ only. For a page elsewhere, ask an agent of the project that owns it (shared pages: the homelab agents)";
    for path in [
        "shared/hosts.md",
        "projects/other/x.md",
        "projects/agent-auth.md",
        "agent-auth/x.md",
    ] {
        let e = t
            .wiki
            .write(&a, path, "text", "s", None, now())
            .await
            .unwrap_err();
        assert_eq!(
            (e.status, e.detail.as_str()),
            (StatusCode::FORBIDDEN, want),
            "{path}"
        );
        let e = t.wiki.delete(&a, path, "s", None, now()).await.unwrap_err();
        assert_eq!(
            (e.status, e.detail.as_str()),
            (StatusCode::FORBIDDEN, want),
            "{path}"
        );
    }
    assert!(
        t.fake
            .calls()
            .iter()
            .all(|c| c.method != "PUT" && c.method != "DELETE")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_agent_without_a_project_reads_and_cannot_write(pool: PgPool) {
    let t = setup(pool).await;
    t.seed("shared/hosts.md", "# Hosts", "editor");
    let a = project_agent(&t.store, "drifter", None).await;
    assert!(t.wiki.read("shared/hosts.md", now()).await.is_ok());
    assert!(
        t.wiki
            .list(&a, "", now())
            .await
            .unwrap()
            .you_may_write
            .is_empty()
    );
    let e = t
        .wiki
        .write(&a, "projects/x/a.md", "t", "s", None, now())
        .await
        .unwrap_err();
    assert_eq!(
        e.detail,
        "you have no project on record, so there is nowhere in the wiki you may write (the operator sets it: `agent-auth admin agent-set --project`)"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_editor_writes_shared_pages_and_a_zone_member_writes_nothing(pool: PgPool) {
    let t = setup(pool).await;
    let ed = project_agent(&t.store, "editor", None).await;
    assert_eq!(
        t.wiki.list(&ed, "", now()).await.unwrap().you_may_write,
        ["(every page)"]
    );
    let (_, created) = written(
        t.wiki
            .write(&ed, "shared/hosts.md", "# Hosts", "hosts", None, now())
            .await
            .unwrap(),
    );
    assert!(created);
    let soc = project_agent(&t.store, "soc-1", Some("soc")).await;
    assert!(
        t.wiki
            .list(&soc, "", now())
            .await
            .unwrap()
            .you_may_write
            .is_empty()
    );
    let e = t
        .wiki
        .write(&soc, "projects/soc/a.md", "t", "s", None, now())
        .await
        .unwrap_err();
    assert_eq!(
        (e.status, e.detail.as_str()),
        (StatusCode::FORBIDDEN, "you don't write the shared wiki")
    );
    assert!(t.wiki.read("shared/hosts.md", now()).await.is_ok());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_page_that_exists_is_replaced_only_from_the_version_read(pool: PgPool) {
    let t = setup(pool).await;
    let a = project_agent(&t.store, "writer", Some("p")).await;
    let path = "projects/p/a.md";
    let (sha1, _) = written(
        t.wiki
            .write(&a, path, "one", "s", None, now())
            .await
            .unwrap(),
    );
    let e = t
        .wiki
        .write(&a, path, "two", "s", None, now())
        .await
        .unwrap_err();
    assert_eq!(
        (e.status, e.detail.as_str()),
        (
            StatusCode::CONFLICT,
            "'projects/p/a.md' exists: read it and pass its `sha` as base_sha"
        )
    );
    let e = t
        .wiki
        .write(&a, path, "two", "s", Some("stale"), now())
        .await
        .unwrap_err();
    assert_eq!(
        e.detail,
        "'projects/p/a.md' exists and has changed since you read it: read it and pass its `sha` as base_sha"
    );
    match t
        .wiki
        .write(&a, path, "one", "s", Some(&sha1), now())
        .await
        .unwrap()
    {
        WikiWritten::Unchanged { sha, .. } => assert_eq!(sha, sha1),
        other => panic!("{other:?}"),
    }
    let (sha2, created) = written(
        t.wiki
            .write(&a, path, "two", "s", Some(&sha1), now())
            .await
            .unwrap(),
    );
    assert!(!created && sha2 != sha1);
    // Someone else changed it in the meantime (GitHub's own check).
    {
        let mut st = t.repo.lock().unwrap();
        st.files
            .insert(path.into(), ("elsewhere".into(), b"three".to_vec()));
    }
    let e = t
        .wiki
        .delete(&a, path, "s", Some(&sha2), now())
        .await
        .unwrap_err();
    assert_eq!(e.status, StatusCode::CONFLICT);
    let d = t
        .wiki
        .delete(&a, path, "gone", Some("elsewhere"), now())
        .await
        .unwrap();
    assert_eq!(d.path, path);
    let e = t
        .wiki
        .write(&a, path, "new", "s", Some("elsewhere"), now())
        .await
        .unwrap_err();
    assert_eq!(
        e.detail,
        "'projects/p/a.md' no longer exists; leave base_sha out to create it"
    );
    assert_eq!(
        t.wiki
            .delete(&a, path, "s", None, now())
            .await
            .unwrap_err()
            .detail,
        "no page 'projects/p/a.md'"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_path_is_plain_segments_ending_in_md(pool: PgPool) {
    let t = setup(pool).await;
    let a = project_agent(&t.store, "editor", None).await;
    for path in [
        "../x.md",
        "projects/p/.hidden.md",
        "a//b.md",
        "/a.md",
        "a b.md",
        "a/b/c/d/e/f/g.md",
        "notes.txt",
    ] {
        let e = t
            .wiki
            .write(&a, path, "t", "s", None, now())
            .await
            .unwrap_err();
        assert_eq!(e.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            t.wiki.read(path, now()).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_page_or_summary_with_a_credential_is_refused(pool: PgPool) {
    let t = setup(pool).await;
    let a = project_agent(&t.store, "editor", None).await;
    let gh = format!("ghp_{}", "A".repeat(30));
    let jwt = format!(
        "eyJ{}.eyJ{}.{}",
        "a".repeat(12),
        "b".repeat(12),
        "c".repeat(12)
    );
    let akia = format!("AKIA{}", "B".repeat(16));
    let cases = [
        ("aa_abcd1234_0123456789abcdefghij", "an agent-auth API key"),
        (gh.as_str(), "a GitHub token"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "a private key"),
        (jwt.as_str(), "a JWT"),
        (akia.as_str(), "an API key"),
    ];
    for (secret, what) in cases {
        let want = format!(
            "this looks like it contains {what}. The wiki holds no credentials: say where one is kept, never its value"
        );
        let e = t
            .wiki
            .write(
                &a,
                "shared/s.md",
                &format!("the key is {secret}"),
                "s",
                None,
                now(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            (e.status, e.detail.as_str()),
            (StatusCode::BAD_REQUEST, want.as_str())
        );
        // B13: the summary goes into git history too.
        let e = t
            .wiki
            .write(
                &a,
                "shared/s.md",
                "fine",
                &format!("added {secret}"),
                None,
                now(),
            )
            .await
            .unwrap_err();
        assert_eq!(e.detail, want);
    }
    assert_eq!(
        t.fake.count("PUT", "/repos/jrt/wiki/contents/shared/s.md"),
        0
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn size_empty_and_missing(pool: PgPool) {
    let t = setup(pool).await;
    let a = project_agent(&t.store, "editor", None).await;
    let e = t
        .wiki
        .write(&a, "shared/a.md", &"x".repeat(201), "s", None, now())
        .await
        .unwrap_err();
    assert_eq!(
        (e.status, e.detail.as_str()),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "a page is at most 200 bytes; split it into several"
        )
    );
    let e = t
        .wiki
        .write(&a, "shared/a.md", " \n ", "s", None, now())
        .await
        .unwrap_err();
    assert_eq!(e.detail, "an empty page; to remove one, delete it");
    let e = t
        .wiki
        .write(&a, "shared/a.md", "x", "  \n ", None, now())
        .await
        .unwrap_err();
    assert_eq!(e.detail, "say in one line what changed (summary)");
    let e = t.wiki.read("shared/none.md", now()).await.unwrap_err();
    assert_eq!(
        (e.status, e.detail.as_str()),
        (
            StatusCode::NOT_FOUND,
            "no page 'shared/none.md' (wiki_list shows what exists)"
        )
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_brokers_copy_is_kept_between_reads_and_survives_an_outage(pool: PgPool) {
    let t = setup_with(pool, 3600).await;
    t.seed("shared/a.md", "# A", "editor");
    let a = project_agent(&t.store, "reader", None).await;
    assert_eq!(t.wiki.list(&a, "", now()).await.unwrap().pages.len(), 1);
    assert_eq!(t.wiki.list(&a, "", now()).await.unwrap().pages.len(), 1);
    assert_eq!(t.fake.count("GET", "/repos/jrt/wiki/git/trees/main"), 1);
    assert_eq!(
        t.fake.count(
            "GET",
            &format!("/repos/jrt/wiki/git/blobs/{}", sha_of(b"# A"))
        ),
        1
    );

    let fresh = setup_with(t.store.pool().clone(), 0).await;
    fresh.seed("shared/a.md", "# A", "editor");
    assert_eq!(fresh.wiki.list(&a, "", now()).await.unwrap().pages.len(), 1);
    fresh.flags.down.store(true, Ordering::SeqCst);
    // Stale but served.
    assert_eq!(fresh.wiki.list(&a, "", now()).await.unwrap().pages.len(), 1);
    // A blob already held is not fetched again.
    fresh.flags.down.store(false, Ordering::SeqCst);
    fresh.wiki.list(&a, "", now()).await.unwrap();
    assert_eq!(
        fresh.fake.count(
            "GET",
            &format!("/repos/jrt/wiki/git/blobs/{}", sha_of(b"# A"))
        ),
        1
    );

    let never = setup_with(t.store.pool().clone(), 0).await;
    never.flags.down.store(true, Ordering::SeqCst);
    let e = never.wiki.list(&a, "", now()).await.unwrap_err();
    assert_eq!(
        (e.status, e.detail.as_str()),
        (
            StatusCode::BAD_GATEWAY,
            "the wiki's repo could not be read; try again later"
        )
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_empty_repo_is_an_empty_wiki(pool: PgPool) {
    let t = setup(pool).await;
    t.repo.lock().unwrap().empty = true;
    let a = project_agent(&t.store, "reader", None).await;
    assert!(t.wiki.list(&a, "", now()).await.unwrap().pages.is_empty());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn hidden_and_non_markdown_files_are_invisible(pool: PgPool) {
    let t = setup(pool).await;
    t.seed("shared/a.md", "# A", "editor");
    t.seed(".github/notes.md", "# Hidden", "editor");
    t.seed("shared/script.sh", "echo", "editor");
    let a = project_agent(&t.store, "reader", None).await;
    let pages: Vec<String> = t
        .wiki
        .list(&a, "", now())
        .await
        .unwrap()
        .pages
        .into_iter()
        .map(|p| p.path)
        .collect();
    assert_eq!(pages, ["shared/a.md"]);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn last_change_is_per_page_and_failures_are_remembered_briefly(pool: PgPool) {
    let t = setup(pool).await;
    // Same content, so the same blob sha, on two pages by two authors (B12).
    t.seed("shared/a.md", "# Same", "alice");
    t.seed("shared/b.md", "# Same", "bob");
    assert_eq!(
        t.wiki
            .read("shared/a.md", now())
            .await
            .unwrap()
            .last_change
            .unwrap()
            .author,
        "alice"
    );
    assert_eq!(
        t.wiki
            .read("shared/b.md", now())
            .await
            .unwrap()
            .last_change
            .unwrap()
            .author,
        "bob"
    );
    t.seed("shared/c.md", "# C", "carol");
    t.flags.commits_down.store(true, Ordering::SeqCst);
    assert!(
        t.wiki
            .read("shared/c.md", now())
            .await
            .unwrap()
            .last_change
            .is_none()
    );
    t.flags.commits_down.store(false, Ordering::SeqCst);
    // A failure is remembered briefly: no second lookup right away.
    let lookups = || {
        t.fake
            .calls()
            .iter()
            .filter(|c| c.path == "/repos/jrt/wiki/commits" && c.query.contains("c.md"))
            .count()
    };
    assert!(
        t.wiki
            .read("shared/c.md", now())
            .await
            .unwrap()
            .last_change
            .is_none()
    );
    assert_eq!(lookups(), 1);
    // ...and only briefly: past the retry delay the author shows.
    let quick = Wiki::new(t.app.clone(), Arc::new(t.policy.clone()))
        .with_change_retry(std::time::Duration::ZERO);
    t.flags.commits_down.store(true, Ordering::SeqCst);
    assert!(
        quick
            .read("shared/c.md", now())
            .await
            .unwrap()
            .last_change
            .is_none()
    );
    t.flags.commits_down.store(false, Ordering::SeqCst);
    assert_eq!(
        quick
            .read("shared/c.md", now())
            .await
            .unwrap()
            .last_change
            .unwrap()
            .author,
        "carol"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_write_refreshes_the_copy_only_when_base_sha_disagrees(pool: PgPool) {
    let t = setup_with(pool, 3600).await;
    let a = project_agent(&t.store, "writer", Some("p")).await;
    let trees = || t.fake.count("GET", "/repos/jrt/wiki/git/trees/main");
    let (sha1, _) = written(
        t.wiki
            .write(&a, "projects/p/a.md", "one", "s", None, now())
            .await
            .unwrap(),
    );
    assert_eq!(trees(), 1);
    written(
        t.wiki
            .write(&a, "projects/p/a.md", "two", "s", Some(&sha1), now())
            .await
            .unwrap(),
    );
    assert_eq!(trees(), 1, "no refresh when the copy agrees");
    let e = t
        .wiki
        .write(&a, "projects/p/a.md", "three", "s", Some(&sha1), now())
        .await
        .unwrap_err();
    assert_eq!(e.status, StatusCode::CONFLICT);
    assert_eq!(trees(), 2, "a disagreeing base_sha re-reads the repo");
}

// ---------------------------------------------------------------- routes

async fn keyed_agent(store: &Store, name: &str) -> (AgentId, String) {
    let key = api_key::generate().unwrap();
    let tx = store.begin().await.unwrap();
    let row = agents::insert(
        &tx,
        &agents::NewAgent {
            id: AgentId::new(),
            name,
            description: "",
            key_id: key.key_id.as_str(),
            api_key_hash: key.hash.as_str(),
            kind: AgentKind::Service,
            webhook_url: None,
            webhook_secret: None,
            lldap_username: None,
            parent_agent_id: None,
            sandbox_id: None,
            runtime: None,
            project: Some("p"),
            host: None,
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: now(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (row.id, key.full_key.expose().clone())
}

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let res = wiki::routes::routes()
        .with_state(state.clone())
        .oneshot(req)
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[sqlx::test(migrations = "../store/migrations")]
async fn routes_a_held_agent_reads_but_writes_nothing(pool: PgPool) {
    let t = setup(pool).await;
    let mut state = AppState::new(t.store.clone(), t.policy.clone(), AuthConfig::default());
    state.platform_services = Arc::new(PlatformServices {
        wiki: Some(t.wiki.clone()),
        github: Some(t.app.clone()),
        ..PlatformServices::default()
    });
    let (_, key) = keyed_agent(&t.store, "writer").await;
    let page = json!({"path": "projects/p/a.md", "content": "# A", "summary": "s"});

    let (s, body) = call(
        &state,
        "PUT",
        "/v1/wiki/page",
        Some(&key),
        Some(page.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["created"], true);
    let (s, body) = call(
        &state,
        "GET",
        "/v1/wiki/page?path=projects%2Fp%2Fa.md",
        Some(&key),
        None,
    )
    .await;
    assert_eq!((s, body["content"].clone()), (StatusCode::OK, json!("# A")));
    let (s, body) = call(
        &state,
        "GET",
        "/v1/wiki/search?q=a&limit=99",
        Some(&key),
        None,
    )
    .await;
    assert_eq!((s, body["matches"].clone()), (StatusCode::OK, json!(1)));

    contain(&t.store, "beefcafe", json!({"name": "writer"})).await;
    let (s, body) = call(
        &state,
        "PUT",
        "/v1/wiki/page",
        Some(&key),
        Some(json!({"path": "projects/p/b.md", "content": "x", "summary": "s"})),
    )
    .await;
    assert_eq!(
        (s, body["detail"].clone()),
        (
            StatusCode::FORBIDDEN,
            json!("contained (beefcafe): no wiki writes while you are held")
        )
    );
    let (s, _) = call(
        &state,
        "POST",
        "/v1/wiki/delete",
        Some(&key),
        Some(json!({"path": "projects/p/a.md", "summary": "s"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, body) = call(&state, "GET", "/v1/wiki", Some(&key), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["pages"].as_array().unwrap().len(), 1);

    // No key: 401. No wiki configured: 501.
    assert_eq!(
        call(&state, "GET", "/v1/wiki", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let bare = AppState::new(t.store.clone(), Policy::default(), AuthConfig::default());
    let (s, body) = call(&bare, "GET", "/v1/wiki", Some(&key), None).await;
    assert_eq!(
        (s, body["detail"].clone()),
        (
            StatusCode::NOT_IMPLEMENTED,
            json!("this broker has no wiki")
        )
    );
}
