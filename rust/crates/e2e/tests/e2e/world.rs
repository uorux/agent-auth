//! A broker with fake GitHub and OpenRouter behind it, and the policy the
//! scenarios rely on.

use std::path::PathBuf;

use serde_json::Value;
use sqlx::postgres::PgConnectOptions;

use crate::fakes::{self, Fake};
use crate::harness::{Broker, Setup, TempDir, database_url};

/// The scenarios' policy: a2a from `auto-*` agents and GitHub repos
/// `acme/auto-*` are approved by policy, `acme/llm-*` goes to the LLM
/// reviewer, delegated work on `acme/delegated-*` for an `auto-*`
/// delegator is approved; everything else waits for a human.
pub const POLICY: &str = r#"
defaults:
  action: surface
  max_duration: 24h
llm:
  model: e2e/reviewer
  retry_budget: 2
  timeout_secs: 10
platforms:
  github:
    repo_allowlist: ["acme/*"]
    permission_ceiling:
      contents: write
      pull_requests: write
      metadata: read
rules:
  - match: {platform: a2a, agent: "auto-*"}
    action: approve
    reason: e2e agents talk freely
  - match: {platform: github, resource: "acme/auto-*"}
    action: approve
    constraints: {max_duration: 8h}
  - match: {platform: github, resource: "acme/llm-*"}
    action: llm
  - match: {platform: github, resource: "acme/delegated-*", delegator: "auto-*"}
    action: approve
"#;

/// The GitHub App key the crypto tests use (PKCS#1 PEM).
fn github_key(dir: &TempDir) -> PathBuf {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crypto/tests/vectors/python.json"
    ))
    .unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    let path = dir.path().join("github-app.pem");
    std::fs::write(&path, v["github_app"]["pkcs1_pem"].as_str().unwrap()).unwrap();
    path
}

#[derive(Debug)]
pub struct World {
    pub broker: Broker,
    pub github: Fake,
    pub openrouter: Fake,
    _files: TempDir,
}

impl World {
    pub async fn start(opts: &PgConnectOptions) -> World {
        World::start_with(opts, POLICY).await
    }

    pub fn setup(
        opts: &PgConnectOptions,
        policy: &str,
        github: &Fake,
        openrouter: &Fake,
        files: &TempDir,
    ) -> Setup {
        let key = github_key(files);
        Setup::new(database_url(opts), policy)
            .env("GITHUB_APP_ID", "12345")
            .env("GITHUB_APP_PRIVATE_KEY_FILE", key.to_str().unwrap())
            .env("GITHUB_API_URL", &github.url)
            .env("OPENROUTER_API_KEY", "sk-or-e2e")
            .env("OPENROUTER_BASE_URL", &format!("{}/api/v1", openrouter.url))
    }

    pub async fn start_with(opts: &PgConnectOptions, policy: &str) -> World {
        let github = fakes::github().await;
        let openrouter = fakes::openrouter().await;
        let files = TempDir::new();
        let setup = World::setup(opts, policy, &github, &openrouter, &files);
        let broker = Broker::start(setup).await;
        World {
            broker,
            github,
            openrouter,
            _files: files,
        }
    }
}
