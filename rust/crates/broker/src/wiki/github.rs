//! The wiki's repo through GitHub's REST API, as the broker's GitHub App:
//! no clone, nothing on disk (a2a-wiki-desktop spec §7.6). The App must be
//! installed on the repo with Contents: write.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use agent_auth_crypto::Secret;
use agent_auth_wire::wiki::LastChange;
use base64::Engine as _;
use reqwest::Method;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::check_path;
use crate::provisioners::common::at;
use crate::provisioners::github::GithubApp;
use crate::provisioners::http::Reply;

const PERMISSIONS: [(&str, &str); 2] = [("contents", "write"), ("metadata", "read")];

/// Why a backend call did not do what was asked.
#[derive(Debug)]
pub enum BackendError {
    /// The page is not at the sha the write was based on.
    Conflict,
    /// GitHub refused (status for the agent's message).
    Refused(u16),
    /// Anything else (unreachable, token, malformed answer): logged.
    Other(String),
}

/// path → (blob sha, content).
pub type Snapshot = BTreeMap<String, (String, Arc<Vec<u8>>)>;

#[derive(Debug)]
pub struct GithubWikiBackend {
    app: Arc<GithubApp>,
    repo: String,
    branch: String,
}

fn author(name: &str) -> Value {
    json!({"name": name, "email": format!("{name}@agents.invalid")})
}

impl GithubWikiBackend {
    #[must_use]
    pub fn new(app: Arc<GithubApp>, repo: &str, branch: &str) -> GithubWikiBackend {
        GithubWikiBackend {
            app,
            repo: repo.to_owned(),
            branch: branch.to_owned(),
        }
    }

    async fn token(&self, now: OffsetDateTime) -> Result<Secret<String>, BackendError> {
        self.app
            .own_token(&self.repo, &PERMISSIONS, now)
            .await
            .map_err(|e| BackendError::Other(e.to_string()))
    }

    async fn call(
        &self,
        method: Method,
        rest: &str,
        body: Option<&Value>,
        query: &[(&str, &str)],
        timeout: u64,
        now: OffsetDateTime,
    ) -> Result<Reply, BackendError> {
        let token = self.token(now).await?;
        self.app
            .call_with_token(
                method,
                &format!("/repos/{}/{rest}", self.repo),
                token.expose(),
                body,
                query,
                Duration::from_secs(timeout),
            )
            .await
            .map_err(|e| BackendError::Other(e.to_string()))
    }

    /// Every markdown page; blobs whose sha is in `known` are not fetched.
    pub async fn snapshot(
        &self,
        known: &HashMap<String, Arc<Vec<u8>>>,
        now: OffsetDateTime,
    ) -> Result<Snapshot, BackendError> {
        let r = self
            .call(
                Method::GET,
                &format!("git/trees/{}", self.branch),
                None,
                &[("recursive", "1")],
                30,
                now,
            )
            .await?;
        if matches!(r.status, 404 | 409) {
            return Ok(Snapshot::new()); // no such branch yet, or an empty repo
        }
        if r.status != 200 {
            return Err(BackendError::Other(format!("tree listing: {}", r.status)));
        }
        let tree = r.json();
        if at(&tree, &["truncated"]).as_bool() == Some(true) {
            // B15: pages past GitHub's limit are invisible; say so.
            tracing::warn!(repo = %self.repo, "wiki: GitHub truncated the tree listing; some pages are missing");
        }
        let mut out = Snapshot::new();
        let mut fetched: HashMap<String, Arc<Vec<u8>>> = HashMap::new();
        for item in at(&tree, &["tree"]).as_array().into_iter().flatten() {
            let path = at(item, &["path"]).as_str().unwrap_or("");
            if at(item, &["type"]).as_str() != Some("blob")
                || !path.ends_with(".md")
                || check_path(path).is_err()
            {
                continue; // put there by hand under a name agents can't address
            }
            let Some(sha) = at(item, &["sha"]).as_str() else {
                continue;
            };
            let data = match known.get(sha).or_else(|| fetched.get(sha)) {
                Some(d) => Arc::clone(d),
                None => {
                    let blob = self
                        .call(Method::GET, &format!("git/blobs/{sha}"), None, &[], 30, now)
                        .await?;
                    if blob.status != 200 {
                        return Err(BackendError::Other(format!("blob {sha}: {}", blob.status)));
                    }
                    let b64: String = at(&blob.json(), &["content"])
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .filter(|c| !c.is_ascii_whitespace())
                        .collect();
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .map_err(|_| BackendError::Other(format!("blob {sha}: not base64")))?;
                    let bytes = Arc::new(bytes);
                    fetched.insert(sha.to_owned(), Arc::clone(&bytes));
                    bytes
                }
            };
            out.insert(path.to_owned(), (sha.to_owned(), data));
        }
        Ok(out)
    }

    /// Create (`sha` none) or replace the page; returns the new blob sha.
    pub async fn put(
        &self,
        path: &str,
        content: &[u8],
        message: &str,
        author_name: &str,
        sha: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<String, BackendError> {
        let mut body = json!({
            "message": message,
            "content": base64::engine::general_purpose::STANDARD.encode(content),
            "branch": self.branch,
            "author": author(author_name),
        });
        if let (Some(sha), Value::Object(m)) = (sha, &mut body) {
            m.insert("sha".into(), json!(sha));
        }
        let r = self
            .call(
                Method::PUT,
                &format!("contents/{path}"),
                Some(&body),
                &[],
                30,
                now,
            )
            .await?;
        match r.status {
            409 | 422 => Err(BackendError::Conflict),
            200 | 201 => at(&r.json(), &["content", "sha"])
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| BackendError::Other("write answer has no sha".to_owned())),
            status => {
                tracing::error!(path, status, body = %r.head(300), "wiki: writing failed");
                Err(BackendError::Refused(status))
            }
        }
    }

    pub async fn delete(
        &self,
        path: &str,
        message: &str,
        author_name: &str,
        sha: &str,
        now: OffsetDateTime,
    ) -> Result<(), BackendError> {
        let body = json!({"message": message, "sha": sha, "branch": self.branch, "author": author(author_name)});
        let r = self
            .call(
                Method::DELETE,
                &format!("contents/{path}"),
                Some(&body),
                &[],
                30,
                now,
            )
            .await?;
        match r.status {
            409 | 422 => Err(BackendError::Conflict),
            200 => Ok(()),
            status => {
                tracing::error!(path, status, body = %r.head(300), "wiki: deleting failed");
                Err(BackendError::Refused(status))
            }
        }
    }

    /// The newest commit touching `path`; `None` when there is none or it
    /// could not be read.
    pub async fn last_change(&self, path: &str, now: OffsetDateTime) -> Option<LastChange> {
        let r = self
            .call(
                Method::GET,
                "commits",
                None,
                &[("path", path), ("sha", &self.branch), ("per_page", "1")],
                15,
                now,
            )
            .await
            .ok()?;
        if r.status != 200 {
            return None;
        }
        let list = r.json();
        let first = list.as_array()?.first()?;
        let commit = at(first, &["commit"]);
        Some(LastChange {
            author: at(commit, &["author", "name"]).as_str()?.to_owned(),
            at: at(commit, &["author", "date"]).as_str()?.to_owned(),
            summary: at(commit, &["message"])
                .as_str()?
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
        })
    }
}
