//! The agents' shared wiki: markdown pages in one GitHub repo that only the
//! broker touches (a2a-wiki-desktop spec §7).
//!
//! Every agent reads and searches it through the broker, with no grant. An
//! agent writes under `projects/<its project>/` and nowhere else; the
//! policy's `wiki.editors` write anywhere. Each write is one commit,
//! authored as the agent. What a page says is whatever some agent wrote, so
//! readers get its project and last author with it.
//!
//! Fixes (DEVIATIONS.md): the last-change cache is keyed by path and blob
//! sha, and a failed lookup is remembered only briefly (B12); writes refresh
//! the copy only when `base_sha` disagrees with it (B14); the credential check also
//! covers the commit summary (B13); a truncated tree listing is logged
//! (B15).

mod github;
pub mod routes;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::policy::Policy;
use agent_auth_core::zones;
use agent_auth_store::agents::AgentRow;
use agent_auth_wire::literal::True;
use agent_auth_wire::wiki::{
    LastChange, WikiDeleted, WikiList, WikiPage, WikiPageEntry, WikiSearch, WikiSearchHit,
    WikiWritten,
};
use axum::http::StatusCode;
use regex::Regex;
use time::OffsetDateTime;
use tokio::time::Instant;

pub use github::GithubWikiBackend;
use github::{BackendError, Snapshot};

use crate::error::ApiError;
use crate::provisioners::common::{agent_ref, repr};
use crate::provisioners::github::GithubApp;

pub const PROJECTS_DIR: &str = "projects";
const MAX_PATH: usize = 200;
const MAX_DEPTH: usize = 6;
const MAX_SUMMARY: usize = 200;
/// How long a failed last-change lookup is remembered.
const CHANGE_RETRY: Duration = Duration::from_secs(30);

/// The shapes of credentials an agent is likely to hold: refused in a page
/// and in a commit summary. A guard against pasting one by mistake.
static SECRET_PATTERNS: LazyLock<Vec<(&'static str, Option<Regex>)>> = LazyLock::new(|| {
    [
        (
            "an agent-auth API key",
            r"\baa_[A-Za-z0-9]{4,}_[A-Za-z0-9_-]{16,}",
        ),
        (
            "a GitHub token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
        ),
        ("a private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        (
            "a JWT",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        ),
        (
            "an API key",
            r"\b(?:sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b",
        ),
    ]
    .into_iter()
    .map(|(what, re)| (what, Regex::new(re).ok()))
    .collect()
});

/// What credential `text` looks like it contains, if any.
fn secret_in(text: &str) -> Option<&'static str> {
    SECRET_PATTERNS
        .iter()
        .find(|(_, re)| re.as_ref().is_none_or(|re| re.is_match(text)))
        .map(|(what, _)| *what)
}

fn segment_ok(s: &str) -> bool {
    let b = s.as_bytes();
    match b.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphanumeric()
                && rest.len() <= 63
                && rest
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        }
        None => false,
    }
}

/// A page's path: plain segments ending in `.md` (INV-15).
pub fn check_path(path: &str) -> Result<(), ApiError> {
    if path.chars().count() > MAX_PATH || !path.ends_with(".md") {
        return Err(ApiError::bad_request(format!(
            "a page's path ends in .md and is at most {MAX_PATH} characters"
        )));
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_DEPTH || !parts.iter().all(|p| segment_ok(p)) {
        return Err(ApiError::bad_request(format!(
            "path {}: at most {MAX_DEPTH} segments of letters, digits, dots, dashes and underscores, each starting with a letter or digit",
            repr(path)
        )));
    }
    Ok(())
}

/// The project a page belongs to: `projects/<p>/...` (at least 3 segments).
#[must_use]
pub fn page_project(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        [first, project, _, ..] if *first == PROJECTS_DIR => Some((*project).to_owned()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct Page {
    sha: String,
    raw: Arc<Vec<u8>>,
    text: String,
}

impl Page {
    fn title(&self, path: &str) -> String {
        for line in self.text.lines() {
            if line.starts_with('#') {
                let t = line.trim_start_matches('#').trim();
                return if t.is_empty() {
                    path.to_owned()
                } else {
                    t.to_owned()
                };
            }
            if !line.trim().is_empty() {
                break;
            }
        }
        path.to_owned()
    }
}

#[derive(Debug, Default)]
struct Cache {
    pages: Arc<BTreeMap<String, Page>>,
    loaded_at: Option<Instant>,
}

/// The wiki service.
#[derive(Debug)]
pub struct Wiki {
    backend: GithubWikiBackend,
    policy: Arc<Policy>,
    cache: tokio::sync::Mutex<Cache>,
    /// Last commit per (path, blob sha); failures are not remembered.
    changes: Mutex<HashMap<(String, String), LastChange>>,
    /// Lookups that failed, and when: not retried for `change_retry`.
    change_failures: Mutex<HashMap<(String, String), Instant>>,
    change_retry: Duration,
}

fn snapshot_to_pages(files: Snapshot) -> BTreeMap<String, Page> {
    files
        .into_iter()
        .map(|(path, (sha, raw))| {
            let text = String::from_utf8_lossy(&raw).into_owned();
            (path, Page { sha, raw, text })
        })
        .collect()
}

impl Wiki {
    /// The wiki of `policy.wiki` (its repo must be set), through `app`.
    #[must_use]
    pub fn new(app: Arc<GithubApp>, policy: Arc<Policy>) -> Wiki {
        let cfg = policy.wiki();
        Wiki {
            backend: GithubWikiBackend::new(app, &cfg.repo, &cfg.branch),
            cache: tokio::sync::Mutex::new(Cache::default()),
            changes: Mutex::new(HashMap::new()),
            change_failures: Mutex::new(HashMap::new()),
            change_retry: CHANGE_RETRY,
            policy,
        }
    }

    /// How long a failed last-change lookup is remembered (default 30 s).
    #[must_use]
    pub fn with_change_retry(mut self, after: Duration) -> Wiki {
        self.change_retry = after;
        self
    }

    fn refresh(&self) -> Duration {
        Duration::from_secs(u64::from(self.policy.wiki().refresh_secs))
    }

    fn is_editor(&self, agent: &AgentRow) -> bool {
        let r = agent_ref(agent);
        self.policy.wiki().editors.iter().any(|p| p.matches(&r))
    }

    /// Where this agent may write, for a person or an agent to read.
    #[must_use]
    pub fn writable(&self, agent: &AgentRow) -> Vec<String> {
        if !zones::may_write_wiki(&self.policy, &agent_ref(agent)) {
            return Vec::new();
        }
        if self.is_editor(agent) {
            return vec!["(every page)".to_owned()];
        }
        agent
            .project
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|p| vec![format!("{PROJECTS_DIR}/{p}/")])
            .unwrap_or_default()
    }

    fn check_write(&self, agent: &AgentRow, path: &str) -> Result<(), ApiError> {
        if !zones::may_write_wiki(&self.policy, &agent_ref(agent)) {
            // Every agent reads the wiki; what this one knows stays where it is.
            return Err(ApiError::forbidden("you don't write the shared wiki"));
        }
        if self.is_editor(agent) {
            return Ok(());
        }
        let Some(project) = agent.project.as_deref().filter(|p| !p.is_empty()) else {
            return Err(ApiError::forbidden(
                "you have no project on record, so there is nowhere in the wiki you may write (the operator sets it: `agent-auth admin agent-set --project`)",
            ));
        };
        if page_project(path).as_deref() != Some(project) {
            return Err(ApiError::forbidden(format!(
                "you may write under {PROJECTS_DIR}/{project}/ only. For a page elsewhere, ask an agent of the project that owns it (shared pages: the homelab agents)"
            )));
        }
        Ok(())
    }

    async fn load(
        &self,
        force: bool,
        now: OffsetDateTime,
    ) -> Result<Arc<BTreeMap<String, Page>>, ApiError> {
        let mut cache = self.cache.lock().await;
        if !force
            && let Some(at) = cache.loaded_at
            && at.elapsed() < self.refresh()
        {
            return Ok(Arc::clone(&cache.pages));
        }
        let known: HashMap<String, Arc<Vec<u8>>> = cache
            .pages
            .values()
            .map(|p| (p.sha.clone(), Arc::clone(&p.raw)))
            .collect();
        match self.backend.snapshot(&known, now).await {
            Ok(files) => {
                cache.pages = Arc::new(snapshot_to_pages(files));
                cache.loaded_at = Some(Instant::now());
                Ok(Arc::clone(&cache.pages))
            }
            Err(e) => {
                // A stale copy is better than none while the repo is unreachable.
                tracing::warn!(repo = %self.policy.wiki().repo, error = ?e, "wiki: could not refresh");
                if cache.loaded_at.is_some() {
                    Ok(Arc::clone(&cache.pages))
                } else {
                    Err(ApiError::new(
                        StatusCode::BAD_GATEWAY,
                        "the wiki's repo could not be read; try again later",
                    ))
                }
            }
        }
    }

    /// The pages a write or delete checks `base_sha` against: the cached
    /// copy when it agrees with `base_sha`, else a fresh one (GitHub's own
    /// sha precondition backs up a stale agreement, B14).
    async fn pages_for_write(
        &self,
        path: &str,
        base_sha: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Arc<BTreeMap<String, Page>>, ApiError> {
        let cached = self.load(false, now).await?;
        let current = cached.get(path);
        if current.is_some() && check_base(path, current, base_sha).is_ok() {
            return Ok(cached);
        }
        if current.is_none() && base_sha.is_none_or(str::is_empty) {
            return Ok(cached);
        }
        self.load(true, now).await
    }

    pub async fn list(
        &self,
        agent: &AgentRow,
        prefix: &str,
        now: OffsetDateTime,
    ) -> Result<WikiList, ApiError> {
        let pages = self.load(false, now).await?;
        Ok(WikiList {
            repo: self.policy.wiki().repo.clone(),
            you_may_write: self.writable(agent),
            pages: pages
                .iter()
                .filter(|(path, _)| path.starts_with(prefix))
                .map(|(path, p)| WikiPageEntry {
                    path: path.clone(),
                    title: p.title(path),
                    bytes: u64::try_from(p.text.len()).unwrap_or(u64::MAX),
                })
                .collect(),
        })
    }

    pub async fn read(&self, path: &str, now: OffsetDateTime) -> Result<WikiPage, ApiError> {
        check_path(path)?;
        let pages = self.load(false, now).await?;
        let Some(page) = pages.get(path) else {
            return Err(ApiError::not_found(format!(
                "no page {} (wiki_list shows what exists)",
                repr(path)
            )));
        };
        let key = (path.to_owned(), page.sha.clone());
        let cached = self
            .changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned();
        let failed_recently = self
            .change_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .is_some_and(|at| at.elapsed() < self.change_retry);
        let change = match cached {
            Some(c) => Some(c),
            None if failed_recently => None,
            None => {
                let c = self.backend.last_change(path, now).await;
                match &c {
                    Some(c) => {
                        self.changes
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(key, c.clone());
                    }
                    // Remembered briefly: a GitHub outage does not cost a
                    // lookup per read, nor hide the author for long.
                    None => {
                        self.change_failures
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(key, Instant::now());
                    }
                }
                c
            }
        };
        Ok(WikiPage {
            path: path.to_owned(),
            sha: page.sha.clone(),
            project: page_project(path),
            last_change: change,
            content: page.text.clone(),
        })
    }

    pub async fn search(
        &self,
        query: &str,
        limit: i64,
        now: OffsetDateTime,
    ) -> Result<WikiSearch, ApiError> {
        let lowered = query.trim().to_lowercase();
        let terms: Vec<&str> = lowered.split_whitespace().collect();
        if terms.is_empty() {
            return Err(ApiError::bad_request("an empty search"));
        }
        let pages = self.load(false, now).await?;
        let mut hits: Vec<(usize, &String, &Page)> = Vec::new();
        for (path, page) in pages.iter() {
            let text = page.text.to_lowercase();
            let head = format!("{path} {}", page.title(path)).to_lowercase();
            if !terms.iter().all(|t| text.contains(t) || head.contains(t)) {
                continue;
            }
            let score = terms.iter().fold(0usize, |acc, t| {
                acc.saturating_add(text.matches(t).count())
                    .saturating_add(head.matches(t).count().saturating_mul(5))
            });
            hits.push((score, path, page));
        }
        hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        let limit = usize::try_from(limit.clamp(1, 25)).unwrap_or(25);
        Ok(WikiSearch {
            query: query.to_owned(),
            matches: u64::try_from(hits.len()).unwrap_or(u64::MAX),
            results: hits
                .iter()
                .take(limit)
                .map(|(_, path, page)| WikiSearchHit {
                    path: (*path).clone(),
                    title: page.title(path),
                    project: page_project(path),
                    lines: matching_lines(&page.text, &terms),
                })
                .collect(),
        })
    }

    pub async fn write(
        &self,
        agent: &AgentRow,
        path: &str,
        content: &str,
        summary: &str,
        base_sha: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<WikiWritten, ApiError> {
        check_path(path)?;
        self.check_write(agent, path)?;
        if content.trim().is_empty() {
            return Err(ApiError::bad_request(
                "an empty page; to remove one, delete it",
            ));
        }
        let max = self.policy.wiki().max_page_bytes;
        if u32::try_from(content.len()).map_or(true, |n| n > max) {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("a page is at most {max} bytes; split it into several"),
            ));
        }
        refuse_secrets(content)?;
        refuse_secrets(summary)?;
        let pages = self.pages_for_write(path, base_sha, now).await?;
        let current = pages.get(path);
        check_base(path, current, base_sha)?;
        if let Some(c) = current
            && c.text == content
        {
            return Ok(WikiWritten::Unchanged {
                path: path.to_owned(),
                sha: c.sha.clone(),
                unchanged: True,
            });
        }
        let message = message(agent, summary)?;
        let sha = match self
            .backend
            .put(
                path,
                content.as_bytes(),
                &message,
                &agent.name,
                current.map(|c| c.sha.as_str()),
                now,
            )
            .await
        {
            Ok(sha) => sha,
            Err(BackendError::Conflict) => {
                return Err(ApiError::conflict(format!(
                    "{} changed while you were writing; read it again",
                    repr(path)
                )));
            }
            Err(e) => return Err(backend_refused(e, "write")),
        };
        let created = current.is_none();
        let raw = Arc::new(content.as_bytes().to_vec());
        let mut cache = self.cache.lock().await;
        let mut updated = (*cache.pages).clone();
        updated.insert(
            path.to_owned(),
            Page {
                sha: sha.clone(),
                raw,
                text: content.to_owned(),
            },
        );
        cache.pages = Arc::new(updated);
        Ok(WikiWritten::Written {
            path: path.to_owned(),
            sha,
            created,
        })
    }

    pub async fn delete(
        &self,
        agent: &AgentRow,
        path: &str,
        summary: &str,
        base_sha: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<WikiDeleted, ApiError> {
        check_path(path)?;
        self.check_write(agent, path)?;
        refuse_secrets(summary)?;
        let pages = self.pages_for_write(path, base_sha, now).await?;
        let Some(current) = pages.get(path) else {
            return Err(ApiError::not_found(format!("no page {}", repr(path))));
        };
        check_base(path, Some(current), base_sha)?;
        let message = message(agent, summary)?;
        match self
            .backend
            .delete(path, &message, &agent.name, &current.sha, now)
            .await
        {
            Ok(()) => {}
            Err(BackendError::Conflict) => {
                return Err(ApiError::conflict(format!(
                    "{} changed while you were deleting it; read it again",
                    repr(path)
                )));
            }
            Err(e) => return Err(backend_refused(e, "delete")),
        }
        let mut cache = self.cache.lock().await;
        let mut updated = (*cache.pages).clone();
        updated.remove(path);
        cache.pages = Arc::new(updated);
        Ok(WikiDeleted {
            path: path.to_owned(),
            deleted: True,
        })
    }
}

fn backend_refused(e: BackendError, what: &str) -> ApiError {
    match e {
        BackendError::Refused(status) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("the wiki's repo refused the {what} ({status})"),
        ),
        other => {
            tracing::error!(error = ?other, "wiki: {what} failed");
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("the wiki's repo refused the {what} (unreachable)"),
            )
        }
    }
}

fn refuse_secrets(text: &str) -> Result<(), ApiError> {
    match secret_in(text) {
        Some(what) => Err(ApiError::bad_request(format!(
            "this looks like it contains {what}. The wiki holds no credentials: say where one is kept, never its value"
        ))),
        None => Ok(()),
    }
}

/// A page that exists is replaced only by someone who read the version
/// being replaced (INV-16).
fn check_base(path: &str, current: Option<&Page>, base_sha: Option<&str>) -> Result<(), ApiError> {
    let base_sha = base_sha.filter(|s| !s.is_empty());
    match (current, base_sha) {
        (None, Some(_)) => Err(ApiError::conflict(format!(
            "{} no longer exists; leave base_sha out to create it",
            repr(path)
        ))),
        (None, None) => Ok(()),
        (Some(c), Some(b)) if c.sha == b => Ok(()),
        (Some(_), b) => Err(ApiError::conflict(format!(
            "{} exists{}: read it and pass its `sha` as base_sha",
            repr(path),
            if b.is_some() {
                " and has changed since you read it"
            } else {
                ""
            }
        ))),
    }
}

fn message(agent: &AgentRow, summary: &str) -> Result<String, ApiError> {
    let line: String = summary
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_SUMMARY)
        .collect();
    if line.is_empty() {
        return Err(ApiError::bad_request(
            "say in one line what changed (summary)",
        ));
    }
    let who = match agent.project.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => format!("{} (project {p})", agent.name),
        None => agent.name.clone(),
    };
    Ok(format!("{line}\n\nAgent: {who}"))
}

fn matching_lines(text: &str, terms: &[&str]) -> Vec<String> {
    text.lines()
        .filter(|line| {
            let low = line.to_lowercase();
            terms.iter().any(|t| low.contains(t))
        })
        .take(3)
        .map(|l| l.trim().chars().take(200).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        for ok in ["a.md", "projects/x/notes.md", "a..b.md", "a/b/c/d/e/f.md"] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "a",
            "../x.md",
            ".hidden.md",
            "a//b.md",
            "/a.md",
            "a b.md",
            "a/b/c/d/e/f/g.md",
            "x/.md",
        ] {
            assert!(check_path(bad).is_err(), "{bad}");
        }
        let long = format!("{}.md", "a".repeat(198));
        assert_eq!(
            check_path(&long).unwrap_err().detail,
            "a page's path ends in .md and is at most 200 characters"
        );
        assert_eq!(
            check_path("../x.md").unwrap_err().detail,
            "path '../x.md': at most 6 segments of letters, digits, dots, dashes and underscores, each starting with a letter or digit"
        );
        assert_eq!(page_project("projects/x/a.md").as_deref(), Some("x"));
        assert_eq!(page_project("projects/x.md"), None);
    }

    #[test]
    fn secret_patterns_compile_and_match() {
        assert!(SECRET_PATTERNS.iter().all(|(_, re)| re.is_some()));
        let gh = format!("ghp_{}", "a".repeat(24));
        assert_eq!(secret_in(&format!("token {gh}")), Some("a GitHub token"));
        assert_eq!(
            secret_in("-----BEGIN RSA PRIVATE KEY-----"),
            Some("a private key")
        );
        assert_eq!(
            secret_in("aa_abcd_0123456789abcdefgh"),
            Some("an agent-auth API key")
        );
        assert_eq!(secret_in("plain text about tokens"), None);
    }

    #[test]
    fn titles() {
        let p = |t: &str| Page {
            sha: String::new(),
            raw: Arc::new(Vec::new()),
            text: t.to_owned(),
        };
        assert_eq!(p("\n# Hello \nx").title("a.md"), "Hello");
        assert_eq!(p("intro\n# Hello").title("a.md"), "a.md");
        assert_eq!(p("###\n").title("a.md"), "a.md");
    }
}
