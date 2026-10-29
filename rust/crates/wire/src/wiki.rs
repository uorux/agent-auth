//! The agents' wiki (`/v1/wiki*`; http-api §2.5, a2a spec §7).

use serde::{Deserialize, Serialize};

use crate::literal::True;
use crate::text::Text;

/// `PUT /v1/wiki/page`. The path's shape, the page size (`max_page_bytes`,
/// 413) and secrets are the service's checks; here the content is only
/// bounded by what a body may carry at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageWrite {
    pub path: Text<0, 300>,
    pub content: Text<0, 1_048_576>,
    pub summary: Text<1, 500>,
    #[serde(default)]
    pub base_sha: Option<Text<0, 64>>,
}

/// `POST /v1/wiki/delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageDelete {
    pub path: Text<0, 300>,
    pub summary: Text<1, 500>,
    #[serde(default)]
    pub base_sha: Option<Text<0, 64>>,
}

/// `GET /v1/wiki?prefix=` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WikiList {
    pub repo: String,
    /// `["projects/<p>/"]`, `["(every page)"]` or `[]`.
    pub you_may_write: Vec<String>,
    pub pages: Vec<WikiPageEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WikiPageEntry {
    pub path: String,
    pub title: String,
    pub bytes: u64,
}

/// `GET /v1/wiki/page?path=` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WikiPage {
    pub path: String,
    pub sha: String,
    /// The project whose page this is; null for shared pages.
    pub project: Option<String>,
    pub last_change: Option<LastChange>,
    pub content: String,
}

/// The page's last commit, as GitHub reports it (its date passed through).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastChange {
    pub author: String,
    pub at: String,
    pub summary: String,
}

/// `GET /v1/wiki/search?q=&limit=` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WikiSearch {
    pub query: String,
    pub matches: u64,
    pub results: Vec<WikiSearchHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WikiSearchHit {
    pub path: String,
    pub title: String,
    pub project: Option<String>,
    /// Up to three matching lines, each at most 200 characters.
    pub lines: Vec<String>,
}

/// `PUT /v1/wiki/page` → 200: written, or nothing to write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WikiWritten {
    Written {
        path: String,
        sha: String,
        created: bool,
    },
    Unchanged {
        path: String,
        sha: String,
        unchanged: True,
    },
}

/// `POST /v1/wiki/delete` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WikiDeleted {
    pub path: String,
    pub deleted: True,
}
