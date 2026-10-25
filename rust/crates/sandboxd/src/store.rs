//! sandboxd's own state, local to the VM (sandboxd spec §4.3): the VM's
//! agent keys (the only copy anywhere: the broker keeps hashes), projects,
//! conversations, which a2a threads each owns, queued messages, project
//! grants, and the lockdown and containment flags.
//!
//! Not SQLite: a few small JSON documents under `state_dir` (root 0700),
//! each file 0600, each change written whole to a new temporary file,
//! fsynced, renamed over the old one and the directory fsynced. A change
//! is visible in memory only once it is on disk; a crash leaves either the
//! old document or the new one. Each document has its own lock, and every
//! read-modify-write (`drain` included) happens under it, which is what the
//! Python's statements under its lock gave.
//!
//! A document that exists but does not read (corrupt, wrong permissions)
//! stops the daemon at startup: the flags in it may be holding agents.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use agent_auth_crypto::Secret;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::names::ConvId;

/// The largest document read back (each is small; inbox files hold queued
/// messages).
const MAX_DOC_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("state file {path} does not read: {reason}")]
    Corrupt { path: PathBuf, reason: String },
}

fn io_err(path: &Path) -> impl Fn(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Seconds since the epoch (the Python's `time.time()`).
#[must_use]
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

// ------------------------------------------------------------- documents

/// Replace `path` with `data` durably: a new 0600 file (never an existing
/// one), fsynced, renamed into place, the directory fsynced.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// A file that exists must be a regular file only its owner can read.
fn read_private(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(path)(e)),
    };
    let meta = f.metadata().map_err(io_err(path))?;
    let corrupt = |reason: &str| StoreError::Corrupt {
        path: path.to_owned(),
        reason: reason.to_owned(),
    };
    if !meta.is_file() {
        return Err(corrupt("not a regular file"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(corrupt("readable by others (must be 0600)"));
    }
    if meta.len() > MAX_DOC_BYTES {
        return Err(corrupt("too large"));
    }
    let mut buf = Vec::new();
    f.take(MAX_DOC_BYTES)
        .read_to_end(&mut buf)
        .map_err(io_err(path))?;
    Ok(Some(buf))
}

/// One JSON document and its lock.
struct Doc<T> {
    path: PathBuf,
    data: Mutex<T>,
}

impl<T: Serialize + DeserializeOwned + Default + Clone> Doc<T> {
    fn open(path: PathBuf) -> Result<Doc<T>, StoreError> {
        let data = match read_private(&path)? {
            None => T::default(),
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt {
                path: path.clone(),
                reason: e.to_string(),
            })?,
        };
        Ok(Doc {
            path,
            data: Mutex::new(data),
        })
    }

    fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.data.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Change it: on disk first, then in memory.
    fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> Result<R, StoreError> {
        let mut guard = self.data.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = guard.clone();
        let out = f(&mut next);
        let bytes = serde_json::to_vec(&next).map_err(|e| StoreError::Corrupt {
            path: self.path.clone(),
            reason: e.to_string(),
        })?;
        write_atomic(&self.path, &bytes).map_err(io_err(&self.path))?;
        *guard = next;
        Ok(out)
    }
}

// ---------------------------------------------------------------- records

/// An agent whose key this VM holds. `Debug` leaves the key out.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub name: String,
    pub agent_id: String,
    /// The key's id (`aa_<key_id>_…`): what `key.ack` names.
    #[serde(default)]
    pub key_id: String,
    pub runtime: Option<String>,
    pub project: Option<String>,
    #[serde(with = "secret_string")]
    pub api_key: Secret<String>,
    pub updated_at: f64,
}

impl fmt::Debug for AgentRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentRecord")
            .field("name", &self.name)
            .field("agent_id", &self.agent_id)
            .field("runtime", &self.runtime)
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

mod secret_string {
    use agent_auth_crypto::Secret;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Secret<String>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Secret<String>, D::Error> {
        Ok(Secret::new(String::deserialize(d)?))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub name: String,
    pub uid: u32,
    pub sealed: bool,
    pub created_at: f64,
}

/// `running | parked | attached | closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConvState {
    Running,
    Parked,
    Attached,
    Closed,
}

impl ConvState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ConvState::Running => "running",
            ConvState::Parked => "parked",
            ConvState::Attached => "attached",
            ConvState::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conversation {
    pub id: ConvId,
    pub agent: String,
    pub runtime: String,
    pub runtime_session_id: Option<String>,
    pub broker_session_id: Option<String>,
    pub state: ConvState,
    /// `headless | interactive`.
    pub mode: String,
    pub title: String,
    pub created_by: String,
    pub created_at: f64,
    pub last_activity: f64,
    pub turns: u64,
}

impl Conversation {
    /// As agents and operators see it: without its broker session.
    #[must_use]
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.as_str(),
            "agent": self.agent,
            "runtime": self.runtime,
            "runtime_session_id": self.runtime_session_id,
            "state": self.state.as_str(),
            "mode": self.mode,
            "title": self.title,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "turns": self.turns,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadRecord {
    pub thread_id: String,
    pub conversation_id: ConvId,
    pub peer: Option<String>,
    pub role: Option<String>,
    pub topic: Option<String>,
    pub cursor: u64,
    /// `open | closed`.
    pub closed: bool,
    /// Insertion order (the Python's rowid), for "its last related thread".
    #[serde(default)]
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub grant_id: String,
    pub project: String,
    pub target: String,
    /// `project.read | project.write`.
    pub access: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Agents(BTreeMap<String, AgentRecord>);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Projects {
    projects: BTreeMap<String, ProjectRecord>,
    grants: BTreeMap<String, GrantRecord>,
    /// Grant ids revoked (or revoked before they arrived), with when: a
    /// late `project.grant` for one is refused (B-7).
    #[serde(default)]
    revoked: BTreeMap<String, f64>,
}

/// The most a conversation's inbox holds (messages, bytes): beyond, a new
/// message is refused (its thread is closed) rather than the document
/// growing without bound.
pub const MAX_INBOX_ITEMS: usize = 1000;
pub const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;

/// The most revoked grant ids remembered (the oldest go first).
pub const MAX_TOMBSTONES: usize = 10_000;

/// The hold flags (`kv` `locked` and `contained` in the Python).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Flags {
    locked: bool,
    contained: BTreeSet<String>,
    /// sha256 of the shared codex login as last synced into the owner
    /// project (an operator's `secret-set` since then wins over its copy).
    #[serde(default)]
    codex_auth_digest: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Conversations {
    conversations: BTreeMap<ConvId, Conversation>,
    threads: BTreeMap<String, ThreadRecord>,
    next_thread_seq: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Inbox(Vec<String>);

/// The state.
pub struct Store {
    dir: PathBuf,
    agents: Doc<Agents>,
    projects: Doc<Projects>,
    flags: Doc<Flags>,
    convs: Doc<Conversations>,
    inboxes: Mutex<BTreeMap<ConvId, std::sync::Arc<Doc<Inbox>>>>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").field("dir", &self.dir).finish()
    }
}

impl Store {
    /// Open (creating `dir`, 0700) and read every document.
    pub fn open(dir: &Path) -> Result<Store, StoreError> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(io_err(dir))?;
        let inbox_dir = dir.join("inbox");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&inbox_dir)
            .map_err(io_err(&inbox_dir))?;
        Ok(Store {
            dir: dir.to_owned(),
            agents: Doc::open(dir.join("agents.json"))?,
            projects: Doc::open(dir.join("projects.json"))?,
            flags: Doc::open(dir.join("flags.json"))?,
            convs: Doc::open(dir.join("conversations.json"))?,
            inboxes: Mutex::new(BTreeMap::new()),
        })
    }

    // --------------------------------------------------------- agents

    /// Insert or replace (by name).
    pub fn put_agent(&self, rec: AgentRecord) -> Result<(), StoreError> {
        self.agents.update(|a| {
            a.0.insert(rec.name.clone(), rec);
        })
    }

    #[must_use]
    pub fn agent(&self, name: &str) -> Option<AgentRecord> {
        self.agents.read(|a| a.0.get(name).cloned())
    }

    /// By name.
    #[must_use]
    pub fn agents(&self) -> Vec<AgentRecord> {
        self.agents.read(|a| a.0.values().cloned().collect())
    }

    // ------------------------------------------------------- projects

    #[must_use]
    pub fn project(&self, name: &str) -> Option<ProjectRecord> {
        self.projects.read(|p| p.projects.get(name).cloned())
    }

    #[must_use]
    pub fn projects(&self) -> Vec<ProjectRecord> {
        self.projects
            .read(|p| p.projects.values().cloned().collect())
    }

    /// Add a project with the lowest free uid in `(base, max]` (`None`:
    /// none free), atomically with the choice.
    pub fn add_project(
        &self,
        name: &str,
        base: u32,
        max: u32,
    ) -> Result<Result<ProjectRecord, AddProject>, StoreError> {
        self.projects.update(|p| {
            if p.projects.contains_key(name) {
                return Err(AddProject::Exists);
            }
            let used: BTreeSet<u32> = p.projects.values().map(|r| r.uid).collect();
            let Some(uid) = (base.saturating_add(1)..=max).find(|u| !used.contains(u)) else {
                return Err(AddProject::NoUid);
            };
            let rec = ProjectRecord {
                name: name.to_owned(),
                uid,
                sealed: false,
                created_at: now(),
            };
            p.projects.insert(name.to_owned(), rec.clone());
            Ok(rec)
        })
    }

    /// Undo [`Store::add_project`] (creating its user or directories failed).
    pub fn remove_project(&self, name: &str) -> Result<(), StoreError> {
        self.projects.update(|p| {
            p.projects.remove(name);
        })
    }

    pub fn seal_project(&self, name: &str) -> Result<(), StoreError> {
        self.projects.update(|p| {
            if let Some(r) = p.projects.get_mut(name) {
                r.sealed = true;
            }
        })
    }

    // -------------------------------------------------- project grants

    pub fn add_project_grant(&self, g: GrantRecord) -> Result<(), StoreError> {
        self.projects.update(|p| {
            p.grants.insert(g.grant_id.clone(), g);
        })
    }

    #[must_use]
    pub fn project_grant(&self, grant_id: &str) -> Option<GrantRecord> {
        self.projects.read(|p| p.grants.get(grant_id).cloned())
    }

    /// Record a grant that is not revoked; false (nothing recorded) if its
    /// id was revoked already.
    pub fn add_project_grant_unless_revoked(&self, g: GrantRecord) -> Result<bool, StoreError> {
        self.projects.update(|p| {
            if p.revoked.contains_key(&g.grant_id) {
                return false;
            }
            p.grants.insert(g.grant_id.clone(), g);
            true
        })
    }

    /// Forget a grant and remember its id as revoked.
    pub fn tombstone_project_grant(&self, grant_id: &str) -> Result<(), StoreError> {
        let t = now();
        self.projects.update(|p| {
            p.grants.remove(grant_id);
            p.revoked.insert(grant_id.to_owned(), t);
            while p.revoked.len() > MAX_TOMBSTONES {
                let oldest = p
                    .revoked
                    .iter()
                    .min_by(|a, b| a.1.total_cmp(b.1))
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => {
                        p.revoked.remove(&k);
                    }
                    None => break,
                }
            }
        })
    }

    #[must_use]
    pub fn is_revoked(&self, grant_id: &str) -> bool {
        self.projects.read(|p| p.revoked.contains_key(grant_id))
    }

    /// Every recorded grant.
    #[must_use]
    pub fn all_project_grants(&self) -> Vec<GrantRecord> {
        self.projects.read(|p| p.grants.values().cloned().collect())
    }

    pub fn pop_project_grant(&self, grant_id: &str) -> Result<Option<GrantRecord>, StoreError> {
        self.projects.update(|p| p.grants.remove(grant_id))
    }

    #[must_use]
    pub fn project_grants(&self, project: &str, target: &str) -> Vec<GrantRecord> {
        self.projects.read(|p| {
            p.grants
                .values()
                .filter(|g| g.project == project && g.target == target)
                .cloned()
                .collect()
        })
    }

    // ---------------------------------------------------------- flags

    #[must_use]
    pub fn locked(&self) -> bool {
        self.flags.read(|f| f.locked)
    }

    #[must_use]
    pub fn contained(&self) -> BTreeSet<String> {
        self.flags.read(|f| f.contained.clone())
    }

    pub fn set_locked(&self, locked: bool) -> Result<(), StoreError> {
        self.flags.update(|f| f.locked = locked)
    }

    pub fn set_contained(&self, contained: BTreeSet<String>) -> Result<(), StoreError> {
        self.flags.update(|f| f.contained = contained)
    }

    #[must_use]
    pub fn codex_auth_digest(&self) -> Option<String> {
        self.flags.read(|f| f.codex_auth_digest.clone())
    }

    pub fn set_codex_auth_digest(&self, digest: Option<String>) -> Result<(), StoreError> {
        self.flags.update(|f| f.codex_auth_digest = digest)
    }

    // -------------------------------------------------- conversations

    /// A new conversation, `parked`, its title cut to 200 characters.
    pub fn new_conversation(
        &self,
        agent: &str,
        runtime: &str,
        mode: &str,
        title: &str,
        created_by: &str,
    ) -> Result<Conversation, StoreError> {
        let t = now();
        self.convs.update(|c| {
            let mut id = ConvId::generate();
            while c.conversations.contains_key(&id) {
                id = ConvId::generate();
            }
            let conv = Conversation {
                id: id.clone(),
                agent: agent.to_owned(),
                runtime: runtime.to_owned(),
                runtime_session_id: None,
                broker_session_id: None,
                state: ConvState::Parked,
                mode: mode.to_owned(),
                title: title.chars().take(200).collect(),
                created_by: created_by.to_owned(),
                created_at: t,
                last_activity: t,
                turns: 0,
            };
            c.conversations.insert(id, conv.clone());
            conv
        })
    }

    #[must_use]
    pub fn conversation(&self, id: &ConvId) -> Option<Conversation> {
        self.convs.read(|c| c.conversations.get(id).cloned())
    }

    /// Most recently active first; closed ones only when asked.
    #[must_use]
    pub fn conversations(&self, agent: Option<&str>, include_closed: bool) -> Vec<Conversation> {
        let mut out: Vec<Conversation> = self.convs.read(|c| {
            c.conversations
                .values()
                .filter(|v| agent.is_none_or(|a| v.agent == a))
                .filter(|v| include_closed || v.state != ConvState::Closed)
                .cloned()
                .collect()
        });
        out.sort_by(|a, b| b.last_activity.total_cmp(&a.last_activity));
        out
    }

    /// Change one conversation (nothing if it is gone).
    pub fn update_conversation(
        &self,
        id: &ConvId,
        f: impl FnOnce(&mut Conversation),
    ) -> Result<(), StoreError> {
        self.convs.update(|c| {
            if let Some(conv) = c.conversations.get_mut(id) {
                f(conv);
            }
        })
    }

    pub fn touch(&self, id: &ConvId) -> Result<(), StoreError> {
        let t = now();
        self.update_conversation(id, |c| c.last_activity = t)
    }

    // -------------------------------------------------------- threads

    /// Bind a thread to a conversation. On a thread already bound only its
    /// conversation changes.
    pub fn bind_thread(
        &self,
        thread_id: &str,
        conv: &ConvId,
        peer: Option<&str>,
        role: Option<&str>,
        topic: Option<&str>,
    ) -> Result<(), StoreError> {
        self.convs.update(|c| {
            if let Some(t) = c.threads.get_mut(thread_id) {
                t.conversation_id = conv.clone();
                return;
            }
            c.next_thread_seq = c.next_thread_seq.saturating_add(1);
            c.threads.insert(
                thread_id.to_owned(),
                ThreadRecord {
                    thread_id: thread_id.to_owned(),
                    conversation_id: conv.clone(),
                    peer: peer.map(str::to_owned),
                    role: role.map(str::to_owned),
                    topic: topic.map(str::to_owned),
                    cursor: 0,
                    closed: false,
                    seq: c.next_thread_seq,
                },
            );
        })
    }

    #[must_use]
    pub fn thread(&self, thread_id: &str) -> Option<ThreadRecord> {
        self.convs.read(|c| c.threads.get(thread_id).cloned())
    }

    /// In the order they were bound.
    #[must_use]
    pub fn threads_of(&self, conv: &ConvId) -> Vec<ThreadRecord> {
        let mut out: Vec<ThreadRecord> = self.convs.read(|c| {
            c.threads
                .values()
                .filter(|t| &t.conversation_id == conv)
                .cloned()
                .collect()
        });
        out.sort_by_key(|t| t.seq);
        out
    }

    pub fn set_thread_cursor(&self, thread_id: &str, cursor: u64) -> Result<(), StoreError> {
        self.convs.update(|c| {
            if let Some(t) = c.threads.get_mut(thread_id) {
                t.cursor = cursor;
            }
        })
    }

    pub fn set_thread_closed(&self, thread_id: &str) -> Result<(), StoreError> {
        self.convs.update(|c| {
            if let Some(t) = c.threads.get_mut(thread_id) {
                t.closed = true;
            }
        })
    }

    // ---------------------------------------------------------- inbox

    fn inbox(&self, conv: &ConvId) -> Result<std::sync::Arc<Doc<Inbox>>, StoreError> {
        let mut map = self.inboxes.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(d) = map.get(conv) {
            return Ok(std::sync::Arc::clone(d));
        }
        let doc = std::sync::Arc::new(Doc::open(
            self.dir
                .join("inbox")
                .join(format!("{}.json", conv.as_str())),
        )?);
        map.insert(conv.clone(), std::sync::Arc::clone(&doc));
        Ok(doc)
    }

    /// Whether one more text fits the conversation's inbox.
    pub fn inbox_room(&self, conv: &ConvId, text: &str) -> Result<bool, StoreError> {
        Ok(self.inbox(conv)?.read(|i| {
            let bytes: usize = i.0.iter().map(String::len).sum();
            i.0.len() < MAX_INBOX_ITEMS && bytes.saturating_add(text.len()) <= MAX_INBOX_BYTES
        }))
    }

    /// Queue a text for a conversation.
    pub fn queue(&self, conv: &ConvId, text: &str) -> Result<(), StoreError> {
        self.inbox(conv)?.update(|i| i.0.push(text.to_owned()))
    }

    /// Queue several, in order.
    pub fn queue_all(&self, conv: &ConvId, texts: &[String]) -> Result<(), StoreError> {
        if texts.is_empty() {
            return Ok(());
        }
        self.inbox(conv)?
            .update(|i| i.0.extend(texts.iter().cloned()))
    }

    /// Take everything queued, in order.
    pub fn drain(&self, conv: &ConvId) -> Result<Vec<String>, StoreError> {
        let doc = self.inbox(conv)?;
        if doc.read(|i| i.0.is_empty()) {
            return Ok(Vec::new());
        }
        doc.update(|i| std::mem::take(&mut i.0))
    }

    /// What is queued, left there.
    pub fn peek(&self, conv: &ConvId) -> Result<Vec<String>, StoreError> {
        Ok(self.inbox(conv)?.read(|i| i.0.clone()))
    }
}

/// Why a project was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddProject {
    Exists,
    NoUid,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::os::unix::fs::PermissionsExt as _;

    fn rec(name: &str) -> AgentRecord {
        AgentRecord {
            name: name.to_owned(),
            agent_id: "id".to_owned(),
            key_id: "0123456789ab".to_owned(),
            runtime: Some("claude".to_owned()),
            project: Some("p".to_owned()),
            api_key: Secret::new("aa_0123456789ab_secret".to_owned()),
            updated_at: 1.0,
        }
    }

    #[test]
    fn survives_a_reopen_with_private_files() {
        let d = TestDir::new("store");
        let s = Store::open(d.path()).unwrap();
        s.put_agent(rec("a")).unwrap();
        let p = s.add_project("larder", 40000, 40002).unwrap().unwrap();
        assert_eq!(p.uid, 40001);
        assert_eq!(
            s.add_project("larder", 40000, 40002).unwrap(),
            Err(AddProject::Exists)
        );
        s.add_project("b", 40000, 40002).unwrap().unwrap();
        assert_eq!(
            s.add_project("c", 40000, 40002).unwrap(),
            Err(AddProject::NoUid)
        );
        s.set_locked(true).unwrap();
        s.set_contained(["x".to_owned()].into()).unwrap();
        let c = s
            .new_conversation("a", "claude", "headless", &"t".repeat(300), "test")
            .unwrap();
        assert_eq!(c.title.chars().count(), 200);
        s.queue(&c.id, "one").unwrap();
        s.queue(&c.id, "two").unwrap();
        s.bind_thread("t1", &c.id, Some("peer"), Some("responder"), None)
            .unwrap();
        s.bind_thread("t1", &c.id, Some("other"), None, None)
            .unwrap();
        assert_eq!(s.thread("t1").unwrap().peer.as_deref(), Some("peer"));
        drop(s);
        let s = Store::open(d.path()).unwrap();
        assert_eq!(
            s.agent("a").unwrap().api_key.expose(),
            "aa_0123456789ab_secret"
        );
        assert!(!format!("{:?}", s.agent("a").unwrap()).contains("secret"));
        assert!(s.locked());
        assert!(s.contained().contains("x"));
        assert_eq!(s.peek(&c.id).unwrap(), vec!["one", "two"]);
        assert_eq!(s.drain(&c.id).unwrap(), vec!["one", "two"]);
        assert!(s.drain(&c.id).unwrap().is_empty());
        for entry in fs::read_dir(d.path()).unwrap() {
            let entry = entry.unwrap();
            let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
            if entry.file_type().unwrap().is_file() {
                assert_eq!(mode, 0o600, "{:?}", entry.path());
                assert!(!entry.file_name().to_string_lossy().ends_with(".tmp"));
            }
        }
    }

    #[test]
    fn refuses_unreadable_or_exposed_documents() {
        let d = TestDir::new("store-bad");
        fs::write(d.path().join("flags.json"), b"{not json").unwrap();
        fs::set_permissions(
            d.path().join("flags.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            Store::open(d.path()),
            Err(StoreError::Corrupt { .. })
        ));
        fs::write(
            d.path().join("flags.json"),
            b"{\"locked\": true, \"contained\": []}",
        )
        .unwrap();
        fs::set_permissions(
            d.path().join("flags.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            Store::open(d.path()),
            Err(StoreError::Corrupt { .. })
        ));
        fs::set_permissions(
            d.path().join("flags.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(Store::open(d.path()).unwrap().locked());
        // A symlink in place of a document is refused, not followed.
        fs::remove_file(d.path().join("flags.json")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", d.path().join("flags.json")).unwrap();
        assert!(Store::open(d.path()).is_err());
    }
}
