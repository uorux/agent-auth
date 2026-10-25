//! Projects (sandboxd spec §4.6): a directory, a home and a tmp per
//! project, each its own unix user's; the orchestrator's setup access
//! until the project is sealed; cross-project grants as ACLs; and the
//! shared codex login.

use std::sync::Arc;

use agent_auth_core::pyfmt::repr;
use agent_auth_core::sandbox::ProjectName;

use super::{Sandboxd, SbxError, SbxResult, locked};
use crate::fsops::Dir;
use crate::host::{Host, Tree};
use crate::store::{AddProject, GrantRecord};

/// The largest codex login read (it is a small JSON document).
pub const MAX_CODEX_AUTH: u64 = 1024 * 1024;

impl<H: Host> Sandboxd<H> {
    /// A new project: its user (the lowest free uid above the
    /// orchestrator's) and its directories.
    pub fn create_project(&self, name: &str) -> SbxResult<serde_json::Value> {
        let project = ProjectName::parse(name).map_err(|e| SbxError::Value(e.0))?;
        let rec = match self.store.add_project(
            project.as_str(),
            self.config.uid_base,
            self.config.uid_max,
        )? {
            Ok(r) => r,
            Err(AddProject::Exists) => {
                return Err(SbxError::Value(format!("project {} exists", repr(name))));
            }
            Err(AddProject::NoUid) => {
                return Err(SbxError::Runtime("no free uids for projects".to_owned()));
            }
        };
        let (work, home, tmp) = self.trees(Some(project.as_str()));
        let made = self
            .host
            .ensure_user(
                &agent_auth_core::sandbox::project_user(&project),
                rec.uid,
                &home.path(),
            )
            .and_then(|()| self.host.make_dirs(rec.uid, &[work.clone(), home, tmp]));
        if let Err(e) = made {
            let _ = self.store.remove_project(project.as_str());
            return Err(e.into());
        }
        Ok(serde_json::json!({
            "project": project.as_str(),
            "path": work.path().display().to_string(),
            "uid": rec.uid,
        }))
    }

    /// The orchestrator may write the project until it is sealed.
    pub async fn open_project_for_setup(&self, name: &str) -> SbxResult<()> {
        let open = self.store.project(name).is_some_and(|p| !p.sealed);
        if !open {
            return Err(SbxError::Value(format!(
                "project {} is not open for setup",
                repr(name)
            )));
        }
        let uid = self.project_uid(Some(name))?;
        let (work, _, _) = self.trees(Some(name));
        self.host
            .grant_acl(&work, self.config.uid_base, true, uid)
            .await?;
        Ok(())
    }

    /// Hand the project to its own user: the orchestrator's ACL goes, and
    /// what the orchestrator made there becomes the project's (INV-23).
    pub async fn seal_project(&self, name: &str) -> SbxResult<()> {
        let Some(proj) = self.store.project(name) else {
            return Err(SbxError::Lookup(format!("no project {}", repr(name))));
        };
        if proj.sealed {
            return Ok(());
        }
        let (work, _, _) = self.trees(Some(name));
        self.host.revoke_acl(&work, self.config.uid_base).await?;
        self.host
            .chown_tree(&work, proj.uid, &[self.config.uid_base])
            .await?;
        self.store.seal_project(name)?;
        Ok(())
    }

    fn grant_lock(&self, project: &str, target: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = locked(&self.grant_locks);
        Arc::clone(
            locks
                .entry((project.to_owned(), target.to_owned()))
                .or_default(),
        )
    }

    /// A `sandbox` grant from the broker: `project`'s user gets `rX` (or
    /// `rwX`) on `target`'s tree (INV-22). Recorded first, so a revoke
    /// that comes after a failure (or after the broker gave up waiting)
    /// still cleans up; undone if applying it fails.
    pub async fn apply_project_grant(
        &self,
        grant_id: &str,
        project: &str,
        target: &str,
        access: &str,
    ) -> SbxResult<()> {
        let write = match access {
            "project.read" => false,
            "project.write" => true,
            other => return Err(SbxError::Value(format!("unknown access {}", repr(other)))),
        };
        let uid = self.project_uid(Some(project))?;
        let owner = self.project_uid(Some(target))?;
        let lock = self.grant_lock(project, target);
        let _g = lock.lock().await;
        self.store.add_project_grant(GrantRecord {
            grant_id: grant_id.to_owned(),
            project: project.to_owned(),
            target: target.to_owned(),
            access: access.to_owned(),
        })?;
        // Another grant of the pair may already give write access: a read
        // grant must not take it away (the Python's setfacl did).
        let write = write
            || self
                .store
                .project_grants(project, target)
                .iter()
                .any(|o| o.access == "project.write");
        let (work, _, _) = self.trees(Some(target));
        if let Err(e) = self.host.grant_acl(&work, uid, write, owner).await {
            let _ = self.store.pop_project_grant(grant_id);
            if let Err(undo) = self.regrant(&work, project, target, uid).await {
                tracing::error!("undoing a failed grant on {target}: {undo}");
            }
            return Err(e.into());
        }
        Ok(())
    }

    /// Remove one; an unknown id is already gone (idempotent). Access still
    /// justified by another grant of the same pair is restored; when the
    /// last write grant goes, what the grantee created in the target is
    /// handed back to the target's user (owner rights outlive an ACL).
    pub async fn remove_project_grant(&self, grant_id: &str) -> SbxResult<()> {
        let Some(grant) = self.store.pop_project_grant(grant_id)? else {
            return Ok(());
        };
        let lock = self.grant_lock(&grant.project, &grant.target);
        let _g = lock.lock().await;
        let uid = self.project_uid(Some(&grant.project))?;
        let (work, _, _) = self.trees(Some(&grant.target));
        self.regrant(&work, &grant.project, &grant.target, uid)
            .await?;
        let others = self.store.project_grants(&grant.project, &grant.target);
        if grant.access == "project.write" && !others.iter().any(|o| o.access == "project.write") {
            let owner = self.project_uid(Some(&grant.target))?;
            self.host.chown_tree(&work, owner, &[uid]).await?;
        }
        Ok(())
    }

    /// `uid`'s entries go, then come back as far as the remaining grants
    /// of the pair justify.
    async fn regrant(&self, work: &Tree, project: &str, target: &str, uid: u32) -> SbxResult<()> {
        self.host.revoke_acl(work, uid).await?;
        let owner = self.project_uid(Some(target))?;
        let others = self.store.project_grants(project, target);
        if let Some(write) = others
            .iter()
            .map(|o| o.access == "project.write")
            .reduce(|a, b| a || b)
        {
            self.host.grant_acl(work, uid, write, owner).await?;
        }
        Ok(())
    }

    // ------------------------------------------------------- codex login

    fn shared_codex_auth(&self) -> Option<Vec<u8>> {
        let dir = Dir::open_trusted(&self.config.secrets_dir()).ok()?;
        dir.read_file("codex-auth.json", MAX_CODEX_AUTH)
            .ok()
            .flatten()
            .map(|(b, _)| b)
    }

    fn is_codex_owner(&self, project: Option<&str>) -> bool {
        match (&self.config.codex_auth_owner, project) {
            (Some(owner), Some(p)) => owner.as_str() == p,
            _ => false,
        }
    }

    /// Before a codex process without the gateway: the shared login into
    /// the project's `~/.codex/auth.json`, reached without following
    /// anything the project controls (B-11). Every project but the
    /// designated owner gets the shared copy (its own changes are never
    /// read back); the owner keeps its own unless the operator replaced
    /// the shared login since the last sync. Nothing trusts the project's
    /// mtimes.
    pub async fn codex_sync_into(&self, project: Option<&str>, uid: u32) {
        let Some(shared) = self.shared_codex_auth() else {
            return;
        };
        let digest = agent_auth_crypto::digest::sha256_hex(&shared);
        let owner = self.is_codex_owner(project);
        let (_, home, _) = self.trees(project);
        let chown = self.host.can_chown().then_some(uid);
        let synced = (|| -> std::io::Result<bool> {
            let home_dir = home.open()?;
            let codex = home_dir.ensure_child(".codex", 0o700)?;
            codex.set_owner_mode(chown, 0o700)?;
            let local = codex.read_file("auth.json", MAX_CODEX_AUTH);
            let local = match local {
                Ok(l) => l.map(|(b, _)| b),
                // A FIFO, a symlink, a directory: replaced.
                Err(_) => None,
            };
            let install = match (&local, owner) {
                (None, _) => true,
                (Some(l), false) => *l != shared,
                (Some(l), true) => {
                    *l != shared
                        && self.store.codex_auth_digest().as_deref() != Some(digest.as_str())
                }
            };
            if install {
                codex.write_file("auth.json", &shared, chown, 0o600)?;
            }
            Ok(install)
        })();
        match synced {
            Ok(_) => {
                if owner {
                    let _ = self.store.set_codex_auth_digest(Some(digest));
                }
            }
            Err(e) => tracing::warn!("codex auth sync: {e}"),
        }
        // Also what an earlier version left there as root.
        if self.host.can_chown() {
            let mut names: Vec<&str> = home.names.iter().map(String::as_str).collect();
            names.push(".codex");
            let tree = Tree::new(&home.root, &names);
            if let Err(e) = self.host.chown_tree(&tree, uid, &[0]).await {
                tracing::warn!("codex auth sync: {e}");
            }
        }
    }

    /// After a codex process parked: only the designated owner project's
    /// login (a refreshed token) goes back to the shared one.
    pub async fn codex_sync_back(&self, project: Option<&str>, uid: u32) {
        if !self.is_codex_owner(project) {
            return;
        }
        let (_, home, _) = self.trees(project);
        let read = (|| -> std::io::Result<Option<Vec<u8>>> {
            let codex = home.open()?.child(".codex")?;
            let Some((bytes, meta)) = codex.read_file("auth.json", MAX_CODEX_AUTH)? else {
                return Ok(None);
            };
            use std::os::unix::fs::MetadataExt as _;
            if self.host.can_chown() && meta.uid() != uid {
                return Ok(None);
            }
            Ok(Some(bytes))
        })();
        let local = match read {
            Ok(Some(l)) => l,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!("codex auth sync: {e}");
                return;
            }
        };
        if serde_json::from_slice::<serde_json::Value>(&local).is_err() {
            tracing::warn!("codex auth sync: the owner's auth.json is not JSON; not copied back");
            return;
        }
        if self.shared_codex_auth().as_deref() == Some(local.as_slice()) {
            return;
        }
        let path = self.config.secrets_dir().join("codex-auth.json");
        match crate::store::write_atomic(&path, &local) {
            Ok(()) => {
                let _ = self
                    .store
                    .set_codex_auth_digest(Some(agent_auth_crypto::digest::sha256_hex(&local)));
            }
            Err(e) => tracing::warn!("codex auth sync: {e}"),
        }
    }
}
