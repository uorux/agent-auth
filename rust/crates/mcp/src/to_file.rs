//! `get_credential(to_file=True)`: a secret goes to a file only the user can
//! read, and the reply names the file instead of carrying the secret.
//!
//! The file is written without following links: an existing symbolic link
//! at its name is refused, the value goes to a new file (`O_CREAT|O_EXCL`,
//! mode 0600) next to it, which is then renamed over the name (a rename
//! replaces a link put there meanwhile, it does not follow it). The
//! directory is made 0700, an existing one is set to 0700, and it must be a
//! real directory owned by the user.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agent_auth_core::pyfmt::{repr, shlex_quote};
use agent_auth_wire::agent::{CredentialKind, CredentialOut};
use serde::Serialize;

/// Kinds whose `value` is not a secret, so it stays in the reply: a
/// created repo's URL, a group membership, a minted identity's name, a
/// shell's grant id, a job's summary, nothing at all. Every other kind,
/// including any added later, is a secret and goes to the file.
pub const NOT_SECRET_KINDS: &[CredentialKind] = &[
    CredentialKind::GithubRepo,
    CredentialKind::LldapGroup,
    CredentialKind::A2aGrant,
    CredentialKind::AgentIdentity,
    CredentialKind::ProjectAccess,
    CredentialKind::HostexecShell,
    CredentialKind::HostexecJob,
    CredentialKind::MailGateway,
];

/// Whether `kind`'s value is a secret (secret unless known otherwise).
#[must_use]
pub fn is_secret(kind: CredentialKind) -> bool {
    !NOT_SECRET_KINDS.contains(&kind)
}

/// `$XDG_RUNTIME_DIR/agent-auth/credentials`, else
/// `~/.cache/agent-auth/credentials`.
pub fn credential_dir() -> io::Result<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    let base = match var("XDG_RUNTIME_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => match var("HOME") {
            Some(home) => PathBuf::from(home).join(".cache"),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither XDG_RUNTIME_DIR nor HOME is set",
                ));
            }
        },
    };
    Ok(base.join("agent-auth").join("credentials"))
}

/// The reply when the value went to a file: the credential with `value`
/// null, then `file`, and for GitHub a credential helper that reads it.
#[derive(Debug, Serialize)]
pub struct InFile {
    #[serde(flatten)]
    pub credential: CredentialOut,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_helper: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_example: Option<String>,
}

/// What `get_credential` answers.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Delivered {
    /// Not a secret kind, or nothing to write: as the broker sent it.
    Inline(CredentialOut),
    InFile(InFile),
}

/// Put `credential`'s secret into `dir`/`<grant id>` when it is a secret
/// kind with a value; otherwise hand it back unchanged.
pub fn deliver(dir: &Path, grant_id: &str, mut credential: CredentialOut) -> io::Result<Delivered> {
    let secret = is_secret(credential.kind)
        && credential
            .value
            .as_ref()
            .is_some_and(|v| !v.expose().is_empty());
    if !secret {
        return Ok(Delivered::Inline(credential));
    }
    let Some(value) = credential.value.take() else {
        return Ok(Delivered::Inline(credential));
    };
    let path = write_secret(dir, grant_id, value.expose())?;
    let file = path.to_string_lossy().into_owned();
    let (git_helper, git_example) = if credential.kind == CredentialKind::GithubInstallationToken {
        let helper = git_helper(&file);
        let example = format!(
            "git -c credential.helper= -c credential.helper={} push https://github.com/<owner>/<repo>.git <branch>",
            repr(&helper)
        );
        (Some(helper), Some(example))
    } else {
        (None, None)
    };
    Ok(Delivered::InFile(InFile {
        credential,
        file,
        git_helper,
        git_example,
    }))
}

/// A git `credential.helper` that answers with the token in `path` (the
/// path shell-quoted; unchanged for an ordinary path, as the Python wrote it).
#[must_use]
pub fn git_helper(path: &str) -> String {
    format!(
        "!f() {{ echo username=x-access-token; echo \"password=$(cat {})\"; }}; f",
        shlex_quote(path)
    )
}

fn refuse(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what)
}

/// Write `value` to `dir`/`<grant id, alphanumerics and '-' only>`, mode
/// 0600, without following a link; the file's path.
pub fn write_secret(dir: &Path, grant_id: &str, value: &str) -> io::Result<PathBuf> {
    let name: String = grant_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a grant id: {grant_id:?}"),
        ));
    }
    write_private(dir, &name, value.as_bytes())
}

/// Write `value` to `dir`/`name` (a plain file name), mode 0600, in a
/// directory of the user's own made 0700, without following a link, through
/// a new temporary file renamed into place; the file's path.
pub fn write_private(dir: &Path, name: &str, value: &[u8]) -> io::Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a file name: {name:?}"),
        ));
    }
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let dir_meta = fs::symlink_metadata(dir)?;
    if !dir_meta.is_dir() {
        return Err(refuse(format!("{} is not a directory", dir.display())));
    }
    if dir_meta.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let path = dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(refuse(format!(
                "refusing to write {}: it is a symbolic link",
                path.display()
            )));
        }
        Ok(meta) if !meta.is_file() => {
            return Err(refuse(format!("{} is not a regular file", path.display())));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let (tmp, mut file) = temp_file(dir, name)?;
    let written = (|| {
        // The directory must be the user's own (compared with the file just
        // made, which is: there is no getuid without libc).
        if file.metadata()?.uid() != dir_meta.uid() {
            return Err(refuse(format!("{} belongs to another user", dir.display())));
        }
        file.write_all(value)?;
        file.sync_all()?;
        fs::rename(&tmp, &path)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(path)
}

/// A new file next to the target: `.<name>.<pid>.<n>.tmp`, created
/// exclusively with mode 0600.
fn temp_file(dir: &Path, name: &str) -> io::Result<(PathBuf, fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let mut last = None;
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        let tmp = dir.join(format!(".{name}.{pid}.{n}.{nanos}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no temporary file name")))
}

#[cfg(test)]
mod tests {
    use agent_auth_wire::secret::WireSecret;

    use super::*;

    /// Every kind there is (the match makes a new one a compile error here).
    fn all_kinds() -> Vec<CredentialKind> {
        use CredentialKind as K;
        let all = [
            K::GithubInstallationToken,
            K::GithubRepo,
            K::KubernetesToken,
            K::LldapAccount,
            K::LldapGroup,
            K::McpToken,
            K::ModelGatewayKey,
            K::A2aGrant,
            K::AgentIdentity,
            K::ProjectAccess,
            K::HostexecShell,
            K::HostexecJob,
            K::PoolItem,
            K::MailGateway,
        ];
        for k in all {
            match k {
                K::GithubInstallationToken
                | K::GithubRepo
                | K::KubernetesToken
                | K::LldapAccount
                | K::LldapGroup
                | K::McpToken
                | K::ModelGatewayKey
                | K::A2aGrant
                | K::AgentIdentity
                | K::ProjectAccess
                | K::HostexecShell
                | K::HostexecJob
                | K::PoolItem
                | K::MailGateway => {}
            }
        }
        all.to_vec()
    }

    #[test]
    fn every_kind_is_decided_and_secrets_go_to_the_file() {
        use CredentialKind as K;
        let dir = std::env::temp_dir().join(format!("agent-auth-kinds-{}", std::process::id()));
        let secrets = [
            K::GithubInstallationToken,
            K::KubernetesToken,
            K::LldapAccount,
            K::McpToken,
            K::ModelGatewayKey,
            K::PoolItem,
        ];
        for (i, kind) in all_kinds().into_iter().enumerate() {
            let credential = CredentialOut {
                kind,
                value: Some(WireSecret::new("the-value").unwrap()),
                username: None,
                url: None,
                expires_at: None,
                note: None,
                properties: None,
            };
            let grant = format!("g-{i}");
            let delivered = deliver(&dir, &grant, credential).unwrap();
            let text = serde_json::to_string(&delivered).unwrap();
            if secrets.contains(&kind) {
                assert!(is_secret(kind), "{kind:?}");
                assert!(matches!(delivered, Delivered::InFile(_)), "{kind:?}");
                assert!(!text.contains("the-value"), "{kind:?}: {text}");
                assert_eq!(
                    std::fs::read_to_string(dir.join(&grant)).unwrap(),
                    "the-value"
                );
            } else {
                assert!(!is_secret(kind), "{kind:?}");
                assert!(matches!(delivered, Delivered::Inline(_)), "{kind:?}");
                assert!(text.contains("the-value"), "{kind:?}");
                assert!(!dir.join(&grant).exists(), "{kind:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
