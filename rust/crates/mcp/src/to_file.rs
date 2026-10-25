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
    /// Kubernetes: `file` is a whole kubeconfig; how to use it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubectl_example: Option<String>,
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
    if credential.kind == CredentialKind::KubernetesToken
        && let Some(config) = kubeconfig(&credential)
    {
        credential.value = None;
        let path = write_private(
            dir,
            &format!("{}.kubeconfig", file_name(grant_id)?),
            config.as_bytes(),
        )?;
        let file = path.to_string_lossy().into_owned();
        return Ok(Delivered::InFile(InFile {
            credential,
            kubectl_example: Some(format!(
                "KUBECONFIG={} kubectl get pods",
                shlex_quote(&file)
            )),
            file,
            git_helper: None,
            git_example: None,
        }));
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
        kubectl_example: None,
    }))
}

/// A Kubernetes credential as a kubeconfig (JSON, which kubectl reads): a
/// cluster and context per API server (the preferred one current), the
/// cluster CA when the broker has one (never `insecure-skip-tls-verify`),
/// the grant's namespace, the token. `None` without a server or token (a
/// broker that sends neither: the token goes to a plain file).
#[must_use]
pub fn kubeconfig(credential: &CredentialOut) -> Option<String> {
    let token = credential.value.as_ref()?.expose();
    let props = credential.properties.as_ref();
    let mut servers: Vec<String> = props
        .and_then(|p| p.get("servers"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if servers.is_empty() {
        servers.extend(credential.url.clone());
    }
    if token.is_empty() || servers.is_empty() {
        return None;
    }
    let ca = props
        .and_then(|p| p.get("certificate_authority_data"))
        .and_then(serde_json::Value::as_str);
    let namespace = props
        .and_then(|p| p.get("namespace"))
        .and_then(serde_json::Value::as_str);
    let name = |i: usize| {
        if i == 0 {
            "agent-auth".to_owned()
        } else {
            format!("agent-auth-{}", i.saturating_add(1))
        }
    };
    let clusters: Vec<serde_json::Value> = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let mut cluster = serde_json::Map::new();
            cluster.insert("server".into(), server.as_str().into());
            if let Some(ca) = ca {
                cluster.insert("certificate-authority-data".into(), ca.into());
            }
            serde_json::json!({"name": name(i), "cluster": cluster})
        })
        .collect();
    let contexts: Vec<serde_json::Value> = (0..servers.len())
        .map(|i| {
            let mut context = serde_json::Map::new();
            context.insert("cluster".into(), name(i).into());
            context.insert("user".into(), "agent-auth".into());
            if let Some(ns) = namespace {
                context.insert("namespace".into(), ns.into());
            }
            serde_json::json!({"name": name(i), "context": context})
        })
        .collect();
    let config = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": clusters,
        "contexts": contexts,
        "current-context": "agent-auth",
        "users": [{"name": "agent-auth", "user": {"token": token}}],
        "preferences": {},
    });
    serde_json::to_string_pretty(&config).ok()
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
    write_private(dir, &file_name(grant_id)?, value.as_bytes())
}

/// A grant id as a file name: alphanumerics and '-' only.
fn file_name(grant_id: &str) -> io::Result<String> {
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
    Ok(name)
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
            K::GoogleAccessToken,
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
                | K::GoogleAccessToken
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

    fn k8s(properties: serde_json::Value) -> CredentialOut {
        CredentialOut {
            kind: CredentialKind::KubernetesToken,
            value: Some(WireSecret::new("k8s-token").unwrap()),
            username: None,
            url: Some("https://100.126.30.73:6443".to_owned()),
            expires_at: None,
            note: Some("bearer token".to_owned()),
            properties: properties.as_object().cloned(),
        }
    }

    /// to_file for Kubernetes: a whole kubeconfig, 0600, the token in it
    /// and nowhere in the reply; the CA when the broker has one.
    #[test]
    fn kubernetes_goes_to_a_kubeconfig() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("agent-auth-kube-{}", std::process::id()));
        let credential = k8s(serde_json::json!({
            "server": "https://100.126.30.73:6443",
            "servers": ["https://100.126.30.73:6443", "https://100.126.30.74:6443"],
            "namespace": "apps-a",
            "tls": "ca",
            "certificate_authority_pem": "PEM",
            "certificate_authority_data": "UEVN",
        }));
        let delivered = deliver(&dir, "g-1", credential).unwrap();
        let reply = serde_json::to_value(&delivered).unwrap();
        assert!(!reply.to_string().contains("k8s-token"), "{reply}");
        assert_eq!(reply["value"], serde_json::Value::Null);
        let file = reply["file"].as_str().unwrap();
        assert!(file.ends_with("/g-1.kubeconfig"), "{file}");
        assert_eq!(
            reply["kubectl_example"],
            format!("KUBECONFIG={file} kubectl get pods")
        );
        assert_eq!(reply["properties"]["certificate_authority_pem"], "PEM");
        let meta = std::fs::metadata(file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let text = std::fs::read_to_string(file).unwrap();
        let config: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(config["current-context"], "agent-auth");
        assert_eq!(config["users"][0]["user"]["token"], "k8s-token");
        assert_eq!(
            config["clusters"],
            serde_json::json!([
                {"name": "agent-auth", "cluster": {"server": "https://100.126.30.73:6443", "certificate-authority-data": "UEVN"}},
                {"name": "agent-auth-2", "cluster": {"server": "https://100.126.30.74:6443", "certificate-authority-data": "UEVN"}},
            ])
        );
        assert_eq!(
            config["contexts"][0],
            serde_json::json!({"name": "agent-auth", "context": {"cluster": "agent-auth", "user": "agent-auth", "namespace": "apps-a"}})
        );
        assert!(!text.contains("insecure"));
        // kubectl reads it, where kubectl is installed.
        if let Ok(out) = std::process::Command::new("kubectl")
            .args(["config", "view", "--raw", "-o", "json"])
            .env("KUBECONFIG", file)
            .output()
        {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let seen: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(
                seen["clusters"][0]["cluster"]["server"],
                "https://100.126.30.73:6443"
            );
            assert_eq!(seen["users"][0]["user"]["token"], "k8s-token");
            assert_eq!(
                seen["clusters"][0]["cluster"]["certificate-authority-data"],
                "UEVN"
            );
        }

        // No CA (an insecure broker): none in the file, and no skipping
        // verification either. Cluster-wide: no namespace.
        let credential = k8s(serde_json::json!({
            "servers": ["https://h:6443"], "namespace": null, "tls": "insecure",
        }));
        let Delivered::InFile(f) = deliver(&dir, "g-2", credential).unwrap() else {
            panic!("a file")
        };
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&f.file).unwrap()).unwrap();
        assert_eq!(
            config["clusters"][0]["cluster"],
            serde_json::json!({"server": "https://h:6443"})
        );
        assert!(config["contexts"][0]["context"].get("namespace").is_none());
        // An older broker (no server at all): the token in a plain file.
        let mut old = k8s(serde_json::json!({}));
        old.url = None;
        old.properties = None;
        let Delivered::InFile(f) = deliver(&dir, "g-3", old).unwrap() else {
            panic!("a file")
        };
        assert!(f.kubectl_example.is_none());
        assert_eq!(std::fs::read_to_string(&f.file).unwrap(), "k8s-token");
        let _ = std::fs::remove_dir_all(&dir);
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
            K::GoogleAccessToken,
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
