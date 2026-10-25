//! What sandboxd does to the VM's system: users, directories, ACLs and
//! ownership, units (sandboxd spec §4.6, §4.8). Behind a trait so the
//! daemon's logic runs in tests without root or systemd
//! (`crate::testing::FakeHost`).
//!
//! Every agent process runs in a transient unit: its own uid, the system
//! read-only, other projects' files unreadable (plain permissions, so ACL
//! grants take effect live), no view of other processes, and its secrets
//! in a root-only EnvironmentFile, never on the `systemd-run` command line
//! (where `systemctl show` hands them to any user).

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::fsops::{self, AclChange, Dir};

/// A failure the daemon reports (`RuntimeError` in the Python).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct HostError(pub String);

impl From<std::io::Error> for HostError {
    fn from(e: std::io::Error) -> Self {
        HostError(e.to_string())
    }
}

/// One unit to start.
#[derive(Clone)]
pub struct UnitSpec {
    /// Without `.service`.
    pub name: String,
    pub uid: u32,
    pub argv: Vec<String>,
    pub workdir: PathBuf,
    pub home: PathBuf,
    /// The host path bound to `/tmp` in the unit.
    pub tmp: PathBuf,
    /// Into the root-only env file (secrets included).
    pub env: BTreeMap<String, String>,
    pub read_write: Vec<PathBuf>,
    pub description: String,
}

impl fmt::Debug for UnitSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnitSpec")
            .field("name", &self.name)
            .field("uid", &self.uid)
            .field("workdir", &self.workdir)
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// How a started process ends: its exit code (None: killed by a signal or
/// unknown), and a way to kill it.
#[derive(Debug, Clone)]
pub struct ProcExit {
    done: watch::Receiver<Option<Option<i32>>>,
    kill: mpsc::UnboundedSender<()>,
}

impl ProcExit {
    /// A pair: the handle, and the side that reports the end and hears kills.
    #[must_use]
    pub fn channel() -> (ProcExit, ProcExitReporter) {
        let (done_tx, done_rx) = watch::channel(None);
        let (kill_tx, kill_rx) = mpsc::unbounded_channel();
        (
            ProcExit {
                done: done_rx,
                kill: kill_tx,
            },
            ProcExitReporter {
                done: done_tx,
                kill: kill_rx,
            },
        )
    }

    /// Wait for the end.
    pub async fn wait(&self) -> Option<i32> {
        let mut rx = self.done.clone();
        loop {
            if let Some(code) = *rx.borrow_and_update() {
                return code;
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }

    /// It ended (or whatever reported on it is gone).
    #[must_use]
    pub fn exited(&self) -> bool {
        self.done.borrow().is_some() || self.done.has_changed().is_err()
    }

    pub fn kill(&self) {
        let _ = self.kill.send(());
    }
}

/// The process side of a [`ProcExit`].
#[derive(Debug)]
pub struct ProcExitReporter {
    done: watch::Sender<Option<Option<i32>>>,
    kill: mpsc::UnboundedReceiver<()>,
}

impl ProcExitReporter {
    /// A kill was asked for (or every handle is gone).
    pub async fn killed(&mut self) {
        let _ = self.kill.recv().await;
    }

    pub fn exited(self, code: Option<i32>) {
        let _ = self.done.send(Some(code));
    }
}

/// A process with its stdin and stdout piped (`systemd-run --pipe --wait`).
pub struct Piped {
    pub stdin: Pin<Box<dyn AsyncWrite + Send>>,
    pub stdout: Pin<Box<dyn AsyncRead + Send>>,
    pub exit: ProcExit,
}

impl fmt::Debug for Piped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Piped").finish_non_exhaustive()
    }
}

/// A project tree: `<root>/<names…>`, opened without following anything
/// below `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub root: PathBuf,
    pub names: Vec<String>,
}

impl Tree {
    #[must_use]
    pub fn new(root: &Path, names: &[&str]) -> Tree {
        Tree {
            root: root.to_owned(),
            names: names.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[must_use]
    pub fn path(&self) -> PathBuf {
        let mut p = self.root.clone();
        for n in &self.names {
            p.push(n);
        }
        p
    }

    pub fn open(&self) -> std::io::Result<Dir> {
        let names: Vec<&str> = self.names.iter().map(String::as_str).collect();
        Dir::open_beneath(&self.root, &names)
    }
}

/// What the daemon needs from the machine.
pub trait Host: Send + Sync + 'static {
    /// A locked userdb user and group (`gid = uid`).
    fn ensure_user(&self, name: &str, uid: u32, home: &Path) -> Result<(), HostError>;

    /// Each directory exists, owned `uid:uid`, mode 0700 (its parent is a
    /// root-owned root).
    fn make_dirs(&self, uid: u32, dirs: &[Tree]) -> Result<(), HostError>;

    /// `uid` gets `rX` (`rwX` with `write`) on the tree, now and for what
    /// is created later; only entries owned by `owner`.
    fn grant_acl(
        &self,
        tree: &Tree,
        uid: u32,
        write: bool,
        owner: u32,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Every ACL entry of `uid` in the tree goes.
    fn revoke_acl(
        &self,
        tree: &Tree,
        uid: u32,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Entries owned by one of `from` become `uid:uid`.
    fn chown_tree(
        &self,
        tree: &Tree,
        uid: u32,
        from: &[u32],
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Whether files written for a uid get that owner (false in tests,
    /// which can't).
    fn can_chown(&self) -> bool;

    fn start_piped(&self, spec: &UnitSpec)
    -> impl Future<Output = Result<Piped, HostError>> + Send;

    fn start_detached(&self, spec: &UnitSpec)
    -> impl Future<Output = Result<(), HostError>> + Send;

    /// Stop the unit (whatever state it is in) and drop its env file.
    fn stop_unit(&self, name: &str) -> impl Future<Output = ()> + Send;

    fn unit_active(&self, name: &str) -> impl Future<Output = bool> + Send;

    /// The cgroup freezer: every process of the unit stops where it is.
    fn freeze_unit(&self, name: &str, frozen: bool) -> impl Future<Output = ()> + Send;

    /// Run `argv` as `uid` outside any unit: (exit code, stdout+stderr).
    fn run_as(&self, uid: u32, argv: &[String]) -> impl Future<Output = (i32, String)> + Send;
}

/// The env file's line for one variable: `KEY="value"` with systemd's
/// double-quote escapes for `\`, `"`, `` ` `` and `$` (the Python's
/// `shlex.quote` single quotes were not systemd's syntax for values with a
/// `'`). A newline or NUL is refused.
pub fn env_line(key: &str, value: &str) -> Result<String, HostError> {
    let key_ok = !key.is_empty()
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !key.starts_with(|c: char| c.is_ascii_digit());
    if !key_ok {
        return Err(HostError(format!(
            "invalid environment variable name {key:?}"
        )));
    }
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(HostError(format!(
            "environment value for {key} contains a newline"
        )));
    }
    let mut out = String::with_capacity(value.len().saturating_add(key.len()).saturating_add(4));
    out.push_str(key);
    out.push_str("=\"");
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '`' | '$') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

/// An argument as systemd's ExecStart= takes it literally: `$` as `$$`
/// (systemd expands `$VAR` in a transient unit's command).
#[must_use]
pub fn systemd_escape(arg: &str) -> String {
    arg.replace('$', "$$")
}

/// The real thing: systemd-userdb records, systemd-run units.
#[derive(Debug, Clone)]
pub struct LinuxHost {
    config: Arc<Config>,
}

impl LinuxHost {
    #[must_use]
    pub fn new(config: Arc<Config>) -> LinuxHost {
        LinuxHost { config }
    }

    fn env_dir(&self) -> PathBuf {
        self.config.runtime_dir.join("env")
    }

    fn write_env_file(&self, spec: &UnitSpec) -> Result<PathBuf, HostError> {
        let dir = self.env_dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        let mut text = String::new();
        for (k, v) in &spec.env {
            text.push_str(&env_line(k, v)?);
            text.push('\n');
        }
        let path = dir.join(format!("{}.env", spec.name));
        crate::store::write_atomic(&path, text.as_bytes())?;
        Ok(path)
    }

    /// `systemd-run … -- argv` (spec §4.8, exactly, plus `$` escaping).
    pub fn unit_argv(&self, spec: &UnitSpec, env_file: &Path, piped: bool) -> Vec<String> {
        let c = &self.config;
        let mut props = vec![
            format!(
                "Description={}",
                if spec.description.is_empty() {
                    &spec.name
                } else {
                    &spec.description
                }
            ),
            format!("WorkingDirectory={}", spec.workdir.display()),
            format!("EnvironmentFile={}", env_file.display()),
            "ProtectSystem=strict".to_owned(),
            "ProtectHome=yes".to_owned(),
            "PrivateDevices=yes".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            "ProtectProc=invisible".to_owned(),
            "ProtectKernelTunables=yes".to_owned(),
            "ProtectKernelModules=yes".to_owned(),
            "ProtectKernelLogs=yes".to_owned(),
            "ProtectControlGroups=yes".to_owned(),
            "ProtectClock=yes".to_owned(),
            "ProtectHostname=yes".to_owned(),
            "RestrictSUIDSGID=yes".to_owned(),
            "LockPersonality=yes".to_owned(),
            "RestrictRealtime=yes".to_owned(),
            "KeyringMode=private".to_owned(),
            "UMask=0077".to_owned(),
            format!("InaccessiblePaths={}", c.runtime_dir.display()),
            "InaccessiblePaths=-/run/systemd/transient".to_owned(),
            format!("InaccessiblePaths={}", c.state_dir.display()),
            format!(
                "ReadWritePaths={}",
                c.sandbox_root.join("projects").display()
            ),
            format!("ReadWritePaths={}", spec.home.display()),
            format!("BindPaths={}:/tmp", spec.tmp.display()),
            format!("MemoryMax={}", c.unit_memory_max),
            format!("TasksMax={}", c.unit_tasks_max),
            "KillMode=control-group".to_owned(),
        ];
        props.extend(
            spec.read_write
                .iter()
                .map(|p| format!("ReadWritePaths={}", p.display())),
        );
        let mut argv = vec![
            c.systemd_run.clone(),
            format!("--unit={}", spec.name),
            format!("--uid={}", spec.uid),
            format!("--gid={}", spec.uid),
            "--quiet".to_owned(),
            "--collect".to_owned(),
        ];
        if piped {
            argv.push("--pipe".to_owned());
            argv.push("--wait".to_owned());
        }
        for p in props {
            argv.push("-p".to_owned());
            argv.push(p);
        }
        argv.push("--".to_owned());
        argv.extend(spec.argv.iter().map(|a| systemd_escape(a)));
        argv
    }

    async fn run(&self, argv: &[String]) -> (i32, String) {
        let Some((program, args)) = argv.split_first() else {
            return (-1, "no command".to_owned());
        };
        match Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
        {
            Ok(out) => {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                (out.status.code().unwrap_or(-1), text)
            }
            Err(e) => (-1, e.to_string()),
        }
    }

    async fn check(&self, argv: &[String]) -> Result<String, HostError> {
        let (code, out) = self.run(argv).await;
        if code == 0 {
            Ok(out)
        } else {
            Err(HostError(format!(
                "{} failed ({code}): {}",
                argv.first().map_or("", String::as_str),
                out.trim().chars().take(300).collect::<String>()
            )))
        }
    }

    async fn tree_op<T: Send + 'static>(
        &self,
        tree: &Tree,
        op: impl FnOnce(Dir) -> std::io::Result<T> + Send + 'static,
    ) -> Result<T, HostError> {
        let tree = tree.clone();
        tokio::task::spawn_blocking(move || {
            let dir = tree.open()?;
            op(dir)
        })
        .await
        .map_err(|e| HostError(e.to_string()))?
        .map_err(HostError::from)
    }
}

use std::os::unix::fs::DirBuilderExt as _;

impl Host for LinuxHost {
    fn ensure_user(&self, name: &str, uid: u32, home: &Path) -> Result<(), HostError> {
        let d = &self.config.userdb_dir;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(d)?;
        let user = serde_json::json!({
            "userName": name,
            "uid": uid,
            "gid": uid,
            "realName": format!("agent sandbox user {name}"),
            "homeDirectory": home.display().to_string(),
            "shell": "/run/current-system/sw/bin/bash",
            "disposition": "regular",
            "locked": true,
        });
        let group = serde_json::json!({"groupName": name, "gid": uid});
        let dir = Dir::open_trusted(d)?;
        for (file, data) in [
            (format!("{name}.user"), user),
            (format!("{name}.group"), group),
        ] {
            let text =
                serde_json::to_string_pretty(&data).map_err(|e| HostError(e.to_string()))? + "\n";
            dir.write_file(&file, text.as_bytes(), None, 0o644)?;
        }
        for (alias, target) in [
            (format!("{uid}.user"), format!("{name}.user")),
            (format!("{uid}.group"), format!("{name}.group")),
        ] {
            let link = d.join(&alias);
            if std::fs::symlink_metadata(&link).is_err() {
                std::os::unix::fs::symlink(&target, &link)?;
            }
        }
        Ok(())
    }

    fn make_dirs(&self, uid: u32, dirs: &[Tree]) -> Result<(), HostError> {
        for t in dirs {
            let Some((last, parents)) = t.names.split_last() else {
                return Err(HostError("not a directory below a root".to_owned()));
            };
            let names: Vec<&str> = parents.iter().map(String::as_str).collect();
            let parent = Dir::open_beneath(&t.root, &names)?;
            let dir = parent.ensure_child(last, 0o700)?;
            dir.set_owner_mode(Some(uid), 0o700)?;
        }
        Ok(())
    }

    async fn grant_acl(
        &self,
        tree: &Tree,
        uid: u32,
        write: bool,
        owner: u32,
    ) -> Result<(), HostError> {
        let setfacl = self.config.setfacl.clone();
        self.tree_op(tree, move |d| {
            fsops::acl_tree(&d, &setfacl, AclChange::Grant { uid, write }, owner)
        })
        .await
        .map(|_| ())
    }

    async fn revoke_acl(&self, tree: &Tree, uid: u32) -> Result<(), HostError> {
        let setfacl = self.config.setfacl.clone();
        self.tree_op(tree, move |d| {
            fsops::acl_tree(&d, &setfacl, AclChange::Revoke { uid }, uid)
        })
        .await
        .map(|_| ())
    }

    async fn chown_tree(&self, tree: &Tree, uid: u32, from: &[u32]) -> Result<(), HostError> {
        let from = from.to_vec();
        let report = self
            .tree_op(tree, move |d| fsops::chown_tree(&d, uid, &from))
            .await?;
        if report.skipped > 0 {
            tracing::warn!(
                tree = %tree.path().display(),
                skipped = report.skipped,
                "chown: entries owned by someone unexpected, hard-linked, or symlinks were left as they are"
            );
        }
        Ok(())
    }

    fn can_chown(&self) -> bool {
        true
    }

    async fn start_piped(&self, spec: &UnitSpec) -> Result<Piped, HostError> {
        let env_file = self.write_env_file(spec)?;
        let argv = self.unit_argv(spec, &env_file, true);
        let Some((program, args)) = argv.split_first() else {
            return Err(HostError("no command".to_owned()));
        };
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| HostError("no stdin".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| HostError("no stdout".to_owned()))?;
        let (exit, mut reporter) = ProcExit::channel();
        tokio::spawn(async move {
            let code = tokio::select! {
                status = child.wait() => status.ok().and_then(|s| s.code()),
                () = reporter.killed() => {
                    let _ = child.start_kill();
                    child.wait().await.ok().and_then(|s| s.code())
                }
            };
            reporter.exited(code);
        });
        Ok(Piped {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            exit,
        })
    }

    async fn start_detached(&self, spec: &UnitSpec) -> Result<(), HostError> {
        let env_file = self.write_env_file(spec)?;
        let argv = self.unit_argv(spec, &env_file, false);
        self.check(&argv).await.map(|_| ())
    }

    async fn stop_unit(&self, name: &str) {
        let argv = [
            self.config.systemctl.clone(),
            "stop".to_owned(),
            format!("{name}.service"),
        ];
        let _ = self.run(&argv).await;
        if let Ok(dir) = Dir::open_trusted(&self.env_dir()) {
            let _ = dir.remove(&format!("{name}.env"));
        }
    }

    async fn unit_active(&self, name: &str) -> bool {
        let argv = [
            self.config.systemctl.clone(),
            "is-active".to_owned(),
            "--quiet".to_owned(),
            format!("{name}.service"),
        ];
        self.run(&argv).await.0 == 0
    }

    async fn freeze_unit(&self, name: &str, frozen: bool) {
        let argv = [
            self.config.systemctl.clone(),
            if frozen { "freeze" } else { "thaw" }.to_owned(),
            format!("{name}.service"),
        ];
        let (code, out) = self.run(&argv).await;
        if code != 0 {
            tracing::warn!(unit = name, frozen, "systemctl: {}", out.trim());
        }
    }

    async fn run_as(&self, uid: u32, argv: &[String]) -> (i32, String) {
        let mut full = vec![
            self.config.setpriv.clone(),
            format!("--reuid={uid}"),
            format!("--regid={uid}"),
            "--clear-groups".to_owned(),
            "--".to_owned(),
        ];
        full.extend(argv.iter().cloned());
        self.run(&full).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn env_lines_are_systemd_quoted() {
        assert_eq!(env_line("A", "plain").unwrap(), "A=\"plain\"");
        assert_eq!(
            env_line("A", r#"it's "q" $HOME `x` \n"#).unwrap(),
            r#"A="it's \"q\" \$HOME \`x\` \\n""#
        );
        assert!(env_line("A", "two\nlines").is_err());
        assert!(env_line("A", "nul\0").is_err());
        assert!(env_line("1A", "x").is_err());
        assert!(env_line("A=B", "x").is_err());
    }

    #[test]
    fn unit_argv_keeps_secrets_out_and_escapes_dollars() {
        let cfg = Config::from_json(
            &serde_json::json!({"broker_url": "https://b.example",
                "broker_public_key": crate::config::tests::key(),
                "name": "excelsior"})
            .to_string(),
        )
        .unwrap();
        let host = LinuxHost::new(Arc::new(cfg));
        let mut env = BTreeMap::new();
        env.insert("AGENT_AUTH_API_KEY".to_owned(), "aa_secret".to_owned());
        let spec = UnitSpec {
            name: "sbx-conv-0123456789ab".into(),
            uid: 40001,
            argv: vec!["claude".into(), "say $HOME".into()],
            workdir: "/var/lib/sandbox/projects/p".into(),
            home: "/var/lib/sandbox/homes/p".into(),
            tmp: "/var/lib/sandbox/tmp/p".into(),
            env,
            read_write: vec![],
            description: "d".into(),
        };
        let argv = host.unit_argv(&spec, Path::new("/run/sandboxd/env/x.env"), true);
        let joined = argv.join(" ");
        assert!(!joined.contains("aa_secret"));
        assert!(joined.contains("InaccessiblePaths=/run/sandboxd"));
        assert!(joined.contains("InaccessiblePaths=/var/lib/sandboxd"));
        assert!(joined.contains("InaccessiblePaths=-/run/systemd/transient"));
        assert!(joined.contains("ProtectProc=invisible"));
        assert!(joined.contains("BindPaths=/var/lib/sandbox/tmp/p:/tmp"));
        assert_eq!(argv.last().unwrap(), "say $$HOME");
        assert_eq!(
            &argv[..4],
            [
                "systemd-run",
                "--unit=sbx-conv-0123456789ab",
                "--uid=40001",
                "--gid=40001"
            ]
        );
        assert!(argv.contains(&"--pipe".to_owned()) && argv.contains(&"--wait".to_owned()));
    }
}
