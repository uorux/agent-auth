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

    /// After `grantee`'s last write grant on the tree ended: everything it
    /// still owns there becomes `owner`'s, as copies (files) or removed
    /// (anything else but directories); see [`fsops::reclaim_tree`].
    fn reclaim_tree(
        &self,
        tree: &Tree,
        grantee: u32,
        owner: u32,
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

    /// The cgroup freezer: every process of the unit stops where it is. A
    /// freeze is verified; a unit that cannot be frozen is stopped and the
    /// error says so (fail closed). A unit that is not running is fine.
    fn freeze_unit(
        &self,
        name: &str,
        frozen: bool,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Run a short command in a transient unit of its own (the spec's uid,
    /// directories and protections; `/tmp` is the spec's tmp) and wait for
    /// it: (exit code, stdout+stderr). The tmux client commands run this
    /// way, never as the project's uid outside a unit (where a process of
    /// the project could read their environment).
    fn run_in_unit(&self, spec: &UnitSpec) -> impl Future<Output = (i32, String)> + Send;
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

/// The PATH of the commands sandboxd runs itself (systemd-run, systemctl,
/// setfacl); configured commands are absolute store paths anyway.
pub const ROOT_PATH: &str = "/run/current-system/sw/bin:/usr/bin:/bin";

/// A command with nothing of sandboxd's environment: PATH and LANG only.
#[must_use]
pub fn clean_command(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear().env("PATH", ROOT_PATH).env("LANG", "C.UTF-8");
    c
}

/// The operator's interactive commands as the project's user (`attach`,
/// `shell`): on a fresh pty that `systemd-run --pty` (root) relays, so no
/// process of the project's uid ever holds an fd of the operator's root
/// tty (or can TIOCSTI into it after a detach); the unit is a session of
/// its own with an environment of TERM, LANG, PATH and HOME only.
#[must_use]
pub fn pty_command(
    systemd_run: &str,
    uid: u32,
    cwd: &str,
    term: Option<&str>,
    argv: &[String],
) -> Vec<String> {
    let mut out = vec![
        systemd_run.to_owned(),
        "--pty".to_owned(),
        "--quiet".to_owned(),
        "--collect".to_owned(),
        format!("--uid={uid}"),
        format!("--gid={uid}"),
        format!("--working-directory={cwd}"),
        format!("--setenv=PATH={ROOT_PATH}"),
        "--setenv=LANG=C.UTF-8".to_owned(),
        format!("--setenv=HOME={cwd}"),
    ];
    if let Some(t) = term.filter(|t| {
        t.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._+".contains(c))
    }) {
        out.push(format!("--setenv=TERM={t}"));
    }
    for p in [
        "NoNewPrivileges=yes",
        "ProtectProc=invisible",
        "KeyringMode=private",
        "RestrictSUIDSGID=yes",
    ] {
        out.push("-p".to_owned());
        out.push(p.to_owned());
    }
    out.push("--".to_owned());
    out.extend(argv.iter().map(|a| systemd_escape(a)));
    out
}

/// What `systemctl show -p FreezerState --value` says of a frozen unit.
#[must_use]
pub fn is_frozen(state: &str) -> bool {
    state.trim() == "frozen"
}

/// How many times a freeze is tried (and verified) before the unit is
/// stopped instead.
pub const FREEZE_TRIES: u32 = 3;

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

    /// Run a command of sandboxd's own (clean environment).
    pub async fn run(&self, argv: &[String]) -> (i32, String) {
        let Some((program, args)) = argv.split_first() else {
            return (-1, "no command".to_owned());
        };
        match clean_command(program)
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

    async fn reclaim_tree(&self, tree: &Tree, grantee: u32, owner: u32) -> Result<(), HostError> {
        self.tree_op(tree, move |d| {
            fsops::reclaim_tree(&d, grantee, fsops::Owner::project(owner))
        })
        .await
        .map(|_| ())
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
        let mut child = clean_command(program)
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

    async fn freeze_unit(&self, name: &str, frozen: bool) -> Result<(), HostError> {
        let unit = format!("{name}.service");
        let ctl = |verb: &str| [self.config.systemctl.clone(), verb.to_owned(), unit.clone()];
        if !frozen {
            let (code, out) = self.run(&ctl("thaw")).await;
            if code != 0 && self.unit_active(name).await {
                return Err(HostError(format!("thawing {unit}: {}", out.trim())));
            }
            return Ok(());
        }
        for _ in 0..FREEZE_TRIES {
            if !self.unit_active(name).await {
                return Ok(());
            }
            let _ = self.run(&ctl("freeze")).await;
            let show = [
                self.config.systemctl.clone(),
                "show".to_owned(),
                "-p".to_owned(),
                "FreezerState".to_owned(),
                "--value".to_owned(),
                unit.clone(),
            ];
            let (_, state) = self.run(&show).await;
            if is_frozen(&state) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        // Held means held: what cannot be frozen does not keep running.
        self.stop_unit(name).await;
        Err(HostError(format!(
            "{unit} could not be frozen; it was stopped instead"
        )))
    }

    async fn run_in_unit(&self, spec: &UnitSpec) -> (i32, String) {
        let env_file = match self.write_env_file(spec) {
            Ok(f) => f,
            Err(e) => return (-1, e.0),
        };
        let argv = self.unit_argv(spec, &env_file, true);
        let out = self.run(&argv).await;
        self.stop_unit(&spec.name).await;
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn script(dir: &Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    fn host_in(dir: &Path, tweak: impl FnOnce(&mut serde_json::Value)) -> LinuxHost {
        let mut v = serde_json::json!({"broker_url": "https://b.example",
            "broker_public_key": crate::config::tests::key(), "name": "excelsior",
            "runtime_dir": dir.join("run"), "state_dir": dir.join("state")});
        tweak(&mut v);
        LinuxHost::new(Arc::new(Config::from_json(&v.to_string()).unwrap()))
    }

    /// Review #5 item 1: nothing of sandboxd's environment reaches what it
    /// runs, and the tmux client runs in a unit of its own.
    #[tokio::test]
    async fn children_get_a_clean_environment_and_clients_a_unit() {
        let d = crate::testdir::TestDir::new("cleanenv");
        let out = d.path().join("seen");
        let run = script(
            d.path(),
            "systemd-run",
            &format!(
                "env > {0}.env; printf '%s\\n' \"$@\" > {0}.args\n",
                out.display()
            ),
        );
        let host = host_in(d.path(), |v| v["systemd_run"] = serde_json::json!(run));
        let mut env = BTreeMap::new();
        env.insert("PATH".to_owned(), "/x".to_owned());
        let spec = UnitSpec {
            name: "sbx-tmuxc-0123456789ab".into(),
            uid: 40001,
            argv: vec![
                "tmux".into(),
                "-S".into(),
                "/tmp/tmux-a.sock".into(),
                "has-session".into(),
            ],
            workdir: "/w".into(),
            home: "/h".into(),
            tmp: "/t".into(),
            env,
            read_write: vec![],
            description: "tmux client".into(),
        };
        let (code, _) = host.run_in_unit(&spec).await;
        assert_eq!(code, 0);
        let seen_env = std::fs::read_to_string(format!("{}.env", out.display())).unwrap();
        let mut keys: Vec<&str> = seen_env
            .lines()
            .filter_map(|l| l.split('=').next())
            .filter(|k| !matches!(*k, "PWD" | "SHLVL" | "_"))
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["LANG", "PATH"], "{seen_env}");
        let args = std::fs::read_to_string(format!("{}.args", out.display())).unwrap();
        for want in [
            "--uid=40001",
            "--pipe",
            "ProtectProc=invisible",
            "BindPaths=/t:/tmp",
            "has-session",
        ] {
            assert!(args.contains(want), "{want} in {args}");
        }
        // The env file is gone afterwards.
        assert!(!d.path().join("run/env/sbx-tmuxc-0123456789ab.env").exists());
    }

    /// Review #5 item 3: a freeze is verified; one that does not take is
    /// retried, then the unit is stopped and the error says so.
    #[tokio::test]
    async fn a_freeze_is_verified_and_an_unfreezable_unit_is_stopped() {
        let d = crate::testdir::TestDir::new("freeze");
        let state = d.path().join("state.txt");
        let calls = d.path().join("calls");
        let ctl = script(
            d.path(),
            "systemctl",
            &format!(
                "echo \"$@\" >> {calls}\ncase \"$1\" in show) cat {state};; esac\nexit 0\n",
                calls = calls.display(),
                state = state.display()
            ),
        );
        let host = host_in(d.path(), |v| v["systemctl"] = serde_json::json!(ctl));
        std::fs::write(&state, "frozen\n").unwrap();
        host.freeze_unit("sbx-conv-a", true).await.unwrap();
        std::fs::write(&state, "running\n").unwrap();
        std::fs::write(&calls, "").unwrap();
        let e = host.freeze_unit("sbx-conv-a", true).await.unwrap_err();
        assert!(e.0.contains("stopped instead"), "{e}");
        let log = std::fs::read_to_string(&calls).unwrap();
        assert_eq!(
            log.matches("freeze sbx-conv-a.service").count(),
            usize::try_from(FREEZE_TRIES).unwrap()
        );
        assert!(log.contains("stop sbx-conv-a.service"), "{log}");
        assert!(is_frozen("frozen\n") && !is_frozen("freezing"));
    }

    #[test]
    fn interactive_commands_get_a_pty_of_their_own() {
        let argv = pty_command(
            "/bin/systemd-run",
            40001,
            "/var/lib/sandbox/projects/p",
            Some("xterm-256color"),
            &["tmux".into(), "attach".into()],
        );
        assert_eq!(&argv[..2], ["/bin/systemd-run", "--pty"]);
        assert!(
            argv.contains(&"--uid=40001".to_owned()) && argv.contains(&"--gid=40001".to_owned())
        );
        assert!(argv.contains(&"--setenv=TERM=xterm-256color".to_owned()));
        assert!(!argv.iter().any(|a| a.contains("setpriv")));
        assert_eq!(&argv[argv.len() - 3..], ["--", "tmux", "attach"]);
        // A TERM that is not a plain name is not passed.
        let odd = pty_command("s", 1, "/", Some("x\ny"), &[]);
        assert!(!odd.iter().any(|a| a.starts_with("--setenv=TERM")));
    }

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
