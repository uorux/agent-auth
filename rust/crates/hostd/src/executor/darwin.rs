//! macOS (docs/hostd-macos.md, spec §11.2): jobs are hostd's children, each
//! in a new process group, with their own working directory and
//! environment, and no inherited descriptors.
//!
//! - Root tier: refused when any existing directory on the job PATH is not
//!   root-owned or is writable by group or others (whoever could write
//!   there would choose what a root job runs).
//! - User tier: `launchctl asuser <uid> <this binary> asuser <json>` moves
//!   the process into the user's launchd domain (still root: only root may
//!   `asuser`), and the `asuser` step ([`run_asuser`]) then becomes the user
//!   for good and execs the job. launchctl gets none of the job's
//!   environment.
//! - A timeout or a kill signals the whole process group; when the job's
//!   main process ends, the rest of its group is killed too.
//!
//! Known gap (as in the Python): a process that leaves its group (setsid,
//! a double fork, a launchd service) escapes timeouts, kills and lockdown.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::Tier;
use agent_auth_core::hostd::output::OutputTail;
use agent_auth_core::hostd::{AdmittedJob, LocalId, PolkitConfirmed};
use serde::{Deserialize, Serialize};

use super::linux::JobParts;
use super::passwd::{self, Passwd};
use super::{
    Collect, Executor, KillSignal, UnitAction, collect, exit_code, kill_group, signal_group,
    spawn_piped,
};

/// Homebrew, for the user tier only (its directories are the user's).
pub const USER_EXTRA_PATH: &str = "/opt/homebrew/bin:/usr/local/bin";
pub const LAUNCHCTL: &str = "/bin/launchctl";
pub const KILL: &str = "/bin/kill";

/// What the `asuser` step runs: one JSON argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsUserSpec {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub argv: Vec<String>,
}

/// What to start, where, with which environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DarwinCommand {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct DarwinExecutor {
    pub job_path: String,
    pub user: Option<String>,
    /// This binary (the `asuser` step).
    pub self_exe: PathBuf,
    groups: Groups,
}

/// A directory on the root tier's PATH that someone other than root could
/// write to (or that cannot be checked). Missing directories are skipped;
/// symlinks are followed.
#[must_use]
pub fn root_path_problem(job_path: &str) -> Option<String> {
    for dir in job_path.split(':').filter(|d| !d.is_empty()) {
        match std::fs::metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Some(format!("{dir}: {e}")),
            Ok(m) => {
                if m.uid() != 0 || m.mode() & 0o022 != 0 {
                    return Some(format!(
                        "{dir} on the root tier's PATH is writable by others than root (owner uid {})",
                        m.uid()
                    ));
                }
            }
        }
    }
    None
}

impl DarwinExecutor {
    #[must_use]
    pub fn new(job_path: String, user: Option<String>, self_exe: PathBuf) -> DarwinExecutor {
        DarwinExecutor {
            job_path,
            user,
            self_exe,
            groups: Groups::new(KILL),
        }
    }

    fn path(&self, tier: Tier) -> String {
        match (tier, &self.user) {
            (Tier::User, Some(u)) => {
                format!(
                    "{}:/etc/profiles/per-user/{u}/bin:{USER_EXTRA_PATH}",
                    self.job_path
                )
            }
            _ => self.job_path.clone(),
        }
    }

    /// The command for a job (`user`: the configured account, for the
    /// user tier).
    pub fn command(&self, job: &JobParts, user: Option<&Passwd>) -> Result<DarwinCommand, String> {
        let mut base: BTreeMap<String, String> = BTreeMap::new();
        base.insert("PATH".into(), self.path(job.tier));
        base.insert("LANG".into(), "C.UTF-8".into());
        if job.tier == Tier::Root {
            base.insert("HOME".into(), "/var/root".into());
            base.insert("USER".into(), "root".into());
            base.insert("LOGNAME".into(), "root".into());
            base.extend(job.env.clone());
            let (program, args) = job
                .argv
                .split_first()
                .ok_or_else(|| "empty argv".to_owned())?;
            return Ok(DarwinCommand {
                program: program.clone(),
                args: args.to_vec(),
                cwd: job.cwd.clone().unwrap_or_else(|| "/".to_owned()),
                env: base,
            });
        }
        let pw = user.ok_or_else(|| "no user configured for the user tier".to_owned())?;
        base.insert("HOME".into(), pw.home.clone());
        base.insert("USER".into(), pw.name.clone());
        base.insert("LOGNAME".into(), pw.name.clone());
        base.insert("SHELL".into(), pw.shell.clone());
        base.extend(job.env.clone());
        let spec = AsUserSpec {
            user: pw.name.clone(),
            uid: pw.uid,
            gid: pw.gid,
            cwd: job.cwd.clone().unwrap_or_else(|| pw.home.clone()),
            env: base,
            argv: job.argv.clone(),
        };
        let json = serde_json::to_string(&spec).map_err(|e| e.to_string())?;
        let launch_env: BTreeMap<String, String> = [
            (
                "PATH".to_owned(),
                "/usr/bin:/bin:/usr/sbin:/sbin".to_owned(),
            ),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ]
        .into();
        Ok(DarwinCommand {
            program: LAUNCHCTL.to_owned(),
            args: vec![
                "asuser".into(),
                pw.uid.to_string(),
                self.self_exe.to_string_lossy().into_owned(),
                "asuser".into(),
                json,
            ],
            // launchctl itself starts in "/" as root; asuser changes directory.
            cwd: "/".into(),
            env: launch_env,
        })
    }
}

/// Running jobs' process groups, and the `kill(1)` that signals them.
#[derive(Debug)]
pub(crate) struct Groups {
    pub(crate) kill: String,
    pub(crate) map: Mutex<BTreeMap<LocalId, u32>>,
}

impl Groups {
    pub(crate) fn new(kill: &str) -> Groups {
        Groups {
            kill: kill.to_owned(),
            map: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn get(&self, id: &LocalId) -> Option<u32> {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .copied()
    }

    /// TERM, then KILL, the job's group.
    pub(crate) async fn kill(&self, id: &LocalId) {
        if let Some(pgid) = self.get(id) {
            kill_group(&self.kill, pgid).await;
        }
    }
}

/// Start `c` in a process group of its own and collect its output; the
/// group dies with the main process (and at the timeout). Shared with the
/// direct executor.
pub(crate) async fn run_in_group(
    groups: &Groups,
    id: &LocalId,
    c: DarwinCommand,
    stdin: Option<&str>,
    timeout: Duration,
    out: &mut OutputTail,
    stop: KillSignal,
) -> Result<i32, String> {
    if *stop.borrow() {
        return Err("killed before it started".to_owned());
    }
    let mut cmd = std::process::Command::new(&c.program);
    cmd.args(&c.args)
        .env_clear()
        .envs(&c.env)
        .current_dir(&c.cwd)
        .process_group(0);
    let (mut child, rx) = spawn_piped(cmd, stdin.is_some()).map_err(|e| e.to_string())?;
    let pgid = child
        .id()
        .ok_or_else(|| "the job exited at once".to_owned())?;
    let kill = groups.kill.as_str();
    groups
        .map
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id.clone(), pgid);
    let result = collect(
        &mut child,
        rx,
        stdin,
        out,
        Collect {
            deadline: Some(super::after(timeout)),
            kill: stop,
            stop_at_exit: true,
            restop: None,
        },
        move || kill_group(kill, pgid),
        // The main process is done: so is the rest of its group.
        async || {
            signal_group(kill, pgid, "KILL").await;
        },
    )
    .await;
    groups
        .map
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(id);
    result.map(exit_code).map_err(|e| e.to_string())
}

impl Executor for DarwinExecutor {
    async fn run(
        &self,
        job: &AdmittedJob,
        out: &mut OutputTail,
        kill: KillSignal,
    ) -> Result<i32, String> {
        if job.tier() == Tier::Root
            && let Some(problem) = root_path_problem(&self.job_path)
        {
            return Err(format!("not running a root job: {problem}"));
        }
        let user = match (job.tier(), &self.user) {
            (Tier::User, Some(name)) => Some(passwd::lookup(name).await?),
            _ => None,
        };
        let parts = JobParts::of(job);
        let c = self.command(&parts, user.as_ref())?;
        run_in_group(
            &self.groups,
            job.id(),
            c,
            job.stdin(),
            Duration::from_secs(u64::from(job.timeout_secs())),
            out,
            kill,
        )
        .await
    }

    async fn kill(&self, job: &LocalId) {
        self.groups.kill(job).await;
    }

    async fn polkit_auth(
        &self,
        _: super::Process,
        _: u32,
        _: &str,
        _: Duration,
    ) -> Option<PolkitConfirmed> {
        // No polkit: approving root commands at the desk is refused by the
        // config on macOS, and this never says yes.
        None
    }

    async fn unit_action(&self, _: UnitAction, _: &str) -> Result<(i32, String), String> {
        Err("there are no systemd units on macOS".to_owned())
    }

    async fn running_jobs(&self) -> Vec<LocalId> {
        Vec::new()
    }
}

/// The `asuser` step (root, inside the user's launchd domain): become the
/// user for good and exec the job. Never runs a job as root. Returns only
/// on failure (the process then exits with 127, as the Python did).
///
/// `setgid`, `setgroups([])` and `setuid` are done by the standard library
/// between fork and exec (`CommandExt::uid`/`gid`); as root, `setuid` sets
/// the real, effective and saved uid, so root cannot be regained (the
/// Python checked this after the fact; without libc there is no `setuid(0)`
/// to try, see DEVIATIONS.md). Supplementary groups are dropped, not
/// initialized from the user's (no `initgroups` without libc).
pub fn run_asuser(json: &str) -> String {
    let spec: AsUserSpec = match serde_json::from_str(json) {
        Ok(s) => s,
        Err(e) => return format!("asuser: bad spec: {e}"),
    };
    if spec.uid == 0 || spec.gid == 0 {
        return "asuser: refusing to run a user-tier job as root".to_owned();
    }
    let Some((program, args)) = spec.argv.split_first() else {
        return "asuser: empty argv".to_owned();
    };
    let err = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(&spec.env)
        .current_dir(&spec.cwd)
        .gid(spec.gid)
        .uid(spec.uid)
        .exec();
    format!("asuser: {program}: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(tier: Tier) -> JobParts {
        JobParts {
            id: LocalId::parse("0123abcd-0000").unwrap(),
            tier,
            argv: vec!["xcodebuild".into(), "-version".into()],
            cwd: None,
            env: [("LANG".to_owned(), "en_US.UTF-8".to_owned())].into(),
            timeout_secs: 60,
        }
    }

    fn exec() -> DarwinExecutor {
        DarwinExecutor::new(
            "/run/current-system/sw/bin:/usr/bin:/bin".into(),
            Some("jrt".into()),
            PathBuf::from("/opt/agent-auth/bin/agent-auth-hostd"),
        )
    }

    #[test]
    fn user_tier_goes_through_launchctl_asuser() {
        let pw = Passwd {
            name: "jrt".into(),
            uid: 501,
            gid: 20,
            home: "/Users/jrt".into(),
            shell: "/bin/zsh".into(),
        };
        let c = exec().command(&parts(Tier::User), Some(&pw)).unwrap();
        assert_eq!(c.program, "/bin/launchctl");
        assert_eq!(
            &c.args[..4],
            [
                "asuser",
                "501",
                "/opt/agent-auth/bin/agent-auth-hostd",
                "asuser"
            ]
        );
        assert_eq!(c.cwd, "/");
        // launchctl gets none of the job's environment.
        assert_eq!(c.env.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(c.env.len(), 2);
        let spec: AsUserSpec = serde_json::from_str(&c.args[4]).unwrap();
        assert_eq!(spec.cwd, "/Users/jrt");
        assert_eq!(spec.env["LANG"], "en_US.UTF-8");
        assert_eq!(spec.env["HOME"], "/Users/jrt");
        assert_eq!(
            spec.env["PATH"],
            "/run/current-system/sw/bin:/usr/bin:/bin:/etc/profiles/per-user/jrt/bin:/opt/homebrew/bin:/usr/local/bin"
        );
        assert_eq!(spec.argv, ["xcodebuild", "-version"]);
    }

    #[test]
    fn root_tier_runs_with_its_own_environment() {
        let c = exec().command(&parts(Tier::Root), None).unwrap();
        assert_eq!(c.program, "xcodebuild");
        assert_eq!(c.cwd, "/");
        assert_eq!(c.env["HOME"], "/var/root");
        assert_eq!(c.env["LANG"], "en_US.UTF-8");
        // Homebrew only on the user tier's PATH.
        assert!(!c.env["PATH"].contains("homebrew"));
    }

    #[test]
    fn root_jobs_refuse_a_path_others_can_write() {
        let d = crate::fsutil::testdir::TestDir::new("rootpath");
        let dir = d.path().join("bin");
        std::fs::create_dir(&dir).unwrap();
        // Owned by the test user (not root): refused.
        let path = format!("/nonexistent-dir:{}", dir.display());
        let problem = root_path_problem(&path).unwrap();
        assert!(
            problem.contains("writable by others than root"),
            "{problem}"
        );
        // Missing directories are skipped.
        assert_eq!(root_path_problem("/nonexistent-a:/nonexistent-b"), None);
    }

    #[test]
    fn asuser_never_runs_as_root() {
        let spec = AsUserSpec {
            user: "root".into(),
            uid: 0,
            gid: 0,
            cwd: "/".into(),
            env: BTreeMap::new(),
            argv: vec!["id".into()],
        };
        let msg = run_asuser(&serde_json::to_string(&spec).unwrap());
        assert_eq!(msg, "asuser: refusing to run a user-tier job as root");
        assert!(run_asuser("{").starts_with("asuser: bad spec"));
    }
}
