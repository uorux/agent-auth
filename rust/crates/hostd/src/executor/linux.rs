//! Linux: every job is a transient system unit started by PID 1, never a
//! child of hostd, so it inherits none of hostd's sandbox, environment or
//! descriptors, and a runaway one is killed as a whole cgroup (§11.1).
//!
//! ```text
//! systemd-run [-p User=<user>] --unit=aa-job-<id> --collect --quiet --pipe --wait
//!   -p RuntimeMaxSec=<timeout> -p KillMode=control-group
//!   -p "Description=agent-auth job <id>" --working-directory=<dir>
//!   --setenv=PATH=<path> --setenv=K=V ... -- argv...
//! ```
//!
//! The job units are named after the job, so after a crash hostd finds
//! them again ([`Executor::running_jobs`]) and lockdown can stop them
//! (daemons bug 4).
//!
//! Integration-tested on real hosts (it needs PID 1 and root); the command
//! line, the verbs and the parsers are unit-tested here.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use agent_auth_core::Tier;
use agent_auth_core::hostd::output::OutputTail;
use agent_auth_core::hostd::{AdmittedJob, LocalId, PolkitConfirmed};

use super::passwd::{self, Passwd};
use super::{
    Collect, Executor, UNIT_PREFIX, UnitAction, collect, exit_code, spawn_piped, unit_name,
};

/// Installed by the NixOS module (auth_admin for the active local session).
pub const POLKIT_ACTION: &str = "dev.agent-auth.hostd.run-as-root";
/// Beyond the job's own RuntimeMaxSec, how long hostd waits before stopping
/// the unit itself.
pub const DEADLINE_SLACK: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct LinuxConfig {
    pub systemd_run: String,
    pub systemctl: String,
    pub pkcheck: String,
    pub job_path: String,
    /// The account the user tier runs as.
    pub user: Option<String>,
}

/// The parts of a job the command line is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobParts {
    pub id: LocalId,
    pub tier: Tier,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub timeout_secs: u32,
}

impl JobParts {
    #[must_use]
    pub fn of(job: &AdmittedJob) -> JobParts {
        JobParts {
            id: job.id().clone(),
            tier: job.tier(),
            argv: job.argv().to_vec(),
            cwd: job.cwd().map(str::to_owned),
            env: job.env().clone(),
            timeout_secs: job.timeout_secs(),
        }
    }
}

/// What to start: the program, its arguments, and the environment of the
/// `systemd-run` process itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl LinuxConfig {
    fn path(&self, tier: Tier) -> String {
        match (tier, &self.user) {
            (Tier::User, Some(user)) => {
                format!("{}:/etc/profiles/per-user/{user}/bin", self.job_path)
            }
            _ => self.job_path.clone(),
        }
    }

    /// The `systemd-run` command for a job. `user` is the configured
    /// account (needed for the user tier).
    pub fn command(&self, job: &JobParts, user: Option<&Passwd>) -> Result<SystemdCommand, String> {
        let path = self.path(job.tier);
        let mut args: Vec<String> = Vec::new();
        // The job's environment, on top of the tier's base.
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        let cwd = match job.tier {
            Tier::User => {
                let pw = user.ok_or_else(|| "no user configured for the user tier".to_owned())?;
                args.push("-p".into());
                args.push(format!("User={}", pw.name));
                let runtime = format!("/run/user/{}", pw.uid);
                env.insert("HOME".into(), pw.home.clone());
                env.insert("USER".into(), pw.name.clone());
                env.insert("LOGNAME".into(), pw.name.clone());
                env.insert("SHELL".into(), pw.shell.clone());
                env.insert(
                    "DBUS_SESSION_BUS_ADDRESS".into(),
                    format!("unix:path={runtime}/bus"),
                );
                env.insert("XDG_RUNTIME_DIR".into(), runtime);
                job.cwd.clone().unwrap_or_else(|| pw.home.clone())
            }
            Tier::Root => {
                // Daemons bug 21: root jobs had no HOME/USER on Linux.
                env.insert("HOME".into(), "/root".into());
                env.insert("USER".into(), "root".into());
                env.insert("LOGNAME".into(), "root".into());
                job.cwd.clone().unwrap_or_else(|| "/".to_owned())
            }
        };
        for (k, v) in &job.env {
            env.insert(k.clone(), v.clone());
        }
        let unit = unit_name(&job.id);
        args.extend([
            format!("--unit={unit}"),
            "--collect".into(),
            "--quiet".into(),
            "--pipe".into(),
            "--wait".into(),
            "-p".into(),
            format!("RuntimeMaxSec={}", job.timeout_secs),
            "-p".into(),
            "KillMode=control-group".into(),
            "-p".into(),
            format!("Description=agent-auth job {}", job.id),
            format!("--working-directory={cwd}"),
            format!("--setenv=PATH={path}"),
        ]);
        for (k, v) in &env {
            args.push(format!("--setenv={k}={v}"));
        }
        args.push("--".into());
        args.extend(job.argv.iter().cloned());
        Ok(SystemdCommand {
            program: self.systemd_run.clone(),
            args,
            env: vec![("PATH".into(), path), ("LANG".into(), "C.UTF-8".into())],
        })
    }
}

/// The start time field of `/proc/<pid>/stat` (the 20th after the `)`
/// closing the command name), which pins the process for polkit.
#[must_use]
pub fn proc_start_time(stat: &str) -> Option<String> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19).map(str::to_owned)
}

/// Job ids of active `aa-job-*` units in `systemctl list-units --plain
/// --no-legend --all` output.
#[must_use]
pub fn parse_job_units(text: &str) -> Vec<LocalId> {
    text.lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let unit = cols.next()?;
            let _load = cols.next()?;
            let active = cols.next()?;
            if !matches!(
                active,
                "active" | "activating" | "deactivating" | "reloading"
            ) {
                return None;
            }
            let id = unit.strip_prefix(UNIT_PREFIX)?.strip_suffix(".service")?;
            LocalId::parse(id).ok()
        })
        .collect()
}

#[derive(Debug)]
pub struct SystemdExecutor {
    cfg: LinuxConfig,
}

impl SystemdExecutor {
    #[must_use]
    pub fn new(cfg: LinuxConfig) -> SystemdExecutor {
        SystemdExecutor { cfg }
    }

    /// `systemctl <args>` with PATH = the job path: (exit code, output).
    pub async fn systemctl(&self, args: &[&str]) -> Result<(i32, String), String> {
        let out = tokio::process::Command::new(&self.cfg.systemctl)
            .args(args)
            .env_clear()
            .env("PATH", &self.cfg.job_path)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| e.to_string())?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((exit_code(out.status), text.trim().to_owned()))
    }
}

impl Executor for SystemdExecutor {
    async fn run(&self, job: &AdmittedJob, out: &mut OutputTail) -> Result<i32, String> {
        let user = match (job.tier(), &self.cfg.user) {
            (Tier::User, Some(name)) => Some(passwd::lookup(name).await?),
            _ => None,
        };
        let parts = JobParts::of(job);
        let c = self.cfg.command(&parts, user.as_ref())?;
        let mut cmd = std::process::Command::new(&c.program);
        cmd.args(&c.args)
            .env_clear()
            .envs(c.env.iter().map(|(k, v)| (k, v)));
        let (mut child, rx) = spawn_piped(cmd, job.stdin().is_some()).map_err(|e| e.to_string())?;
        let deadline = super::after(
            Duration::from_secs(u64::from(parts.timeout_secs)).saturating_add(DEADLINE_SLACK),
        );
        let unit = format!("{}.service", unit_name(&parts.id));
        let status = collect(
            &mut child,
            rx,
            job.stdin(),
            out,
            Collect {
                deadline: Some(deadline),
                stop_at_exit: false,
            },
            async || {
                let _ = self.systemctl(&["stop", &unit]).await;
            },
            async || {},
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(exit_code(status))
    }

    async fn kill(&self, job: &LocalId) {
        let unit = format!("{}.service", unit_name(job));
        if let Err(e) = self.systemctl(&["stop", &unit]).await {
            tracing::warn!(job = %job, error = %e, "could not stop the job's unit");
        }
    }

    async fn polkit_auth(
        &self,
        pid: i32,
        uid: u32,
        message: &str,
        timeout: Duration,
    ) -> Option<PolkitConfirmed> {
        let stat = tokio::fs::read_to_string(format!("/proc/{pid}/stat"))
            .await
            .ok()?;
        let start = proc_start_time(&stat)?;
        let mut child = tokio::process::Command::new(&self.cfg.pkcheck)
            .args([
                "--action-id",
                POLKIT_ACTION,
                "--process",
                &format!("{pid},{start},{uid}"),
                "--allow-user-interaction",
                "--detail",
                "polkit.message",
                message,
            ])
            .env_clear()
            .env("PATH", &self.cfg.job_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(s)) if s.success() => Some(PolkitConfirmed::after_successful_pkcheck()),
            _ => None,
        }
    }

    async fn unit_action(&self, action: UnitAction, unit: &str) -> Result<(i32, String), String> {
        if unit.starts_with('-') {
            return Err("not a unit".to_owned());
        }
        self.systemctl(&[action.as_str(), unit]).await
    }

    async fn running_jobs(&self) -> Vec<LocalId> {
        let pattern = format!("{UNIT_PREFIX}*");
        match self
            .systemctl(&[
                "list-units",
                "--plain",
                "--no-legend",
                "--all",
                "--type=service",
                &pattern,
            ])
            .await
        {
            Ok((0, text)) => parse_job_units(&text),
            Ok((code, text)) => {
                tracing::warn!(code, "systemctl list-units failed: {text}");
                Vec::new()
            }
            Err(e) => {
                tracing::warn!("systemctl list-units failed: {e}");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LinuxConfig {
        LinuxConfig {
            systemd_run: "/nix/store/s/bin/systemd-run".into(),
            systemctl: "/nix/store/s/bin/systemctl".into(),
            pkcheck: "pkcheck".into(),
            job_path: "/run/wrappers/bin:/run/current-system/sw/bin".into(),
            user: Some("jrt".into()),
        }
    }

    fn parts(tier: Tier, cwd: Option<&str>) -> JobParts {
        JobParts {
            id: LocalId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
            tier,
            argv: vec![
                "systemctl".into(),
                "--user".into(),
                "status".into(),
                "a b".into(),
            ],
            cwd: cwd.map(str::to_owned),
            env: [("LANG".to_owned(), "C".to_owned())].into(),
            timeout_secs: 60,
        }
    }

    fn jrt() -> Passwd {
        Passwd {
            name: "jrt".into(),
            uid: 1000,
            gid: 100,
            home: "/home/jrt".into(),
            shell: "/bin/zsh".into(),
        }
    }

    #[test]
    fn linux_executor_user_tier_command() {
        let c = cfg()
            .command(&parts(Tier::User, None), Some(&jrt()))
            .unwrap();
        assert_eq!(c.program, "/nix/store/s/bin/systemd-run");
        let a: Vec<&str> = c.args.iter().map(String::as_str).collect();
        assert_eq!(&a[..2], ["-p", "User=jrt"]);
        assert!(a.contains(&"--unit=aa-job-01234567-89ab-cdef-0123-456789abcdef"));
        assert!(a.contains(&"--working-directory=/home/jrt"));
        assert!(a.contains(&"RuntimeMaxSec=60"));
        assert!(a.contains(&"KillMode=control-group"));
        assert!(a.contains(
            &"--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin:/etc/profiles/per-user/jrt/bin"
        ));
        assert!(a.contains(&"--setenv=XDG_RUNTIME_DIR=/run/user/1000"));
        assert!(a.contains(&"--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"));
        assert!(a.contains(&"--setenv=LANG=C"));
        let dash = a.iter().position(|x| *x == "--").unwrap();
        assert_eq!(&a[dash + 1..], ["systemctl", "--user", "status", "a b"]);
        assert_eq!(
            c.env,
            vec![
                (
                    "PATH".to_owned(),
                    "/run/wrappers/bin:/run/current-system/sw/bin:/etc/profiles/per-user/jrt/bin"
                        .to_owned()
                ),
                ("LANG".to_owned(), "C.UTF-8".to_owned())
            ]
        );
        assert_eq!(
            cfg().command(&parts(Tier::User, None), None).unwrap_err(),
            "no user configured for the user tier"
        );
    }

    #[test]
    fn linux_executor_root_tier_command() {
        let c = cfg()
            .command(&parts(Tier::Root, Some("/srv")), None)
            .unwrap();
        let a: Vec<&str> = c.args.iter().map(String::as_str).collect();
        assert!(!a.iter().any(|x| x.starts_with("User=")));
        assert!(a.contains(&"--working-directory=/srv"));
        assert!(a.contains(&"--setenv=HOME=/root"));
        assert!(a.contains(&"--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin"));
        let c = cfg().command(&parts(Tier::Root, None), None).unwrap();
        assert!(c.args.contains(&"--working-directory=/".to_owned()));
    }

    #[test]
    fn parsers() {
        let stat = "1234 (my (odd) prog) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 200";
        assert_eq!(proc_start_time(stat).as_deref(), Some("987654"));
        let units = "aa-job-0123abcd-0000.service loaded active running agent-auth job x\n\
                     aa-job-ffffffff-1111.service loaded inactive dead agent-auth job y\n\
                     aa-job-..%2f.service loaded active running z\n";
        assert_eq!(
            parse_job_units(units),
            vec![LocalId::parse("0123abcd-0000").unwrap()]
        );
    }
}
