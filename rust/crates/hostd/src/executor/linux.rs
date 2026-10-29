//! Linux: every job is a transient system unit started by PID 1, never a
//! child of hostd, so it inherits none of hostd's sandbox, environment or
//! descriptors, and a runaway one is killed as a whole cgroup (§11.1).
//!
//! ```text
//! systemd-run [-p User=<user>] --unit=aa-job-<id> --collect --quiet --pipe --wait
//!   -p RuntimeMaxSec=<timeout> -p KillMode=control-group
//!   -p "Description=agent-auth job <id>" --working-directory=<dir>
//!   -p EnvironmentFile=<runtime_dir>/env/aa-job-<id>.env -- argv...
//! ```
//!
//! The job's environment (PATH included) is in a root-only file written
//! before and removed after, never on the `systemd-run` command line, where
//! `/proc/<pid>/cmdline` shows it to every user (security review 2026-10).
//!
//! ```text
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
    Collect, Executor, KillSignal, UNIT_PREFIX, UnitAction, collect, exit_code, spawn_piped,
    unit_name,
};

/// Installed by the NixOS module (auth_admin for the active local session).
pub const POLKIT_ACTION: &str = "dev.agent-auth.hostd.run-as-root";
/// Beyond the job's own RuntimeMaxSec, how long hostd waits before stopping
/// the unit itself.
pub const DEADLINE_SLACK: Duration = Duration::from_secs(120);
/// After a kill, `systemctl stop` again this often until `systemd-run`
/// exits.
pub const RESTOP: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct LinuxConfig {
    pub systemd_run: String,
    pub systemctl: String,
    pub pkcheck: String,
    pub job_path: String,
    /// The account the user tier runs as.
    pub user: Option<String>,
    /// Where the jobs' environment files go (`{runtime_dir}/env`, 0700).
    pub env_dir: std::path::PathBuf,
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
    /// The job's environment file and what goes in it.
    pub env_file: std::path::PathBuf,
    pub env_text: String,
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
        ]);
        env.insert("PATH".into(), path.clone());
        let mut env_text = String::new();
        for (k, v) in &env {
            env_text.push_str(&env_line(k, v)?);
            env_text.push('\n');
        }
        let env_file = self.env_dir.join(format!("{unit}.env"));
        args.push("-p".into());
        args.push(format!("EnvironmentFile={}", env_file.display()));
        args.push("--".into());
        // The service manager expands `$VAR`/`${VAR}` in a transient unit's
        // command as in ExecStart=, so what ran would differ from the argv
        // that was approved and matched: every `$` goes as `$$` (review
        // 2026-10; `--expand-environment=no` needs systemd 254).
        args.extend(job.argv.iter().map(|a| systemd_escape(a)));
        Ok(SystemdCommand {
            program: self.systemd_run.clone(),
            args,
            env: vec![("PATH".into(), path), ("LANG".into(), "C.UTF-8".into())],
            env_file,
            env_text,
        })
    }
}

/// An environment file's line: `KEY="value"` with systemd's double-quote
/// escapes for `\`, `"`, `` ` `` and `$`. A line break or NUL is refused.
pub fn env_line(key: &str, value: &str) -> Result<String, String> {
    let key_ok = !key.is_empty()
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !key.starts_with(|c: char| c.is_ascii_digit());
    if !key_ok {
        return Err(format!("invalid environment variable name {key:?}"));
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err(format!("environment value for {key} contains a line break"));
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

/// Write a job's environment file (its directory 0700, the file 0600).
fn write_env_file(c: &SystemdCommand) -> Result<(), String> {
    let dir = c
        .env_file
        .parent()
        .ok_or_else(|| "no directory for the environment file".to_owned())?;
    crate::fsutil::private_dir(dir, 0o700)
        .and_then(|()| {
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        })
        .and_then(|()| crate::fsutil::write_atomic(&c.env_file, c.env_text.as_bytes(), 0o600))
        .map_err(|e| format!("the job's environment file: {e}"))
}

/// Removes a file when dropped.
struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// An argument as systemd's ExecStart= takes it literally: `$` as `$$`.
#[must_use]
pub fn systemd_escape(arg: &str) -> String {
    arg.replace('$', "$$")
}

/// What systemd makes of a command argument (its documented ExecStart=
/// rules for `$`): `$$` is a `$`; any other `$` starts a variable
/// reference. `None` when something would be expanded.
#[must_use]
pub fn systemd_literal(arg: &str) -> Option<String> {
    let mut out = String::with_capacity(arg.len());
    let mut chars = arg.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'$') {
                chars.next();
                out.push('$');
            } else {
                return None;
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
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
    async fn run(
        &self,
        job: &AdmittedJob,
        out: &mut OutputTail,
        kill: KillSignal,
    ) -> Result<i32, String> {
        if *kill.borrow() {
            return Err("killed before it started".to_owned());
        }
        let user = match (job.tier(), &self.cfg.user) {
            (Tier::User, Some(name)) => Some(passwd::lookup(name).await?),
            _ => None,
        };
        let parts = JobParts::of(job);
        let c = self.cfg.command(&parts, user.as_ref())?;
        write_env_file(&c)?;
        // Gone again however the run ends.
        let _remove = RemoveOnDrop(c.env_file.clone());
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
                kill,
                // Once systemd-run is gone the unit is (its whole cgroup was
                // stopped): what still holds the output pipe is outside it
                // (handed to the user manager, say) and doesn't keep the
                // job open past the drain (review 2026-10, finding 5).
                stop_at_exit: true,
                // A stop before the unit exists stops nothing: again until
                // systemd-run ends (finding 2).
                restop: Some(RESTOP),
            },
            || {
                let unit = unit.as_str();
                async move {
                    let _ = self.systemctl(&["stop", unit]).await;
                }
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
        process: super::Process,
        uid: u32,
        message: &str,
        timeout: Duration,
    ) -> Option<PolkitConfirmed> {
        // The start time from when the helper connected: polkit then refuses
        // if that process is gone, whoever has its pid now.
        let pid = process.pid;
        let start = process.start_time?;
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
            env_dir: "/run/agent-auth-hostd/env".into(),
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
        // The environment is in the file, not on the command line.
        assert!(!a.iter().any(|x| x.starts_with("--setenv")));
        assert!(a.contains(
            &"EnvironmentFile=/run/agent-auth-hostd/env/aa-job-01234567-89ab-cdef-0123-456789abcdef.env"
        ));
        let lines: Vec<&str> = c.env_text.lines().collect();
        assert!(lines.contains(
            &"PATH=\"/run/wrappers/bin:/run/current-system/sw/bin:/etc/profiles/per-user/jrt/bin\""
        ));
        assert!(lines.contains(&"XDG_RUNTIME_DIR=\"/run/user/1000\""));
        assert!(lines.contains(&"DBUS_SESSION_BUS_ADDRESS=\"unix:path=/run/user/1000/bus\""));
        assert!(lines.contains(&"LANG=\"C\""));
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
        assert!(c.env_text.lines().any(|l| l == "HOME=\"/root\""));
        assert!(
            c.env_text
                .lines()
                .any(|l| l == "PATH=\"/run/wrappers/bin:/run/current-system/sw/bin\"")
        );
        let c = cfg().command(&parts(Tier::Root, None), None).unwrap();
        assert!(c.args.contains(&"--working-directory=/".to_owned()));
    }

    #[test]
    fn env_lines_are_systemd_quoted() {
        assert_eq!(env_line("A", "plain").unwrap(), "A=\"plain\"");
        assert_eq!(
            env_line("A", r#"it's "q" $HOME `x` \n"#).unwrap(),
            r#"A="it's \"q\" \$HOME \`x\` \\n""#
        );
        assert!(env_line("A", "two\nlines").is_err());
        assert!(env_line("A", "cr\r").is_err());
        assert!(env_line("1A", "x").is_err());
        // A secret value never reaches the command line.
        let mut p = parts(Tier::Root, None);
        p.env.insert("TOKEN".into(), "s3cr3t".into());
        let c = cfg().command(&p, None).unwrap();
        assert!(!c.args.iter().any(|a| a.contains("s3cr3t")));
        assert!(c.env_text.contains("TOKEN=\"s3cr3t\""));
    }

    #[test]
    fn dollars_reach_the_job_literally() {
        let mut p = parts(Tier::Root, None);
        p.argv = vec!["sh".into(), "-c".into(), "echo $HOME ${PATH} $$".into()];
        let c = cfg().command(&p, None).unwrap();
        assert_eq!(c.args.last().unwrap(), "echo $$HOME $${PATH} $$$$");
        assert_eq!(systemd_literal("echo $$HOME"), Some("echo $HOME".into()));
        assert_eq!(systemd_literal("echo $HOME"), None);
        assert_eq!(systemd_literal("a$"), None);
    }

    proptest::proptest! {
        /// Any argument survives systemd's `$` rules unchanged once escaped.
        #[test]
        fn escaping_round_trips(arg in "\\PC*", dollars in proptest::collection::vec("[$a-z{}]{0,4}", 0..6)) {
            let s = format!("{arg}{}", dollars.concat());
            proptest::prop_assert_eq!(systemd_literal(&systemd_escape(&s)), Some(s));
        }
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

    /// The real `run` path against a stand-in `systemd-run` that runs what
    /// follows `--` (systemd itself is integration-tested on hosts).
    /// A root job admitted on an armed tier, stdin "in\n".
    fn admitted_root(id: &str, argv: &[&str]) -> AdmittedJob {
        use agent_auth_core::hostd::{
            ArmProof, ArmState, Authorizations, Evidence, HostPolicy, HostView, LocalCaller,
            UnixMillis, admit, normalize,
        };
        let mut policy = HostPolicy::connect_only("h");
        policy.root.enable = true;
        let now = UnixMillis(1_000_000);
        let mut arm = ArmState::default();
        arm.arm(
            &policy,
            Tier::Root,
            60,
            ArmProof::Local(LocalCaller::Root),
            agent_auth_core::hostd::LockState::Unlocked,
            now,
        )
        .unwrap();
        let raw = serde_json::json!({"kind": "run", "host": "h", "tier": "root",
            "argv": argv, "cwd": null, "env": {}, "timeout": 60, "stdin": "in\n"});
        let job = normalize(&policy, &raw, false).unwrap();
        let digest = agent_auth_core::hostd::SpecDigest::parse(&"0".repeat(64)).unwrap();
        admit(
            HostView {
                policy: &policy,
                arm: &arm,
                lock: agent_auth_core::hostd::LockState::Unlocked,
                now,
            },
            LocalId::parse(id).unwrap(),
            job,
            &digest,
            Evidence {
                source: Some(agent_auth_core::hostd::Source::Human),
                window: false,
            },
            &mut Authorizations::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn runs_through_systemd_run() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = crate::fsutil::testdir::TestDir::new("systemd");
        let script = d.path().join("systemd-run");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do case \"$1\" in EnvironmentFile=*) f=\"${{1#EnvironmentFile=}}\";; esac; shift; done\nshift\nstat -c %a \"$f\" > {}/mode\nset -a; . \"$f\"; set +a\nexec \"$@\"\n",
                d.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut c = cfg();
        c.systemd_run = script.to_string_lossy().into_owned();
        c.job_path = std::env::var("PATH").unwrap();
        c.env_dir = d.path().join("env");
        let exec = SystemdExecutor::new(c);
        let admitted = admitted_root("0123abcd-0000", &["sh", "-c", "cat; printenv HOME; exit 7"]);
        let mut out = OutputTail::new(1024);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let code = exec.run(&admitted, &mut out, rx).await.unwrap();
        assert_eq!(code, 7);
        // The root tier gets HOME=/root (daemons bug 21), stdin reached the job.
        assert_eq!(out.finish().bytes, b"in\n/root\n");
        // Read from a 0600 file, gone after the run.
        assert_eq!(
            std::fs::read_to_string(d.path().join("mode"))
                .unwrap()
                .trim(),
            "600"
        );
        assert_eq!(std::fs::read_dir(d.path().join("env")).unwrap().count(), 0);
    }

    /// Security review 2026-10, finding 2: a kill that lands before
    /// systemd-run has made the unit is stopped again until it has, so the
    /// job does not run on.
    #[tokio::test]
    async fn a_kill_before_the_unit_exists_still_stops_the_job() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = crate::fsutil::testdir::TestDir::new("systemd-late");
        let dir = d.path().to_string_lossy().into_owned();
        // systemd-run makes the unit (its pid file) only after a while;
        // systemctl stop kills what the unit holds, if it exists yet.
        let run = d.path().join("systemd-run");
        std::fs::write(
            &run,
            format!(
                "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do case \"$1\" in --unit=*) u=\"${{1#--unit=}}\";; esac; shift; done\nshift\nsleep 0.6\n\"$@\" &\necho $! > {dir}/$u.service.pid\nwait $!\n"
            ),
        )
        .unwrap();
        let ctl = d.path().join("systemctl");
        std::fs::write(
            &ctl,
            format!(
                "#!/bin/sh\n[ \"$1\" = stop ] && [ -f {dir}/$2.pid ] && kill $(cat {dir}/$2.pid)\nexit 0\n"
            ),
        )
        .unwrap();
        for f in [&run, &ctl] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut c = cfg();
        c.systemd_run = run.to_string_lossy().into_owned();
        c.systemctl = ctl.to_string_lossy().into_owned();
        c.job_path = std::env::var("PATH").unwrap();
        c.env_dir = d.path().join("env");
        let exec = SystemdExecutor::new(c);
        let admitted = admitted_root("0123abcd-0001", &["sh", "-c", "sleep 2; echo ran"]);
        let mut out = OutputTail::new(1024);
        // Killed after systemd-run started, before the unit exists.
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = tx.send(true);
            // Kept: a closed signal would read as a kill anyway.
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let code = exec.run(&admitted, &mut out, rx).await.unwrap();
        assert_ne!(code, 0);
        assert!(!String::from_utf8_lossy(&out.finish().bytes).contains("ran"));
    }

    /// Security review 2026-10, finding 5: once systemd-run is gone (its
    /// unit with it), a process outside the unit still holding the output
    /// pipe (handed to the user manager, say) doesn't keep the job open.
    #[tokio::test]
    async fn output_held_outside_the_unit_does_not_keep_the_job_open() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = crate::fsutil::testdir::TestDir::new("systemd-escape");
        let run = d.path().join("systemd-run");
        // The "unit" ends at once; something it started elsewhere keeps the
        // pipe for 30 s.
        std::fs::write(
            &run,
            "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\n(sleep 30) &\n\"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut c = cfg();
        c.systemd_run = run.to_string_lossy().into_owned();
        c.job_path = std::env::var("PATH").unwrap();
        c.env_dir = d.path().join("env");
        let exec = SystemdExecutor::new(c);
        let admitted = admitted_root("0123abcd-0002", &["echo", "done"]);
        let mut out = OutputTail::new(1024);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let started = std::time::Instant::now();
        let code = exec.run(&admitted, &mut out, rx).await.unwrap();
        assert_eq!(code, 0);
        assert_eq!(out.finish().bytes, b"done\n");
        assert!(started.elapsed() < Duration::from_secs(15));
    }
}
