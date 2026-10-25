//! How hostd runs things (daemons-hostd spec §11), behind [`Executor`] so
//! its decisions are tested without root or systemd.
//!
//! - [`linux::SystemdExecutor`]: every job is a transient system unit
//!   started by PID 1 (`systemd-run --pipe --wait`), never a child of hostd,
//!   killed as a whole cgroup. Integration-tested on real hosts; its
//!   command line is unit-tested here.
//! - [`darwin::DarwinExecutor`]: jobs are hostd's children, each in its own
//!   process group; the user tier goes through `launchctl asuser` and then
//!   this binary's `asuser` step.
//! - [`direct::DirectExecutor`]: the job's argv run directly as this user,
//!   in its own process group (tests, and the reference for output and
//!   timeout handling).
//!
//! Processes are started with `std::process::Command` only (no `pre_exec`,
//! no libc): environments are replaced, not inherited; process groups and
//! uid/gid changes use `CommandExt`; signals to a group go through
//! `kill(1)`.

pub mod darwin;
pub mod direct;
pub mod linux;
pub mod passwd;

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use agent_auth_core::hostd::output::OutputTail;
use agent_auth_core::hostd::{AdmittedJob, LocalId, PolkitConfirmed};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::Instant;

/// Read output in pieces of at most this.
pub const READ_CHUNK: usize = 64 * 1024;
/// `now + d`, saturating at now (never overflows in practice).
#[must_use]
pub fn after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).unwrap_or(now)
}

/// A job unit's name prefix (`aa-job-<id>`).
pub const UNIT_PREFIX: &str = "aa-job-";
/// After a job's main process ends: how long its output may still drain.
pub const DRAIN: Duration = Duration::from_secs(5);
/// A kill: SIGTERM, then this long before SIGKILL.
pub const KILL_GRACE: Duration = Duration::from_secs(5);

#[must_use]
pub fn unit_name(job: &LocalId) -> String {
    format!("{UNIT_PREFIX}{job}")
}

/// `systemctl` verbs hostd uses on the VM unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitAction {
    Freeze,
    Thaw,
    Stop,
    IsActive,
}

impl UnitAction {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            UnitAction::Freeze => "freeze",
            UnitAction::Thaw => "thaw",
            UnitAction::Stop => "stop",
            UnitAction::IsActive => "is-active",
        }
    }
}

/// How hostd runs, kills and asks.
pub trait Executor: Send + Sync + 'static {
    /// Run an admitted job to completion, feeding its combined stdout and
    /// stderr to `out`. `Ok(exit code)` (a signal death is `128 + N`);
    /// `Err` if it could not be started.
    fn run(
        &self,
        job: &AdmittedJob,
        out: &mut OutputTail,
        kill: KillSignal,
    ) -> impl Future<Output = Result<i32, String>> + Send;

    /// Stop a job by id, outside its run: a job left running by an earlier
    /// hostd (its unit). Running jobs are stopped through their
    /// [`KillSignal`].
    fn kill(&self, job: &LocalId) -> impl Future<Output = ()> + Send;

    /// Have polkit authenticate the user of `process` as an administrator,
    /// showing `message`. `Some` only if they did.
    fn polkit_auth(
        &self,
        process: Process,
        uid: u32,
        message: &str,
        timeout: Duration,
    ) -> impl Future<Output = Option<PolkitConfirmed>> + Send;

    /// `systemctl <action> <unit>`: (exit code, output).
    fn unit_action(
        &self,
        action: UnitAction,
        unit: &str,
    ) -> impl Future<Output = Result<(i32, String), String>> + Send;

    /// Jobs still running from an earlier hostd process (Linux: their
    /// `aa-job-*` units), so a crash leaves nothing unkillable.
    fn running_jobs(&self) -> impl Future<Output = Vec<LocalId>> + Send;
}

/// A process as polkit names it: its pid and its start time (read when it
/// connected, so a process that took the pid later isn't the one asked
/// about; security review 2026-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process {
    pub pid: i32,
    pub start_time: Option<u64>,
}

/// `pid`'s start time (`/proc/<pid>/stat` field 22), on Linux.
#[must_use]
pub fn start_time_of(pid: i32) -> Option<u64> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    linux::proc_start_time(&stat)?.parse().ok()
}

/// A process's exit status as a job's exit code.
#[must_use]
pub fn exit_code(status: ExitStatus) -> i32 {
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(sig)) => sig.saturating_add(128),
        (None, None) => 0,
    }
}

/// Set to true to stop a running job (hostd's `job.kill`, a shell's end,
/// lockdown). The job's own run watches it, so a kill that lands before
/// the process exists still stops it.
pub type KillSignal = tokio::sync::watch::Receiver<bool>;

/// What to do while collecting a child's output.
pub(crate) struct Collect {
    /// Past this, `on_stop` runs (once).
    pub deadline: Option<Instant>,
    /// When it turns true, `on_stop` runs (once).
    pub kill: KillSignal,
    /// Once the main process ended, stop reading after [`DRAIN`] (a
    /// process left in the background must not hold the job open). Without
    /// it, read to end of output.
    pub stop_at_exit: bool,
    /// After the first stop: stop again this often until the main process
    /// ends (Linux: a `systemctl stop` that lands before `systemd-run` made
    /// the unit stops nothing; security review 2026-10, finding 2).
    pub restop: Option<Duration>,
}

/// A command with stdout and stderr on one pipe, stdin from `stdin` (or
/// /dev/null). Returns the child and the pipe's read end.
pub(crate) fn spawn_piped(
    mut cmd: std::process::Command,
    stdin: bool,
) -> io::Result<(tokio::process::Child, tokio::net::unix::pipe::Receiver)> {
    let (reader, writer) = io::pipe()?;
    cmd.stdout(Stdio::from(writer.try_clone()?));
    cmd.stderr(Stdio::from(writer));
    cmd.stdin(if stdin { Stdio::piped() } else { Stdio::null() });
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.kill_on_drop(true);
    let child = cmd.spawn()?;
    // The command (and its copies of the write end) goes now, so the pipe
    // ends when the job's processes close it.
    drop(cmd);
    let rx = tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(reader))?;
    Ok((child, rx))
}

/// Feed `stdin`, collect output into `out`, wait for the child. Calls
/// `on_deadline` if the deadline passes or the kill signal fires (once, or
/// every [`Collect::restop`] until the main process ends), and
/// `after_exit` once when the main process has ended.
pub(crate) async fn collect<D, DF, A>(
    child: &mut tokio::process::Child,
    mut rx: tokio::net::unix::pipe::Receiver,
    stdin: Option<&str>,
    out: &mut OutputTail,
    how: Collect,
    on_deadline: D,
    after_exit: A,
) -> io::Result<ExitStatus>
where
    D: Fn() -> DF,
    DF: Future<Output = ()>,
    A: AsyncFnOnce(),
{
    if let Some(mut pipe) = child.stdin.take() {
        let data = stdin.unwrap_or("").as_bytes().to_vec();
        // Written from its own task: a job that doesn't read its stdin
        // must not stop us reading its output.
        tokio::spawn(async move {
            let _ = pipe.write_all(&data).await;
            let _ = pipe.shutdown().await;
        });
    }
    let mut stopped = false;
    let mut next_stop: Option<Instant> = None;
    let mut kill = how.kill.clone();
    if *kill.borrow_and_update() {
        stopped = true;
        on_deadline().await;
        next_stop = how.restop.map(after);
    }
    let mut after_exit = Some(after_exit);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut status: Option<ExitStatus> = None;
    let mut eof = false;
    let mut drain_until: Option<Instant> = None;
    loop {
        if eof && status.is_some() {
            break;
        }
        // A disabled branch's timer is built but never polled.
        let deadline = how.deadline.unwrap_or_else(Instant::now);
        let drain = drain_until.unwrap_or_else(Instant::now);
        let restop = next_stop.unwrap_or_else(Instant::now);
        tokio::select! {
            n = rx.read(&mut buf), if !eof => {
                match n {
                    Ok(0) | Err(_) => eof = true,
                    Ok(n) => out.push(buf.get(..n).unwrap_or_default()),
                }
            }
            s = child.wait(), if status.is_none() => {
                status = Some(s?);
                next_stop = None;
                if let Some(f) = after_exit.take() {
                    f().await;
                }
                if how.stop_at_exit && !eof {
                    drain_until = Some(after(DRAIN));
                }
            }
            changed = kill.changed(), if !stopped => {
                if changed.is_err() || *kill.borrow_and_update() {
                    stopped = true;
                    on_deadline().await;
                    next_stop = how.restop.filter(|_| status.is_none()).map(after);
                }
            }
            () = tokio::time::sleep_until(deadline), if !stopped && how.deadline.is_some() => {
                stopped = true;
                on_deadline().await;
                next_stop = how.restop.filter(|_| status.is_none()).map(after);
            }
            () = tokio::time::sleep_until(restop), if next_stop.is_some() && status.is_none() => {
                on_deadline().await;
                next_stop = how.restop.map(after);
            }
            () = tokio::time::sleep_until(drain), if drain_until.is_some() => {
                eof = true;
            }
        }
    }
    status.ok_or_else(|| io::Error::other("no exit status"))
}

/// `kill -s SIG -- -PGID` (the whole group), without libc. True if the
/// group existed.
pub(crate) async fn signal_group(kill: &str, pgid: u32, sig: &str) -> bool {
    let mut cmd = tokio::process::Command::new(kill);
    cmd.args(["-s", sig, "--", &format!("-{pgid}")])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    matches!(cmd.status().await, Ok(s) if s.success())
}

/// SIGTERM the group, wait up to [`KILL_GRACE`] for it to go, then SIGKILL.
pub(crate) async fn kill_group(kill: &str, pgid: u32) {
    if !signal_group(kill, pgid, "TERM").await {
        return;
    }
    let until = after(KILL_GRACE);
    while Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !signal_group(kill, pgid, "0").await {
            return;
        }
    }
    signal_group(kill, pgid, "KILL").await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(15)), 143);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
        assert_eq!(
            unit_name(&LocalId::parse("0123abcd-0000").unwrap()),
            "aa-job-0123abcd-0000"
        );
    }
}
