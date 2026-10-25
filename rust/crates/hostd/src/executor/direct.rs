//! The job's argv run directly, as this process's user, in a process group
//! of its own, with exactly the job's environment (plus a PATH): the test
//! double for [`super::Executor`], and what a connect-only development
//! setup can use. Not a production executor (it does not change user).

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::hostd::output::OutputTail;
use agent_auth_core::hostd::{AdmittedJob, LocalId, PolkitConfirmed};

use super::darwin::{DarwinCommand, Groups, run_in_group};
use super::{Executor, KillSignal, UnitAction};

/// What a test can observe and steer.
#[derive(Debug, Default)]
pub struct Recorded {
    /// `(job, tier, argv)` of every run.
    pub runs: Vec<(String, String, Vec<String>)>,
    /// `(action, unit)` of every unit action.
    pub units: Vec<(String, String)>,
    /// `(process, uid, message)` of every polkit request.
    pub polkit: Vec<(super::Process, u32, String)>,
    /// Does the user type their password when polkit asks?
    pub password_ok: bool,
    /// Jobs reported as still running from an earlier process.
    pub leftover: Vec<LocalId>,
    /// Jobs killed through `kill`.
    pub killed: Vec<String>,
}

#[derive(Debug)]
pub struct DirectExecutor {
    path: String,
    groups: Groups,
    pub recorded: Mutex<Recorded>,
}

impl DirectExecutor {
    /// `path`: the PATH jobs get. `kill_program`: `kill(1)`.
    #[must_use]
    pub fn new(path: &str, kill_program: &str) -> DirectExecutor {
        DirectExecutor {
            path: path.to_owned(),
            groups: Groups::new(kill_program),
            recorded: Mutex::new(Recorded {
                password_ok: true,
                ..Recorded::default()
            }),
        }
    }

    fn rec(&self) -> std::sync::MutexGuard<'_, Recorded> {
        self.recorded.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Executor for DirectExecutor {
    async fn run(
        &self,
        job: &AdmittedJob,
        out: &mut OutputTail,
        kill: KillSignal,
    ) -> Result<i32, String> {
        self.rec().runs.push((
            job.id().to_string(),
            job.tier().to_string(),
            job.argv().to_vec(),
        ));
        let (program, args) = job
            .argv()
            .split_first()
            .ok_or_else(|| "empty argv".to_owned())?;
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        env.insert("PATH".into(), self.path.clone());
        env.extend(job.env().clone());
        let c = DarwinCommand {
            program: program.clone(),
            args: args.to_vec(),
            cwd: job.cwd().unwrap_or("/").to_owned(),
            env,
        };
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
        self.rec().killed.push(job.to_string());
        self.groups.kill(job).await;
    }

    async fn polkit_auth(
        &self,
        process: super::Process,
        uid: u32,
        message: &str,
        _timeout: Duration,
    ) -> Option<PolkitConfirmed> {
        let mut rec = self.rec();
        rec.polkit.push((process, uid, message.to_owned()));
        rec.password_ok
            .then(PolkitConfirmed::after_successful_pkcheck)
    }

    async fn unit_action(&self, action: UnitAction, unit: &str) -> Result<(i32, String), String> {
        self.rec()
            .units
            .push((action.as_str().to_owned(), unit.to_owned()));
        Ok((0, "active".to_owned()))
    }

    async fn running_jobs(&self) -> Vec<LocalId> {
        self.rec().leftover.clone()
    }
}
