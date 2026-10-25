//! Who is on the other end of a local socket, beyond its uid: a process
//! inside a job's unit (`aa-job-*`) is refused on `ctl.sock` and as the
//! desktop helper on `user.sock`, so a job can't arm its own tier, answer
//! its own desk prompt or unlock the host (security review 2026-10,
//! findings 1e and 6).
//!
//! Linux reads `/proc/<pid>/cgroup` (fail closed: an unreadable one is
//! refused). macOS has no cgroups and nothing that marks a launchd job's
//! processes to a peer; there the check passes (see DEVIATIONS.md).
//!
//! The pid is the one the kernel gave for the connecting process; a process
//! that connected, handed the socket on and exited could leave its pid to
//! an unrelated process before the check reads it. Narrow, and noted.

use std::path::Path;

use crate::executor::UNIT_PREFIX;

/// Does a `/proc/<pid>/cgroup` text put the process in a job's unit?
#[must_use]
pub fn cgroup_is_job(text: &str) -> bool {
    text.lines().any(|line| {
        // `hierarchy-id:controllers:path`; the path may hold colons.
        let path = line.splitn(3, ':').nth(2).unwrap_or(line);
        path.split('/').any(|seg| seg.starts_with(UNIT_PREFIX))
    })
}

/// Refuse a peer that runs inside a job's unit, or that can't be placed.
/// `proc_root`: `/proc` (tests use a stand-in).
pub fn check(proc_root: &Path, pid: Option<i32>) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let Some(pid) = pid.filter(|p| *p > 0) else {
        return Err("the caller's process is unknown".to_owned());
    };
    let text = std::fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup"))
        .map_err(|_| "the caller's process can't be placed".to_owned())?;
    if cgroup_is_job(&text) {
        return Err("not from inside a job".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_cgroups() {
        assert!(cgroup_is_job(
            "0::/system.slice/aa-job-0123abcd-0000.service\n"
        ));
        assert!(cgroup_is_job(
            "12:pids:/system.slice/aa-job-x.service/sub\n0::/user.slice\n"
        ));
        assert!(!cgroup_is_job(
            "0::/user.slice/user-1000.slice/session-2.scope\n"
        ));
        assert!(!cgroup_is_job("0::/system.slice/not-aa-job-x.service\n"));
        let d = crate::fsutil::testdir::TestDir::new("peers");
        assert!(check(d.path(), Some(42)).is_err());
        assert!(check(d.path(), None).is_err());
        std::fs::create_dir_all(d.path().join("42")).unwrap();
        std::fs::write(d.path().join("42/cgroup"), "0::/user.slice\n").unwrap();
        assert!(check(d.path(), Some(42)).is_ok());
        std::fs::write(
            d.path().join("42/cgroup"),
            "0::/system.slice/aa-job-1.service\n",
        )
        .unwrap();
        assert_eq!(
            check(d.path(), Some(42)).unwrap_err(),
            "not from inside a job"
        );
    }
}
