"""How hostd runs things on the host, behind an interface so its decisions are
tested without root or systemd (FakeExecutor in the tests).

Jobs run in transient systemd units (docs/sandbox-design.md §8.9), never as
children of hostd, so a job doesn't inherit hostd's sandbox, environment or
file descriptors, a runaway one is killed as a whole cgroup, and the journal
has it under its own unit name (aa-job-<id>).

Both tiers are system units, started by PID 1 on hostd's request (hostd is
root; it needs no capability for that):
- root tier: as root.
- user tier: with User=<the configured user>, their groups, and their
  session's runtime dir and bus in the environment, so `systemctl --user` and
  desktop tools work while they are logged in. It is not a unit of the user's
  own manager: hostd would have to become the user to ask for one, and
  changing uid inside the service failed on the first real run (EPERM from
  setpriv and from setuid in a child, cause not found).

Run on a real host so far: nothing of this version.

On macOS (DarwinExecutor, docs/hostd-macos.md) there is no systemd: jobs are
hostd's children, each in a new session and process group, started with an
environment and working directory of their own and no inherited descriptors.
The user tier goes through `launchctl asuser` into the user's launchd domain
and then drops to the user (hostd/asuser.py). A timeout or a kill signals the
process group, and when the job's main process ends the rest of its group is
killed, as KillMode=control-group would. What a cgroup catches and this does
not: a process that leaves the group (setsid, a double fork) outlives it.
"""

from __future__ import annotations

import asyncio
import json
import os
import pwd
import signal
import sys
from typing import Awaitable, Callable, Protocol

from .config import HostConfig

UNIT_PREFIX = "aa-job-"
# Installed by the NixOS module (auth_admin for the active local session).
POLKIT_ACTION = "dev.agent-auth.hostd.run-as-root"
READ_CHUNK = 64 * 1024


def unit_name(job_id: str) -> str:
    return f"{UNIT_PREFIX}{job_id}"


class Executor(Protocol):
    async def run(
        self,
        job_id: str,
        tier: str,
        argv: list[str],
        cwd: str | None,
        env: dict[str, str],
        timeout: int,
        stdin: bytes | None,
        on_output: Callable[[bytes], Awaitable[None]],
    ) -> int:
        """Run to completion, feeding combined stdout+stderr to on_output.
        Returns the exit status. Raises OSError/RuntimeError if it couldn't
        start."""
        ...

    async def kill(self, job_id: str, tier: str) -> None: ...
    async def polkit_auth(self, pid: int, uid: int, message: str, timeout: int) -> bool:
        """Have polkit authenticate the user of that process as an
        administrator (their password, in their session's agent), showing
        `message`. True only if they did."""
        ...

    async def unit_action(self, action: str, unit: str) -> tuple[int, str]:
        """systemctl freeze | thaw | stop | is-active a system unit."""
        ...


class LinuxExecutor:
    def __init__(self, config: HostConfig):
        self.config = config

    def _user(self) -> pwd.struct_passwd:
        if not self.config.user:
            raise RuntimeError("no user configured for the user tier")
        return pwd.getpwnam(self.config.user)

    def _as_user(self) -> tuple[list[str], dict[str, str]]:
        """systemd-run properties and the job's environment for the user tier."""
        pw = self._user()
        runtime = f"/run/user/{pw.pw_uid}"
        env = {
            "HOME": pw.pw_dir,
            "USER": pw.pw_name,
            "LOGNAME": pw.pw_name,
            "SHELL": pw.pw_shell,
            # Only there while the user is logged in (or lingering).
            "XDG_RUNTIME_DIR": runtime,
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
        }
        return ["-p", f"User={pw.pw_name}"], env

    def _path(self, tier: str) -> str:
        if tier == "user" and self.config.user:
            return f"{self.config.job_path}:/etc/profiles/per-user/{self.config.user}/bin"
        return self.config.job_path

    async def run(self, job_id, tier, argv, cwd, env, timeout, stdin, on_output) -> int:
        c = self.config
        path = self._path(tier)
        command = [c.systemd_run]
        if tier == "user":
            props, user_env = self._as_user()
            command += props
            cwd = cwd or user_env["HOME"]
            env = {**user_env, **env}
        command += [
            f"--unit={unit_name(job_id)}",
            "--collect",
            "--quiet",
            "--pipe",
            "--wait",
            "-p", f"RuntimeMaxSec={timeout}",
            "-p", "KillMode=control-group",
            "-p", f"Description=agent-auth job {job_id}",
            f"--working-directory={cwd or '/'}",
            f"--setenv=PATH={path}",
        ]
        command += [f"--setenv={key}={value}" for key, value in env.items()]
        proc = await asyncio.create_subprocess_exec(
            *command,
            "--",
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={"PATH": path, "LANG": "C.UTF-8"},
        )
        if stdin is not None:
            assert proc.stdin is not None
            proc.stdin.write(stdin)
            try:
                await proc.stdin.drain()
            except ConnectionError:
                pass
            proc.stdin.close()
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(READ_CHUNK)
            if not chunk:
                break
            await on_output(chunk)
        return await proc.wait()

    async def _systemctl(self, *args: str) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            self.config.systemctl, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={"PATH": self.config.job_path},
        )
        out, _ = await proc.communicate()
        return proc.returncode or 0, out.decode(errors="replace").strip()

    async def polkit_auth(self, pid: int, uid: int, message: str, timeout: int) -> bool:
        # The subject is the session helper's process, pinned by its start
        # time. polkit.message is honoured because hostd is root: the
        # password dialog itself says what is being approved.
        try:
            stat = open(f"/proc/{pid}/stat").read()
            start_time = stat.rsplit(")", 1)[1].split()[19]
            proc = await asyncio.create_subprocess_exec(
                self.config.pkcheck,
                "--action-id", POLKIT_ACTION,
                "--process", f"{pid},{start_time},{uid}",
                "--allow-user-interaction",
                "--detail", "polkit.message", message,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                env={"PATH": self.config.job_path},
            )
        except (OSError, IndexError):
            return False
        try:
            return await asyncio.wait_for(proc.wait(), timeout) == 0
        except TimeoutError:
            proc.kill()
            return False

    async def kill(self, job_id: str, tier: str) -> None:
        try:
            await self._systemctl("stop", f"{unit_name(job_id)}.service")
        except (OSError, RuntimeError, KeyError):
            pass

    async def unit_action(self, action: str, unit: str) -> tuple[int, str]:
        if action not in ("freeze", "thaw", "stop", "is-active"):
            raise ValueError(action)
        return await self._systemctl(action, unit)


KILL_GRACE = 5
DRAIN_SECS = 5
# Homebrew, for the user tier only (it is the user's).
USER_EXTRA_PATH = "/opt/homebrew/bin:/usr/local/bin"


class DarwinExecutor:
    """Jobs as hostd's children, one process group each (see the module doc)."""

    def __init__(self, config: HostConfig):
        self.config = config
        self.launchctl = "/bin/launchctl"
        self.python = sys.executable
        self._groups: dict[str, int] = {}

    def _user(self) -> pwd.struct_passwd:
        if not self.config.user:
            raise RuntimeError("no user configured for the user tier")
        return pwd.getpwnam(self.config.user)

    def _path(self, tier: str) -> str:
        if tier == "user" and self.config.user:
            return f"{self.config.job_path}:/etc/profiles/per-user/{self.config.user}/bin:{USER_EXTRA_PATH}"
        return self.config.job_path

    def root_path_problem(self) -> str | None:
        """A directory on the root tier's PATH that someone other than root
        could write to would let them choose what a root job runs."""
        for directory in self.config.job_path.split(":"):
            try:
                st = os.stat(directory)
            except FileNotFoundError:
                continue
            except OSError as exc:
                return f"{directory}: {exc.strerror}"
            if st.st_uid != 0 or st.st_mode & 0o022:
                return f"{directory} on the root tier's PATH is writable by others than root (owner uid {st.st_uid})"
        return None

    def command(
        self, tier: str, argv: list[str], cwd: str | None, env: dict[str, str]
    ) -> tuple[list[str], str, dict[str, str]]:
        """What to start, in which directory, with which environment."""
        path = self._path(tier)
        base = {"PATH": path, "LANG": "C.UTF-8"}
        if tier != "user":
            # root's home on macOS (xcodebuild and swift want a HOME).
            return list(argv), cwd or "/", {**base, "HOME": "/var/root", "USER": "root", "LOGNAME": "root", **env}
        pw = self._user()
        job_env = {
            **base,
            "HOME": pw.pw_dir,
            "USER": pw.pw_name,
            "LOGNAME": pw.pw_name,
            "SHELL": pw.pw_shell,
            **env,
        }
        spec = {"user": pw.pw_name, "cwd": cwd or pw.pw_dir, "env": job_env, "argv": list(argv)}
        command = [
            self.launchctl, "asuser", str(pw.pw_uid),
            self.python, "-I", "-m", "agent_auth.hostd.asuser", json.dumps(spec),
        ]
        # launchctl itself starts in "/" as root; asuser changes directory.
        return command, "/", {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"}

    def _signal(self, job_id: str, sig: int) -> bool:
        pgid = self._groups.get(job_id)
        if pgid is None:
            return False
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError):
            return False
        return True

    async def run(self, job_id, tier, argv, cwd, env, timeout, stdin, on_output) -> int:
        if tier != "user" and (problem := self.root_path_problem()):
            raise RuntimeError(f"not running a root job: {problem}")
        command, workdir, job_env = self.command(tier, argv, cwd, env)
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=workdir,
            env=job_env,
            start_new_session=True,
        )
        self._groups[job_id] = proc.pid
        try:
            if stdin is not None:
                assert proc.stdin is not None
                proc.stdin.write(stdin)
                try:
                    await proc.stdin.drain()
                except ConnectionError:
                    pass
                proc.stdin.close()

            async def relay() -> None:
                assert proc.stdout is not None
                while chunk := await proc.stdout.read(READ_CHUNK):
                    await on_output(chunk)

            async def exited() -> None:
                # Not proc.wait(): that also waits for the pipe to close,
                # which a process left in the background can hold open.
                while proc.returncode is None:
                    await asyncio.sleep(0.1)

            reader = asyncio.create_task(relay())
            try:
                await asyncio.wait_for(exited(), timeout)
            except TimeoutError:
                await self.kill(job_id, tier)
                await exited()
            # The main process is done: so is the rest of its group, and
            # whatever still holds the pipe open does not hold the job.
            self._signal(job_id, signal.SIGKILL)
            try:
                await asyncio.wait_for(reader, DRAIN_SECS)
            except TimeoutError:
                reader.cancel()
            try:
                await asyncio.wait_for(proc.wait(), DRAIN_SECS)
            except TimeoutError:
                pass
        finally:
            self._groups.pop(job_id, None)
        code = proc.returncode or 0
        return 128 - code if code < 0 else code

    async def kill(self, job_id: str, tier: str) -> None:
        if not self._signal(job_id, signal.SIGTERM):
            return
        for _ in range(KILL_GRACE * 10):
            await asyncio.sleep(0.1)
            if not self._signal(job_id, 0):  # the whole group is gone
                return
        self._signal(job_id, signal.SIGKILL)

    async def polkit_auth(self, pid: int, uid: int, message: str, timeout: int) -> bool:
        # No polkit: approving root commands at the desk is refused by the
        # config on macOS, and this never says yes.
        return False

    async def unit_action(self, action: str, unit: str) -> tuple[int, str]:
        raise RuntimeError("there are no systemd units on macOS")


def make_executor(config: HostConfig) -> Executor:
    return DarwinExecutor(config) if sys.platform == "darwin" else LinuxExecutor(config)
