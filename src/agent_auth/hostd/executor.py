"""How hostd runs things on the host, behind an interface so its decisions are
tested without root or systemd (FakeExecutor in the tests).

Jobs run in transient systemd units (docs/sandbox-design.md §8.9), never as
children of hostd, so a job doesn't inherit hostd's sandbox, environment or
file descriptors, a runaway one is killed as a whole cgroup, and the journal
has it under its own unit name (aa-job-<id>).

- root tier: a system unit, started by PID 1.
- user tier: a unit of the user's own systemd manager (so it sees the user's
  session bus and environment). hostd drops to the user to ask for it:
  systemd-run talks to /run/user/<uid>/bus directly, which carries the job's
  stdio as file descriptors. Needs the user's manager running (logged in, or
  lingering).

NOT yet run on a real host: the user-tier path in particular depends on the
service's sandboxing leaving /run/user reachable.
"""

from __future__ import annotations

import asyncio
import os
import pwd
from typing import Awaitable, Callable, Protocol

from .config import HostConfig

UNIT_PREFIX = "aa-job-"
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
        """argv prefix and environment for acting as the configured user
        against their systemd manager."""
        pw = self._user()
        runtime = f"/run/user/{pw.pw_uid}"
        if not os.path.exists(f"{runtime}/bus"):
            raise RuntimeError(
                f"{pw.pw_name}'s systemd manager isn't running (not logged in, and lingering is off)"
            )
        prefix = [
            self.config.setpriv,
            f"--reuid={pw.pw_uid}",
            f"--regid={pw.pw_gid}",
            "--init-groups",
            "--",
        ]
        env = {
            "XDG_RUNTIME_DIR": runtime,
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
            "HOME": pw.pw_dir,
            "USER": pw.pw_name,
            "LOGNAME": pw.pw_name,
        }
        return prefix, env

    def _path(self, tier: str) -> str:
        if tier == "user" and self.config.user:
            return f"{self.config.job_path}:/etc/profiles/per-user/{self.config.user}/bin"
        return self.config.job_path

    async def run(self, job_id, tier, argv, cwd, env, timeout, stdin, on_output) -> int:
        c = self.config
        path = self._path(tier)
        command = [c.systemd_run]
        proc_env = {"PATH": path, "LANG": "C.UTF-8"}
        if tier == "user":
            prefix, user_env = self._as_user()
            command = [*prefix, c.systemd_run, "--user"]
            proc_env.update(user_env)
            cwd = cwd or user_env["HOME"]
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
            env=proc_env,
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

    async def _systemctl(self, tier: str, *args: str) -> tuple[int, str]:
        command, env = [self.config.systemctl], None
        if tier == "user":
            prefix, env = self._as_user()
            command = [*prefix, self.config.systemctl, "--user"]
        proc = await asyncio.create_subprocess_exec(
            *command, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={"PATH": self.config.job_path, **(env or {})},
        )
        out, _ = await proc.communicate()
        return proc.returncode or 0, out.decode(errors="replace").strip()

    async def kill(self, job_id: str, tier: str) -> None:
        try:
            await self._systemctl(tier, "stop", f"{unit_name(job_id)}.service")
        except (OSError, RuntimeError, KeyError):
            pass

    async def unit_action(self, action: str, unit: str) -> tuple[int, str]:
        if action not in ("freeze", "thaw", "stop", "is-active"):
            raise ValueError(action)
        return await self._systemctl("root", action, unit)
