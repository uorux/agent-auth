"""What sandboxd does to the VM's system: users, directories, ACLs, units.

Behind an interface so the daemon's logic runs in tests without root or
systemd (FakeHost in the tests).

Layout (docs/sandbox-design.md §6.2), all on the persisted /var/lib:

    /var/lib/sandbox/projects/<p>/   0700 p-<p>   the project
    /var/lib/sandbox/homes/<p>/      0700 p-<p>   its agents' $HOME
    /var/lib/sandbox/tmp/<p>/        0700 p-<p>   bound to /tmp in its units

Users are systemd-userdb drop-in records (/var/lib/userdb, which the guest
links at /etc/userdb), so the guest's NixOS config keeps mutableUsers off.

Every agent process runs in a transient unit: its own uid, the system
read-only, other projects' files unreadable (plain permissions, so ACL grants
take effect live), no view of other processes, and its secrets in a root-only
EnvironmentFile — never on the systemd-run command line, where `systemctl
show` would hand them to any user.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .config import Config

ORCHESTRATOR_USER = "sbx-orchestrator"
ORCHESTRATOR_DIR = "_orchestrator"  # its workspace/home/tmp under the roots


def project_user(project: str) -> str:
    return f"p-{project}"


@dataclass
class UnitSpec:
    name: str  # without .service
    uid: int
    argv: list[str]
    workdir: Path
    home: Path
    tmp: Path
    env: dict[str, str] = field(default_factory=dict)  # into the root-only env file
    read_write: list[Path] = field(default_factory=list)
    description: str = ""


class Host(Protocol):
    def ensure_user(self, name: str, uid: int, home: Path) -> None: ...
    def make_dirs(self, uid: int, *paths: Path) -> None: ...
    async def grant_acl(self, path: Path, uid: int, write: bool) -> None: ...
    async def revoke_acl(self, path: Path, uid: int) -> None: ...
    async def chown_tree(self, path: Path, uid: int) -> None: ...
    def write_file(self, path: Path, content: str, uid: int | None, mode: int) -> None: ...
    async def start_piped(self, spec: UnitSpec) -> asyncio.subprocess.Process: ...
    async def start_detached(self, spec: UnitSpec) -> None: ...
    async def stop_unit(self, name: str) -> None: ...
    async def unit_active(self, name: str) -> bool: ...
    async def run_as(self, uid: int, argv: list[str]) -> tuple[int, str]: ...


class LinuxHost:
    def __init__(self, config: Config):
        self.config = config

    # --- users and files ------------------------------------------------------

    def ensure_user(self, name: str, uid: int, home: Path) -> None:
        d = self.config.userdb_dir
        d.mkdir(mode=0o755, parents=True, exist_ok=True)
        user = {
            "userName": name,
            "uid": uid,
            "gid": uid,
            "realName": f"agent sandbox user {name}",
            "homeDirectory": str(home),
            "shell": "/run/current-system/sw/bin/bash",
            "disposition": "regular",
            "locked": True,
        }
        group = {"groupName": name, "gid": uid}
        for fname, data in ((f"{name}.user", user), (f"{name}.group", group)):
            tmp = d / f".{fname}.tmp"
            tmp.write_text(json.dumps(data, indent=2) + "\n")
            tmp.chmod(0o644)
            tmp.replace(d / fname)
        for alias, target in ((f"{uid}.user", f"{name}.user"), (f"{uid}.group", f"{name}.group")):
            link = d / alias
            if not link.is_symlink():
                link.symlink_to(target)

    def make_dirs(self, uid: int, *paths: Path) -> None:
        for path in paths:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chown(path, uid, uid)
            path.chmod(0o700)

    async def _run(self, *argv: str) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await proc.communicate()
        return proc.returncode, out.decode(errors="replace")

    async def _check(self, *argv: str) -> str:
        code, out = await self._run(*argv)
        if code != 0:
            raise RuntimeError(f"{argv[0]} failed ({code}): {out.strip()[:300]}")
        return out

    async def grant_acl(self, path: Path, uid: int, write: bool) -> None:
        perms = "rwX" if write else "rX"
        # The existing tree, and defaults so files created later inherit it.
        await self._check(self.config.setfacl, "-R", "-m", f"u:{uid}:{perms}", str(path))
        await self._check(self.config.setfacl, "-R", "-d", "-m", f"u:{uid}:{perms}", str(path))
        # Reaching the project dir from its parent needs no ACL: the roots are 0711.

    async def revoke_acl(self, path: Path, uid: int) -> None:
        await self._check(self.config.setfacl, "-R", "-x", f"u:{uid}", str(path))
        await self._check(self.config.setfacl, "-R", "-d", "-x", f"u:{uid}", str(path))

    async def chown_tree(self, path: Path, uid: int) -> None:
        await self._check("chown", "-R", "--no-dereference", f"{uid}:{uid}", str(path))

    def write_file(self, path: Path, content: str, uid: int | None, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        if uid is not None:
            os.chown(tmp, uid, uid)
        os.chmod(tmp, mode)
        tmp.replace(path)

    # --- units -------------------------------------------------------------------

    def _env_file(self, spec: UnitSpec) -> Path:
        path = self.config.runtime_dir / "env" / f"{spec.name}.env"
        lines = []
        for key, value in spec.env.items():
            if "\n" in value or "\x00" in value:
                raise ValueError(f"environment value for {key} contains a newline")
            lines.append(f"{key}={shlex.quote(value)}")
        self.write_file(path, "\n".join(lines) + "\n", None, 0o600)
        return path

    def _argv(self, spec: UnitSpec, *, piped: bool) -> list[str]:
        c = self.config
        props = [
            f"Description={spec.description or spec.name}",
            f"WorkingDirectory={spec.workdir}",
            f"EnvironmentFile={self._env_file(spec)}",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "NoNewPrivileges=yes",
            "ProtectProc=invisible",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "RestrictRealtime=yes",
            "KeyringMode=private",
            "UMask=0077",
            # The unit definitions (and their EnvironmentFile paths) and
            # sandboxd's own runtime files are none of the agent's business.
            f"InaccessiblePaths={c.runtime_dir}",
            "InaccessiblePaths=-/run/systemd/transient",
            f"InaccessiblePaths={c.state_dir}",
            f"ReadWritePaths={c.sandbox_root / 'projects'}",
            f"ReadWritePaths={spec.home}",
            f"BindPaths={spec.tmp}:/tmp",
            f"MemoryMax={c.unit_memory_max}",
            f"TasksMax={c.unit_tasks_max}",
            "KillMode=control-group",
        ]
        props += [f"ReadWritePaths={p}" for p in spec.read_write]
        argv = [
            c.systemd_run,
            f"--unit={spec.name}",
            f"--uid={spec.uid}",
            f"--gid={spec.uid}",
            "--quiet",
            "--collect",
        ]
        if piped:
            argv += ["--pipe", "--wait"]
        for p in props:
            argv += ["-p", p]
        return argv + ["--", *spec.argv]

    async def start_piped(self, spec: UnitSpec) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            *self._argv(spec, piped=True),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=16 * 1024 * 1024,
        )

    async def start_detached(self, spec: UnitSpec) -> None:
        await self._check(*self._argv(spec, piped=False))

    async def stop_unit(self, name: str) -> None:
        await self._run(self.config.systemctl, "stop", f"{name}.service")
        (self.config.runtime_dir / "env" / f"{name}.env").unlink(missing_ok=True)

    async def unit_active(self, name: str) -> bool:
        code, _ = await self._run(self.config.systemctl, "is-active", "--quiet", f"{name}.service")
        return code == 0

    async def run_as(self, uid: int, argv: list[str]) -> tuple[int, str]:
        return await self._run("setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "--", *argv)
