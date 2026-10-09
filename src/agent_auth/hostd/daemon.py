"""hostd: what a host is willing to run for the broker, and under which proof
(docs/sandbox-design.md §8, §9).

The broker proposes; this daemon decides, from its own state and its own
config, and the broker can't change either:

- **Local policy** (nix store): which tiers exist, deny and auto patterns,
  templates, how long a tier may be armed, whether shells exist at all.
- **TOTP secrets** generated on this host. A *direct* code approves one exact
  request (its digest); an *arm* code opens a window in which the broker's
  own approvals (a human's click on Discord, relayed) are believed.
- **Arm state**, in memory only: a restart disarms.
- **Lockdown**, on disk: everything is refused until it is cleared with a
  root arm code or locally by root.

Every decision is written to the journal with the evidence it was made on —
an audit log the broker can't edit.

What this does NOT protect against: a compromised broker can attach a direct
TOTP code you typed to a different command (once per code), and while a tier
is armed it can run anything in that tier. Disarmed and without codes, it
can run nothing but the auto patterns.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import pwd
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__
from ..daemon_common import hostexec as hx
from ..daemon_common.channel import DaemonChannel, DaemonIdentity
from ..daemon_common.crypto import load_or_create_key
from ..daemon_common.localsock import ApiError, peer_uid, serve_unix
from ..daemon_common.totp import TotpError, TotpStore
from .config import HostConfig, duration_secs, match_argv
from .executor import Executor

log = logging.getLogger(__name__)
audit = logging.getLogger("agent_auth.hostd.audit")

ROLE = "host"
ID_RE = re.compile(r"[0-9a-f-]{8,64}")
AUTHZ_TTL_SECS = 300
SOURCES = ("human", "rule", "llm", "policy")
# How long a finished job's result is kept for a broker that hasn't
# acknowledged it.
SPOOL_KEEP_SECS = 7 * 86400
RESEND_AFTER_SECS = 15


class Refused(Exception):
    """hostd won't do it; the text goes back to the broker and the human."""


@dataclass
class Authorization:
    digest: str
    expires_at: float


@dataclass
class Shell:
    tier: str
    expires_at: float
    timer: asyncio.Task | None = None


@dataclass
class Presence:
    """What is known about the user's desktop session on this host."""

    connected: bool = False
    idle_secs: float | None = None  # reported by hostd-user (None = unknown)
    locked: bool | None = None
    fullscreen: bool = False
    reported_at: float = 0.0
    # Set by `agent-auth-hostctl presence …` (hypridle / hyprlock hooks);
    # these win over what hostd-user polled.
    idle_since: float | None = None
    explicit_idle: bool | None = None
    explicit_locked: bool | None = None
    dnd_until: float = 0.0


@dataclass
class RunningJob:
    tier: str
    task: asyncio.Task
    shell_id: str | None = None
    killed: bool = False
    chunks: list[bytes] = field(default_factory=list)


class Hostd:
    def __init__(self, config: HostConfig, executor: Executor):
        self.config = config
        self.executor = executor
        self.totp = TotpStore(config.totp_dir)
        self.armed_until: dict[str, float] = {"user": 0.0, "root": 0.0}
        self.authorizations: dict[str, Authorization] = {}
        self.jobs: dict[str, RunningJob] = {}
        self.shells: dict[str, Shell] = {}
        self.presence = Presence()
        self.channel: DaemonChannel | None = None
        self.started_at = time.time()
        self.vm_state: str | None = None
        self._user_writer: asyncio.StreamWriter | None = None
        self._load_presence()
        self._tasks: set[asyncio.Task] = set()

    # --- lifecycle -----------------------------------------------------------------

    def identity(self) -> DaemonIdentity:
        return DaemonIdentity(
            role=ROLE,
            name=self.config.name,
            key=load_or_create_key(self.config.state_dir / "key"),
            broker_url=self.config.broker_url,
            broker_public_key=self.config.broker_public_key,
        )

    def _task(self, coro, name: str) -> asyncio.Task:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def run(self) -> None:
        servers = []
        try:
            self._recover_spool()
            self.channel = DaemonChannel(
                self.identity(), version=__version__, status=self.status, on_message=self.on_message
            )
            if self.config.privileged or self.config.desktop.enable:
                servers.append(await serve_unix(self.config.ctl_socket, 0o666, self.ctl))
            if self.config.desktop.enable:
                self.config.user_socket.unlink(missing_ok=True)
                servers.append(
                    await asyncio.start_unix_server(self._user_conn, path=str(self.config.user_socket))
                )
                # Anyone may connect; only the configured user is listened to.
                self.config.user_socket.chmod(0o666)
            self._task(self._resend_results(), "resend")
            if self.config.vm_unit:
                self._task(self._watch_vm(), "vm")
            await self.channel.run()
        finally:
            for server in servers:
                server.close()
            tasks = list(self._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # --- state -----------------------------------------------------------------------

    @property
    def lockdown_file(self) -> Path:
        return self.config.state_dir / "lockdown"

    @property
    def locked_down(self) -> bool:
        return self.lockdown_file.exists()

    def armed(self, tier: str) -> bool:
        return self.armed_until.get(tier, 0.0) > time.time()

    def present(self) -> bool:
        """Is the user at this host's desktop right now? Unknown counts as no."""
        p, now = self.presence, time.time()
        if not self.config.desktop.enable or not p.connected or p.dnd_until > now or p.fullscreen:
            return False
        locked = p.explicit_locked if p.explicit_locked is not None else p.locked
        if locked is not False:
            return False
        if p.explicit_idle is not None:
            idle = (now - p.idle_since) if (p.explicit_idle and p.idle_since) else 0.0
        elif p.idle_secs is not None:
            idle = p.idle_secs + (now - p.reported_at)
        else:
            return False
        return idle <= self.config.desktop.max_idle_secs

    def status(self) -> dict[str, Any]:
        now = time.time()
        tiers = {}
        for name, tier in self.config.tiers.items():
            tiers[name] = {
                "enabled": tier.enable,
                "armed_until": self.armed_until[name] if self.armed_until[name] > now else None,
                "shell": tier.shell_enable,
                "totp": self.totp.enrolled(f"{name}-arm") and self.totp.enrolled(f"{name}-direct"),
            }
        return {
            "version": __version__,
            "role": ROLE,
            "started_at": self.started_at,
            "tiers": tiers,
            "jobs": len(self.jobs),
            "shells": len(self.shells),
            "lockdown": self.locked_down,
            "vm": {"unit": self.config.vm_unit, "state": self.vm_state} if self.config.vm_unit else None,
            "templates": sorted(self.config.templates),
            "desktop": {
                "enabled": self.config.desktop.enable,
                "present": self.present(),
                "dnd_until": self.presence.dnd_until if self.presence.dnd_until > now else None,
            },
        }

    def _audit(self, event: str, **fields: Any) -> None:
        audit.info(json.dumps({"event": event, "host": self.config.name, **fields}, default=str))

    # --- the broker channel ----------------------------------------------------------

    async def on_message(self, msg: dict[str, Any]) -> None:
        kind = msg.get("type")
        handler = {
            "hostexec.precheck": self._precheck,
            "hostexec.authorize": self._authorize,
            "job.start": self._job_start,
            "job.kill": self._job_kill,
            "job.ack": self._job_ack,
            "shell.open": self._shell_open,
            "shell.exec": self._shell_exec,
            "shell.close": self._shell_close,
            "arm": self._arm_remote,
            "disarm": self._disarm_remote,
            "lockdown": self._lockdown_remote,
            "unlock": self._unlock_remote,
            "dnd": self._dnd_remote,
            "prompt": self._prompt,
            "prompt.cancel": self._prompt_cancel,
        }.get(kind)
        if handler is None:
            log.debug("ignoring %r from the broker", kind)
            return
        try:
            reply = {"ok": True, "data": await handler(msg) or {}}
        except (Refused, hx.SpecError, TotpError) as exc:
            reply = {"ok": False, "error": str(exc)}
        except Exception as exc:
            log.exception("handling %r failed", kind)
            reply = {"ok": False, "error": f"hostd error: {exc}"}
        if msg.get("call_id") and self.channel:
            await self.channel.send({"type": "reply", "call_id": msg["call_id"], **reply})

    # --- the decision ------------------------------------------------------------------

    def _tier(self, tier: Any) -> str:
        if tier not in hx.TIERS:
            raise Refused("tier must be user or root")
        if not self.config.tiers[tier].enable:
            raise Refused(f"the {tier} tier is not enabled on {self.config.name}")
        return tier

    def _job_id(self, value: Any) -> str:
        if not isinstance(value, str) or not ID_RE.fullmatch(value):
            raise Refused("malformed job id")
        return value

    def _normalize(self, raw: Any, *, shell_command: bool = False) -> dict[str, Any]:
        """Re-validate a spec from scratch (nothing the broker sent is taken
        on trust) and resolve it to what would actually run."""
        if not isinstance(raw, dict):
            raise Refused("malformed job")
        if raw.get("host") != self.config.name:
            raise Refused(f"that job is for {raw.get('host')!r}, this is {self.config.name}")
        kind = raw.get("kind")
        if kind not in ("run", "tpl"):
            raise Refused("not a runnable job")
        spec = hx.make_spec(
            kind=kind,
            host=self.config.name,
            tier=raw.get("tier"),
            argv=raw.get("argv"),
            template=raw.get("template"),
            params=raw.get("params"),
            cwd=raw.get("cwd"),
            env=raw.get("env"),
            timeout=raw.get("timeout") or self.config.default_timeout_secs,
            stdin=raw.get("stdin"),
        )
        if kind == "tpl":
            if shell_command:
                raise Refused("templates don't run inside a shell")
            template = self.config.templates.get(spec["template"])
            if template is None:
                raise Refused(f"no template {spec['template']!r} on {self.config.name}")
            if template["tier"] != spec["tier"]:
                raise Refused(f"template {spec['template']!r} is a {template['tier']}-tier template")
            # This host's own template decides the command; the broker's
            # copy is for display.
            spec["argv"] = hx.expand_template(template, spec["params"])
        self._tier(spec["tier"])
        if spec["timeout"] > self.config.max_timeout_secs:
            raise Refused(f"timeout exceeds this host's maximum ({self.config.max_timeout_secs}s)")
        extra = sorted(set(spec["env"]) - set(self.config.env_allow))
        if extra:
            raise Refused(f"environment variables not allowed on this host: {', '.join(extra)}")
        for pattern in self.config.deny_commands:
            if match_argv(pattern, spec["argv"], loose_program=True):
                raise Refused("that command is denied by this host's policy")
        return spec

    def _take_authorization(self, job_id: str, digest: str) -> bool:
        authz = self.authorizations.pop(job_id, None)
        return authz is not None and authz.expires_at > time.time() and authz.digest == digest

    def _admit(self, job_id: str, raw: dict[str, Any], spec: dict[str, Any], evidence: dict[str, Any]) -> str:
        """§8.5, in order. Returns what the job is admitted on; raises Refused."""
        if self.locked_down:
            raise Refused(f"{self.config.name} is locked down")
        tier = spec["tier"]
        # The TOTP code was given for the request as the broker described it.
        if self._take_authorization(job_id, hx.digest(raw)):
            return "totp"
        if spec["kind"] == "run" and tier == "user" and any(
            match_argv(p, spec["argv"]) for p in self.config.auto_commands
        ):
            return "auto"
        source = evidence.get("source")
        if source not in SOURCES:
            raise Refused("no approval evidence")
        cfg = self.config.tiers[tier]
        if self.armed(tier):
            if evidence.get("window"):
                if cfg.accept_approve_all:
                    return "armed+window"
                raise Refused(f"{self.config.name} does not accept approve-all windows for the {tier} tier")
            if source == "human":
                return "armed+human"
            if cfg.accept_machine_approvals:
                return f"armed+{source}"
            raise Refused(
                f"{self.config.name} only accepts a human's approval for the {tier} tier (this one came from {source})"
            )
        raise Refused(
            f"not_armed: the {tier} tier of {self.config.name} is not armed — arm it (/arm) or approve with a TOTP code"
        )

    async def _precheck(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Would a job of this shape be admitted now? Consumes nothing; lets
        the broker tell a human "arm first" before they approve."""
        if msg.get("kind") == "shell":
            tier = self._tier(msg.get("tier"))
            cfg = self.config.tiers[tier]
            if not cfg.shell_enable:
                raise Refused(f"{tier} shells are not enabled on {self.config.name}")
            if self.locked_down:
                raise Refused(f"{self.config.name} is locked down")
            duration = msg.get("duration")
            if isinstance(duration, int) and duration > cfg.shell_max_duration_secs:
                raise Refused(
                    f"a {tier} shell on {self.config.name} lasts at most {cfg.shell_max_duration_secs}s"
                )
            return {"needs": "totp"}
        raw = msg.get("spec")
        spec = self._normalize(raw)
        evidence = {"source": msg.get("source"), "window": bool(msg.get("window"))}
        if msg.get("totp"):
            if self.locked_down:
                raise Refused(f"{self.config.name} is locked down")
            return {"via": "totp"}
        # A stand-in id: there is no authorization to consume in a precheck.
        return {"via": self._admit("precheck", raw, spec, evidence)}

    async def _authorize(self, msg: dict[str, Any]) -> dict[str, Any]:
        """A direct TOTP code for one request. Verified and spent here; the
        job (or shell) it approves must follow with the same digest."""
        job_id = self._job_id(msg.get("job_id"))
        tier = self._tier(msg.get("tier"))
        digest = msg.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Refused("malformed digest")
        if self.locked_down:
            raise Refused(f"{self.config.name} is locked down")
        try:
            self.totp.verify(f"{tier}-direct", str(msg.get("totp") or ""))
        except TotpError as exc:
            self._audit("totp.refused", job=job_id, tier=tier, why=str(exc))
            raise
        now = time.time()
        self.authorizations = {k: v for k, v in self.authorizations.items() if v.expires_at > now}
        self.authorizations[job_id] = Authorization(digest, now + AUTHZ_TTL_SECS)
        self._audit("totp.accepted", job=job_id, tier=tier, digest=digest)
        return {"authorized": True}

    # --- jobs ----------------------------------------------------------------------------

    async def _job_start(self, msg: dict[str, Any]) -> dict[str, Any]:
        job_id = self._job_id(msg.get("job_id"))
        if job_id in self.jobs or self._spool_path(job_id).exists():
            raise Refused("that job already ran here")
        raw = msg.get("spec")
        evidence = msg.get("evidence") if isinstance(msg.get("evidence"), dict) else {}
        try:
            spec = self._normalize(raw)
            via = self._admit(job_id, raw, spec, evidence)
        except (Refused, hx.SpecError) as exc:
            self._audit("job.refused", job=job_id, why=str(exc), evidence=evidence, spec=_loggable(raw))
            raise
        self._audit("job.admitted", job=job_id, via=via, evidence=evidence, spec=_loggable(spec))
        self._launch(job_id, spec, None)
        return {"started": True, "via": via}

    def _launch(self, job_id: str, spec: dict[str, Any], shell_id: str | None) -> None:
        self._spool_write(job_id, {"status": "running", "tier": spec["tier"], "at": time.time()})
        job = RunningJob(tier=spec["tier"], task=None, shell_id=shell_id)  # type: ignore[arg-type]
        job.task = self._task(self._run_job(job_id, spec, job), f"job:{job_id}")
        self.jobs[job_id] = job

    async def _run_job(self, job_id: str, spec: dict[str, Any], job: RunningJob) -> None:
        started = time.time()
        size = 0
        truncated = False

        async def on_output(chunk: bytes) -> None:
            nonlocal size, truncated
            job.chunks.append(chunk)
            size += len(chunk)
            # Keep the end: that is where a failure explains itself.
            while size - len(job.chunks[0]) >= hx.MAX_OUTPUT_BYTES:
                size -= len(job.chunks.pop(0))
                truncated = True

        error = None
        exit_code: int | None = None
        try:
            exit_code = await self.executor.run(
                job_id,
                spec["tier"],
                spec["argv"],
                spec["cwd"],
                spec["env"],
                spec["timeout"],
                spec["stdin"].encode() if spec["stdin"] is not None else None,
                on_output,
            )
        except asyncio.CancelledError:
            await self.executor.kill(job_id, spec["tier"])
            error = "hostd stopped while the job was running"
        except Exception as exc:
            error = f"could not run: {exc}"
        output = b"".join(job.chunks)[-hx.MAX_OUTPUT_BYTES :]
        if job.killed and error is None:
            error = "killed"
        result = {
            "job_id": job_id,
            "exit_code": exit_code,
            "error": error,
            "duration_secs": round(time.time() - started, 3),
            "bytes": len(output),
            "sha256": hashlib.sha256(output).hexdigest(),
            "truncated": truncated,
        }
        self._audit("job.done", **{k: v for k, v in result.items() if k != "job_id"}, job=job_id)
        self._spool_write(
            job_id,
            {"status": "done", "at": time.time(), "result": result, "output": base64.b64encode(output).decode()},
        )
        self.jobs.pop(job_id, None)
        await self._send_result(job_id)

    async def _job_kill(self, msg: dict[str, Any]) -> dict[str, Any]:
        job_id = self._job_id(msg.get("job_id"))
        return {"killed": await self._kill(job_id)}

    async def _kill(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if job is None:
            return False
        job.killed = True
        self._audit("job.kill", job=job_id)
        await self.executor.kill(job_id, job.tier)
        return True

    async def _job_ack(self, msg: dict[str, Any]) -> None:
        job_id = self._job_id(msg.get("job_id"))
        path = self._spool_path(job_id)
        try:
            if json.loads(path.read_text()).get("status") == "done":
                path.unlink()
        except (OSError, ValueError):
            pass

    # --- results kept until the broker has them ---------------------------------------------

    def _spool_path(self, job_id: str) -> Path:
        return self.config.state_dir / "jobs" / f"{job_id}.json"

    def _spool_write(self, job_id: str, data: dict[str, Any]) -> None:
        path = self._spool_path(job_id)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(path)

    def _recover_spool(self) -> None:
        """Jobs that were running when hostd last stopped: their outcome is
        unknown, and the broker is told exactly that."""
        directory = self.config.state_dir / "jobs"
        if not directory.is_dir():
            return
        now = time.time()
        for path in directory.glob("*.json"):
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                path.unlink(missing_ok=True)
                continue
            if data.get("status") == "running":
                job_id = path.stem
                result = {
                    "job_id": job_id, "exit_code": None, "duration_secs": None, "bytes": 0,
                    "sha256": hashlib.sha256(b"").hexdigest(), "truncated": False,
                    "error": "hostd restarted while the job was running; its outcome is unknown",
                }
                self._spool_write(job_id, {"status": "done", "at": now, "result": result, "output": ""})
            elif now - data.get("at", now) > SPOOL_KEEP_SECS:
                path.unlink(missing_ok=True)

    async def _send_result(self, job_id: str) -> bool:
        if self.channel is None:
            return False
        try:
            data = json.loads(self._spool_path(job_id).read_text())
        except (OSError, ValueError):
            return False
        if data.get("status") != "done":
            return False
        output = base64.b64decode(data.get("output") or "")
        for seq, start in enumerate(range(0, len(output), hx.OUTPUT_CHUNK_BYTES)):
            chunk = output[start : start + hx.OUTPUT_CHUNK_BYTES]
            if not await self.channel.send(
                {"type": "job.output", "job_id": job_id, "seq": seq, "data": base64.b64encode(chunk).decode()}
            ):
                return False
        return await self.channel.send({"type": "job.done", **data["result"]})

    async def _resend_results(self) -> None:
        """Results the broker hasn't acknowledged, again: after a reconnect,
        and for as long as they stay unacknowledged."""
        assert self.channel is not None
        directory = self.config.state_dir / "jobs"
        while True:
            await self.channel.connected.wait()
            if directory.is_dir():
                for path in sorted(directory.glob("*.json")):
                    try:
                        fresh = time.time() - path.stat().st_mtime < RESEND_AFTER_SECS
                    except OSError:
                        continue
                    if path.stem not in self.jobs and not fresh:
                        await self._send_result(path.stem)
            await asyncio.sleep(RESEND_AFTER_SECS)

    # --- shells (§8.7) ------------------------------------------------------------------------

    async def _shell_open(self, msg: dict[str, Any]) -> dict[str, Any]:
        shell_id = self._job_id(msg.get("shell_id"))
        raw = msg.get("spec")
        if not isinstance(raw, dict) or raw.get("host") != self.config.name:
            raise Refused("malformed shell request")
        spec = hx.shell_spec(self.config.name, raw.get("tier"), raw.get("duration"))
        tier = self._tier(spec["tier"])
        cfg = self.config.tiers[tier]
        try:
            if self.locked_down:
                raise Refused(f"{self.config.name} is locked down")
            if not cfg.shell_enable:
                raise Refused(f"{tier} shells are not enabled on {self.config.name}")
            if spec["duration"] > cfg.shell_max_duration_secs:
                raise Refused(
                    f"a {tier} shell on {self.config.name} lasts at most {cfg.shell_max_duration_secs}s"
                )
            # Nothing but a direct TOTP code for this exact shell opens one:
            # arming, windows and rules never do.
            if not self._take_authorization(shell_id, hx.digest(spec)):
                raise Refused("a shell is opened with a TOTP code only")
        except Refused as exc:
            self._audit("shell.refused", shell=shell_id, tier=tier, why=str(exc))
            raise
        # The expiry is kept here: the broker can end a shell, never extend one.
        expires_at = time.time() + spec["duration"]
        shell = Shell(tier=tier, expires_at=expires_at)
        shell.timer = self._task(self._expire_shell(shell_id, spec["duration"]), f"shell:{shell_id}")
        self.shells[shell_id] = shell
        self._audit("shell.open", shell=shell_id, tier=tier, expires_at=expires_at)
        return {"expires_at": expires_at}

    async def _expire_shell(self, shell_id: str, after: float) -> None:
        await asyncio.sleep(after)
        await self._end_shell(shell_id, "expired")

    async def _end_shell(self, shell_id: str, why: str) -> bool:
        shell = self.shells.pop(shell_id, None)
        if shell is None:
            return False
        if shell.timer and shell.timer is not asyncio.current_task():
            shell.timer.cancel()
        for job_id, job in list(self.jobs.items()):
            if job.shell_id == shell_id:
                await self._kill(job_id)
        self._audit("shell.close", shell=shell_id, why=why)
        return True

    async def _shell_close(self, msg: dict[str, Any]) -> dict[str, Any]:
        return {"closed": await self._end_shell(self._job_id(msg.get("shell_id")), "closed by the broker")}

    async def _shell_exec(self, msg: dict[str, Any]) -> dict[str, Any]:
        shell_id = self._job_id(msg.get("shell_id"))
        job_id = self._job_id(msg.get("job_id"))
        if job_id in self.jobs or self._spool_path(job_id).exists():
            raise Refused("that job already ran here")
        raw = msg.get("spec")
        try:
            if self.locked_down:
                raise Refused(f"{self.config.name} is locked down")
            shell = self.shells.get(shell_id)
            if shell is None or shell.expires_at <= time.time():
                raise Refused("no such shell on this host (expired, closed, or hostd restarted)")
            spec = self._normalize(raw, shell_command=True)
            if spec["tier"] != shell.tier:
                raise Refused(f"that is a {shell.tier} shell")
        except (Refused, hx.SpecError) as exc:
            self._audit("shell.exec.refused", shell=shell_id, job=job_id, why=str(exc), spec=_loggable(raw))
            raise
        # Logged before it runs.
        self._audit("shell.exec", shell=shell_id, job=job_id, spec=_loggable(spec))
        self._launch(job_id, spec, shell_id)
        return {"started": True}

    # --- arming --------------------------------------------------------------------------------

    def arm(self, tier: str, seconds: int, via: str) -> float:
        tier = self._tier(tier)
        if self.locked_down:
            raise Refused(f"{self.config.name} is locked down")
        seconds = min(seconds, self.config.tiers[tier].max_arm_secs)
        self.armed_until[tier] = time.time() + seconds
        self._audit("arm", tier=tier, seconds=seconds, via=via)
        return self.armed_until[tier]

    def disarm(self, tier: str | None, via: str) -> None:
        for name in [tier] if tier else list(self.armed_until):
            if name in self.armed_until:
                self.armed_until[name] = 0.0
        self._audit("disarm", tier=tier or "all", via=via)

    async def _arm_remote(self, msg: dict[str, Any]) -> dict[str, Any]:
        tier = self._tier(msg.get("tier"))
        seconds = duration_secs(msg.get("duration") or self.config.tiers[tier].max_arm_secs)
        self.totp.verify(f"{tier}-arm", str(msg.get("totp") or ""))
        return {"armed_until": self.arm(tier, seconds, "totp via the broker")}

    async def _disarm_remote(self, msg: dict[str, Any]) -> dict[str, Any]:
        # Needs no proof: it only ever takes authority away.
        tier = msg.get("tier")
        self.disarm(tier if tier in hx.TIERS else None, "the broker")
        return {"disarmed": True}

    # --- the kill switch (§9) --------------------------------------------------------------------

    async def lockdown(self, via: str, kill_vm: bool = False) -> dict[str, Any]:
        self.lockdown_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lockdown_file.write_text(json.dumps({"at": time.time(), "via": via}))
        self.disarm(None, f"lockdown ({via})")
        self.authorizations.clear()
        for shell_id in list(self.shells):
            await self._end_shell(shell_id, "lockdown")
        for job_id in list(self.jobs):
            await self._kill(job_id)
        vm = None
        if self.config.vm_unit:
            # From outside: nothing inside the guest is asked to cooperate.
            action = "stop" if kill_vm else "freeze"
            code, out = await self.executor.unit_action(action, self.config.vm_unit)
            vm = f"{action}: {'ok' if code == 0 else out or code}"
        self._audit("lockdown", via=via, vm=vm)
        return {"locked": True, "vm": vm}

    async def unlock(self, via: str) -> dict[str, Any]:
        self.lockdown_file.unlink(missing_ok=True)
        vm = None
        if self.config.vm_unit:
            code, out = await self.executor.unit_action("thaw", self.config.vm_unit)
            vm = f"thaw: {'ok' if code == 0 else out or code}"
        self._audit("unlock", via=via, vm=vm)
        return {"locked": False, "vm": vm}

    async def _lockdown_remote(self, msg: dict[str, Any]) -> dict[str, Any]:
        # No proof needed for the same reason as disarm.
        return await self.lockdown("the broker", kill_vm=bool(msg.get("kill_vm")))

    async def _unlock_remote(self, msg: dict[str, Any]) -> dict[str, Any]:
        """The broker alone can't undo a lockdown: it takes a root arm code
        (or root, locally)."""
        self.totp.verify("root-arm", str(msg.get("totp") or ""))
        return await self.unlock("root arm code via the broker")

    async def _watch_vm(self) -> None:
        while True:
            try:
                code, out = await self.executor.unit_action("is-active", self.config.vm_unit)
                self.vm_state = out.splitlines()[0] if out else ("active" if code == 0 else "unknown")
                if self.locked_down and self.vm_state == "active":
                    self.vm_state = "frozen"
            except Exception:
                self.vm_state = "unknown"
            await asyncio.sleep(30)

    # --- hostctl (local socket) ------------------------------------------------------------------

    def _user_uid(self) -> int | None:
        try:
            return pwd.getpwnam(self.config.user).pw_uid if self.config.user else None
        except KeyError:
            return None

    async def ctl(self, method: str, params: dict[str, Any], token: str | None, uid: int) -> Any:
        """root may do anything; the configured user may see status, arm and
        disarm their own tier, and report presence."""
        is_root = uid == 0
        if not is_root and uid != self._user_uid():
            raise ApiError("not for this user")

        def root_only() -> None:
            if not is_root:
                raise ApiError(f"{method} needs root")

        try:
            if method == "status":
                return self.status()
            if method == "arm":
                tier = params.get("tier") or "user"
                if tier != "user":
                    root_only()
                return {"armed_until": self.arm(tier, duration_secs(params.get("duration") or "1h"), f"local uid {uid}")}
            if method == "disarm":
                self.disarm(params.get("tier"), f"local uid {uid}")
                return {"disarmed": True}
            if method == "lockdown":
                return await self.lockdown(f"local uid {uid}", kill_vm=bool(params.get("kill_vm")))
            if method == "unlock":
                root_only()
                return await self.unlock(f"local uid {uid}")
            if method == "dnd":
                seconds = duration_secs(params["duration"]) if params.get("duration") else 0
                self.presence.dnd_until = time.time() + seconds if seconds else 0.0
                await self._presence_changed()
                return {"dnd_until": self.presence.dnd_until or None}
            if method == "presence":
                self._presence_event(str(params.get("state")))
                await self._presence_changed()
                return {"present": self.present()}
        except (Refused, TotpError) as exc:
            raise ApiError(str(exc)) from None
        raise ApiError(f"unknown method {method!r}")

    # --- the desktop (hostd-user) ---------------------------------------------------------------

    @property
    def _presence_file(self) -> Path:
        # In /run: it survives hostd restarts, not reboots (after which the
        # session, and what we knew about it, is new anyway).
        return self.config.runtime_dir / "presence.json"

    def _load_presence(self) -> None:
        try:
            saved = json.loads(self._presence_file.read_text())
        except (OSError, ValueError):
            return
        p = self.presence
        for key in ("explicit_idle", "explicit_locked"):
            if isinstance(saved.get(key), bool):
                setattr(p, key, saved[key])
        if isinstance(saved.get("idle_since"), (int, float)):
            p.idle_since = float(saved["idle_since"])

    def _save_presence(self) -> None:
        p = self.presence
        try:
            self._presence_file.parent.mkdir(parents=True, exist_ok=True)
            self._presence_file.write_text(
                json.dumps({"explicit_idle": p.explicit_idle, "explicit_locked": p.explicit_locked,
                            "idle_since": p.idle_since})
            )
        except OSError:
            pass

    def _presence_event(self, state: str) -> None:
        p = self.presence
        if state == "idle":
            p.explicit_idle, p.idle_since = True, time.time()
        elif state == "active":
            p.explicit_idle, p.idle_since = False, None
        elif state == "locked":
            p.explicit_locked = True
        elif state == "unlocked":
            p.explicit_locked = False
            p.explicit_idle, p.idle_since = False, None
        else:
            raise ApiError("presence state: idle | active | locked | unlocked")
        self._save_presence()

    async def _presence_changed(self) -> None:
        if self.channel:
            await self.channel.send({"type": "presence", **self.status()["desktop"]})

    async def _dnd_remote(self, msg: dict[str, Any]) -> dict[str, Any]:
        seconds = duration_secs(msg["duration"]) if msg.get("duration") else 0
        self.presence.dnd_until = time.time() + seconds if seconds else 0.0
        return {"dnd_until": self.presence.dnd_until or None}

    async def _user_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """hostd-user: reports presence, shows prompts, sends answers back."""
        try:
            if peer_uid(writer) != self._user_uid():
                writer.close()
                return
            previous, self._user_writer = self._user_writer, writer
            if previous is not None:
                previous.close()
            self.presence.connected = True
            while line := await reader.readline():
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("type") == "presence":
                    was = self.present()
                    p = self.presence
                    idle, locked = msg.get("idle_secs"), msg.get("locked")
                    p.idle_secs = float(idle) if isinstance(idle, (int, float)) else None
                    p.locked = locked if isinstance(locked, bool) else None
                    p.fullscreen = bool(msg.get("fullscreen"))
                    p.reported_at = time.time()
                    if (
                        msg.get("fresh")
                        and self.config.desktop.idle_source == "hooks"
                        and p.explicit_idle is None
                        and p.explicit_locked is None
                    ):
                        # The helper just started with the session, and no
                        # hook has said otherwise yet: you just logged in.
                        self._presence_event("unlocked")
                    if self.present() != was:
                        await self._presence_changed()
                elif msg.get("type") == "answer" and isinstance(msg.get("id"), str):
                    answer = msg.get("answer")
                    if answer not in ("allow", "deny", "mute", "discord", "timeout"):
                        answer = "timeout"
                    self._audit("prompt.answer", prompt=msg["id"], answer=answer)
                    if self.channel:
                        await self.channel.send(
                            {"type": "prompt.answer", "prompt_id": msg["id"], "answer": answer}
                        )
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            if self._user_writer is writer:
                self._user_writer = None
                self.presence.connected = False
                await self._presence_changed()
            writer.close()

    async def _to_user(self, msg: dict[str, Any]) -> bool:
        writer = self._user_writer
        if writer is None:
            return False
        try:
            writer.write(json.dumps(msg).encode() + b"\n")
            await writer.drain()
        except ConnectionError:
            return False
        return True

    async def _prompt(self, msg: dict[str, Any]) -> dict[str, Any]:
        prompt_id = self._job_id(msg.get("prompt_id"))
        if not self.present():
            raise Refused("nobody is at this desktop")
        shown = await self._to_user(
            {
                "type": "prompt",
                "id": prompt_id,
                "title": str(msg.get("title") or "agent-auth")[:200],
                "text": str(msg.get("text") or "")[:4000],
                "timeout": min(int(msg.get("timeout") or 90), self.config.desktop.prompt_timeout_secs),
            }
        )
        if not shown:
            raise Refused("nobody is at this desktop")
        self._audit("prompt.shown", prompt=prompt_id, request=msg.get("request_id"))
        return {"shown": True}

    async def _prompt_cancel(self, msg: dict[str, Any]) -> dict[str, Any]:
        await self._to_user({"type": "cancel", "id": self._job_id(msg.get("prompt_id"))})
        return {}


def _loggable(spec: Any) -> Any:
    """A spec for the journal: stdin as a size, not its content."""
    if not isinstance(spec, dict):
        return None
    out = dict(spec)
    if out.get("stdin") is not None:
        out["stdin"] = f"<{len(str(out['stdin']))} chars>"
    return out
