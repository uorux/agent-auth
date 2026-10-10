"""Commands on hosts, as seen from the broker (docs/sandbox-design.md §8, §9).

The broker's part is bookkeeping and relaying: it validates and records what
was asked, carries the human's decision (and TOTP code) to the host's hostd,
keeps the job's result, and mirrors shells to Discord. Whether anything runs
is decided on the host, by hostd, from its own config and secrets — a `run`
the broker approved still fails if the host isn't armed and no TOTP code came
with it.

- A `run` / `tpl.<name>` grant is ONE execution: provisioning it starts the
  job (id = the request's id), and its result is kept in host_jobs.
- A `shell` grant is a window in which the agent may run commands one at a
  time; each is its own job, shown on Discord before it is sent to the host.
- Lockdown revokes grants here and tells every hostd (and sandboxd) to stop;
  hosts stay locked until unlocked with their own TOTP code or locally.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update

from .. import authority as authority_mod
from ..daemon_common import hostexec as hx
from ..db import Database
from ..models import AccessRequest, Agent, BrokerFlag, Daemon, Grant, HostJob, Rule, utcnow
from ..provisioners.base import RequestSpec, SpecValidationError
from .daemons import DaemonCallError, DaemonHub, LiveConnection
from .events import KeyedEvents
from .states import DecisionSource, GrantStatus, Platform, RuleAction

log = logging.getLogger(__name__)

HOST_ROLE = "host"
SANDBOX_ROLE = "sandbox"
# A sandbox gets this long to lock itself before its host freezes the VM.
SANDBOX_LOCKDOWN_TIMEOUT = 5.0
LOCKDOWN_FLAG = "lockdown"
CALL_TIMEOUT = 20
# Output arrives in chunks; a job's buffer is dropped past this.
MAX_BUFFER_BYTES = hx.MAX_OUTPUT_BYTES + hx.OUTPUT_CHUNK_BYTES
TAIL_LINES = 30


class HostExecError(Exception):
    """The host said no, or couldn't be asked. The text is for a human."""


def job_spec(capability: str, host: str, scope: dict[str, Any]) -> dict[str, Any]:
    """The canonical spec of a run/tpl request (what the digest is over)."""
    if capability.startswith("tpl."):
        return hx.make_spec(
            kind="tpl",
            host=host,
            tier=scope.get("tier"),
            template=capability[len("tpl."):],
            params=scope.get("params") or {},
            cwd=scope.get("cwd"),
            env=scope.get("env"),
            timeout=scope.get("timeout"),
            stdin=scope.get("stdin"),
        )
    return hx.make_spec(
        kind="run",
        host=host,
        tier=scope.get("tier"),
        argv=scope.get("argv"),
        cwd=scope.get("cwd"),
        env=scope.get("env"),
        timeout=scope.get("timeout"),
        stdin=scope.get("stdin"),
    )


def tail(output: str | None, lines: int = TAIL_LINES, limit: int = 1500) -> str:
    text = "\n".join((output or "").splitlines()[-lines:])
    return text[-limit:]


def job_out(job: HostJob, full: bool = True) -> dict[str, Any]:
    out = {
        "job_id": job.id,
        "host": job.host,
        "tier": job.tier,
        "status": job.status,
        "exit_code": job.exit_code,
        "error": job.error,
        "duration_ms": job.duration_ms,
        "output_bytes": job.output_bytes,
        "output_sha256": job.output_sha256,
        "truncated": job.truncated,
        "command": job.spec.get("argv") or job.spec.get("template"),
    }
    if job.status in ("done", "refused", "lost"):
        out["output"] = job.output if full else tail(job.output)
    return out


class HostExecService:
    def __init__(self, db: Database, hub: DaemonHub, events: KeyedEvents):
        self.db = db
        self.hub = hub
        self.events = events
        self.service = None  # RequestService, via bind()
        self.a2a = None
        # policy/risk.Watcher: looks at shell commands, and commands no human
        # saw individually, as they run. None = nobody is watching.
        self.watcher = None
        self._watch_tasks: set[asyncio.Task] = set()
        self._buffers: dict[tuple[str, str], list[bytes]] = {}
        hub.handle("job.output", self._on_output)
        hub.handle("job.done", self._on_done)
        hub.on_connect(self._on_connect)

    def bind(self, service, a2a=None) -> None:
        self.service = service
        self.a2a = a2a
        service.gates[Platform.HOSTEXEC] = self.gate

    # --- talking to hosts ----------------------------------------------------------

    async def call(self, host: str, payload: dict[str, Any], timeout: float = CALL_TIMEOUT) -> dict[str, Any]:
        try:
            return await self.hub.call(HOST_ROLE, host, payload, timeout=timeout)
        except DaemonCallError as exc:
            raise HostExecError(str(exc)) from None

    async def hosts(self) -> list[dict[str, Any]]:
        """Paired hosts with what their hostd last reported."""
        async with self.db.session() as session:
            rows = (
                await session.execute(select(Daemon).where(Daemon.role == HOST_ROLE).order_by(Daemon.name))
            ).scalars().all()
        out = []
        for row in rows:
            status = row.last_status or {}
            out.append(
                {
                    "name": row.name,
                    "online": self.hub.is_online(HOST_ROLE, row.name),
                    "tiers": status.get("tiers") or {},
                    "lockdown": bool(status.get("lockdown")),
                    "templates": status.get("templates") or [],
                    "vm": status.get("vm"),
                    "desktop": status.get("desktop") or {},
                }
            )
        return out

    # --- the approval gate -----------------------------------------------------------

    async def final_spec(self, request: AccessRequest, agent: Agent, decision) -> dict[str, Any]:
        """The spec a human approval would be for, edits applied, normalized
        exactly as the grant will be."""
        assert self.service is not None
        provisioner = self.service.registry.get(Platform.HOSTEXEC)
        scope = decision.scope_override if decision.scope_override is not None else request.scope
        async with self.db.session() as session:
            spec = await provisioner.validate_request(
                session,
                RequestSpec(
                    agent=agent,
                    capability=request.capability,
                    resource=decision.resource_override or request.resource,
                    scope=dict(scope or {}),
                ),
            )
        capability, scope = authority_mod.split(
            Platform.HOSTEXEC, authority_mod.fold(Platform.HOSTEXEC, spec.capability, spec.scope)
        )
        if capability == "shell":
            from .service import HUMAN_MAX_DURATION_SECS

            duration = decision.duration_secs or self.service.engine.cap_duration(
                request.requested_duration_secs, None
            )
            return hx.shell_spec(spec.resource, scope.get("tier"), min(duration, HUMAN_MAX_DURATION_SECS))
        return job_spec(capability, spec.resource, scope)

    async def gate(self, request: AccessRequest, agent: Agent, decision) -> None:
        """Before a human approval takes effect: would the host accept it?
        With a TOTP code, the host verifies and spends it here, for this
        exact request. A refusal leaves the request pending."""
        from .service import TransitionError

        try:
            spec = await self.final_spec(request, agent, decision)
        except (SpecValidationError, hx.SpecError) as exc:
            raise TransitionError(f"rejected by validator: {exc}") from None
        host, shell = spec["host"], spec["kind"] == "shell"
        if shell and not decision.totp:
            raise TransitionError("a shell is approved with a TOTP code only (Approve with TOTP)")
        try:
            if shell:
                # Everything the host would refuse, before a code is spent on it.
                await self.call(
                    host,
                    {"type": "hostexec.precheck", "kind": "shell", "tier": spec["tier"], "duration": spec["duration"]},
                )
            else:
                await self.call(
                    host,
                    {
                        "type": "hostexec.precheck",
                        "job_id": request.id,  # it may already be approved at that host's desk
                        "spec": spec,
                        "source": "human",
                        "totp": bool(decision.totp),
                    },
                )
            if decision.totp:
                await self.call(
                    host,
                    {
                        "type": "hostexec.authorize",
                        "job_id": request.id,
                        "tier": spec["tier"],
                        "digest": hx.digest(spec),
                        "totp": decision.totp,
                    },
                )
        except HostExecError as exc:
            raise TransitionError(f"{host}: {exc}") from None

    async def precheck_window(self, host: str, tier: str) -> None:
        """Would this host honour an approve-all window for the tier now?"""
        probe = hx.make_spec(kind="run", host=host, tier=tier, argv=["true"])
        await self.call(host, {"type": "hostexec.precheck", "spec": probe, "source": "rule", "window": True})

    # --- jobs ---------------------------------------------------------------------------

    @staticmethod
    def evidence(request: AccessRequest) -> dict[str, Any]:
        """What the host is told about why the broker approved. The host
        believes it only while armed; a TOTP code needs no believing."""
        return {
            "request_id": request.id,
            "decided_by": request.decided_by,
            "source": request.decision_source.value if request.decision_source else None,
            "window": (request.decided_by or "").startswith("window:"),
        }

    async def start(self, grant: Grant, request: AccessRequest) -> dict[str, Any]:
        """Provision a hostexec grant: start its one job, or open its shell."""
        host = grant.resource
        if grant.capability == "shell":
            spec = hx.shell_spec(host, grant.scope.get("tier"), request.approved_duration_secs)
            data = await self.call(host, {"type": "shell.open", "shell_id": request.id, "spec": spec})
            return {"shell_id": request.id, "host": host, "tier": spec["tier"], "expires_at": data.get("expires_at")}
        spec = job_spec(grant.capability, host, grant.scope)
        # Committed before the host is asked: a fast job's result must find its row.
        async with self.db.session() as session:
            session.add(
                HostJob(
                    id=request.id,
                    grant_id=grant.id,
                    request_id=request.id,
                    agent_id=grant.agent_id,
                    host=host,
                    tier=spec["tier"],
                    spec=spec,
                    status="starting",
                )
            )
        try:
            data = await self.call(
                host,
                {"type": "job.start", "job_id": request.id, "spec": spec, "evidence": self.evidence(request)},
            )
        except HostExecError as exc:
            await self._set_status(request.id, "refused", error=str(exc))
            raise
        await self._set_status(request.id, "running", via=data.get("via"))
        if request.decision_source != DecisionSource.HUMAN or self.evidence(request)["window"]:
            # Nobody looked at this one command: a rule, a window or the
            # reviewer let it through.
            async with self.db.session() as session:
                job = await session.get(HostJob, request.id)
            self._watch(request, job)
        return {"job_id": request.id, "host": host}

    def _watch(self, request: AccessRequest, job: HostJob) -> None:
        """Have the watcher look at a command that is now running. Never in
        its way: a task of its own, and only ever a message to the operator."""
        if self.watcher is None or job is None:
            return
        task = asyncio.create_task(self._watched(request, job))
        self._watch_tasks.add(task)
        task.add_done_callback(self._watch_tasks.discard)

    async def _watched(self, request: AccessRequest, job: HostJob) -> None:
        try:
            async with self.db.session() as session:
                agent = await session.get(Agent, job.agent_id)
                earlier = []
                if job.shell_id:
                    rows = (
                        await session.execute(
                            select(HostJob.spec)
                            .where(HostJob.shell_id == job.shell_id, HostJob.id != job.id)
                            .order_by(HostJob.created_at)
                        )
                    ).scalars().all()
                    earlier = [list((spec or {}).get("argv") or []) for spec in rows]
            verdict = await self.watcher.assess(
                agent.name if agent else "?", job.host, job.tier, request.justification, earlier,
                list(job.spec.get("argv") or []),
            )
            if verdict is None or verdict[0] != "alarming":
                return
            log.warning("watch: %s on %s (%s): %s", job.id, job.host, job.tier, verdict[1])
            await self.service.notifier.watch_alert(
                request, job, f"watch ({self.watcher.model}, advisory): {verdict[1]}"
            )
        except Exception:
            log.exception("watching job %s failed", job.id)

    async def _set_status(self, job_id: str, status: str, **fields: Any) -> None:
        async with self.db.session() as session:
            # Never over a result that already arrived.
            await session.execute(
                update(HostJob)
                .where(HostJob.id == job_id, HostJob.status == "starting")
                .values(status=status, **fields)
            )
            if "via" in fields:
                await session.execute(update(HostJob).where(HostJob.id == job_id).values(via=fields["via"]))
        if status != "running":
            self.events.notify(f"job:{job_id}")

    async def _on_output(self, live: LiveConnection, msg: dict[str, Any]) -> None:
        job_id, data, seq = msg.get("job_id"), msg.get("data"), msg.get("seq")
        if live.role != HOST_ROLE or not isinstance(job_id, str) or not isinstance(data, str):
            return
        key = (live.name, job_id)
        if seq == 0:
            self._buffers[key] = []
        chunks = self._buffers.setdefault(key, [])
        try:
            chunks.append(base64.b64decode(data, validate=True))
        except ValueError:
            return
        if sum(len(c) for c in chunks) > MAX_BUFFER_BYTES:
            self._buffers[key] = []

    async def _on_done(self, live: LiveConnection, msg: dict[str, Any]) -> None:
        job_id = msg.get("job_id")
        if live.role != HOST_ROLE or not isinstance(job_id, str):
            return
        output = b"".join(self._buffers.pop((live.name, job_id), []))
        if msg.get("sha256") != hashlib.sha256(output).hexdigest():
            # A chunk went missing (reconnect mid-result): no ack, so the host
            # sends the whole result again.
            log.warning("result of job %s from %s is incomplete; waiting for a resend", job_id, live.name)
            return
        async with self.db.session() as session:
            job = await session.get(HostJob, job_id)
            # Only the host the job was sent to may report it.
            if job is None or job.host != live.name:
                log.warning("host %s reported a job that isn't its own: %s", live.name, job_id)
                return
            fresh = job.status in ("starting", "running")
            if fresh:
                exit_code, duration = msg.get("exit_code"), msg.get("duration_secs")
                job.status = "done"
                job.exit_code = exit_code if isinstance(exit_code, int) else None
                job.error = str(msg["error"])[:2000] if msg.get("error") else None
                job.output = output.decode(errors="replace")
                job.output_bytes = len(output)
                job.output_sha256 = msg["sha256"]
                job.truncated = bool(msg.get("truncated"))
                job.duration_ms = int(duration * 1000) if isinstance(duration, (int, float)) else None
                job.finished_at = utcnow()
            request = await session.get(AccessRequest, job.request_id)
        await self.hub.send(HOST_ROLE, live.name, {"type": "job.ack", "job_id": job_id})
        if not fresh:
            return
        self.events.notify(f"job:{job_id}")
        if self.service is not None:
            try:
                await self.service.notifier.job_finished(request, job)
            except Exception:
                log.exception("notifier.job_finished failed for %s", job_id)

    async def get_job(self, job_id: str, agent_id: str, wait: float = 0) -> HostJob | None:
        """A job of this agent's, after waiting up to `wait` s for it to end."""
        import asyncio

        deadline = asyncio.get_running_loop().time() + wait
        while True:
            async with self.db.session() as session:
                job = await session.get(HostJob, job_id)
            if job is None or job.agent_id != agent_id:
                return None
            remaining = deadline - asyncio.get_running_loop().time()
            if job.status not in ("starting", "running") or remaining <= 0:
                return job
            await self.events.wait(f"job:{job_id}", timeout=min(remaining, 2.0))

    async def kill(self, job: HostJob) -> None:
        if job.status in ("starting", "running"):
            try:
                await self.call(job.host, {"type": "job.kill", "job_id": job.id}, timeout=10)
            except HostExecError as exc:
                log.info("could not kill job %s on %s: %s", job.id, job.host, exc)

    # --- shells ----------------------------------------------------------------------------

    async def shell_exec(self, grant_id: str, agent_id: str, body: dict[str, Any]) -> HostJob:
        """One command in an open shell. Shown on Discord before it is sent."""
        assert self.service is not None
        async with self.db.session() as session:
            grant = await session.get(Grant, grant_id)
            if (
                grant is None
                or grant.agent_id != agent_id
                or grant.platform != Platform.HOSTEXEC
                or grant.capability != "shell"
            ):
                raise LookupError("unknown shell")
            if grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
                raise HostExecError("that shell has ended")
            if await self.locked(session, grant.resource):
                raise HostExecError("locked down")
            request = await session.get(AccessRequest, grant.request_id)
            host, tier = grant.resource, grant.scope.get("tier")
        spec = hx.make_spec(
            kind="run",
            host=host,
            tier=tier,
            argv=body.get("argv"),
            cwd=body.get("cwd"),
            env=body.get("env"),
            timeout=body.get("timeout"),
            stdin=body.get("stdin"),
        )
        job = HostJob(
            id=str(uuid.uuid4()),
            grant_id=grant_id,
            request_id=request.id,
            agent_id=agent_id,
            host=host,
            tier=tier,
            shell_id=request.id,
            spec=spec,
            status="starting",
        )
        async with self.db.session() as session:
            session.add(job)
        # Before dispatch, and failing closed: a command nobody was shown
        # does not run.
        if not await self.service.notifier.shell_command(request, job):
            await self._set_status(job.id, "refused", error="could not show the command on Discord")
            raise HostExecError("could not show the command on Discord; not run")
        try:
            await self.call(host, {"type": "shell.exec", "shell_id": request.id, "job_id": job.id, "spec": spec})
        except HostExecError as exc:
            await self._set_status(job.id, "refused", error=str(exc))
            async with self.db.session() as session:
                refused = await session.get(HostJob, job.id)
            await self.service.notifier.job_finished(request, refused)
            raise
        await self._set_status(job.id, "running")
        self._watch(request, job)
        return job

    async def close_shell(self, grant: Grant) -> None:
        """Best effort: the host ends a shell at its own expiry regardless,
        and is told again when it next connects."""
        try:
            await self.call(grant.resource, {"type": "shell.close", "shell_id": grant.request_id}, timeout=10)
        except HostExecError as exc:
            log.info("shell %s on %s not closed yet: %s", grant.request_id, grant.resource, exc)

    # --- arming ------------------------------------------------------------------------------

    async def arm(self, host: str, tier: str, duration: str | int, totp: str) -> dict[str, Any]:
        return await self.call(host, {"type": "arm", "tier": tier, "duration": duration, "totp": totp})

    async def disarm(self, host: str, tier: str | None = None) -> dict[str, Any]:
        return await self.call(host, {"type": "disarm", "tier": tier})

    async def open_window(
        self, request: AccessRequest, agent: Agent, duration_secs: int, created_by: str
    ) -> tuple[Rule, list[str]]:
        """"Approve all": an expiring rule for this agent, host and tier (any
        command, never a shell), which also approves what is already waiting.
        The host must be armed and accept windows — checked now, and again by
        the host for every job."""
        assert self.service is not None
        tier = request.scope.get("tier")
        if request.capability == "shell":
            raise HostExecError("shells are approved one at a time, with a TOTP code")
        await self.precheck_window(request.resource, tier)
        async with self.db.session() as session:
            delegator = (
                await session.get(Agent, request.delegator_agent_id) if request.delegator_agent_id else None
            )
            rule = Rule(
                action=RuleAction.AUTO_APPROVE,
                agent_pattern=agent.name,
                delegator_pattern=delegator.name if delegator else None,
                platform=Platform.HOSTEXEC,
                resource_pattern=request.resource,
                authority={"action": "window", "tier": tier},
                created_by=created_by,
                notes=f"approve-all window ({tier} on {request.resource})",
                expires_at=utcnow() + timedelta(seconds=duration_secs),
            )
            session.add(rule)
            await session.flush()
            rule_id = rule.id
        return rule, await self.service.apply_rule_to_pending(rule_id)

    # --- lockdown (§9) -------------------------------------------------------------------------

    async def lockdown_state(self) -> dict[str, Any]:
        async with self.db.session() as session:
            flag = await session.get(BrokerFlag, LOCKDOWN_FLAG)
            return dict(flag.value) if flag else {}

    @staticmethod
    async def locked(session, host: str | None = None) -> bool:
        """Is the broker locked down, for everything or for this host?"""
        flag = await session.get(BrokerFlag, LOCKDOWN_FLAG)
        hosts = (flag.value if flag else {}).get("hosts") or []
        return "*" in hosts or (host is not None and host in hosts)

    async def lockdown(
        self, scope: str = "sandboxes", host: str | None = None, kill_vm: bool = False, by: str = ""
    ) -> dict[str, Any]:
        """scope "sandboxes": every agent VM's agents lose their grants, every
        host disarms, kills its jobs and freezes its VM. "all": the grants of
        every agent. "host": one host and its VM's agents."""
        assert self.service is not None
        if scope not in ("all", "sandboxes", "host") or (scope == "host" and not host):
            raise ValueError("scope: all | sandboxes | host (with a host name)")
        async with self.db.session() as session:
            flag = await session.get(BrokerFlag, LOCKDOWN_FLAG)
            if flag is None:
                flag = BrokerFlag(key=LOCKDOWN_FLAG, value={})
                session.add(flag)
            hosts = set(flag.value.get("hosts") or [])
            hosts.add(host if scope == "host" else "*")
            flag.value = {
                "hosts": sorted(hosts),
                "by": by,
                "at": datetime.now(timezone.utc).isoformat(),
                "scope": scope,
            }
            daemons = (await session.execute(select(Daemon))).scalars().all()
            agents = (await session.execute(select(Agent))).scalars().all()
        targets = [d for d in daemons if scope != "host" or d.name == host]
        sandbox_ids = {d.id for d in targets if d.role == SANDBOX_ROLE}
        if scope == "all":
            affected = agents
        else:
            affected = [a for a in agents if a.sandbox_id in sandbox_ids]
        # Stop what is running before tidying up the records. Sandboxes
        # first, briefly: once its host has frozen the VM a sandbox can't
        # answer any more. Then the hosts, which don't depend on them.
        reports: dict[str, str] = {}
        payload = {"type": "lockdown", "kill_vm": kill_vm}

        async def tell(daemon: Daemon, timeout: float) -> tuple[Daemon, dict[str, Any] | None, str]:
            try:
                return daemon, await self.hub.call(daemon.role, daemon.name, payload, timeout=timeout), ""
            except DaemonCallError as exc:
                return daemon, None, str(exc)

        sandboxes = [d for d in targets if d.role == SANDBOX_ROLE]
        others = [d for d in targets if d.role != SANDBOX_ROLE]
        answers = list(await asyncio.gather(*(tell(d, SANDBOX_LOCKDOWN_TIMEOUT) for d in sandboxes)))
        answers += await asyncio.gather(*(tell(d, CALL_TIMEOUT) for d in others))
        frozen = {d.name for d, data, _ in answers if d.role != SANDBOX_ROLE and data and data.get("vm")}
        for daemon, data, error in answers:
            key = f"{daemon.role}:{daemon.name}"
            if data is not None:
                reports[key] = "locked" + (f" · vm {data['vm']}" if data.get("vm") else "")
            elif daemon.role == SANDBOX_ROLE and daemon.name in frozen:
                # Told again when it connects (_on_connect).
                reports[key] = "did not answer; its VM is stopped by its host, and it is locked when it reconnects"
            else:
                reports[key] = f"NOT reached ({error}); it is locked when it reconnects"
        revoked = 0
        agent_ids = [a.id for a in affected]
        async with self.db.session() as session:
            grant_ids = (
                (
                    await session.execute(
                        select(Grant.id).where(Grant.status == GrantStatus.ACTIVE, Grant.agent_id.in_(agent_ids))
                    )
                ).scalars().all()
                if agent_ids
                else []
            )
        for grant_id in grant_ids:
            try:
                await self.service.revoke_grant(grant_id, "lockdown", by)
                revoked += 1
            except Exception:
                # Left to the scheduler: due at once.
                async with self.db.session() as session:
                    await session.execute(update(Grant).where(Grant.id == grant_id).values(expires_at=utcnow()))
        closed = 0
        if self.a2a is not None:
            for agent in affected:
                if agent.sandbox_id:
                    closed += await self.a2a.orphan_inbound_threads(agent.id)
        log.warning("LOCKDOWN (%s%s) by %s: %d grants revoked", scope, f" {host}" if host else "", by, revoked)
        return {"scope": scope, "host": host, "daemons": reports, "grants_revoked": revoked, "threads_closed": closed}

    async def unlock(self, host: str | None = None, totp: str | None = None, by: str = "") -> dict[str, Any]:
        """Without a host: clear the broker's side (and tell sandboxes). With
        a host and its root arm code: also unlock that host's hostd — which
        nothing the broker says alone can do."""
        reports: dict[str, str] = {}
        if host and totp:
            await self.call(host, {"type": "unlock", "totp": totp})
            reports[f"host:{host}"] = "unlocked"
        async with self.db.session() as session:
            flag = await session.get(BrokerFlag, LOCKDOWN_FLAG)
            if flag is not None:
                hosts = set(flag.value.get("hosts") or [])
                hosts = set() if host is None else hosts - {host}
                if hosts:
                    flag.value = {**flag.value, "hosts": sorted(hosts)}
                else:
                    await session.delete(flag)
            sandboxes = (
                await session.execute(select(Daemon).where(Daemon.role == SANDBOX_ROLE))
            ).scalars().all()
        for daemon in sandboxes:
            if host is None or daemon.name == host:
                if await self.hub.send(daemon.role, daemon.name, {"type": "unlock"}):
                    reports[f"sandbox:{daemon.name}"] = "unlocked"
        log.warning("UNLOCK (%s) by %s", host or "broker", by)
        async with self.db.session() as session:
            still = await session.get(BrokerFlag, LOCKDOWN_FLAG)
        return {"host": host, "daemons": reports, "broker_locked": sorted((still.value.get("hosts") or [])) if still else []}

    async def _on_connect(self, live: LiveConnection) -> None:
        """A daemon that was offline when it mattered is told now."""
        async with self.db.session() as session:
            locked = await self.locked(session, live.name)
            stale = []
            if live.role == HOST_ROLE:
                # Shells that ended while this host was away.
                ended = (
                    await session.execute(
                        select(Grant).where(
                            Grant.platform == Platform.HOSTEXEC,
                            Grant.resource == live.name,
                            Grant.status.in_([GrantStatus.REVOKED, GrantStatus.EXPIRED]),
                            Grant.revoked_at > utcnow() - timedelta(days=1),
                        )
                    )
                ).scalars().all()
                stale = [g.request_id for g in ended if g.capability == "shell"]
        if locked:
            await self.hub.send(live.role, live.name, {"type": "lockdown", "kill_vm": False})
        for shell_id in stale:
            await self.hub.send(live.role, live.name, {"type": "shell.close", "shell_id": shell_id})

