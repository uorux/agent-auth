"""Platform "hostexec": a command, a template, or a time-boxed shell on a
host, run by that host's hostd (docs/sandbox-design.md §8).

    capability "run"         scope {"tier": "user"|"root", "argv": [...],
                                    "cwd"?, "env"?, "timeout"?, "stdin"?}
    capability "tpl.<name>"  scope {"tier", "params": {...}, "cwd"?, ...}
    capability "shell"       scope {"tier"}     (duration = the grant's)
    resource                 the host

A run/tpl grant is one execution, started when the grant is provisioned; a
refusal by the host (not armed, denied by its policy, a wrong TOTP code)
fails the provisioning with the host's reason. Root commands and all shells
are sensitive; shells are human-and-TOTP only.
"""

from __future__ import annotations

import json
import shlex

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.daemons import NAME_RE
from ..core.hostexec import HOST_ROLE, HostExecError, HostExecService, job_out, job_spec, tail
from ..core.states import GrantStatus, Platform
from ..daemon_common import hostexec as hx
from ..models import AccessRequest, Daemon, Grant, HostJob
from ..policy.schema import HostexecPlatformConfig
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError
from sqlalchemy import select


class HostexecProvisioner:
    platform = Platform.HOSTEXEC

    def __init__(self, config: HostexecPlatformConfig, hostexec: HostExecService):
        self.config = config
        self.hostexec = hostexec

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        host = spec.resource.strip().lower()
        if not NAME_RE.fullmatch(host):
            raise SpecValidationError("resource is the host's name")
        daemon = (
            await session.execute(select(Daemon).where(Daemon.role == HOST_ROLE, Daemon.name == host))
        ).scalar_one_or_none()
        if daemon is None:
            raise SpecValidationError(f"no host {host!r} is paired with this broker")
        if not self.hostexec.hub.is_online(HOST_ROLE, host):
            raise SpecValidationError(f"host {host} is offline")
        if await self.hostexec.locked(session, host):
            raise SpecValidationError(f"locked down: nothing runs on {host} until it is unlocked")
        scope = spec.scope
        tier = scope.get("tier")
        capability = spec.capability
        try:
            if capability == "shell":
                if set(scope) - {"tier"}:
                    raise SpecValidationError("a shell's scope is {\"tier\": \"user\"|\"root\"}")
                hx.shell_spec(host, tier, 1)
                spec.scope = {"tier": tier}
                spec.notes.append(
                    f"{'ROOT' if tier == 'root' else 'user'} shell on {host}: any command, one at a time, "
                    "each shown here before it runs"
                )
            elif capability == "run" or capability.startswith("tpl."):
                known = {"tier", "cwd", "env", "timeout", "stdin", "params" if capability != "run" else "argv"}
                if set(scope) - known:
                    raise SpecValidationError(f"unknown scope keys: {', '.join(sorted(set(scope) - known))}")
                job = job_spec(capability, host, scope)
                normalized = {
                    key: job[key]
                    for key in ("tier", "argv", "params", "cwd", "env", "timeout", "stdin")
                    if job.get(key) not in (None, {}) or key in ("argv", "params") and key in job
                }
                spec.scope = normalized
                if job["kind"] == "tpl":
                    spec.notes.append(self._template_note(job))
                else:
                    spec.notes.append(f"runs as {'ROOT' if tier == 'root' else 'your user'} on {host}: {shlex.join(job['argv'])}")
            else:
                raise SpecValidationError('hostexec capability is "run", "tpl.<name>" or "shell"')
        except hx.SpecError as exc:
            raise SpecValidationError(str(exc)) from None
        # What the host last said it accepts: no point asking a human for
        # something it will refuse whatever they answer. (The host checks
        # again; a host that reported nothing is asked later.)
        reported = ((daemon.last_status or {}).get("tiers") or {}).get(spec.scope.get("tier") or "user")
        if reported is not None:
            wanted = spec.scope.get("tier") or "user"
            if not reported.get("enabled"):
                raise SpecValidationError(f"the {wanted} tier is not enabled on {host}")
            if capability == "shell" and not reported.get("shell"):
                raise SpecValidationError(f"{wanted} shells are not enabled on {host}")
        spec.resource = host
        return spec

    def _template_note(self, job: dict) -> str:
        """Check a template request against the broker's mirror, if it has
        one, and say what it expands to. The host expands its own copy."""
        template = self.config.templates.get(job["template"])
        if template is None:
            return (
                f"template {job['template']!r} with {json.dumps(job['params'])}: not mirrored in the "
                "broker's policy, so what it runs is known only to the host"
            )
        if template.tier != job["tier"]:
            raise SpecValidationError(f"template {job['template']!r} is a {template.tier}-tier template")
        argv = hx.expand_template({"argv": template.argv, "params": template.params}, job["params"])
        return f"template {job['template']!r} on {job['host']} ({job['tier']}) expands to: {shlex.join(argv)}"

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        request = await session.get(AccessRequest, grant.request_id)
        try:
            return await self.hostexec.start(grant, request)
        except (HostExecError, hx.SpecError) as exc:
            raise ProvisionerError(f"{grant.resource} refused: {exc}") from None

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        """Ending the grant ends what it started: a running job is killed, a
        shell is closed. Never blocks on an unreachable host — it ends the
        shell at its own expiry, and is told again when it reconnects."""
        if grant.capability == "shell":
            await self.hostexec.close_shell(grant)
            return
        job = await session.get(HostJob, grant.request_id)
        if job is not None:
            await self.hostexec.kill(job)

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        if grant.capability == "shell":
            if grant.status != GrantStatus.ACTIVE:
                raise ProvisionerError("that shell has ended")
            return CredentialOut(
                kind="hostexec_shell",
                value=grant.id,
                expires_at=grant.expires_at,
                note=(
                    f"A {grant.scope.get('tier')} shell on {grant.resource}. Run commands with "
                    "host_shell_exec(grant_id, argv) — one at a time, each shown to the operator "
                    "before it runs — and end it with host_shell_close(grant_id)."
                ),
            )
        job = await session.get(HostJob, grant.request_id)
        if job is None:
            raise ProvisionerError("no job was started for this grant")
        summary = job_out(job, full=False)
        summary["output_tail"] = tail(job.output)
        summary.pop("output", None)
        return CredentialOut(
            kind="hostexec_job",
            value=json.dumps(summary),
            note=(
                "The command ran once; this grant does not run it again. Full output: "
                f"host_job(\"{job.id}\") / GET /v1/hostexec/jobs/{job.id} (which also waits while it runs)."
            ),
        )
