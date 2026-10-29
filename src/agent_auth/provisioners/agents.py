"""Platform "agents": minting identities in an agent VM (docs/sandbox-design.md §4).

capability "mint", resource "<runtime>-<project>-<host>-sandbox", scope
{"runtime": …} (optional; derived from the name). Only an agent that lives in
an agent VM may ask, and only for its own VM's host; the name is checked
against the structured fields, never parsed for trust. The new agent's key
goes to the sandbox daemon alone (core/sandboxes.py). Minting an existing
agent of the same VM renews its lease. Nothing is undone when the mint grant
ends: the identity's lifetime is its lease.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.sandboxes import PROJECT_RE, SANDBOX_ROLE, SandboxError, SandboxService, agent_name
from ..core.states import Platform
from ..models import Agent, Daemon, Grant
from ..policy.schema import AgentsPlatformConfig
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError


class AgentsProvisioner:
    platform = Platform.AGENTS

    def __init__(self, config: AgentsPlatformConfig, sandboxes: SandboxService):
        self.config = config
        self.sandboxes = sandboxes

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability != "mint":
            raise SpecValidationError("agents capability must be 'mint'")
        if not self.config.runtimes:
            raise SpecValidationError("minting is disabled (platforms.agents.runtimes is empty)")
        daemon = await session.get(Daemon, spec.agent.sandbox_id) if spec.agent.sandbox_id else None
        if daemon is None or daemon.role != SANDBOX_ROLE:
            raise SpecValidationError("only agents running in an agent VM can mint identities")
        from ..core.hostexec import HostExecService

        if await HostExecService.locked(session, daemon.name):
            raise SpecValidationError("locked down: no identities are minted until it is lifted")
        name = spec.resource.strip().lower()
        suffix = f"-{daemon.name}-sandbox"
        runtime = next(
            (r for r in self.config.runtimes if name.startswith(f"{r}-") and name.endswith(suffix)),
            None,
        )
        if runtime is None:
            raise SpecValidationError(
                f"resource must be '<runtime>-<project>{suffix}' with runtime one of "
                f"{', '.join(self.config.runtimes)}"
            )
        project = name[len(runtime) + 1 : -len(suffix)]
        if not PROJECT_RE.fullmatch(project):
            raise SpecValidationError(
                f"invalid project name {project!r} (lowercase letters, digits and '-', ≤30)"
            )
        wanted = spec.scope.get("runtime")
        if wanted not in (None, runtime) or set(spec.scope) - {"runtime"}:
            raise SpecValidationError("scope may only repeat the name's runtime")
        assert agent_name(runtime, project, daemon.name) == name
        spec.resource = name
        spec.scope = {"runtime": runtime}
        spec.notes.append(f"mints {name} ({runtime} on project {project}) in the agent VM on {daemon.name}")
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        parent = await session.get(Agent, grant.agent_id)
        runtime = grant.scope["runtime"]
        daemon = await session.get(Daemon, parent.sandbox_id) if parent and parent.sandbox_id else None
        if parent is None or daemon is None:
            raise ProvisionerError("the requesting agent is no longer in an agent VM")
        project = grant.resource[len(runtime) + 1 : -len(f"-{daemon.name}-sandbox")]
        try:
            agent, created = await self.sandboxes.mint(
                session, parent, runtime, project, self.config.lease_secs
            )
        except SandboxError as exc:
            raise ProvisionerError(str(exc)) from None
        # The daemon collects the key on its next heartbeat at the latest;
        # nudge it now, once this transaction has committed.
        self.sandboxes.nudge(daemon.id)
        return {
            "agent_id": agent.id,
            "name": agent.name,
            "created": created,
            "lease_expires_at": agent.lease_expires_at.isoformat(),
        }

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        return  # the identity lives by its lease, not by the mint grant

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        state = grant.provisioner_state or {}
        return CredentialOut(
            kind="agent_identity",
            value=state.get("name"),
            note=(
                f"{'minted' if state.get('created') else 'renewed'}; lease until "
                f"{state.get('lease_expires_at')}. Its key went to the sandbox daemon, "
                "which runs it — you never hold it."
            ),
        )
