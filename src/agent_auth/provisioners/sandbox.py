"""Platform "sandbox": access to another project's files inside an agent VM
(docs/sandbox-design.md §6.2).

capability "project.read" | "project.write", resource = the target project.
Requested by an agent of the same VM for its own project's unix user; the
sandbox daemon applies it as ACLs (and removes them at revoke), answering
over the daemon channel. project.write is sensitive (always a human).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.daemons import DaemonCallError, DaemonHub
from ..core.sandboxes import PROJECT_RE, SANDBOX_ROLE
from ..core.states import Platform
from ..models import Agent, Daemon, Grant
from ..schemas import CredentialOut
from .base import ProvisionerError, RequestSpec, SpecValidationError

ACCESS = ("project.read", "project.write")


class SandboxProvisioner:
    platform = Platform.SANDBOX

    def __init__(self, hub: DaemonHub):
        self.hub = hub

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability not in ACCESS:
            raise SpecValidationError(f"sandbox capability must be one of {', '.join(ACCESS)}")
        agent = spec.agent
        if not agent.sandbox_id or not agent.project:
            raise SpecValidationError("only a project's agent in an agent VM can ask for this")
        target = spec.resource.strip().lower()
        if not PROJECT_RE.fullmatch(target):
            raise SpecValidationError(f"invalid project name {target!r}")
        if target == agent.project:
            raise SpecValidationError("that's your own project")
        if spec.scope:
            raise SpecValidationError("no scope for sandbox grants")
        spec.resource = target
        spec.notes.append(
            f"{'reads' if spec.capability == 'project.read' else 'WRITES'} project {target} "
            f"from project {agent.project}"
        )
        return spec

    async def _daemon(self, session: AsyncSession, grant: Grant) -> tuple[Agent, Daemon]:
        agent = await session.get(Agent, grant.agent_id)
        daemon = await session.get(Daemon, agent.sandbox_id) if agent and agent.sandbox_id else None
        if agent is None or daemon is None or daemon.role != SANDBOX_ROLE:
            raise ProvisionerError("the requesting agent is no longer in an agent VM")
        return agent, daemon

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        agent, daemon = await self._daemon(session, grant)
        try:
            await self.hub.call(
                daemon.role,
                daemon.name,
                {
                    "type": "project.grant",
                    "grant_id": grant.id,
                    "project": agent.project,
                    "target": grant.resource,
                    "access": grant.capability,
                },
            )
        except DaemonCallError as exc:
            raise ProvisionerError(f"sandbox {daemon.name}: {exc}") from None
        return {"project": agent.project, "target": grant.resource, "access": grant.capability}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        agent, daemon = await self._daemon(session, grant)
        try:
            await self.hub.call(
                daemon.role,
                daemon.name,
                {
                    "type": "project.revoke",
                    "grant_id": grant.id,
                    "project": agent.project,
                    "target": grant.resource,
                },
            )
        except DaemonCallError as exc:
            # Retried by the scheduler until the daemon answers.
            raise ProvisionerError(f"sandbox {daemon.name}: {exc}") from None

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        return CredentialOut(
            kind="project_access",
            note=(
                f"{grant.capability} on /var/lib/sandbox/projects/{grant.resource} is applied "
                "to your project's user; it ends with the grant."
            ),
        )
