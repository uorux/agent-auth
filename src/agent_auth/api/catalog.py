from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import Platform
from ..models import AccessRequest, Agent
from ..policy.engine import PolicyEngine
from ..policy.schema import PolicyAction
from ..provisioners.base import ProvisionerRegistry
from ..schemas import CatalogEntry, CatalogOut, PlatformCatalog

_DISPOSITION = {
    PolicyAction.APPROVE: "auto-approve",
    PolicyAction.SURFACE: "human review",
    PolicyAction.LLM: "llm review",
    PolicyAction.DENY: "denied",
}


async def _disposition(
    session: AsyncSession, engine: PolicyEngine, agent: Agent, platform: Platform, capability: str
) -> str:
    """Resource-agnostic policy routing for (agent, platform, capability).

    Uses resource='*', so resource-specific rules that narrow to particular
    namespaces are not matched here — the result errs toward the catch-all
    (usually 'human review'), never toward falsely advertising auto-approval.
    """
    probe = AccessRequest(
        agent_id=agent.id,
        platform=platform,
        capability=capability,
        resource="*",
        scope={},
        justification="",
        requested_duration_secs=0,
    )
    decision = await engine.evaluate(session, agent, probe)
    return _DISPOSITION.get(decision.action, decision.action.value)


async def build_catalog(
    session: AsyncSession,
    agent: Agent,
    registry: ProvisionerRegistry,
    engine: PolicyEngine,
) -> CatalogOut:
    """What this agent may request, per enabled platform — the menu it needs
    before composing a request."""
    policy = engine.policy
    platforms: list[PlatformCatalog] = []

    if registry.enabled(Platform.GITHUB):
        gh = policy.platforms.github
        platforms.append(
            PlatformCatalog(
                platform=Platform.GITHUB,
                capability_hint="repo",
                resource_hint="owner/repo",
                repo_allowlist=gh.repo_allowlist or ["<any>"],
                permission_ceiling=gh.permission_ceiling,
            )
        )

    if registry.enabled(Platform.HOMELAB):
        hl = policy.platforms.homelab
        platforms.append(
            PlatformCatalog(
                platform=Platform.HOMELAB,
                capability_hint="group",
                resource_hint="<lldap group>",
                groups=[
                    CatalogEntry(name=g, description=hl.group_descriptions.get(g))
                    for g in hl.allowed_groups
                ],
            )
        )

    if registry.enabled(Platform.KUBERNETES):
        k = policy.platforms.kubernetes
        roles = []
        for role in k.role_allowlist:
            roles.append(
                CatalogEntry(
                    name=role,
                    description=k.role_descriptions.get(role),
                    typical_disposition=await _disposition(
                        session, engine, agent, Platform.KUBERNETES, role
                    ),
                )
            )
        platforms.append(
            PlatformCatalog(
                platform=Platform.KUBERNETES,
                capability_hint="<role name>",
                resource_hint='<namespace>, or "*" for cluster-wide',
                namespace_allowlist=k.namespace_allowlist,
                roles=roles,
                cluster_roles=k.cluster_role_allowlist or None,
            )
        )

    if registry.enabled(Platform.A2A):
        # Only service agents can receive threads (ephemeral = initiate-only).
        peers = (
            await session.execute(
                select(Agent.name).where(
                    Agent.id != agent.id,
                    Agent.disabled.is_(False),
                    Agent.kind == "service",
                )
            )
        ).scalars().all()
        platforms.append(
            PlatformCatalog(
                platform=Platform.A2A,
                capability_hint="talk",
                resource_hint="<agent name>",
                peers=sorted(peers),
            )
        )

    if registry.enabled(Platform.GOOGLE):
        from ..provisioners.google_stub import _KNOWN_CAPABILITIES

        platforms.append(
            PlatformCatalog(
                platform=Platform.GOOGLE,
                capability_hint="<calendar.read | gmail.read | ...>",
                resource_hint="<calendar id / label / folder>",
                capabilities=sorted(_KNOWN_CAPABILITIES),
            )
        )

    return CatalogOut(platforms=platforms)
