from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import authority as authority_mod
from ..core.a2a import reachability
from ..core.states import Platform
from ..models import AccessRequest, Agent
from ..policy.engine import PolicyEngine
from ..policy.schema import PolicyAction
from ..provisioners.base import ProvisionerRegistry
from ..schemas import CatalogEntry, CatalogOut, PeerEntry, PlatformCatalog

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
    probe.authority = authority_mod.fold(platform, capability, {})
    decision = await engine.evaluate(session, agent, probe)
    # Mirror the service's gate: a privilege only an explicit rule may clear
    # (github "create") goes to a human when a catch-all matched it.
    if (
        decision.action in (PolicyAction.APPROVE, PolicyAction.LLM)
        and not decision.explicit
        and engine.needs_explicit_rule(probe)
    ):
        return _DISPOSITION[PolicyAction.SURFACE]
    return _DISPOSITION.get(decision.action, decision.action.value)


async def build_catalog(
    session: AsyncSession,
    agent: Agent,
    registry: ProvisionerRegistry,
    engine: PolicyEngine,
    listen_threshold_secs: int = 300,
    hosts: list[dict] | None = None,
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
                create_owners=gh.create_owners or None,
                create_disposition=(
                    await _disposition(session, engine, agent, Platform.GITHUB, "create")
                    if gh.create_owners
                    else None
                ),
            )
        )

    # Agent VMs (docs/sandbox-design.md): only agents living in one can mint
    # or reach other projects, so only they see these.
    if agent.sandbox_id and registry.enabled(Platform.AGENTS):
        platforms.append(
            PlatformCatalog(
                platform=Platform.AGENTS,
                capability_hint="mint",
                resource_hint="<runtime>-<project>-<this host>-sandbox",
                capabilities=list(policy.platforms.agents.runtimes),
            )
        )
    if agent.sandbox_id and agent.project and registry.enabled(Platform.SANDBOX):
        platforms.append(
            PlatformCatalog(
                platform=Platform.SANDBOX,
                capability_hint="project.read | project.write (write: always a human)",
                resource_hint="<another project in this agent VM>",
                capabilities=["project.read", "project.write"],
            )
        )

    if registry.enabled(Platform.HOSTEXEC) and hosts:
        platforms.append(
            PlatformCatalog(
                platform=Platform.HOSTEXEC,
                capability_hint='run | tpl.<template> | shell (root and every shell: always a human)',
                resource_hint="<host>",
                capabilities=["run", "shell", *[f"tpl.{name}" for name in policy.platforms.hostexec.templates]],
                hosts=hosts,
            )
        )

    if registry.enabled(Platform.MCP):
        platforms.append(
            PlatformCatalog(
                platform=Platform.MCP,
                capability_hint='use (scope {"tools": [...]}; omit for every tool)',
                resource_hint="<server>",
                capabilities=["use"],
                servers=[
                    {"name": name, "url": s.url, "description": s.description, "tools": s.tools or None}
                    for name, s in sorted(policy.platforms.mcp.servers.items())
                ],
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
        # Only service agents can receive threads (ephemeral = initiate-only),
        # and each carries its live reachability so callers can skip peers that
        # nothing is currently listening on.
        rows = (
            await session.execute(
                select(Agent).where(
                    Agent.id != agent.id,
                    Agent.disabled.is_(False),
                    Agent.kind == "service",
                )
            )
        ).scalars().all()
        peers = [
            PeerEntry(
                description=peer.description or None,
                **reachability(peer, listen_threshold_secs),
            )
            for peer in rows
        ]
        platforms.append(
            PlatformCatalog(
                platform=Platform.A2A,
                capability_hint="talk",
                resource_hint="<agent name>",
                peers=sorted(peers, key=lambda p: (not p.reachable, p.name)),
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
