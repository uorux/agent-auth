"""Restricted zones: resources only their own agents can reach.

A zone (policy `restricted`) names its members (agent patterns, usually
one project) and what is theirs: Kubernetes namespaces, GitHub repos. For
an agent outside the zone those resources do not exist:

- a request for them is refused before any rule is read, as if it named
  something the broker doesn't broker. Saved rules (Discord, the panel) and
  the policy file's own rules are matched after this, so no rule of either
  kind opens a zone;
- a cluster-wide Kubernetes grant binds every namespace except the zone's
  (provisioners/kubernetes.py), where it would otherwise be a
  ClusterRoleBinding;
- members are not a2a peers of anyone outside: neither side can open a
  thread to the other, and members don't show in anyone else's catalog;
- no outside agent in an agent VM may read or write a member project's
  files;
- members don't write the shared wiki (everyone reads it) unless the zone
  says `wiki: true`;
- an agent that would be a member is never minted without a human (an
  orchestrator could otherwise make itself a way in).

What a zone does not do: hide that the namespace exists (namespaces are
cluster-scoped; anyone who can list them sees its name), stop someone who
can change the cluster another way (Flux applies the gitops repo as
cluster-admin: what a homelab PR touches is for the person merging it),
or keep out an agent that holds credentials from outside the broker.
"""

from __future__ import annotations

from fnmatch import fnmatch
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Agent, Daemon
from ..policy.agents import agent_matches
from .a2a import OPERATOR_KIND
from .states import Platform

# What an outsider is told: the same words as a resource the broker does
# not broker at all, so a refusal says nothing about the zone.
NOT_BROKERED = {
    Platform.KUBERNETES: "namespace {resource!r} is not brokered (allowlist)",
    Platform.GITHUB: "repo {resource!r} is never brokered (denylist)",
    Platform.A2A: "unknown target agent {resource!r}",
    Platform.SANDBOX: "no project {resource!r} in this agent VM",
}


class Zones:
    def __init__(self, policy):
        self.zones = dict(policy.restricted)
        self.runtimes = sorted({*policy.platforms.agents.runtimes, "orchestrator"})

    def __bool__(self) -> bool:
        return bool(self.zones)

    def member_of(self, agent: Any) -> set[str]:
        if agent is None or getattr(agent, "kind", None) == OPERATOR_KIND:
            return set()
        return {name for name, zone in self.zones.items() if any(agent_matches(p, agent) for p in zone.members)}

    def is_member(self, agent: Any) -> bool:
        return bool(self.member_of(agent))

    def _owner(self, platform: Platform, resource: str) -> set[str]:
        resource = resource.lower()
        out = set()
        for name, zone in self.zones.items():
            globs = zone.kubernetes if platform == Platform.KUBERNETES else zone.github if platform == Platform.GITHUB else []
            if any(fnmatch(resource, g.lower()) for g in globs):
                out.add(name)
        return out

    def outside(self, agent: Any, platform: Platform, resource: str) -> bool:
        """The resource belongs to a zone this agent is not in."""
        owners = self._owner(platform, resource)
        return bool(owners - self.member_of(agent))

    def excluded_namespaces(self, agent: Any) -> list[str]:
        """Namespace globs a cluster-wide grant of this agent must leave out."""
        mine = self.member_of(agent)
        return sorted({g for name, zone in self.zones.items() if name not in mine for g in zone.kubernetes})

    def apart(self, a: Any, b: Any) -> bool:
        """Two agents on different sides of a zone's edge (a2a). The
        operator is on every side."""
        if getattr(a, "kind", None) == OPERATOR_KIND or getattr(b, "kind", None) == OPERATOR_KIND:
            return False
        return self.member_of(a) != self.member_of(b)

    def may_write_wiki(self, agent: Any) -> bool:
        return all(self.zones[name].wiki for name in self.member_of(agent))

    async def check(self, session: AsyncSession, agent: Agent, platform: Platform, resource: str, scope: dict) -> tuple[str, str] | None:
        """("deny", reason) or ("human", note) for a validated request, or
        None. Runs before any rule."""
        if not self.zones:
            return None
        if platform in (Platform.KUBERNETES, Platform.GITHUB):
            if self.outside(agent, platform, resource):
                return "deny", NOT_BROKERED[platform].format(resource=resource)
            return None
        if platform == Platform.A2A:
            peer = (await session.execute(select(Agent).where(Agent.name == resource))).scalar_one_or_none()
            if peer is not None and self.apart(agent, peer):
                return "deny", NOT_BROKERED[platform].format(resource=resource)
            return None
        if platform == Platform.SANDBOX:
            # resource: another project in the requester's agent VM. Its
            # agents, those there now and any of a runtime that could be
            # minted there.
            daemon = await session.get(Daemon, agent.sandbox_id) if agent.sandbox_id else None
            others = list(
                (await session.execute(select(Agent).where(Agent.sandbox_id == agent.sandbox_id, Agent.project == resource))).scalars()
            ) if agent.sandbox_id else []
            others += [
                SimpleNamespace(name=f"{rt}-{resource}-{daemon.name}-sandbox", runtime=rt, project=resource,
                                host=daemon.name, placement="sandbox", kind="service")
                for rt in self.runtimes
            ] if daemon else []
            # One way: a member may read outside its zone.
            if any(self.member_of(other) - self.member_of(agent) for other in others):
                return "deny", NOT_BROKERED[platform].format(resource=resource)
            return None
        if platform == Platform.AGENTS:
            daemon = await session.get(Daemon, agent.sandbox_id) if agent.sandbox_id else None
            runtime = (scope or {}).get("runtime")
            suffix = f"-{daemon.name}-sandbox" if daemon else None
            if daemon is None or not runtime or not resource.endswith(suffix):
                return None
            would_be = SimpleNamespace(
                name=resource,
                runtime=runtime,
                project=resource[len(runtime) + 1 : -len(suffix)],
                host=daemon.name,
                placement="sandbox",
                kind="service",
            )
            zones = self.member_of(would_be)
            if zones:
                return "human", f"mints an agent inside restricted zone {', '.join(sorted(zones))}: always a human"
        return None
