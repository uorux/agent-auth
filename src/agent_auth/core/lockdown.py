"""Containment: lockdown for agents, wherever they run.

An entry names agents the way a rule does (AgentMatch: name glob, project,
host, runtime, placement; {} is every agent). While it stands, the agents
it matches:

- lose every active grant, revoked through its provisioner: GitHub tokens
  stop being issued, Kubernetes service accounts are deleted, LDAP groups
  dropped, and their model-gateway keys deleted, so an agent whose model
  calls go through the gateway cannot think another step;
- are refused every new request (RequestService.create_request) and every
  credential fetch;
- have their a2a conversations closed.

The hosts and agent VMs (hostexec's lockdown: disarm, kill jobs, freeze
VMs) are the other half; hostexec records an entry here for what it locks,
so its scopes refuse requests too.

Who may contain: the operator (admin API, CLI), and agents the policy
names under `containment.agents`, within what it allows. Lifting is the
operator's alone. Every containment pings the operator on Discord.

What it does not do: stop a process that is already running and needs
nothing more from the broker or the gateway (a shell loop in a VM keeps
going until the VM is frozen: that is hostexec's lockdown), or reach
credentials an agent got outside the broker.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update

from ..models import Agent, BrokerFlag, Grant, utcnow
from ..policy.agents import AgentMatch, pattern_text
from .a2a import OPERATOR_KIND
from .states import GrantStatus

log = logging.getLogger(__name__)

CONTAIN_FLAG = "containment"


class ContainError(Exception):
    pass


def _matches(entry: dict[str, Any], agent: Agent) -> bool:
    try:
        return AgentMatch.model_validate(entry.get("match") or {}).matches(agent)
    except ValueError:
        return True  # an entry that no longer parses holds everyone: fail closed


async def entries(session) -> list[dict[str, Any]]:
    flag = await session.get(BrokerFlag, CONTAIN_FLAG)
    return list((flag.value if flag else {}).get("entries") or [])


async def holding(session, agent: Agent) -> dict[str, Any] | None:
    """The containment entry that holds this agent, if any."""
    if agent.kind == OPERATOR_KIND:
        return None
    for entry in await entries(session):
        if _matches(entry, agent):
            return entry
    return None


def describe(entry: dict[str, Any]) -> str:
    match = entry.get("match") or {}
    who = "every agent" if not match else pattern_text(AgentMatch.model_validate(match))
    return f"{who}: {entry.get('reason') or 'no reason given'} (by {entry.get('by')}, {entry.get('at')})"


class ContainmentService:
    def __init__(self, db, service, a2a=None, hub=None):
        self.db = db
        self.service = service
        self.a2a = a2a
        self.hub = hub  # the daemon channel: agent VMs freeze held agents

    async def held_in(self, session, sandbox_id: str) -> list[str]:
        """The agents of one agent VM that some entry holds."""
        agents = (await session.execute(select(Agent).where(Agent.sandbox_id == sandbox_id))).scalars().all()
        current = await entries(session)
        return sorted(a.name for a in agents if any(_matches(e, a) for e in current))

    async def tell_sandboxes(self) -> dict[str, str]:
        """Every agent VM gets its list of held agents (they freeze those
        agents' processes, and thaw the ones no longer held)."""
        if self.hub is None:
            return {}
        from .sandboxes import SANDBOX_ROLE
        from ..models import Daemon

        async with self.db.session() as session:
            daemons = (await session.execute(select(Daemon).where(Daemon.role == SANDBOX_ROLE))).scalars().all()
            lists = {d.name: await self.held_in(session, d.id) for d in daemons}
        reports = {}
        for name, agents in lists.items():
            sent = await self.hub.send(SANDBOX_ROLE, name, {"type": "agents.contained", "agents": agents})
            reports[f"sandbox:{name}"] = (
                f"{len(agents)} held" if sent else "not connected; told when it reconnects"
            )
        return reports

    async def list(self) -> list[dict[str, Any]]:
        async with self.db.session() as session:
            return await entries(session)

    async def record(self, match: dict[str, Any], reason: str, by: str, evidence: str = "", source: str = "") -> dict[str, Any]:
        """Add an entry (requests and credentials refused from now on)."""
        AgentMatch.model_validate(match)  # raises on a malformed match
        entry = {
            "id": secrets.token_hex(4),
            "match": match,
            "reason": reason[:500],
            "evidence": evidence[:4000],
            "by": by,
            "source": source,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        async with self.db.session() as session:
            flag = await session.get(BrokerFlag, CONTAIN_FLAG)
            if flag is None:
                flag = BrokerFlag(key=CONTAIN_FLAG, value={})
                session.add(flag)
            flag.value = {"entries": [*(flag.value.get("entries") or []), entry]}
        return entry

    async def contain(
        self, match: dict[str, Any], reason: str, by: str, evidence: str = "", source: str = ""
    ) -> dict[str, Any]:
        """Record an entry and act on it at once: revoke, close, ping."""
        try:
            entry = await self.record(match, reason, by, evidence, source)
        except ValueError as exc:
            raise ContainError(f"not an agent match: {exc}") from None
        async with self.db.session() as session:
            agents = [a for a in (await session.execute(select(Agent))).scalars() if a.kind != OPERATOR_KIND]
        held = [a for a in agents if _matches(entry, a)]
        ids = [a.id for a in held]
        async with self.db.session() as session:
            grant_ids = (
                (
                    await session.execute(
                        select(Grant.id).where(Grant.status == GrantStatus.ACTIVE, Grant.agent_id.in_(ids))
                    )
                ).scalars().all()
                if ids
                else []
            )
        revoked = 0
        for grant_id in grant_ids:
            try:
                await self.service.revoke_grant(grant_id, f"contained: {reason[:120]}", by)
                revoked += 1
            except Exception:
                # Left to the scheduler: due at once.
                async with self.db.session() as session:
                    await session.execute(update(Grant).where(Grant.id == grant_id).values(expires_at=utcnow()))
        closed = 0
        if self.a2a is not None:
            for agent in held:
                closed += await self.a2a.close_all_for(agent.id, "contained")
        daemons = await self.tell_sandboxes()
        out = {
            **entry,
            "agents": [a.name for a in held],
            "grants_revoked": revoked,
            "threads_closed": closed,
            "daemons": daemons,
        }
        log.warning("CONTAINED %s by %s: %d agents, %d grants revoked", describe(entry), by, len(held), revoked)
        await self.announce(out)
        return out

    async def announce(self, out: dict[str, Any]) -> None:
        notify = getattr(self.service.notifier, "contained", None)
        if notify is None:
            return
        try:
            await notify(out)
        except Exception:
            log.exception("could not announce a containment")

    async def lift(self, entry_id: str | None, by: str) -> list[dict[str, Any]]:
        """The operator's: remove one entry, or all of them (None)."""
        async with self.db.session() as session:
            flag = await session.get(BrokerFlag, CONTAIN_FLAG)
            current = list((flag.value if flag else {}).get("entries") or [])
            lifted = [e for e in current if entry_id is None or e["id"] == entry_id]
            if entry_id is not None and not lifted:
                raise ContainError(f"no containment {entry_id!r}")
            rest = [e for e in current if e not in lifted]
            if flag is not None:
                if rest:
                    flag.value = {"entries": rest}
                else:
                    await session.delete(flag)
        for e in lifted:
            log.warning("LIFTED containment %s (%s) by %s", e["id"], describe(e), by)
        await self.tell_sandboxes()
        return lifted

    async def lift_where(self, predicate, by: str) -> None:
        """Remove the entries a lockdown recorded (hostexec's unlock)."""
        async with self.db.session() as session:
            flag = await session.get(BrokerFlag, CONTAIN_FLAG)
            if flag is None:
                return
            rest = [e for e in flag.value.get("entries") or [] if not predicate(e)]
            if rest:
                flag.value = {"entries": rest}
            else:
                await session.delete(flag)
        log.warning("lockdown entries lifted by %s", by)
        await self.tell_sandboxes()
