"""Agent VMs as seen from the broker (docs/sandbox-design.md §2, §4, §6.7).

A sandbox daemon (sandboxd, daemon role "sandbox", named after its host) is
paired like any daemon. This service gives it agents:

- Pairing it bootstraps `orchestrator-<host>-sandbox`, the one identity whose
  policy may mint others. Re-pairing rotates that key: a re-paired sandbox may
  have lost its state, and the old key must not outlive the old daemon key.
- Minting (provisioners/agents.py) creates `<runtime>-<project>-<host>-sandbox`
  with its lineage and lease. Its API key is generated here and handed ONLY to
  the sandbox daemon, over the signed channel — never to the agent that asked
  for the mint. Until the daemon acknowledges it, the key waits Fernet-wrapped
  in pending_key_deliveries; that row is the only place it is recoverable.
- A sandbox may ask for a fresh key for one of its own agents (it lost it).
- Leases: a minted agent past its lease is disabled, together with everything
  it minted, and its grants end within a scheduler tick.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..crypto import SecretBox, generate_api_key
from ..db import Database
from ..models import Agent, Daemon, Grant, PendingKeyDelivery, utcnow
from .daemons import DaemonHub, LiveConnection
from .states import GrantStatus

log = logging.getLogger(__name__)

SANDBOX_ROLE = "sandbox"
ORCHESTRATOR_RUNTIME = "orchestrator"
# Project names become unix users (p-<project>) inside the VM, so they follow
# the strict user-name rules, within 32 characters including the prefix.
PROJECT_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?")


class SandboxError(Exception):
    pass


def orchestrator_name(host: str) -> str:
    return f"orchestrator-{host}-sandbox"


def agent_name(runtime: str, project: str, host: str) -> str:
    return f"{runtime}-{project}-{host}-sandbox"


async def disable_agent_tree(session: AsyncSession, agent_id: str) -> list[str]:
    """Disable an agent and everything it minted, transitively; their
    active grants are due at once (the scheduler revokes them through
    their provisioners). Returns the disabled agents' names."""
    names: list[str] = []
    frontier = [agent_id]
    seen: set[str] = set()
    now = utcnow()
    while frontier:
        current = frontier.pop()
        if current in seen:
            continue
        seen.add(current)
        agent = await session.get(Agent, current)
        if agent is None:
            continue
        agent.disabled = True
        names.append(agent.name)
        await session.execute(
            update(Grant)
            .where(Grant.agent_id == current, Grant.status == GrantStatus.ACTIVE)
            .values(expires_at=now)
        )
        await session.execute(delete(PendingKeyDelivery).where(PendingKeyDelivery.agent_id == current))
        children = (
            await session.execute(select(Agent.id).where(Agent.parent_agent_id == current))
        ).scalars()
        frontier.extend(children)
    return names



class SandboxService:
    def __init__(self, db: Database, hub: DaemonHub, secret_box: SecretBox | None):
        self.db = db
        self.hub = hub
        self.secret_box = secret_box
        hub.on_paired(self._paired)
        hub.on_connect(self._push_keys)
        hub.on_heartbeat(self._push_keys)
        hub.handle("key.ack", self._key_ack)
        hub.handle("key.rotate", self._key_rotate)

    # --- keys ----------------------------------------------------------------

    def _wrap(self, key: str) -> str:
        if self.secret_box is None:
            raise SandboxError("ENCRYPTION_KEY is required to hand keys to a sandbox")
        return self.secret_box.encrypt(key)

    async def _queue_key(self, session: AsyncSession, agent: Agent) -> None:
        """New API key for an existing sandbox agent, queued for its daemon only."""
        full_key, key_id, key_hash = generate_api_key()
        agent.key_id = key_id
        agent.api_key_hash = key_hash
        await self._queue_delivery(session, agent, full_key)

    async def _queue_delivery(self, session: AsyncSession, agent: Agent, full_key: str) -> None:
        await session.execute(
            delete(PendingKeyDelivery).where(PendingKeyDelivery.agent_id == agent.id)
        )
        session.add(
            PendingKeyDelivery(
                agent_id=agent.id, sandbox_id=agent.sandbox_id, key_encrypted=self._wrap(full_key)
            )
        )

    def nudge(self, daemon_id: str, delay: float = 0.5) -> None:
        """Push pending keys to a sandbox shortly (after the caller's
        transaction commits); heartbeats retry anyway."""

        async def later():
            await asyncio.sleep(delay)
            await self.push_keys_to(daemon_id)

        self.hub._spawn(later(), "key push")

    async def push_keys_to(self, daemon_id: str) -> None:
        async with self.db.session() as session:
            daemon = await session.get(Daemon, daemon_id)
        if daemon is not None and self.hub.is_online(daemon.role, daemon.name):
            await self._push(daemon.role, daemon.name, daemon_id)

    async def _push_keys(self, live: LiveConnection) -> None:
        if live.role == SANDBOX_ROLE:
            await self._push(live.role, live.name, live.daemon_id)

    async def _push(self, role: str, name: str, daemon_id: str) -> None:
        async with self.db.session() as session:
            rows = (
                await session.execute(
                    select(PendingKeyDelivery, Agent)
                    .join(Agent, Agent.id == PendingKeyDelivery.agent_id)
                    .where(PendingKeyDelivery.sandbox_id == daemon_id)
                )
            ).all()
        for delivery, agent in rows:
            if self.secret_box is None:
                return
            await self.hub.send(
                role,
                name,
                {
                    "type": "key",
                    "agent_id": agent.id,
                    "name": agent.name,
                    "runtime": agent.runtime,
                    "project": agent.project,
                    "api_key": self.secret_box.decrypt(delivery.key_encrypted),
                },
            )

    async def _key_ack(self, live: LiveConnection, message: dict) -> None:
        agent_id = message.get("agent_id")
        if not isinstance(agent_id, str):
            return
        async with self.db.session() as session:
            # Only the sandbox the key was meant for can retire its delivery.
            await session.execute(
                delete(PendingKeyDelivery).where(
                    PendingKeyDelivery.agent_id == agent_id,
                    PendingKeyDelivery.sandbox_id == live.daemon_id,
                )
            )

    async def _key_rotate(self, live: LiveConnection, message: dict) -> None:
        """A sandbox lost an agent's key: issue a new one, to it alone."""
        name = message.get("name")
        if live.role != SANDBOX_ROLE or not isinstance(name, str):
            return
        async with self.db.session() as session:
            agent = (
                await session.execute(select(Agent).where(Agent.name == name))
            ).scalar_one_or_none()
            if agent is None or agent.sandbox_id != live.daemon_id or agent.disabled:
                log.warning("sandbox %s asked for a key it doesn't own: %r", live.name, name)
                return
            await self._queue_key(session, agent)
        log.info("rotated the key of %s for sandbox %s", name, live.name)
        await self._push(live.role, live.name, live.daemon_id)

    # --- the orchestrator ------------------------------------------------------

    async def _paired(self, role: str, name: str, daemon_id: str) -> None:
        if role != SANDBOX_ROLE:
            return
        async with self.db.session() as session:
            orch_name = orchestrator_name(name)
            agent = (
                await session.execute(select(Agent).where(Agent.name == orch_name))
            ).scalar_one_or_none()
            if agent is None:
                full_key, key_id, key_hash = generate_api_key()
                agent = Agent(
                    name=orch_name,
                    description=f"orchestrator of the agent VM on {name}",
                    kind="service",
                    key_id=key_id,
                    api_key_hash=key_hash,
                    sandbox_id=daemon_id,
                    runtime=ORCHESTRATOR_RUNTIME,
                    last_seen_at=utcnow(),
                )
                session.add(agent)
                await session.flush()
                await self._queue_delivery(session, agent, full_key)
                log.info("sandbox %s: orchestrator %s created, key queued", name, orch_name)
                return
            elif agent.sandbox_id not in (None, daemon_id) or agent.runtime != ORCHESTRATOR_RUNTIME:
                log.error(
                    "%s exists and isn't this sandbox's orchestrator; not taking it over", orch_name
                )
                return
            agent.sandbox_id = daemon_id
            agent.disabled = False
            await self._queue_key(session, agent)
        log.info("sandbox %s: orchestrator %s ready, key queued", name, orch_name)

    # --- minting ---------------------------------------------------------------

    async def mint(
        self,
        session: AsyncSession,
        parent: Agent,
        runtime: str,
        project: str,
        lease_secs: int,
    ) -> tuple[Agent, bool]:
        """Create or renew `<runtime>-<project>-<host>-sandbox` in the parent's
        sandbox. Returns (agent, created)."""
        daemon = await session.get(Daemon, parent.sandbox_id) if parent.sandbox_id else None
        if daemon is None or daemon.role != SANDBOX_ROLE:
            raise SandboxError("only agents in an agent VM can mint")
        name = agent_name(runtime, project, daemon.name)
        agent = (await session.execute(select(Agent).where(Agent.name == name))).scalar_one_or_none()
        lease = utcnow() + timedelta(seconds=lease_secs)
        if agent is not None:
            if agent.sandbox_id != daemon.id or agent.runtime != runtime or agent.project != project:
                raise SandboxError(f"{name} exists and doesn't belong to this sandbox")
            # Renewal; the key the sandbox holds stays valid.
            agent.lease_expires_at = lease
            agent.disabled = False
            return agent, False
        full_key, key_id, key_hash = generate_api_key()
        agent = Agent(
            name=name,
            description=f"{runtime} on project {project} in the agent VM on {daemon.name}",
            kind="service",
            key_id=key_id,
            api_key_hash=key_hash,
            parent_agent_id=parent.id,
            sandbox_id=daemon.id,
            runtime=runtime,
            project=project,
            lease_expires_at=lease,
            last_seen_at=utcnow(),
        )
        session.add(agent)
        await session.flush()
        await self._queue_delivery(session, agent, full_key)
        return agent, True

    # --- leases ------------------------------------------------------------------

    async def sweep_leases(self) -> int:
        """Scheduler tick: disable minted agents past their lease."""
        async with self.db.session() as session:
            due = (
                await session.execute(
                    select(Agent.id).where(
                        Agent.lease_expires_at.is_not(None),
                        Agent.lease_expires_at <= utcnow(),
                        Agent.disabled.is_(False),
                    )
                )
            ).scalars().all()
            disabled: list[str] = []
            for agent_id in due:
                disabled += await disable_agent_tree(session, agent_id)
        if disabled:
            log.info("lease expired: disabled %s", ", ".join(disabled))
        return len(disabled)
