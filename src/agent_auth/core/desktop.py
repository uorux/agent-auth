"""Approval prompts on the desktops you are at (docs/sandbox-design.md §8.10,
phase 9).

When a request reaches a human, Discord gets it as always. In addition, every
host whose hostd reports you present (session unlocked, recently used, not
fullscreen, no do-not-disturb) shows a dialog — all of them at once; the
first answer decides and the other dialogs are taken down. No answer within
the timeout leaves the request to Discord.

An answer from a desktop counts exactly like a click on Discord, no more:
- it is accepted only for a prompt this broker sent to that host and that is
  still open;
- a command on a host still needs that host armed (the answer carries no
  TOTP code), and a shell is never asked on a desktop;
- sensitive requests are asked on a desktop only if policy says so.

What this does NOT protect against: anything running as you on one of these
desktops, or a compromised host, can answer its prompts. `desktop:` in the
policy decides which agents and platforms may be asked there at all; keep it
to what you would let any process of yours approve.

Anti-spam (policy `desktop:`): eligibility by agent and platform, one dialog
per host at a time, per-agent and global rates, a cooldown after a Deny (and
a mute after three), an optional quiet window, and do-not-disturb.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from typing import Any

from sqlalchemy import select

from .. import authority as authority_mod
from ..db import Database
from ..models import AccessRequest, Agent, Daemon
from ..policy.schema import DesktopConfig
from ..schemas import format_duration, parse_duration
from .daemons import DaemonCallError, DaemonHub, LiveConnection
from .service import HumanDecision, TransitionError
from .states import Platform, RequestStatus

log = logging.getLogger(__name__)

HOST_ROLE = "host"
BURST_WINDOW_SECS = 120
DENIES_TO_MUTE = 3


@dataclass
class Offer:
    """One request being asked on one or more desktops."""

    request_id: str
    agent: str
    prompts: dict[str, str] = field(default_factory=dict)  # prompt id -> host
    answer: asyncio.Future | None = None


def prompt_text(request: AccessRequest, agent: Agent, delegator: Agent | None) -> tuple[str, str]:
    """(title, text). Who is asking comes from the broker's records; only the
    quoted justification is the agent's own words."""
    import shlex

    lines = [f"{agent.name} asks for:"]
    if request.platform == Platform.HOSTEXEC:
        tier = "ROOT" if request.scope.get("tier") == "root" else "your user"
        if request.capability.startswith("tpl."):
            what = f"template {request.capability[4:]} {request.scope.get('params') or {}}"
        else:
            what = shlex.join(request.scope.get("argv") or [])
        lines.append(f"run on {request.resource} as {tier}:\n    {what[:600]}")
        if request.scope.get("cwd"):
            lines.append(f"in {request.scope['cwd']}")
    else:
        lines.append(f"{request.platform.value} / {request.capability} on {request.resource}")
        if request.scope:
            lines.append(f"scope: {str(request.scope)[:300]}")
        lines.append(f"for {format_duration(request.requested_duration_secs)}")
    if delegator is not None:
        lines.append(f"on behalf of {delegator.name}")
    for note in (request.risk_notes or [])[:4]:
        lines.append(f"• {str(note)[:300]}")
    lines.append(f"\nThe agent says (unverified):\n{request.justification[:600]}")
    return f"agent-auth: {agent.name}"[:120], "\n".join(lines)


class DesktopService:
    def __init__(self, db: Database, hub: DaemonHub, config: DesktopConfig, service):
        self.db = db
        self.hub = hub
        self.config = config
        self.service = service
        self.dnd_until = 0.0
        # What hosts said since their last heartbeat was stored.
        self._presence: dict[str, tuple[bool, float]] = {}
        self._offers: dict[str, Offer] = {}  # by request id
        self._prompts: dict[str, Offer] = {}  # by prompt id
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._asked: dict[str, deque[float]] = defaultdict(deque)  # agent -> times
        self._asked_all: deque[float] = deque()
        self._denies: dict[str, deque[float]] = defaultdict(deque)
        self._paused_until: dict[str, float] = {}
        self._tasks: set[asyncio.Task] = set()
        hub.handle("presence", self._on_presence)
        hub.handle("prompt.answer", self._on_answer)

    # --- presence --------------------------------------------------------------------

    async def _on_presence(self, live: LiveConnection, msg: dict[str, Any]) -> None:
        if live.role == HOST_ROLE:
            self._presence[live.name] = (msg.get("present") is True, time.time())

    async def present_hosts(self) -> list[str]:
        """Hosts whose hostd is connected and says you are at the desk."""
        async with self.db.session() as session:
            rows = (await session.execute(select(Daemon).where(Daemon.role == HOST_ROLE))).scalars().all()
        out = []
        for row in rows:
            if not self.hub.is_online(HOST_ROLE, row.name):
                continue
            desktop = (row.last_status or {}).get("desktop") or {}
            present = desktop.get("present") is True
            fresh = self._presence.get(row.name)
            if fresh is not None and (row.last_seen_at is None or fresh[1] >= row.last_seen_at.timestamp()):
                present = fresh[0]
            if present:
                out.append(row.name)
        return sorted(out)

    async def set_dnd(self, seconds: int) -> None:
        """Do-not-disturb for every desktop (0 = off)."""
        self.dnd_until = time.time() + seconds if seconds else 0.0
        async with self.db.session() as session:
            names = (await session.execute(select(Daemon.name).where(Daemon.role == HOST_ROLE))).scalars().all()
        for name in names:
            await self.hub.send(HOST_ROLE, name, {"type": "dnd", "duration": seconds or None})

    # --- who may be asked, and how often ------------------------------------------------

    def _quiet_now(self) -> bool:
        if not self.config.quiet_hours:
            return False
        start, end = self.config.quiet_hours
        now = datetime.now().strftime("%H:%M")
        return (start <= now < end) if start <= end else (now >= start or now < end)

    def refusal(self, request: AccessRequest, agent: Agent) -> str | None:
        """Why this request is not asked on a desktop (None = it may be)."""
        c, now = self.config, time.time()
        if not c.enabled:
            return "desktop prompts are off"
        if not any(fnmatch(agent.name, glob) for glob in c.agents):
            return "agent not listed under desktop.agents"
        if c.platforms and request.platform not in c.platforms:
            return "platform not listed under desktop.platforms"
        if authority_mod.human_only(request.platform, request.authority):
            return "never asked on a desktop"
        if not c.sensitive and self.service.engine.is_sensitive(request):
            return "sensitive (desktop.sensitive is off)"
        if self.dnd_until > now:
            return "do-not-disturb"
        if self._quiet_now():
            return "quiet hours"
        if self._paused_until.get(agent.name, 0) > now:
            return "this agent's desktop prompts are paused"
        hour = now - 3600
        for times in (self._asked[agent.name], self._asked_all):
            while times and times[0] < hour:
                times.popleft()
        mine = self._asked[agent.name]
        if len(mine) >= c.per_agent_per_hour or sum(1 for t in mine if t > now - BURST_WINDOW_SECS) >= c.per_agent_burst:
            return "desktop rate-limited (agent)"
        if len(self._asked_all) >= c.per_hour:
            return "desktop rate-limited"
        return None

    def _note_deny(self, agent: str) -> None:
        now = time.time()
        denies = self._denies[agent]
        denies.append(now)
        while denies and denies[0] < now - 3600:
            denies.popleft()
        pause = self.config.mute if len(denies) >= DENIES_TO_MUTE else self.config.deny_cooldown
        self._paused_until[agent] = now + parse_duration(pause)

    # --- asking ----------------------------------------------------------------------------

    def offer(self, request: AccessRequest, agent: Agent) -> None:
        """Called when a request is surfaced. Returns at once."""
        if self.refusal(request, agent) is not None:
            return
        task = asyncio.create_task(self._offer(request.id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _offer(self, request_id: str) -> None:
        try:
            await self._ask(request_id)
        except Exception:
            log.exception("desktop prompt for %s failed", request_id)

    async def _ask(self, request_id: str) -> None:
        async with self.db.session() as session:
            request = await session.get(AccessRequest, request_id)
            if request is None or request.status != RequestStatus.AWAITING_HUMAN:
                return
            agent = await session.get(Agent, request.agent_id)
            delegator = (
                await session.get(Agent, request.delegator_agent_id) if request.delegator_agent_id else None
            )
            target = None
            if request.platform == Platform.HOSTEXEC:
                target = (
                    await session.execute(
                        select(Daemon).where(Daemon.role == HOST_ROLE, Daemon.name == request.resource)
                    )
                ).scalar_one_or_none()
        if request.platform == Platform.HOSTEXEC:
            # A desktop answer carries no TOTP code: only worth asking while
            # the target's tier is armed.
            tier = ((target.last_status or {}).get("tiers") or {}).get(request.scope.get("tier")) if target else None
            if not (tier or {}).get("armed_until"):
                return
        hosts = await self.present_hosts()
        if not hosts:
            return
        title, text = prompt_text(request, agent, delegator)
        timeout = parse_duration(self.config.timeout)
        now = time.time()
        self._asked[agent.name].append(now)
        self._asked_all.append(now)
        offer = Offer(request_id=request_id, agent=agent.name, answer=asyncio.get_running_loop().create_future())
        self._offers[request_id] = offer
        shows = [asyncio.create_task(self._show(offer, host, title, text, timeout)) for host in hosts]
        try:
            host, answer = await asyncio.wait_for(asyncio.shield(offer.answer), timeout + parse_duration(self.config.queue_timeout))
        except TimeoutError:
            host, answer = None, "timeout"
        finally:
            for show in shows:
                show.cancel()
            await asyncio.gather(*shows, return_exceptions=True)
            await self._close(offer)
        await self._apply(offer, host, answer)

    async def _show(self, offer: Offer, host: str, title: str, text: str, timeout: int) -> None:
        """One dialog on one host; a host shows one at a time. Holds the
        host's slot until the offer ends (this task is cancelled then)."""
        lock = self._host_locks[host]
        try:
            await asyncio.wait_for(lock.acquire(), parse_duration(self.config.queue_timeout))
        except TimeoutError:
            return  # that desktop is busy with another dialog: Discord has it
        try:
            prompt_id = str(uuid.uuid4())
            offer.prompts[prompt_id] = host
            self._prompts[prompt_id] = offer
            try:
                await self.hub.call(
                    HOST_ROLE,
                    host,
                    {"type": "prompt", "prompt_id": prompt_id, "request_id": offer.request_id,
                     "title": title, "text": text, "timeout": timeout},
                    timeout=10,
                )
            except DaemonCallError:
                self._prompts.pop(prompt_id, None)
                offer.prompts.pop(prompt_id, None)
                return
            await asyncio.Event().wait()  # until cancelled
        finally:
            lock.release()

    async def _close(self, offer: Offer) -> None:
        self._offers.pop(offer.request_id, None)
        for prompt_id, host in list(offer.prompts.items()):
            self._prompts.pop(prompt_id, None)
            await self.hub.send(HOST_ROLE, host, {"type": "prompt.cancel", "prompt_id": prompt_id})

    async def _on_answer(self, live: LiveConnection, msg: dict[str, Any]) -> None:
        prompt_id, answer = msg.get("prompt_id"), msg.get("answer")
        offer = self._prompts.get(prompt_id) if isinstance(prompt_id, str) else None
        # Only for a prompt we sent to this very host, and that is still open.
        if live.role != HOST_ROLE or offer is None or offer.prompts.get(prompt_id) != live.name:
            return
        if answer not in ("allow", "deny", "mute", "discord", "timeout"):
            return
        if answer == "timeout":
            # That desktop gave up; the others may still answer.
            self._prompts.pop(prompt_id, None)
            return
        if offer.answer is not None and not offer.answer.done():
            offer.answer.set_result((live.name, answer))

    async def _apply(self, offer: Offer, host: str | None, answer: str) -> None:
        if answer == "mute":
            self._paused_until[offer.agent] = time.time() + parse_duration(self.config.mute)
            return
        if answer not in ("allow", "deny"):
            return
        if answer == "deny":
            self._note_deny(offer.agent)
        try:
            await self.service.decide(
                offer.request_id,
                HumanDecision(
                    approve=answer == "allow",
                    decided_by=f"desktop:{host}",
                    reason="" if answer == "allow" else "denied at the desk",
                ),
            )
        except TransitionError as exc:
            # Decided elsewhere meanwhile, or the platform's gate said no
            # (a host that isn't armed): Discord still has the request.
            log.info("desktop answer for %s from %s not applied: %s", offer.request_id, host, exc)

    def cancel(self, request_id: str) -> None:
        """The request was decided some other way: take the dialogs down."""
        offer = self._offers.get(request_id)
        if offer is not None and offer.answer is not None and not offer.answer.done():
            offer.answer.set_result((None, "discord"))


class FanoutNotifier:
    """The broker's notifier with desktops alongside: everything goes to the
    primary (Discord); surfaced requests are also offered to desktops, and a
    decision takes their dialogs down."""

    def __init__(self, primary, desktop: DesktopService):
        self.primary = primary
        self.desktop = desktop

    async def surface(self, request: AccessRequest, agent: Agent) -> None:
        await self.primary.surface(request, agent)
        self.desktop.offer(request, agent)

    async def update_outcome(self, request: AccessRequest, grant) -> None:
        self.desktop.cancel(request.id)
        await self.primary.update_outcome(request, grant)

    def __getattr__(self, name: str):
        return getattr(self.primary, name)
