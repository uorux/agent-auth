"""Approval prompts, and notifications, on the desktops you are at
(docs/sandbox-design.md §8.6, §8.10).

When a request reaches a human, Discord gets it as always. In addition:

- A command on a host is asked at THAT host's desk, if you are there. hostd
  builds the dialog from what it would actually run, and Allow there is that
  host's own approval of exactly that command (for root, with your password
  through polkit): no arming, no TOTP code. Whether a desk may do that is the
  host's setting, not the broker's.
- Anything else is asked on every desk you are at, all at once; the first
  answer decides and the other dialogs are taken down. That answer counts
  like a click on Discord, no more: a command on another host still needs
  that host armed, and sensitive requests are asked only if policy says so.
- A shell is never asked on a desktop.

No answer within the timeout leaves the request to Discord.

What this does NOT protect against: anything running as you on one of these
desktops, or a compromised host, can answer its prompts (not type your
password). `desktop:` in the policy decides which agents and platforms may be
asked there at all; keep it to what you would let any process of yours
approve.

Anti-spam: eligibility by agent and platform, one dialog per host at a time,
per-agent and global rates, a pause after a Deny (longer after three), and
do-not-disturb.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from .. import authority as authority_mod
from ..db import Database
from ..models import AccessRequest, Agent, Daemon
from ..policy.agents import agent_matches
from ..policy.schema import DesktopConfig
from ..schemas import format_duration, parse_duration
from .daemons import DaemonCallError, DaemonHub, LiveConnection
from .service import HumanDecision, TransitionError
from .states import Platform, RequestStatus

log = logging.getLogger(__name__)

HOST_ROLE = "host"
# At most this many prompts per agent in a burst; a request waits this long
# for a desk that is showing another dialog.
BURST, BURST_WINDOW_SECS = 2, 120
QUEUE_SECS = 30
DENIES_TO_MUTE = 3


@dataclass
class Offer:
    """One request being asked on one or more desktops."""

    request_id: str
    agent: str
    prompts: dict[str, str] = field(default_factory=dict)  # prompt id -> host
    answer: asyncio.Future | None = None


def prompt_fields(request: AccessRequest, agent: Agent, delegator: Agent | None) -> tuple[str, str, str]:
    """(who, what, detail), one line each. Who is asking comes from the
    broker's records; only the quoted justification is the agent's own
    words. (For a command at its own host's desk, hostd replaces `what`
    with what it would run.)"""
    import shlex

    who = agent.name + (f" (for {delegator.name})" if delegator is not None else "")
    if request.platform == Platform.HOSTEXEC:
        tier = "ROOT" if request.scope.get("tier") == "root" else "your user"
        if request.capability.startswith("tpl."):
            command = f"template {request.capability[4:]} {request.scope.get('params') or {}}"
        else:
            command = shlex.join(request.scope.get("argv") or [])
        what = f"run on {request.resource} as {tier}: {command}"
    else:
        what = f"{request.platform.value} / {request.capability} on {request.resource}"
        if request.scope:
            what += f" {str(request.scope)[:200]}"
        what += f", for {format_duration(request.requested_duration_secs)}"
    detail = [str(note)[:200] for note in (request.risk_notes or [])[:2]]
    detail.append(f"The agent says (unverified): {request.justification[:400]}")
    return who, what, " · ".join(detail)


class DesktopService:
    def __init__(self, db: Database, hub: DaemonHub, config: DesktopConfig, service, hostexec=None):
        self.db = db
        self.hub = hub
        self.config = config
        self.service = service
        self.hostexec = hostexec  # HostExecService, for a command's final spec
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

    def refusal(self, request: AccessRequest, agent: Agent) -> str | None:
        """Why this request is not asked on a desktop (None = it may be)."""
        c, now = self.config, time.time()
        if not c.enabled:
            return "desktop prompts are off"
        if not any(agent_matches(pattern, agent) for pattern in c.agents):
            return "agent not listed under desktop.agents"
        if c.platforms and request.platform not in c.platforms:
            return "platform not listed under desktop.platforms"
        if authority_mod.human_only(request.platform, request.authority):
            return "never asked on a desktop"
        # A command is asked at its own host's desk, where the host itself
        # decides what an answer is worth (_ask); the rest by sensitivity.
        if request.platform != Platform.HOSTEXEC and self._too_sensitive(request):
            return "sensitive (desktop.sensitive is off)"
        if self.dnd_until > now:
            return "do-not-disturb"
        if self._paused_until.get(agent.name, 0) > now:
            return "this agent's desktop prompts are paused"
        hour = now - 3600
        for times in (self._asked[agent.name], self._asked_all):
            while times and times[0] < hour:
                times.popleft()
        mine = self._asked[agent.name]
        if len(mine) >= c.per_agent_per_hour or sum(1 for t in mine if t > now - BURST_WINDOW_SECS) >= BURST:
            return "desktop rate-limited (agent)"
        if len(self._asked_all) >= c.per_hour:
            return "desktop rate-limited"
        return None

    def _too_sensitive(self, request: AccessRequest) -> bool:
        return not self.config.sensitive and self.service.engine.is_sensitive(request)

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
        hosts = await self.present_hosts()
        job = None
        if request.platform == Platform.HOSTEXEC:
            if request.resource in hosts and self.hostexec is not None:
                # At its own host's desk: that hostd says what will run, and
                # whether Allow there is enough.
                try:
                    spec = await self.hostexec.final_spec(
                        request, agent, HumanDecision(approve=True, decided_by="desktop")
                    )
                except Exception as exc:
                    log.info("desktop prompt for %s: %s", request_id, exc)
                    return
                hosts, job = [request.resource], {"job_id": request.id, "spec": spec}
            else:
                # Elsewhere an answer is only a click: worth asking while the
                # target's tier is armed, and not for what stays on Discord.
                tier = ((target.last_status or {}).get("tiers") or {}).get(request.scope.get("tier")) if target else None
                if not (tier or {}).get("armed_until") or self._too_sensitive(request):
                    return
        if not hosts:
            return
        who, what, detail = prompt_fields(request, agent, delegator)
        timeout = parse_duration(self.config.timeout)
        now = time.time()
        self._asked[agent.name].append(now)
        self._asked_all.append(now)
        offer = Offer(request_id=request_id, agent=agent.name, answer=asyncio.get_running_loop().create_future())
        self._offers[request_id] = offer
        payload = {"request_id": request_id, "who": who, "what": what, "detail": detail, "timeout": timeout}
        if job is not None:
            payload["job"] = job
        shows = [asyncio.create_task(self._show(offer, host, payload)) for host in hosts]
        try:
            host, answer = await asyncio.wait_for(asyncio.shield(offer.answer), timeout + QUEUE_SECS)
        except TimeoutError:
            host, answer = None, "timeout"
        finally:
            for show in shows:
                show.cancel()
            await asyncio.gather(*shows, return_exceptions=True)
            await self._close(offer)
        await self._apply(offer, host, answer)

    async def _show(self, offer: Offer, host: str, payload: dict[str, Any]) -> None:
        """One dialog on one host; a host shows one at a time. Holds the
        host's slot until the offer ends (this task is cancelled then)."""
        lock = self._host_locks[host]
        try:
            await asyncio.wait_for(lock.acquire(), QUEUE_SECS)
        except TimeoutError:
            return  # that desktop is busy with another dialog: Discord has it
        try:
            prompt_id = str(uuid.uuid4())
            offer.prompts[prompt_id] = host
            self._prompts[prompt_id] = offer
            try:
                await self.hub.call(HOST_ROLE, host, {"type": "prompt", "prompt_id": prompt_id, **payload}, timeout=10)
            except DaemonCallError:
                # Nobody there after all, or that host won't ask this.
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

    # --- attention -------------------------------------------------------------------------

    async def notify(self, agent: Agent, text: str, urgency: str = "normal") -> list[str]:
        """A notification (and a sound) on every desk the operator is at.
        Returns the hosts that showed it."""
        c, now = self.config, time.time()
        if (
            not c.enabled
            or not any(agent_matches(pattern, agent) for pattern in c.agents)
            or self.dnd_until > now
            or self._paused_until.get(agent.name, 0) > now
        ):
            return []
        shown = []
        for host in await self.present_hosts():
            try:
                await self.hub.call(
                    HOST_ROLE,
                    host,
                    {"type": "notify", "title": f"agent-auth: {agent.name}", "text": text,
                     "urgency": "critical" if urgency == "high" else "normal"},
                    timeout=10,
                )
                shown.append(host)
            except DaemonCallError:
                pass
        return shown

    async def alert(self, title: str, text: str) -> None:
        """Something the operator should see now, from the broker itself: on
        every desk they are at, whatever the agent-eligibility rules say."""
        for host in await self.present_hosts():
            try:
                await self.hub.call(
                    HOST_ROLE, host, {"type": "notify", "title": title, "text": text, "urgency": "critical"}, timeout=10
                )
            except DaemonCallError:
                pass

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

    async def watch_alert(self, request: AccessRequest, job, text: str) -> None:
        await self.primary.watch_alert(request, job, text)
        import shlex

        await self.desktop.alert(
            f"agent-auth: look at {job.host}", f"{shlex.join(job.spec.get('argv') or [])[:200]} — {text}"
        )

    def __getattr__(self, name: str):
        return getattr(self.primary, name)
