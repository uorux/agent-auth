from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select, update

from ..config import Settings
from ..crypto import sign_body
from ..db import Database
from ..models import Agent, AgentSession, A2AMessage, A2AThread, Grant, new_uuid, utcnow
from ..provisioners.a2a import check_grant
from .events import KeyedEvents
from .states import (
    CLOSE_CLOSED,
    CLOSE_GRANT_REVOKED,
    CLOSE_IDLE_TIMEOUT,
    CLOSE_OPEN_TIMEOUT,
    CLOSE_PEER_GONE,
    CLOSE_REJECTED,
    GrantStatus,
    SESSION_CLOSE_IDLE,
    THREAD_CLOSED,
    THREAD_OPEN,
    THREAD_PENDING_OPEN,
)

log = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT_SECS = 5


class A2AError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


class A2AThreadService:
    """TCP-like a2a conversations: fast-open with accept/reject, cursor reads,
    liveness from last-seen timestamps, and scheduler sweeps for every timeout.

    All notifications fire post-commit so a woken long-poller's re-read sees
    the row. Webhook pings are notify-only (no payload) and best-effort — the
    cursor read is the source of truth.
    """

    def __init__(self, db: Database, settings: Settings, events: KeyedEvents):
        self.db = db
        self.settings = settings
        self.events = events

    # ------------------------------------------------------------ lifecycle

    async def open_thread(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        to: str,
        topic: str | None,
        payload: dict,
    ) -> dict:
        async with self.db.session() as db:
            responder = (
                await db.execute(select(Agent).where(Agent.name == to))
            ).scalar_one_or_none()
            if responder is None or responder.disabled:
                raise A2AError(404, f"unknown agent {to!r}")
            if responder.kind != "service":
                # Initiate-only: ephemeral agents can never receive threads.
                raise A2AError(403, f"{to!r} is ephemeral and cannot receive threads")
            self._require_session(agent, agent_session)
            grant = await check_grant(db, agent.id, responder.name, topic)
            if grant is None:
                raise A2AError(
                    403,
                    f"no active a2a grant to talk to {to!r}; request one via "
                    f'POST /v1/requests {{"platform": "a2a", "capability": '
                    f'"talk", "resource": "{to}"}} — topic-scoped grants also require '
                    "an explicit matching topic on the open",
                )
            thread_id = new_uuid()
            now = utcnow()
            thread = A2AThread(
                id=thread_id,
                initiator_agent_id=agent.id,
                initiator_session_id=agent_session.id if agent_session else None,
                responder_agent_id=responder.id,
                topic=topic,
                grant_id=grant.id,
                state=THREAD_PENDING_OPEN,
                last_activity_at=now,
                last_seq=1,
            )
            db.add(thread)
            # Flush the thread first: no relationship() ties these mappers, so
            # a single flush won't order the inserts for the FK.
            await db.flush()
            db.add(
                A2AMessage(
                    thread_id=thread_id,
                    seq=1,
                    sender_agent_id=agent.id,
                    sender_session_id=agent_session.id if agent_session else None,
                    recipient_agent_id=responder.id,
                    grant_id=grant.id,
                    payload=payload,
                )
            )
            await db.flush()
            out = await self._thread_out(db, thread, agent.id)
            ping = self._ping_target(
                responder,
                {
                    "type": "a2a_thread_open",
                    "thread_id": thread_id,
                    "from": agent.name,
                    "topic": topic,
                    "seq": 1,
                },
            )
        self.events.notify(responder.id)
        await self._deliver_pings([ping])
        return out

    async def send_message(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        thread_id: str,
        payload: dict,
    ) -> dict:
        dead_grant: A2AError | None = None
        async with self.db.session() as db:
            thread = await self._own_thread(db, thread_id, agent, agent_session)
            self._require_not_closed(thread)
            is_initiator = thread.initiator_agent_id == agent.id

            grant = await db.get(Grant, thread.grant_id)
            if grant is None or grant.status != GrantStatus.ACTIVE or grant.expires_at <= utcnow():
                # Close inside this transaction, but raise only after it
                # commits — raising here would roll the closure back.
                await self._close(db, thread, CLOSE_GRANT_REVOKED, closed_by=None)
                notices = self._closure_notices(thread)
                pings = await self._closure_pings(db, thread)
                dead_grant = A2AError(403, "backing grant is no longer active; thread closed")
            elif is_initiator:
                if thread.state == THREAD_PENDING_OPEN:
                    raise A2AError(
                        409,
                        "thread is pending_open: your opening message already rides the "
                        "open; wait for the responder to accept or reply",
                    )
                recipient_id = thread.responder_agent_id
            else:
                if thread.state == THREAD_PENDING_OPEN:
                    # Replying is accepting; a sessioned reply also claims the
                    # thread for that worker conversation.
                    thread.state = THREAD_OPEN
                    thread.accepted_at = utcnow()
                    if agent_session is not None:
                        thread.responder_session_id = agent_session.id
                recipient_id = thread.initiator_agent_id

            if dead_grant is None:
                seq = await self._next_seq(db, thread)
                message = A2AMessage(
                    thread_id=thread.id,
                    seq=seq,
                    sender_agent_id=agent.id,
                    sender_session_id=agent_session.id if agent_session else None,
                    recipient_agent_id=recipient_id,
                    grant_id=thread.grant_id,
                    payload=payload,
                )
                db.add(message)
                await db.flush()
                state = thread.state
                message_id = message.id
                notices = [await self._peer_wake_key(db, thread, agent.id)]
                recipient = await db.get(Agent, recipient_id)
                pings = [
                    self._ping_target(
                        recipient,
                        {
                            "type": "a2a_message",
                            "thread_id": thread.id,
                            "message_id": message_id,
                            "from": agent.name,
                            "topic": thread.topic,
                            "seq": seq,
                        },
                    )
                ]
        self._fire_notices(notices)
        await self._deliver_pings(pings)
        if dead_grant is not None:
            raise dead_grant
        return {"message_id": message_id, "seq": seq, "thread_state": state}

    async def accept(
        self, agent: Agent, agent_session: AgentSession | None, thread_id: str
    ) -> dict:
        async with self.db.session() as db:
            thread = await self._own_thread(db, thread_id, agent, agent_session)
            self._require_responder(thread, agent.id)
            self._require_pending(thread)
            thread.state = THREAD_OPEN
            thread.accepted_at = utcnow()
            thread.last_activity_at = utcnow()
            if agent_session is not None:
                # Accepting with a session binds the thread to that worker
                # conversation: its wake key, its liveness, its exclusive access.
                thread.responder_session_id = agent_session.id
            out = await self._thread_out(db, thread, agent.id)
            wake_key = await self._peer_wake_key(db, thread, agent.id)
        self.events.notify(wake_key)
        return out

    async def reject(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        thread_id: str,
        reason: str | None,
    ) -> dict:
        async with self.db.session() as db:
            thread = await self._own_thread(db, thread_id, agent, agent_session)
            self._require_responder(thread, agent.id)
            self._require_pending(thread)
            await self._close(db, thread, CLOSE_REJECTED, closed_by=agent.id, note=reason)
            out = await self._thread_out(db, thread, agent.id)
            notices = self._closure_notices(thread, exclude_agent_id=agent.id)
            pings = await self._closure_pings(db, thread, exclude_agent_id=agent.id)
        self._fire_notices(notices)
        await self._deliver_pings(pings)
        return out

    async def close(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        thread_id: str,
        reason: str | None,
    ) -> dict:
        async with self.db.session() as db:
            thread = await self._own_thread(db, thread_id, agent, agent_session)
            self._require_not_closed(thread)
            await self._close(db, thread, CLOSE_CLOSED, closed_by=agent.id, note=reason)
            out = await self._thread_out(db, thread, agent.id)
            notices = self._closure_notices(thread, exclude_agent_id=agent.id)
            pings = await self._closure_pings(db, thread, exclude_agent_id=agent.id)
        self._fire_notices(notices)
        await self._deliver_pings(pings)
        return out

    async def end_session(self, agent: Agent, session_id: str) -> int:
        """Explicit session close (clean CLI exit): threads end peer_gone."""
        async with self.db.session() as db:
            row = await db.get(AgentSession, session_id)
            if row is None or row.agent_id != agent.id:
                raise A2AError(404, "unknown session")
            if row.closed_at is None:
                row.closed_at = utcnow()
                row.close_reason = "closed"
            threads = list(
                (
                    await db.execute(
                        select(A2AThread).where(
                            (A2AThread.initiator_session_id == session_id)
                            | (A2AThread.responder_session_id == session_id),
                            A2AThread.state != THREAD_CLOSED,
                        )
                    )
                ).scalars()
            )
            notices: list[str] = []
            pings: list = []
            for thread in threads:
                await self._close(db, thread, CLOSE_PEER_GONE, closed_by=agent.id)
                notices.extend(self._closure_notices(thread, exclude_agent_id=agent.id))
                pings.extend(
                    await self._closure_pings(db, thread, exclude_agent_id=agent.id)
                )
        self._fire_notices(notices)
        await self._deliver_pings(pings)
        return len(threads)

    # --------------------------------------------------------------- reads

    async def get_thread(
        self, agent: Agent, agent_session: AgentSession | None, thread_id: str
    ) -> dict:
        async with self.db.session() as db:
            thread = await self._own_thread(db, thread_id, agent, agent_session)
            return await self._thread_out(db, thread, agent.id)

    async def list_threads(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        state: str | None = None,
        role: str | None = None,
    ) -> list[dict]:
        self._require_session(agent, agent_session)
        async with self.db.session() as db:
            query = select(A2AThread).order_by(A2AThread.last_activity_at.desc())
            initiator_side = A2AThread.initiator_agent_id == agent.id
            responder_side = A2AThread.responder_agent_id == agent.id
            if agent_session is not None:
                # A sessioned caller sees only its own conversations; unclaimed
                # responder-side threads are the sessionless dispatcher's view.
                initiator_side = initiator_side & (
                    A2AThread.initiator_session_id == agent_session.id
                )
                responder_side = responder_side & (
                    A2AThread.responder_session_id == agent_session.id
                )
            if role == "initiator":
                query = query.where(initiator_side)
            elif role == "responder":
                query = query.where(responder_side)
            else:
                query = query.where(initiator_side | responder_side)
            if state:
                query = query.where(A2AThread.state == state)
            threads = list((await db.execute(query.limit(200))).scalars())
            return [await self._thread_out(db, t, agent.id) for t in threads]

    async def read_messages(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        thread_id: str,
        after_seq: int = 0,
    ) -> dict:
        async with self.db.session() as db:
            thread = await self._own_thread(db, thread_id, agent, agent_session)
            rows = (
                await db.execute(
                    select(A2AMessage, Agent.name)
                    .join(Agent, Agent.id == A2AMessage.sender_agent_id)
                    .where(A2AMessage.thread_id == thread_id, A2AMessage.seq > after_seq)
                    .order_by(A2AMessage.seq)
                )
            ).all()
            return {
                "thread": await self._thread_out(db, thread, agent.id),
                "messages": [
                    {
                        "message_id": m.id,
                        "seq": m.seq,
                        "from": sender_name,
                        "payload": m.payload,
                        "created_at": m.created_at.isoformat(),
                    }
                    for m, sender_name in rows
                ],
            }

    async def events_snapshot(
        self,
        agent: Agent,
        agent_session: AgentSession | None,
        after: datetime | None,
    ) -> dict:
        self._require_session(agent, agent_session)
        async with self.db.session() as db:
            # Pending opens are the sessionless dispatcher's queue: a worker
            # session only tracks conversations it owns.
            pending = []
            if agent_session is None:
                pending = list(
                    (
                        await db.execute(
                            select(A2AThread).where(
                                A2AThread.responder_agent_id == agent.id,
                                A2AThread.state == THREAD_PENDING_OPEN,
                            )
                        )
                    ).scalars()
                )
            initiator_side = A2AThread.initiator_agent_id == agent.id
            responder_side = A2AThread.responder_agent_id == agent.id
            if agent_session is not None:
                initiator_side = initiator_side & (
                    A2AThread.initiator_session_id == agent_session.id
                )
                responder_side = responder_side & (
                    A2AThread.responder_session_id == agent_session.id
                )
            activity_q = select(A2AThread).where(initiator_side | responder_side)
            if after is not None:
                activity_q = activity_q.where(A2AThread.last_activity_at > after)
            else:
                activity_q = activity_q.where(A2AThread.state != THREAD_CLOSED)
            activity = list(
                (
                    await db.execute(
                        activity_q.order_by(A2AThread.last_activity_at).limit(200)
                    )
                ).scalars()
            )
            pending_out = [await self._thread_out(db, t, agent.id) for t in pending]
            activity_out = [await self._thread_out(db, t, agent.id) for t in activity]
        cursor = after
        for t in activity:
            if cursor is None or t.last_activity_at > cursor:
                cursor = t.last_activity_at
        return {
            "pending_opens": pending_out,
            "activity": activity_out,
            "cursor": cursor.isoformat() if cursor else None,
        }

    def wake_key(self, agent: Agent, agent_session: AgentSession | None) -> str:
        return agent_session.id if agent_session is not None else agent.id

    # --------------------------------------------------------------- sweep

    async def sweep(self) -> dict[str, int]:
        """One scheduler tick: idle sessions → peer_gone threads, open-timeout,
        idle threads, and threads whose backing grant died without a send."""
        counts = {"sessions_idled": 0, "open_timeout": 0, "idle_timeout": 0, "grant_revoked": 0}
        now = utcnow()
        notices: list[str] = []
        pings: list[tuple[str, str | None, dict] | None] = []

        async with self.db.session() as db:
            session_cutoff = now - timedelta(seconds=self.settings.session_idle_timeout_secs)
            idle_sessions = list(
                (
                    await db.execute(
                        select(AgentSession).where(
                            AgentSession.closed_at.is_(None),
                            AgentSession.last_seen_at < session_cutoff,
                        )
                    )
                ).scalars()
            )
            for s in idle_sessions:
                s.closed_at = now
                s.close_reason = SESSION_CLOSE_IDLE
                counts["sessions_idled"] += 1
            if idle_sessions:
                dead_ids = [s.id for s in idle_sessions]
                gone = list(
                    (
                        await db.execute(
                            select(A2AThread).where(
                                A2AThread.initiator_session_id.in_(dead_ids)
                                | A2AThread.responder_session_id.in_(dead_ids),
                                A2AThread.state != THREAD_CLOSED,
                            )
                        )
                    ).scalars()
                )
                for thread in gone:
                    await self._close(db, thread, CLOSE_PEER_GONE, closed_by=None)
                    notices.extend(self._closure_notices(thread))
                    pings.extend(await self._closure_pings(db, thread))

            open_cutoff = now - timedelta(seconds=self.settings.a2a_open_timeout_secs)
            stale_opens = list(
                (
                    await db.execute(
                        select(A2AThread).where(
                            A2AThread.state == THREAD_PENDING_OPEN,
                            A2AThread.created_at < open_cutoff,
                        )
                    )
                ).scalars()
            )
            for thread in stale_opens:
                await self._close(db, thread, CLOSE_OPEN_TIMEOUT, closed_by=None)
                counts["open_timeout"] += 1
                notices.extend(self._closure_notices(thread))
                pings.extend(await self._closure_pings(db, thread))

            idle_cutoff = now - timedelta(seconds=self.settings.a2a_thread_idle_timeout_secs)
            idle_threads = list(
                (
                    await db.execute(
                        select(A2AThread).where(
                            A2AThread.state == THREAD_OPEN,
                            A2AThread.last_activity_at < idle_cutoff,
                        )
                    )
                ).scalars()
            )
            for thread in idle_threads:
                await self._close(db, thread, CLOSE_IDLE_TIMEOUT, closed_by=None)
                counts["idle_timeout"] += 1
                notices.extend(self._closure_notices(thread))
                pings.extend(await self._closure_pings(db, thread))

            dead_grant_threads = list(
                (
                    await db.execute(
                        select(A2AThread)
                        .join(Grant, Grant.id == A2AThread.grant_id)
                        .where(
                            A2AThread.state != THREAD_CLOSED,
                            (Grant.status != GrantStatus.ACTIVE)
                            | (Grant.expires_at <= now),
                        )
                    )
                ).scalars()
            )
            for thread in dead_grant_threads:
                await self._close(db, thread, CLOSE_GRANT_REVOKED, closed_by=None)
                counts["grant_revoked"] += 1
                notices.extend(self._closure_notices(thread))
                pings.extend(await self._closure_pings(db, thread))

        self._fire_notices(notices)
        await self._deliver_pings(pings)
        return counts

    # ------------------------------------------------------------- helpers

    def _require_session(self, agent: Agent, agent_session: AgentSession | None) -> None:
        if agent.kind == "ephemeral" and agent_session is None:
            raise A2AError(
                400,
                "ephemeral agents must open a session before using a2a "
                "(POST /v1/sessions, then send X-Agent-Session)",
            )

    async def _own_thread(
        self, db, thread_id: str, agent: Agent, agent_session: AgentSession | None
    ) -> A2AThread:
        """Participant check + session binding on BOTH sides. Conversations are
        session-lived: a bound thread is visible/usable only to the session
        that owns it (opened it, or accepted it), so no other conversation of
        the same agent can read or act on its transcript."""
        thread = await db.get(A2AThread, thread_id)
        if thread is None or agent.id not in (
            thread.initiator_agent_id,
            thread.responder_agent_id,
        ):
            raise A2AError(404, "unknown thread")
        if thread.initiator_agent_id == agent.id:
            self._require_session(agent, agent_session)
            bound = thread.initiator_session_id
        else:
            # Responders are service agents: sessionless (dispatcher) access is
            # fine until a worker session claims the thread.
            bound = thread.responder_session_id
        if bound is not None and (agent_session is None or agent_session.id != bound):
            raise A2AError(403, "thread is bound to a different session of this agent")
        return thread

    def _require_not_closed(self, thread: A2AThread) -> None:
        if thread.state == THREAD_CLOSED:
            raise A2AError(
                409, f"thread is closed ({thread.close_reason or 'closed'})"
            )

    def _require_responder(self, thread: A2AThread, agent_id: str) -> None:
        if thread.responder_agent_id != agent_id:
            raise A2AError(403, "only the thread responder may do this")

    def _require_pending(self, thread: A2AThread) -> None:
        if thread.state != THREAD_PENDING_OPEN:
            raise A2AError(409, f"thread is not pending_open (state {thread.state})")

    async def _next_seq(self, db, thread: A2AThread) -> int:
        # Atomic increment; the UPDATE takes the write lock, so two concurrent
        # senders can't read the same value.
        now = utcnow()
        await db.execute(
            update(A2AThread)
            .where(A2AThread.id == thread.id)
            .values(last_seq=A2AThread.last_seq + 1, last_activity_at=now)
        )
        await db.refresh(thread)
        return thread.last_seq

    async def _close(
        self,
        db,
        thread: A2AThread,
        reason: str,
        closed_by: str | None,
        note: str | None = None,
    ) -> None:
        now = utcnow()
        thread.state = THREAD_CLOSED
        thread.closed_at = now
        thread.close_reason = reason
        thread.closed_by = closed_by
        thread.close_note = note
        # Closure is activity: events_snapshot cursors must pick it up.
        thread.last_activity_at = now

    def _closure_notices(
        self, thread: A2AThread, exclude_agent_id: str | None = None
    ) -> list[str]:
        keys = []
        if thread.initiator_agent_id != exclude_agent_id:
            keys.append(thread.initiator_session_id or thread.initiator_agent_id)
        if thread.responder_agent_id != exclude_agent_id:
            keys.append(thread.responder_session_id or thread.responder_agent_id)
        return keys

    async def _closure_pings(
        self, db, thread: A2AThread, exclude_agent_id: str | None = None
    ) -> list:
        pings = []
        for agent_id in (thread.initiator_agent_id, thread.responder_agent_id):
            if agent_id == exclude_agent_id:
                continue
            agent = await db.get(Agent, agent_id)
            pings.append(
                self._ping_target(
                    agent,
                    {
                        "type": "a2a_thread_closed",
                        "thread_id": thread.id,
                        "topic": thread.topic,
                        "close_reason": thread.close_reason,
                    },
                )
            )
        return pings

    def _fire_notices(self, keys: list[str]) -> None:
        for key in keys:
            self.events.notify(key)

    async def _peer_wake_key(self, db, thread: A2AThread, sender_agent_id: str) -> str:
        if sender_agent_id == thread.initiator_agent_id:
            return thread.responder_session_id or thread.responder_agent_id
        return thread.initiator_session_id or thread.initiator_agent_id

    async def _thread_out(self, db, thread: A2AThread, viewer_agent_id: str) -> dict:
        if viewer_agent_id == thread.initiator_agent_id:
            role, peer_agent_id = "initiator", thread.responder_agent_id
        else:
            role, peer_agent_id = "responder", thread.initiator_agent_id
        peer = await db.get(Agent, peer_agent_id)
        peer_last_seen = peer.last_seen_at if peer else None
        # When the peer's side is session-bound, liveness is the CONVERSATION's
        # (the worker may be dead while the daemon is healthy, and vice versa).
        peer_session_id = (
            thread.initiator_session_id
            if peer_agent_id == thread.initiator_agent_id
            else thread.responder_session_id
        )
        if peer_session_id:
            peer_session = await db.get(AgentSession, peer_session_id)
            if peer_session is not None:
                peer_last_seen = peer_session.last_seen_at
        threshold = timedelta(seconds=self.settings.liveness_threshold_secs)
        return {
            "thread_id": thread.id,
            "peer": peer.name if peer else None,
            "role": role,
            "topic": thread.topic,
            "state": thread.state,
            "close_reason": thread.close_reason,
            "close_note": thread.close_note,
            "grant_id": thread.grant_id,
            "last_seq": thread.last_seq,
            "created_at": thread.created_at.isoformat(),
            "accepted_at": thread.accepted_at.isoformat() if thread.accepted_at else None,
            "closed_at": thread.closed_at.isoformat() if thread.closed_at else None,
            "last_activity_at": thread.last_activity_at.isoformat(),
            "peer_last_seen_at": peer_last_seen.isoformat() if peer_last_seen else None,
            "peer_alive": (
                peer_last_seen is not None and utcnow() - peer_last_seen <= threshold
            ),
        }

    # ------------------------------------------------------------- webhooks

    def _ping_target(self, agent: Agent | None, event: dict):
        """Capture ping ingredients while the DB session is open; delivery
        happens post-commit via _deliver_pings."""
        if agent is None or agent.kind != "service" or not agent.webhook_url:
            return None
        secret = agent.webhook_secret or self.settings.webhook_signing_secret
        if not secret:
            # Never send unsigned pings — the recipient couldn't authenticate
            # them. Polling stays authoritative; rotate-webhook-secret fixes it.
            log.warning(
                "no webhook signing secret for %s; skipping ping", agent.name
            )
            return None
        return (agent.webhook_url, secret, event)

    async def _deliver_pings(self, pings: list) -> None:
        for ping in pings:
            if ping is None:
                continue
            url, secret, event = ping
            raw = json.dumps(event).encode()
            headers = {"Content-Type": "application/json"}
            if secret:
                headers["X-Agent-Auth-Signature"] = sign_body(secret, raw)
            try:
                async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT_SECS) as client:
                    await client.post(url, content=raw, headers=headers)
            except httpx.HTTPError:
                log.warning("a2a webhook ping to %s failed (poll remains authoritative)", url)
