"""The broker's own record, for the agents policy names as its readers
(`audit.readers`). To any other agent the route doesn't exist (404,
before the query is read).

    GET /v1/audit/events?since=<ISO time>&limit=500

One stream, oldest first, each item `{kind, id, at, ...}`:

- request: an access request as it changes (created, decided, ended),
  with who decided it and why;
- grant.issued, grant.ended: a grant's start, and its revocation or expiry;
- host_job: a command a host was asked to run, and how it ended;
- a2a.opened, a2a.closed: conversations between agents (who, the topic;
  never the messages);
- agent.created: a new identity (minted in an agent VM, or by the operator);
- containment: a containment that started;
- security.*: refusals the database doesn't keep (core/security_log.py).

`since` is inclusive: pass back `next` and drop what you've seen (an item
is the same item while kind, id and status are). Model calls are not
here: those are the gateway's.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from .. import authority as authority_mod
from ..core.lockdown import entries as containment_entries
from ..models import A2AThread, AccessRequest, Agent, Grant, HostJob, utcnow
from ..policy.agents import agent_matches
from .admin_log_routes import _command, _names
from .deps import get_agent

router = APIRouter(prefix="/v1")

MAX_LIMIT = 2000
TEXT = 2000


def _allowed(request: Request, agent: Agent) -> None:
    readers = request.app.state.service.engine.policy.audit.readers
    if not any(agent_matches(p, agent) for p in readers):
        raise HTTPException(404, "Not Found")


def _at(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _cut(text: str | None) -> str | None:
    return text if text is None or len(text) <= TEXT else text[:TEXT] + "…"


@router.get("/audit/events")
async def audit_events(request: Request, since: str | None = None, limit: int = 500, agent: Agent = Depends(get_agent)):
    _allowed(request, agent)
    limit = max(1, min(limit, MAX_LIMIT))
    try:
        start = _at(datetime.fromisoformat(since.replace("Z", "+00:00"))) if since else utcnow() - timedelta(hours=1)
    except ValueError:
        raise HTTPException(422, "since: an ISO 8601 time") from None
    out: list[dict[str, Any]] = []
    async with request.app.state.db.session() as session:
        requests = (
            await session.execute(
                select(AccessRequest).where(AccessRequest.updated_at >= start).order_by(AccessRequest.updated_at).limit(limit)
            )
        ).scalars().all()
        async def rows(model, column):
            query = select(model).where(column >= start).order_by(column).limit(limit)
            return list((await session.execute(query)).scalars().all())

        # Each kind of item from its own time column, so a limit cuts every
        # list at the same point in time.
        issued, ended = await rows(Grant, Grant.granted_at), await rows(Grant, Grant.revoked_at)
        started, finished = await rows(HostJob, HostJob.created_at), await rows(HostJob, HostJob.finished_at)
        opened, closed = await rows(A2AThread, A2AThread.created_at), await rows(A2AThread, A2AThread.closed_at)
        grants = {g.id: g for g in issued + ended}.values()
        jobs = {j.id: j for j in started + finished}.values()
        threads = {t.id: t for t in opened + closed}.values()
        agents = (
            await session.execute(select(Agent).where(Agent.created_at >= start).order_by(Agent.created_at).limit(limit))
        ).scalars().all()
        held = await containment_entries(session)
        ids = {r.agent_id for r in requests} | {r.delegator_agent_id for r in requests}
        ids |= {g.agent_id for g in grants} | {j.agent_id for j in jobs}
        ids |= {t.initiator_agent_id for t in threads} | {t.responder_agent_id for t in threads}
        ids |= {a.parent_agent_id for a in agents}
        names = await _names(session, ids)

    for r in requests:
        out.append(
            {
                "kind": "request",
                "id": r.id,
                "at": _at(r.updated_at),
                "created_at": _at(r.created_at),
                "agent": names.get(r.agent_id, "?"),
                "for": names.get(r.delegator_agent_id) if r.delegator_agent_id else None,
                "platform": r.platform.value,
                "what": authority_mod.label(r.platform, r.authority),
                "resource": r.resource,
                "status": r.status.value,
                "source": r.decision_source.value if r.decision_source else None,
                "by": r.decided_by,
                "reason": _cut(r.decision_reason),
                "justification": _cut(r.justification),
                "risk_notes": r.risk_notes or [],
                "duration_secs": r.approved_duration_secs or r.requested_duration_secs,
            }
        )
    for g in grants:
        base = {
            "id": g.id,
            "agent": names.get(g.agent_id, "?"),
            "platform": g.platform.value,
            "what": authority_mod.label(g.platform, g.authority),
            "resource": g.resource,
            "request_id": g.request_id,
        }
        if _at(g.granted_at) >= start:
            out.append({"kind": "grant.issued", "at": _at(g.granted_at), "status": "active",
                        "expires_at": _at(g.expires_at), **base})
        if g.revoked_at is not None and _at(g.revoked_at) >= start:
            out.append({"kind": "grant.ended", "at": _at(g.revoked_at), "status": g.status.value,
                        "reason": _cut(g.revoke_reason), **base})
    started_ids, finished_ids = {j.id for j in started}, {j.id for j in finished}
    for j in jobs:
        base = {
            "id": j.id,
            "created_at": _at(j.created_at),
            "agent": names.get(j.agent_id, "?"),
            "host": j.host,
            "tier": j.tier,
            "shell": j.shell_id is not None,
            "command": _cut(_command(j.spec or {})),
            "cwd": (j.spec or {}).get("cwd"),
            "via": j.via,
        }
        if j.id in started_ids:
            out.append({"kind": "host_job", "at": _at(j.created_at), "status": "started", **base})
        if j.id in finished_ids:
            out.append({"kind": "host_job", "at": _at(j.finished_at), "status": j.status,
                        "exit_code": j.exit_code, "error": _cut(j.error), **base})
    for t in threads:
        base = {
            "id": t.id,
            "from": names.get(t.initiator_agent_id, "?"),
            "to": names.get(t.responder_agent_id, "?"),
            "topic": t.topic,
            "operator": t.grant_id is None,
        }
        if _at(t.created_at) >= start:
            out.append({"kind": "a2a.opened", "at": _at(t.created_at), "status": "open", **base})
        if t.closed_at is not None and _at(t.closed_at) >= start:
            out.append({"kind": "a2a.closed", "at": _at(t.closed_at), "status": "closed",
                        "reason": t.close_reason, **base})
    for a in agents:
        out.append(
            {
                "kind": "agent.created",
                "id": a.id,
                "at": _at(a.created_at),
                "status": "created",
                "agent": a.name,
                "agent_kind": a.kind,
                "runtime": a.runtime,
                "project": a.project,
                "host": a.host,
                "placement": a.placement,
                "parent": names.get(a.parent_agent_id) if a.parent_agent_id else None,
            }
        )
    for e in held:
        try:
            when = _at(datetime.fromisoformat(e["at"]))
        except (KeyError, ValueError):
            continue
        if when >= start:
            out.append(
                {
                    "kind": "containment",
                    "id": e["id"],
                    "at": when,
                    "status": "standing",
                    "match": e.get("match"),
                    "reason": e.get("reason"),
                    "by": e.get("by"),
                    "source": e.get("source"),
                }
            )
    security = getattr(request.app.state, "security_log", None)
    if security is not None:
        out += security.since(start, limit)

    out.sort(key=lambda item: item["at"])
    out = out[:limit]
    return {
        "events": out,
        "next": (out[-1]["at"] if out else start).isoformat(),
        "truncated": len(out) == limit,
    }
