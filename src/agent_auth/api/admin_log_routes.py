"""What happened, for the operator: how each request was decided and by
whom (a rule, the LLM, a person), the commands hosts ran, and who talks to
whom between agents. Read-only; the admin panel shows these."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select

from .. import authority as authority_mod
from ..models import A2AMessage, A2AThread, AccessRequest, Agent, HostJob, utcnow
from .deps import require_admin

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])

OUTPUT_TAIL = 20_000
PAYLOAD_MAX = 4_000


async def _names(session, ids: set[str | None]) -> dict[str, str]:
    ids.discard(None)
    if not ids:
        return {}
    rows = await session.execute(select(Agent.id, Agent.name).where(Agent.id.in_(ids)))
    return {row.id: row.name for row in rows}


@router.get("/log/decisions")
async def decisions(request: Request, limit: int = 200, source: str | None = None, agent: str | None = None):
    """Requests, newest first, each with how it was decided: `source` is
    policy (a rule in the policy file, or its default), rule (a saved rule),
    llm or human; `by` who, where a person or a named rule did."""
    async with request.app.state.db.session() as session:
        query = select(AccessRequest).order_by(AccessRequest.created_at.desc()).limit(max(1, min(limit, 1000)))
        if source:
            query = query.where(AccessRequest.decision_source == source)
        if agent:
            found = (await session.execute(select(Agent.id).where(Agent.name == agent))).scalar_one_or_none()
            query = query.where(AccessRequest.agent_id == (found or ""))
        rows = (await session.execute(query)).scalars().all()
        names = await _names(session, {r.agent_id for r in rows} | {r.delegator_agent_id for r in rows})
        return [
            {
                "id": r.id,
                "at": r.created_at,
                "decided_at": r.decided_at,
                "agent": names.get(r.agent_id, "?"),
                "for": names.get(r.delegator_agent_id) if r.delegator_agent_id else None,
                "platform": r.platform.value,
                "what": authority_mod.label(r.platform, r.authority),
                "resource": r.resource,
                "status": r.status.value,
                "source": r.decision_source.value if r.decision_source else None,
                "by": r.decided_by,
                "reason": r.decision_reason,
                "justification": r.justification,
                "duration_secs": r.approved_duration_secs or r.requested_duration_secs,
            }
            for r in rows
        ]


def _command(spec: dict[str, Any]) -> str:
    if spec.get("template"):
        params = " ".join(f"{k}={v}" for k, v in (spec.get("params") or {}).items())
        return f"[{spec['template']}] {params}".strip()
    return " ".join(str(a) for a in spec.get("argv") or [])


def _job(job: HostJob, names: dict[str, str]) -> dict[str, Any]:
    return {
        "id": job.id,
        "at": job.created_at,
        "agent": names.get(job.agent_id, "?"),
        "host": job.host,
        "tier": job.tier,
        "shell": job.shell_id is not None,
        "command": _command(job.spec or {}),
        "cwd": (job.spec or {}).get("cwd"),
        "status": job.status,
        # What the host admitted it on (a TOTP code, the desk, armed + a person, ...).
        "via": job.via,
        "exit_code": job.exit_code,
        "error": job.error,
        "duration_ms": job.duration_ms,
        "output_bytes": job.output_bytes,
        "request_id": job.request_id,
    }


@router.get("/log/commands")
async def commands(request: Request, limit: int = 200, host: str | None = None):
    """Commands hosts ran (or refused) for agents, newest first."""
    async with request.app.state.db.session() as session:
        query = select(HostJob).order_by(HostJob.created_at.desc()).limit(max(1, min(limit, 1000)))
        if host:
            query = query.where(HostJob.host == host)
        rows = (await session.execute(query)).scalars().all()
        names = await _names(session, {j.agent_id for j in rows})
        return [_job(j, names) for j in rows]


@router.get("/log/commands/{job_id}")
async def command(job_id: str, request: Request):
    """One command with the end of its output and why it was asked for."""
    async with request.app.state.db.session() as session:
        job = await session.get(HostJob, job_id)
        if job is None:
            raise HTTPException(404, "unknown command")
        names = await _names(session, {job.agent_id})
        asked = await session.get(AccessRequest, job.request_id)
        output = job.output or ""
        return {
            **_job(job, names),
            "justification": asked.justification if asked else None,
            "decided_by": asked.decided_by if asked else None,
            "output": output[-OUTPUT_TAIL:],
            "output_cut": len(output) > OUTPUT_TAIL or bool(job.truncated),
            "output_sha256": job.output_sha256,
        }


@router.get("/a2a/graph")
async def a2a_graph(request: Request, hours: int = 24):
    """Who talked to whom in the last `hours`: agents as nodes, one edge per
    (initiator, responder) with its threads and message counts, and the
    threads themselves, newest first. Agents that talked to nobody are left
    out unless they are alive now."""
    hours = max(1, min(hours, 24 * 30))
    now = utcnow()
    since = now - timedelta(hours=hours)
    alive_secs = request.app.state.settings.liveness_threshold_secs
    async with request.app.state.db.session() as session:
        threads = (
            await session.execute(
                select(A2AThread).where(A2AThread.last_activity_at >= since).order_by(A2AThread.last_activity_at.desc())
            )
        ).scalars().all()
        counts = dict(
            (
                await session.execute(
                    select(A2AMessage.thread_id, func.count())
                    .where(A2AMessage.thread_id.in_([t.id for t in threads] or [""]))
                    .group_by(A2AMessage.thread_id)
                )
            ).all()
        )
        delegated = dict(
            (
                await session.execute(
                    select(AccessRequest.delegation_thread_id, func.count())
                    .where(AccessRequest.delegation_thread_id.in_([t.id for t in threads] or [""]))
                    .group_by(AccessRequest.delegation_thread_id)
                )
            ).all()
        )
        agents = (await session.execute(select(Agent).where(Agent.disabled.is_(False)))).scalars().all()
    by_id = {a.id: a for a in agents}
    alive = {
        a.id for a in agents if a.last_seen_at is not None and (now - a.last_seen_at).total_seconds() <= alive_secs
    }
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    out_threads = []
    talked: set[str] = set()
    for t in threads:
        a, b = by_id.get(t.initiator_agent_id), by_id.get(t.responder_agent_id)
        if a is None or b is None:
            continue
        talked |= {a.id, b.id}
        live = t.state in ("open", "pending_open")
        edge = edges.setdefault(
            (a.name, b.name),
            {"from": a.name, "to": b.name, "threads": 0, "open": 0, "messages": 0, "requests": 0, "last": t.last_activity_at},
        )
        edge["threads"] += 1
        edge["open"] += live
        edge["messages"] += counts.get(t.id, 0)
        edge["requests"] += delegated.get(t.id, 0)
        edge["last"] = max(edge["last"], t.last_activity_at)
        out_threads.append(
            {
                "id": t.id,
                "from": a.name,
                "to": b.name,
                "topic": t.topic,
                "state": t.state,
                "close_reason": t.close_reason,
                "messages": counts.get(t.id, 0),
                # Access the responder asked for on the initiator's behalf.
                "requests": delegated.get(t.id, 0),
                "opened": t.created_at,
                "last": t.last_activity_at,
            }
        )
    return {
        "hours": hours,
        "now": now,
        "nodes": [
            {
                "name": a.name,
                "runtime": a.runtime,
                "project": a.project,
                "host": a.host,
                "placement": a.placement,
                "kind": a.kind,
                "alive": a.id in alive,
            }
            for a in agents
            if a.id in talked or a.id in alive
        ],
        "edges": list(edges.values()),
        "threads": out_threads,
    }


@router.get("/a2a/threads/{thread_id}")
async def a2a_thread(thread_id: str, request: Request):
    """One conversation: its messages in order (long payloads cut), and the
    access requested on its behalf."""
    async with request.app.state.db.session() as session:
        thread = await session.get(A2AThread, thread_id)
        if thread is None:
            raise HTTPException(404, "unknown thread")
        messages = (
            await session.execute(
                select(A2AMessage).where(A2AMessage.thread_id == thread_id).order_by(A2AMessage.seq)
            )
        ).scalars().all()
        requests = (
            await session.execute(
                select(AccessRequest).where(AccessRequest.delegation_thread_id == thread_id).order_by(AccessRequest.created_at)
            )
        ).scalars().all()
        names = await _names(
            session,
            {thread.initiator_agent_id, thread.responder_agent_id} | {m.sender_agent_id for m in messages},
        )
    import json

    def cut(payload: Any) -> tuple[str, bool]:
        text = payload.get("text") if isinstance(payload, dict) and isinstance(payload.get("text"), str) else None
        text = text if text is not None else json.dumps(payload, indent=1, default=str)
        return text[:PAYLOAD_MAX], len(text) > PAYLOAD_MAX

    return {
        "id": thread.id,
        "from": names.get(thread.initiator_agent_id, "?"),
        "to": names.get(thread.responder_agent_id, "?"),
        "topic": thread.topic,
        "state": thread.state,
        "close_reason": thread.close_reason,
        "opened": thread.created_at,
        "messages": [
            {
                "seq": m.seq,
                "at": m.created_at,
                "from": names.get(m.sender_agent_id, "?"),
                "type": m.payload.get("type") if isinstance(m.payload, dict) else None,
                "text": cut(m.payload)[0],
                "cut": cut(m.payload)[1],
            }
            for m in messages
        ],
        "requests": [
            {
                "platform": r.platform.value,
                "what": authority_mod.label(r.platform, r.authority),
                "resource": r.resource,
                "status": r.status.value,
                "source": r.decision_source.value if r.decision_source else None,
            }
            for r in requests
        ],
    }
