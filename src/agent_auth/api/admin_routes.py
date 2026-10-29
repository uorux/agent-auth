from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, update

from .. import authority as authority_mod
from ..core.a2a import OPERATOR_KIND, OPERATOR_NAME
from ..core.daemons import DaemonsDisabled
from ..core.sandboxes import disable_agent_tree
from ..core.service import HumanDecision, TransitionError
from ..crypto import generate_api_key
from ..core.states import GrantStatus, Platform
from ..models import AccessRequest, Agent, Grant, Rule
from ..schemas import (
    AgentAttributesBody,
    AgentCreate,
    AgentOut,
    AgentRenameBody,
    AgentRenamed,
    RequestOut,
    RuleOut,
    SetKindBody,
    SetWebhookBody,
    parse_duration,
)
from .deps import require_admin
from .serialize import request_out

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


def _agent_out(
    agent: Agent, api_key: str | None = None, webhook_secret: str | None = None
) -> AgentOut:
    return AgentOut(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        kind=agent.kind,
        webhook_url=agent.webhook_url,
        lldap_username=agent.lldap_username,
        lldap_managed=agent.lldap_password_encrypted is not None,
        disabled=agent.disabled,
        last_seen_at=agent.last_seen_at,
        parent=agent.parent_agent_id,
        sandbox=agent.sandbox_id,
        runtime=agent.runtime,
        project=agent.project,
        host=agent.host,
        placement=agent.placement,
        lease_expires_at=agent.lease_expires_at,
        api_key=api_key,
        webhook_secret=webhook_secret,
    )


def _not_operator(agent: Agent) -> None:
    # The operator's row is the panel's side of its chats: giving it a key, a
    # webhook or another kind would let something other than the panel speak
    # as the operator.
    if agent.kind == OPERATOR_KIND:
        raise HTTPException(409, "the operator's identity belongs to the admin panel's chat")


def _not_operator_name(name: str) -> None:
    if name == OPERATOR_NAME:
        raise HTTPException(409, f"{OPERATOR_NAME!r} is the admin panel's name for the operator")


@router.post("/agents", response_model=AgentOut, response_model_exclude_none=True)
async def create_agent(body: AgentCreate, request: Request):
    state = request.app.state
    _not_operator_name(body.name)
    full_key, key_id, key_hash = generate_api_key()
    async with state.db.session() as session:
        existing = (
            await session.execute(select(Agent).where(Agent.name == body.name))
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(409, f"agent {body.name!r} already exists")
        webhook_secret = secrets.token_urlsafe(32) if body.webhook_url else None
        agent = Agent(
            name=body.name,
            description=body.description,
            kind=body.kind,
            key_id=key_id,
            api_key_hash=key_hash,
            webhook_url=body.webhook_url,
            webhook_secret=webhook_secret,
            lldap_username=body.lldap_username,
            runtime=body.runtime,
            project=body.project,
            host=body.host,
            # Only the broker places an agent in a VM, when it mints one.
            placement="host",
        )
        session.add(agent)
        await session.flush()
        return _agent_out(agent, api_key=full_key, webhook_secret=webhook_secret)


@router.patch("/agents/{agent_id}/attributes", response_model=AgentOut)
async def set_attributes(agent_id: str, body: AgentAttributesBody, request: Request):
    """Correct what an agent is. Not for agents minted in a VM: the broker
    recorded those from the sandbox they came through."""
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            agent = (
                await session.execute(select(Agent).where(Agent.name == agent_id))
            ).scalar_one_or_none()
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        if agent.sandbox_id is not None:
            raise HTTPException(409, f"{agent.name} was minted in an agent VM; its fields are the broker's")
        for field in body.model_fields_set:
            setattr(agent, field, getattr(body, field) or None)
        return _agent_out(agent)


@router.post("/agents/{agent_id}/rename", response_model=AgentRenamed)
async def rename_agent(agent_id: str, body: AgentRenameBody, request: Request):
    """Give an agent another name. Its key, requests and grants follow its id;
    what holds the name as text is carried over here: saved rules written for
    exactly this agent, and active a2a grants to it. Rules that reach it by a
    glob, and the policy file, are left as they are. Not for agents minted in
    a VM: the broker finds those by the name it gave them."""
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            agent = (
                await session.execute(select(Agent).where(Agent.name == agent_id))
            ).scalar_one_or_none()
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        if agent.sandbox_id is not None:
            raise HTTPException(409, f"{agent.name} was minted in an agent VM; its name is the broker's")
        old, new = agent.name, body.name
        _not_operator_name(new)
        if new == old:
            return AgentRenamed(agent=_agent_out(agent), previous_name=old, rules=0, grants=0)
        taken = (await session.execute(select(Agent.id).where(Agent.name == new))).scalar_one_or_none()
        if taken is not None:
            raise HTTPException(409, f"agent {new!r} already exists")
        agent.name = new
        rules = 0
        for column in (Rule.agent_pattern, Rule.delegator_pattern):
            done = await session.execute(update(Rule).where(column == old).values({column.key: new}))
            rules += done.rowcount
        done = await session.execute(
            update(Rule)
            .where(Rule.platform == Platform.A2A, Rule.resource_pattern == old)
            .values(resource_pattern=new)
        )
        rules += done.rowcount
        done = await session.execute(
            update(Grant)
            .where(
                Grant.platform == Platform.A2A,
                Grant.resource == old,
                Grant.status == GrantStatus.ACTIVE,
            )
            .values(resource=new)
        )
        log.info("agent %s renamed to %s (%d rules, %d grants)", old, new, rules, done.rowcount)
        return AgentRenamed(agent=_agent_out(agent), previous_name=old, rules=rules, grants=done.rowcount)


@router.get("/agents", response_model=list[AgentOut])
async def list_agents(request: Request):
    async with request.app.state.db.session() as session:
        agents = (await session.execute(select(Agent).order_by(Agent.name))).scalars()
        return [_agent_out(a) for a in agents]


@router.post("/agents/{agent_id}/rotate-key", response_model=AgentOut)
async def rotate_key(agent_id: str, request: Request):
    full_key, key_id, key_hash = generate_api_key()
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        agent.key_id = key_id
        agent.api_key_hash = key_hash
        return _agent_out(agent, api_key=full_key)


@router.post(
    "/agents/{agent_id}/rotate-webhook-secret",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def rotate_webhook_secret(agent_id: str, request: Request):
    """Mint (or replace) the per-agent HMAC key for webhook pings — also how
    pre-existing agents opt out of the global-secret fallback."""
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        agent.webhook_secret = secrets.token_urlsafe(32)
        return _agent_out(agent, webhook_secret=agent.webhook_secret)


@router.post(
    "/agents/{agent_id}/rotate-lldap-password",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def rotate_lldap_password(agent_id: str, request: Request):
    """Replace the password of the agent's broker-managed LLDAP account. The
    agent picks the new one up on its next homelab credential fetch; it is
    never printed. Refused for hand-registered accounts."""
    from ..provisioners.base import ProvisionerError, SpecValidationError

    state = request.app.state
    try:
        provisioner = state.registry.get(Platform.HOMELAB)
    except SpecValidationError as exc:
        raise HTTPException(501, str(exc))
    async with state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        try:
            await provisioner.rotate_password(session, agent)
        except ProvisionerError as exc:
            raise HTTPException(409, str(exc))
        return _agent_out(agent)


@router.post(
    "/agents/{agent_id}/set-kind",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def set_kind(agent_id: str, body: SetKindBody, request: Request):
    """Reclassify an existing agent without rotating its API key — the fix for
    a CLI agent registered on the default kind (`service`), which leaves it
    advertised as an a2a peer that never answers.

    Demoting to `ephemeral` also drops the webhook (meaningless: pings only go
    to service agents), closes any thread the agent was RESPONDING to, since
    it can no longer receive them, and revokes every active a2a grant that
    targets it — an ephemeral agent cannot be the resource of a talk grant, so
    none may linger from before the reclassification. Initiators are notified
    `peer_gone` rather than being left to wait out the idle sweep.
    """
    state = request.app.state
    closed = 0
    revoked = 0
    async with state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        was = agent.kind
        agent.kind = body.kind
        if body.kind != "service":
            agent.webhook_url = None
            agent.webhook_secret = None
            agent.last_listen_at = None
        out = _agent_out(agent)
    if body.kind != "service" and was == "service":
        closed = await state.a2a.orphan_inbound_threads(agent_id)
        revoked = await _revoke_a2a_grants_targeting(state, out.name)
    if closed or revoked:
        log.info(
            "set-kind %s → %s closed %d inbound thread(s), revoked %d a2a grant(s)",
            agent_id,
            body.kind,
            closed,
            revoked,
        )
    return out


async def _revoke_a2a_grants_targeting(state, agent_name: str) -> int:
    """Revoke active a2a grants whose resource is `agent_name`. Runs after the
    kind flip so a concurrent open loses either way: the open re-checks the
    responder's kind, and the grant it would ride is gone."""
    async with state.db.session() as session:
        grant_ids = list(
            (
                await session.execute(
                    select(Grant.id).where(
                        Grant.platform == Platform.A2A,
                        Grant.resource == agent_name,
                        Grant.status == GrantStatus.ACTIVE,
                    )
                )
            ).scalars()
        )
    revoked = 0
    for grant_id in grant_ids:
        try:
            await state.service.revoke_grant(
                grant_id, f"target {agent_name!r} reclassified ephemeral", "admin"
            )
            revoked += 1
        except TransitionError:
            # Expired or revoked between the select and now; nothing to do.
            continue
    return revoked


@router.post(
    "/agents/{agent_id}/set-webhook",
    response_model=AgentOut,
    response_model_exclude_none=True,
)
async def set_webhook(agent_id: str, body: SetWebhookBody, request: Request):
    """Set/replace an existing agent's webhook_url (null clears it). Setting a
    URL mints a fresh webhook_secret, shown ONCE in the response."""
    async with request.app.state.db.session() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "unknown agent")
        _not_operator(agent)
        agent.webhook_url = body.webhook_url
        agent.webhook_secret = secrets.token_urlsafe(32) if body.webhook_url else None
        return _agent_out(agent, webhook_secret=agent.webhook_secret)


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(request: Request):
    async with request.app.state.db.session() as session:
        rules = (await session.execute(select(Rule).order_by(Rule.created_at.desc()))).scalars()
        return [
            RuleOut(
                id=r.id,
                action=r.action.value,
                agent_pattern=r.agent_pattern,
                delegator_pattern=r.delegator_pattern,
                platform=r.platform,
                capability_pattern=authority_mod.label(r.platform, r.authority)
                if r.authority is not None
                else "*",
                resource_pattern=r.resource_pattern,
                authority=r.authority,
                max_duration_secs=r.max_duration_secs,
                enabled=r.enabled,
                created_by=r.created_by,
                notes=r.notes,
            )
            for r in rules
        ]


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, request: Request):
    async with request.app.state.db.session() as session:
        rule = await session.get(Rule, rule_id)
        if rule is None:
            raise HTTPException(404, "unknown rule")
        await session.delete(rule)
    return {"ok": True}


@router.get("/requests", response_model=list[RequestOut])
async def list_requests(request: Request, limit: int = 100):
    async with request.app.state.db.session() as session:
        rows = (
            await session.execute(
                select(AccessRequest)
                .order_by(AccessRequest.created_at.desc())
                .limit(min(limit, 500))
            )
        ).scalars()
        return [await request_out(session, r) for r in rows]


class DecideBody(BaseModel):
    approve: bool
    reason: str = ""
    duration: str | int | None = None
    resource_override: str | None = None
    scope_override: dict | None = None
    # hostexec: a code for the host's direct TOTP secret (approves while the
    # host is not armed; the only way to approve a shell).
    totp: str | None = None


@router.post("/requests/{request_id}/decide", response_model=RequestOut)
async def decide_request(request_id: str, body: DecideBody, request: Request):
    """Human decision via API — the fallback surface when Discord is unavailable."""
    duration_secs = None
    if body.duration is not None:
        try:
            duration_secs = parse_duration(body.duration)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
    try:
        req = await request.app.state.service.decide(
            request_id,
            HumanDecision(
                approve=body.approve,
                decided_by="admin-api",
                reason=body.reason,
                duration_secs=duration_secs,
                resource_override=body.resource_override,
                scope_override=body.scope_override,
                totp=body.totp,
            ),
        )
    except TransitionError as exc:
        raise HTTPException(409, str(exc))
    async with request.app.state.db.session() as session:
        return await request_out(session, req)


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant(grant_id: str, request: Request, reason: str = "revoked by admin"):
    try:
        grant = await request.app.state.service.revoke_grant(grant_id, reason, "admin")
    except TransitionError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True, "grant_id": grant.id, "status": grant.status.value}


@router.get("/projects")
async def list_projects(request: Request):
    """The projects policy names, and the agents recorded on each (also the
    projects agents are on that policy does not name)."""
    policy = request.app.state.service.engine.policy
    async with request.app.state.db.session() as session:
        agents = (await session.execute(select(Agent).where(Agent.disabled.is_(False)))).scalars().all()
    out = {
        name: {"description": p.description, "repos": p.repos, "in_policy": True, "agents": []}
        for name, p in policy.projects.items()
    }
    for agent in agents:
        if agent.project:
            out.setdefault(
                agent.project, {"description": "", "repos": [], "in_policy": False, "agents": []}
            )["agents"].append(agent.name)
    return {"projects": out, "wiki": policy.wiki.repo or None}


# --- paired daemons ----------------------------------------------------------


class PairingCodeCreate(BaseModel):
    role: str
    name: str


@router.post("/daemons/pairing-codes")
async def create_pairing_code(body: PairingCodeCreate, request: Request):
    hub = request.app.state.daemons
    try:
        code, expires_at = await hub.create_pairing_code(body.role, body.name)
    except DaemonsDisabled as exc:
        raise HTTPException(503, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return {
        "role": body.role,
        "name": body.name,
        "code": code,
        "expires_at": expires_at,
        "broker_public_key": hub.public_key,
    }


@router.get("/daemons")
async def list_daemons(request: Request):
    return await request.app.state.daemons.list_daemons()


@router.delete("/daemons/{daemon_id}")
async def unpair_daemon(daemon_id: str, request: Request):
    if not await request.app.state.daemons.unpair(daemon_id):
        raise HTTPException(404, "daemon not found")
    return {"ok": True}


@router.get("/broker-key")
async def broker_key(request: Request):
    try:
        return {"broker_public_key": request.app.state.daemons.public_key}
    except DaemonsDisabled as exc:
        raise HTTPException(503, str(exc)) from None


@router.post("/agents/{agent_id}/disable")
async def disable_agent(agent_id: str, request: Request):
    """Disable an agent and every agent it minted (transitively); their active
    grants end within a scheduler tick, revoked through their provisioners."""
    async with request.app.state.db.session() as session:
        if await session.get(Agent, agent_id) is None:
            raise HTTPException(404, "agent not found")
        names = await disable_agent_tree(session, agent_id)
    return {"disabled": names}


# --- hosts: arming and the kill switch ------------------------------------------


def _hostexec(request: Request):
    hostexec = request.app.state.hostexec
    if hostexec is None:
        raise HTTPException(503, "the daemon channel is disabled (BROKER_SIGNING_KEY)")
    return hostexec


@router.get("/hosts")
async def list_hosts(request: Request):
    """Paired hosts: tiers, arm state, lockdown, VM, desktop presence."""
    hostexec = _hostexec(request)
    return {"lockdown": await hostexec.lockdown_state(), "hosts": await hostexec.hosts()}


class ArmBody(BaseModel):
    tier: str = "user"
    duration: str | int = "1h"
    totp: str


@router.post("/hosts/{name}/arm")
async def arm_host(name: str, body: ArmBody, request: Request):
    """Arm a tier: the host then believes the broker's approvals for it. The
    code is for the host's <tier>-arm secret; the host checks it."""
    from ..core.hostexec import HostExecError

    try:
        return await _hostexec(request).arm(name, body.tier, body.duration, body.totp)
    except HostExecError as exc:
        raise HTTPException(409, str(exc)) from None


@router.post("/hosts/{name}/disarm")
async def disarm_host(name: str, request: Request, tier: str | None = None):
    from ..core.hostexec import HostExecError

    try:
        return await _hostexec(request).disarm(name, tier)
    except HostExecError as exc:
        raise HTTPException(409, str(exc)) from None


class LockdownBody(BaseModel):
    scope: str = "sandboxes"
    host: str | None = None
    kill_vm: bool = False


@router.post("/lockdown")
async def lockdown(body: LockdownBody, request: Request):
    """The kill switch: revoke grants, disarm hosts, kill jobs and shells,
    freeze (or stop) agent VMs. scope: sandboxes | all | host."""
    try:
        return await _hostexec(request).lockdown(body.scope, body.host, body.kill_vm, by="admin-api")
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


class UnlockBody(BaseModel):
    host: str | None = None
    totp: str | None = None


@router.post("/unlock")
async def unlock(body: UnlockBody, request: Request):
    """Lift the broker's side of a lockdown. A host's own lock needs its root
    arm code here (host + totp), or `agent-auth-hostctl unlock` on the host."""
    from ..core.hostexec import HostExecError

    try:
        return await _hostexec(request).unlock(body.host, body.totp, by="admin-api")
    except HostExecError as exc:
        raise HTTPException(409, str(exc)) from None
