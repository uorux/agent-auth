from __future__ import annotations

from fnmatch import fnmatch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..models import Agent, Grant, utcnow
from ..schemas import CredentialOut
from .base import RequestSpec, SpecValidationError


class A2AProvisioner:
    """Check-based agent-to-agent grants backing thread conversations.

    The ACTIVE grant row is the artifact: provision/revoke are no-ops and
    enforcement happens when a thread is opened or a message sent (the thread
    lifecycle lives in core.a2a). A grant authorizes the whole conversation —
    the responder replies under the initiator's grant, so revoking it closes
    the thread in both directions.

    Convention: capability="talk", resource=<responder agent name>,
    scope={"topic": <optional glob>}. Grants belong to the agent identity —
    for CLI agents that identity is one folder/workspace (claude-<folder>,
    key in that folder's env), so all sessions of a folder share its grants
    while each session keeps its own threads.
    """

    platform = Platform.A2A

    async def validate_request(self, session: AsyncSession, spec: RequestSpec) -> RequestSpec:
        if spec.capability != "talk":
            raise SpecValidationError("a2a capability must be 'talk'")
        recipient = (
            await session.execute(select(Agent).where(Agent.name == spec.resource))
        ).scalar_one_or_none()
        if recipient is None or recipient.disabled:
            raise SpecValidationError(f"unknown target agent {spec.resource!r}")
        if recipient.id == spec.agent.id:
            raise SpecValidationError("agent cannot request a2a access to itself")
        if recipient.kind != "service":
            raise SpecValidationError(
                f"a2a targets must be service agents; {spec.resource!r} is ephemeral "
                "and can only initiate threads itself"
            )
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        return {"mode": "check_based"}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        return None

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        return CredentialOut(
            kind="a2a_grant",
            note="a2a grants are check-based; open a thread via POST /v1/a2a/threads",
        )


async def check_grant(
    session: AsyncSession,
    sender_agent_id: str,
    recipient_name: str,
    topic: str | None = None,
    any_topic: bool = False,
) -> Grant | None:
    """Active, unexpired grant allowing sender → recipient (topic glob-matched).

    Topic: a topic-scoped grant (scope.topic other than "*") only matches an
    explicit topic that satisfies the glob — topic=None matches unscoped grants
    only, so omitting the topic can never widen a narrow grant. any_topic=True
    (the informational check endpoint) answers "is there any grant at all".

    Grants are agent-level: sessions of the same agent share them (the folder's
    key IS the permission boundary; sessions only scope threads/liveness).
    """
    now = utcnow()
    rows = await session.execute(
        select(Grant).where(
            Grant.platform == Platform.A2A,
            Grant.agent_id == sender_agent_id,
            Grant.resource == recipient_name,
            Grant.status == GrantStatus.ACTIVE,
            Grant.expires_at > now,
        )
    )
    for grant in rows.scalars():
        pattern = (grant.scope or {}).get("topic", "*")
        if any_topic:
            return grant
        if topic is None:
            if pattern == "*":
                return grant
        elif fnmatch(topic, pattern):
            return grant
    return None
