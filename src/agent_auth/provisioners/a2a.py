from __future__ import annotations

from fnmatch import fnmatch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.states import GrantStatus, Platform
from ..models import Agent, Grant, utcnow
from ..schemas import CredentialOut
from .base import RequestSpec, SpecValidationError


class A2AProvisioner:
    """Check-based agent-to-agent grants.

    The ACTIVE grant row is the artifact: provision/revoke are no-ops and
    enforcement happens when either side calls check_grant. Message relay
    (webhook/inbox) lives in the API layer and consults check_grant too.

    Convention: capability="talk", resource=<recipient agent name>,
    scope={"topic": <optional glob>}.
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
        if not recipient.webhook_url:
            spec.notes.append("recipient has no webhook; relay messages land in its inbox")
        return spec

    async def provision(self, session: AsyncSession, grant: Grant) -> dict:
        return {"mode": "check_based"}

    async def revoke(self, session: AsyncSession, grant: Grant) -> None:
        return None

    async def get_credential(self, session: AsyncSession, grant: Grant) -> CredentialOut:
        return CredentialOut(
            kind="a2a_grant",
            note="a2a grants are check-based; use /v1/a2a/check and /v1/a2a/send",
        )


async def check_grant(
    session: AsyncSession,
    sender_agent_id: str,
    recipient_name: str,
    topic: str | None = None,
) -> Grant | None:
    """Active, unexpired grant allowing sender → recipient (topic glob-matched)."""
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
        if topic is None or fnmatch(topic, pattern):
            return grant
    return None
