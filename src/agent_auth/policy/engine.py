from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import authority as authority_mod
from ..core.states import Platform, RuleAction
from ..models import AccessRequest, Agent, Rule
from .schema import PolicyAction, PolicyFile, PolicyRule


@dataclass
class PolicyDecision:
    action: PolicyAction
    reason: str
    source: str  # "rule" (DB) | "policy" (YAML/default)
    max_duration_secs: int | None
    llm_model: str | None = None
    retry_budget: int | None = None
    rule_id: str | None = None
    # True when a DB rule pinned this request's exact authority. Only such a rule
    # may bypass the sensitive-capability gate — a wildcard (null-authority) rule
    # cannot silently auto-approve a sensitive role/permission.
    pinned_authority: bool = False


def _matches(
    agent_pattern: str,
    platform: Platform | None,
    capability_pattern: str,
    resource_pattern: str,
    agent_name: str,
    request: AccessRequest,
) -> bool:
    if platform is not None and platform != request.platform:
        return False
    return (
        fnmatch(agent_name, agent_pattern)
        and fnmatch(request.capability, capability_pattern)
        and fnmatch(request.resource, resource_pattern)
    )


class PolicyEngine:
    """Layered evaluation: DB rules (human-created) → YAML rules → default.

    Platform validators run before this in RequestService; they normalize the
    request and enforce hard ceilings, so pattern matching here is stable.
    """

    def __init__(self, policy: PolicyFile):
        self.policy = policy

    async def evaluate(
        self, session: AsyncSession, agent: Agent, request: AccessRequest
    ) -> PolicyDecision:
        db_decision = await self._match_db_rules(session, agent, request)
        if db_decision is not None:
            return db_decision

        for rule in self.policy.rules:
            m = rule.match
            if _matches(
                m.agent, m.platform, m.capability, m.resource, agent.name, request
            ):
                return self._from_yaml_rule(rule)

        defaults = self.policy.defaults
        return PolicyDecision(
            action=defaults.action,
            reason="no matching rule; policy default",
            source="policy",
            max_duration_secs=defaults.max_duration_secs,
            llm_model=self.policy.llm.model,
            retry_budget=self.policy.llm.retry_budget,
        )

    async def _match_db_rules(
        self, session: AsyncSession, agent: Agent, request: AccessRequest
    ) -> PolicyDecision | None:
        rows = await session.execute(
            select(Rule)
            .where(Rule.enabled.is_(True), Rule.platform == request.platform)
            .order_by(Rule.created_at.desc())
        )
        for rule in rows.scalars():
            if not fnmatch(agent.name, rule.agent_pattern):
                continue
            if not fnmatch(request.resource, rule.resource_pattern):
                continue
            # Authority-pinned rules must match the request's exact normalized
            # privilege, so an "approve contents:write" rule never rubber-stamps
            # a later secrets:write, and an "approve view" rule never clears an
            # edit. null authority = any privilege (but see pinned_authority).
            if rule.authority is not None and rule.authority != request.authority:
                continue
            action = (
                PolicyAction.APPROVE
                if rule.action == RuleAction.AUTO_APPROVE
                else PolicyAction.DENY
            )
            return PolicyDecision(
                action=action,
                reason=f"matched saved rule ({rule.notes})" if rule.notes else "matched saved rule",
                source="rule",
                max_duration_secs=rule.max_duration_secs
                or self.policy.defaults.max_duration_secs,
                rule_id=rule.id,
                pinned_authority=rule.authority is not None,
            )
        return None

    def _from_yaml_rule(self, rule: PolicyRule) -> PolicyDecision:
        c = rule.constraints
        return PolicyDecision(
            action=rule.action,
            reason=rule.reason or "matched policy rule",
            source="policy",
            max_duration_secs=c.max_duration_secs or self.policy.defaults.max_duration_secs,
            llm_model=c.llm_model or self.policy.llm.model,
            retry_budget=c.retry_budget
            if c.retry_budget is not None
            else self.policy.llm.retry_budget,
        )

    def cap_duration(self, requested_secs: int, max_secs: int | None) -> int:
        caps = [requested_secs, self.policy.defaults.max_duration_secs]
        if max_secs is not None:
            caps.append(max_secs)
        return min(caps)

    def is_sensitive(self, request: AccessRequest) -> bool:
        """An authority that must always reach a human (unless a human's own
        authority-pinned rule already approved this exact privilege)."""
        return authority_mod.is_sensitive(
            request.platform, request.authority, self.policy.platforms
        )
