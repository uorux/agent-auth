from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import authority as authority_mod
from ..core.states import Platform, RuleAction
from ..models import AccessRequest, Agent, Rule, utcnow
from .agents import AgentPattern, Project, agent_matches, resources_for
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
    # True when the matched rule names this request's privilege itself: a DB
    # rule pinned to the exact authority, or a YAML rule whose match.capability
    # is literally the request's capability (no glob). Privileges flagged by
    # `needs_explicit_rule` (github "create") are only cleared by such a rule.
    explicit: bool = False
    # True when the rule is a time-boxed "approve all" window (hostexec): the
    # host is told so, and decides for itself whether it honours windows.
    window: bool = False


def _matches(
    agent_pattern: AgentPattern,
    platform: Platform | None,
    capability_pattern: str,
    resource_pattern: str,
    agent: Agent,
    request: AccessRequest,
    projects: dict[str, Project],
) -> bool:
    if platform is not None and platform != request.platform:
        return False
    return (
        agent_matches(agent_pattern, agent)
        and fnmatch(request.capability, capability_pattern)
        and any(
            fnmatch(request.resource, resource)
            for resource in resources_for(resource_pattern, agent, projects)
        )
    )


def _delegator_matches(
    pattern: AgentPattern | None, delegator: Agent | None, grants_access: bool
) -> bool:
    """Delegation axis of rule matching.

    A rule that names a delegator is delegation-specific: it matches only
    delegated requests whose delegator fits the glob. A rule with no delegator
    pattern was written without delegation in mind — it still applies its
    deny/surface (fail-safe) to delegated requests, but must never be the
    thing that auto-approves or LLM-clears one.
    """
    if pattern is not None:
        return delegator is not None and agent_matches(pattern, delegator)
    if delegator is None:
        return True
    return not grants_access


# Stands in for a delegator whose agent no longer exists.
_GONE = Agent(name="?", placement="host")


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
        delegator = None
        if request.delegator_agent_id is not None:
            # A delegator that is gone matches no rule that names one, and
            # still keeps rules written without delegation from approving.
            delegator = await session.get(Agent, request.delegator_agent_id) or _GONE

        db_decision = await self._match_db_rules(session, agent, request, delegator)
        if db_decision is not None:
            return db_decision

        for rule in self.policy.rules:
            m = rule.match
            if _matches(
                m.agent, m.platform, m.capability, m.resource, agent, request, self.policy.projects
            ) and _delegator_matches(
                m.delegator,
                delegator,
                grants_access=rule.action in (PolicyAction.APPROVE, PolicyAction.LLM),
            ):
                return self._from_yaml_rule(rule, explicit=m.capability == request.capability)

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
        self,
        session: AsyncSession,
        agent: Agent,
        request: AccessRequest,
        delegator: Agent | None,
    ) -> PolicyDecision | None:
        rows = await session.execute(
            select(Rule)
            .where(Rule.enabled.is_(True), Rule.platform == request.platform)
            .order_by(Rule.created_at.desc())
        )
        now = utcnow()
        for rule in rows.scalars():
            if rule.expires_at is not None and rule.expires_at <= now:
                continue
            if not fnmatch(agent.name, rule.agent_pattern):
                continue
            if not fnmatch(request.resource, rule.resource_pattern):
                continue
            if not _delegator_matches(
                rule.delegator_pattern,
                delegator,
                grants_access=rule.action == RuleAction.AUTO_APPROVE,
            ):
                continue
            # Authority-pinned rules must match the request's exact normalized
            # privilege, so an "approve contents:write" rule never rubber-stamps
            # a later secrets:write, and an "approve view" rule never clears an
            # edit. null authority = any privilege (but see pinned_authority).
            if not authority_mod.rule_covers(request.platform, rule.authority, request.authority):
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
                explicit=rule.authority is not None,
                window=(rule.authority or {}).get("action") == "window",
            )
        return None

    def _from_yaml_rule(self, rule: PolicyRule, explicit: bool = False) -> PolicyDecision:
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
            explicit=explicit,
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

    def needs_explicit_rule(self, request: AccessRequest) -> bool:
        """An authority that only a rule naming it may approve or LLM-route
        (see PolicyDecision.explicit); anything else surfaces it to a human."""
        return authority_mod.needs_explicit_rule(request.platform, request.authority)
