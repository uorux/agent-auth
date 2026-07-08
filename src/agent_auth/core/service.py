from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import Database
from ..models import AccessRequest, Agent, Grant, LLMEvaluation, Rule, utcnow
from ..policy.engine import PolicyEngine
from ..policy.llm import LLMEvaluator
from ..policy.schema import PolicyAction
from ..provisioners.base import (
    ProvisionerError,
    ProvisionerRegistry,
    RequestSpec,
    SpecValidationError,
)
from ..schemas import RequestCreate
from .events import DecisionEvents
from .states import DecisionSource, GrantStatus, RequestStatus, RuleAction, can_transition

log = logging.getLogger(__name__)


class Notifier(Protocol):
    """Discord (or other) surface. All methods must swallow their own errors."""

    async def surface(self, request: AccessRequest, agent: Agent) -> None: ...
    async def update_outcome(self, request: AccessRequest, grant: Grant | None) -> None: ...
    async def update_grant_ended(self, request: AccessRequest, grant: Grant) -> None: ...


class NullNotifier:
    async def surface(self, request: AccessRequest, agent: Agent) -> None:
        log.warning("no notifier configured; request %s awaits human via API only", request.id)

    async def update_outcome(self, request: AccessRequest, grant: Grant | None) -> None:
        pass

    async def update_grant_ended(self, request: AccessRequest, grant: Grant) -> None:
        pass


class TransitionError(Exception):
    """Illegal or lost-race state transition."""


@dataclass
class HumanDecision:
    approve: bool
    decided_by: str
    reason: str = ""
    duration_secs: int | None = None  # None → requested capped by policy default
    resource_override: str | None = None
    scope_override: dict[str, Any] | None = None
    # Optional persistent rule created alongside the decision
    rule_action: RuleAction | None = None
    rule_capability_pattern: str | None = None
    rule_resource_pattern: str | None = None


class RequestService:
    def __init__(
        self,
        db: Database,
        engine: PolicyEngine,
        registry: ProvisionerRegistry,
        events: DecisionEvents,
        llm: LLMEvaluator | None = None,
        notifier: Notifier | None = None,
    ):
        self.db = db
        self.engine = engine
        self.registry = registry
        self.events = events
        self.llm = llm
        self.notifier: Notifier = notifier or NullNotifier()
        self._llm_tasks: set[asyncio.Task] = set()

    def set_notifier(self, notifier: Notifier) -> None:
        self.notifier = notifier

    # ---------------------------------------------------------------- create

    async def create_request(self, agent_id: str, body: RequestCreate) -> AccessRequest:
        async with self.db.session() as session:
            agent = await session.get(Agent, agent_id)
            assert agent is not None

            request = AccessRequest(
                agent_id=agent.id,
                platform=body.platform,
                capability=body.capability,
                resource=body.resource,
                scope=body.scope,
                justification=body.justification,
                requested_duration_secs=body.duration_secs,
            )

            provisioner = self.registry.get(body.platform)
            try:
                spec = await provisioner.validate_request(
                    session,
                    RequestSpec(
                        agent=agent,
                        capability=body.capability,
                        resource=body.resource,
                        scope=dict(body.scope),
                    ),
                )
            except SpecValidationError as exc:
                request.status = RequestStatus.DENIED
                request.decision_source = DecisionSource.POLICY
                request.decision_reason = f"validator: {exc}"
                request.decided_at = utcnow()
                session.add(request)
                await session.flush()
                return request

            request.capability = spec.capability
            request.resource = spec.resource
            request.scope = spec.scope
            request.risk_notes = spec.notes
            session.add(request)
            await session.flush()

            decision = await self.engine.evaluate(session, agent, request)
            source = (
                DecisionSource.RULE if decision.source == "rule" else DecisionSource.POLICY
            )

            if decision.action == PolicyAction.DENY:
                request.status = RequestStatus.DENIED
                request.decision_source = source
                request.decision_reason = decision.reason
                request.decided_at = utcnow()
                return request

            if decision.action == PolicyAction.APPROVE:
                duration = self.engine.cap_duration(
                    request.requested_duration_secs, decision.max_duration_secs
                )
                await self._approve(session, request, source, "policy", decision.reason, duration)
                await self._provision(session, request)
                return request

            if decision.action == PolicyAction.LLM:
                if self.llm is None:
                    # No evaluator configured — fail safe to human review.
                    request.status = RequestStatus.AWAITING_HUMAN
                    request.risk_notes = [*request.risk_notes, "llm evaluator unavailable"]
                else:
                    request.status = RequestStatus.LLM_EVALUATING
                    request.attempt = 1

            if decision.action == PolicyAction.SURFACE:
                request.status = RequestStatus.AWAITING_HUMAN

            await session.flush()
            request_id = request.id
            status = request.status

        # Post-commit side effects
        if status == RequestStatus.LLM_EVALUATING:
            self._spawn_llm_eval(request_id)
        elif status == RequestStatus.AWAITING_HUMAN:
            await self._surface(request_id)
        return request

    # ------------------------------------------------------------- LLM path

    def _spawn_llm_eval(self, request_id: str) -> None:
        task = asyncio.create_task(self._llm_evaluate(request_id))
        self._llm_tasks.add(task)
        task.add_done_callback(self._llm_tasks.discard)

    async def _llm_evaluate(self, request_id: str) -> None:
        try:
            await self._llm_evaluate_inner(request_id)
        except Exception:
            log.exception("llm evaluation crashed for %s; escalating", request_id)
            try:
                await self._escalate_from_llm(request_id, "internal error during LLM evaluation")
            except Exception:
                log.exception("escalation after crash failed for %s", request_id)

    async def _llm_evaluate_inner(self, request_id: str) -> None:
        assert self.llm is not None
        async with self.db.session() as session:
            request = await session.get(AccessRequest, request_id)
            assert request is not None
            if request.status != RequestStatus.LLM_EVALUATING:
                return
            agent = await session.get(Agent, request.agent_id)
            decision = await self.engine.evaluate(session, agent, request)
            priors = list(
                (
                    await session.execute(
                        select(LLMEvaluation)
                        .where(LLMEvaluation.request_id == request_id)
                        .order_by(LLMEvaluation.attempt)
                    )
                ).scalars()
            )
            max_duration = self.engine.cap_duration(
                request.requested_duration_secs, decision.max_duration_secs
            )
            model = decision.llm_model or self.engine.policy.llm.model
            retry_budget = (
                decision.retry_budget
                if decision.retry_budget is not None
                else self.engine.policy.llm.retry_budget
            )

        verdict = await self.llm.evaluate(model, agent, request, max_duration, priors)

        async with self.db.session() as session:
            request = await session.get(AccessRequest, request_id)
            if request is None or request.status != RequestStatus.LLM_EVALUATING:
                return  # decided elsewhere while we were evaluating
            if verdict.verdict != "error":
                session.add(
                    LLMEvaluation(
                        request_id=request_id,
                        attempt=request.attempt,
                        model=model,
                        verdict=verdict.verdict,
                        reasoning=verdict.reasoning,
                        suggested_duration_secs=verdict.suggested_duration_secs,
                        raw_response={},
                    )
                )

            if verdict.verdict == "approve":
                duration = max_duration
                if verdict.suggested_duration_secs:
                    duration = min(duration, verdict.suggested_duration_secs)
                if not await self._guarded_transition(
                    session, request, RequestStatus.APPROVED
                ):
                    return
                request.decision_source = DecisionSource.LLM
                request.decided_by = model
                request.decision_reason = verdict.reasoning
                request.approved_duration_secs = duration
                request.decided_at = utcnow()
                await self._provision(session, request)
            elif verdict.verdict == "deny":
                if request.attempt >= retry_budget:
                    if await self._guarded_transition(
                        session, request, RequestStatus.AWAITING_HUMAN
                    ):
                        request.risk_notes = [
                            *request.risk_notes,
                            f"LLM denied (attempt {request.attempt}/{retry_budget}): {verdict.reasoning}",
                        ]
                else:
                    if await self._guarded_transition(session, request, RequestStatus.LLM_DENIED):
                        request.decision_source = DecisionSource.LLM
                        request.decided_by = model
                        request.decision_reason = verdict.reasoning
            else:  # error → fail safe to human
                await self._guarded_transition(session, request, RequestStatus.AWAITING_HUMAN)
                request.risk_notes = [*request.risk_notes, verdict.reasoning]

            await session.flush()
            status = request.status

        self.events.notify(request_id)
        if status == RequestStatus.AWAITING_HUMAN:
            await self._surface(request_id)

    async def retry(self, request_id: str, agent_id: str, justification: str) -> AccessRequest:
        async with self.db.session() as session:
            request = await self._own_request(session, request_id, agent_id)
            if request.status != RequestStatus.LLM_DENIED:
                raise TransitionError(f"cannot retry from status {request.status.value}")
            agent = await session.get(Agent, request.agent_id)
            decision = await self.engine.evaluate(session, agent, request)
            retry_budget = (
                decision.retry_budget
                if decision.retry_budget is not None
                else self.engine.policy.llm.retry_budget
            )
            if request.attempt >= retry_budget:
                raise TransitionError("retry budget exhausted; use escalate")
            if not await self._guarded_transition(session, request, RequestStatus.LLM_EVALUATING):
                raise TransitionError("request was decided concurrently")
            request.justification = justification
            request.attempt += 1
            await session.flush()
        self._spawn_llm_eval(request_id)
        return request

    async def escalate(self, request_id: str, agent_id: str) -> AccessRequest:
        async with self.db.session() as session:
            request = await self._own_request(session, request_id, agent_id)
            if request.status != RequestStatus.LLM_DENIED:
                raise TransitionError(f"cannot escalate from status {request.status.value}")
            if not await self._guarded_transition(session, request, RequestStatus.AWAITING_HUMAN):
                raise TransitionError("request was decided concurrently")
            request.risk_notes = [
                *request.risk_notes,
                f"escalated by agent after LLM denial: {request.decision_reason}",
            ]
            await session.flush()
        await self._surface(request_id)
        return request

    async def _escalate_from_llm(self, request_id: str, note: str) -> None:
        async with self.db.session() as session:
            request = await session.get(AccessRequest, request_id)
            if request is None or request.status != RequestStatus.LLM_EVALUATING:
                return
            if await self._guarded_transition(session, request, RequestStatus.AWAITING_HUMAN):
                request.risk_notes = [*request.risk_notes, note]
                await session.flush()
        self.events.notify(request_id)
        await self._surface(request_id)

    # ----------------------------------------------------------- human path

    async def decide(self, request_id: str, decision: HumanDecision) -> AccessRequest:
        async with self.db.session() as session:
            request = await session.get(AccessRequest, request_id)
            if request is None:
                raise TransitionError("unknown request")
            if request.status not in (
                RequestStatus.AWAITING_HUMAN,
                RequestStatus.LLM_DENIED,  # human may pre-empt an agent mid-retry-loop
                RequestStatus.LLM_EVALUATING,
            ):
                raise TransitionError(
                    f"request already resolved (status {request.status.value})"
                )

            target = RequestStatus.APPROVED if decision.approve else RequestStatus.DENIED
            # LLM states can't reach DENIED/APPROVED(HUMAN) directly in the table;
            # human authority overrides — hop through AWAITING_HUMAN.
            if request.status != RequestStatus.AWAITING_HUMAN:
                if not await self._guarded_transition(
                    session, request, RequestStatus.AWAITING_HUMAN
                ):
                    raise TransitionError("request changed state concurrently")
            if not await self._guarded_transition(session, request, target):
                raise TransitionError("request changed state concurrently")

            if decision.rule_action is not None:
                agent = await session.get(Agent, request.agent_id)
                session.add(
                    Rule(
                        action=decision.rule_action,
                        agent_pattern=agent.name,
                        platform=request.platform,
                        capability_pattern=decision.rule_capability_pattern
                        or request.capability,
                        resource_pattern=decision.rule_resource_pattern or request.resource,
                        max_duration_secs=decision.duration_secs,
                        created_by=decision.decided_by,
                        notes=decision.reason or "created from decision",
                    )
                )

            request.decision_source = DecisionSource.HUMAN
            request.decided_by = decision.decided_by
            request.decision_reason = decision.reason
            request.decided_at = utcnow()

            if decision.approve:
                if decision.resource_override:
                    request.approved_resource = decision.resource_override
                if decision.scope_override is not None:
                    request.approved_scope = decision.scope_override
                request.approved_duration_secs = decision.duration_secs or self.engine.cap_duration(
                    request.requested_duration_secs, None
                )
                await self._provision(session, request)

            await session.flush()
            grant = await self._grant_for(session, request_id)

        self.events.notify(request_id)
        await self.notifier.update_outcome(request, grant)
        return request

    # -------------------------------------------------------- provision/revoke

    async def _approve(
        self,
        session: AsyncSession,
        request: AccessRequest,
        source: DecisionSource,
        decided_by: str,
        reason: str,
        duration_secs: int,
    ) -> None:
        if not await self._guarded_transition(session, request, RequestStatus.APPROVED):
            raise TransitionError("request changed state concurrently")
        request.decision_source = source
        request.decided_by = decided_by
        request.decision_reason = reason
        request.approved_duration_secs = duration_secs
        request.decided_at = utcnow()

    async def _provision(self, session: AsyncSession, request: AccessRequest) -> None:
        if not await self._guarded_transition(session, request, RequestStatus.PROVISIONING):
            raise TransitionError("request changed state concurrently")
        grant = Grant(
            request_id=request.id,
            agent_id=request.agent_id,
            platform=request.platform,
            capability=request.capability,
            resource=request.approved_resource or request.resource,
            scope=request.approved_scope
            if request.approved_scope is not None
            else request.scope,
            expires_at=utcnow() + timedelta(seconds=request.approved_duration_secs),
        )
        session.add(grant)
        await session.flush()
        provisioner = self.registry.get(request.platform)
        try:
            grant.provisioner_state = await provisioner.provision(session, grant)
        except Exception as exc:
            if not isinstance(exc, ProvisionerError):
                log.exception("unexpected provisioning error for request %s", request.id)
            log.error("provisioning failed for request %s: %s", request.id, exc)
            grant.status = GrantStatus.PROVISION_FAILED
            grant.revoke_reason = str(exc)
            await self._guarded_transition(session, request, RequestStatus.PROVISION_FAILED)
            request.decision_reason = (request.decision_reason or "") + f" | provisioning failed: {exc}"
            return
        await self._guarded_transition(session, request, RequestStatus.GRANTED)

    async def revoke_grant(self, grant_id: str, reason: str, revoked_by: str = "") -> Grant:
        async with self.db.session() as session:
            grant = await session.get(Grant, grant_id)
            if grant is None or grant.status != GrantStatus.ACTIVE:
                raise TransitionError("grant is not active")
            provisioner = self.registry.get(grant.platform)
            await provisioner.revoke(session, grant)
            grant.status = GrantStatus.REVOKED
            grant.revoked_at = utcnow()
            grant.revoke_reason = f"{reason} ({revoked_by})" if revoked_by else reason
            request = await session.get(AccessRequest, grant.request_id)
        self.events.notify(grant.request_id)
        await self.notifier.update_grant_ended(request, grant)
        return grant

    async def expire_due_grants(self) -> int:
        """One scheduler tick. Returns number of grants expired."""
        async with self.db.session() as session:
            due = list(
                (
                    await session.execute(
                        select(Grant).where(
                            Grant.status == GrantStatus.ACTIVE,
                            Grant.expires_at <= utcnow(),
                        )
                    )
                ).scalars()
            )
        expired = 0
        for grant in due:
            try:
                async with self.db.session() as session:
                    fresh = await session.get(Grant, grant.id)
                    if fresh is None or fresh.status != GrantStatus.ACTIVE:
                        continue
                    provisioner = self.registry.get(fresh.platform)
                    await provisioner.revoke(session, fresh)
                    fresh.status = GrantStatus.EXPIRED
                    fresh.revoked_at = utcnow()
                    fresh.revoke_reason = "expired"
                    request = await session.get(AccessRequest, fresh.request_id)
                expired += 1
                self.events.notify(fresh.request_id)
                await self.notifier.update_grant_ended(request, fresh)
            except Exception:
                # Retried on the next tick; grant stays ACTIVE.
                log.exception("failed to expire grant %s; will retry", grant.id)
        return expired

    # ------------------------------------------------------------- helpers

    async def _surface(self, request_id: str) -> None:
        async with self.db.session() as session:
            request = await session.get(AccessRequest, request_id)
            agent = await session.get(Agent, request.agent_id)
        try:
            await self.notifier.surface(request, agent)
        except Exception:
            log.exception("notifier.surface failed for %s", request_id)

    async def _guarded_transition(
        self, session: AsyncSession, request: AccessRequest, new: RequestStatus
    ) -> bool:
        """Optimistic-concurrency transition; False if illegal or lost a race."""
        current = request.status
        if not can_transition(current, new):
            return False
        result = await session.execute(
            update(AccessRequest)
            .where(AccessRequest.id == request.id, AccessRequest.status == current)
            .values(status=new, updated_at=utcnow())
        )
        if result.rowcount != 1:
            await session.refresh(request)
            return False
        request.status = new
        return True

    async def _own_request(
        self, session: AsyncSession, request_id: str, agent_id: str
    ) -> AccessRequest:
        request = await session.get(AccessRequest, request_id)
        if request is None or request.agent_id != agent_id:
            raise TransitionError("unknown request")
        return request

    async def _grant_for(self, session: AsyncSession, request_id: str) -> Grant | None:
        return (
            await session.execute(select(Grant).where(Grant.request_id == request_id))
        ).scalar_one_or_none()
