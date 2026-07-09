from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import httpx

from ..models import AccessRequest, Agent, LLMEvaluation
from ..schemas import format_duration

log = logging.getLogger(__name__)

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["approve", "deny"]},
        "reasoning": {"type": "string"},
        "suggested_duration_secs": {"type": "integer"},
        "notes": {"type": "string"},
    },
    "required": ["verdict", "reasoning"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """\
You are a security reviewer for an AI-agent credential broker. An autonomous agent is
requesting time-bounded access to a resource. Decide whether to approve or deny.

Approve when the justification is specific, plausible, matches the requested capability,
and the scope/duration are proportionate to the stated task. Deny when the justification
is vague, overbroad, mismatched with the capability, or requests more scope/duration than
the task needs. When denying, explain precisely what was insufficient so the agent can
revise its request. Prefer suggesting a shorter duration over denying an otherwise
reasonable request. You cannot grant more than the policy cap; suggesting a duration
above the cap is pointless.
"""


@dataclass
class LLMVerdict:
    verdict: str  # approve | deny | error
    reasoning: str
    suggested_duration_secs: int | None
    raw: dict


class LLMEvaluator:
    def __init__(self, api_key: str, base_url: str, timeout_secs: int = 60):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_secs = timeout_secs

    async def evaluate(
        self,
        model: str,
        agent: Agent,
        request: AccessRequest,
        max_duration_secs: int,
        prior_evaluations: list[LLMEvaluation],
    ) -> LLMVerdict:
        """Any failure returns verdict='error' — callers escalate to human, never approve."""
        try:
            return await self._call(model, agent, request, max_duration_secs, prior_evaluations)
        except Exception:
            log.exception("LLM evaluation failed for request %s", request.id)
            return LLMVerdict(
                verdict="error",
                reasoning="LLM evaluation failed; escalating to human review",
                suggested_duration_secs=None,
                raw={},
            )

    async def _call(
        self,
        model: str,
        agent: Agent,
        request: AccessRequest,
        max_duration_secs: int,
        prior_evaluations: list[LLMEvaluation],
    ) -> LLMVerdict:
        history = ""
        for ev in prior_evaluations:
            history += (
                f"\n- Attempt {ev.attempt}: verdict={ev.verdict}; reasoning: {ev.reasoning}"
            )
        # risk_notes carry validator context, incl. the structural "on behalf
        # of <delegator> (a2a thread topic ...)" line for delegated requests.
        notes = "".join(f"\n- {n}" for n in (request.risk_notes or []))
        user_prompt = f"""\
Agent: {agent.name}
Agent description: {agent.description or "(none)"}

Request:
- Platform: {request.platform.value}
- Capability: {request.capability}
- Resource: {request.resource}
- Scope: {json.dumps(request.scope)}
- Requested duration: {format_duration(request.requested_duration_secs)}
- Policy maximum duration: {format_duration(max_duration_secs)}
- Justification: {request.justification}

Context notes:{notes or " (none)"}

Prior attempts on this request:{history or " (none — first attempt)"}

Respond with your verdict."""

        async with httpx.AsyncClient(timeout=self.timeout_secs) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "access_verdict",
                            "strict": True,
                            "schema": VERDICT_SCHEMA,
                        },
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()

        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        verdict = parsed["verdict"]
        if verdict not in ("approve", "deny"):
            raise ValueError(f"invalid verdict {verdict!r}")
        return LLMVerdict(
            verdict=verdict,
            reasoning=parsed.get("reasoning", ""),
            suggested_duration_secs=parsed.get("suggested_duration_secs"),
            raw=data,
        )
