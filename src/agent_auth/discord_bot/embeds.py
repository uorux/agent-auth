from __future__ import annotations

import json

import discord

from ..core.states import RequestStatus
from ..models import AccessRequest, Agent, Grant
from ..schemas import format_duration

COLOR_PENDING = 0xF1C40F  # yellow
COLOR_APPROVED = 0x2ECC71  # green
COLOR_DENIED = 0xE74C3C  # red
COLOR_ENDED = 0x95A5A6  # grey

_PLATFORM_EMOJI = {"github": "🐙", "homelab": "🏠", "a2a": "🤝", "google": "📅"}


def _trim(text: str, limit: int = 1000) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_request_embed(request: AccessRequest, agent: Agent) -> discord.Embed:
    emoji = _PLATFORM_EMOJI.get(request.platform.value, "🔑")
    embed = discord.Embed(
        title=f"{emoji} Access request: {request.platform.value}/{request.capability}",
        description=_trim(request.justification),
        color=COLOR_PENDING,
    )
    embed.add_field(name="Agent", value=agent.name, inline=True)
    embed.add_field(name="Resource", value=_trim(request.resource, 256), inline=True)
    embed.add_field(
        name="Requested duration",
        value=format_duration(request.requested_duration_secs),
        inline=True,
    )
    if request.scope:
        embed.add_field(
            name="Scope",
            value=_trim(f"```json\n{json.dumps(request.scope, indent=2)}\n```"),
            inline=False,
        )
    if request.risk_notes:
        embed.add_field(
            name="⚠️ Risk context",
            value=_trim("\n".join(f"• {n}" for n in request.risk_notes)),
            inline=False,
        )
    if request.attempt > 1:
        embed.add_field(name="LLM attempt", value=str(request.attempt), inline=True)
    embed.set_footer(text=f"request {request.id}")
    embed.timestamp = request.created_at
    return embed


def apply_outcome(
    embed: discord.Embed, request: AccessRequest, grant: Grant | None
) -> discord.Embed:
    if request.status in (RequestStatus.GRANTED, RequestStatus.PROVISIONING):
        embed.color = COLOR_APPROVED
        line = f"✅ Approved by {request.decided_by}"
        if request.approved_duration_secs:
            line += f" for **{format_duration(request.approved_duration_secs)}**"
        if grant is not None:
            line += f" — expires <t:{int(grant.expires_at.timestamp())}:R>"
    elif request.status == RequestStatus.PROVISION_FAILED:
        embed.color = COLOR_DENIED
        line = "⚠️ Approved but provisioning **failed**"
    else:
        embed.color = COLOR_DENIED
        line = f"⛔ Denied by {request.decided_by or 'policy'}"
    if request.decision_reason:
        line += f"\n> {_trim(request.decision_reason, 500)}"
    embed.add_field(name="Outcome", value=line, inline=False)
    return embed


def apply_grant_ended(embed: discord.Embed, grant: Grant) -> discord.Embed:
    embed.color = COLOR_ENDED
    label = "Expired" if grant.status.value == "expired" else "Revoked"
    embed.add_field(
        name=label,
        value=f"<t:{int(grant.revoked_at.timestamp())}:f> — {grant.revoke_reason or ''}",
        inline=False,
    )
    return embed
