from __future__ import annotations

import json
import logging
import re

import discord

from ..core.service import HumanDecision, TransitionError
from ..core.states import RuleAction
from ..schemas import format_duration, parse_duration

log = logging.getLogger(__name__)

_UUID = r"[0-9a-f-]{36}"


def _owner_only(interaction: discord.Interaction) -> bool:
    owner_id = interaction.client.settings.discord_owner_id
    return owner_id and interaction.user.id == owner_id


async def _reject_non_owner(interaction: discord.Interaction) -> bool:
    if _owner_only(interaction):
        return False
    await interaction.response.send_message(
        "Only the configured owner can decide access requests.", ephemeral=True
    )
    return True


def pending_view(request_id: str) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(ApproveButton(request_id))
    view.add_item(DenyButton(request_id))
    view.add_item(EditButton(request_id))
    return view


def disabled_view() -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    for label, style in (
        ("Approve", discord.ButtonStyle.success),
        ("Deny", discord.ButtonStyle.danger),
        ("Edit", discord.ButtonStyle.secondary),
    ):
        view.add_item(discord.ui.Button(label=label, style=style, disabled=True))
    return view


class ApproveButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=rf"aa:approve:(?P<rid>{_UUID})",
):
    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(
            discord.ui.Button(
                label="Approve",
                style=discord.ButtonStyle.success,
                custom_id=f"aa:approve:{request_id}",
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match: re.Match):
        return cls(match["rid"])

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        await interaction.response.send_modal(DecisionModal(self.request_id, approve=True))


class DenyButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=rf"aa:deny:(?P<rid>{_UUID})",
):
    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(
            discord.ui.Button(
                label="Deny",
                style=discord.ButtonStyle.danger,
                custom_id=f"aa:deny:{request_id}",
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match: re.Match):
        return cls(match["rid"])

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        await interaction.response.send_modal(DecisionModal(self.request_id, approve=False))


class EditButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=rf"aa:edit:(?P<rid>{_UUID})",
):
    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(
            discord.ui.Button(
                label="Edit",
                style=discord.ButtonStyle.secondary,
                custom_id=f"aa:edit:{request_id}",
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match: re.Match):
        return cls(match["rid"])

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        # Prefill from the current request state (modal must be the initial response,
        # but a DB read is fast enough to fit the 3s ack window).
        bot = interaction.client
        from ..models import AccessRequest

        async with bot.db.session() as session:
            request = await session.get(AccessRequest, self.request_id)
        if request is None:
            await interaction.response.send_message("Request no longer exists.", ephemeral=True)
            return
        await interaction.response.send_modal(EditModal(self.request_id, request))


class DecisionModal(discord.ui.Modal):
    """Approve (with optional duration override) or Deny, plus optional reason."""

    def __init__(self, request_id: str, approve: bool):
        self.request_id = request_id
        self.approve = approve
        super().__init__(
            title="Approve request" if approve else "Deny request",
            custom_id=f"aa:decision:{request_id}",
        )
        self.reason = discord.ui.TextInput(
            label="Reason (optional)",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=500,
        )
        self.add_item(self.reason)
        if approve:
            self.duration = discord.ui.TextInput(
                label="Duration (blank = requested, capped)",
                required=False,
                placeholder="e.g. 4h, 30m, 2d",
                max_length=16,
            )
            self.add_item(self.duration)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        duration_secs = None
        if self.approve and self.duration.value.strip():
            try:
                duration_secs = parse_duration(self.duration.value.strip())
            except ValueError as exc:
                await interaction.followup.send(f"Invalid duration: {exc}", ephemeral=True)
                return
        decision = HumanDecision(
            approve=self.approve,
            decided_by=str(interaction.user),
            reason=self.reason.value.strip(),
            duration_secs=duration_secs,
        )
        await _apply_decision(interaction, self.request_id, decision)


class EditModal(discord.ui.Modal):
    """Approve with modifications; optionally persist an auto-approve/deny rule.

    Rule field syntax: blank = no rule; otherwise 'approve' or 'deny', with an
    optional breadth suffix that widens the *resource* only — ':exact' (this
    exact privilege on this resource, default), ':capability' (this exact
    privilege on any resource), ':platform' (any privilege on this platform;
    still human-reviewed for sensitive roles/permissions).
    """

    def __init__(self, request_id: str, request):
        self.request_id = request_id
        super().__init__(title="Edit & approve", custom_id=f"aa:editmodal:{request_id}")
        self.duration = discord.ui.TextInput(
            label="Duration",
            default=format_duration(request.requested_duration_secs),
            max_length=16,
        )
        self.resource = discord.ui.TextInput(
            label="Resource",
            default=request.resource[:512],
            max_length=512,
        )
        self.scope = discord.ui.TextInput(
            label="Scope (JSON)",
            style=discord.TextStyle.paragraph,
            default=json.dumps(request.scope)[:4000],
            required=False,
        )
        self.rule = discord.ui.TextInput(
            # Discord caps modal labels at 45 chars; full syntax goes in the placeholder.
            label="Rule (optional)",
            required=False,
            placeholder="approve|deny[:exact|:capability|:platform] — blank = decide once",
            max_length=32,
        )
        self.notes = discord.ui.TextInput(
            label="Notes (optional)",
            style=discord.TextStyle.paragraph,
            required=False,
            max_length=500,
        )
        for item in (self.duration, self.resource, self.scope, self.rule, self.notes):
            self.add_item(item)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            duration_secs = parse_duration(self.duration.value.strip())
        except ValueError as exc:
            await interaction.followup.send(f"Invalid duration: {exc}", ephemeral=True)
            return

        scope_override = None
        if self.scope.value.strip():
            try:
                scope_override = json.loads(self.scope.value)
                if not isinstance(scope_override, dict):
                    raise ValueError("scope must be a JSON object")
            except ValueError as exc:
                await interaction.followup.send(f"Invalid scope JSON: {exc}", ephemeral=True)
                return

        rule_action, rule_res, rule_any_auth, rule_deny_now = None, None, False, False
        rule_raw = self.rule.value.strip().lower()
        if rule_raw:
            m = re.fullmatch(r"(approve|deny)(?::(exact|capability|platform))?", rule_raw)
            if m is None:
                await interaction.followup.send(
                    "Invalid rule: use approve|deny[:exact|:capability|:platform]",
                    ephemeral=True,
                )
                return
            rule_action = (
                RuleAction.AUTO_APPROVE if m.group(1) == "approve" else RuleAction.AUTO_DENY
            )
            rule_deny_now = m.group(1) == "deny"
            breadth = m.group(2) or "exact"
            if breadth == "capability":
                rule_res = "*"  # same privilege, any resource
            elif breadth == "platform":
                rule_res = "*"  # any privilege — sensitive roles still surface
                rule_any_auth = True

        decision = HumanDecision(
            # Creating a deny rule from the Edit modal also denies this request.
            approve=not rule_deny_now,
            decided_by=str(interaction.user),
            reason=self.notes.value.strip(),
            duration_secs=duration_secs,
            resource_override=self.resource.value.strip() or None,
            scope_override=scope_override,
            rule_action=rule_action,
            rule_resource_pattern=rule_res,
            rule_any_authority=rule_any_auth,
        )
        await _apply_decision(interaction, self.request_id, decision)


async def _apply_decision(
    interaction: discord.Interaction, request_id: str, decision: HumanDecision
) -> None:
    bot = interaction.client
    try:
        request = await bot.service.decide(request_id, decision)
    except TransitionError as exc:
        await interaction.followup.send(f"Could not apply decision: {exc}", ephemeral=True)
        return
    verb = "Approved" if decision.approve else "Denied"
    extra = ""
    if decision.approve and request.approved_duration_secs:
        extra = f" for {format_duration(request.approved_duration_secs)}"
    if decision.rule_action is not None:
        extra += " (rule saved)"
    await interaction.followup.send(f"{verb} `{request_id[:8]}`{extra}.", ephemeral=True)
