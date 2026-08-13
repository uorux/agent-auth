"""/rules slash command: browse and manage the persistent auto-approve/deny
rules created from a request's Edit dialogue (or seeded any other way).

The browser is an ephemeral message, so its components die with the message —
plain views with a timeout suffice, no persistent DynamicItems needed (unlike
the request Approve/Deny/Edit buttons, which must survive bot restarts).
"""

from __future__ import annotations

import logging

import discord
from sqlalchemy import func, select

from .. import authority as authority_mod
from ..core.states import RuleAction
from ..models import Rule
from ..schemas import format_duration
from .views import _reject_non_owner

log = logging.getLogger(__name__)

# Discord select menus cap at 25 options, so that's the page size.
PAGE_SIZE = 25

COLOR_LIST = 0x3498DB  # blue
COLOR_APPROVE = 0x2ECC71  # green
COLOR_DENY = 0xE74C3C  # red
COLOR_DISABLED = 0x95A5A6  # grey

_ACTION_EMOJI = {RuleAction.AUTO_APPROVE: "✅", RuleAction.AUTO_DENY: "⛔"}
_ACTION_LABEL = {RuleAction.AUTO_APPROVE: "auto-approve", RuleAction.AUTO_DENY: "auto-deny"}


def register(bot) -> None:
    @bot.tree.command(name="rules", description="View and manage auto-approve/deny rules")
    async def rules_command(interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        await render(interaction, edit=False)


def _privilege(rule: Rule) -> str:
    if rule.authority is None:
        return "*"
    return authority_mod.label(rule.platform, rule.authority)


def rule_summary(rule: Rule) -> str:
    line = (
        f"{_ACTION_EMOJI[rule.action]} `{rule.id[:8]}` **{rule.agent_pattern}** → "
        f"{rule.platform.value}/{_privilege(rule)} on `{rule.resource_pattern}`"
    )
    if not rule.enabled:
        line += " *(disabled)*"
    return line


def build_rules_embed(rules: list[Rule], page: int = 0, pages: int = 1, total: int = 0) -> discord.Embed:
    embed = discord.Embed(title="🧾 Decision rules", color=COLOR_LIST)
    if not rules:
        embed.description = "No rules yet. Create one from a request's **Edit** dialogue."
        return embed
    embed.description = "\n".join(rule_summary(r) for r in rules)
    if pages > 1:
        embed.set_footer(text=f"Page {page + 1}/{pages} · {total} rules, newest first")
    return embed


def build_rule_detail_embed(rule: Rule) -> discord.Embed:
    if not rule.enabled:
        color = COLOR_DISABLED
    elif rule.action == RuleAction.AUTO_APPROVE:
        color = COLOR_APPROVE
    else:
        color = COLOR_DENY
    embed = discord.Embed(
        title=f"{_ACTION_EMOJI[rule.action]} Rule {rule.id[:8]} — {_ACTION_LABEL[rule.action]}",
        color=color,
    )
    embed.add_field(name="Agent", value=rule.agent_pattern, inline=True)
    if rule.delegator_pattern is not None:
        embed.add_field(name="🤝 Delegator", value=rule.delegator_pattern, inline=True)
    embed.add_field(name="Platform", value=rule.platform.value, inline=True)
    embed.add_field(name="Privilege", value=_privilege(rule), inline=True)
    embed.add_field(name="Resource", value=rule.resource_pattern, inline=True)
    embed.add_field(
        name="Max duration",
        value=format_duration(rule.max_duration_secs) if rule.max_duration_secs else "—",
        inline=True,
    )
    embed.add_field(name="Enabled", value="yes" if rule.enabled else "no", inline=True)
    if rule.created_by:
        embed.add_field(name="Created by", value=rule.created_by, inline=True)
    if rule.notes:
        embed.add_field(name="Notes", value=rule.notes[:1000], inline=False)
    embed.set_footer(text=f"rule {rule.id}")
    embed.timestamp = rule.created_at
    return embed


async def _load_rules(db, page: int) -> tuple[list[Rule], int, int, int]:
    """One page of rules, newest first. Returns (rules, page, pages, total)
    with page clamped — deletes and races can strand a stale page index."""
    async with db.session() as session:
        total = (await session.execute(select(func.count()).select_from(Rule))).scalar_one()
        pages = max(1, -(-total // PAGE_SIZE))
        page = max(0, min(page, pages - 1))
        rules = list(
            (
                await session.execute(
                    select(Rule)
                    .order_by(Rule.created_at.desc())
                    .offset(page * PAGE_SIZE)
                    .limit(PAGE_SIZE)
                )
            ).scalars()
        )
    return rules, page, pages, total


async def render(
    interaction: discord.Interaction,
    selected_id: str | None = None,
    page: int = 0,
    edit: bool = True,
) -> None:
    """(Re)draw the browser from fresh DB state as the interaction response."""
    rules, page, pages, total = await _load_rules(interaction.client.db, page)
    selected = next((r for r in rules if r.id == selected_id), None)
    embeds = [build_rules_embed(rules, page, pages, total)]
    if selected is not None:
        embeds.append(build_rule_detail_embed(selected))
    view = RulesView(rules, selected, page, pages)
    if edit:
        await interaction.response.edit_message(embeds=embeds, view=view)
    else:
        await interaction.response.send_message(embeds=embeds, view=view, ephemeral=True)


class RulesView(discord.ui.View):
    def __init__(self, rules: list[Rule], selected: Rule | None, page: int = 0, pages: int = 1):
        super().__init__(timeout=600)
        if rules:
            self.add_item(RuleSelect(rules, selected, page))
        if pages > 1:
            self.add_item(PageButton(page, pages, delta=-1))
            self.add_item(PageButton(page, pages, delta=1))
        if selected is not None:
            self.add_item(ToggleRuleButton(selected, page))
            self.add_item(DeleteRuleButton(selected, page))


class RuleSelect(discord.ui.Select):
    def __init__(self, rules: list[Rule], selected: Rule | None, page: int):
        self.page = page
        options = [
            discord.SelectOption(
                label=f"{r.agent_pattern} · {r.platform.value}/{_privilege(r)}"[:100],
                description=f"on {r.resource_pattern}"[:100],
                emoji=_ACTION_EMOJI[r.action],
                value=r.id,
                default=selected is not None and r.id == selected.id,
            )
            for r in rules
        ]
        super().__init__(placeholder="Select a rule to manage…", options=options, row=0)

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        await render(interaction, selected_id=self.values[0], page=self.page)


class PageButton(discord.ui.Button):
    def __init__(self, page: int, pages: int, delta: int):
        self.target = page + delta
        super().__init__(
            label="◀ Prev" if delta < 0 else "Next ▶",
            style=discord.ButtonStyle.primary,
            disabled=not (0 <= self.target < pages),
            row=1,
        )

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        # Selection is cleared on page turns; it usually isn't on the new page.
        await render(interaction, page=self.target)


class ToggleRuleButton(discord.ui.Button):
    def __init__(self, rule: Rule, page: int):
        self.rule_id = rule.id
        self.page = page
        super().__init__(
            label="Disable" if rule.enabled else "Enable",
            style=discord.ButtonStyle.secondary if rule.enabled else discord.ButtonStyle.success,
            row=2,
        )

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        async with interaction.client.db.session() as session:
            rule = await session.get(Rule, self.rule_id)
            if rule is not None:
                rule.enabled = not rule.enabled
        await render(interaction, selected_id=self.rule_id, page=self.page)


class DeleteRuleButton(discord.ui.Button):
    def __init__(self, rule: Rule, page: int):
        self.rule_id = rule.id
        self.page = page
        super().__init__(label="Delete", style=discord.ButtonStyle.danger, row=2)

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        async with interaction.client.db.session() as session:
            rule = await session.get(Rule, self.rule_id)
            if rule is not None:
                await session.delete(rule)
        await render(interaction, page=self.page)
