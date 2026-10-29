"""Slash commands for containment (core/lockdown.py): /contain, /contained,
/release. The owner's alone. A containment's own message (with the ping)
is posted by the notifier, whoever made it."""

from __future__ import annotations

import logging

import discord
from discord import app_commands

from ..core.lockdown import ContainError, describe
from .views import _reject_non_owner

log = logging.getLogger(__name__)


def register(bot) -> None:
    def service():
        return getattr(bot, "containment", None)

    async def entry_ids(interaction: discord.Interaction, current: str):
        if service() is None:
            return []
        found = await service().list()
        return [
            app_commands.Choice(name=f"{e['id']} · {describe(e)}"[:100], value=e["id"])
            for e in found
            if current.lower() in e["id"]
        ][:25]

    @bot.tree.command(name="contain", description="Hold agents wherever they run: grants revoked, requests refused")
    @app_commands.describe(
        reason="why (shown with the containment)",
        name="agent name glob, e.g. codex-food-*",
        project="every agent of this project",
        host="every agent on this host",
        runtime="every agent of this runtime",
        everyone="every agent at once",
    )
    async def contain(
        interaction: discord.Interaction,
        reason: str,
        name: str | None = None,
        project: str | None = None,
        host: str | None = None,
        runtime: str | None = None,
        everyone: bool = False,
    ):
        if await _reject_non_owner(interaction):
            return
        if service() is None:
            await interaction.response.send_message("Containment is not set up on this broker.", ephemeral=True)
            return
        match = {k: v for k, v in {"name": name, "project": project, "host": host, "runtime": runtime}.items() if v}
        if not match and not everyone:
            await interaction.response.send_message(
                "Say which agents (name, project, host, runtime), or everyone:True.", ephemeral=True
            )
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            out = await service().contain(match, reason, by=str(interaction.user), source="operator")
        except ContainError as exc:
            await interaction.followup.send(str(exc), ephemeral=True)
            return
        await interaction.followup.send(
            f"Contained `{out['id']}`: {len(out['agents'])} agent(s), {out['grants_revoked']} grant(s) revoked.",
            ephemeral=True,
        )

    @bot.tree.command(name="contained", description="What containments stand")
    async def contained(interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        found = await service().list() if service() is not None else []
        text = "\n".join(f"• `{e['id']}` {discord.utils.escape_markdown(describe(e))}" for e in found)
        await interaction.response.send_message(text[:2000] or "Nothing is contained.", ephemeral=True)

    @bot.tree.command(name="release", description="Lift a containment (its agents ask for their grants again)")
    @app_commands.describe(entry="which one; leave empty to lift every containment")
    @app_commands.autocomplete(entry=entry_ids)
    async def release(interaction: discord.Interaction, entry: str | None = None):
        if await _reject_non_owner(interaction):
            return
        if service() is None:
            await interaction.response.send_message("Containment is not set up on this broker.", ephemeral=True)
            return
        try:
            lifted = await service().lift(entry, by=str(interaction.user))
        except ContainError as exc:
            await interaction.response.send_message(str(exc), ephemeral=True)
            return
        await interaction.response.send_message(
            "Lifted: " + (", ".join(f"`{e['id']}`" for e in lifted) or "nothing was contained")
            + (". A lockdown's hosts stay locked until /unlock with their codes." if any(e.get("source") == "lockdown" for e in lifted) else "."),
        )
