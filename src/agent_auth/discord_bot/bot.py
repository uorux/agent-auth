from __future__ import annotations

import logging

import discord

from discord import app_commands

from ..config import Settings
from ..core.service import RequestService
from ..db import Database
from ..models import AccessRequest, Agent, A2AThread, Grant, Rule
from . import embeds, rules, views

log = logging.getLogger(__name__)


class AgentAuthBot(discord.Client):
    def __init__(self, settings: Settings, db: Database, service: RequestService):
        super().__init__(intents=discord.Intents.default())
        self.settings = settings
        self.db = db
        self.service = service
        self.tree = app_commands.CommandTree(self)
        self._commands_synced = False
        rules.register(self)

    async def setup_hook(self) -> None:
        self.add_dynamic_items(views.ApproveButton, views.DenyButton, views.EditButton)

    async def on_ready(self) -> None:
        log.info("discord bot ready as %s", self.user)
        await self._sync_commands()

    async def _sync_commands(self) -> None:
        """Sync slash commands to the approvals channel's guild — guild-scoped
        sync is instant, global takes up to an hour to propagate."""
        if self._commands_synced:
            return  # on_ready refires on reconnect; sync once per process
        try:
            channel = self.get_channel(
                self.settings.discord_channel_id
            ) or await self.fetch_channel(self.settings.discord_channel_id)
            guild = getattr(channel, "guild", None)
            if guild is None:
                await self.tree.sync()
            else:
                self.tree.copy_global_to(guild=guild)
                await self.tree.sync(guild=guild)
            self._commands_synced = True
        except Exception:
            log.exception("failed to sync slash commands")


class DiscordNotifier:
    """RequestService → Discord. Every method swallows its own errors: a Discord
    outage must never fail the underlying decision."""

    def __init__(self, bot: AgentAuthBot, db: Database, settings: Settings):
        self.bot = bot
        self.db = db
        self.settings = settings

    async def surface(self, request: AccessRequest, agent: Agent) -> None:
        try:
            await self.bot.wait_until_ready()
            delegator = thread = None
            if request.delegator_agent_id is not None:
                async with self.db.session() as session:
                    delegator = await session.get(Agent, request.delegator_agent_id)
                    if request.delegation_thread_id is not None:
                        thread = await session.get(A2AThread, request.delegation_thread_id)
            channel = self.bot.get_channel(
                self.settings.discord_channel_id
            ) or await self.bot.fetch_channel(self.settings.discord_channel_id)
            mention = (
                f"<@{self.settings.discord_owner_id}> access request from **{agent.name}**"
            )
            if delegator is not None:
                mention += f" on behalf of **{delegator.name}**"
            message = await channel.send(
                content=mention,
                embed=embeds.build_request_embed(request, agent, delegator, thread),
                view=views.pending_view(request.id),
            )
            async with self.db.session() as session:
                fresh = await session.get(AccessRequest, request.id)
                if fresh is not None:
                    fresh.discord_channel_id = channel.id
                    fresh.discord_message_id = message.id
        except Exception:
            log.exception("failed to surface request %s on discord", request.id)

    async def update_outcome(self, request: AccessRequest, grant: Grant | None) -> None:
        try:
            message = await self._message(request)
            if message is None:
                return
            embed = message.embeds[0] if message.embeds else discord.Embed()
            await message.edit(
                embed=embeds.apply_outcome(embed, request, grant), view=views.disabled_view()
            )
        except Exception:
            log.exception("failed to update outcome for request %s", request.id)

    async def rule_applied(
        self, request: AccessRequest, agent: Agent, rule: Rule | None, grant: Grant | None
    ) -> None:
        try:
            await self.bot.wait_until_ready()
            channel = self.bot.get_channel(
                self.settings.discord_channel_id
            ) or await self.bot.fetch_channel(self.settings.discord_channel_id)
            await channel.send(embed=embeds.build_rule_applied_embed(request, agent, rule, grant))
        except Exception:
            log.exception("failed to log rule application for request %s", request.id)

    async def update_grant_ended(self, request: AccessRequest, grant: Grant) -> None:
        try:
            message = await self._message(request)
            if message is None:
                return
            embed = message.embeds[0] if message.embeds else discord.Embed()
            await message.edit(embed=embeds.apply_grant_ended(embed, grant))
        except Exception:
            log.exception("failed to mark grant ended for request %s", request.id)

    async def _message(self, request: AccessRequest) -> discord.Message | None:
        if not request.discord_message_id or not request.discord_channel_id:
            return None
        await self.bot.wait_until_ready()
        channel = self.bot.get_channel(
            request.discord_channel_id
        ) or await self.bot.fetch_channel(request.discord_channel_id)
        return await channel.fetch_message(request.discord_message_id)
