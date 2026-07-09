from __future__ import annotations

import logging

import discord

from ..config import Settings
from ..core.service import RequestService
from ..db import Database
from ..models import AccessRequest, Agent, A2AThread, Grant
from . import embeds, views

log = logging.getLogger(__name__)


class AgentAuthBot(discord.Client):
    def __init__(self, settings: Settings, db: Database, service: RequestService):
        super().__init__(intents=discord.Intents.default())
        self.settings = settings
        self.db = db
        self.service = service

    async def setup_hook(self) -> None:
        self.add_dynamic_items(views.ApproveButton, views.DenyButton, views.EditButton)

    async def on_ready(self) -> None:
        log.info("discord bot ready as %s", self.user)


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
