from __future__ import annotations

import logging

import discord

from discord import app_commands

from ..config import Settings
from ..core.daemons import DaemonHub
from ..core.service import RequestService
from ..db import Database
from ..core.states import GrantStatus
from ..models import AccessRequest, Agent, A2AThread, Grant, Rule
from . import embeds, hostexec as hx_views, hosts, rules, views

log = logging.getLogger(__name__)


class AgentAuthBot(discord.Client):
    def __init__(
        self,
        settings: Settings,
        db: Database,
        service: RequestService,
        daemons: DaemonHub | None = None,
        hostexec=None,
        desktop=None,
    ):
        super().__init__(intents=discord.Intents.default())
        self.settings = settings
        self.db = db
        self.service = service
        self.daemons = daemons
        # core/hostexec.HostExecService and core/desktop.DesktopService (or None).
        self.hostexec = hostexec
        self.desktop = desktop
        self.tree = app_commands.CommandTree(self)
        self._commands_synced = False
        rules.register(self)
        hosts.register(self)
        hx_views.register(self)

    async def setup_hook(self) -> None:
        self.add_dynamic_items(
            views.ApproveButton, views.DenyButton, views.EditButton, *hx_views.DYNAMIC_ITEMS
        )

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
            channel_id = self.settings.discord_channel_id
            if hx_views.is_hostexec(request):
                host = None
                if self.bot.hostexec is not None:
                    host = next(
                        (h for h in await self.bot.hostexec.hosts() if h["name"] == request.resource), None
                    )
                embed = hx_views.build_embed(request, agent, delegator, thread, host)
                view = hx_views.pending_view(request)
                if request.capability == "shell":
                    # Loud: its own channel if there is one.
                    channel_id = self.settings.discord_loud_channel_id or channel_id
                    what = f"🚨 **SHELL request** ({request.scope.get('tier')} on {request.resource})"
                else:
                    what = "host command request"
            else:
                embed = embeds.build_request_embed(request, agent, delegator, thread)
                view = views.pending_view(request.id)
                what = "access request"
            channel = self.bot.get_channel(channel_id) or await self.bot.fetch_channel(channel_id)
            mention = f"<@{self.settings.discord_owner_id}> {what} from **{agent.name}**"
            if delegator is not None:
                mention += f" on behalf of **{delegator.name}**"
            message = await channel.send(content=mention, embed=embed, view=view)
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
            view = views.disabled_view()
            if (
                hx_views.is_hostexec(request)
                and request.capability == "shell"
                and grant is not None
                and grant.status == GrantStatus.ACTIVE
            ):
                view = hx_views.shell_view(request.id)  # End shell
            await message.edit(embed=embeds.apply_outcome(embed, request, grant), view=view)
        except Exception:
            log.exception("failed to update outcome for request %s", request.id)

    async def job_finished(self, request: AccessRequest, job) -> None:
        """A host command's result: on the approval message for a run, in the
        shell's thread for a shell command."""
        try:
            file = hx_views.output_file(job)
            files = [file] if file else []
            if job.shell_id is not None:
                thread = await self._shell_thread(request, create=False)
                if thread is not None:
                    await thread.send(hx_views.result_field(job)[:2000], files=files)
                return
            message = await self._message(request)
            if message is None:
                # Decided by a rule: there is no approval message to edit.
                channel = self.bot.get_channel(
                    self.settings.discord_channel_id
                ) or await self.bot.fetch_channel(self.settings.discord_channel_id)
                await channel.send(
                    f"🖥️ `{job.host}` ({job.tier}) for request `{request.id[:8]}`: {hx_views.result_field(job)}"[:2000],
                    files=files,
                )
                return
            embed = message.embeds[0] if message.embeds else discord.Embed()
            embed.add_field(name="Result", value=hx_views.result_field(job), inline=False)
            await message.edit(embed=embed)
            if files:
                await message.reply("Full output:", files=files)
        except Exception:
            log.exception("failed to post the result of job %s", job.id)

    async def shell_command(self, request: AccessRequest, job) -> bool:
        """Post a shell command to the shell's thread BEFORE it is sent to the
        host. False (it could not be shown) stops the command."""
        try:
            thread = await self._shell_thread(request, create=True)
            if thread is None:
                return False
            import shlex

            where = f" (cwd `{job.spec['cwd']}`)" if job.spec.get("cwd") else ""
            await thread.send(f"`$` {hx_views._code(shlex.join(job.spec['argv']))}{where}"[:2000])
            return True
        except Exception:
            log.exception("failed to mirror shell command %s", job.id)
            return False

    async def _shell_thread(self, request: AccessRequest, create: bool):
        async with self.db.session() as session:
            fresh = await session.get(AccessRequest, request.id)
            thread_id = fresh.discord_thread_id if fresh else None
        await self.bot.wait_until_ready()
        if thread_id:
            return self.bot.get_channel(thread_id) or await self.bot.fetch_channel(thread_id)
        message = await self._message(request)
        if message is None or not create:
            return None
        thread = await message.create_thread(
            name=f"shell · {request.scope.get('tier')} on {request.resource}"[:100], auto_archive_duration=1440
        )
        async with self.db.session() as session:
            fresh = await session.get(AccessRequest, request.id)
            if fresh is not None:
                fresh.discord_thread_id = thread.id
        return thread

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
