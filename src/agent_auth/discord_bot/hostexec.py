"""Discord surface for commands on hosts (docs/sandbox-design.md §8.6, §8.7, §9).

A `run` / `tpl` request gets: Approve (the host must be armed) · Approve all…
(a time-boxed window; armed, and the host must accept windows) · Approve with
TOTP (works disarmed) · Deny · Edit. A shell request is loud and offers TOTP
and Deny only. The host has the last word on every one of them; a refusal is
shown to whoever clicked and the request stays open.

Slash commands: /arm, /disarm, /lockdown, /unlock, /dnd.
"""

from __future__ import annotations

import io
import logging
import re
import shlex

import discord
from discord import app_commands

from ..core.hostexec import HostExecError, tail
from ..core.service import HumanDecision, TransitionError
from ..core.states import GrantStatus, Platform
from ..models import AccessRequest, Agent, A2AThread, Grant, HostJob
from ..schemas import format_duration, parse_duration
from .views import DenyButton, EditButton, ApproveButton, _apply_decision, _reject_non_owner

log = logging.getLogger(__name__)

_UUID = r"[0-9a-f-]{36}"
COLOR_RUN = 0xF1C40F  # yellow
COLOR_ROOT = 0xE67E22  # orange
COLOR_SHELL = 0xE74C3C  # red
MAX_CODE = 900


def is_hostexec(request: AccessRequest) -> bool:
    return request.platform == Platform.HOSTEXEC


def _code(text: str, limit: int = MAX_CODE) -> str:
    text = text.replace("```", "ʼʼʼ")
    if len(text) > limit:
        text = "…" + text[-(limit - 1) :]
    return f"```\n{text}\n```"


def _command(request: AccessRequest) -> str:
    scope = request.scope
    if request.capability == "shell":
        return "(any command, one at a time)"
    if request.capability.startswith("tpl."):
        params = " ".join(f"{k}={shlex.quote(v)}" for k, v in (scope.get("params") or {}).items())
        return f"template {request.capability[4:]} {params}".strip()
    return shlex.join(scope.get("argv") or [])


def build_embed(
    request: AccessRequest,
    agent: Agent,
    delegator: Agent | None,
    thread: A2AThread | None,
    host: dict | None,
) -> discord.Embed:
    tier = request.scope.get("tier")
    shell = request.capability == "shell"
    if shell:
        title = f"🚨 ROOT SHELL on {request.resource}" if tier == "root" else f"⚠️ USER SHELL on {request.resource}"
        color = COLOR_SHELL
    else:
        title = f"🖥️ Run on {request.resource} as {'ROOT' if tier == 'root' else 'your user'}"
        color = COLOR_ROOT if tier == "root" else COLOR_RUN
    embed = discord.Embed(title=title, description=request.justification[:1000], color=color)
    embed.add_field(name="Command", value=_code(_command(request)), inline=False)
    embed.add_field(name="Agent", value=agent.name, inline=True)
    if agent.project:
        embed.add_field(name="Project", value=agent.project, inline=True)
    if delegator is not None:
        topic = f" (thread topic `{thread.topic}`)" if thread and thread.topic else ""
        embed.add_field(name="🤝 On behalf of", value=f"**{delegator.name}**{topic}"[:256], inline=True)
    scope = request.scope
    if scope.get("cwd"):
        embed.add_field(name="cwd", value=f"`{scope['cwd'][:200]}`", inline=True)
    if scope.get("env"):
        embed.add_field(name="env", value=", ".join(f"`{k}`" for k in scope["env"])[:500], inline=True)
    if scope.get("stdin"):
        embed.add_field(name="stdin", value=f"{len(scope['stdin'])} chars", inline=True)
    if shell:
        embed.add_field(name="For", value=format_duration(request.requested_duration_secs), inline=True)
    elif scope.get("timeout"):
        embed.add_field(name="Timeout", value=format_duration(scope["timeout"]), inline=True)
    embed.add_field(name="Host", value=_host_line(host, tier, shell), inline=False)
    if request.risk_notes:
        embed.add_field(
            name="⚠️ Risk context",
            value="\n".join(f"• {n}" for n in request.risk_notes)[:1000],
            inline=False,
        )
    embed.set_footer(text=f"request {request.id}")
    embed.timestamp = request.created_at
    return embed


def _host_line(host: dict | None, tier: str, shell: bool) -> str:
    if host is None or not host.get("online"):
        return "⚫ offline"
    if host.get("lockdown"):
        return "⛔ locked down"
    state = (host.get("tiers") or {}).get(tier) or {}
    if not state.get("enabled"):
        return f"⛔ the {tier} tier is not enabled on this host"
    if shell:
        return "🔐 a shell is approved with a TOTP code only" if state.get("shell") else "⛔ shells are not enabled here"
    if state.get("armed_until"):
        return f"🔓 {tier} tier armed until <t:{int(state['armed_until'])}:t> — Approve works"
    return f"🔒 {tier} tier not armed — Approve needs `/arm`; Approve with TOTP works now"


def pending_view(request: AccessRequest) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    if request.capability == "shell":
        view.add_item(TotpButton(request.id))
        view.add_item(DenyButton(request.id))
        return view
    view.add_item(ApproveButton(request.id))
    view.add_item(ApproveAllButton(request.id))
    view.add_item(TotpButton(request.id))
    view.add_item(DenyButton(request.id))
    view.add_item(EditButton(request.id))
    return view


def shell_view(request_id: str) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(EndShellButton(request_id))
    return view


async def _load(interaction: discord.Interaction, request_id: str):
    """(request, agent), or None after telling the user it is gone."""
    bot = interaction.client
    async with bot.db.session() as session:
        request = await session.get(AccessRequest, request_id)
        agent = await session.get(Agent, request.agent_id) if request else None
    if request is None or agent is None:
        await interaction.response.send_message("Request no longer exists.", ephemeral=True)
        return None
    return request, agent


class TotpButton(discord.ui.DynamicItem[discord.ui.Button], template=rf"aa:hxtotp:(?P<rid>{_UUID})"):
    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(
            discord.ui.Button(
                label="Approve with TOTP", style=discord.ButtonStyle.primary, custom_id=f"aa:hxtotp:{request_id}"
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match: re.Match):
        return cls(match["rid"])

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        loaded = await _load(interaction, self.request_id)
        if loaded is not None:
            await interaction.response.send_modal(TotpModal(loaded[0]))


class TotpModal(discord.ui.Modal):
    def __init__(self, request: AccessRequest):
        self.request_id = request.id
        self.shell = request.capability == "shell"
        tier = request.scope.get("tier")
        super().__init__(title=f"Approve with TOTP ({request.resource})"[:45], custom_id=f"aa:hxtotpm:{request.id}")
        self.code = discord.ui.TextInput(
            label=f"{request.resource} {tier}-direct code"[:45], min_length=6, max_length=8, placeholder="123456"
        )
        self.add_item(self.code)
        self.duration = None
        if self.shell:
            self.duration = discord.ui.TextInput(
                label="Shell duration",
                default=format_duration(request.requested_duration_secs),
                max_length=16,
            )
            self.add_item(self.duration)
        self.reason = discord.ui.TextInput(
            label="Reason (optional)", style=discord.TextStyle.paragraph, required=False, max_length=500
        )
        self.add_item(self.reason)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        duration_secs = None
        if self.duration is not None and self.duration.value.strip():
            try:
                duration_secs = parse_duration(self.duration.value.strip())
            except ValueError as exc:
                await interaction.followup.send(f"Invalid duration: {exc}", ephemeral=True)
                return
        await _apply_decision(
            interaction,
            self.request_id,
            HumanDecision(
                approve=True,
                decided_by=str(interaction.user),
                reason=self.reason.value.strip(),
                duration_secs=duration_secs,
                totp=self.code.value.strip(),
            ),
        )


class ApproveAllButton(discord.ui.DynamicItem[discord.ui.Button], template=rf"aa:hxall:(?P<rid>{_UUID})"):
    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(
            discord.ui.Button(
                label="Approve all…", style=discord.ButtonStyle.secondary, custom_id=f"aa:hxall:{request_id}"
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match: re.Match):
        return cls(match["rid"])

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        loaded = await _load(interaction, self.request_id)
        if loaded is None:
            return
        config = interaction.client.service.engine.policy.platforms.hostexec
        await interaction.response.send_modal(WindowModal(loaded[0], str(config.window_default)))


class WindowModal(discord.ui.Modal):
    """A time-boxed rule: every command of this tier, from this agent, on
    this host, without asking — for as long as the host stays armed."""

    def __init__(self, request: AccessRequest, default: str):
        self.request_id = request.id
        super().__init__(title="Approve all for a while", custom_id=f"aa:hxallm:{request.id}")
        tier = request.scope.get("tier")
        self.duration = discord.ui.TextInput(
            label=f"{tier} commands on {request.resource}, for"[:45], default=default, max_length=16
        )
        self.add_item(self.duration)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        config = bot.service.engine.policy.platforms.hostexec
        try:
            duration = parse_duration(self.duration.value.strip())
        except ValueError as exc:
            await interaction.followup.send(f"Invalid duration: {exc}", ephemeral=True)
            return
        if duration > parse_duration(config.window_max):
            await interaction.followup.send(f"A window lasts at most {config.window_max}.", ephemeral=True)
            return
        async with bot.db.session() as session:
            request = await session.get(AccessRequest, self.request_id)
            agent = await session.get(Agent, request.agent_id) if request else None
        if request is None or agent is None:
            await interaction.followup.send("Request no longer exists.", ephemeral=True)
            return
        try:
            rule, approved = await bot.hostexec.open_window(request, agent, duration, str(interaction.user))
        except HostExecError as exc:
            await interaction.followup.send(f"No window opened — {request.resource}: {exc}", ephemeral=True)
            return
        await interaction.followup.send(
            f"Window open for {format_duration(duration)}: **{agent.name}** may run "
            f"{request.scope.get('tier')} commands on **{request.resource}** without asking "
            f"(rule `{rule.id[:8]}`, /rules to end it early). Approved now: {len(approved)}.",
            ephemeral=True,
        )


class EndShellButton(discord.ui.DynamicItem[discord.ui.Button], template=rf"aa:hxend:(?P<rid>{_UUID})"):
    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(
            discord.ui.Button(label="End shell", style=discord.ButtonStyle.danger, custom_id=f"aa:hxend:{request_id}")
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match: re.Match):
        return cls(match["rid"])

    async def callback(self, interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot = interaction.client
        from sqlalchemy import select

        async with bot.db.session() as session:
            grant = (
                await session.execute(select(Grant).where(Grant.request_id == self.request_id))
            ).scalar_one_or_none()
        if grant is None or grant.status != GrantStatus.ACTIVE:
            await interaction.followup.send("That shell has already ended.", ephemeral=True)
            return
        try:
            await bot.service.revoke_grant(grant.id, "shell ended", str(interaction.user))
        except TransitionError as exc:
            await interaction.followup.send(f"Could not end it: {exc}", ephemeral=True)
            return
        await interaction.followup.send("Shell ended; anything it was running is killed.", ephemeral=True)


DYNAMIC_ITEMS = (TotpButton, ApproveAllButton, EndShellButton)


# --- results and the shell mirror ---------------------------------------------------


def result_line(job: HostJob) -> str:
    if job.status == "refused":
        return f"⛔ refused by {job.host}: {job.error or '?'}"
    if job.error and job.exit_code is None:
        return f"⚠️ {job.error}"
    took = f" in {job.duration_ms / 1000:.1f}s" if job.duration_ms is not None else ""
    mark = "✅" if job.exit_code == 0 else "❌"
    extra = f" ({job.error})" if job.error else ""
    return f"{mark} exit {job.exit_code}{took}{extra}"


def result_field(job: HostJob) -> str:
    text = result_line(job)
    shown = tail(job.output, limit=MAX_CODE - 20)
    if shown:
        text += "\n" + _code(shown)
    if job.truncated:
        text += "\n(the host kept only the last 1 MiB)"
    return text[:1024]


def output_file(job: HostJob) -> discord.File | None:
    """The whole output, when the message shows only its end."""
    if not job.output or len(job.output) <= MAX_CODE - 20:
        return None
    return discord.File(io.BytesIO(job.output.encode()), filename=f"output-{job.id[:8]}.txt")


# --- slash commands ------------------------------------------------------------------


def register(bot) -> None:
    def unavailable() -> str | None:
        return None if bot.hostexec is not None else "The daemon channel is disabled on this broker."

    async def host_names(interaction: discord.Interaction, current: str):
        if bot.hostexec is None:
            return []
        names = [h["name"] for h in await bot.hostexec.hosts()]
        return [app_commands.Choice(name=n, value=n) for n in names if current.lower() in n][:25]

    tiers = [app_commands.Choice(name="user", value="user"), app_commands.Choice(name="root", value="root")]

    @bot.tree.command(name="arm", description="Let approvals made here count on a host, for a while")
    @app_commands.describe(
        host="the host", tier="user or root", duration="e.g. 30m, 2h (the host caps it)",
        code="a code from that host's <tier>-arm TOTP secret",
    )
    @app_commands.choices(tier=tiers)
    @app_commands.autocomplete(host=host_names)
    async def arm(interaction: discord.Interaction, host: str, tier: str, code: str, duration: str = "1h"):
        if await _reject_non_owner(interaction):
            return
        if unavailable():
            await interaction.response.send_message(unavailable(), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            out = await bot.hostexec.arm(host, tier, duration, code)
        except HostExecError as exc:
            await interaction.followup.send(f"Not armed — {host}: {exc}", ephemeral=True)
            return
        await interaction.followup.send(
            f"🔓 **{host}** {tier} tier armed until <t:{int(out['armed_until'])}:t>.", ephemeral=True
        )

    @bot.tree.command(name="disarm", description="Stop approvals made here from counting on a host")
    @app_commands.choices(tier=tiers)
    @app_commands.autocomplete(host=host_names)
    async def disarm(interaction: discord.Interaction, host: str, tier: str | None = None):
        if await _reject_non_owner(interaction):
            return
        if unavailable():
            await interaction.response.send_message(unavailable(), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            await bot.hostexec.disarm(host, tier)
        except HostExecError as exc:
            await interaction.followup.send(f"{host}: {exc}", ephemeral=True)
            return
        await interaction.followup.send(f"🔒 **{host}** {tier or 'both tiers'} disarmed.", ephemeral=True)

    @bot.tree.command(name="lockdown", description="Kill switch: revoke agents' grants, stop hosts, freeze VMs")
    @app_commands.describe(
        scope="sandboxes: agent-VM agents (default) · all: every agent · host: one host",
        host="with scope host", kill_vm="stop the agent VMs instead of freezing them",
    )
    @app_commands.choices(
        scope=[app_commands.Choice(name=s, value=s) for s in ("sandboxes", "all", "host")]
    )
    @app_commands.autocomplete(host=host_names)
    async def lockdown(
        interaction: discord.Interaction, scope: str = "sandboxes", host: str | None = None, kill_vm: bool = False
    ):
        if await _reject_non_owner(interaction):
            return
        if unavailable():
            await interaction.response.send_message(unavailable(), ephemeral=True)
            return
        await interaction.response.defer(thinking=True)
        try:
            out = await bot.hostexec.lockdown(scope, host, kill_vm, by=str(interaction.user))
        except ValueError as exc:
            await interaction.followup.send(str(exc))
            return
        lines = [f"• `{name}`: {report}" for name, report in out["daemons"].items()] or ["• no daemons paired"]
        embed = discord.Embed(
            title=f"⛔ LOCKDOWN ({scope}{' ' + host if host else ''})",
            description=(
                f"{out['grants_revoked']} grant(s) revoked, {out['threads_closed']} thread(s) closed.\n"
                + "\n".join(lines)
                + "\n\n`/unlock` lifts the broker's side. Each host stays locked until "
                "`/unlock host:<h> code:<root-arm code>` or `sudo agent-auth-hostctl unlock` on it."
            )[:4000],
            color=COLOR_SHELL,
        )
        view = None if kill_vm else KillVmView(scope, host)
        await interaction.followup.send(embed=embed, **({"view": view} if view else {}))

    @bot.tree.command(name="unlock", description="Lift a lockdown (a host needs its own root arm code)")
    @app_commands.autocomplete(host=host_names)
    async def unlock(interaction: discord.Interaction, host: str | None = None, code: str | None = None):
        if await _reject_non_owner(interaction):
            return
        if unavailable():
            await interaction.response.send_message(unavailable(), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            out = await bot.hostexec.unlock(host, code, by=str(interaction.user))
        except HostExecError as exc:
            await interaction.followup.send(f"Not unlocked — {host}: {exc}", ephemeral=True)
            return
        done = ", ".join(f"`{k}`" for k in out["daemons"]) or "the broker only"
        note = "" if (host and code) else " Hosts stay locked until they get their own code."
        await interaction.followup.send(f"Unlocked: {done}.{note}", ephemeral=True)

    @bot.tree.command(name="dnd", description="No approval prompts on your desktops for a while")
    @app_commands.describe(duration="e.g. 2h; leave empty to turn it off")
    async def dnd(interaction: discord.Interaction, duration: str | None = None):
        if await _reject_non_owner(interaction):
            return
        if getattr(bot, "desktop", None) is None:
            await interaction.response.send_message("Desktop prompts are not enabled.", ephemeral=True)
            return
        try:
            seconds = parse_duration(duration) if duration else 0
        except ValueError as exc:
            await interaction.response.send_message(f"Invalid duration: {exc}", ephemeral=True)
            return
        await bot.desktop.set_dnd(seconds)
        await interaction.response.send_message(
            f"Desktop prompts off for {format_duration(seconds)}." if seconds else "Desktop prompts back on.",
            ephemeral=True,
        )


class KillVmView(discord.ui.View):
    """On the lockdown message: stop the frozen VMs outright."""

    def __init__(self, scope: str, host: str | None):
        super().__init__(timeout=3600)
        self.scope, self.host = scope, host

    @discord.ui.button(label="Kill VMs", style=discord.ButtonStyle.danger)
    async def kill(self, interaction: discord.Interaction, button: discord.ui.Button):
        if await _reject_non_owner(interaction):
            return
        await interaction.response.defer(thinking=True)
        out = await interaction.client.hostexec.lockdown(self.scope, self.host, True, by=str(interaction.user))
        lines = [f"• `{name}`: {report}" for name, report in out["daemons"].items()]
        await interaction.followup.send("Agent VMs stopped.\n" + "\n".join(lines))
        button.disabled = True
        await interaction.message.edit(view=self)

