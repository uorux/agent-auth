"""/hosts slash command: fleet health of the paired daemons (hostd, sandboxd)."""

from __future__ import annotations

import discord

from .views import _reject_non_owner

COLOR_HOSTS = 0x3498DB  # blue
# Discord caps an embed's description at 4096 characters.
MAX_DESCRIPTION = 4000


def register(bot) -> None:
    @bot.tree.command(name="hosts", description="Paired host and sandbox daemons")
    async def hosts_command(interaction: discord.Interaction):
        if await _reject_non_owner(interaction):
            return
        daemons = await bot.daemons.list_daemons() if bot.daemons is not None else []
        await interaction.response.send_message(embed=build_hosts_embed(daemons), ephemeral=True)


def _line(d: dict) -> str:
    state = "🟢 online" if d["online"] else "⚫ offline"
    seen = (
        f"last seen <t:{int(d['last_seen_at'].timestamp())}:R>"
        if d.get("last_seen_at")
        else "never connected"
    )
    version = f" · v{d['version']}" if d.get("version") else ""
    return f"{state} **{d['name']}** ({d['role']}){version} · {seen} · `{d['fingerprint'][:19]}`"


def build_hosts_embed(daemons: list[dict]) -> discord.Embed:
    if not daemons:
        body = "No paired daemons. Pair one with `agent-auth admin daemon-pair`."
    else:
        body = "\n".join(_line(d) for d in daemons)
        if len(body) > MAX_DESCRIPTION:
            body = body[: MAX_DESCRIPTION - 1] + "…"
    online = sum(1 for d in daemons if d["online"])
    embed = discord.Embed(title="Hosts", description=body, color=COLOR_HOSTS)
    embed.set_footer(text=f"{online}/{len(daemons)} online")
    return embed
