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
    # Daemon-supplied: validated at ingest, escaped here as well.
    version = f" · v{discord.utils.escape_markdown(d['version'])}" if d.get("version") else ""
    return (
        f"{state} **{d['name']}** ({d['role']}){version} · {seen} · `{d['fingerprint'][:19]}`"
        f"{_host_state(d.get('status'))}"
    )


def _host_state(status) -> str:
    """What a hostd reported about itself. Daemon-supplied: only fixed words,
    numbers and timestamps are taken from it."""
    if not isinstance(status, dict) or status.get("role") != "host":
        return ""
    parts = []
    if status.get("lockdown") is True:
        parts.append("⛔ locked down")
    tiers = status.get("tiers") if isinstance(status.get("tiers"), dict) else {}
    for name in ("user", "root"):
        tier = tiers.get(name)
        if not isinstance(tier, dict) or tier.get("enabled") is not True:
            continue
        until = tier.get("armed_until")
        parts.append(
            f"{name} 🔓 until <t:{int(until)}:t>" if isinstance(until, (int, float)) else f"{name} 🔒"
        )
    for key, label in (("jobs", "job"), ("shells", "shell")):
        if isinstance(status.get(key), int) and status[key] > 0:
            parts.append(f"{status[key]} {label}(s)")
    desktop = status.get("desktop") if isinstance(status.get("desktop"), dict) else {}
    if desktop.get("present") is True:
        parts.append("🧑‍💻 at the desk")
    return ("\n　" + " · ".join(parts)) if parts else ""


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
