"""agent-auth-hostctl: talk to this host's hostd over its local socket.

root may do everything; the user the host is configured for may see the
status, arm and disarm their own (user) tier, set do-not-disturb, and report
desktop presence (for hypridle / lock-screen hooks).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

import typer

from ..daemon_common.localsock import LocalApiError, call

app = typer.Typer(help="control this host's agent-auth daemon", no_args_is_help=True,
                  pretty_exceptions_show_locals=False)

SOCKET_ENV = "AGENT_AUTH_HOSTD_CTL"
DEFAULT_SOCKET = "/run/agent-auth-hostd/ctl.sock"


def _call(method: str, **params):
    try:
        return call(os.environ.get(SOCKET_ENV, DEFAULT_SOCKET), method, params, timeout=60)
    except LocalApiError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        sys.exit(1)
    except OSError as exc:
        typer.secho(f"hostd is not reachable: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(1)


def _when(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "-"


@app.command()
def status(as_json: bool = typer.Option(False, "--json")):
    """Tiers, arming, jobs, shells, lockdown, desktop presence."""
    s = _call("status")
    if as_json:
        typer.echo(json.dumps(s, indent=2))
        return
    if s["lockdown"]:
        typer.secho("LOCKED DOWN (agent-auth-hostctl unlock, as root)", fg=typer.colors.RED, bold=True)
    for name, tier in s["tiers"].items():
        if not tier["enabled"]:
            typer.echo(f"{name:5} disabled")
            continue
        armed = f"armed until {_when(tier['armed_until'])}" if tier["armed_until"] else "not armed"
        totp = "" if tier["totp"] else "  (TOTP not enrolled)"
        typer.echo(f"{name:5} {armed}{'  shells on' if tier['shell'] else ''}{totp}")
    typer.echo(f"jobs {s['jobs']}  shells {s['shells']}")
    if s.get("vm"):
        typer.echo(f"vm {s['vm']['unit']}: {s['vm']['state']}")
    d = s["desktop"]
    if d["enabled"]:
        dnd = f"  do-not-disturb until {_when(d['dnd_until'])}" if d["dnd_until"] else ""
        typer.echo(f"desktop: {'present' if d['present'] else 'away'}{dnd}")


@app.command()
def arm(
    duration: str = typer.Argument("1h", help="e.g. 30m, 2h (capped by this host's policy)"),
    tier: str = typer.Option("user", "--tier", help="user | root (root needs sudo)"),
):
    """Let Discord approvals count for a tier, for a while."""
    out = _call("arm", tier=tier, duration=duration)
    typer.echo(f"{tier} tier armed until {_when(out['armed_until'])}")


@app.command()
def disarm(tier: str = typer.Option(None, "--tier", help="default: both")):
    _call("disarm", tier=tier)
    typer.echo("disarmed")


@app.command()
def lockdown(kill_vm: bool = typer.Option(False, "--kill-vm", help="stop the agent VM instead of freezing it")):
    """Refuse everything on this host, kill running jobs and shells, and
    freeze the agent VM. Stays in force across restarts until `unlock`."""
    out = _call("lockdown", kill_vm=kill_vm)
    typer.echo(f"locked down{' · vm ' + out['vm'] if out.get('vm') else ''}")


@app.command()
def unlock():
    """Clear a lockdown (root only)."""
    out = _call("unlock")
    typer.echo(f"unlocked{' · vm ' + out['vm'] if out.get('vm') else ''}")


@app.command()
def dnd(duration: str = typer.Argument(None, help="e.g. 2h; omit to turn it off")):
    """No approval prompts on this desktop for a while (they go to Discord)."""
    out = _call("dnd", duration=duration)
    typer.echo(f"do-not-disturb until {_when(out['dnd_until'])}" if out["dnd_until"] else "do-not-disturb off")


@app.command()
def presence(state: str = typer.Argument(..., help="idle | active | locked | unlocked")):
    """Tell hostd whether you are at this desktop (call from hypridle and your
    lock screen)."""
    _call("presence", state=state)


if __name__ == "__main__":
    app()
