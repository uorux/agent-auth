"""agent-auth-hostd CLI.

Phase 1 is the skeleton: pairing, the signed connection, and heartbeats. It
accepts no work yet — the broker can see the host but can't make it do
anything.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import typer

from .. import __version__
from ..daemon_common.channel import (
    DaemonChannel,
    DaemonIdentity,
    PairingFailed,
    check_broker_url,
    pair as pair_with,
)
from ..daemon_common.crypto import fingerprint, load_or_create_key, parse_public_key

log = logging.getLogger("agent_auth.hostd")

app = typer.Typer(
    help="agent-auth host daemon", no_args_is_help=True, pretty_exceptions_show_locals=False
)

ROLE = "host"
PAIRING_CODE_ENV = "AGENT_AUTH_HOSTD_PAIRING_CODE"


def _default_name() -> str:
    return socket.gethostname().split(".")[0].lower()


BrokerUrl = typer.Option(..., "--broker-url", envvar="AGENT_AUTH_HOSTD_BROKER_URL")
BrokerKey = typer.Option(
    ...,
    "--broker-key",
    envvar="AGENT_AUTH_HOSTD_BROKER_KEY",
    help="the broker's pinned public key (ed25519:…)",
)
Name = typer.Option(None, "--name", envvar="AGENT_AUTH_HOSTD_NAME", help="default: hostname")
StateDir = typer.Option(
    Path("/var/lib/agent-auth-hostd"), "--state-dir", envvar="AGENT_AUTH_HOSTD_STATE_DIR"
)


def _identity(broker_url: str, broker_key: str, name: str | None, state_dir: Path) -> DaemonIdentity:
    try:
        parse_public_key(broker_key)
    except ValueError as exc:
        typer.secho(f"invalid --broker-key: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(2)
    try:
        check_broker_url(broker_url)  # https, or plain http to a loopback broker
    except ValueError as exc:
        typer.secho(f"invalid --broker-url: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(2)
    return DaemonIdentity(
        role=ROLE,
        name=name or _default_name(),
        key=load_or_create_key(state_dir / "key"),
        broker_url=broker_url,
        broker_public_key=broker_key,
    )


def _read_pairing_code(source: str | None) -> str:
    """The code never comes from argv, where /proc, sudo's log and shell
    history would keep it: env, stdin (`-`), or a hidden prompt."""
    if source not in (None, "-"):
        typer.secho(
            "the pairing code is not accepted on the command line (it lands in "
            "shell history and process listings). Issue a fresh code with "
            "`agent-auth admin daemon-pair`, then run `agent-auth-hostd pair` "
            f"and enter it at the prompt (or pipe it to `pair -`, or set {PAIRING_CODE_ENV}).",
            fg=typer.colors.RED,
            err=True,
        )
        sys.exit(2)
    if source == "-":
        code = sys.stdin.readline()
    else:
        code = os.environ.get(PAIRING_CODE_ENV) or typer.prompt("pairing code", hide_input=True)
    code = code.strip()
    if not code:
        typer.secho("no pairing code given", fg=typer.colors.RED, err=True)
        sys.exit(2)
    return code


@app.command()
def pair(
    source: str = typer.Argument(
        None,
        metavar="[-]",
        help=f"`-` reads the code from stdin; otherwise {PAIRING_CODE_ENV} or a prompt",
        show_default=False,
    ),
    broker_url: str = BrokerUrl,
    broker_key: str = BrokerKey,
    name: str = Name,
    state_dir: Path = StateDir,
):
    """Pair this host with the broker using a one-time code from
    `agent-auth admin daemon-pair <name>`."""
    identity = _identity(broker_url, broker_key, name, state_dir)
    code = _read_pairing_code(source)
    try:
        pair_with(identity, code)
    except PairingFailed as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        sys.exit(1)
    except httpx.HTTPError as exc:
        typer.secho(f"could not reach the broker: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(1)
    record = {
        "role": ROLE,
        "name": identity.name,
        "broker_url": broker_url,
        "broker_public_key": broker_key,
        "paired_at": datetime.now(timezone.utc).isoformat(),
    }
    (state_dir / "paired.json").write_text(json.dumps(record, indent=2) + "\n")
    typer.echo(f"paired as {identity.principal}")
    typer.echo(f"  this host's key: {fingerprint(identity.public_key)}")
    typer.echo(f"  broker key:      {fingerprint(broker_key)}")
    typer.echo("Compare with `agent-auth admin daemons`. Restart agent-auth-hostd to connect.")


@app.command()
def key(state_dir: Path = StateDir):
    """Print this host's public key and fingerprint (creating the key if needed)."""
    from ..daemon_common.crypto import public_key_text

    public = public_key_text(load_or_create_key(state_dir / "key"))
    typer.echo(public)
    typer.echo(fingerprint(public))


@app.command()
def run(
    broker_url: str = BrokerUrl,
    broker_key: str = BrokerKey,
    name: str = Name,
    state_dir: Path = StateDir,
):
    """Hold the connection to the broker (the systemd service's entry point)."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s: %(message)s",
    )
    identity = _identity(broker_url, broker_key, name, state_dir)
    if not (state_dir / "paired.json").exists():
        log.warning(
            "%s has not been paired on this machine; the broker will refuse it until "
            "`agent-auth-hostd pair` succeeds",
            identity.principal,
        )
    started_at = datetime.now(timezone.utc).isoformat()

    def status() -> dict:
        return {"version": __version__, "started_at": started_at, "role": ROLE}

    channel = DaemonChannel(identity, version=__version__, status=status)
    asyncio.run(_run_until_signalled(channel))


async def _run_until_signalled(channel: DaemonChannel) -> None:
    task = asyncio.create_task(channel.run())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    try:
        await task
    except asyncio.CancelledError:
        log.info("stopping")


if __name__ == "__main__":
    app()
