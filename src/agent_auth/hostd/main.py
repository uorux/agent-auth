"""agent-auth-hostd CLI: pair the host, enroll its TOTP secrets, run the
daemon (hostd/daemon.py), and the desktop helper (hostd/user.py).

Without a config file (AGENT_AUTH_HOSTD_CONFIG) the daemon only connects and
reports: no tier is enabled, so it runs nothing for anyone.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import typer

from ..daemon_common.channel import (
    DaemonIdentity,
    PairingFailed,
    check_broker_url,
    pair as pair_with,
)
from ..daemon_common.crypto import fingerprint, load_or_create_key, parse_public_key
from ..daemon_common.totp import SECRET_NAMES, TotpError, TotpStore, otpauth_uri
from .config import CONFIG_ENV, HostConfig

log = logging.getLogger("agent_auth.hostd")

app = typer.Typer(
    help="agent-auth host daemon", no_args_is_help=True, pretty_exceptions_show_locals=False
)

ROLE = "host"
PAIRING_CODE_ENV = "AGENT_AUTH_HOSTD_PAIRING_CODE"


def _default_name() -> str:
    return socket.gethostname().split(".")[0].lower()


BrokerUrl = typer.Option(None, "--broker-url", envvar="AGENT_AUTH_HOSTD_BROKER_URL")
ConfigFile = typer.Option(
    None, "--config", envvar=CONFIG_ENV, help="hostd's config and local policy (JSON, from the NixOS module)"
)
BrokerKey = typer.Option(
    None,
    "--broker-key",
    envvar="AGENT_AUTH_HOSTD_BROKER_KEY",
    help="the broker's pinned public key (ed25519:…)",
)
Name = typer.Option(None, "--name", envvar="AGENT_AUTH_HOSTD_NAME", help="default: hostname")
StateDir = typer.Option(
    Path("/var/lib/agent-auth-hostd"), "--state-dir", envvar="AGENT_AUTH_HOSTD_STATE_DIR"
)


def _load_config(
    config: Path | None, broker_url: str | None, broker_key: str | None, name: str | None, state_dir: Path
) -> HostConfig:
    """The config file if there is one; else a connect-only config from the
    options (no tiers: nothing can be run)."""
    if config is not None:
        try:
            return HostConfig.load(config)
        except (OSError, ValueError, KeyError) as exc:
            typer.secho(f"invalid config {config}: {exc}", fg=typer.colors.RED, err=True)
            sys.exit(2)
    if not broker_url or not broker_key:
        typer.secho("need --config, or --broker-url and --broker-key", fg=typer.colors.RED, err=True)
        sys.exit(2)
    return HostConfig(
        broker_url=broker_url, broker_public_key=broker_key, name=name or _default_name(), state_dir=state_dir
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
    config: Path = ConfigFile,
):
    """Pair this host with the broker using a one-time code from
    `agent-auth admin daemon-pair <name>`."""
    cfg = _load_config(config, broker_url, broker_key, name, state_dir)
    broker_url, broker_key, state_dir = cfg.broker_url, cfg.broker_public_key, cfg.state_dir
    identity = _identity(broker_url, broker_key, cfg.name, state_dir)
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


@app.command("totp-enroll")
def totp_enroll(
    rotate: str = typer.Option(None, "--rotate", help=f"replace one secret: {', '.join(SECRET_NAMES)}"),
    state_dir: Path = StateDir,
    config: Path = ConfigFile,
    qrencode: str = typer.Option(None, "--qrencode", help="qrencode binary (default: from the config, or PATH)"),
):
    """Create this host's TOTP secrets and show each one ONCE, as a QR code,
    for your authenticator. They are generated here and never leave the host.

    \b
    <tier>-arm     opens an arming window (/arm on Discord)
    <tier>-direct  approves one request ("Approve with TOTP"), armed or not
    """
    cfg = HostConfig.load(config) if config is not None else None
    if cfg is not None:
        state_dir = cfg.state_dir
    if os.geteuid() != 0:
        typer.secho("run as root: the secrets are root-only", fg=typer.colors.RED, err=True)
        sys.exit(1)
    host = cfg.name if cfg else _default_name()
    store = TotpStore(state_dir / "totp")
    names = [rotate] if rotate else [n for n in SECRET_NAMES if not store.enrolled(n)]
    if not names:
        typer.echo("all four secrets are enrolled; use --rotate <name> to replace one")
        return
    qr = qrencode or (cfg.qrencode if cfg else "qrencode")
    for secret_name in names:
        try:
            secret = store.enroll(secret_name, replace=bool(rotate))
        except TotpError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            sys.exit(1)
        uri = otpauth_uri(secret, host, secret_name)
        typer.secho(f"\n== {host} {secret_name} ==", bold=True)
        try:
            subprocess.run([qr, "-t", "ANSIUTF8", uri], check=True)
        except (OSError, subprocess.CalledProcessError):
            typer.echo("(no qrencode: add it by hand)")
        typer.echo(f"secret: {secret}")
        typer.echo(uri)
    typer.echo("\nScan them now: they are not shown again. Restart is not needed.")


@app.command()
def run(
    broker_url: str = BrokerUrl,
    broker_key: str = BrokerKey,
    name: str = Name,
    state_dir: Path = StateDir,
    config: Path = ConfigFile,
):
    """The daemon (the systemd service's entry point)."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s: %(message)s",
    )
    from .daemon import Hostd
    from .executor import LinuxExecutor

    cfg = _load_config(config, broker_url, broker_key, name, state_dir)
    _identity(cfg.broker_url, cfg.broker_public_key, cfg.name, cfg.state_dir)  # validates; creates the key
    if not (cfg.state_dir / "paired.json").exists():
        log.warning(
            "host:%s has not been paired on this machine; the broker will refuse it until "
            "`agent-auth-hostd pair` succeeds",
            cfg.name,
        )
    if cfg.privileged and os.geteuid() != 0:
        log.error("tiers or a VM are configured but hostd is not root: jobs will fail to start")
    asyncio.run(_run_until_signalled(Hostd(cfg, LinuxExecutor(cfg))))


@app.command()
def user(config: Path = ConfigFile):
    """The desktop helper (a user service): reports whether you are at this
    desktop and shows approval prompts there."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s: %(message)s",
    )
    from .user import run_user

    if config is None:
        typer.secho(f"need --config (or {CONFIG_ENV})", fg=typer.colors.RED, err=True)
        sys.exit(2)
    asyncio.run(run_user(HostConfig.load(config)))


async def _run_until_signalled(daemon) -> None:
    task = asyncio.create_task(daemon.run())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    try:
        await task
    except asyncio.CancelledError:
        log.info("stopping")


if __name__ == "__main__":
    app()
