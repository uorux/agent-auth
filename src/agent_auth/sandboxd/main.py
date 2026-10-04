"""agent-auth-sandboxd: run the daemon, pair it, show its key."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

import httpx
import typer

from ..daemon_common.channel import PairingFailed, pair as pair_with
from ..daemon_common.crypto import fingerprint
from .config import CONFIG_ENV, Config

app = typer.Typer(help="agent-auth sandbox daemon (agent VM)", no_args_is_help=True,
                  pretty_exceptions_show_locals=False)
log = logging.getLogger("agent_auth.sandboxd")
PAIRING_CODE_ENV = "AGENT_AUTH_SANDBOXD_PAIRING_CODE"


def _config(path: str | None) -> Config:
    return Config.load(path)


@app.command()
def run(config: str = typer.Option(None, "--config", envvar=CONFIG_ENV)):
    """The daemon (the systemd service's entry point)."""
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(levelname)s %(name)s: %(message)s")
    from .daemon import Sandboxd
    from .host import LinuxHost
    from .localapi import AgentApi, OperatorApi, serve_unix

    cfg = _config(config)

    async def main():
        sbx = Sandboxd(cfg, LinuxHost(cfg))
        agent_srv = await serve_unix(cfg.agent_socket, 0o666, AgentApi(sbx))
        op_srv = await serve_unix(cfg.runtime_dir / "operator.sock", 0o600, OperatorApi(sbx))
        task = asyncio.create_task(sbx.run())
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, task.cancel)
        try:
            await task
        except asyncio.CancelledError:
            log.info("stopping")
        finally:
            agent_srv.close()
            op_srv.close()

    asyncio.run(main())


@app.command()
def pair(
    source: str = typer.Argument(None, metavar="[-]", help=f"`-`: read the code from stdin; else {PAIRING_CODE_ENV} or a prompt"),
    config: str = typer.Option(None, "--config", envvar=CONFIG_ENV),
):
    """Pair this agent VM with the broker (code from `agent-auth admin
    daemon-pair --role sandbox <host>`)."""
    from .daemon import Sandboxd
    from .host import LinuxHost

    cfg = _config(config)
    if source not in (None, "-"):
        typer.secho("the pairing code is not accepted as an argument; enter it at the prompt", fg=typer.colors.RED, err=True)
        sys.exit(2)
    code = (sys.stdin.readline() if source == "-" else os.environ.get(PAIRING_CODE_ENV)
            or typer.prompt("pairing code", hide_input=True)).strip()
    identity = Sandboxd(cfg, LinuxHost(cfg)).identity()
    try:
        pair_with(identity, code)
    except PairingFailed as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        sys.exit(1)
    except httpx.HTTPError as exc:
        typer.secho(f"could not reach the broker: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(1)
    typer.echo(f"paired as {identity.principal}")
    typer.echo(f"  this VM's key: {fingerprint(identity.public_key)}")
    typer.echo(f"  broker key:    {fingerprint(cfg.broker_public_key)}")
    typer.echo("Restart agent-auth-sandboxd; the broker then delivers the orchestrator's key.")


if __name__ == "__main__":
    app()
