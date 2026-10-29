"""agent-auth-sandboxctl: the operator's CLI inside the agent VM (root).
`avm` on the host runs it over SSH."""

from __future__ import annotations

import json
import os
import sys
import time

import typer

from .client import LocalApiError, operator_call

app = typer.Typer(help="operate the agent VM (sandboxd)", no_args_is_help=True,
                  pretty_exceptions_show_locals=False)


def _call(method: str, **params):
    try:
        return operator_call(method, params)
    except LocalApiError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        sys.exit(1)
    except OSError as exc:
        typer.secho(f"sandboxd unreachable: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(1)


def _out(data) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


def _exec_as(uid: int, argv: list[str], cwd: str | None = None) -> None:
    if cwd:
        os.chdir(cwd)
    os.execvp("setpriv", ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "--", *argv])


@app.command()
def status():
    _out(_call("status"))


@app.command("ls")
def ls(project: str = typer.Option(None, "--project", "-p"), all_: bool = typer.Option(False, "--all", "-a")):
    """Conversations: agent, state, last activity."""
    convs = _call("conversations", project=project, all=all_)
    for c in convs:
        age = int(time.time() - c["last_activity"])
        typer.echo(f"{c['id']}  {c['state']:<9} {c['agent']:<44} {age:>6}s ago  {c['title']}")


@app.command()
def agents():
    _out(_call("agents"))


@app.command()
def projects():
    _out(_call("projects"))


@app.command("project-create")
def project_create(name: str, open_for_orchestrator: bool = typer.Option(False, "--open", help="leave it writable by the orchestrator")):
    _out(_call("project_create", name=name, sealed=not open_for_orchestrator))


@app.command()
def mint(project: str, runtime: str = typer.Option("claude", "--runtime", "-r")):
    """Ask the broker (as the orchestrator) for <runtime>-<project>-<host>-sandbox."""
    _out(_call("mint", runtime=runtime, project=project))


@app.command()
def new(
    project: str,
    runtime: str = typer.Option("claude", "--runtime", "-r"),
    prompt: str = typer.Option(None, "--prompt"),
    detach: bool = typer.Option(False, "--detach", "-d", help="headless; don't attach"),
):
    """New conversation of <runtime>-<project>-<host>-sandbox, attached in its
    TUI. Mints the agent first if it doesn't exist (the broker's policy decides;
    a human may be asked on Discord)."""
    def find():
        return next((a["name"] for a in _call("agents") if a["project"] == project and a["runtime"] == runtime), None)

    agent = find()
    if agent is None:
        typer.echo(f"minting {runtime} for {project} (the broker may ask a human)…", err=True)
        res = _call("mint", runtime=runtime, project=project, why=f"operator opened a {runtime} session on {project}")
        agent = find()
        if agent is None:
            typer.secho(f"not minted: {res.get('status')} {res.get('reason') or ''}", fg=typer.colors.RED, err=True)
            sys.exit(1)
    res = _call("new", agent=agent, prompt=prompt, attach=not detach)
    if detach:
        _out(res["conversation"])
        return
    _attach(res["attach"])


def _attach(info: dict) -> None:
    _exec_as(info["uid"], info["argv"])


@app.command()
def attach(conversation: str, now: bool = typer.Option(False, "--now", help="interrupt a running turn")):
    """Take a conversation over in its TUI (detach with tmux's prefix + d)."""
    _attach(_call("attach", conversation=conversation, now=now))


@app.command()
def send(conversation: str, text: str):
    _out(_call("send", conversation=conversation, text=text))


@app.command()
def logs(conversation: str, follow: bool = typer.Option(False, "--follow", "-f")):
    """The conversation's transcript as sandboxd saw it (in / out / errors)."""
    path = _call("log_path", conversation=conversation)
    pos = 0
    while True:
        try:
            with open(path) as f:
                f.seek(pos)
                for line in f:
                    rec = json.loads(line)
                    stamp = time.strftime("%H:%M:%S", time.localtime(rec["t"]))
                    typer.echo(f"--- {stamp} {rec['dir']}\n{rec['text']}")
                pos = f.tell()
        except FileNotFoundError:
            pass
        if not follow:
            return
        time.sleep(1)


@app.command()
def stop(conversation: str):
    """Park it now (it resumes on its next message)."""
    _out(_call("stop", conversation=conversation))


@app.command()
def close(conversation: str):
    """End it: its threads close and its broker session ends."""
    _out(_call("close", conversation=conversation))


@app.command()
def shell(project: str):
    """A shell as the project's user, in its directory (no runtime)."""
    info = _call("shell", project=project)
    _exec_as(info["uid"], [os.environ.get("SHELL", "bash"), "-l"], cwd=info["workdir"])


@app.command("secret-set")
def secret_set(name: str = typer.Argument(help="claude-oauth-token | codex-auth.json")):
    """Store a runtime credential, read from stdin (never an argument)."""
    value = sys.stdin.read()
    _out(_call("secret_set", name=name, value=value if name.endswith(".json") else value.strip()))


if __name__ == "__main__":
    app()
