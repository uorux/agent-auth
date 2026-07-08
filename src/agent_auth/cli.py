from __future__ import annotations

import json
import sys

import typer

from .client import BrokerClient, BrokerError

app = typer.Typer(help="agent-auth broker CLI", no_args_is_help=True)
admin = typer.Typer(help="Admin operations (AGENT_AUTH_ADMIN_TOKEN)", no_args_is_help=True)
a2a = typer.Typer(help="Agent-to-agent messaging", no_args_is_help=True)
app.add_typer(admin, name="admin")
app.add_typer(a2a, name="a2a")


def _client() -> BrokerClient:
    return BrokerClient()


def _out(data) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


def _run(fn):
    try:
        _out(fn())
    except BrokerError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        sys.exit(1)


@app.command()
def me():
    """Show the calling agent's identity."""
    _run(lambda: _client().me())


@app.command()
def request(
    platform: str = typer.Argument(help="github | homelab | kubernetes | a2a | google"),
    capability: str = typer.Argument(help="e.g. repo, group, namespace, talk, calendar.read"),
    resource: str = typer.Argument(help="e.g. jrt/myrepo, svc-gitea, personal-site, homelab-agent"),
    justification: str = typer.Option(..., "--why", "-j", help="Why you need this"),
    duration: str = typer.Option("1h", "--duration", "-d", help="e.g. 30m, 8h, 2d"),
    scope: str = typer.Option("{}", "--scope", "-s", help="JSON scope object"),
    wait: bool = typer.Option(False, "--wait", "-w", help="Block until decided"),
):
    """Submit an access request."""
    client = _client()

    def go():
        req = client.request_access(
            platform, capability, resource, justification, duration, json.loads(scope)
        )
        if wait and req["status"] in (
            "pending",
            "llm_evaluating",
            "awaiting_human",
            "approved",
            "provisioning",
        ):
            req = client.wait(req["id"], timeout=300)
        return req

    _run(go)


@app.command()
def status(request_id: str):
    """Get a request's current status."""
    _run(lambda: _client().get_request(request_id))


@app.command()
def wait(request_id: str, timeout: float = typer.Option(60, help="Seconds to wait")):
    """Long-poll until the request is decided."""
    _run(lambda: _client().wait(request_id, timeout))


@app.command()
def retry(request_id: str, justification: str = typer.Option(..., "--why", "-j")):
    """Retry an LLM-denied request with a revised justification."""
    _run(lambda: _client().retry(request_id, justification))


@app.command()
def escalate(request_id: str):
    """Escalate an LLM-denied request to human review."""
    _run(lambda: _client().escalate(request_id))


@app.command()
def grants(status: str = typer.Option("active", help="active|expired|revoked|all")):
    """List your grants."""
    _run(lambda: _client().grants(status))


@app.command()
def cred(grant_id: str):
    """Fetch the credential for an active grant."""
    _run(lambda: _client().credential(grant_id))


@a2a.command("check")
def a2a_check(
    peer: str,
    direction: str = typer.Option("out", help="out: can I reach peer; in: can peer reach me"),
    topic: str = typer.Option(None),
):
    _run(lambda: _client().a2a_check(peer, direction, topic))


@a2a.command("send")
def a2a_send(
    to: str,
    payload: str = typer.Option(..., "--payload", "-p", help="JSON payload"),
    topic: str = typer.Option(None),
):
    _run(lambda: _client().a2a_send(to, json.loads(payload), topic))


@a2a.command("inbox")
def a2a_inbox():
    _run(lambda: _client().a2a_inbox())


@a2a.command("ack")
def a2a_ack(message_id: str):
    _run(lambda: _client().a2a_ack(message_id))


@admin.command("gen-key")
def gen_key():
    """Generate a Fernet ENCRYPTION_KEY."""
    from .crypto import generate_fernet_key

    typer.echo(generate_fernet_key())


@admin.command("agent-create")
def agent_create(
    name: str,
    description: str = typer.Option("", "--description"),
    webhook_url: str = typer.Option(None, "--webhook-url"),
    lldap_username: str = typer.Option(None, "--lldap-username"),
):
    """Register an agent; prints its API key ONCE."""
    _run(lambda: _client().admin_create_agent(name, description, webhook_url, lldap_username))


@admin.command("agents")
def agents_list():
    _run(lambda: _client().admin_list_agents())


@admin.command("rotate-key")
def rotate_key(agent_id: str):
    _run(lambda: _client().admin_rotate_key(agent_id))


@admin.command("rules")
def rules_list():
    _run(lambda: _client().admin_list_rules())


@admin.command("rule-delete")
def rule_delete(rule_id: str):
    _run(lambda: _client().admin_delete_rule(rule_id))


@admin.command("requests")
def requests_list(limit: int = 100):
    _run(lambda: _client().admin_list_requests(limit))


@admin.command("decide")
def decide(
    request_id: str,
    approve: bool = typer.Option(..., "--approve/--deny"),
    reason: str = typer.Option("", "--reason"),
    duration: str = typer.Option(None, "--duration", "-d"),
):
    """Decide a surfaced request via API (fallback when Discord is unavailable)."""
    _run(lambda: _client().admin_decide(request_id, approve, reason, duration))


@admin.command("revoke")
def revoke(grant_id: str, reason: str = typer.Option("revoked by admin", "--reason")):
    _run(lambda: _client().admin_revoke_grant(grant_id, reason))


if __name__ == "__main__":
    app()
