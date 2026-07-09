from __future__ import annotations

import json
import sys

import typer

from .client import BrokerClient, BrokerError

app = typer.Typer(help="agent-auth broker CLI", no_args_is_help=True)
admin = typer.Typer(help="Admin operations (AGENT_AUTH_ADMIN_TOKEN)", no_args_is_help=True)
a2a = typer.Typer(help="Agent-to-agent threads", no_args_is_help=True)
session = typer.Typer(
    help="Agent sessions (ephemeral agents need one for a2a; AGENT_AUTH_SESSION)",
    no_args_is_help=True,
)
app.add_typer(admin, name="admin")
app.add_typer(a2a, name="a2a")
app.add_typer(session, name="session")


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
def catalog():
    """List what you can request: platforms, roles, groups, repos, peers."""
    _run(lambda: _client().catalog())


@app.command()
def request(
    platform: str = typer.Argument(help="github | homelab | kubernetes | a2a | google"),
    capability: str = typer.Argument(help="e.g. repo, group, view/edit (k8s role), talk, calendar.read"),
    resource: str = typer.Argument(help="e.g. jrt/myrepo, svc-gitea, media (k8s namespace), homelab-agent"),
    justification: str = typer.Option(..., "--why", "-j", help="Why you need this"),
    duration: str = typer.Option("1h", "--duration", "-d", help="e.g. 30m, 8h, 2d"),
    scope: str = typer.Option("{}", "--scope", "-s", help="JSON scope object"),
    on_behalf_of_thread: str = typer.Option(
        None,
        "--on-behalf-of-thread",
        help="a2a thread id whose conversation asked for this work (delegated request)",
    ),
    wait: bool = typer.Option(False, "--wait", "-w", help="Block until decided"),
):
    """Submit an access request."""
    client = _client()

    def go():
        req = client.request_access(
            platform,
            capability,
            resource,
            justification,
            duration,
            json.loads(scope),
            on_behalf_of_thread=on_behalf_of_thread,
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


@session.command("create")
def session_create(
    label: str = typer.Option(None, "--label", "-l", help="Defaults to cwd basename"),
):
    """Mint a session; export AGENT_AUTH_SESSION=<session_id> to use it."""
    import os

    if label is None:
        label = os.path.basename(os.getcwd()) or "session"
        label = "".join(c for c in label if c.isalnum() or c in "._-")[:64] or "session"

    def go():
        out = _client().create_session(label)
        typer.secho(
            f"export AGENT_AUTH_SESSION={out['session_id']}", fg=typer.colors.GREEN, err=True
        )
        return out

    _run(go)


@session.command("close")
def session_close():
    """Close the current session (AGENT_AUTH_SESSION); its threads end peer_gone."""
    _run(lambda: _client().close_session())


@a2a.command("check")
def a2a_check(
    peer: str,
    direction: str = typer.Option("out", help="out: can I reach peer; in: can peer reach me"),
    topic: str = typer.Option(None),
):
    _run(lambda: _client().a2a_check(peer, direction, topic))


@a2a.command("open")
def a2a_open(
    to: str,
    payload: str = typer.Option(..., "--payload", "-p", help="JSON payload (first message)"),
    topic: str = typer.Option(None),
):
    """Open a thread; it stays pending_open until the peer accepts or replies."""
    _run(lambda: _client().a2a_open(to, json.loads(payload), topic))


@a2a.command("send")
def a2a_send(
    thread_id: str,
    payload: str = typer.Option(..., "--payload", "-p", help="JSON payload"),
):
    """Send a message into an open thread."""
    _run(lambda: _client().a2a_send(thread_id, json.loads(payload)))


@a2a.command("poll")
def a2a_poll(
    thread_id: str,
    after_seq: int = typer.Option(0, help="Return messages with seq greater than this"),
    wait: float = typer.Option(0, help="Long-poll seconds (0 = return immediately)"),
):
    """Read a thread past your cursor; --wait blocks for the reply."""
    _run(lambda: _client().a2a_poll(thread_id, after_seq, wait))


@a2a.command("threads")
def a2a_threads(
    state: str = typer.Option(None, help="pending_open|open|closed"),
    role: str = typer.Option(None, help="initiator|responder"),
):
    _run(lambda: _client().a2a_threads(state, role))


@a2a.command("show")
def a2a_show(thread_id: str):
    _run(lambda: _client().a2a_thread(thread_id))


@a2a.command("accept")
def a2a_accept(thread_id: str):
    _run(lambda: _client().a2a_accept(thread_id))


@a2a.command("reject")
def a2a_reject(thread_id: str, reason: str = typer.Option(None, "--reason", "-r")):
    _run(lambda: _client().a2a_reject(thread_id, reason))


@a2a.command("close")
def a2a_close(thread_id: str, reason: str = typer.Option(None, "--reason", "-r")):
    _run(lambda: _client().a2a_close(thread_id, reason))


@a2a.command("events")
def a2a_events(
    wait: float = typer.Option(0, help="Long-poll seconds"),
    after: str = typer.Option(None, help="Cursor from the previous call"),
):
    """Pending opens awaiting you + threads with new activity (service loop)."""
    _run(lambda: _client().a2a_events(wait, after))


@admin.command("gen-key")
def gen_key():
    """Generate a Fernet ENCRYPTION_KEY."""
    from .crypto import generate_fernet_key

    typer.echo(generate_fernet_key())


@admin.command("agent-create")
def agent_create(
    name: str,
    description: str = typer.Option("", "--description"),
    kind: str = typer.Option("service", "--kind", help="service | ephemeral (CLI agents)"),
    webhook_url: str = typer.Option(None, "--webhook-url"),
    lldap_username: str = typer.Option(None, "--lldap-username"),
):
    """Register an agent; prints its API key (and webhook secret) ONCE."""
    _run(
        lambda: _client().admin_create_agent(
            name, description, webhook_url, lldap_username, kind=kind
        )
    )


@admin.command("rotate-webhook-secret")
def rotate_webhook_secret(agent_id: str):
    """Mint/replace an agent's per-agent webhook HMAC key; prints it ONCE."""
    _run(lambda: _client().admin_rotate_webhook_secret(agent_id))


@admin.command("set-webhook")
def set_webhook(
    agent_id: str,
    url: str = typer.Option(None, "--url", help="http(s) endpoint; omit to clear"),
):
    """Set/replace an existing agent's webhook URL; prints the new secret ONCE."""
    _run(lambda: _client().admin_set_webhook(agent_id, url))


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
