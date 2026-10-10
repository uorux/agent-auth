"""Approval prompts on the desktops you are at: a real broker and hostd, the
real hostd-user helper on hostd's user socket, and a script for the dialog.

Covered: a request reaches every present desktop and the first answer
decides; who is asked at all (policy, sensitivity, shells, presence,
do-not-disturb, cooldowns, rates); an answer only counts for a prompt this
broker sent to that host; a decision elsewhere takes the dialog down.
"""

from __future__ import annotations

import asyncio
import json
import os
import textwrap
import time
from types import SimpleNamespace

import pytest

from agent_auth.core.service import HumanDecision
from agent_auth.core.states import Platform, RequestStatus
from agent_auth.hostd.user import UserHelper, parse_answer
from agent_auth.models import AccessRequest
from agent_auth.schemas import RequestCreate

from .conftest import make_agent
from .test_hostexec import (  # noqa: F401  (fixtures)
    HOST,
    ask,
    broker_key,
    host,
    live,
    run_request,
    shell_request,
    stack,
    wait_for,
)

DIALOG = textwrap.dedent(
    """\
    import json, os, sys, time
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "dialog.log"), "a") as f:
        f.write(json.dumps({"title": sys.argv[1], "text": sys.argv[2], "timeout": sys.argv[3]}) + "\\n")
    try:
        mode = open(os.path.join(here, "dialog.mode")).read().strip()
    except OSError:
        mode = "allow"
    if mode == "hang":
        time.sleep(60)
    if mode == "mute":
        print("Mute agent 1h")
    sys.exit(0 if mode == "allow" else 1)
    """
)


def talk(to="peer"):
    return RequestCreate(platform=Platform.A2A, capability="talk", resource=to, scope={},
                         justification="ask about the deploy", requested_duration="1h")


@pytest.fixture
async def desk(host, tmp_path, db):
    """hostd-user connected to the host fixture's hostd: you are at the desk."""
    (tmp_path / "dialog.py").write_text(DIALOG)
    host.daemon._user_uid = lambda: os.getuid()  # the test's user may not be in passwd
    helper = UserHelper(host.daemon.config)
    reader, writer = await asyncio.open_unix_connection(str(host.daemon.config.user_socket))
    task = asyncio.create_task(helper.session(reader, writer))
    assert await wait_for(host.daemon.present)
    await make_agent(db, "peer")

    def shown():
        log = tmp_path / "dialog.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    yield SimpleNamespace(helper=helper, mode=lambda m: (tmp_path / "dialog.mode").write_text(m), shown=shown)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    writer.close()


async def status_of(db, request_id):
    async with db.session() as session:
        request = await session.get(AccessRequest, request_id)
        return request.status, request.decided_by


async def test_a_request_is_asked_at_the_desk_and_the_answer_decides(db, stack, host, desk):
    assert await wait_for(lambda: stack["desktop"].present_hosts())
    _, req = await ask(stack, db, talk(), name="desk-claude")
    assert stack["notifier"].surfaced == [req.id]  # Discord has it too

    async def decided():
        return (await status_of(db, req.id))[0] == RequestStatus.GRANTED

    assert await wait_for(decided)
    assert (await status_of(db, req.id))[1] == f"desktop:{HOST}"
    dialog = desk.shown()[0]
    assert dialog["title"] == "agent-auth: desk-claude"
    assert "a2a / talk on peer" in dialog["text"] and "ask about the deploy" in dialog["text"]
    assert "unverified" in dialog["text"]


async def test_a_deny_at_the_desk_denies_and_pauses_that_agent(db, stack, host, desk):
    desk.mode("deny")
    agent, req = await ask(stack, db, talk(), name="desk-claude")
    assert await wait_for(lambda: status_of(db, req.id), 10) and await wait_for(
        lambda: _is(db, req.id, RequestStatus.DENIED)
    )
    # The same agent again, right away: Discord only.
    _, again = await ask(stack, db, talk(), name="desk-claude")
    await asyncio.sleep(0.5)
    assert len(desk.shown()) == 1 and (await status_of(db, again.id))[0] == RequestStatus.AWAITING_HUMAN
    async with db.session() as session:
        request = await session.get(AccessRequest, again.id)
    assert "paused" in stack["desktop"].refusal(request, agent)


async def _is(db, request_id, status):
    return (await status_of(db, request_id))[0] == status


async def test_mute_decides_nothing_and_silences_the_agent(db, stack, host, desk):
    desk.mode("mute")
    agent, req = await ask(stack, db, talk(), name="desk-claude")
    assert await wait_for(lambda: len(desk.shown()) == 1)
    assert await wait_for(lambda: stack["desktop"]._paused_until.get("desk-claude", 0) > time.time())
    assert (await status_of(db, req.id))[0] == RequestStatus.AWAITING_HUMAN


async def test_who_is_never_asked_at_a_desk(db, stack, host, desk):
    desktop = stack["desktop"]

    async def refusal(body, name):
        agent, req = await ask(stack, db, body, name=name)
        async with db.session() as session:
            return desktop.refusal(await session.get(AccessRequest, req.id), agent)

    assert "not listed" in await refusal(talk(), "claude-elsewhere")
    assert "sensitive" in await refusal(run_request(["id"], tier="root"), "desk-claude")
    assert "never asked" in await refusal(shell_request(), "desk-claude")
    await asyncio.sleep(0.3)
    assert desk.shown() == []

    # A user command on a host: only while that host is armed (the answer has no code).
    _, req = await ask(stack, db, run_request(["echo", "hi"]), name="desk-claude")
    await asyncio.sleep(0.5)
    assert desk.shown() == [] and await _is(db, req.id, RequestStatus.AWAITING_HUMAN)
    await stack["hostexec"].arm(HOST, "user", "30m", host.code("user-arm"))
    await stack["hub"].call("host", HOST, {"type": "disarm", "tier": "root"})  # any call: let a heartbeat land
    assert await wait_for(lambda: _armed(stack))
    agent, req = await ask(stack, db, run_request(["echo", "from the desk"]), name="desk-claude")
    assert await wait_for(lambda: _is(db, req.id, RequestStatus.GRANTED))
    assert "run on excelsior as your user" in desk.shown()[0]["text"]
    assert (await stack["hostexec"].get_job(req.id, agent.id, 10)).output == "from the desk\n"


async def _armed(stack):
    hosts = await stack["hostexec"].hosts()
    return bool(hosts and hosts[0]["tiers"].get("user", {}).get("armed_until"))


async def test_away_locked_or_do_not_disturb_means_discord_only(db, stack, host, desk):
    daemon = host.daemon
    me = os.getuid()
    for state in ("locked", "idle"):
        await daemon.ctl("presence", {"state": "unlocked"}, None, me)
        assert daemon.present()
        await daemon.ctl("presence", {"state": state}, None, me)
        if state == "idle":
            daemon.presence.idle_since = time.time() - 3600
        assert not daemon.present()
    assert await wait_for(lambda: _none_present(stack))
    _, req = await ask(stack, db, talk(), name="desk-claude")
    await asyncio.sleep(0.5)
    assert desk.shown() == [] and await _is(db, req.id, RequestStatus.AWAITING_HUMAN)

    await daemon.ctl("presence", {"state": "active"}, None, me)
    await daemon.ctl("presence", {"state": "unlocked"}, None, me)
    assert daemon.present()
    await daemon.ctl("dnd", {"duration": "1h"}, None, me)
    assert not daemon.present()
    await daemon.ctl("dnd", {}, None, me)
    assert daemon.present()
    # The broker's own do-not-disturb (/dnd) reaches every host.
    await stack["desktop"].set_dnd(600)
    assert await wait_for(lambda: not daemon.present())
    # Explicit presence survives a hostd restart (it is kept under /run).
    from agent_auth.hostd.daemon import Hostd

    await daemon.ctl("presence", {"state": "locked"}, None, me)
    assert Hostd(daemon.config, host.executor).presence.explicit_locked is True


async def _none_present(stack):
    return not await stack["desktop"].present_hosts()


async def test_an_answer_counts_only_for_a_prompt_sent_to_that_host(db, stack, host, desk):
    desk.mode("hang")
    desktop = stack["desktop"]
    _, req = await ask(stack, db, talk(), name="desk-claude")
    assert await wait_for(lambda: bool(desktop._prompts))
    prompt_id = next(iter(desktop._prompts))
    conn = lambda role, name: SimpleNamespace(role=role, name=name)  # noqa: E731
    # A made-up prompt, the right prompt from another host, and from a sandbox: all ignored.
    await desktop._on_answer(conn("host", HOST), {"prompt_id": "f" * 36, "answer": "allow"})
    await desktop._on_answer(conn("host", "galaxy"), {"prompt_id": prompt_id, "answer": "allow"})
    await desktop._on_answer(conn("sandbox", HOST), {"prompt_id": prompt_id, "answer": "allow"})
    await asyncio.sleep(0.2)
    assert await _is(db, req.id, RequestStatus.AWAITING_HUMAN)

    # Decided on Discord meanwhile: the dialog is taken down, and a late answer does nothing.
    await stack["service"].decide(req.id, HumanDecision(approve=False, decided_by="jrt"))
    assert await wait_for(lambda: desk.helper._current is None and not desktop._prompts)
    await desktop._on_answer(conn("host", HOST), {"prompt_id": prompt_id, "answer": "allow"})
    assert await _is(db, req.id, RequestStatus.DENIED)


async def test_rates_keep_an_agent_from_flooding_the_desk(db, stack, host, desk):
    desk.mode("hang")
    desktop = stack["desktop"]
    desktop.config.timeout = "1s"
    requests = []
    for _ in range(3):
        agent, req = await ask(stack, db, talk(), name="desk-claude")
        requests.append(req)
    async with db.session() as session:
        third = await session.get(AccessRequest, requests[2].id)
    # Burst of two; the third goes to Discord only.
    assert "rate-limited" in desktop.refusal(third, agent)
    assert await wait_for(lambda: len(desk.shown()) >= 1)
    await asyncio.sleep(3)
    assert len(desk.shown()) <= 2
    # Unanswered dialogs time out and leave the requests to Discord.
    for req in requests:
        assert await _is(db, req.id, RequestStatus.AWAITING_HUMAN)
    assert not desktop._prompts


def test_dialog_answers():
    assert parse_answer(0, "") == "allow" and parse_answer(1, "") == "deny" and parse_answer(5, "") == "timeout"
    assert parse_answer(1, "Mute agent 1h\n") == "mute" and parse_answer(1, "Send to Discord\n") == "discord"
    # sbx-prompt's vocabulary.
    assert parse_answer(0, "once\n") == "allow" and parse_answer(0, "session") == "allow"
    assert parse_answer(0, "deny\n") == "deny"


def test_quiet_hours_wrap_midnight(stack):
    from datetime import datetime

    desktop = stack["desktop"]
    now = datetime.now().strftime("%H:%M")
    desktop.config.quiet_hours = ["00:00", "23:59"]
    assert desktop._quiet_now() or now == "23:59"
    hour = int(now[:2])
    desktop.config.quiet_hours = [f"{(hour + 23) % 24:02d}:00", f"{(hour + 1) % 24:02d}:00"]  # wraps around now
    assert desktop._quiet_now()
    desktop.config.quiet_hours = [f"{(hour + 2) % 24:02d}:00", f"{(hour + 3) % 24:02d}:00"]
    assert not desktop._quiet_now()


def test_busy_command_decides_whether_prompts_are_shown(tmp_path):
    """desktop.busy_command: exit 0 = not now; a command that can't run
    counts as busy too."""
    from agent_auth.hostd.user import _busy

    assert asyncio.run(_busy(["true"])) is True
    assert asyncio.run(_busy(["false"])) is False
    assert asyncio.run(_busy([str(tmp_path / "missing")])) is True
