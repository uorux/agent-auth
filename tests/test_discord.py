"""Thin smoke tests for Discord components: custom_id parsing and embed building.

The full decision path is exercised via RequestService in test_lifecycle; here we
only check the pieces that would break silently (regex templates, field mapping).
"""

from __future__ import annotations

import re

from agent_auth.discord_bot import embeds, rules as rules_mod, views
from agent_auth.models import AccessRequest, Agent, Rule, utcnow
from agent_auth.core.states import Platform, RequestStatus, RuleAction


def _request(**kw):
    defaults = dict(
        id="123e4567-e89b-12d3-a456-426614174000",
        agent_id="a",
        platform=Platform.GITHUB,
        capability="repo",
        resource="jrt/cactus",
        scope={"permissions": {"contents": "write"}},
        justification="push a fix",
        requested_duration_secs=3600,
        risk_notes=["grants contents:write on jrt/cactus"],
        status=RequestStatus.AWAITING_HUMAN,
        attempt=0,
        created_at=utcnow(),
    )
    defaults.update(kw)
    return AccessRequest(**defaults)


def test_dynamic_item_templates_match_custom_ids():
    rid = "123e4567-e89b-12d3-a456-426614174000"
    for cls, action in (
        (views.ApproveButton, "approve"),
        (views.DenyButton, "deny"),
        (views.EditButton, "edit"),
    ):
        custom_id = f"aa:{action}:{rid}"
        match = re.fullmatch(cls.__discord_ui_compiled_template__, custom_id)
        assert match is not None, custom_id
        assert match["rid"] == rid
        # constructing the item produces the same custom_id
        item = cls(rid)
        assert item.item.custom_id == custom_id


def test_request_embed_fields():
    agent = Agent(name="sde-agent", description="", key_id="k", api_key_hash="h")
    request = _request()
    embed = embeds.build_request_embed(request, agent)
    names = [f.name for f in embed.fields]
    assert "Agent" in names and "Resource" in names and "Requested duration" in names
    assert any("Risk context" in n for n in names)
    assert embed.footer.text.endswith(request.id)

    # outcome application recolors and appends
    request.status = RequestStatus.GRANTED
    request.decided_by = "jrt"
    request.approved_duration_secs = 1800
    embed = embeds.apply_outcome(embed, request, None)
    assert embed.color.value == embeds.COLOR_APPROVED
    assert any("Approved by jrt" in (f.value or "") for f in embed.fields)


def test_edit_modal_prefills():
    request = _request()
    modal = views.EditModal(request.id, request)
    assert modal.duration.default == "1h"
    assert modal.resource.default == "jrt/cactus"
    assert "contents" in modal.scope.default
    assert len(modal.children) == 5  # discord hard limit


def _rule(**kw):
    defaults = dict(
        id="223e4567-e89b-12d3-a456-426614174000",
        action=RuleAction.AUTO_APPROVE,
        agent_pattern="sde-agent",
        platform=Platform.GITHUB,
        resource_pattern="jrt/cactus",
        authority={"permissions": {"contents": "write"}},
        max_duration_secs=3600,
        enabled=True,
        created_by="jrt",
        notes="trusted repo",
        created_at=utcnow(),
    )
    defaults.update(kw)
    return Rule(**defaults)


def test_rules_list_embed():
    rules = [
        _rule(),
        _rule(
            id="323e4567-e89b-12d3-a456-426614174000",
            action=RuleAction.AUTO_DENY,
            authority=None,
            enabled=False,
        ),
    ]
    embed = rules_mod.build_rules_embed(rules)
    assert "223e4567" in embed.description
    assert "contents:write" in embed.description
    assert "(disabled)" in embed.description

    empty = rules_mod.build_rules_embed([])
    assert "No rules" in empty.description


def test_rule_detail_embed():
    rule = _rule(delegator_pattern="hermes")
    embed = rules_mod.build_rule_detail_embed(rule)
    names = [f.name for f in embed.fields]
    assert "Agent" in names and "Resource" in names and "Max duration" in names
    assert any("Delegator" in n for n in names)
    assert embed.footer.text.endswith(rule.id)
    assert embed.color.value == rules_mod.COLOR_APPROVE

    rule.enabled = False
    assert rules_mod.build_rule_detail_embed(rule).color.value == rules_mod.COLOR_DISABLED


def test_rules_view_components_respect_limits():
    rules = [
        _rule(id=f"{i:08x}-e89b-12d3-a456-426614174000", resource_pattern="x" * 600)
        for i in range(rules_mod.PAGE_SIZE)
    ]
    view = rules_mod.RulesView(rules, selected=rules[0])
    select = view.children[0]
    assert len(select.options) == rules_mod.PAGE_SIZE  # discord hard limit is 25
    assert select.options[0].default is True
    for opt in select.options:
        assert len(opt.label) <= 100 and len(opt.description) <= 100
    labels = {c.label for c in view.children[1:]}
    assert labels == {"Disable", "Delete"}

    # no selection → browse only; disabled rule → Enable button
    assert len(rules_mod.RulesView(rules, selected=None).children) == 1
    off = _rule(enabled=False)
    labels = {c.label for c in rules_mod.RulesView([off], selected=off).children[1:]}
    assert labels == {"Enable", "Delete"}


def test_rules_view_pagination():
    rules = [_rule()]

    # single page → no pager buttons
    assert len(rules_mod.RulesView(rules, selected=None, page=0, pages=1).children) == 1

    view = rules_mod.RulesView(rules, selected=None, page=0, pages=3)
    prev, nxt = [c for c in view.children if isinstance(c, rules_mod.PageButton)]
    assert prev.disabled is True and prev.target == -1  # first page: can't go back
    assert nxt.disabled is False and nxt.target == 1

    view = rules_mod.RulesView(rules, selected=None, page=2, pages=3)
    prev, nxt = [c for c in view.children if isinstance(c, rules_mod.PageButton)]
    assert prev.disabled is False and prev.target == 1
    assert nxt.disabled is True  # last page: can't go forward

    embed = rules_mod.build_rules_embed(rules, page=1, pages=3, total=55)
    assert "Page 2/3" in embed.footer.text and "55" in embed.footer.text


def test_rule_applied_embed():
    agent = Agent(name="sde-agent", description="", key_id="k", api_key_hash="h")
    rule = _rule(notes="trusted repo")
    request = _request(
        status=RequestStatus.GRANTED,
        decided_by="policy",
        approved_duration_secs=1800,
        decided_at=utcnow(),
    )
    embed = embeds.build_rule_applied_embed(request, agent, rule, None)
    assert "auto-approved" in embed.description
    assert "sde-agent" in embed.description
    assert rule.id[:8] in embed.description
    assert "trusted repo" in embed.description
    assert embed.color.value == embeds.COLOR_APPROVED
    assert embed.footer.text.endswith(request.id)

    request.status = RequestStatus.DENIED
    embed = embeds.build_rule_applied_embed(request, agent, None, None)
    assert "auto-denied" in embed.description
    assert "since-deleted rule" in embed.description
    assert embed.color.value == embeds.COLOR_DENIED


def test_edit_modal_respects_discord_field_limits():
    # Discord validates these server-side only (400 Invalid Form Body), so
    # enforce them here. Use an oversized resource to cover prefill truncation.
    request = _request()
    request.resource = "x" * 5000
    modal = views.EditModal(request.id, request)
    assert len(modal.title) <= 45
    for item in modal.children:
        assert len(item.label) <= 45, item.label
        assert len(item.placeholder or "") <= 100, item.label
        if item.default and item.max_length:
            assert len(item.default) <= item.max_length, item.label


# --- commands on hosts ---------------------------------------------------------


def _hostexec_request(capability="run", tier="user", **scope):
    from agent_auth.discord_bot import hostexec as hx_views  # noqa: F401

    scope = {"tier": tier, **scope}
    if capability == "run":
        scope.setdefault("argv", ["nixos-rebuild", "switch", "--flake", ".#excelsior"])
    return _request(
        platform=Platform.HOSTEXEC,
        capability=capability,
        resource="excelsior",
        scope=scope,
        justification="apply the config change",
        risk_notes=["risk (some/model, advisory): MEDIUM — rebuilds the system"],
    )


def test_hostexec_embeds_say_what_runs_where_and_whether_approve_works():
    from agent_auth.discord_bot import hostexec as hx_views

    agent = Agent(id="a", name="claude-larder-excelsior-sandbox", key_id="k", api_key_hash="h", project="larder")
    armed = {"online": True, "lockdown": False,
             "tiers": {"user": {"enabled": True, "armed_until": 1_800_000_000, "shell": True},
                       "root": {"enabled": True, "armed_until": None, "shell": False}}}
    run = hx_views.build_embed(_hostexec_request(cwd="/home/jrt/dots", env={"LANG": "C"}), agent, None, None, armed)
    fields = {f.name: f.value for f in run.fields}
    assert "your user" in run.title and "nixos-rebuild switch --flake" in fields["Command"]
    assert fields["Project"] == "larder" and "LANG" in fields["env"] and "armed until" in fields["Host"]
    assert "MEDIUM" in fields["⚠️ Risk context"]

    root = hx_views.build_embed(_hostexec_request(tier="root"), agent, None, None, armed)
    assert "ROOT" in root.title and "not armed" in {f.name: f.value for f in root.fields}["Host"]
    shell = hx_views.build_embed(_hostexec_request("shell", tier="root"), agent, None, None, armed)
    assert shell.title.startswith("🚨 ROOT SHELL") and shell.color.value == hx_views.COLOR_SHELL
    assert "not enabled" in {f.name: f.value for f in shell.fields}["Host"]
    offline = hx_views.build_embed(_hostexec_request(), agent, None, None, None)
    assert "offline" in {f.name: f.value for f in offline.fields}["Host"]
    # A command can't break out of its code block.
    sneaky = hx_views.build_embed(_hostexec_request(argv=["echo", "```\n**APPROVED**"]), agent, None, None, armed)
    assert "```\n**APPROVED**" not in {f.name: f.value for f in sneaky.fields}["Command"][4:-4]


def test_hostexec_buttons():
    from agent_auth.discord_bot import hostexec as hx_views

    rid = "0" * 8 + "-0000-0000-0000-" + "0" * 12
    run = hx_views.pending_view(_hostexec_request(id=rid))
    assert [c.item.label for c in run.children] == ["Approve", "Approve all…", "Approve with TOTP", "Deny", "Edit"]
    # A shell: a TOTP code or nothing.
    shell = hx_views.pending_view(_hostexec_request("shell", id=rid))
    assert [c.item.label for c in shell.children] == ["Approve with TOTP", "Deny"]
    for item in (*run.children, *hx_views.shell_view(rid).children):
        assert len(item.item.custom_id) <= 100
    for cls in hx_views.DYNAMIC_ITEMS:
        assert re.fullmatch(cls.__discord_ui_compiled_template__, cls(rid).item.custom_id)
    modal = hx_views.TotpModal(_hostexec_request("shell", id=rid))
    assert len(modal.children) == 3 and all(len(c.label) <= 45 for c in modal.children)
    assert len(hx_views.TotpModal(_hostexec_request(id=rid)).children) == 2


def test_hostexec_result_field():
    from agent_auth.discord_bot import hostexec as hx_views
    from agent_auth.models import HostJob

    job = HostJob(id="j" * 36, host="excelsior", tier="user", status="done", exit_code=0, duration_ms=1234,
                  output="line\n" * 500, spec={}, truncated=False)
    text = hx_views.result_field(job)
    assert text.startswith("✅ exit 0 in 1.2s") and len(text) <= 1024
    assert hx_views.output_file(job) is not None
    refused = HostJob(id="j" * 36, host="excelsior", tier="root", status="refused", error="not_armed", spec={})
    assert "refused by excelsior" in hx_views.result_field(refused) and hx_views.output_file(refused) is None
