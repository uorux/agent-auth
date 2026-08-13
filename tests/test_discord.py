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
