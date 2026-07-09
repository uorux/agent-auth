"""Thin smoke tests for Discord components: custom_id parsing and embed building.

The full decision path is exercised via RequestService in test_lifecycle; here we
only check the pieces that would break silently (regex templates, field mapping).
"""

from __future__ import annotations

import re

from agent_auth.discord_bot import embeds, views
from agent_auth.models import AccessRequest, Agent, utcnow
from agent_auth.core.states import Platform, RequestStatus


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
