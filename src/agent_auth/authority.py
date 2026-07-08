"""Canonical grant authority.

`capability` and `scope` on a request are two projections of one thing: the
authority a grant conveys over its `resource`. Each platform puts that authority
in whichever field is ergonomic — Kubernetes in `capability` (the role), GitHub
in `scope` (the permission map) — and leaves the other a constant or empty. That
split is convenient at the edge but dangerous in the middle: security logic
(rule-pinning, the sensitive-capability gate) has to know which field holds the
privilege, and guessing wrong is how a rule pinned to a harmless request ends up
rubber-stamping a dangerous one.

So `authority` is the single stored source of truth. `fold` canonicalizes
(capability, scope) into it; `split` reconstructs the pair for the wire and for
humans. Everything security-critical compares `authority` directly.
"""

from __future__ import annotations

from typing import Any

from .core.states import Platform


def fold(platform: Platform, capability: str, scope: dict[str, Any] | None) -> dict[str, Any]:
    """Collapse a request's (capability, scope) into its canonical authority."""
    scope = scope or {}
    if platform == Platform.GITHUB:
        return {"permissions": dict(scope.get("permissions", {}))}
    if platform == Platform.KUBERNETES:
        return {"role": capability}
    if platform == Platform.A2A:
        return dict(scope)
    if platform == Platform.GOOGLE:
        return {"action": capability}
    return {}  # HOMELAB: membership only; the group is the resource


def split(platform: Platform, authority: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
    """Reconstruct (capability, scope) from authority — the inverse of fold."""
    authority = authority or {}
    if platform == Platform.GITHUB:
        return "repo", {"permissions": dict(authority.get("permissions", {}))}
    if platform == Platform.KUBERNETES:
        return authority.get("role", ""), {}
    if platform == Platform.A2A:
        return "talk", dict(authority)
    if platform == Platform.GOOGLE:
        return authority.get("action", ""), {}
    return "group", {}  # HOMELAB


def label(platform: Platform, authority: dict[str, Any] | None) -> str:
    """Short human/policy-facing name for an authority (used in admin listings)."""
    if platform == Platform.GITHUB:
        perms = (authority or {}).get("permissions", {})
        return "+".join(f"{k}:{v}" for k, v in sorted(perms.items())) or "repo"
    return split(platform, authority)[0] or "*"


def is_sensitive(platform: Platform, authority: dict[str, Any] | None, platforms_cfg) -> bool:
    """Does this authority always require a human, regardless of policy routing?"""
    authority = authority or {}
    if platform == Platform.GITHUB:
        sensitive = set(platforms_cfg.github.sensitive_permissions)
        return any(p in sensitive for p in authority.get("permissions", {}))
    if platform == Platform.KUBERNETES:
        return authority.get("role") in set(platforms_cfg.kubernetes.sensitive_roles)
    return False
