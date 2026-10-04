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
        # Creating a repo is a different privilege from any access to one, so
        # it folds into a distinct authority: no rule pinned to repo access
        # can ever approve a create, and vice versa.
        if capability == "create":
            return {"action": "create", "visibility": scope.get("visibility", "private")}
        return {"permissions": dict(scope.get("permissions", {}))}
    if platform == Platform.KUBERNETES:
        # Cluster-wide is a distinct privilege from the same role in a namespace,
        # so it folds into a distinct authority — an auto-approve rule pinned to
        # a namespaced grant can never rubber-stamp its cluster-wide cousin.
        authority = {"role": capability}
        if scope.get("cluster"):
            authority["cluster"] = True
        return authority
    if platform == Platform.A2A:
        return dict(scope)
    if platform == Platform.GOOGLE:
        return {"action": capability}
    if platform == Platform.AGENTS:
        # The runtime is the privilege's kind; the name (resource) carries the
        # project and host.
        return {"action": capability, "runtime": scope.get("runtime")}
    if platform == Platform.SANDBOX:
        # capability "project.read" / "project.write" on another project
        return {"access": capability}
    return {}  # HOMELAB: membership only; the group is the resource


def split(platform: Platform, authority: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
    """Reconstruct (capability, scope) from authority — the inverse of fold."""
    authority = authority or {}
    if platform == Platform.GITHUB:
        if authority.get("action") == "create":
            return "create", {"visibility": authority.get("visibility", "private")}
        return "repo", {"permissions": dict(authority.get("permissions", {}))}
    if platform == Platform.KUBERNETES:
        scope = {"cluster": True} if authority.get("cluster") else {}
        return authority.get("role", ""), scope
    if platform == Platform.A2A:
        return "talk", dict(authority)
    if platform == Platform.AGENTS:
        return authority.get("action", "mint"), {"runtime": authority.get("runtime")}
    if platform == Platform.SANDBOX:
        return authority.get("access", ""), {}
    if platform == Platform.GOOGLE:
        return authority.get("action", ""), {}
    return "group", {}  # HOMELAB


def label(platform: Platform, authority: dict[str, Any] | None) -> str:
    """Short human/policy-facing name for an authority (used in admin listings)."""
    if platform == Platform.GITHUB:
        if (authority or {}).get("action") == "create":
            return f"create:{authority.get('visibility', 'private')}"
        perms = (authority or {}).get("permissions", {})
        return "+".join(f"{k}:{v}" for k, v in sorted(perms.items())) or "repo"
    if platform == Platform.KUBERNETES:
        role = (authority or {}).get("role") or "*"
        return f"{role} (cluster-wide)" if (authority or {}).get("cluster") else role
    if platform == Platform.AGENTS:
        return f"mint:{(authority or {}).get('runtime') or '?'}"
    return split(platform, authority)[0] or "*"


def needs_explicit_rule(platform: Platform, authority: dict[str, Any] | None) -> bool:
    """May only a rule that names this authority clear it (approve / route to
    the LLM)? Stricter than "anything goes" and looser than `is_sensitive`: a
    YAML rule whose `match.capability` is exactly this capability, or a saved
    rule pinned to this exact authority, still counts. Catch-alls written for
    repo access ({platform: github, resource: "org/*"}, a null-authority
    "approve:platform" rule, the default) never do."""
    if platform == Platform.GITHUB:
        # Creating a repo is a different act from accessing one; a rule
        # written to hand out access must not start minting repos.
        return (authority or {}).get("action") == "create"
    if platform == Platform.AGENTS:
        # Minting an identity: never cleared by a rule written for something
        # else (a null-authority catch-all, the default).
        return True
    return False


def is_sensitive(platform: Platform, authority: dict[str, Any] | None, platforms_cfg) -> bool:
    """Does this authority always require a human, regardless of policy routing?"""
    authority = authority or {}
    if platform == Platform.GITHUB:
        # A public repo publishes whatever is pushed to it: a human's call.
        if authority.get("action") == "create":
            return authority.get("visibility") != "private"
        sensitive = set(platforms_cfg.github.sensitive_permissions)
        return any(p in sensitive for p in authority.get("permissions", {}))
    if platform == Platform.KUBERNETES:
        # Cluster-wide binds a ClusterRole across every namespace — always a
        # human's call, whatever the role or how routing would otherwise clear it.
        if authority.get("cluster"):
            return True
        return authority.get("role") in set(platforms_cfg.kubernetes.sensitive_roles)
    if platform == Platform.SANDBOX:
        # Writing into another project's files: a human's call.
        return authority.get("access") == "project.write"
    return False
