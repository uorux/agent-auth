"""collapse capability+scope into a single authority field

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-08

capability and scope were two projections of one thing — the authority a grant
conveys over its resource. This migration stores that authority directly on
access_requests, grants, and rules, backfilling from the old columns, then drops
them. fold/split round-trips exactly, so active grants keep minting the same
credentials. See agent_auth.authority.

Behaviour note: a pre-existing DB rule with a wildcard capability_pattern on
kubernetes/google (which previously auto-approved *any* role, including edit /
admin) becomes a null-authority rule. It still auto-approves non-sensitive
roles, but sensitive ones now correctly fall through to human review — a
fail-safe tightening, not a regression.
"""

import sqlalchemy as sa
from alembic import op

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def _fold(platform, capability, scope):
    scope = scope or {}
    if platform == "github":
        return {"permissions": dict(scope.get("permissions", {}))}
    if platform == "kubernetes":
        return {"role": capability}
    if platform == "a2a":
        return dict(scope)
    if platform == "google":
        return {"action": capability}
    return {}  # homelab


def _fold_rule(platform, capability_pattern, scope, action):
    # Deny rules stayed scope-agnostic (broad); keep them so. Approve rules pin
    # to the exact privilege. A wildcard capability on a platform whose privilege
    # lives in the capability (k8s/google) can't be an exact pin, so it becomes
    # null (any) — which no longer bypasses the sensitive-capability gate.
    if action == "auto_deny":
        return None
    if platform == "github":
        perms = (scope or {}).get("permissions")
        return {"permissions": dict(perms)} if perms else None
    if platform == "kubernetes":
        return {"role": capability_pattern} if capability_pattern not in ("*", "") else None
    if platform == "a2a":
        return dict(scope) if scope else None
    if platform == "google":
        return {"action": capability_pattern} if capability_pattern not in ("*", "") else None
    return {}  # homelab


def _split(platform, authority):
    authority = authority or {}
    if platform == "github":
        return "repo", {"permissions": dict(authority.get("permissions", {}))}
    if platform == "kubernetes":
        return authority.get("role", ""), {}
    if platform == "a2a":
        return "talk", dict(authority)
    if platform == "google":
        return authority.get("action", ""), {}
    return "group", {}  # homelab


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    op.add_column("access_requests", sa.Column("authority", sa.JSON(), nullable=True))
    op.add_column("access_requests", sa.Column("approved_authority", sa.JSON(), nullable=True))
    op.add_column("grants", sa.Column("authority", sa.JSON(), nullable=True))
    op.add_column("rules", sa.Column("authority", sa.JSON(), nullable=True))

    req = sa.table(
        "access_requests",
        sa.column("id", sa.String), sa.column("platform", sa.String),
        sa.column("capability", sa.String), sa.column("scope", sa.JSON),
        sa.column("approved_scope", sa.JSON),
        sa.column("authority", sa.JSON), sa.column("approved_authority", sa.JSON),
    )
    for row in bind.execute(
        sa.select(req.c.id, req.c.platform, req.c.capability, req.c.scope, req.c.approved_scope)
    ).fetchall():
        appr = (
            None if row.approved_scope is None
            else _fold(row.platform, row.capability, row.approved_scope)
        )
        bind.execute(
            req.update().where(req.c.id == row.id).values(
                authority=_fold(row.platform, row.capability, row.scope),
                approved_authority=appr,
            )
        )

    grants = sa.table(
        "grants",
        sa.column("id", sa.String), sa.column("platform", sa.String),
        sa.column("capability", sa.String), sa.column("scope", sa.JSON),
        sa.column("authority", sa.JSON),
    )
    for row in bind.execute(
        sa.select(grants.c.id, grants.c.platform, grants.c.capability, grants.c.scope)
    ).fetchall():
        bind.execute(
            grants.update().where(grants.c.id == row.id).values(
                authority=_fold(row.platform, row.capability, row.scope)
            )
        )

    rules = sa.table(
        "rules",
        sa.column("id", sa.String), sa.column("platform", sa.String),
        sa.column("capability_pattern", sa.String), sa.column("scope", sa.JSON),
        sa.column("action", sa.String), sa.column("authority", sa.JSON),
    )
    for row in bind.execute(
        sa.select(rules.c.id, rules.c.platform, rules.c.capability_pattern, rules.c.scope, rules.c.action)
    ).fetchall():
        bind.execute(
            rules.update().where(rules.c.id == row.id).values(
                authority=_fold_rule(row.platform, row.capability_pattern, row.scope, row.action)
            )
        )

    if is_sqlite:
        with op.batch_alter_table("access_requests") as b:
            b.drop_column("capability")
            b.drop_column("scope")
            b.drop_column("approved_scope")
        with op.batch_alter_table("grants") as b:
            b.drop_column("capability")
            b.drop_column("scope")
        with op.batch_alter_table("rules") as b:
            b.drop_column("capability_pattern")
            b.drop_column("scope")
    else:
        op.drop_column("access_requests", "capability")
        op.drop_column("access_requests", "scope")
        op.drop_column("access_requests", "approved_scope")
        op.drop_column("grants", "capability")
        op.drop_column("grants", "scope")
        op.drop_column("rules", "capability_pattern")
        op.drop_column("rules", "scope")


def downgrade() -> None:
    bind = op.get_bind()

    op.add_column("access_requests", sa.Column("capability", sa.String(length=128), nullable=True))
    op.add_column("access_requests", sa.Column("scope", sa.JSON(), nullable=True))
    op.add_column("access_requests", sa.Column("approved_scope", sa.JSON(), nullable=True))
    op.add_column("grants", sa.Column("capability", sa.String(length=128), nullable=True))
    op.add_column("grants", sa.Column("scope", sa.JSON(), nullable=True))
    op.add_column("rules", sa.Column("capability_pattern", sa.String(length=128), nullable=True))
    op.add_column("rules", sa.Column("scope", sa.JSON(), nullable=True))

    req = sa.table(
        "access_requests",
        sa.column("id", sa.String), sa.column("platform", sa.String),
        sa.column("capability", sa.String), sa.column("scope", sa.JSON),
        sa.column("approved_scope", sa.JSON),
        sa.column("authority", sa.JSON), sa.column("approved_authority", sa.JSON),
    )
    for row in bind.execute(
        sa.select(req.c.id, req.c.platform, req.c.authority, req.c.approved_authority)
    ).fetchall():
        cap, scope = _split(row.platform, row.authority)
        appr = None if row.approved_authority is None else _split(row.platform, row.approved_authority)[1]
        bind.execute(
            req.update().where(req.c.id == row.id).values(
                capability=cap, scope=scope, approved_scope=appr
            )
        )

    grants = sa.table(
        "grants",
        sa.column("id", sa.String), sa.column("platform", sa.String),
        sa.column("capability", sa.String), sa.column("scope", sa.JSON),
        sa.column("authority", sa.JSON),
    )
    for row in bind.execute(sa.select(grants.c.id, grants.c.platform, grants.c.authority)).fetchall():
        cap, scope = _split(row.platform, row.authority)
        bind.execute(
            grants.update().where(grants.c.id == row.id).values(capability=cap, scope=scope)
        )

    rules = sa.table(
        "rules",
        sa.column("id", sa.String), sa.column("platform", sa.String),
        sa.column("capability_pattern", sa.String), sa.column("scope", sa.JSON),
        sa.column("authority", sa.JSON),
    )
    for row in bind.execute(sa.select(rules.c.id, rules.c.platform, rules.c.authority)).fetchall():
        if row.authority is None:
            cap, scope = "*", None
        else:
            cap, scope = _split(row.platform, row.authority)
        bind.execute(
            rules.update().where(rules.c.id == row.id).values(
                capability_pattern=cap, scope=scope
            )
        )

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("access_requests") as b:
            b.drop_column("authority")
            b.drop_column("approved_authority")
        with op.batch_alter_table("grants") as b:
            b.drop_column("authority")
        with op.batch_alter_table("rules") as b:
            b.drop_column("authority")
    else:
        op.drop_column("access_requests", "authority")
        op.drop_column("access_requests", "approved_authority")
        op.drop_column("grants", "authority")
        op.drop_column("rules", "authority")
