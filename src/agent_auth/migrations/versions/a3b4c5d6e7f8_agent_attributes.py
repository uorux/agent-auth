"""agent attributes: host and placement, filled in for the agents there are

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
"""

from __future__ import annotations

import re

import sqlalchemy as sa
from alembic import op

revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None

# What names were built from until now: <runtime>-<project>-<host>, with
# "-sandbox" after it for agents in a VM.
RUNTIMES = ("claude", "codex", "hermes", "orchestrator")
ATTR = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


def from_name(name: str) -> dict[str, str | None]:
    """A best guess at an existing agent's fields from its name. The last
    part is taken for the host, which is wrong for a project whose own name
    ends the agent's; `agent-auth admin agents` shows the result, and
    `agent-auth admin agent-set` corrects it."""
    parts = name.lower().removesuffix("-sandbox").split("-")
    if len(parts) < 2 or parts[0] not in RUNTIMES:
        return {}
    out: dict[str, str | None] = {"runtime": parts[0], "host": parts[-1]}
    project = "-".join(parts[1:-1])
    if project:
        out["project"] = project
    return {k: v for k, v in out.items() if v and ATTR.fullmatch(v) and len(v) <= (16 if k == "runtime" else 64)}


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # The mcp platform arrived without a migration of its own.
        op.execute("ALTER TYPE platform ADD VALUE IF NOT EXISTS 'mcp'")
    with op.batch_alter_table("agents") as batch:
        batch.add_column(sa.Column("host", sa.String(64), nullable=True))
        batch.add_column(
            sa.Column("placement", sa.String(16), nullable=False, server_default="host")
        )
    agents = sa.table(
        "agents",
        sa.column("id", sa.String), sa.column("name", sa.String), sa.column("sandbox_id", sa.String),
        sa.column("runtime", sa.String), sa.column("project", sa.String),
        sa.column("host", sa.String), sa.column("placement", sa.String),
    )
    daemons = sa.table("daemons", sa.column("id", sa.String), sa.column("name", sa.String))
    hosts = {row.id: row.name for row in bind.execute(sa.select(daemons.c.id, daemons.c.name))}
    rows = bind.execute(
        sa.select(agents.c.id, agents.c.name, agents.c.sandbox_id, agents.c.runtime, agents.c.project)
    ).all()
    for row in rows:
        if row.sandbox_id is not None:
            # Minted in a VM: the broker already recorded what it is.
            values = {"placement": "sandbox", "host": hosts.get(row.sandbox_id)}
        else:
            guess = from_name(row.name)
            values = {
                "runtime": row.runtime or guess.get("runtime"),
                "project": row.project or guess.get("project"),
                "host": guess.get("host"),
            }
        bind.execute(agents.update().where(agents.c.id == row.id).values(**values))


def downgrade() -> None:
    with op.batch_alter_table("agents") as batch:
        batch.drop_column("placement")
        batch.drop_column("host")
