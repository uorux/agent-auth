"""sandbox agents: lineage/sandbox columns, key deliveries, agents/sandbox platforms

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "e1f2a3b4c5d6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE platform ADD VALUE IF NOT EXISTS 'agents'")
        op.execute("ALTER TYPE platform ADD VALUE IF NOT EXISTS 'sandbox'")
    # SQLite stores the enum as plain VARCHAR: no DDL needed.
    with op.batch_alter_table("agents") as batch:
        batch.add_column(sa.Column("parent_agent_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("sandbox_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("runtime", sa.String(16), nullable=True))
        batch.add_column(sa.Column("project", sa.String(64), nullable=True))
        batch.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_foreign_key("fk_agents_parent", "agents", ["parent_agent_id"], ["id"])
        batch.create_foreign_key(
            "fk_agents_sandbox", "daemons", ["sandbox_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_agents_parent_agent_id", ["parent_agent_id"])
        batch.create_index("ix_agents_sandbox_id", ["sandbox_id"])
    op.create_table(
        "pending_key_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False, unique=True),
        sa.Column(
            "sandbox_id",
            sa.String(36),
            sa.ForeignKey("daemons.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_encrypted", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pending_key_deliveries_sandbox_id", "pending_key_deliveries", ["sandbox_id"])


def downgrade() -> None:
    op.drop_index("ix_pending_key_deliveries_sandbox_id", table_name="pending_key_deliveries")
    op.drop_table("pending_key_deliveries")
    with op.batch_alter_table("agents") as batch:
        batch.drop_index("ix_agents_sandbox_id")
        batch.drop_index("ix_agents_parent_agent_id")
        batch.drop_constraint("fk_agents_sandbox", type_="foreignkey")
        batch.drop_constraint("fk_agents_parent", type_="foreignkey")
        for col in ("lease_expires_at", "project", "runtime", "sandbox_id", "parent_agent_id"):
            batch.drop_column(col)
