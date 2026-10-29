"""hostexec: host jobs, expiring rules, broker flags, the shell mirror thread

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE platform ADD VALUE IF NOT EXISTS 'hostexec'")
    # SQLite stores the enum as plain VARCHAR: no DDL needed.
    with op.batch_alter_table("rules") as batch:
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("access_requests") as batch:
        batch.add_column(sa.Column("discord_thread_id", sa.BigInteger(), nullable=True))
    op.create_table(
        "host_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("grant_id", sa.String(36), sa.ForeignKey("grants.id"), nullable=True),
        sa.Column("request_id", sa.String(36), sa.ForeignKey("access_requests.id"), nullable=False),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("host", sa.String(128), nullable=False),
        sa.Column("tier", sa.String(8), nullable=False),
        sa.Column("shell_id", sa.String(36), nullable=True),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("via", sa.String(32), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("output_bytes", sa.Integer(), nullable=True),
        sa.Column("output_sha256", sa.String(64), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("grant_id", "request_id", "agent_id", "shell_id", "status"):
        op.create_index(f"ix_host_jobs_{column}", "host_jobs", [column])
    op.create_table(
        "broker_flags",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("broker_flags")
    op.drop_table("host_jobs")
    with op.batch_alter_table("access_requests") as batch:
        batch.drop_column("discord_thread_id")
    with op.batch_alter_table("rules") as batch:
        batch.drop_column("expires_at")
