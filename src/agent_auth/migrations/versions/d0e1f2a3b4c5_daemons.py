"""paired daemons (hostd, sandboxd) and their pairing codes

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "daemons",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("public_key", sa.String(128), nullable=False),
        sa.Column("paired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("last_status", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("role", "name", name="uq_daemons_role_name"),
    )
    op.create_table(
        "daemon_pairing_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("pairing_key", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_daemon_pairing_codes_role_name", "daemon_pairing_codes", ["role", "name"]
    )


def downgrade() -> None:
    op.drop_index("ix_daemon_pairing_codes_role_name", table_name="daemon_pairing_codes")
    op.drop_table("daemon_pairing_codes")
    op.drop_table("daemons")
