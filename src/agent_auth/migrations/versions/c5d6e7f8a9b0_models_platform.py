"""platform "models": the LiteLLM gateway

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-10-14
"""

from alembic import op

revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE platform ADD VALUE IF NOT EXISTS 'models'")
    # SQLite stores the enum as plain VARCHAR: no DDL needed.


def downgrade() -> None:
    pass
