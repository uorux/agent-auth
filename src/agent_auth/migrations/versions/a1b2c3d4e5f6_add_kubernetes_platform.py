"""add kubernetes platform enum value

Revision ID: a1b2c3d4e5f6
Revises: 3ed47f6283bc
Create Date: 2026-07-07

"""
from alembic import op

revision = 'a1b2c3d4e5f6'
down_revision = '3ed47f6283bc'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # PG >= 12 allows ADD VALUE inside a transaction as long as the new
        # value isn't used in the same transaction.
        op.execute("ALTER TYPE platform ADD VALUE IF NOT EXISTS 'kubernetes'")
    # SQLite stores these enums as plain VARCHAR (no CHECK constraint is
    # emitted by SQLAlchemy 2.x), so new values need no DDL there.


def downgrade() -> None:
    # Postgres cannot remove enum values; leave 'kubernetes' in place.
    pass
