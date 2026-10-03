"""grant status PROVISIONING

Provisioning now runs outside the deciding transaction: the grant row is
committed in status `provisioning` first, the provisioner runs in its own
short transaction, and only then does the row become `active`. A crash in
between leaves a durable record for the scheduler to reap instead of external
access with no grant row.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
"""

from __future__ import annotations

from alembic import op

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # PG >= 12 allows ADD VALUE inside a transaction as long as the new
        # value isn't used in the same transaction.
        op.execute("ALTER TYPE grant_status ADD VALUE IF NOT EXISTS 'provisioning'")
    # SQLite stores these enums as plain VARCHAR, so no DDL is needed there.


def downgrade() -> None:
    # PG cannot drop an enum value; rows in `provisioning` would need manual
    # cleanup first. Nothing to undo on SQLite.
    pass
