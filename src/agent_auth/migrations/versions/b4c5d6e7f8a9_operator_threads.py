"""operator threads carry no grant

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-10-14

The operator writes to agents from the admin panel under the panel's sign-in,
not under an a2a grant, so a thread's (and its messages') grant_id may be
NULL. Existing rows all have one and are unaffected.
"""

import sqlalchemy as sa
from alembic import op

revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("a2a_threads", "a2a_messages"):
        with op.batch_alter_table(table) as b:
            b.alter_column("grant_id", existing_type=sa.String(36), nullable=True)


def downgrade() -> None:
    # Fails while operator threads exist; delete them first.
    for table in ("a2a_messages", "a2a_threads"):
        with op.batch_alter_table(table) as b:
            b.alter_column("grant_id", existing_type=sa.String(36), nullable=False)
