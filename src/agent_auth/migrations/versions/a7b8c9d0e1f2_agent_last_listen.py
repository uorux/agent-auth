"""agent last_listen_at (inbound-listening liveness)

Distinct from last_seen_at, which any authenticated call refreshes: an agent
busy REQUESTING access looks alive while nothing reads its inbound threads.
last_listen_at is touched only by the a2a inbound surfaces, so it answers
"would a thread opened to this agent actually be read?"

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents", sa.Column("last_listen_at", sa.DateTime(timezone=True), nullable=True)
    )
    # Existing service agents have no listening history recorded. Seed from
    # last_seen_at so a running deployment doesn't flip every peer to
    # unreachable the moment this lands; the next real poll corrects it.
    op.execute("UPDATE agents SET last_listen_at = last_seen_at WHERE kind = 'service'")


def downgrade() -> None:
    op.drop_column("agents", "last_listen_at")
