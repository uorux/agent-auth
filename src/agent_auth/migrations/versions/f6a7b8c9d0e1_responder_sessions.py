"""responder-side thread sessions

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-07-09

Sessions become uniform machinery for any agent kind: a service agent's worker
conversation may bind an inbound thread by accepting (or first replying) with a
session, mirroring the initiator side — per-conversation liveness, precise wake
routing, peer_gone teardown, and session-enforced access on both ends. NULL
keeps today's agent-level behavior (sessionless dispatcher), so existing rows
and existing Hermes deployments are unaffected.
"""

import sqlalchemy as sa
from alembic import op

revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("a2a_threads") as b:
            b.add_column(sa.Column("responder_session_id", sa.String(36), nullable=True))
            b.create_foreign_key(
                "fk_a2a_threads_responder_session_id",
                "agent_sessions",
                ["responder_session_id"],
                ["id"],
            )
    else:
        op.add_column(
            "a2a_threads", sa.Column("responder_session_id", sa.String(36), nullable=True)
        )
        op.create_foreign_key(
            "fk_a2a_threads_responder_session_id",
            "a2a_threads",
            "agent_sessions",
            ["responder_session_id"],
            ["id"],
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("a2a_threads") as b:
            b.drop_constraint("fk_a2a_threads_responder_session_id", type_="foreignkey")
            b.drop_column("responder_session_id")
    else:
        op.drop_constraint(
            "fk_a2a_threads_responder_session_id", "a2a_threads", type_="foreignkey"
        )
        op.drop_column("a2a_threads", "responder_session_id")
