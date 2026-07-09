"""a2a threads, agent kinds/sessions, per-agent webhook secrets

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-09

The flat a2a send/inbox/ack relay becomes TCP-like threads: fast-open with
accept/reject, cursor reads instead of acks, session-bound grants for ephemeral
(CLI) agents, and liveness via last-seen timestamps.

Existing agents default to kind="service" (correct for Hermes deployments) and
keep NULL webhook_secret, so webhook signing falls back to the global
WEBHOOK_SIGNING_SECRET until rotated. Pre-existing a2a_messages rows keep a
NULL thread_id: they are audit history for the retired inbox protocol and are
excluded from all new APIs — drain inboxes before upgrading if their content
still matters. Downgrade drops threads/sessions data outright.
"""

import sqlalchemy as sa
from alembic import op

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("close_reason", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("agent_id", "name", name="uq_agent_sessions_agent_name"),
    )
    op.create_index("ix_agent_sessions_agent_id", "agent_sessions", ["agent_id"])
    op.create_index("ix_agent_sessions_open", "agent_sessions", ["agent_id", "closed_at"])

    op.create_table(
        "a2a_threads",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "initiator_agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False
        ),
        sa.Column(
            "initiator_session_id",
            sa.String(36),
            sa.ForeignKey("agent_sessions.id"),
            nullable=True,
        ),
        sa.Column(
            "responder_agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False
        ),
        sa.Column("topic", sa.String(256), nullable=True),
        sa.Column("grant_id", sa.String(36), sa.ForeignKey("grants.id"), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seq", sa.Integer(), nullable=False),
        sa.Column("closed_by", sa.String(36), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("close_reason", sa.String(32), nullable=True),
        sa.Column("close_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_a2a_threads_initiator_agent_id", "a2a_threads", ["initiator_agent_id"])
    op.create_index("ix_a2a_threads_responder_agent_id", "a2a_threads", ["responder_agent_id"])
    op.create_index("ix_a2a_threads_state", "a2a_threads", ["state"])
    op.create_index("ix_a2a_threads_last_activity_at", "a2a_threads", ["last_activity_at"])

    op.add_column(
        "agents",
        sa.Column("kind", sa.String(16), nullable=False, server_default="service"),
    )
    op.add_column("agents", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("webhook_secret", sa.String(64), nullable=True))

    if is_sqlite:
        with op.batch_alter_table("access_requests") as b:
            b.add_column(sa.Column("session_id", sa.String(36), nullable=True))
            b.create_foreign_key(
                "fk_access_requests_session_id", "agent_sessions", ["session_id"], ["id"]
            )
        with op.batch_alter_table("grants") as b:
            b.add_column(sa.Column("session_id", sa.String(36), nullable=True))
            b.create_foreign_key("fk_grants_session_id", "agent_sessions", ["session_id"], ["id"])
        with op.batch_alter_table("a2a_messages") as b:
            b.add_column(sa.Column("thread_id", sa.String(36), nullable=True))
            b.add_column(sa.Column("seq", sa.Integer(), nullable=True))
            b.add_column(sa.Column("sender_session_id", sa.String(36), nullable=True))
            b.create_foreign_key(
                "fk_a2a_messages_thread_id", "a2a_threads", ["thread_id"], ["id"]
            )
            b.create_foreign_key(
                "fk_a2a_messages_sender_session_id",
                "agent_sessions",
                ["sender_session_id"],
                ["id"],
            )
            b.drop_column("delivered_via")
            b.drop_column("acked_at")
    else:
        op.add_column("access_requests", sa.Column("session_id", sa.String(36), nullable=True))
        op.create_foreign_key(
            "fk_access_requests_session_id",
            "access_requests",
            "agent_sessions",
            ["session_id"],
            ["id"],
        )
        op.add_column("grants", sa.Column("session_id", sa.String(36), nullable=True))
        op.create_foreign_key(
            "fk_grants_session_id", "grants", "agent_sessions", ["session_id"], ["id"]
        )
        op.add_column("a2a_messages", sa.Column("thread_id", sa.String(36), nullable=True))
        op.add_column("a2a_messages", sa.Column("seq", sa.Integer(), nullable=True))
        op.add_column(
            "a2a_messages", sa.Column("sender_session_id", sa.String(36), nullable=True)
        )
        op.create_foreign_key(
            "fk_a2a_messages_thread_id", "a2a_messages", "a2a_threads", ["thread_id"], ["id"]
        )
        op.create_foreign_key(
            "fk_a2a_messages_sender_session_id",
            "a2a_messages",
            "agent_sessions",
            ["sender_session_id"],
            ["id"],
        )
        op.drop_column("a2a_messages", "delivered_via")
        op.drop_column("a2a_messages", "acked_at")

    op.create_index(
        "ix_a2a_messages_thread_seq", "a2a_messages", ["thread_id", "seq"], unique=True
    )


def downgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    op.drop_index("ix_a2a_messages_thread_seq", table_name="a2a_messages")

    if is_sqlite:
        with op.batch_alter_table("a2a_messages") as b:
            b.add_column(sa.Column("delivered_via", sa.String(16), nullable=True))
            b.add_column(sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True))
            b.drop_constraint("fk_a2a_messages_thread_id", type_="foreignkey")
            b.drop_constraint("fk_a2a_messages_sender_session_id", type_="foreignkey")
            b.drop_column("thread_id")
            b.drop_column("seq")
            b.drop_column("sender_session_id")
        with op.batch_alter_table("grants") as b:
            b.drop_constraint("fk_grants_session_id", type_="foreignkey")
            b.drop_column("session_id")
        with op.batch_alter_table("access_requests") as b:
            b.drop_constraint("fk_access_requests_session_id", type_="foreignkey")
            b.drop_column("session_id")
    else:
        op.add_column("a2a_messages", sa.Column("delivered_via", sa.String(16), nullable=True))
        op.add_column(
            "a2a_messages", sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True)
        )
        op.drop_constraint("fk_a2a_messages_thread_id", "a2a_messages", type_="foreignkey")
        op.drop_constraint(
            "fk_a2a_messages_sender_session_id", "a2a_messages", type_="foreignkey"
        )
        op.drop_column("a2a_messages", "thread_id")
        op.drop_column("a2a_messages", "seq")
        op.drop_column("a2a_messages", "sender_session_id")
        op.drop_constraint("fk_grants_session_id", "grants", type_="foreignkey")
        op.drop_column("grants", "session_id")
        op.drop_constraint("fk_access_requests_session_id", "access_requests", type_="foreignkey")
        op.drop_column("access_requests", "session_id")

    op.drop_column("agents", "webhook_secret")
    op.drop_column("agents", "last_seen_at")
    op.drop_column("agents", "kind")

    for ix in (
        "ix_a2a_threads_last_activity_at",
        "ix_a2a_threads_state",
        "ix_a2a_threads_responder_agent_id",
        "ix_a2a_threads_initiator_agent_id",
    ):
        op.drop_index(ix, table_name="a2a_threads")
    op.drop_table("a2a_threads")
    op.drop_index("ix_agent_sessions_open", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_agent_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")
