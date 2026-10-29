"""OAuth connectors for web UIs (remote MCP): clients and tokens

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-10-16
"""

import sqlalchemy as sa
from alembic import op

revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, server_default=""),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=True),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_oauth_clients_agent_id", "oauth_clients", ["agent_id"])
    op.create_table(
        "oauth_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("client_id", sa.String(64), sa.ForeignKey("oauth_clients.id"), nullable=False),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("family", sa.String(36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("code_challenge", sa.String(128), nullable=True),
        sa.Column("redirect_uri", sa.String(512), nullable=True),
        sa.Column("authorized_by", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_oauth_tokens_token_hash", "oauth_tokens", ["token_hash"], unique=True)
    op.create_index("ix_oauth_tokens_client_id", "oauth_tokens", ["client_id"])
    op.create_index("ix_oauth_tokens_agent_id", "oauth_tokens", ["agent_id"])
    op.create_index("ix_oauth_tokens_family", "oauth_tokens", ["family"])
    op.create_index("ix_oauth_tokens_expires_at", "oauth_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("oauth_tokens")
    op.drop_table("oauth_clients")
