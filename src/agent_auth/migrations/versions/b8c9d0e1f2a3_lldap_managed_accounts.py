"""LLDAP managed accounts

Agents registered without an lldap_username get an LLDAP service account
created by the broker at their first homelab grant. The generated password is
stored Fernet-wrapped here and handed out through credential fetches; NULL
marks a pre-existing, hand-registered account the broker never touches.

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("lldap_password_encrypted", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "lldap_password_encrypted")
