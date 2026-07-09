"""thread-anchored delegated auth (on-behalf-of)

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-09

A request may be anchored to an OPEN a2a thread the requester participates in;
the thread's other participant becomes the structural delegator. Policy rules
gain a delegator pattern so authorization is over the (delegate, delegator)
pair, and delegated grants are revoked when their thread closes.

All columns are nullable and default to "no delegation" — existing rows and
rules behave exactly as before (rules with NULL delegator_pattern never
auto-approve delegated requests, by engine semantics, not schema).
"""

import sqlalchemy as sa
from alembic import op

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None

_TABLES = ("access_requests", "grants")


def upgrade() -> None:
    is_sqlite = op.get_bind().dialect.name == "sqlite"

    for table in _TABLES:
        if is_sqlite:
            with op.batch_alter_table(table) as b:
                b.add_column(sa.Column("delegation_thread_id", sa.String(36), nullable=True))
                b.add_column(sa.Column("delegator_agent_id", sa.String(36), nullable=True))
                b.create_foreign_key(
                    f"fk_{table}_delegation_thread_id",
                    "a2a_threads",
                    ["delegation_thread_id"],
                    ["id"],
                )
                b.create_foreign_key(
                    f"fk_{table}_delegator_agent_id",
                    "agents",
                    ["delegator_agent_id"],
                    ["id"],
                )
        else:
            op.add_column(table, sa.Column("delegation_thread_id", sa.String(36), nullable=True))
            op.add_column(table, sa.Column("delegator_agent_id", sa.String(36), nullable=True))
            op.create_foreign_key(
                f"fk_{table}_delegation_thread_id",
                table,
                "a2a_threads",
                ["delegation_thread_id"],
                ["id"],
            )
            op.create_foreign_key(
                f"fk_{table}_delegator_agent_id", table, "agents", ["delegator_agent_id"], ["id"]
            )

    op.add_column("rules", sa.Column("delegator_pattern", sa.String(128), nullable=True))


def downgrade() -> None:
    is_sqlite = op.get_bind().dialect.name == "sqlite"

    op.drop_column("rules", "delegator_pattern")
    for table in _TABLES:
        if is_sqlite:
            with op.batch_alter_table(table) as b:
                b.drop_constraint(f"fk_{table}_delegation_thread_id", type_="foreignkey")
                b.drop_constraint(f"fk_{table}_delegator_agent_id", type_="foreignkey")
                b.drop_column("delegation_thread_id")
                b.drop_column("delegator_agent_id")
        else:
            op.drop_constraint(f"fk_{table}_delegation_thread_id", table, type_="foreignkey")
            op.drop_constraint(f"fk_{table}_delegator_agent_id", table, type_="foreignkey")
            op.drop_column(table, "delegation_thread_id")
            op.drop_column(table, "delegator_agent_id")
