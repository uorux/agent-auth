"""add scope column to rules (scope-aware rule matching)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-08

"""
import sqlalchemy as sa
from alembic import op

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('scope', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('rules', 'scope')
