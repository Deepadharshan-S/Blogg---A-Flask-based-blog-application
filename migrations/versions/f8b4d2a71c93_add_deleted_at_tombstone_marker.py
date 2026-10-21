"""add deleted_at tombstone marker (B3)

Revision ID: f8b4d2a71c93
Revises: e5c9f3b7d216
Create Date: 2026-10-16 10:05:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f8b4d2a71c93"
down_revision = "e5c9f3b7d216"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("deleted_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("users", "deleted_at")
