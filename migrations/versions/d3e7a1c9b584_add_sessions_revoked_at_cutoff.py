"""add sessions_revoked_at cutoff (A4)

Revision ID: d3e7a1c9b584
Revises: c7d1e5a9f4b2
Create Date: 2026-10-16 08:30:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d3e7a1c9b584"
down_revision = "c7d1e5a9f4b2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("sessions_revoked_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("users", "sessions_revoked_at")
