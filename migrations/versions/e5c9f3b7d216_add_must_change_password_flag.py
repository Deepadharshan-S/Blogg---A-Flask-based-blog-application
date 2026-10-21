"""add must_change_password flag (B1)

Revision ID: e5c9f3b7d216
Revises: d3e7a1c9b584
Create Date: 2026-10-16 09:20:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e5c9f3b7d216"
down_revision = "d3e7a1c9b584"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade():
    op.drop_column("users", "must_change_password")
