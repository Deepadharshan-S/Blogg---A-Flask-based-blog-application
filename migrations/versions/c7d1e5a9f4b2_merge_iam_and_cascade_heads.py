"""merge iam and cascade heads

Revision ID: c7d1e5a9f4b2
Revises: 8eb278139506, 1a7bdb00f7b3
Create Date: 2026-10-16 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "c7d1e5a9f4b2"
down_revision = ("8eb278139506", "1a7bdb00f7b3")
branch_labels = None
depends_on = None


def upgrade():
    # Merge point only: no schema changes. Both parent branches carry their
    # own DDL (IAM models; ON DELETE CASCADE foreign keys).
    pass


def downgrade():
    # Splitting heads again is not supported.
    pass
