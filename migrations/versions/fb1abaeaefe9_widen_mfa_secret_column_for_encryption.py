"""widen mfa_secret column for encryption

Revision ID: fb1abaeaefe9
Revises: 3f9a1c5d7e21
Create Date: 2026-11-03 22:17:33.081072

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fb1abaeaefe9'
down_revision = '3f9a1c5d7e21'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "mfa_secret",
            existing_type=sa.String(length=64),
            type_=sa.String(length=255),
            existing_nullable=True,
        )


def downgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "mfa_secret",
            existing_type=sa.String(length=255),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
