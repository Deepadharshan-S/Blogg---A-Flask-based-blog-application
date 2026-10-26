"""add access_logs table (per-request IAM access trail)

Revision ID: 3f9a1c5d7e21
Revises: f8b4d2a71c93
Create Date: 2026-10-26 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "3f9a1c5d7e21"
down_revision = "f8b4d2a71c93"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "access_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("user_label", sa.String(length=128), nullable=True),
        sa.Column("method", sa.String(length=8), nullable=True),
        sa.Column("path", sa.String(length=256), nullable=True),
        sa.Column("endpoint", sa.String(length=128), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("is_api", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("access_logs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_access_logs_timestamp"), ["timestamp"], unique=False)
        batch_op.create_index(batch_op.f("ix_access_logs_user_id"), ["user_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_access_logs_path"), ["path"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_access_logs_status_code"), ["status_code"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_access_logs_is_api"), ["is_api"], unique=False)


def downgrade():
    with op.batch_alter_table("access_logs", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_access_logs_is_api"))
        batch_op.drop_index(batch_op.f("ix_access_logs_status_code"))
        batch_op.drop_index(batch_op.f("ix_access_logs_path"))
        batch_op.drop_index(batch_op.f("ix_access_logs_user_id"))
        batch_op.drop_index(batch_op.f("ix_access_logs_timestamp"))

    op.drop_table("access_logs")
