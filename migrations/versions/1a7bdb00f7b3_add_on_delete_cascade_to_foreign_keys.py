"""add_on_delete_cascade_to_foreign_keys

Revision ID: 1a7bdb00f7b3
Revises: 5459bc4c9cf7
Create Date: 2026-10-15 02:26:10.955600

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a7bdb00f7b3'
down_revision = '5459bc4c9cf7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table(
        'comments',
        schema=None,
        table_args=(
            sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ondelete='CASCADE'),
        ),
    ) as batch_op:
        pass

    with op.batch_alter_table(
        'follows',
        schema=None,
        table_args=(
            sa.ForeignKeyConstraint(['followed_id'], ['users.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['follower_id'], ['users.id'], ondelete='CASCADE'),
        ),
    ) as batch_op:
        pass

    with op.batch_alter_table(
        'posts',
        schema=None,
        table_args=(
            sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='CASCADE'),
        ),
    ) as batch_op:
        pass


def downgrade():
    with op.batch_alter_table(
        'posts',
        schema=None,
        table_args=(
            sa.ForeignKeyConstraint(['author_id'], ['users.id']),
        ),
    ) as batch_op:
        pass

    with op.batch_alter_table(
        'follows',
        schema=None,
        table_args=(
            sa.ForeignKeyConstraint(['follower_id'], ['users.id']),
            sa.ForeignKeyConstraint(['followed_id'], ['users.id']),
        ),
    ) as batch_op:
        pass

    with op.batch_alter_table(
        'comments',
        schema=None,
        table_args=(
            sa.ForeignKeyConstraint(['author_id'], ['users.id']),
            sa.ForeignKeyConstraint(['post_id'], ['posts.id']),
        ),
    ) as batch_op:
        pass
