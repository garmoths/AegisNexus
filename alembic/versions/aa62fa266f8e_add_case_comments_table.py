"""add_case_comments_table

Revision ID: aa62fa266f8e
Revises: b1bd93ace2e8
Create Date: 2026-05-02 13:12:03.450008

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'aa62fa266f8e'
down_revision: Union[str, Sequence[str], None] = 'b1bd93ace2e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'case_comments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('case_id', sa.Integer(), sa.ForeignKey('victim_cases.id'), nullable=False, index=True),
        sa.Column('nickname', sa.String(60), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('upvotes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ip_hash', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_comment_case_created', 'case_comments', ['case_id', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_comment_case_created', table_name='case_comments')
    op.drop_table('case_comments')
