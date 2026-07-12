"""increase_raw_documents_external_id_size

Revision ID: b1bd93ace2e8
Revises: 001
Create Date: 2026-04-30 22:01:44.890925

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1bd93ace2e8'
down_revision: Union[str, Sequence[str], None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Postgres: ALTER COLUMN TYPE VARCHAR(2000).
    SQLite: tipi değiştirmek için table rebuild gerekir; ancak SQLite
    kolon tipi zaten yaratım sırasında TEXT olarak gelir (tip genişletme
    anlamsız). Batch mode güvenli çalışır.
    """
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        # SQLite — no-op, kolon zaten TEXT (genişlik constraint'i yok)
        return
    op.alter_column('raw_documents', 'external_id',
                    existing_type=sa.String(200),
                    type_=sa.String(2000),
                    existing_nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        return
    op.alter_column('raw_documents', 'external_id',
                    existing_type=sa.String(2000),
                    type_=sa.String(200),
                    existing_nullable=False)