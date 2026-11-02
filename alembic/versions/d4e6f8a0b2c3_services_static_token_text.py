"""services: store the encrypted static bearer token in a TEXT column

AES-GCM plus base64 grows a token by about a third, so VARCHAR(1024) held at most ~740 bytes of plaintext; a
typical JWT bearer is longer. PostgreSQL refused such a row (500), SQLite silently ignored the limit.

Revision ID: d4e6f8a0b2c3
Revises: c3d5e7f9a1b2
Create Date: 2026-11-02 08:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'd4e6f8a0b2c3'
down_revision: Union[str, Sequence[str], None] = 'c3d5e7f9a1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('services', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.alter_column('auth_token_encrypted', existing_type=sa.String(length=1024), type_=sa.Text(),
                              existing_nullable=True)


def downgrade() -> None:
    """Downgrade schema."""
    # A token that does not fit the old column cannot be kept: drop it (the operator re-enters it after upgrading)
    op.execute(sa.text("UPDATE services SET auth_token_encrypted = NULL WHERE LENGTH(auth_token_encrypted) > 1024"))
    with op.batch_alter_table('services', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.alter_column('auth_token_encrypted', existing_type=sa.Text(), type_=sa.String(length=1024),
                              existing_nullable=True)
