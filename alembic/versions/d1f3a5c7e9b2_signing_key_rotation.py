"""signing key rotation (#30): publish-before-use, per-key signed-until, emergency revocation; tokens record their kid

Revision ID: d1f3a5c7e9b2
Revises: a1c3e5f7b9d1
Create Date: 2026-11-14 01:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'd1f3a5c7e9b2'
down_revision: Union[str, Sequence[str], None] = 'a1c3e5f7b9d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. Every new column is nullable, so existing rows need no backfill: a key with no
    activates_at was active from its creation, a key with no signed_until falls back to the longest token lifetime,
    and a token with no kid is attributed to the key that was active when it was issued (as before)."""
    with op.batch_alter_table('oauth_signing_keys', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('activates_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('signed_until', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('revoked_at', sa.DateTime(), nullable=True))
    with op.batch_alter_table('oauth_tokens', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('kid', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_oauth_tokens_kid'), 'oauth_tokens', ['kid'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_oauth_tokens_kid'), table_name='oauth_tokens')
    with op.batch_alter_table('oauth_tokens', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('kid')
    with op.batch_alter_table('oauth_signing_keys', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('revoked_at')
        batch_op.drop_column('signed_until')
        batch_op.drop_column('activates_at')
