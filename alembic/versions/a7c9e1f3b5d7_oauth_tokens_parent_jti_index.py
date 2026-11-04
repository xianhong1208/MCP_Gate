"""oauth_tokens: index parent_jti (family revocation on replay)

Revision ID: a7c9e1f3b5d7
Revises: f6a8b0c2d4e6
Create Date: 2026-11-03 06:00:00

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a7c9e1f3b5d7'
down_revision: Union[str, Sequence[str], None] = 'f6a8b0c2d4e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # A plain CREATE INDEX works on SQLite and PostgreSQL alike; no batch (table rebuild) needed
    op.create_index(op.f('ix_oauth_tokens_parent_jti'), 'oauth_tokens', ['parent_jti'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_oauth_tokens_parent_jti'), table_name='oauth_tokens')
