"""oauth_clients: revocation_polled_at (last revocation-feed poll of a resource server)

Revision ID: b8d0f2a4c6e9
Revises: a7c9e1f3b5d7
Create Date: 2026-11-03 07:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'b8d0f2a4c6e9'
down_revision: Union[str, Sequence[str], None] = 'a7c9e1f3b5d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('revocation_polled_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('revocation_polled_at')
