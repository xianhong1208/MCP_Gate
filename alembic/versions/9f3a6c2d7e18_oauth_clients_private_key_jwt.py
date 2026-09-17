"""oauth_clients: public keys for private_key_jwt client authentication (RFC 7523)

Revision ID: 9f3a6c2d7e18
Revises: 4b2c9d7e1f03
Create Date: 2026-09-17 04:10:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = '9f3a6c2d7e18'
down_revision: Union[str, Sequence[str], None] = '4b2c9d7e1f03'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('jwks', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('jwks_uri', sa.String(length=512), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('jwks_uri')
        batch_op.drop_column('jwks')
