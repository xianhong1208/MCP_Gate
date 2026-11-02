"""oauth_clients: resource-server binding (resource_audience)

Revision ID: e5f7a9b1c3d4
Revises: d4e6f8a0b2c3
Create Date: 2026-11-02 08:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'e5f7a9b1c3d4'
down_revision: Union[str, Sequence[str], None] = 'd4e6f8a0b2c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('resource_audience', sa.String(length=256), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('resource_audience')
