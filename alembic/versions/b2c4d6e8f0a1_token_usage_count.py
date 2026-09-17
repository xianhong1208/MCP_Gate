"""token_usage: count column for batched usage reports from MCP servers

Revision ID: b2c4d6e8f0a1
Revises: 9f3a6c2d7e18
Create Date: 2026-09-17 05:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'b2c4d6e8f0a1'
down_revision: Union[str, Sequence[str], None] = '9f3a6c2d7e18'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('token_usage', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('count', sa.Integer(), nullable=False, server_default='1'))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('token_usage', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('count')
