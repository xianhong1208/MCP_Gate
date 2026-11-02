"""admin_users.owner_slot: a unique marker that makes first-time setup atomic

Revision ID: f6a8b0c2d4e6
Revises: e5f7a9b1c3d5
Create Date: 2026-11-02 11:00:00

Concurrent POST /api/session/setup requests could each pass the "no account yet" check and each create an
owner. The owner now takes owner_slot = 1 and the unique constraint lets only one INSERT win. Existing installs:
the earliest account gets the slot, so setup stays closed.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'f6a8b0c2d4e6'
down_revision: Union[str, Sequence[str], None] = 'e5f7a9b1c3d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('admin_users', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('owner_slot', sa.Integer(), nullable=True))
        batch_op.create_unique_constraint(batch_op.f('uq_admin_users_owner_slot'), ['owner_slot'])
    op.execute(
        "UPDATE admin_users SET owner_slot = 1 WHERE id = "
        "(SELECT id FROM (SELECT id FROM admin_users ORDER BY created_at, id LIMIT 1) AS first_account)"
    )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('admin_users', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_admin_users_owner_slot'), type_='unique')
        batch_op.drop_column('owner_slot')
