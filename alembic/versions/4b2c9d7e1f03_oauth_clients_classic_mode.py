"""oauth_clients classic mode: optional PKCE and default resource

Revision ID: 4b2c9d7e1f03
Revises: 1ee09c99d84d
Create Date: 2026-09-01 16:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = '4b2c9d7e1f03'
down_revision: Union[str, Sequence[str], None] = '1ee09c99d84d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('require_pkce', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column('default_resource', sa.String(length=512), nullable=True))
    for table in ('oauth_authorization_requests', 'oauth_authorization_codes'):
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
            batch_op.alter_column('code_challenge', existing_type=sa.VARCHAR(length=128), nullable=True)
            batch_op.alter_column('code_challenge_method', existing_type=sa.VARCHAR(length=16), nullable=True)


def downgrade() -> None:
    """Downgrade schema."""
    for table in ('oauth_authorization_requests', 'oauth_authorization_codes'):
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
            batch_op.alter_column('code_challenge_method', existing_type=sa.VARCHAR(length=16), nullable=False)
            batch_op.alter_column('code_challenge', existing_type=sa.VARCHAR(length=128), nullable=False)
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('default_resource')
        batch_op.drop_column('require_pkce')
