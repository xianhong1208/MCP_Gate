"""service_scopes: scopes declared by one MCP server in addition to the global registry

Revision ID: c3d5e7f9a1b2
Revises: b2c4d6e8f0a1
Create Date: 2026-09-17 06:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d5e7f9a1b2'
down_revision: Union[str, Sequence[str], None] = 'b2c4d6e8f0a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'service_scopes',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('service_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('is_default', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], name=op.f('fk_service_scopes_service_id_services'),
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_service_scopes')),
        sa.UniqueConstraint('service_id', 'name', name='uq_service_scope'),
    )
    with op.batch_alter_table('service_scopes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_service_scopes_service_id'), ['service_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('service_scopes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_service_scopes_service_id'))
    op.drop_table('service_scopes')
