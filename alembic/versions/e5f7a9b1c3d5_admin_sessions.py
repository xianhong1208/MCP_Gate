"""admin_sessions: server-side console sessions (logout and password change revoke them)

Revision ID: e5f7a9b1c3d5
Revises: e5f7a9b1c3d4
Create Date: 2026-11-02 10:00:00

Console session cookies issued before this revision have no row here and stop working: every console user
signs in once after the upgrade.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f7a9b1c3d5'
down_revision: Union[str, Sequence[str], None] = 'e5f7a9b1c3d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'admin_sessions',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['admin_users.id'], name=op.f('fk_admin_sessions_user_id_admin_users'),
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_admin_sessions')),
    )
    with op.batch_alter_table('admin_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_admin_sessions_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_admin_sessions_expires_at'), ['expires_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('admin_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_admin_sessions_expires_at'))
        batch_op.drop_index(batch_op.f('ix_admin_sessions_user_id'))
    op.drop_table('admin_sessions')
