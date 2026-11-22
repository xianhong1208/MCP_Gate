"""tool policy feed (#33): where each tool version came from, and when a resource server last read the policy feed

Revision ID: e3a5c7d9f1b3
Revises: f2b4d6a8c0e1
Create Date: 2026-11-22 03:00:00

mcp_tool_versions.source: "scan" (MCP Gate listed the tools itself) or "reported" (the server's pinning middleware
sent a definition MCP Gate had not approved, POST /oauth/tool-report). Every existing version came from a scan.
oauth_clients.policy_polled_at: when the resource server last read POST /oauth/policy, so the console can tell
whether the server enforces tool approvals.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'e3a5c7d9f1b3'
down_revision: Union[str, Sequence[str], None] = 'f2b4d6a8c0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('mcp_tool_versions', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('source', sa.String(length=16), nullable=False, server_default='scan'))
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('policy_polled_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('policy_polled_at')
    with op.batch_alter_table('mcp_tool_versions', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('source')
