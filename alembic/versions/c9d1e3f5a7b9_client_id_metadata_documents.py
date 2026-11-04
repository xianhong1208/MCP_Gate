"""Client ID Metadata Documents: client_id columns widen to 255 (a URL), oauth_clients.metadata_fetched_at

Revision ID: c9d1e3f5a7b9
Revises: b8d0f2a4c6e9
Create Date: 2026-11-03 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'c9d1e3f5a7b9'
down_revision: Union[str, Sequence[str], None] = 'b8d0f2a4c6e9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, column, old length, nullable)
WIDENED = (
    ('oauth_clients', 'client_id', 64, False),
    ('oauth_authorization_requests', 'client_id', 64, False),
    ('oauth_authorization_codes', 'client_id', 64, False),
    ('oauth_tokens', 'client_id', 64, True),
    ('oauth_consents', 'client_id', 64, False),
    ('token_usage', 'client_id', 64, True),
    ('audit_logs', 'resource_id', 128, True),
    ('audit_logs', 'actor_id', 128, True),
)
NEW_LENGTH = 255


def _alter(table: str, changes: list) -> None:
    with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        for column, old, new, nullable in changes:
            batch_op.alter_column(column, existing_type=sa.String(length=old), type_=sa.String(length=new),
                                  existing_nullable=nullable)


def _by_table(rows):
    tables: dict = {}
    for table, column, old, new, nullable in rows:
        tables.setdefault(table, []).append((column, old, new, nullable))
    return tables


def upgrade() -> None:
    """Upgrade schema."""
    # Widening a VARCHAR is metadata-only on PostgreSQL (foreign keys between the widened columns stay valid);
    # SQLite does not enforce the length, its batch copy only rewrites the declared type.
    for table, changes in _by_table([(t, c, old, NEW_LENGTH, n) for t, c, old, n in WIDENED]).items():
        _alter(table, changes)
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('metadata_fetched_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    # Rows that only exist because of the wider columns (clients identified by a metadata-document URL and what
    # hangs off them) cannot be represented by the old schema: remove them first, or the narrowing fails on
    # PostgreSQL. Tokens keep their history with the client gone (client_id NULL, as when a client is deleted).
    op.execute(sa.text(
        "UPDATE oauth_tokens SET client_name_snapshot = COALESCE(client_name_snapshot, "
        "(SELECT client_name FROM oauth_clients WHERE oauth_clients.client_id = oauth_tokens.client_id)), "
        "client_id = NULL WHERE length(client_id) > 64"))
    for table in ('oauth_authorization_requests', 'oauth_authorization_codes', 'oauth_consents'):
        op.execute(sa.text(f"DELETE FROM {table} WHERE length(client_id) > 64"))
    op.execute(sa.text("UPDATE token_usage SET client_id = substr(client_id, 1, 64) WHERE length(client_id) > 64"))
    op.execute(sa.text("DELETE FROM oauth_clients WHERE length(client_id) > 64"))
    op.execute(sa.text("UPDATE audit_logs SET resource_id = substr(resource_id, 1, 128) WHERE length(resource_id) > 128"))
    op.execute(sa.text("UPDATE audit_logs SET actor_id = substr(actor_id, 1, 128) WHERE length(actor_id) > 128"))

    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('metadata_fetched_at')
    # children before the parent, so PostgreSQL never sees a foreign key wider than the key it references
    for table, changes in reversed(list(_by_table([(t, c, NEW_LENGTH, old, n) for t, c, old, n in WIDENED]).items())):
        _alter(table, changes)
