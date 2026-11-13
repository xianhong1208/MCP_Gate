"""Built-in clients renamed: mcp-center-console / mcp-center-scanner -> mcp-gate-console / mcp-gate-scanner

Revision ID: a1c3e5f7b9d1
Revises: c9d1e3f5a7b9
Create Date: 2026-11-13 10:00:00

The last names left over from MCP Center. oauth_clients.client_id is a primary key that four tables reference
with foreign keys, so the row is not updated in place (PostgreSQL would refuse while children point at it, and
SQLite enforces the keys too): a copy is inserted under the new id, every row that names the old id is moved to it,
then the old row is deleted. That works the same on both databases and needs no ON UPDATE CASCADE.

Moved: oauth_authorization_requests, oauth_authorization_codes, oauth_tokens and oauth_consents (foreign keys),
token_usage.client_id, and audit_logs.resource_id / actor_id where they hold the id. Display names still reading
"MCP Center Console" / "MCP Center Scanner" (and the token records' snapshot of them) become "MCP Gate ...".

Personal access tokens keep working: their records follow the client, resource servers verify the JWT itself,
and the claim's old id is still accepted as the console's (db/seed.py LEGACY_CLIENT_IDS). Console sign-in does
not use these clients, and scanner tokens are short-lived and never recorded, so nothing else changes. If a copy
under the new id already exists (seeded by a newer server that skipped migrations), the old row's references
move to it and the old row goes.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1c3e5f7b9d1'
down_revision: Union[str, Sequence[str], None] = 'c9d1e3f5a7b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (old id, new id, old display name, new display name)
RENAMES = (
    ('mcp-center-console', 'mcp-gate-console', 'MCP Center Console', 'MCP Gate Console'),
    ('mcp-center-scanner', 'mcp-gate-scanner', 'MCP Center Scanner', 'MCP Gate Scanner'),
)

# (table, column) holding a client id, foreign key or not
REFERENCES = (
    ('oauth_authorization_requests', 'client_id'),
    ('oauth_authorization_codes', 'client_id'),
    ('oauth_tokens', 'client_id'),
    ('oauth_consents', 'client_id'),
    ('token_usage', 'client_id'),
    ('audit_logs', 'resource_id'),
    ('audit_logs', 'actor_id'),
)


def _rename(old: str, new: str, old_name: str, new_name: str) -> None:
    bind = op.get_bind()
    params = {'old': old, 'new': new, 'old_name': old_name, 'new_name': new_name}
    # Installs seeded before the 2026-11-02 rename also kept the old display names (the seed never updates a row);
    # the token records' name snapshot shows it too
    bind.execute(sa.text("UPDATE oauth_clients SET client_name = :new_name WHERE client_id IN (:old, :new) "
                         "AND client_name = :old_name"), params)
    bind.execute(sa.text("UPDATE oauth_tokens SET client_name_snapshot = :new_name WHERE client_id IN (:old, :new) "
                         "AND client_name_snapshot = :old_name"), params)
    if bind.execute(sa.text("SELECT 1 FROM oauth_clients WHERE client_id = :old"), params).first() is None:
        return
    if bind.execute(sa.text("SELECT 1 FROM oauth_clients WHERE client_id = :new"), params).first() is None:
        others = [c['name'] for c in sa.inspect(bind).get_columns('oauth_clients') if c['name'] != 'client_id']
        cols = ", ".join(others)
        bind.execute(sa.text(
            f"INSERT INTO oauth_clients (client_id, {cols}) SELECT :new, {cols} FROM oauth_clients WHERE client_id = :old"
        ), params)
    for table, column in REFERENCES:
        bind.execute(sa.text(f"UPDATE {table} SET {column} = :new WHERE {column} = :old"), params)
    bind.execute(sa.text("DELETE FROM oauth_clients WHERE client_id = :old"), params)


def upgrade() -> None:
    for old, new, old_name, new_name in RENAMES:
        _rename(old, new, old_name, new_name)


def downgrade() -> None:
    for old, new, old_name, new_name in RENAMES:
        _rename(new, old, new_name, old_name)
