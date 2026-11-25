"""tool access (#37): tools in scopes (bundles), per-subject deny / "only" rules, user groups, scope columns as TEXT

Revision ID: b5d7f9a1c3e6
Revises: e3a5c7d9f1b3
Create Date: 2026-11-24 03:00:00

New tables:
- tool_scopes: a tool belongs to a scope (global: scope_service_id NULL, or the server's own scope); a token may call
  the tool when it carries any of them; is_challenge marks the scope named in a step-up challenge.
- tool_access_rules: per server, deny / "only" rules for a subject (pat jti, client, user sub, group).
- user_groups, user_group_members: named groups of console users; group rules are expanded to members' subs.

New columns: services.unscoped_tools ("allow" for every existing server: nothing changes on upgrade),
oauth_clients.policy_features, title on oauth_scopes and service_scopes.

The scope columns of oauth_clients, oauth_authorization_requests, oauth_authorization_codes, oauth_tokens and
oauth_consents become TEXT (were VARCHAR(512), which PostgreSQL enforces): a token with many bundle scopes would not
fit. Downgrading back to VARCHAR(512) fails on PostgreSQL if a longer value was stored since.

No backfill. Existing scope names that could not appear in a quoted WWW-Authenticate value (RFC 6749 scope-token
characters) are only logged: such a scope cannot be assigned to a tool, everything else keeps working.
"""
import logging
import re
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'b5d7f9a1c3e6'
down_revision: Union[str, Sequence[str], None] = 'e3a5c7d9f1b3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

SCOPE_TABLES = ('oauth_clients', 'oauth_authorization_requests', 'oauth_authorization_codes', 'oauth_tokens',
                'oauth_consents')
# RFC 6749 §3.3 scope-token: %x21 / %x23-5B / %x5D-7E (frozen copy of src/tool_policy/validation.py)
_SCOPE_TOKEN = re.compile(r'^[\x21\x23-\x5B\x5D-\x7E]+$')


def upgrade() -> None:
    op.create_table(
        'tool_scopes',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tool_id', sa.Uuid(), nullable=False),
        sa.Column('scope_name', sa.String(length=128), nullable=False),
        sa.Column('scope_service_id', sa.Uuid(), nullable=True),
        sa.Column('is_challenge', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(['tool_id'], ['mcp_tools.id'], name=op.f('fk_tool_scopes_tool_id_mcp_tools'),
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scope_service_id'], ['services.id'],
                                name=op.f('fk_tool_scopes_scope_service_id_services'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_scopes')),
        sa.UniqueConstraint('tool_id', 'scope_name', name='uq_tool_scopes_tool_id_scope_name'),
    )
    with op.batch_alter_table('tool_scopes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tool_scopes_tool_id'), ['tool_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_scopes_scope_name'), ['scope_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_scopes_scope_service_id'), ['scope_service_id'], unique=False)

    op.create_table(
        'tool_access_rules',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('service_id', sa.Uuid(), nullable=False),
        sa.Column('effect', sa.String(length=8), nullable=False),
        sa.Column('subject_kind', sa.String(length=8), nullable=False),
        sa.Column('subject_id', sa.String(length=255), nullable=False),
        sa.Column('tools', sa.Text(), nullable=False),
        sa.Column('note', sa.String(length=256), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=256), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'],
                                name=op.f('fk_tool_access_rules_service_id_services'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_access_rules')),
    )
    with op.batch_alter_table('tool_access_rules', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_tool_access_rules_service_id'), ['service_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_tool_access_rules_subject_id'), ['subject_id'], unique=False)

    op.create_table(
        'user_groups',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=256), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_user_groups')),
        sa.UniqueConstraint('name', name=op.f('uq_user_groups_name')),
    )
    op.create_table(
        'user_group_members',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('group_id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('added_at', sa.DateTime(), nullable=False),
        sa.Column('added_by', sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(['group_id'], ['user_groups.id'],
                                name=op.f('fk_user_group_members_group_id_user_groups'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['admin_users.id'],
                                name=op.f('fk_user_group_members_user_id_admin_users'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_user_group_members')),
        sa.UniqueConstraint('group_id', 'user_id', name='uq_user_group_members_group_id_user_id'),
    )
    with op.batch_alter_table('user_group_members', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_group_members_group_id'), ['group_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_group_members_user_id'), ['user_id'], unique=False)

    with op.batch_alter_table('services', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('unscoped_tools', sa.String(length=16), nullable=False,
                                      server_default='allow'))
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('policy_features', sa.String(length=64), nullable=True))
    for table in ('oauth_scopes', 'service_scopes'):
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
            batch_op.add_column(sa.Column('title', sa.String(length=128), nullable=True))
    for table in SCOPE_TABLES:
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
            batch_op.alter_column('scope', existing_type=sa.String(length=512), type_=sa.Text(),
                                  existing_nullable=True)

    bind = op.get_bind()
    names = [r[0] for r in bind.execute(sa.text('SELECT name FROM oauth_scopes'))]
    names += [r[0] for r in bind.execute(sa.text('SELECT name FROM service_scopes'))]
    for name in sorted(set(names)):
        if not _SCOPE_TOKEN.match(name or ''):
            logger.warning("Scope %r has characters a step-up challenge cannot carry (RFC 6749 scope-token); "
                           "it keeps working but cannot be assigned to a tool", name)


def downgrade() -> None:
    for table in SCOPE_TABLES:
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
            batch_op.alter_column('scope', existing_type=sa.Text(), type_=sa.String(length=512),
                                  existing_nullable=True)
    for table in ('service_scopes', 'oauth_scopes'):
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
            batch_op.drop_column('title')
    with op.batch_alter_table('oauth_clients', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('policy_features')
    with op.batch_alter_table('services', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_column('unscoped_tools')

    with op.batch_alter_table('user_group_members', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_group_members_user_id'))
        batch_op.drop_index(batch_op.f('ix_user_group_members_group_id'))
    op.drop_table('user_group_members')
    op.drop_table('user_groups')
    with op.batch_alter_table('tool_access_rules', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tool_access_rules_subject_id'))
        batch_op.drop_index(batch_op.f('ix_tool_access_rules_service_id'))
    op.drop_table('tool_access_rules')
    with op.batch_alter_table('tool_scopes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_tool_scopes_scope_service_id'))
        batch_op.drop_index(batch_op.f('ix_tool_scopes_scope_name'))
        batch_op.drop_index(batch_op.f('ix_tool_scopes_tool_id'))
    op.drop_table('tool_scopes')
