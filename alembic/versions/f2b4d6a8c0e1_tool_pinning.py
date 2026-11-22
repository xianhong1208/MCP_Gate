"""tool pinning (#32): every tool definition is pinned by a hash with an approval state; existing tools are the baseline

Revision ID: f2b4d6a8c0e1
Revises: d1f3a5c7e9b2
Create Date: 2026-11-21 02:00:00

mcp_tools keeps one row per tool name (now unique per service) with its current definition, which gains title,
outputSchema and annotations, the current hash, when it was last listed and whether the server stopped listing it.
mcp_tool_versions holds every definition a tool has had: hash, the canonical JSON it covers, and approved / pending /
rejected.

Baseline: every tool already stored is approved, decided_by "upgrade", flagged legacy_baseline. Its hash covers the
fields stored before pinning (name, description, inputSchema). The first refresh that lists the tool again completes
the baseline with the server's full definition when those three fields are unchanged (db/crud.py
MCPToolCRUD.sync_tools), so title / outputSchema / annotations do not turn every existing tool pending.

The hash below is a frozen copy of src/tool_pinning/hashing.py version 1 (tests/test_tool_pinning_migration.py checks
they agree), so this migration keeps producing the same pins whatever later happens to the application code.
"""
import hashlib
import json
import uuid
from datetime import datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from db.database import NAMING_CONVENTION


# revision identifiers, used by Alembic.
revision: str = 'f2b4d6a8c0e1'
down_revision: Union[str, Sequence[str], None] = 'd1f3a5c7e9b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BASELINE_ACTOR = 'upgrade'
_HASHED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def _canonical_json(tool: dict) -> str:
    canonical = {key: tool[key] for key in _HASHED_FIELDS if tool.get(key) is not None}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def legacy_definition(name, description, input_schema_text) -> dict:
    """The MCP form of a tool row stored before pinning."""
    return {"name": name, "description": description,
            "inputSchema": json.loads(input_schema_text) if input_schema_text else None}


_tools = sa.table(
    'mcp_tools',
    sa.column('id', sa.Uuid()), sa.column('service_id', sa.Uuid()), sa.column('name', sa.String()),
    sa.column('description', sa.Text()), sa.column('input_schema', sa.Text()),
    sa.column('created_at', sa.DateTime()), sa.column('current_hash', sa.String()),
    sa.column('last_seen_at', sa.DateTime()), sa.column('removed_at', sa.DateTime()),
)
_versions = sa.table(
    'mcp_tool_versions',
    sa.column('id', sa.Uuid()), sa.column('tool_id', sa.Uuid()), sa.column('hash', sa.String()),
    sa.column('definition', sa.Text()), sa.column('state', sa.String()),
    sa.column('first_seen_at', sa.DateTime()), sa.column('last_seen_at', sa.DateTime()),
    sa.column('decided_at', sa.DateTime()), sa.column('decided_by', sa.String()),
    sa.column('legacy_baseline', sa.Boolean()),
)


def upgrade() -> None:
    bind = op.get_bind()
    with op.batch_alter_table('mcp_tools', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column('title', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('output_schema', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('annotations', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('current_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('last_seen_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('removed_at', sa.DateTime(), nullable=True))

    # The old sync deleted and re-inserted the whole list, so a name appears once per service; should an old bug
    # have left a duplicate, keep the oldest row so the unique constraint can be created.
    rows = bind.execute(sa.select(_tools.c.id, _tools.c.service_id, _tools.c.name, _tools.c.created_at)
                        .order_by(_tools.c.created_at, _tools.c.id)).all()
    seen, duplicates = set(), []
    for row in rows:
        key = (row.service_id, row.name)
        if key in seen:
            duplicates.append(row.id)
        seen.add(key)
    for dup in duplicates:
        bind.execute(sa.delete(_tools).where(_tools.c.id == dup))

    with op.batch_alter_table('mcp_tools', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.create_unique_constraint('uq_mcp_tools_service_id_name', ['service_id', 'name'])

    op.create_table(
        'mcp_tool_versions',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tool_id', sa.Uuid(), nullable=False),
        sa.Column('hash', sa.String(length=64), nullable=False),
        sa.Column('definition', sa.Text(), nullable=False),
        sa.Column('state', sa.String(length=16), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('decided_at', sa.DateTime(), nullable=True),
        sa.Column('decided_by', sa.String(length=256), nullable=True),
        sa.Column('legacy_baseline', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.ForeignKeyConstraint(['tool_id'], ['mcp_tools.id'], name=op.f('fk_mcp_tool_versions_tool_id_mcp_tools'),
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mcp_tool_versions')),
        sa.UniqueConstraint('tool_id', 'hash', name='uq_mcp_tool_versions_tool_id_hash'),
    )
    with op.batch_alter_table('mcp_tool_versions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mcp_tool_versions_tool_id'), ['tool_id'], unique=False)

    # The baseline: every tool stored today is approved as it is
    now = datetime.now()
    baseline = []
    for row in bind.execute(sa.select(_tools.c.id, _tools.c.name, _tools.c.description, _tools.c.input_schema,
                                      _tools.c.created_at)).all():
        definition = _canonical_json(legacy_definition(row.name, row.description, row.input_schema))
        digest = hashlib.sha256(definition.encode("utf-8")).hexdigest()
        bind.execute(sa.update(_tools).where(_tools.c.id == row.id).values(
            current_hash=digest, last_seen_at=row.created_at))
        baseline.append({
            'id': uuid.uuid4(), 'tool_id': row.id, 'hash': digest, 'definition': definition, 'state': 'approved',
            'first_seen_at': row.created_at or now, 'last_seen_at': row.created_at or now, 'decided_at': now,
            'decided_by': BASELINE_ACTOR, 'legacy_baseline': True,
        })
    if baseline:
        op.bulk_insert(_versions, baseline)


def downgrade() -> None:
    """Back to one row per listed tool: the versions go, and so do tools the server no longer lists (before pinning
    such a tool was simply deleted by the next refresh)."""
    with op.batch_alter_table('mcp_tool_versions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mcp_tool_versions_tool_id'))
    op.drop_table('mcp_tool_versions')
    bind = op.get_bind()
    bind.execute(sa.delete(_tools).where(_tools.c.removed_at.isnot(None)))
    with op.batch_alter_table('mcp_tools', schema=None, naming_convention=NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint('uq_mcp_tools_service_id_name', type_='unique')
        batch_op.drop_column('removed_at')
        batch_op.drop_column('last_seen_at')
        batch_op.drop_column('current_hash')
        batch_op.drop_column('annotations')
        batch_op.drop_column('output_schema')
        batch_op.drop_column('title')
