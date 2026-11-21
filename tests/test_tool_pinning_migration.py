"""The tool pinning migration (#32): every tool an existing deployment has is approved as the baseline, and the first
refresh after the upgrade completes that baseline instead of turning every tool pending."""

import json
import uuid
from datetime import datetime
from pathlib import Path

import sqlalchemy as sa

from src.tool_pinning.hashing import tool_hash
from tests.test_schema_drift import _alembic_config, scratch_db  # noqa: F401  (fixture)

BEFORE = "d1f3a5c7e9b2"
REVISION = "f2b4d6a8c0e1"

_services = sa.table("services", sa.column("id", sa.Uuid()), sa.column("name", sa.String()),
                     sa.column("is_active", sa.Boolean()), sa.column("protocol", sa.String()),
                     sa.column("mcp_path", sa.String()), sa.column("source", sa.String()),
                     sa.column("requires_auth", sa.Boolean()), sa.column("health_status", sa.String()),
                     sa.column("health_fail_count", sa.Integer()), sa.column("created_at", sa.DateTime()),
                     sa.column("updated_at", sa.DateTime()))
_tools = sa.table("mcp_tools", sa.column("id", sa.Uuid()), sa.column("service_id", sa.Uuid()),
                  sa.column("name", sa.String()), sa.column("description", sa.Text()),
                  sa.column("input_schema", sa.Text()), sa.column("created_at", sa.DateTime()))

LEGACY = [
    ("search", "Search the docs.", json.dumps({"type": "object", "properties": {"q": {"type": "string"}}})),
    ("ping", None, None),
    ("翻譯", "翻成繁體中文", json.dumps({"type": "object"})),
]


def _seed_legacy(url):
    eng = sa.create_engine(url)
    sid = uuid.uuid4()
    created = datetime(2026, 11, 1, 12, 0, 0)
    with eng.begin() as conn:
        conn.execute(sa.insert(_services).values(
            id=sid, name="legacy", is_active=True, protocol="http", mcp_path="/mcp", source="manual",
            requires_auth=True, health_status="unknown", health_fail_count=0, created_at=created, updated_at=created))
        for name, desc, schema in LEGACY:
            conn.execute(sa.insert(_tools).values(id=uuid.uuid4(), service_id=sid, name=name, description=desc,
                                                  input_schema=schema, created_at=created))
    eng.dispose()
    return str(sid)


def _legacy_mcp(name, desc, schema):
    return {"name": name, "description": desc, "inputSchema": json.loads(schema) if schema else None}


def _rows(url):
    eng = sa.create_engine(url)
    with eng.connect() as conn:
        tools = conn.execute(sa.text("SELECT name, current_hash, removed_at FROM mcp_tools")).all()
        versions = conn.execute(sa.text(
            "SELECT t.name, v.hash, v.state, v.decided_by, v.legacy_baseline, v.definition "
            "FROM mcp_tool_versions v JOIN mcp_tools t ON t.id = v.tool_id")).all()
    eng.dispose()
    return tools, versions


def test_tpin_m01_frozen_hash_copy_matches_the_application():
    import importlib.util

    from db.migrate import _resolve_alembic_dir
    path = next(Path(_resolve_alembic_dir(), "versions").glob(f"{REVISION}_*.py"))
    spec = importlib.util.spec_from_file_location("pin_migration", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    vectors = json.loads((Path(__file__).parent / "fixtures" / "tool_hash_vectors.json").read_text("utf-8"))
    for v in vectors["vectors"]:
        assert mod._canonical_json(v["tool"]) == v["canonical"], v["label"]


def test_tpin_m02_existing_tools_become_the_approved_baseline(scratch_db):  # noqa: F811
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, BEFORE)
    _seed_legacy(scratch_db)
    command.upgrade(cfg, "head")

    tools, versions = _rows(scratch_db)
    assert len(tools) == 3 and len(versions) == 3
    expected = {name: tool_hash(_legacy_mcp(name, desc, schema)) for name, desc, schema in LEGACY}
    assert {name: h for name, h, _ in tools} == expected
    for name, digest, state, decided_by, legacy, definition in versions:
        assert (digest, state, decided_by, bool(legacy)) == (expected[name], "approved", "upgrade", True)
        assert json.loads(definition)["name"] == name

    # downgrade and upgrade again: same baseline
    command.downgrade(cfg, BEFORE)
    eng = sa.create_engine(scratch_db)
    with eng.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM mcp_tools")).scalar() == 3
    eng.dispose()
    command.upgrade(cfg, "head")
    tools, versions = _rows(scratch_db)
    assert {name: h for name, h, _ in tools} == expected and len(versions) == 3


def test_tpin_m03_first_refresh_completes_the_baseline_once(scratch_db):  # noqa: F811
    from alembic import command

    from db.database import make_session, reset_engine
    from src.adapters import MCPToolAdapter

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, BEFORE)
    sid = _seed_legacy(scratch_db)
    command.upgrade(cfg, "head")
    reset_engine()

    search = _legacy_mcp(*LEGACY[0])
    ping = _legacy_mcp(*LEGACY[1])
    translate = _legacy_mcp(*LEGACY[2])
    db = make_session()
    try:
        # search: the server now also sends title / annotations, same description and schema -> still approved
        # ping: its description changed while MCP Gate was not looking -> pending
        # 翻譯: identical -> the baseline version itself
        MCPToolAdapter.sync_tools(db, sid, [
            {**search, "title": "Search", "annotations": {"readOnlyHint": True}},
            {**ping, "description": "now different"},
            translate,
        ])
        tools = {t.name: t for t in MCPToolAdapter.get_by_service(db, sid)}
        assert tools["search"].state == "approved" and len(tools["search"].versions) == 2
        completed = tools["search"].current_version
        assert completed.decided_by == "upgrade" and completed.legacy_baseline is False
        assert tools["ping"].state == "pending"
        assert tools["翻譯"].state == "approved" and len(tools["翻譯"].versions) == 1
        assert not any(v.legacy_baseline for t in tools.values() for v in t.versions)

        # the completion happens once: a later title change is a change to review
        MCPToolAdapter.sync_tools(db, sid, [{**search, "title": "Search v2", "annotations": {"readOnlyHint": True}},
                                            ping, translate])
        db.expire_all()
        tools = {t.name: t for t in MCPToolAdapter.get_by_service(db, sid)}
        assert tools["search"].state == "pending"
        assert tools["ping"].state == "approved"      # back to its baseline definition
    finally:
        db.close()
        reset_engine()
