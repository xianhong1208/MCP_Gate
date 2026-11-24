"""The tool access migration (#37): nothing changes for an existing deployment (every server keeps allowing
unscoped tools, no rule, no scope assignment), existing scope strings survive the move to TEXT both ways, and
existing scope names a challenge could not carry are reported, not changed."""

import logging
import uuid
from datetime import datetime

import sqlalchemy as sa

from tests.test_schema_drift import _alembic_config, scratch_db  # noqa: F401  (fixture)

BEFORE = "e3a5c7d9f1b3"
REVISION = "b5d7f9a1c3e6"
CREATED = datetime(2026, 11, 1, 12, 0, 0)
LONG_SCOPE = " ".join(f"s{i:03d}" for i in range(100))  # 499 characters: fits the old VARCHAR(512)


def _seed(url):
    eng = sa.create_engine(url)
    sid = uuid.uuid4()
    with eng.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO services (id, name, is_active, protocol, mcp_path, source, requires_auth, health_status, "
            "health_fail_count, created_at, updated_at) VALUES (:id, 'legacy', :t, 'http', '/mcp', 'manual', :t, "
            "'unknown', 0, :c, :c)"), {"id": sid.hex if url.startswith("sqlite") else str(sid), "t": True,
                                       "c": CREATED})
        conn.execute(sa.text("INSERT INTO oauth_scopes (name, description, is_default, created_at) "
                             "VALUES (:n, 'legacy', :f, :c)"), [{"n": n, "f": False, "c": CREATED}
                                                                for n in ("files:read", 'bad"name')])
        conn.execute(sa.text(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types, scope, "
            "token_endpoint_auth_method, require_pkce, created_via, is_approved, is_active, created_at, updated_at) "
            "VALUES ('c1', 'Legacy', '[]', '[]', '[\"code\"]', :s, 'none', :t, 'manual', :t, :t, :c, :c)"),
            {"s": LONG_SCOPE, "t": True, "c": CREATED})
    eng.dispose()


def _columns(url, table):
    eng = sa.create_engine(url)
    try:
        return {c["name"]: c for c in sa.inspect(eng).get_columns(table)}
    finally:
        eng.dispose()


def _scalar(url, sql):
    eng = sa.create_engine(url)
    try:
        with eng.connect() as conn:
            return conn.execute(sa.text(sql)).scalar()
    finally:
        eng.dispose()


def test_tamg_001_upgrade_keeps_every_server_as_it_was(scratch_db, caplog):  # noqa: F811
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, BEFORE)
    _seed(scratch_db)
    with caplog.at_level(logging.WARNING, logger="alembic.runtime.migration"):
        command.upgrade(cfg, REVISION)

    assert _scalar(scratch_db, "SELECT unscoped_tools FROM services") == "allow"
    assert _scalar(scratch_db, "SELECT policy_features FROM oauth_clients") is None
    assert _scalar(scratch_db, "SELECT scope FROM oauth_clients") == LONG_SCOPE
    assert _scalar(scratch_db, "SELECT count(*) FROM oauth_scopes WHERE title IS NULL") == 2
    for table in ("tool_scopes", "tool_access_rules", "user_groups", "user_group_members"):
        assert _scalar(scratch_db, f"SELECT count(*) FROM {table}") == 0
    for table in ("oauth_clients", "oauth_authorization_requests", "oauth_authorization_codes", "oauth_tokens",
                  "oauth_consents"):
        assert isinstance(_columns(scratch_db, table)["scope"]["type"], sa.Text), table
    warned = [r.getMessage() for r in caplog.records if "step-up challenge" in r.getMessage()]
    assert len(warned) == 1 and 'bad"name' in warned[0]

    # a scope longer than the old column now fits
    eng = sa.create_engine(scratch_db)
    with eng.begin() as conn:
        conn.execute(sa.text("UPDATE oauth_clients SET scope = :s"), {"s": "x" * 3000})
    eng.dispose()


def test_tamg_002_downgrade_and_upgrade_again(scratch_db):  # noqa: F811
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, BEFORE)
    _seed(scratch_db)
    command.upgrade(cfg, REVISION)
    command.downgrade(cfg, BEFORE)
    assert "unscoped_tools" not in _columns(scratch_db, "services")
    assert "policy_features" not in _columns(scratch_db, "oauth_clients")
    assert not isinstance(_columns(scratch_db, "oauth_clients")["scope"]["type"], sa.Text)
    assert _scalar(scratch_db, "SELECT scope FROM oauth_clients") == LONG_SCOPE
    eng = sa.create_engine(scratch_db)
    try:
        assert "tool_scopes" not in sa.inspect(eng).get_table_names()
    finally:
        eng.dispose()
    command.upgrade(cfg, REVISION)
    assert _scalar(scratch_db, "SELECT unscoped_tools FROM services") == "allow"
    assert _scalar(scratch_db, "SELECT scope FROM oauth_clients") == LONG_SCOPE


def test_tamg_003_frozen_charset_copy_matches_the_application():
    import importlib.util
    from pathlib import Path

    from db.migrate import _resolve_alembic_dir
    from src.tool_policy.validation import is_scope_token

    path = next(Path(_resolve_alembic_dir(), "versions").glob(f"{REVISION}_*.py"))
    spec = importlib.util.spec_from_file_location("access_migration", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for code in range(0, 256):
        ch = chr(code)
        assert bool(mod._SCOPE_TOKEN.match(ch)) is is_scope_token(ch), repr(ch)
