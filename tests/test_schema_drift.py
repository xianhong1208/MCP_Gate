"""The Alembic migrations and the ORM models describe the same schema.

The rest of the suite builds its tables with ``Base.metadata.create_all``, so a model change without a matching
migration would pass every other test and only break real deployments (which are migrated, not created). This test
migrates an empty database to head and asks Alembic's autogenerate comparison for the difference.

It runs on SQLite by default and on PostgreSQL when ``TEST_DATABASE_URL`` is set; there it works in a scratch schema
of that database so it never collides with the tables the other tests use. Neither path touches ``data/``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, make_url, text

from tests.conftest import TEST_DATABASE_URL, using_postgres


@pytest.fixture
def scratch_db(tmp_path, monkeypatch):
    """Yield the URL of an empty database (SQLite file, or a throwaway PostgreSQL schema) and point the app config
    at it for the duration of the test."""
    from db.database import reset_engine
    from src.config import Config

    # alembic/env.py loads MCP_GATE_CONFIG_DIR when it can; point it nowhere so it keeps the in-memory test config
    monkeypatch.setenv("MCP_GATE_CONFIG_DIR", str(tmp_path / "missing-config"))

    schema = None
    if using_postgres():
        schema = f"drift_{uuid.uuid4().hex[:12]}"
        url = make_url(TEST_DATABASE_URL).update_query_dict({"options": f"-csearch_path={schema}"})
        url = url.render_as_string(hide_password=False)
        admin = create_engine(TEST_DATABASE_URL, isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    else:
        url = f"sqlite:///{tmp_path / 'drift.db'}"

    db_cfg = Config.get_database_config()
    saved_url = db_cfg.url
    db_cfg.url = url
    reset_engine()
    try:
        yield url
    finally:
        db_cfg.url = saved_url
        reset_engine()
        if schema:
            with admin.connect() as conn:
                conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            admin.dispose()


def _alembic_config(url: str):
    from alembic.config import Config as AlembicConfig

    from db.migrate import _resolve_alembic_dir

    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_resolve_alembic_dir()))
    # ConfigParser interpolation: a percent-encoded password must not be read as %(name)s
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def _diff(url: str) -> list:
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from db import models  # noqa: F401
    from db.database import Base

    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={"compare_type": True, "compare_server_default": True})
            return compare_metadata(ctx, Base.metadata)
    finally:
        eng.dispose()


def test_migrations_match_models(scratch_db):
    from alembic import command

    command.upgrade(_alembic_config(scratch_db), "head")

    diff = _diff(scratch_db)
    assert diff == [], "models and migrations disagree; add a migration:\n" + "\n".join(map(repr, diff))


def test_full_downgrade_and_upgrade_round_trip(scratch_db):
    """Every migration can be undone and replayed on an empty database, ending at the same schema."""
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")

    assert _diff(scratch_db) == []
