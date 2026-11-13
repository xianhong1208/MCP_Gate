"""The last pre-rename names are gone (#53): the SQLite file moves to mcp_gate.db, the built-in clients are renamed
by a migration, and the old environment variables are no longer read."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, text

from tests.test_schema_drift import _alembic_config, scratch_db  # noqa: F401 - fixture (SQLite or a PG schema)

OLD_CONSOLE, NEW_CONSOLE = "mcp-center-console", "mcp-gate-console"
OLD_SCANNER, NEW_SCANNER = "mcp-center-scanner", "mcp-gate-scanner"
BEFORE = "c9d1e3f5a7b9"
RENAME = "a1c3e5f7b9d1"


# ---------------------------------------------------------------------------
# the SQLite file moves on startup
# ---------------------------------------------------------------------------
def _write(path, content: bytes) -> None:
    path.write_bytes(content)


def test_old_file_and_its_wal_move_to_the_new_name(tmp_path):
    from db.database import move_legacy_sqlite_file

    for suffix, body in (("", b"db"), ("-wal", b"wal"), ("-shm", b"shm")):
        _write(tmp_path / f"mcp_center.db{suffix}", body)

    assert move_legacy_sqlite_file(f"sqlite:///{tmp_path / 'mcp_gate.db'}") is True

    for suffix, body in (("", b"db"), ("-wal", b"wal"), ("-shm", b"shm")):
        assert (tmp_path / f"mcp_gate.db{suffix}").read_bytes() == body
        assert not (tmp_path / f"mcp_center.db{suffix}").exists()


def test_a_real_wal_survives_the_move(tmp_path):
    """Committed rows that live only in the WAL (no checkpoint yet) are still there under the new name."""
    import sqlite3

    from db.database import move_legacy_sqlite_file

    old = tmp_path / "mcp_center.db"
    writer = sqlite3.connect(old)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE t (v TEXT)")
    writer.execute("INSERT INTO t VALUES ('kept')")
    writer.commit()
    # copy the three files as a crashed server would leave them (the open connection would checkpoint on close)
    crashed = tmp_path / "crashed"
    crashed.mkdir()
    for suffix in ("", "-wal", "-shm"):
        (crashed / f"mcp_center.db{suffix}").write_bytes((tmp_path / f"mcp_center.db{suffix}").read_bytes())
    writer.close()
    assert (crashed / "mcp_center.db-wal").stat().st_size > 0

    assert move_legacy_sqlite_file(f"sqlite:///{crashed / 'mcp_gate.db'}") is True
    reader = sqlite3.connect(crashed / "mcp_gate.db")
    try:
        assert reader.execute("SELECT v FROM t").fetchall() == [("kept",)]
    finally:
        reader.close()


def test_an_existing_new_file_is_never_overwritten(tmp_path):
    from db.database import move_legacy_sqlite_file

    _write(tmp_path / "mcp_center.db", b"old")
    _write(tmp_path / "mcp_gate.db", b"new")

    assert move_legacy_sqlite_file(f"sqlite:///{tmp_path / 'mcp_gate.db'}") is False
    assert (tmp_path / "mcp_gate.db").read_bytes() == b"new"
    assert (tmp_path / "mcp_center.db").read_bytes() == b"old"


def test_a_leftover_new_wal_next_to_an_old_wal_stops_the_move(tmp_path):
    """Two WALs would leave no right answer; nothing is moved and the old database stays usable."""
    from db.database import move_legacy_sqlite_file

    _write(tmp_path / "mcp_center.db", b"old")
    _write(tmp_path / "mcp_center.db-wal", b"old-wal")
    _write(tmp_path / "mcp_gate.db-wal", b"stray")

    assert move_legacy_sqlite_file(f"sqlite:///{tmp_path / 'mcp_gate.db'}") is False
    assert not (tmp_path / "mcp_gate.db").exists()
    assert (tmp_path / "mcp_center.db-wal").read_bytes() == b"old-wal"


def test_an_interrupted_move_is_finished(tmp_path):
    """The WAL was moved before the database file when the process died; the next start moves the rest."""
    from db.database import move_legacy_sqlite_file

    _write(tmp_path / "mcp_center.db", b"db")
    _write(tmp_path / "mcp_gate.db-wal", b"wal")

    assert move_legacy_sqlite_file(f"sqlite:///{tmp_path / 'mcp_gate.db'}") is True
    assert (tmp_path / "mcp_gate.db").read_bytes() == b"db"
    assert (tmp_path / "mcp_gate.db-wal").read_bytes() == b"wal"


def test_an_explicit_old_url_keeps_its_file(tmp_path):
    from db.database import move_legacy_sqlite_file

    _write(tmp_path / "mcp_center.db", b"old")

    assert move_legacy_sqlite_file(f"sqlite:///{tmp_path / 'mcp_center.db'}") is False
    assert (tmp_path / "mcp_center.db").read_bytes() == b"old"
    assert not (tmp_path / "mcp_gate.db").exists()


def test_another_file_name_is_left_alone(tmp_path):
    from db.database import move_legacy_sqlite_file

    _write(tmp_path / "mcp_center.db", b"old")

    assert move_legacy_sqlite_file(f"sqlite:///{tmp_path / 'other.db'}") is False
    assert (tmp_path / "mcp_center.db").exists()


def test_postgresql_and_memory_urls_are_left_alone(tmp_path, monkeypatch):
    from db.database import move_legacy_sqlite_file

    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    _write(tmp_path / "data" / "mcp_center.db", b"old")
    _write(tmp_path / "mcp_center.db", b"old")  # where a database named "mcp_gate.db" would resolve as a path

    assert move_legacy_sqlite_file("postgresql://u:p@localhost/mcp_gate.db") is False
    assert (tmp_path / "mcp_center.db").exists()
    assert move_legacy_sqlite_file("sqlite://") is False
    assert move_legacy_sqlite_file("sqlite:///:memory:") is False
    assert (tmp_path / "data" / "mcp_center.db").exists()


def test_the_default_url_moves_the_old_file_when_the_engine_starts(tmp_path, monkeypatch):
    """get_engine() moves the file before it opens the database (the relative default resolves against the cwd)."""
    from db.database import get_engine, reset_engine
    from src.config import Config
    from src.config.model import DatabaseConfig

    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    old = sqlite3_db(tmp_path / "data" / "mcp_center.db")
    db_cfg = Config.get_database_config()
    saved = db_cfg.url
    db_cfg.url = DatabaseConfig().url
    assert db_cfg.url == "sqlite:///data/mcp_gate.db"
    reset_engine()
    try:
        with get_engine().connect() as conn:
            assert conn.execute(text("SELECT v FROM t")).scalar() == "here"
    finally:
        db_cfg.url = saved
        reset_engine()
    assert not old.exists()
    assert (tmp_path / "data" / "mcp_gate.db").exists()


def test_migrating_from_the_cli_moves_the_old_file_first(tmp_path, monkeypatch):
    """alembic's env.py opens its own engine: it must move the file too, or it would migrate a new empty one."""
    from alembic import command

    from db.database import reset_engine
    from src.config import Config

    monkeypatch.setenv("MCP_GATE_CONFIG_DIR", str(tmp_path / "missing-config"))
    sqlite3_db(tmp_path / "mcp_center.db")
    url = f"sqlite:///{tmp_path / 'mcp_gate.db'}"
    db_cfg = Config.get_database_config()
    saved = db_cfg.url
    db_cfg.url = url
    reset_engine()
    try:
        command.upgrade(_alembic_config(url), "head")
    finally:
        db_cfg.url = saved
        reset_engine()
    assert not (tmp_path / "mcp_center.db").exists()
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            assert conn.execute(text("SELECT v FROM t")).scalar() == "here"
    finally:
        eng.dispose()


def sqlite3_db(path):
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t VALUES ('here')")
    conn.commit()
    conn.close()
    return path


# ---------------------------------------------------------------------------
# the built-in clients are renamed by migration a1c3e5f7b9d1
# ---------------------------------------------------------------------------
def _insert_client(conn, client_id: str, name: str, created_via: str = "system") -> None:
    now = datetime(2026, 1, 1)
    conn.execute(text(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types, "
        "token_endpoint_auth_method, created_via, is_approved, is_active, created_at, updated_at) "
        "VALUES (:id, :name, '[]', '[\"personal_access_token\"]', '[]', 'none', :via, :t, :t2, :now, :now)"
    ), {"id": client_id, "name": name, "via": created_via, "t": True, "t2": True, "now": now})


def _references(conn, client_id: str) -> dict:
    counts = {}
    for table, column in (("oauth_authorization_requests", "client_id"), ("oauth_authorization_codes", "client_id"),
                          ("oauth_tokens", "client_id"), ("oauth_consents", "client_id"),
                          ("token_usage", "client_id"), ("audit_logs", "resource_id"), ("audit_logs", "actor_id"),
                          ("oauth_clients", "client_id")):
        counts[f"{table}.{column}"] = conn.execute(
            text(f"SELECT COUNT(*) FROM {table} WHERE {column} = :id"), {"id": client_id}).scalar()
    return counts


def _seed_old_world(conn) -> str:
    """The two built-in clients under their old ids, one unrelated client, and a row of every kind naming them."""
    now = datetime(2026, 1, 1)
    later = now + timedelta(days=30)
    user_id = uuid.uuid4().hex
    conn.execute(text(
        "INSERT INTO admin_users (id, email, username, auth_provider, is_active, created_at) "
        "VALUES (:id, 'o@example.com', 'o', 'local', :t, :now)"
    ), {"id": user_id, "t": True, "now": now})
    _insert_client(conn, OLD_CONSOLE, "MCP Center Console")  # seeded before the 2026-11-02 rename
    _insert_client(conn, OLD_SCANNER, "MCP Gate Scanner")
    _insert_client(conn, "mcpc_other", "Someone else", created_via="dcr")
    for cid in (OLD_CONSOLE, "mcpc_other"):
        conn.execute(text(
            "INSERT INTO oauth_tokens (jti, kind, client_id, client_name_snapshot, user_id, sub, audience, scope, "
            "label, issued_at, expires_at, use_count) VALUES (:jti, 'pat', :cid, :snap, :uid, :uid, 'http://x/mcp', "
            "'mcp:tools:read', 'l', :now, :later, 0)"
        ), {"jti": f"jti-{cid}", "cid": cid, "uid": user_id, "now": now, "later": later,
            "snap": "MCP Center Console" if cid == OLD_CONSOLE else "Someone else"})
        conn.execute(text(
            "INSERT INTO token_usage (id, jti, event, grant_type, client_id, sub, success, used_at, count) "
            "VALUES (:id, :jti, 'issued', 'personal_access_token', :cid, :uid, :t, :now, 1)"
        ), {"id": uuid.uuid4().hex, "jti": f"jti-{cid}", "cid": cid, "uid": user_id, "t": True, "now": now})
        conn.execute(text(
            "INSERT INTO oauth_consents (id, user_id, client_id, audience, scope, granted_at) "
            "VALUES (:id, :uid, :cid, 'http://x/mcp', 'mcp:tools:read', :now)"
        ), {"id": uuid.uuid4().hex, "uid": user_id, "cid": cid, "now": now})
        conn.execute(text(
            "INSERT INTO oauth_authorization_requests (id, client_id, redirect_uri, created_at, expires_at) "
            "VALUES (:id, :cid, 'http://x/cb', :now, :later)"
        ), {"id": f"req-{cid}", "cid": cid, "now": now, "later": later})
        conn.execute(text(
            "INSERT INTO oauth_authorization_codes (code_hash, client_id, user_id, redirect_uri, expires_at, "
            "created_at) VALUES (:h, :cid, :uid, 'http://x/cb', :later, :now)"
        ), {"h": f"code-{cid}", "cid": cid, "uid": user_id, "now": now, "later": later})
    conn.execute(text(
        "INSERT INTO audit_logs (id, action, resource_type, resource_id, actor_type, actor_id, status, created_at) "
        "VALUES (:id, 'oauth_token_issue', 'oauth_client', :cid, 'oauth_client', :cid, 'success', :now)"
    ), {"id": uuid.uuid4().hex, "cid": OLD_SCANNER, "now": now})
    return user_id


ONE_OF_EACH = {
    "oauth_authorization_requests.client_id": 1, "oauth_authorization_codes.client_id": 1,
    "oauth_tokens.client_id": 1, "oauth_consents.client_id": 1, "token_usage.client_id": 1,
    "audit_logs.resource_id": 0, "audit_logs.actor_id": 0, "oauth_clients.client_id": 1,
}
NONE = {k: 0 for k in ONE_OF_EACH}
SCANNER_ROWS = {**NONE, "audit_logs.resource_id": 1, "audit_logs.actor_id": 1, "oauth_clients.client_id": 1}


def test_migration_renames_the_builtin_clients_and_everything_naming_them(scratch_db):  # noqa: F811
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, BEFORE)
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            _seed_old_world(conn)
            assert _references(conn, OLD_CONSOLE) == ONE_OF_EACH
        command.upgrade(cfg, "head")
        with eng.connect() as conn:
            assert _references(conn, OLD_CONSOLE) == NONE
            assert _references(conn, OLD_SCANNER) == NONE
            assert _references(conn, NEW_CONSOLE) == ONE_OF_EACH
            assert _references(conn, NEW_SCANNER) == SCANNER_ROWS
            assert _references(conn, "mcpc_other") == ONE_OF_EACH  # untouched
            row = conn.execute(text(
                "SELECT client_name, created_via, grant_types FROM oauth_clients WHERE client_id = :id"
            ), {"id": NEW_CONSOLE}).one()
            assert tuple(row) == ("MCP Gate Console", "system", '["personal_access_token"]')
            assert conn.execute(text("SELECT client_name_snapshot FROM oauth_tokens WHERE client_id = :id"),
                                {"id": NEW_CONSOLE}).scalar() == "MCP Gate Console"
            assert conn.execute(text("SELECT client_name FROM oauth_clients WHERE client_id = :id"),
                                {"id": NEW_SCANNER}).scalar() == "MCP Gate Scanner"
            assert conn.execute(text("SELECT COUNT(*) FROM oauth_clients")).scalar() == 3

        command.downgrade(cfg, BEFORE)
        with eng.connect() as conn:
            assert _references(conn, OLD_CONSOLE) == ONE_OF_EACH
            assert _references(conn, OLD_SCANNER) == SCANNER_ROWS
            assert _references(conn, NEW_CONSOLE) == NONE
            assert _references(conn, NEW_SCANNER) == NONE
    finally:
        eng.dispose()


def test_migration_merges_into_a_client_seeded_under_the_new_id(scratch_db):  # noqa: F811
    """A newer server started with --no-migrate seeds the new ids next to the old ones: the old rows' references
    move to the new client and the old client goes."""
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, BEFORE)
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            _seed_old_world(conn)
            _insert_client(conn, NEW_CONSOLE, "MCP Gate Console")
        command.upgrade(cfg, "head")
        with eng.connect() as conn:
            assert _references(conn, OLD_CONSOLE) == NONE
            assert _references(conn, NEW_CONSOLE) == ONE_OF_EACH
            assert conn.execute(text("SELECT COUNT(*) FROM oauth_clients")).scalar() == 3
    finally:
        eng.dispose()


def test_migration_on_an_install_without_the_old_clients_is_a_no_op(scratch_db):  # noqa: F811
    from alembic import command

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, "head")
    eng = create_engine(scratch_db)
    try:
        with eng.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM oauth_clients")).scalar() == 0
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# tokens signed before the rename
# ---------------------------------------------------------------------------
def _old_pat(seeded_service_id: str, *, client_id: str = OLD_CONSOLE) -> str:
    """A personal access token as MCP Gate signed it before the rename: client_id claim = the old console id."""
    from db.database import make_session
    from db.models import AdminUser, Service
    from src.oauth import service as oauth_service

    db = make_session()
    try:
        user = db.query(AdminUser).first()
        svc = db.get(Service, uuid.UUID(seeded_service_id))
        token, _, _ = oauth_service.issue_access_token(
            db, sub=str(user.id), client_id=client_id, scope="mcp:tools:read", audience=svc.effective_audience,
            service=svc, user=user, kind="pat", ttl_seconds=3600, record=False,
        )
        return token
    finally:
        db.close()


def test_a_token_signed_before_the_rename_still_belongs_to_the_console(owner_client, service):
    token = _old_pat(service["id"])
    intro = owner_client.post("/oauth/introspect", data={"token": token, "client_id": NEW_CONSOLE}).json()
    assert intro["active"] is True
    assert intro["client_id"] == OLD_CONSOLE


def test_the_old_id_is_no_alias_for_any_other_client(owner_client, service):
    """Only the old built-in ids map to their renamed clients: a token claiming the console is not the scanner's."""
    token = _old_pat(service["id"], client_id=OLD_SCANNER)
    intro = owner_client.post("/oauth/introspect", data={"token": token, "client_id": NEW_CONSOLE}).json()
    assert intro == {"active": False}


def test_new_tokens_carry_the_new_ids(owner_client, service):
    import jwt

    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 1,
                                                               "label": "new"})
    assert r.status_code == 201, r.text
    assert jwt.decode(r.json()["access_token"], options={"verify_signature": False})["client_id"] == NEW_CONSOLE

    from db.database import make_session
    from db.models import Service
    from src.oauth import service as oauth_service

    db = make_session()
    try:
        scanner = oauth_service.mint_scanner_token(db, db.get(Service, uuid.UUID(service["id"])))
    finally:
        db.close()
    claims = jwt.decode(scanner, options={"verify_signature": False})
    assert claims["client_id"] == claims["sub"] == NEW_SCANNER


# ---------------------------------------------------------------------------
# the pre-rename environment variables are no longer read
# ---------------------------------------------------------------------------
def test_old_secrets_file_variable_is_ignored(tmp_path, monkeypatch):
    from src.utils import secrets_store

    monkeypatch.delenv("MCP_GATE_SECRETS_FILE", raising=False)
    monkeypatch.setenv("MCP_" + "CENTER_SECRETS_FILE", str(tmp_path / "old.json"))
    assert secrets_store._store_path() == secrets_store._DEFAULT_DIR / secrets_store.FILE_NAME


@pytest.mark.parametrize("module", ["db/migrate.py", "alembic/env.py"])
def test_old_config_variable_is_not_read(module):
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / module).read_text(encoding="utf-8")
    assert "MCP_" + "CENTER" not in source
    assert "default_config_dir()" in source
