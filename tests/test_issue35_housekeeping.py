"""#35 housekeeping: bcrypt off the event loop, audited scheduled purges, single-process warning, model/migration
default alignment and migration downgrades that survive data the newer schema allows."""

import asyncio
from datetime import timedelta

import bcrypt
import pytest
from sqlalchemy import create_engine, text

from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD, SETUP_TOKEN


# ---------------------------------------------------------------------------
# bcrypt runs in a worker thread, never on the event loop
# ---------------------------------------------------------------------------
def _on_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


@pytest.fixture
def bcrypt_calls(monkeypatch):
    calls = []
    real_hashpw, real_checkpw = bcrypt.hashpw, bcrypt.checkpw

    def hashpw(*a, **kw):
        calls.append(("hashpw", _on_event_loop()))
        return real_hashpw(*a, **kw)

    def checkpw(*a, **kw):
        calls.append(("checkpw", _on_event_loop()))
        return real_checkpw(*a, **kw)

    monkeypatch.setattr(bcrypt, "hashpw", hashpw)
    monkeypatch.setattr(bcrypt, "checkpw", checkpw)
    return calls


def test_setup_login_and_password_change_hash_off_the_event_loop(client, bcrypt_calls):
    r = client.post("/api/session/setup", json={"setup_token": SETUP_TOKEN, "email": OWNER_EMAIL, "password": OWNER_PASSWORD, "username": "owner"})
    assert r.status_code == 200, r.text
    r = client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": "wrong-password"})
    assert r.status_code == 401
    r = client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    assert r.status_code == 200
    r = client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                       "new_password": "another-password-456"})
    assert r.status_code == 200, r.text

    kinds = {kind for kind, _ in bcrypt_calls}
    assert kinds == {"hashpw", "checkpw"}
    assert not any(on_loop for _, on_loop in bcrypt_calls), bcrypt_calls


# ---------------------------------------------------------------------------
# Scheduled purges leave an audit record
# ---------------------------------------------------------------------------
def test_audit_log_purge_is_audited(db_session):
    from db.models import AuditLog, local_now
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    db_session.add(AuditLog(action="admin_login", resource_type="admin", status="success", actor_type="admin",
                            created_at=local_now() - timedelta(days=400)))
    db_session.commit()

    sched = CleanupScheduler()
    assert asyncio.run(sched._cleanup_old_audit_logs()) == 1

    db_session.expire_all()
    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    entry = rows[0]
    assert entry.action == "cleanup_expired"
    assert entry.actor_type == "system"
    assert entry.resource_id == "old_audit_logs"
    assert '"deleted": 1' in entry.details


def test_purge_that_deletes_nothing_is_not_audited(db_session):
    from db.models import AuditLog
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    assert asyncio.run(CleanupScheduler()._cleanup_oauth()) == 0
    assert db_session.query(AuditLog).count() == 0


# ---------------------------------------------------------------------------
# Single-process warning
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("env, warned", [
    ({}, False),
    ({"WEB_CONCURRENCY": "1"}, False),
    ({"WEB_CONCURRENCY": "4"}, True),
    ({"UVICORN_WORKERS": "2"}, True),
    ({"UVICORN_WORKERS": "abc"}, False),
])
def test_multiple_workers_warning(env, warned):
    from main import warn_if_multiple_workers

    assert warn_if_multiple_workers(env) is warned


# ---------------------------------------------------------------------------
# Model and migration agree on require_pkce's server default
# ---------------------------------------------------------------------------
def test_require_pkce_has_server_default():
    from db.models import OAuthClient

    default = OAuthClient.__table__.c.require_pkce.server_default
    assert default is not None


# ---------------------------------------------------------------------------
# Downgrades that re-add NOT NULL clean up rows the newer schema allowed
# ---------------------------------------------------------------------------
@pytest.fixture
def migrated_db(tmp_path, monkeypatch):
    """A temp SQLite database migrated to head through alembic (never data/)."""
    from alembic import command
    from alembic.config import Config as AlembicConfig

    from db.database import reset_engine
    from db.migrate import _resolve_alembic_dir
    from src.config import Config

    url = f"sqlite:///{tmp_path / 'migrations.db'}"
    # env.py loads MCP_GATE_CONFIG_DIR; point it nowhere so it keeps the in-memory test config (and our URL)
    monkeypatch.setenv("MCP_GATE_CONFIG_DIR", str(tmp_path / "missing-config"))
    db_cfg = Config.get_database_config()
    saved_url = db_cfg.url
    db_cfg.url = url
    reset_engine()

    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(_resolve_alembic_dir()))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    engine = create_engine(url)
    try:
        yield cfg, engine
    finally:
        engine.dispose()
        db_cfg.url = saved_url
        reset_engine()


def test_downgrade_with_classic_and_orphan_rows(migrated_db):
    from alembic import command

    cfg, engine = migrated_db
    now = "2026-01-01 00:00:00"
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO admin_users (id, email, username, auth_provider, is_active, created_at) "
            "VALUES ('00000000000000000000000000000001', 'a@example.com', 'a', 'local', 1, :now)"
        ), {"now": now})
        conn.execute(text(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types, "
            "token_endpoint_auth_method, created_via, is_approved, is_active, created_at, updated_at) "
            "VALUES ('c1', 'Classic', '[]', '[]', '[\"code\"]', 'client_secret_basic', 'manual', 1, 1, :now, :now)"
        ), {"now": now})
        # require_pkce was omitted above: the server default must fill it in
        assert conn.execute(text("SELECT require_pkce FROM oauth_clients")).scalar() in (1, True)
        for rid, challenge in (("with-pkce", "abc"), ("classic", None)):
            conn.execute(text(
                "INSERT INTO oauth_authorization_requests (id, client_id, redirect_uri, code_challenge, "
                "code_challenge_method, created_at, expires_at) VALUES (:id, 'c1', 'http://x/cb', :ch, :m, :now, :now)"
            ), {"id": rid, "ch": challenge, "m": "S256" if challenge else None, "now": now})
            conn.execute(text(
                "INSERT INTO oauth_authorization_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, "
                "code_challenge_method, expires_at, created_at) "
                "VALUES (:id, 'c1', '00000000000000000000000000000001', 'http://x/cb', :ch, :m, :now, :now)"
            ), {"id": rid, "ch": challenge, "m": "S256" if challenge else None, "now": now})
        for jti, client_id in (("kept", "c1"), ("orphan", None)):
            conn.execute(text(
                "INSERT INTO oauth_tokens (jti, kind, client_id, sub, issued_at, expires_at, use_count) "
                "VALUES (:jti, 'access', :cid, 'u', :now, :now, 0)"
            ), {"jti": jti, "cid": client_id, "now": now})

    command.downgrade(cfg, "8813dec38e2b")

    with engine.connect() as conn:
        assert [r[0] for r in conn.execute(text("SELECT jti FROM oauth_tokens"))] == ["kept"]
        assert [r[0] for r in conn.execute(text("SELECT id FROM oauth_authorization_requests"))] == ["with-pkce"]
        assert [r[0] for r in conn.execute(text("SELECT code_hash FROM oauth_authorization_codes"))] == ["with-pkce"]

    # And back up again
    command.upgrade(cfg, "head")
