"""Test foundation.

By default each test gets its own temporary SQLite file, so the suite has zero external dependencies.

Set ``TEST_DATABASE_URL=postgresql://user:pass@host:port/dbname`` to run the same suite against PostgreSQL instead.
That database is **wiped**: the schema is dropped and recreated once per session, and every table is truncated
before each test. Point it at a throwaway database, never at a real one.
"""

import base64
import hashlib
import os
import secrets
import sys
import tempfile
from pathlib import Path

import pytest

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Tests do not read .env / data/secrets.json: fixed keys and a separate secrets file
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-not-for-production")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-not-for-production")
os.environ["MCP_GATE_SECRETS_FILE"] = os.path.join(tempfile.gettempdir(), "mcp-gate-test-secrets.json")
# First-run setup needs the one-time token (src/identity/setup_token.py); tests pin it
SETUP_TOKEN = "test-setup-token-not-for-production"
os.environ["MCP_GATE_SETUP_TOKEN"] = SETUP_TOKEN

# Empty means SQLite (the default); otherwise a PostgreSQL URL the suite may wipe at will
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "").strip()

OWNER_EMAIL = "owner@example.com"
OWNER_PASSWORD = "owner-password-123"


@pytest.fixture(scope="session", autouse=True)
def _base_config():
    from src.config import Config
    from src.config.model import ConfigModel, DatabaseConfig, LoggingConfig, OAuthConfig, RateLimitConfig

    Config.set_model(ConfigModel(
        database=DatabaseConfig(url="sqlite://"),
        oauth=OAuthConfig(issuer="http://testserver", signing_key_bits=2048, access_expire_minutes=5,
                          refresh_expire_days=1, auth_code_ttl_seconds=60),
        rate_limit=RateLimitConfig(enabled=False),
        logging=LoggingConfig(level="WARNING"),
    ))
    yield


def using_postgres() -> bool:
    return bool(TEST_DATABASE_URL)


def _terminate_other_connections(conn) -> None:
    """Kill connections a previous test leaked (an open transaction would block TRUNCATE / DROP forever)."""
    from sqlalchemy import text

    conn.execute(text(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        "WHERE datname = current_database() AND pid <> pg_backend_pid()"
    ))


@pytest.fixture(scope="session")
def _pg_schema():
    """PostgreSQL only: rebuild the public schema from the models once per session."""
    if not using_postgres():
        yield None
        return
    from sqlalchemy import create_engine, text

    from db import models  # noqa: F401
    from db.database import Base

    eng = create_engine(TEST_DATABASE_URL, isolation_level="AUTOCOMMIT")
    try:
        with eng.connect() as conn:
            _terminate_other_connections(conn)
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        Base.metadata.create_all(bind=eng)
        yield eng
    finally:
        eng.dispose()


def _truncate_all(pg_engine) -> None:
    from sqlalchemy import text

    from db.database import Base

    tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with pg_engine.connect() as conn:
        _terminate_other_connections(conn)
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest.fixture
def db_url(tmp_path, _pg_schema):
    if _pg_schema is not None:
        _truncate_all(_pg_schema)
        return TEST_DATABASE_URL
    return f"sqlite:///{tmp_path / 'test.db'}"


@pytest.fixture
def engine(db_url):
    """A separate SQLite file per test (or a truncated PostgreSQL schema); the schema comes straight from
    create_all (tests/test_schema_drift.py checks that the migrations produce the same schema)."""
    from db.database import reset_engine, get_engine, Base
    from src.config import Config
    from src.utils.crypto import reset_crypto

    Config.get_config_model().database.url = db_url
    reset_engine()
    reset_crypto()
    eng = get_engine()
    from db import models  # noqa: F401
    if not using_postgres():
        Base.metadata.create_all(bind=eng)
    yield eng
    reset_engine()


@pytest.fixture
def db_session(engine):
    from db.database import make_session

    session = make_session()
    yield session
    session.close()


@pytest.fixture
def seeded(engine):
    from db import seed_database
    from db.database import make_session
    from src.oauth.signing_keys import ensure_active_signing_key

    db = make_session()
    try:
        seed_database(db)
        ensure_active_signing_key(db)
    finally:
        db.close()


@pytest.fixture
def app(seeded):
    from main import create_app

    return create_app()


def make_console_client(app, **kwargs):
    """A TestClient that behaves like the console SPA with respect to the session binding (H-04): it keeps the
    ``session_binding`` a login / setup / password-change response returns and sends it as ``X-Session-Binding``
    on every later request (and as a WebSocket subprotocol), exactly as the SPA does from localStorage."""
    from fastapi.testclient import TestClient

    from src.identity.session import SESSION_BINDING_HEADER, WS_PROTOCOL

    class ConsoleTestClient(TestClient):
        def request(self, method, url, *args, **kw):
            response = super().request(method, url, *args, **kw)
            if response.headers.get("content-type", "").startswith("application/json"):
                try:
                    body = response.json()
                except ValueError:
                    body = None
                if isinstance(body, dict) and body.get("session_binding"):
                    self.headers[SESSION_BINDING_HEADER] = body["session_binding"]
            return response

        def websocket_connect(self, url, subprotocols=None, **kw):
            binding = self.headers.get(SESSION_BINDING_HEADER)
            if subprotocols is None and binding:
                subprotocols = [WS_PROTOCOL, f"{WS_PROTOCOL}.binding.{binding}"]
            return super().websocket_connect(url, subprotocols=subprotocols, **kw)

    return ConsoleTestClient(app, base_url="http://testserver", **kwargs)


@pytest.fixture
def client(app):
    """Unauthenticated TestClient (does not trigger lifespan, avoiding the scheduler / docker)."""
    with make_console_client(app) as c:
        yield c


@pytest.fixture
def owner_client(client):
    """Client that has completed /setup and logged in (cookies are kept automatically)."""
    r = client.post("/api/session/setup", json={"setup_token": SETUP_TOKEN, "email": OWNER_EMAIL, "password": OWNER_PASSWORD, "username": "owner"})
    assert r.status_code == 200, r.text
    return client


@pytest.fixture
def service(owner_client):
    r = owner_client.post("/api/services", json={
        "name": "demo-mcp", "host": "127.0.0.1", "port": 8123, "protocol": "http", "mcp_path": "/mcp",
        "description": "demo",
    })
    assert r.status_code == 201, r.text
    return r.json()


def make_pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge
