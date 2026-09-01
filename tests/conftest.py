"""Test foundation: each test gets its own temporary SQLite file; zero external dependencies."""

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
os.environ["MCP_CENTER_SECRETS_FILE"] = os.path.join(tempfile.gettempdir(), "mcp-center-test-secrets.json")

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


@pytest.fixture
def db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'test.db'}"


@pytest.fixture
def engine(db_url):
    """A separate SQLite file per test; the schema comes straight from create_all (migrations have their own
    tests)."""
    from db.database import reset_engine, get_engine, Base
    from src.config import Config
    from src.utils.crypto import reset_crypto

    Config.get_config_model().database.url = db_url
    reset_engine()
    reset_crypto()
    eng = get_engine()
    from db import models  # noqa: F401
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


@pytest.fixture
def client(app):
    """Unauthenticated TestClient (does not trigger lifespan, avoiding the scheduler / docker)."""
    from fastapi.testclient import TestClient

    with TestClient(app, base_url="http://testserver") as c:
        yield c


@pytest.fixture
def owner_client(client):
    """Client that has completed /setup and logged in (cookies are kept automatically)."""
    r = client.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD, "username": "owner"})
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
