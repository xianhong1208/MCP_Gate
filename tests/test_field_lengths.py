"""Over-long values get a clean 4xx (input) or are shortened (text MCP Gate relays), never a database error.

SQLite does not enforce ``VARCHAR(n)``, PostgreSQL does: before these checks every case below stored the value
on SQLite and answered 500 on PostgreSQL (run the suite with TEST_DATABASE_URL to see it). The assertions hold
on both, so they also pin the behaviour on the default SQLite run.
"""

from tests.conftest import SETUP_TOKEN
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import pytest

from src.discovery import scanner as scanner_mod
from src.discovery.scanner import DiscoveredService, MCPToolInfo, MCPVerifyResult


def _too_long(r, field, limit, status=400):
    assert r.status_code == status, r.text
    body = r.json()
    detail = body.get("detail", body)
    assert detail["error"] == "validation.too_long", body
    assert detail["params"] == {"field": field, "max": limit}


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------
def test_clip_marks_the_cut_and_leaves_short_text_alone():
    from src.utils.field_limits import clip

    assert clip(None, 5) is None
    assert clip("abcde", 5) == "abcde"
    assert clip("abcdef", 5) == "abcd…"


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------
SERVICE = {"name": "svc", "host": "127.0.0.1", "port": 9100, "protocol": "http", "mcp_path": "/mcp"}


@pytest.mark.parametrize("field,value,limit", [
    ("name", "n" * 65, 64),
    ("host", "h" * 129, 128),
    ("tags", ["t" * 300, "u" * 300], 512),
    ("oauth_audience", "http://a.example/" + "p" * 300, 256),
    ("oauth_scopes", ["s" * 300, "r" * 300], 512),
])
def test_service_fields_longer_than_their_column(owner_client, service, field, value, limit):
    _too_long(owner_client.post("/api/services", json={**SERVICE, field: value}), field, limit)
    _too_long(owner_client.put(f"/api/services/{service['id']}", json={field: value}), field, limit)


def test_service_fields_at_the_limit_are_accepted(owner_client):
    r = owner_client.post("/api/services", json={**SERVICE, "name": "n" * 64, "tags": ["t" * 512]})
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "n" * 64


def test_long_static_token_is_stored_and_decrypts(owner_client, db_session):
    """A JWT bearer is easily longer than the ~740 bytes the old VARCHAR(1024) could hold once encrypted."""
    from src.adapters import ServiceAdapter
    from src.utils.crypto import decrypt_token

    token = "eyJ" + "a" * 1500
    r = owner_client.post("/api/services", json={**SERVICE, "auth_token": token})
    assert r.status_code == 201, r.text
    stored = ServiceAdapter.get_by_id(db_session, r.json()["id"])
    assert decrypt_token(stored.auth_token_encrypted) == token

    from src.api.routes import MAX_STATIC_TOKEN_LENGTH
    _too_long(owner_client.post("/api/services", json={**SERVICE, "port": 9101,
                                                         "auth_token": "x" * (MAX_STATIC_TOKEN_LENGTH + 1)}),
              "auth_token", MAX_STATIC_TOKEN_LENGTH)


# ---------------------------------------------------------------------------
# console account
# ---------------------------------------------------------------------------
def test_setup_rejects_long_email_and_username(client):
    _too_long(client.post("/api/session/setup", json={"setup_token": SETUP_TOKEN, "email": "a" * 120 + "@example.com",
                                                       "password": "owner-password-123"}), "email", 128)
    _too_long(client.post("/api/session/setup", json={"setup_token": SETUP_TOKEN, "email": "owner@example.com", "password": "owner-password-123",
                                                       "username": "u" * 65}), "username", 64)


def test_profile_rejects_long_username(owner_client):
    _too_long(owner_client.put("/api/session/me/profile", json={"username": "u" * 65}), "username", 64)
    assert owner_client.put("/api/session/me/profile", json={"username": "u" * 64}).status_code == 200


def test_failed_login_with_long_email_and_user_agent_is_audited(owner_client):
    r = owner_client.post("/api/session/login", json={"email": "x" * 300 + "@example.com", "password": "nope-nope"},
                          headers={"User-Agent": "ua" * 400})
    assert r.status_code == 400
    entry = next(e for e in owner_client.get("/api/audit/logs").json()["logs"] if e["status"] == "failure")
    assert len(entry["actor_name"]) == 128 and entry["actor_name"].endswith("…")
    assert len(entry["user_agent"]) <= 256


def test_external_login_shortens_a_long_display_name(seeded, db_session):
    from src.config import Config
    from src.identity import service as identity_service
    from src.identity.providers.base import ExternalIdentity

    identity_cfg = Config.get_config_model().identity
    saved = list(identity_cfg.allowed_emails)
    identity_cfg.allowed_emails = ["dev@example.com"]
    try:
        user = identity_service.login_external(db_session, ExternalIdentity(
            provider="github", sub="42", email="dev@example.com", email_verified=True, name="N" * 200))
    finally:
        identity_cfg.allowed_emails = saved
    assert len(user.username) == 64


# ---------------------------------------------------------------------------
# scopes
# ---------------------------------------------------------------------------
def test_scope_name_and_description_limits(owner_client, service):
    _too_long(owner_client.put(f"/api/oauth/scopes/{'s' * 129}", json={}), "name", 128)
    _too_long(owner_client.put("/api/oauth/scopes/ok", json={"description": "d" * 257}), "description", 256)
    base = f"/api/oauth/services/{service['id']}/scopes"
    _too_long(owner_client.put(f"{base}/{'s' * 129}", json={}), "name", 128)
    _too_long(owner_client.put(f"{base}/own", json={"description": "d" * 257}), "description", 256)
    assert owner_client.put(f"{base}/own", json={"description": "d" * 256}).status_code == 200


# ---------------------------------------------------------------------------
# OAuth protocol endpoints (public)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("field,value,error", [
    ("client_uri", "https://a.example/" + "p" * 600, "invalid_client_metadata"),
    ("logo_uri", "https://a.example/" + "p" * 600, "invalid_client_metadata"),
    ("software_id", "s" * 129, "invalid_client_metadata"),
    ("redirect_uris", ["https://a.example/" + "p" * 600], "invalid_redirect_uri"),
])
def test_dynamic_registration_rejects_long_metadata(client, field, value, error):
    body = {"client_name": "c", "redirect_uris": ["https://a.example/cb"], field: value}
    r = client.post("/oauth/register", json=body)
    assert r.status_code == 400, r.text
    assert r.json()["error"] == error and "too long" in r.json()["error_description"]


def test_dynamic_registration_shortens_a_long_client_name(client):
    r = client.post("/oauth/register", json={"client_name": "c" * 300, "redirect_uris": ["https://a.example/cb"]})
    assert r.status_code == 201 and len(r.json()["client_name"]) == 128


@pytest.mark.parametrize("param,value", [("state", "s" * 513), ("code_challenge", "c" * 129)])
def test_authorize_rejects_long_state_and_code_challenge(owner_client, service, param, value):
    reg = owner_client.post("/oauth/register", json={"client_name": "c", "redirect_uris": ["https://a.example/cb"]})
    query = {"response_type": "code", "client_id": reg.json()["client_id"], "redirect_uri": "https://a.example/cb",
             "code_challenge": "a" * 43, "code_challenge_method": "S256", "resource": service["effective_audience"],
             param: value}
    r = owner_client.get("/oauth/authorize", params=query, follow_redirects=False)
    assert r.status_code == 302, r.text
    location = urlparse(r.headers["location"])
    assert location.netloc == "a.example"
    assert parse_qs(location.query)["error"] == ["invalid_request"]


# ---------------------------------------------------------------------------
# managed / BYO
# ---------------------------------------------------------------------------
def test_byo_definition_name_limit(owner_client):
    _too_long(owner_client.post("/api/byo-mcp", json={"name": "b" * 65, "command": "npx", "args": ["-y", "x"]}),
              "name", 64)


# ---------------------------------------------------------------------------
# discovery: scan input, remote server names and tool lists
# ---------------------------------------------------------------------------
def test_scan_rejects_names_and_hosts_that_cannot_be_registered(owner_client):
    _too_long(owner_client.post("/api/discovery/scan", json={"hosts": ["127.0.0.1"], "ports": [80],
                                                              "service_name": "n" * 65}), "service_name", 64, 422)
    _too_long(owner_client.post("/api/discovery/scan", json={"hosts": ["h" * 129], "ports": [80]}),
              "hosts", 128, 422)


BAD_TOOLS = [
    MCPToolInfo(name="search", description="ok"),
    MCPToolInfo(name="search", description="duplicate"),
    MCPToolInfo(name="   ", description="blank"),
    MCPToolInfo(name="x" * 129, description="too long"),
    MCPToolInfo(name="y" * 128, description="exactly at the limit"),
]


def test_refresh_tools_drops_tools_that_cannot_be_stored(owner_client, service, monkeypatch):
    monkeypatch.setattr(scanner_mod.get_scanner(), "get_tools_list", AsyncMock(return_value=BAD_TOOLS))
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools")
    assert r.status_code == 200, r.text
    assert sorted(t["name"] for t in r.json()["tools"]) == ["search", "y" * 128]
    assert next(t for t in r.json()["tools"] if t["name"] == "search")["description"] == "ok"


def test_scan_registers_a_server_with_a_long_name_and_bad_tools(owner_client, monkeypatch):
    found = DiscoveredService(
        host="127.0.0.1", port=9200, verify_result=MCPVerifyResult(success=True, server_name="Very Long " * 30),
        tools=BAD_TOOLS,
    )
    monkeypatch.setattr(scanner_mod.get_scanner(), "discover_services", AsyncMock(return_value=[found]))
    r = owner_client.post("/api/discovery/scan", json={"hosts": ["127.0.0.1"], "ports": [9200]})
    assert r.status_code == 200, r.text
    info = r.json()["discovered"][0]
    assert info["registered"] and len(info["service_name"]) == 64
    svc = owner_client.get(f"/api/services/{info['service_id']}", params={"include_tools": True}).json()
    assert svc["name"] == info["service_name"] and svc["tools_count"] == 2


# ---------------------------------------------------------------------------
# health checks relay the remote error text
# ---------------------------------------------------------------------------
def test_health_check_shortens_a_long_remote_error(owner_client, service, monkeypatch):
    failing = MCPVerifyResult(success=False, error="remote said: " + "e" * 2000, response_time_ms=1.0)
    monkeypatch.setattr(scanner_mod.get_scanner(), "verify_mcp_service", AsyncMock(return_value=failing))
    r = owner_client.post(f"/api/services/{service['id']}/health-check")
    assert r.status_code == 200, r.text
    stored = owner_client.get(f"/api/services/{service['id']}/health").json()["error_message"]
    assert len(stored) == 512 and stored.startswith("remote said: ") and stored.endswith("…")
