"""Refreshing a server's tool list as a chosen identity: anonymous scanner token, the signed-in owner, or a
pasted bearer -- for servers that show different tools per caller."""

from unittest.mock import AsyncMock

import jwt
import pytest

from src.discovery import scanner as scanner_mod
from src.discovery.scanner import MCPToolInfo


@pytest.fixture
def captured(monkeypatch):
    """Stub the scanner's tools/list and capture the Authorization token it was given."""
    fake = AsyncMock(return_value=[MCPToolInfo(name="search", description="Search", input_schema={"type": "object"})])
    monkeypatch.setattr(scanner_mod.get_scanner(), "get_tools_list", fake)
    return fake


def _token_arg(fake):
    return fake.await_args.kwargs["auth_token"]


def test_default_is_the_anonymous_scanner_token(owner_client, service, captured):
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools")
    assert r.status_code == 200 and r.json()["tools_count"] == 1
    claims = jwt.decode(_token_arg(captured), options={"verify_signature": False})
    assert claims["sub"] == claims["client_id"] and "email" not in claims
    assert claims["aud"] == service["effective_audience"]


def test_owner_identity_carries_user_and_scopes(owner_client, service, captured):
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools",
                          json={"identity": "owner", "scopes": ["mcp:tools:read"]})
    assert r.status_code == 200, r.text
    claims = jwt.decode(_token_arg(captured), options={"verify_signature": False})
    me = owner_client.get("/api/session/me").json()
    me = me.get("user", me)
    assert claims["sub"] == me["id"]
    assert claims["email"] == me["email"] and claims["name"] == me["username"]
    assert claims["scope"] == "mcp:tools:read"
    assert claims["exp"] - claims["iat"] <= 120
    # not recorded as a token
    assert all(t["sub"] != claims["sub"] or t["kind"] != "access"
               for t in owner_client.get("/api/oauth/tokens", params={"include_inactive": True}).json()["tokens"])
    # audited with the identity
    entries = [e for e in owner_client.get("/api/audit/logs").json()["logs"] if e["action"] == "refresh_tools"]
    assert entries[0]["details"]["identity"] == "owner" and entries[0]["details"]["scopes"] == ["mcp:tools:read"]


def test_owner_identity_defaults_to_server_defaults_and_rejects_unknown_scope(owner_client, service, captured):
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools", json={"identity": "owner"})
    assert r.status_code == 200, r.text
    claims = jwt.decode(_token_arg(captured), options={"verify_signature": False})
    assert "mcp:tools:read" in claims["scope"].split()
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools",
                          json={"identity": "owner", "scopes": ["nope:x"]})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "oauth.invalid_scope"


def test_bearer_identity_passes_the_pasted_token_through(owner_client, service, captured):
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools",
                          json={"identity": "bearer", "bearer": "  external-token-123 "})
    assert r.status_code == 200, r.text
    assert _token_arg(captured) == "external-token-123"
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools", json={"identity": "bearer"})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "service.refresh_bearer_missing"
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools", json={"identity": "root"})
    assert r.status_code == 422
