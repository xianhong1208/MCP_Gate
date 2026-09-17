"""Refreshing a server's tool list as a chosen identity: anonymous scanner token, one of the server's issued
tokens (PAT or OAuth access token) -- for servers that show different tools per caller."""

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


def _issue_pat(owner_client, service, scopes=None):
    body = {"service_id": service["id"], "expires_days": 1, "label": "agent"}
    if scopes:
        body["scopes"] = scopes
    r = owner_client.post("/api/oauth/tokens/personal", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def test_token_identity_presents_the_chosen_pat(owner_client, service, captured):
    pat = _issue_pat(owner_client, service, scopes=["mcp:tools:read"])
    original = _claims(pat["access_token"])
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools",
                          json={"identity": "token", "jti": pat["jti"]})
    assert r.status_code == 200, r.text
    probe = _claims(_token_arg(captured))
    # same identity, same jti; only freshly signed and short-lived
    for claim in ("iss", "sub", "client_id", "scope", "aud", "jti", "email", "name", "token_use"):
        assert probe[claim] == original[claim], claim
    assert probe["exp"] - probe["iat"] <= 120 and probe["exp"] < original["exp"]
    assert _token_arg(captured) != pat["access_token"]
    # the probe is not a new token record
    assert owner_client.get("/api/oauth/tokens", params={"include_inactive": True}).json()["total"] == 1
    entries = [e for e in owner_client.get("/api/audit/logs").json()["logs"] if e["action"] == "refresh_tools"]
    assert entries[0]["details"]["identity"] == "token" and entries[0]["details"]["jti"] == pat["jti"]


def test_token_identity_works_for_oauth_access_tokens(owner_client, service, captured):
    from tests.test_oauth_flow import _authorize_and_consent, _exchange, _register
    reg = _register(owner_client, client_name="Agent client")
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"], scope="mcp:tools:read mcp:tools:invoke")
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    original = _claims(tokens["access_token"])
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools",
                          json={"identity": "token", "jti": original["jti"]})
    assert r.status_code == 200, r.text
    probe = _claims(_token_arg(captured))
    assert probe["client_id"] == reg["client_id"] and probe["sub"] == original["sub"]
    assert probe["scope"] == original["scope"] and probe["jti"] == original["jti"]


def test_token_identity_refuses_revoked_foreign_and_unknown(owner_client, service, captured):
    pat = _issue_pat(owner_client, service)
    r = owner_client.post("/api/services", json={"name": "other", "host": "127.0.0.1", "port": 8124,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    other = r.json()
    r = owner_client.post(f"/api/services/{other['id']}/refresh-tools", json={"identity": "token", "jti": pat["jti"]})
    assert r.status_code == 400 and "not issued for this server" in r.json()["detail"]["fallback"]
    assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools", json={"identity": "token", "jti": pat["jti"]})
    assert r.status_code == 400 and "no longer active" in r.json()["detail"]["fallback"]
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools", json={"identity": "token", "jti": "nope"})
    assert r.status_code == 404
    captured.assert_not_awaited()


def test_unknown_identity_is_rejected(owner_client, service, captured):
    r = owner_client.post(f"/api/services/{service['id']}/refresh-tools", json={"identity": "bearer"})
    assert r.status_code == 422
    captured.assert_not_awaited()
