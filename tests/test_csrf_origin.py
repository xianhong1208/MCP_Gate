"""State-changing requests from a foreign page are refused (CSRF), by Origin or Referer.

The console session is a cookie, and ``SameSite=Lax`` does not separate same-site pages: a page on another
port of the same host (any local dev server, any MCP client's loopback listener) or a sibling subdomain gets
the cookie attached to its requests. Body-less POSTs need no CORS preflight, so before this check a page on
``http://localhost:5174`` could rotate the signing keys or revoke tokens with one ``fetch``.
"""
import pytest

from src.middleware.csrf import needs_origin_check

EVIL = "http://localhost:5174"


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/oauth/keys/rotate"),
    ("POST", "/api/system/cleanup/run"),
    ("POST", "/api/session/logout"),
    ("PUT", "/api/session/me/profile"),
    ("DELETE", "/api/audit/cleanup"),
    ("POST", "/oauth/authorize/requests/abc/decision"),
])
def test_state_changing_paths_are_checked(method, path):
    assert needs_origin_check(method, path)


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/session/me"),
    ("HEAD", "/api/services"),
    ("OPTIONS", "/api/services"),
    ("POST", "/oauth/token"),
    ("POST", "/oauth/register"),
    ("POST", "/oauth/revoke"),
    ("POST", "/oauth/introspect"),
    ("POST", "/oauth/usage"),
    ("POST", "/.well-known/anything"),
])
def test_protocol_and_safe_requests_are_exempt(method, path):
    assert not needs_origin_check(method, path)


def _denied(r):
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "auth.csrf_origin_denied"


@pytest.mark.parametrize("headers", [
    {"origin": EVIL},
    {"origin": "null"},
    {"origin": "http://testserver.evil.example"},
    {"referer": f"{EVIL}/attack.html"},
    {"referer": "not a url"},
])
def test_bodyless_post_from_foreign_page_is_refused(owner_client, headers):
    before = owner_client.get("/api/oauth/keys").json()
    _denied(owner_client.post("/api/oauth/keys/rotate", headers=headers))
    assert owner_client.get("/api/oauth/keys").json() == before


def test_logout_and_json_bodies_are_checked_too(owner_client):
    _denied(owner_client.post("/api/session/logout", headers={"origin": EVIL}))
    _denied(owner_client.put("/api/session/me/profile", json={"username": "pwned"}, headers={"origin": EVIL}))
    assert owner_client.get("/api/session/me").json()["username"] == "owner"


def test_consent_decision_is_checked(owner_client):
    _denied(owner_client.post("/oauth/authorize/requests/whatever/decision", json={"approve": True},
                              headers={"origin": EVIL}))


@pytest.mark.parametrize("headers", [
    {"origin": "http://testserver"},
    {"referer": "http://testserver/settings"},
    {},  # no Origin and no Referer: not a browser page, so not a forgery
])
def test_console_and_non_browser_requests_pass(owner_client, headers):
    r = owner_client.put("/api/session/me/profile", json={"username": "renamed"}, headers=headers)
    assert r.status_code == 200, r.text


def test_configured_cors_origin_passes(owner_client):
    from src.config import Config

    cors = Config.get_cors_config()
    saved = list(cors.allowed_origins)
    cors.allowed_origins = ["http://console.example"]
    try:
        r = owner_client.put("/api/session/me/profile", json={"username": "x"},
                             headers={"origin": "http://console.example"})
        assert r.status_code == 200, r.text
    finally:
        cors.allowed_origins = saved


def test_public_oauth_endpoints_stay_open_cross_origin(client):
    """Browser-based MCP clients call /oauth/register and /oauth/token from their own origin."""
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["http://localhost:9/cb"]},
                    headers={"origin": "https://some-mcp-client.example"})
    assert r.status_code == 201, r.text


def test_bearer_only_request_is_exempt(owner_client):
    """No cookie, an Authorization header: nothing ambient for a forged request to ride on."""
    token = owner_client.cookies.get("mcp_session")
    owner_client.cookies.clear()
    r = owner_client.put("/api/session/me/profile", json={"username": "bearer"},
                         headers={"origin": EVIL, "authorization": f"Bearer {token}"})
    assert r.status_code != 403
