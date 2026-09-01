"""OAuth protocol endpoints are CORS-open to any origin; the console API keeps its narrow policy."""

FOREIGN = {"Origin": "http://some-mcp-host.example"}


def test_discovery_and_token_endpoints_open_to_any_origin(client):
    r = client.get("/.well-known/oauth-authorization-server", headers=FOREIGN)
    assert r.status_code == 200 and r.headers.get("access-control-allow-origin") == "*"
    r = client.get("/.well-known/jwks.json", headers=FOREIGN)
    assert r.status_code == 200 and r.headers.get("access-control-allow-origin") == "*"
    r = client.options("/oauth/token", headers={**FOREIGN, "Access-Control-Request-Method": "POST"})
    assert r.status_code == 204 and r.headers.get("access-control-allow-origin") == "*"
    r = client.options("/oauth/register", headers={**FOREIGN, "Access-Control-Request-Method": "POST"})
    assert r.status_code == 204


def test_console_api_keeps_restricted_policy(client):
    r = client.get("/api/session/status", headers=FOREIGN)
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") is None
