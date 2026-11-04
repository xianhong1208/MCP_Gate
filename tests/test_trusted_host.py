"""DNS rebinding: requests whose Host is a foreign host name are refused.

A page on ``http://evil.example:4568`` whose DNS name is re-pointed at 127.0.0.1 becomes, for the browser, a
same-origin page talking to MCP Gate: it can read every response and send any header. Without a Host check it could
run first-time setup on a fresh install, register clients, and walk the unauthenticated surface. The browser still
sends ``Host: evil.example:4568`` (that is the name it resolved), so refusing host names MCP Gate does not answer to
closes it. IP literals are always accepted: a rebinding attack needs a name the attacker controls.
"""
import pytest
from starlette.websockets import WebSocketDisconnect

from src.middleware.trusted_host import host_allowed


def _scope(host, peer="203.0.113.9", **headers):
    hdrs = [(b"host", host.encode())] if host is not None else []
    hdrs += [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()]
    return {"type": "http", "scheme": "http", "path": "/api/session/status", "headers": hdrs, "client": (peer, 1234)}


ISSUER = "http://localhost:4568"


@pytest.mark.parametrize("host", [
    "localhost:4568", "localhost", "LOCALHOST:4568", "mcp-gate.localhost:4568", "127.0.0.1:4568", "127.0.0.1",
    "192.168.1.20:4568", "[::1]:4568", "10.0.0.5",
])
def test_issuer_loopback_and_ip_hosts_pass(host):
    assert host_allowed(_scope(host), issuer=ISSUER, allowed_hosts=[], trusted_proxies=[])


@pytest.mark.parametrize("host", [
    "evil.example:4568", "evil.example", "localhost.evil.example:4568", "127.0.0.1.nip.io:4568", "", "a b",
])
def test_foreign_host_names_are_refused(host):
    assert not host_allowed(_scope(host), issuer=ISSUER, allowed_hosts=[], trusted_proxies=[])


def test_missing_host_header_is_not_a_browser():
    assert host_allowed(_scope(None), issuer=ISSUER, allowed_hosts=[], trusted_proxies=[])


def test_issuer_host_and_configured_hosts_pass():
    issuer = "https://mcp.example.com"
    assert host_allowed(_scope("mcp.example.com"), issuer=issuer, allowed_hosts=[], trusted_proxies=[])
    assert not host_allowed(_scope("mcp-gate:4568"), issuer=issuer, allowed_hosts=[], trusted_proxies=[])
    assert host_allowed(_scope("mcp-gate:4568"), issuer=issuer, allowed_hosts=["mcp-gate"], trusted_proxies=[])
    assert host_allowed(_scope("a.internal.example"), issuer=issuer, allowed_hosts=["*.internal.example"],
                        trusted_proxies=[])
    assert not host_allowed(_scope("internal.example.evil"), issuer=issuer, allowed_hosts=["*.internal.example"],
                            trusted_proxies=[])
    assert host_allowed(_scope("anything.example"), issuer=issuer, allowed_hosts=["*"], trusted_proxies=[])


def test_forwarded_host_cannot_launder_a_foreign_host():
    """A rebound page is same-origin with itself and may set X-Forwarded-Host; when the browser runs on the same
    machine its peer address is 127.0.0.1, a trusted proxy by default. The raw Host is still checked."""
    scope = _scope("evil.example:4568", peer="127.0.0.1", x_forwarded_host="localhost:4568")
    assert not host_allowed(scope, issuer=ISSUER, allowed_hosts=[], trusted_proxies=["127.0.0.1"])


def test_behind_a_proxy_both_hosts_must_pass():
    issuer = "https://mcp.example.com"
    ok = _scope("127.0.0.1:4568", peer="127.0.0.1", x_forwarded_host="mcp.example.com")
    assert host_allowed(ok, issuer=issuer, allowed_hosts=[], trusted_proxies=["127.0.0.1"])
    bad = _scope("127.0.0.1:4568", peer="127.0.0.1", x_forwarded_host="evil.example")
    assert not host_allowed(bad, issuer=issuer, allowed_hosts=[], trusted_proxies=["127.0.0.1"])


@pytest.mark.parametrize("path", ["/api/session/status", "/.well-known/jwks.json", "/", "/api/session/setup"])
def test_app_answers_421_to_a_foreign_host(client, path):
    method = client.post if path.endswith("setup") else client.get
    kwargs = {"json": {"email": "a@example.com", "password": "password-123"}} if path.endswith("setup") else {}
    r = method(path, headers={"host": "evil.example:4568"}, **kwargs)
    assert r.status_code == 421, r.text
    assert r.json()["error"] == "http.host_not_allowed"
    # The setup did not happen
    assert client.get("/api/session/status").json()["needs_setup"] is True


def test_app_serves_the_issuer_host_and_health_everywhere(client):
    assert client.get("/api/session/status").status_code == 200           # Host: testserver = issuer
    assert client.get("/api/session/status", headers={"host": "127.0.0.1:4568"}).status_code == 200
    assert client.get("/health", headers={"host": "mcp-gate:4568"}).status_code == 200


def test_websocket_from_a_foreign_host_is_refused(owner_client):
    with pytest.raises(WebSocketDisconnect) as e:
        with owner_client.websocket_connect("/ws/services", headers={"host": "evil.example"}) as ws:
            ws.receive_json()
    assert e.value.code == 1008


def test_ip_literal_hosts_still_feed_the_issuer_mismatch_warning(client):
    from src.middleware.issuer_check import observed_mismatches, reset_observed

    reset_observed()
    try:
        assert client.get("/.well-known/jwks.json", headers={"host": "192.168.1.20:4568"}).status_code == 200
        assert [m["base_url"] for m in observed_mismatches()] == ["http://192.168.1.20:4568"]
        client.get("/.well-known/jwks.json", headers={"host": "evil.example"})
        assert len(observed_mismatches()) == 1     # refused before it could be recorded
    finally:
        reset_observed()
