"""/ws/services only accepts the console's own origin and only the session cookie.

WebSockets are not covered by CORS: the browser sends the session cookie on a handshake started by any
page, so without an Origin check a page on another port of the same host could read the live service
feed (cross-site WebSocket hijacking). `?token=` is gone because URLs end up in proxy logs.
"""
import pytest
from starlette.websockets import WebSocketDisconnect

from src.middleware.origin_check import is_trusted_origin, normalize_origin


def _ping(ws):
    ws.send_json({"type": "ping"})
    while True:
        msg = ws.receive_json()
        if msg.get("type") == "pong":
            return msg


@pytest.mark.parametrize("origin", ["http://testserver", None])
def test_console_origins_connect(owner_client, origin):
    headers = {"origin": origin} if origin else {}
    with owner_client.websocket_connect("/ws/services", headers=headers) as ws:
        assert _ping(ws)["type"] == "pong"


@pytest.mark.parametrize("origin", [
    "http://evil.example", "http://testserver:8080", "http://localhost:5173", "https://testserver", "null", "http://testserver.evil.example",
])
def test_foreign_origins_are_refused(owner_client, origin):
    with pytest.raises(WebSocketDisconnect) as e:
        with owner_client.websocket_connect("/ws/services", headers={"origin": origin}) as ws:
            ws.receive_json()
    assert e.value.code == 1008


def test_query_string_token_is_not_accepted(owner_client):
    token = owner_client.cookies.get("mcp_session")
    owner_client.cookies.clear()
    with pytest.raises(WebSocketDisconnect) as e:
        with owner_client.websocket_connect(f"/ws/services?token={token}",
                                            headers={"origin": "http://testserver"}) as ws:
            ws.receive_json()
    assert e.value.code == 4001


def _scope(host, scheme="ws", peer="203.0.113.9", **extra):
    headers = [(b"host", host.encode())] + [(k.encode(), v.encode()) for k, v in extra.items()]
    return {"type": "websocket", "scheme": scheme, "headers": headers, "client": (peer, 1234)}


def test_the_other_loopback_host_is_not_locked_out():
    """Browsing via 127.0.0.1 while OAUTH_ISSUER says localhost: the page's own origin is still trusted."""
    scope = _scope("127.0.0.1:4568")
    assert is_trusted_origin("http://127.0.0.1:4568", scope, issuer="http://localhost:4568")
    assert is_trusted_origin("http://localhost:4568", _scope("localhost:4568"), issuer="http://localhost:4568")
    # ...but one loopback name is not a stand-in for the other
    assert not is_trusted_origin("http://localhost:4568", scope, issuer="http://example.com")


def test_forwarded_host_only_from_trusted_proxies():
    behind_proxy = _scope("127.0.0.1:4568", peer="127.0.0.1", **{"x-forwarded-host": "mcp.example.com",
                                                                  "x-forwarded-proto": "https"})
    assert is_trusted_origin("https://mcp.example.com", behind_proxy, issuer="http://localhost:4568",
                             trusted_proxies=["127.0.0.1"])
    spoofed = _scope("127.0.0.1:4568", peer="203.0.113.9", **{"x-forwarded-host": "evil.example"})
    assert not is_trusted_origin("http://evil.example", spoofed, issuer="http://localhost:4568",
                                 trusted_proxies=["127.0.0.1"])


def test_wildcard_allowed_origin_is_not_a_blanket_pass():
    assert not is_trusted_origin("http://evil.example", _scope("localhost:4568"), issuer="http://localhost:4568",
                                 allowed_origins=["*"])


@pytest.mark.parametrize("value, expected", [
    ("http://Example.com:80", "http://example.com"),
    ("https://example.com:8443", "https://example.com:8443"),
    ("null", None), ("http://a@example.com", None), ("http://example.com/path", None), ("ftp://x", None),
])
def test_normalize_origin(value, expected):
    assert normalize_origin(value) == expected
