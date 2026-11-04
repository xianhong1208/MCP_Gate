"""H-04: the session cookie alone is not a session.

Cookies ignore ports, so on a ``localhost`` / ``127.0.0.1`` deployment the browser sends ``mcp_session`` to every
other local port too, including an OAuth client's loopback callback (``http://localhost:<port>/cb``) the moment
the owner approves it on the consent screen. The hunt reproduced it: the listener received the cookie and replayed
it against ``/api/session/me`` as the owner.

Each session is now bound to a second secret, the *session binding*, returned in the login response body and kept
by the console in its origin's ``localStorage`` (which, unlike cookies, *is* scoped by port). Every authenticated
request has to present it in the ``X-Session-Binding`` header (WebSocket: a ``Sec-WebSocket-Protocol`` entry).
A replayed cookie without it is useless.
"""
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from starlette.websockets import WebSocketDisconnect

from src.identity.session import SESSION_BINDING_HEADER, WS_PROTOCOL
from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD


def _as_loopback_listener(owner_client):
    """What a process on another localhost port receives: the Cookie header, nothing else."""
    return owner_client.cookies.get("mcp_session")


def _raw(client, method, path, *, cookie=None, binding=None, **kw):
    headers = dict(kw.pop("headers", {}) or {})
    if cookie:
        headers["cookie"] = f"mcp_session={cookie}"
    if binding:
        headers[SESSION_BINDING_HEADER] = binding
    saved_cookies, saved_binding = dict(client.cookies), client.headers.pop(SESSION_BINDING_HEADER, None)
    client.cookies.clear()
    try:
        return client.request(method, path, headers=headers, **kw)
    finally:
        for k, v in saved_cookies.items():
            client.cookies.set(k, v)
        if saved_binding:
            client.headers[SESSION_BINDING_HEADER] = saved_binding


def test_replayed_cookie_alone_is_refused(owner_client):
    cookie = _as_loopback_listener(owner_client)
    assert _raw(owner_client, "GET", "/api/session/me", cookie=cookie).status_code == 401
    assert _raw(owner_client, "GET", "/api/services", cookie=cookie).status_code == 401
    assert _raw(owner_client, "POST", "/api/oauth/keys/rotate", cookie=cookie).status_code == 401


def test_wrong_binding_is_refused_and_the_right_one_works(owner_client):
    cookie = owner_client.cookies.get("mcp_session")
    binding = owner_client.headers[SESSION_BINDING_HEADER]
    assert _raw(owner_client, "GET", "/api/session/me", cookie=cookie, binding="x" * 43).status_code == 401
    assert _raw(owner_client, "GET", "/api/session/me", cookie=cookie, binding=binding).status_code == 200


def test_bearer_session_jwt_needs_the_binding_too(owner_client):
    token = owner_client.cookies.get("mcp_session")
    bearer = {"authorization": f"Bearer {token}"}
    assert _raw(owner_client, "GET", "/api/session/me", headers=bearer).status_code == 401
    binding = owner_client.headers[SESSION_BINDING_HEADER]
    assert _raw(owner_client, "GET", "/api/session/me", headers=bearer, binding=binding).status_code == 200


def test_binding_comes_in_the_body_never_in_a_cookie(client):
    r = client.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    binding = r.json()["session_binding"]
    assert len(binding) >= 32
    assert binding not in " ".join(r.headers.get_list("set-cookie"))
    # The cookie JWT carries only a hash of it
    claims = jwt.decode(r.cookies["mcp_session"], options={"verify_signature": False})
    assert binding not in str(claims) and claims.get("sbh")


def test_login_and_password_change_return_a_fresh_binding(owner_client):
    first = owner_client.headers[SESSION_BINDING_HEADER]
    login = owner_client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    second = login.json()["session_binding"]
    changed = owner_client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                                  "new_password": "new-password-456"})
    third = changed.json()["session_binding"]
    assert len({first, second, third}) == 3


def test_logout_with_the_cookie_alone_cannot_end_the_owners_session(owner_client):
    """A replayed cookie could otherwise at least log the owner out."""
    cookie = owner_client.cookies.get("mcp_session")
    _raw(owner_client, "POST", "/api/session/logout", cookie=cookie)
    assert owner_client.get("/api/session/me").status_code == 200


def test_websocket_needs_the_binding_subprotocol(owner_client):
    binding = owner_client.headers[SESSION_BINDING_HEADER]
    with pytest.raises(WebSocketDisconnect) as e:
        with owner_client.websocket_connect("/ws/services", subprotocols=[]) as ws:
            ws.receive_json()
    assert e.value.code == 4001
    with pytest.raises(WebSocketDisconnect) as e:
        with owner_client.websocket_connect("/ws/services", subprotocols=[WS_PROTOCOL, f"{WS_PROTOCOL}.binding.wrong"]) as ws:
            ws.receive_json()
    assert e.value.code == 4001
    with owner_client.websocket_connect("/ws/services",
                                        subprotocols=[WS_PROTOCOL, f"{WS_PROTOCOL}.binding.{binding}"]) as ws:
        assert ws.accepted_subprotocol == WS_PROTOCOL
        ws.send_json({"type": "ping"})
        assert ws.receive_json()["type"] == "pong"


def test_authorize_never_issues_a_code_on_the_cookie_alone(owner_client, service):
    """With a remembered consent, /oauth/authorize used to answer a cookie-only request with a 302 straight to
    the client, code included: whoever replayed the cookie read the code from the Location header. The skip now
    happens on the consent page, which has the binding."""
    from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _register
    from tests.conftest import make_pkce

    reg = _register(owner_client)
    _authorize_and_consent(owner_client, reg["client_id"], remember=True)
    _, challenge = make_pkce()
    params = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
              "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE, "state": "s"}
    cookie = owner_client.cookies.get("mcp_session")
    r = _raw(owner_client, "GET", "/oauth/authorize", cookie=cookie, params=params, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/consent?")
    assert "code=" not in r.headers["location"]
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    # The console (cookie + binding) sees that consent can be skipped and approves without asking
    assert owner_client.get(f"/oauth/authorize/requests/{rid}").json()["can_skip"] is True


def test_external_login_hands_the_binding_over_in_the_fragment(client, monkeypatch):
    """The provider callback ends in a redirect, not a JSON body: the binding travels in the URL fragment, which
    the browser keeps on the console's own origin and never sends to any server."""
    from src.config import Config
    from src.identity.providers.base import ExternalIdentity
    from src.identity.providers.github import GitHubLoginProvider

    client.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    client.cookies.clear()
    client.headers.pop(SESSION_BINDING_HEADER, None)
    cfg = Config.get_config_model()
    monkeypatch.setattr(cfg.identity.github, "client_id", "gh-id")
    monkeypatch.setattr(cfg.identity.github, "client_secret", "gh-secret")

    async def fake_exchange(self, *, code, redirect_uri):
        return ExternalIdentity(provider="github", sub="42", email=OWNER_EMAIL, name="o", email_verified=True)

    monkeypatch.setattr(GitHubLoginProvider, "exchange", fake_exchange)
    start = client.get("/api/session/oauth/github/start", params={"next": "/services#frag"}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    cb = client.get("/api/session/oauth/github/callback", params={"code": "c", "state": state},
                    follow_redirects=False)
    assert cb.status_code == 302
    location = urlparse(cb.headers["location"])
    assert location.path == "/services" and not location.netloc
    binding = parse_qs(location.fragment)["mcp_sb"][0]
    cookie = cb.cookies["mcp_session"]
    client.cookies.clear()
    assert _raw(client, "GET", "/api/session/me", cookie=cookie).status_code == 401
    assert _raw(client, "GET", "/api/session/me", cookie=cookie, binding=binding).status_code == 200
