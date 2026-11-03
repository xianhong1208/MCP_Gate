"""Authorization-code redemption rules: a failed PKCE check burns the code (OAuth 2.1), and loopback redirect URIs
(127.0.0.1, [::1], localhost) accept any port (RFC 8252 §7.3, RFC 9700)."""

from urllib.parse import parse_qs, urlparse

from tests.conftest import make_pkce
from tests.test_oauth_flow import RESOURCE, _authorize_and_consent, _exchange, _register


def test_wrong_pkce_verifier_burns_the_code(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    bad = _exchange(owner_client, reg["client_id"], code, "x" * 43)
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    good = _exchange(owner_client, reg["client_id"], code, verifier)
    assert good.status_code == 400 and good.json()["error"] == "invalid_grant", good.text


def test_wrong_redirect_uri_burns_the_code(owner_client, service):
    reg = _register(owner_client, redirect_uris=["http://localhost:9999/callback", "http://localhost:9999/other"])
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = owner_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": reg["client_id"], "code": code,
        "redirect_uri": "http://localhost:9999/other", "code_verifier": verifier, "resource": RESOURCE})
    assert r.status_code == 400
    assert _exchange(owner_client, reg["client_id"], code, verifier).status_code == 400


def _authorize(owner_client, client_id, redirect_uri):
    _verifier, challenge = make_pkce()
    return owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": RESOURCE, "state": "s"}, follow_redirects=False)


def _flow_ok(owner_client, client_id, redirect_uri):
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": RESOURCE, "state": "s"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/consent"), r.text
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    d = owner_client.post(f"/oauth/authorize/requests/{rid}/decision", json={"approve": True})
    loc = d.json()["redirect_to"]
    assert loc.startswith(redirect_uri + "?")
    code = parse_qs(urlparse(loc).query)["code"][0]
    t = owner_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": redirect_uri,
        "code_verifier": verifier, "resource": RESOURCE})
    assert t.status_code == 200, t.text


def test_loopback_ip_redirect_accepts_any_port(owner_client, service):
    reg = _register(owner_client, redirect_uris=["http://127.0.0.1:4617/cb", "http://[::1]:4617/cb"])
    _flow_ok(owner_client, reg["client_id"], "http://127.0.0.1:51234/cb")
    _flow_ok(owner_client, reg["client_id"], "http://127.0.0.1/cb")
    _flow_ok(owner_client, reg["client_id"], "http://[::1]:40000/cb")
    # everything but the port must still match exactly
    for other in ("http://127.0.0.1:51234/cb2", "http://127.0.0.1:51234/cb?x=1", "https://127.0.0.1:51234/cb",
                  "http://[::1]:51234/other", "http://127.0.0.2:4617/cb"):
        r = _authorize(owner_client, reg["client_id"], other)
        assert r.status_code == 400 and r.json()["error"] == "invalid_request", other


def test_localhost_redirect_accepts_any_port(owner_client, service):
    """RFC 9700 §2.1 / §4.1.3: the port of a localhost redirect URI is not compared either (CLI MCP clients
    register http://localhost:<port>/callback and listen on whatever port is free)."""
    reg = _register(owner_client, redirect_uris=["http://localhost:4617/cb"])
    _flow_ok(owner_client, reg["client_id"], "http://localhost:4618/cb")
    _flow_ok(owner_client, reg["client_id"], "http://localhost/cb")
    for other in ("http://localhost:4618/cb2", "http://localhost:4618/cb?x=1", "https://localhost:4618/cb",
                  "http://127.0.0.1:4617/cb", "http://localhost.example.com:4617/cb",
                  "http://user@localhost:4618/cb"):
        r = _authorize(owner_client, reg["client_id"], other)
        assert r.status_code == 400 and r.json()["error"] == "invalid_request", other


def test_non_loopback_redirect_is_exact(owner_client, service):
    reg = _register(owner_client, redirect_uris=["https://app.example.com:8443/cb"])
    r = _authorize(owner_client, reg["client_id"], "https://app.example.com:9443/cb")
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    r = _authorize(owner_client, reg["client_id"], "https://app.example.com/cb")
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
