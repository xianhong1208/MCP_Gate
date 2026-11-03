"""The consent page cannot be framed (clickjacking), names where the browser is sent back to, and flags clients
whose every redirect URI is on this machine."""

from urllib.parse import parse_qs, urlparse

from tests.conftest import make_pkce
from tests.test_oauth_flow import RESOURCE, _register


def _consent_info(owner_client, client_id, redirect_uri):
    _verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": RESOURCE}, follow_redirects=False)
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    return owner_client.get(f"/oauth/authorize/requests/{rid}").json()


def test_consent_page_cannot_be_framed(client):
    r = client.get("/consent?rid=x")
    assert r.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert r.headers["x-frame-options"] == "DENY"


def test_loopback_only_clients_are_flagged(owner_client, service):
    local = _register(owner_client, redirect_uris=["http://localhost:7777/cb", "http://127.0.0.1:7777/cb"])
    info = _consent_info(owner_client, local["client_id"], "http://localhost:7777/cb")
    assert info["redirect_host"] == "localhost:7777"
    assert info["redirect_loopback_only"] is True

    mixed = _register(owner_client, redirect_uris=["http://localhost:7777/cb", "https://app.example.com/cb"])
    info = _consent_info(owner_client, mixed["client_id"], "https://app.example.com/cb")
    assert info["redirect_host"] == "app.example.com"
    assert info["redirect_loopback_only"] is False


def test_loopback_only_helper():
    from src.oauth.service import _loopback_only

    assert _loopback_only(["http://[::1]:1/cb", "http://LOCALHOST/cb"]) is True
    assert _loopback_only([]) is False
    assert _loopback_only(["cursor://callback"]) is False
    assert _loopback_only(["http://localhost.evil.example/cb"]) is False
