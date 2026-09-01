"""Classic OAuth clients: confidential, registered in the console, no PKCE, no `resource` parameter.

Some platforms' OAuth modules only know client_id / client_secret (Google / Zoho style). MCP Center is
OAuth 2.1 and normally requires PKCE and an RFC 8707 `resource`; a console-registered confidential client
may opt out of both, the secret proving its identity and `default_resource` deciding the audience.
Public and dynamically registered clients cannot opt out.
"""
from urllib.parse import parse_qs, urlparse

import jwt

from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _register


def _create_classic(owner_client, **overrides):
    body = {
        "client_name": "Legacy Platform",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "client_secret_post",
        "require_pkce": False,
        "default_resource": RESOURCE,
    }
    body.update(overrides)
    return owner_client.post("/api/oauth/clients", json=body)


def test_classic_client_completes_flow_without_pkce_or_resource(owner_client, service):
    r = _create_classic(owner_client)
    assert r.status_code == 201, r.text
    client_id, secret = r.json()["client_id"], r.json()["client_secret"]

    # No code_challenge, no resource: a plain OAuth 2.0 authorization request
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI, "state": "s1",
    }, follow_redirects=False)
    assert r.status_code == 302, r.text
    location = r.headers["location"]
    assert location.startswith(REDIRECT_URI), location  # console-registered -> consent skipped
    code = parse_qs(urlparse(location).query)["code"][0]

    # Token exchange with the secret only (no code_verifier, no resource)
    r = owner_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "client_secret": secret,
        "code": code, "redirect_uri": REDIRECT_URI,
    })
    assert r.status_code == 200, r.text
    claims = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert claims["aud"] == RESOURCE  # default_resource decided the audience

    # A wrong secret cannot redeem a PKCE-less code
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI,
    }, follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    r = owner_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "client_secret": "wrong",
        "code": code, "redirect_uri": REDIRECT_URI,
    })
    assert r.status_code == 401


def test_public_and_dcr_clients_still_need_pkce(client, owner_client, service):
    # Console-registered public client cannot opt out
    r = _create_classic(owner_client, token_endpoint_auth_method="none")
    assert r.status_code == 400, r.text

    # Dynamic registration ignores/rejects the flag
    r = client.post("/oauth/register", json={
        "client_name": "x", "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "client_secret_post",
        "require_pkce": False,
    })
    assert r.status_code == 400, r.text

    # A normal public client without code_challenge is refused
    public = _register(client)
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": public["client_id"], "redirect_uri": REDIRECT_URI,
        "resource": RESOURCE,
    }, follow_redirects=False)
    assert r.status_code == 302
    assert "error=invalid_request" in r.headers["location"]


def test_default_resource_must_be_a_registered_server(owner_client, service):
    r = _create_classic(owner_client, default_resource="http://nowhere.example/mcp")
    assert r.status_code == 400, r.text
