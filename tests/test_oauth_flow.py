"""OAuth 2.1 end to end: discovery -> DCR -> authorize + consent -> token (PKCE) -> introspect -> refresh -> revoke."""

from urllib.parse import parse_qs, urlparse

import jwt
import pytest

from tests.conftest import make_pkce

REDIRECT_URI = "http://localhost:9999/callback"
RESOURCE = "http://127.0.0.1:8123/mcp"


def _register(client, **overrides):
    body = {
        "client_name": "Test MCP Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
    }
    body.update(overrides)
    r = client.post("/oauth/register", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _authorize_and_consent(client, client_id, *, scope=None, resource=RESOURCE, remember=False):
    verifier, challenge = make_pkce()
    params = {
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz",
    }
    if scope:
        params["scope"] = scope
    if resource:
        params["resource"] = resource
    r = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert r.status_code == 302, r.text
    location = r.headers["location"]
    if location.startswith("/consent"):
        rid = parse_qs(urlparse(location).query)["rid"][0]
        info = client.get(f"/oauth/authorize/requests/{rid}").json()
        assert info["client"]["client_id"] == client_id
        d = client.post(f"/oauth/authorize/requests/{rid}/decision", json={"approve": True, "remember": remember})
        assert d.status_code == 200, d.text
        location = d.json()["redirect_to"]
    q = parse_qs(urlparse(location).query)
    assert q["state"] == ["xyz"]
    assert q["iss"] == ["http://testserver"]
    return q["code"][0], verifier


def _exchange(client, client_id, code, verifier, resource=RESOURCE):
    data = {
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "redirect_uri": REDIRECT_URI, "code_verifier": verifier,
    }
    if resource:
        data["resource"] = resource
    return client.post("/oauth/token", data=data)


def _jwks_key(client, token):
    jwks = client.get("/.well-known/jwks.json").json()
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in jwks["keys"] if k["kid"] == kid)
    return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)


# ---------------------------------------------------------------------------

def test_discovery_metadata(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == "http://testserver"
    assert meta["authorization_endpoint"] == "http://testserver/oauth/authorize"
    assert meta["token_endpoint"] == "http://testserver/oauth/token"
    assert meta["registration_endpoint"] == "http://testserver/oauth/register"
    assert meta["jwks_uri"] == "http://testserver/.well-known/jwks.json"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "mcp:tools:invoke" in meta["scopes_supported"]
    assert client.get("/.well-known/openid-configuration").json()["issuer"] == meta["issuer"]
    jwks = client.get("/.well-known/jwks.json").json()
    assert jwks["keys"] and jwks["keys"][0]["kty"] == "RSA" and "kid" in jwks["keys"][0]


def test_dcr_public_client(client):
    reg = _register(client)
    assert reg["client_id"].startswith("mcpc_")
    assert "client_secret" not in reg
    assert reg["token_endpoint_auth_method"] == "none"


def test_dcr_rejects_bad_redirect(client):
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["http://evil.example.com/cb"]})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


def test_dcr_confidential_client_gets_secret_once(client):
    reg = _register(client, token_endpoint_auth_method="client_secret_post",
                    grant_types=["client_credentials"], redirect_uris=[])
    assert reg["client_secret"]
    r = client.get("/oauth/register")  # no such GET
    assert r.status_code in (404, 405)


def test_authorize_requires_login_then_consent(client, service):
    """Not logged in -> redirected to /consent (the SPA then redirects to login); consent after login -> code."""
    client.post("/api/session/logout")  # the service fixture logged in with this same client
    reg = _register(client)
    verifier, challenge = make_pkce()
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE,
    }, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/consent?rid=")
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    # Consent page data cannot be read without being logged in
    assert client.get(f"/oauth/authorize/requests/{rid}").status_code == 401


def test_full_authorization_code_flow(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])

    r = _exchange(owner_client, reg["client_id"], code, verifier)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "Bearer" and body["refresh_token"] and body["expires_in"] > 0
    assert "mcp:tools:invoke" in body["scope"].split()

    # Verify offline with the JWKS (= what FastMCP JWTVerifier does): iss / aud / scope
    claims = jwt.decode(body["access_token"], _jwks_key(owner_client, body["access_token"]),
                        algorithms=["RS256"], audience=RESOURCE, issuer="http://testserver")
    assert claims["client_id"] == reg["client_id"]
    assert claims["email"] == "owner@example.com"
    assert claims["token_use"] == "access"
    assert jwt.get_unverified_header(body["access_token"])["typ"] == "at+jwt"

    # introspect (public client sends only client_id)
    intro = owner_client.post("/oauth/introspect", data={"token": body["access_token"], "client_id": reg["client_id"]}).json()
    assert intro["active"] is True and intro["aud"] == RESOURCE and intro["sub"] == claims["sub"]

    # Reusing the same code -> invalid_grant, and (RFC 6749 section 4.1.2) every token exchanged from it is revoked
    r2 = _exchange(owner_client, reg["client_id"], code, verifier)
    assert r2.status_code == 400 and r2.json()["error"] == "invalid_grant"
    intro = owner_client.post("/oauth/introspect", data={"token": body["access_token"], "client_id": reg["client_id"]}).json()
    assert intro["active"] is False


def test_pkce_mismatch_rejected(owner_client, service):
    reg = _register(owner_client)
    code, _verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = _exchange(owner_client, reg["client_id"], code, "wrong-verifier-wrong-verifier-wrong-verifier")
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_unknown_resource_rejected(owner_client, service):
    reg = _register(owner_client)
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s1",
        "resource": "http://unknown.example.com/mcp",
    }, follow_redirects=False)
    # Unknown resource -> safe to redirect back to redirect_uri with error=invalid_target
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["error"] == ["invalid_target"] and q["state"] == ["s1"]


def test_unregistered_redirect_uri_not_redirected(owner_client, service):
    reg = _register(owner_client)
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": "http://localhost:1/other",
        "code_challenge": challenge, "code_challenge_method": "S256",
    }, follow_redirects=False)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"


def test_refresh_rotation_and_replay_detection(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    first = _exchange(owner_client, reg["client_id"], code, verifier).json()

    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": first["refresh_token"]})
    assert r.status_code == 200, r.text
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"]

    # Replaying the old refresh token -> rejected, and the whole chain (incl. the just-issued tokens) is revoked
    replay = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                     "refresh_token": first["refresh_token"]})
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    intro = owner_client.post("/oauth/introspect", data={"token": second["access_token"], "client_id": reg["client_id"]}).json()
    assert intro["active"] is False


def test_revoke_endpoint(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    r = owner_client.post("/oauth/revoke", data={"token": tokens["access_token"], "client_id": reg["client_id"]})
    assert r.status_code == 200
    intro = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], "client_id": reg["client_id"]}).json()
    assert intro["active"] is False
    # Revoking someone else's / garbage tokens also returns 200 (no information leak)
    assert owner_client.post("/oauth/revoke", data={"token": "garbage", "client_id": reg["client_id"]}).status_code == 200


def test_consent_remembered_skips_second_time(owner_client, service):
    reg = _register(owner_client)
    _authorize_and_consent(owner_client, reg["client_id"], remember=True)
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE, "state": "again",
    }, follow_redirects=False)
    # The second time the client is redirected with the code directly, without passing through /consent
    assert r.status_code == 302 and r.headers["location"].startswith(REDIRECT_URI)
    assert "code=" in r.headers["location"]
    consents = owner_client.get("/api/oauth/consents").json()["consents"]
    assert len(consents) == 1 and consents[0]["client_id"] == reg["client_id"]


def test_manual_client_skips_consent(owner_client, service):
    r = owner_client.post("/api/oauth/clients", json={"client_name": "My trusted client", "redirect_uris": [REDIRECT_URI]})
    assert r.status_code == 201, r.text
    client_id = r.json()["client_id"]
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE,
    }, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith(REDIRECT_URI)


def test_client_credentials_grant(owner_client, service):
    reg = _register(owner_client, token_endpoint_auth_method="client_secret_basic",
                    grant_types=["client_credentials"], redirect_uris=[])
    r = owner_client.post("/oauth/token", data={"grant_type": "client_credentials", "resource": RESOURCE,
                                                "scope": "mcp:tools:read"},
                          auth=(reg["client_id"], reg["client_secret"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"] == "mcp:tools:read" and "refresh_token" not in body
    claims = jwt.decode(body["access_token"], _jwks_key(owner_client, body["access_token"]),
                        algorithms=["RS256"], audience=RESOURCE)
    assert claims["sub"] == reg["client_id"]
    bad = owner_client.post("/oauth/token", data={"grant_type": "client_credentials"},
                            auth=(reg["client_id"], "wrong"))
    assert bad.status_code == 401 and bad.json()["error"] == "invalid_client"


def test_scope_restrictions(owner_client, service):
    reg = _register(owner_client, scope="mcp:tools:read")
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE,
        "scope": "mcp:tools:read mcp:tools:invoke", "state": "sc",
    }, follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["error"] == ["invalid_scope"]


def test_personal_access_token(owner_client, service):
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 7,
                                                               "label": "laptop"})
    assert r.status_code == 201, r.text
    pat = r.json()
    assert pat["kind"] == "pat" and pat["label"] == "laptop"
    claims = jwt.decode(pat["access_token"], _jwks_key(owner_client, pat["access_token"]),
                        algorithms=["RS256"], audience=RESOURCE, issuer="http://testserver")
    assert claims["client_id"] == "mcp-center-console"

    listed = owner_client.get("/api/oauth/tokens", params={"kind": "pat"}).json()["tokens"]
    assert [t["jti"] for t in listed] == [pat["jti"]]

    assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
    intro = owner_client.post("/oauth/introspect", data={"token": pat["access_token"], "client_id": "mcp-center-console"}).json()
    assert intro["active"] is False


def test_admin_client_management(owner_client):
    reg = _register(owner_client)
    listed = owner_client.get("/api/oauth/clients").json()["clients"]
    assert any(c["client_id"] == reg["client_id"] for c in listed)
    r = owner_client.post(f"/api/oauth/clients/{reg['client_id']}/revoke")
    assert r.status_code == 200 and r.json()["is_active"] is False
    # No more codes once the client is deactivated
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }, follow_redirects=False)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client"
    assert owner_client.delete(f"/api/oauth/clients/{reg['client_id']}").status_code == 200


def test_key_rotation_keeps_old_tokens_verifiable(owner_client, service):
    pat = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 1}).json()
    r = owner_client.post("/api/oauth/keys/rotate")
    assert r.status_code == 200
    keys = owner_client.get("/api/oauth/keys").json()["keys"]
    assert len(keys) == 2 and sum(1 for k in keys if k["is_active"]) == 1
    jwks = owner_client.get("/.well-known/jwks.json").json()
    assert len(jwks["keys"]) == 2
    # Old tokens still verify with the old public key kept in the JWKS
    jwt.decode(pat["access_token"], _jwks_key(owner_client, pat["access_token"]), algorithms=["RS256"],
               audience=RESOURCE)
    # New tokens use the new kid
    pat2 = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 1}).json()
    assert jwt.get_unverified_header(pat2["access_token"])["kid"] != jwt.get_unverified_header(pat["access_token"])["kid"]


def test_snippets(owner_client, service):
    s = owner_client.get(f"/api/oauth/snippets/{service['id']}").json()
    assert "JWTVerifier" in s["fastmcp_server"]
    assert s["audience"] == RESOURCE and s["issuer"] == "http://testserver"
    assert s["mcp_json_oauth"]["mcpServers"]["demo-mcp"]["url"] == RESOURCE


@pytest.mark.parametrize("path", ["/api/oauth/clients", "/api/oauth/tokens", "/api/services", "/api/session/me"])
def test_admin_endpoints_require_login(client, path):
    assert client.get(path).status_code == 401
