"""Pins behaviour the MCP authorization spec and RFC 9207 / RFC 8414 require (already implemented; kept from
regressing): `iss` on every authorization response, and the discovery fields clients rely on, identical under the
OpenID Connect alias."""

from urllib.parse import parse_qs, urlparse

from tests.conftest import make_pkce
from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _register

ISSUER = "http://testserver"


def test_success_and_error_redirects_carry_iss(owner_client, service):
    reg = _register(owner_client)
    _authorize_and_consent(owner_client, reg["client_id"])  # asserts iss on the success redirect

    _verifier, challenge = make_pkce()
    base = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": "st"}
    # error at /authorize itself (redirectable)
    r = owner_client.get("/oauth/authorize", params={**base, "resource": "http://nope.example/mcp"},
                         follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["error"] == ["invalid_target"] and q["iss"] == [ISSUER] and q["state"] == ["st"]
    # the user denies
    r = owner_client.get("/oauth/authorize", params={**base, "resource": RESOURCE}, follow_redirects=False)
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    loc = owner_client.post(f"/oauth/authorize/requests/{rid}/decision", json={"approve": False}).json()["redirect_to"]
    q = parse_qs(urlparse(loc).query)
    assert q["error"] == ["access_denied"] and q["iss"] == [ISSUER]


def test_metadata_fields_and_openid_alias(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["authorization_response_iss_parameter_supported"] is True
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "none" in meta["token_endpoint_auth_methods_supported"]
    assert client.get("/.well-known/openid-configuration").json() == meta
