"""Refresh tokens are for the token endpoint only: never usable as a Bearer token at a resource server."""

import jwt
import httpx
import pytest

from tests.test_oauth_flow import RESOURCE, _authorize_and_consent, _exchange, _register, _register_console
from tests.test_offline_hooks import _load_hooks_module


def _flow(owner_client):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    return reg, tokens


def test_refresh_token_audience_is_not_the_resource(owner_client, service):
    _reg, tokens = _flow(owner_client)
    claims = jwt.decode(tokens["refresh_token"], options={"verify_signature": False})
    assert claims["token_use"] == "refresh"
    assert claims["aud"] != RESOURCE
    assert claims["aud"] == "http://testserver/oauth/token"
    assert jwt.get_unverified_header(tokens["refresh_token"])["typ"] == "refresh+jwt"


@pytest.mark.asyncio
async def test_fastmcp_jwt_verifier_rejects_refresh_token(owner_client, service, app):
    """H-02: the snippet MCP Gate generates (plain JWTVerifier with the server's audience)."""
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    _reg, tokens = _flow(owner_client)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        verifier = JWTVerifier(jwks_uri="http://testserver/.well-known/jwks.json", issuer="http://testserver",
                               audience=RESOURCE, http_client=http)
        assert await verifier.verify_token(tokens["access_token"]) is not None
        assert await verifier.verify_token(tokens["refresh_token"]) is None


@pytest.mark.asyncio
async def test_mcp_gate_verifier_rejects_non_access_tokens(owner_client, service, app, db_session):
    """Refresh JWTs issued by earlier releases carried the server's audience; MCPGateVerifier refuses them by
    token_use even then."""
    from src.oauth import service as oauth

    hooks = _load_hooks_module()
    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    legacy = oauth._sign(db_session, {"iss": "http://testserver", "sub": "u", "client_id": "c", "scope": "",
                                      "iat": 1, "exp": 4102444800, "jti": "legacy-rt", "token_use": "refresh",
                                      "aud": RESOURCE}, typ="refresh+jwt")
    _reg, tokens = _flow(owner_client)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        verifier = hooks.MCPGateVerifier(
            jwks_uri="http://testserver/.well-known/jwks.json", issuer="http://testserver", audience=RESOURCE,
            client_id=rs["client_id"], client_secret=rs["client_secret"], http_client=http,
            poll_interval=1000, flush_interval=1000,
        )
        assert await verifier.verify_token(tokens["access_token"]) is not None
        assert await verifier.verify_token(legacy) is None
        assert "legacy-rt" not in verifier._pending
        if verifier._task:
            verifier._task.cancel()


def test_revoked_refresh_token_is_in_the_feed(owner_client, service):
    """A revoked refresh token is listed (older verifiers may still accept the legacy audience-bearing ones);
    routine rotation is not, so the feed does not grow with every refresh."""
    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    creds = {"client_id": rs["client_id"], "client_secret": rs["client_secret"]}
    reg, tokens = _flow(owner_client)
    rotated = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                      "refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200, rotated.text
    first_jti = jwt.decode(tokens["refresh_token"], options={"verify_signature": False})["jti"]
    assert first_jti not in {x["jti"] for x in owner_client.post("/oauth/revoked", data=creds).json()["revoked"]}

    second = rotated.json()["refresh_token"]
    second_jti = jwt.decode(second, options={"verify_signature": False})["jti"]
    assert owner_client.post("/oauth/revoke", data={"token": second, "client_id": reg["client_id"]}).status_code == 200
    jtis = {x["jti"] for x in owner_client.post("/oauth/revoked", data=creds).json()["revoked"]}
    assert second_jti in jtis


def test_rotation_and_reuse_detection_still_work(owner_client, service):
    reg, tokens = _flow(owner_client)
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"], "resource": RESOURCE})
    assert r.status_code == 200, r.text
    new = r.json()
    claims = jwt.decode(new["access_token"], options={"verify_signature": False})
    assert claims["aud"] == RESOURCE and claims["token_use"] == "access"
    replay = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                     "refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 400
    assert owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                   "refresh_token": new["refresh_token"]}).status_code == 400


def test_access_token_cannot_be_used_as_refresh_token(owner_client, service):
    reg, tokens = _flow(owner_client)
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["access_token"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
