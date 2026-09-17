"""Revocation feed and usage reports for MCP servers that verify tokens offline, plus the FastMCP helper in
examples/mcp_center_hooks.py driven against the app in-process."""

import importlib.util
import json
import pathlib
import time

import httpx
import pytest

from tests.test_oauth_flow import _authorize_and_consent, _exchange, _register


def _resource_server(client, **overrides):
    """A confidential client standing in for an MCP server."""
    reg = _register(client, client_name="Resource server", token_endpoint_auth_method="client_secret_post",
                    **overrides)
    return {"client_id": reg["client_id"], "client_secret": reg["client_secret"]}


def _issue_pat(owner_client, service, days=1):
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": days})
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# /oauth/revoked
# ---------------------------------------------------------------------------
def test_feed_requires_resource_server(owner_client, service):
    public = _register(owner_client)
    r = owner_client.post("/oauth/revoked", data={"client_id": public["client_id"]})
    assert r.status_code == 403 and r.json()["error"] == "unauthorized_client"
    r = owner_client.post("/oauth/usage", data={"client_id": public["client_id"], "events": "[]"})
    assert r.status_code == 403


def test_feed_lists_revoked_unexpired_tokens_with_since(owner_client, service):
    rs = _resource_server(owner_client)
    a = _issue_pat(owner_client, service)
    b = _issue_pat(owner_client, service)
    assert owner_client.post("/oauth/revoked", data=rs).json()["revoked"] == []

    assert owner_client.post(f"/api/oauth/tokens/{a['jti']}/revoke").status_code == 200
    feed = owner_client.post("/oauth/revoked", data=rs).json()
    assert [x["jti"] for x in feed["revoked"]] == [a["jti"]]
    assert feed["revoked"][0]["exp"] > feed["now"] >= feed["revoked"][0]["revoked_at"]

    # `since` in the future hides it; `since` in the past keeps it; garbage is rejected
    assert owner_client.post("/oauth/revoked", data={**rs, "since": str(feed["now"] + 60)}).json()["revoked"] == []
    assert len(owner_client.post("/oauth/revoked", data={**rs, "since": str(feed["now"] - 60)}).json()["revoked"]) == 1
    assert owner_client.post("/oauth/revoked", data={**rs, "since": "yesterday"}).status_code == 400

    # revoking the client of an authorization-code flow revokes its access token too, and that shows up
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    assert owner_client.post(f"/api/oauth/clients/{reg['client_id']}/revoke").status_code == 200
    jtis = {x["jti"] for x in owner_client.post("/oauth/revoked", data=rs).json()["revoked"]}
    assert a["jti"] in jtis and b["jti"] not in jtis
    assert any(j != a["jti"] for j in jtis), "the access token of the revoked client should be listed"
    assert tokens["access_token"]


def test_feed_omits_expired_tokens(owner_client, service, db_session):
    from datetime import timedelta
    from src.adapters import OAuthTokenAdapter
    from db.models import local_now

    rs = _resource_server(owner_client)
    pat = _issue_pat(owner_client, service)
    assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
    rec = OAuthTokenAdapter.get(db_session, pat["jti"])
    rec.expires_at = local_now() - timedelta(seconds=1)
    db_session.commit()
    assert owner_client.post("/oauth/revoked", data=rs).json()["revoked"] == []


# ---------------------------------------------------------------------------
# /oauth/usage
# ---------------------------------------------------------------------------
def test_usage_report_updates_counters_and_stats(owner_client, service):
    rs = _resource_server(owner_client)
    pat = _issue_pat(owner_client, service)
    before = owner_client.get("/api/stats/summary").json()["total_all_time"]
    now = int(time.time())
    events = [{"jti": pat["jti"], "count": 7, "last_seen": now - 30}, {"jti": "nope", "count": 1}]
    r = owner_client.post("/oauth/usage", data={**rs, "events": json.dumps(events)})
    assert r.status_code == 200, r.text
    assert r.json() == {"accepted": 1, "unknown": ["nope"]}

    tok = owner_client.get(f"/api/oauth/tokens/{pat['jti']}").json()
    assert tok["use_count"] == 7 and tok["last_used_at"]
    assert owner_client.get("/api/stats/summary").json()["total_all_time"] == before + 7

    # a later batch with an older last_seen does not move last_used_at backwards
    r = owner_client.post("/oauth/usage", data={**rs, "events": json.dumps([{"jti": pat["jti"], "count": 2,
                                                                              "last_seen": now - 3600}])})
    assert r.status_code == 200
    tok2 = owner_client.get(f"/api/oauth/tokens/{pat['jti']}").json()
    assert tok2["use_count"] == 9 and tok2["last_used_at"] == tok["last_used_at"]

    for bad in ("not json", json.dumps({"jti": "x"}), json.dumps([{"count": 1}]), json.dumps([{"jti": "x", "count": "many"}])):
        assert owner_client.post("/oauth/usage", data={**rs, "events": bad}).status_code == 400


def test_metadata_advertises_extension_endpoints(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["revoked_tokens_endpoint"] == "http://testserver/oauth/revoked"
    assert meta["usage_report_endpoint"] == "http://testserver/oauth/usage"


# ---------------------------------------------------------------------------
# examples/mcp_center_hooks.py against the app, in-process
# ---------------------------------------------------------------------------
def _load_hooks_module():
    path = pathlib.Path(__file__).resolve().parents[1] / "examples" / "mcp_center_hooks.py"
    spec = importlib.util.spec_from_file_location("mcp_center_hooks", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_verifier_rejects_after_poll_and_reports_usage(owner_client, service, app):
    hooks = _load_hooks_module()
    rs = _resource_server(owner_client)
    pat = _issue_pat(owner_client, service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        verifier = hooks.MCPCenterVerifier(
            jwks_uri="http://testserver/.well-known/jwks.json", issuer="http://testserver",
            audience=service["effective_audience"], client_id=rs["client_id"], client_secret=rs["client_secret"],
            http_client=http, poll_interval=1000, flush_interval=1000,
        )
        # valid token verifies (twice) and is counted locally
        assert (await verifier.verify_token(pat["access_token"])) is not None
        assert (await verifier.verify_token(pat["access_token"])) is not None
        assert verifier._pending[pat["jti"]][0] == 2
        assert (await verifier.verify_token("garbage")) is None

        # owner revokes it in the console; the next poll makes the verifier refuse it, usage is flushed
        assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
        await verifier.sync_once()
        assert pat["jti"] in verifier._revoked
        assert (await verifier.verify_token(pat["access_token"])) is None
        assert verifier._pending == {}
        tok = owner_client.get(f"/api/oauth/tokens/{pat['jti']}").json()
        assert tok["use_count"] == 2
        if verifier._task:
            verifier._task.cancel()


@pytest.mark.asyncio
async def test_verifier_with_private_key_jwt_client(owner_client, service, app):
    from tests.test_oauth_private_key_jwt import rsa_keypair

    hooks = _load_hooks_module()
    pem, jwk, _ = rsa_keypair("srv-1")
    reg = _register(owner_client, client_name="RS (key)", token_endpoint_auth_method="private_key_jwt",
                    jwks={"keys": [jwk]})
    pat = _issue_pat(owner_client, service)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        verifier = hooks.MCPCenterVerifier(
            jwks_uri="http://testserver/.well-known/jwks.json", issuer="http://testserver",
            audience=service["effective_audience"], client_id=reg["client_id"], private_key_pem=pem, kid="srv-1",
            http_client=http, poll_interval=1000, flush_interval=1000,
        )
        assert (await verifier.verify_token(pat["access_token"])) is not None
        await verifier.sync_once()  # both endpoints accept the assertion
        assert owner_client.get(f"/api/oauth/tokens/{pat['jti']}").json()["use_count"] == 1
        if verifier._task:
            verifier._task.cancel()
