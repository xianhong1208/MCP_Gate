"""Who counts as a resource server (revocation feed, introspecting other clients' tokens, usage reports).

Only a confidential client the owner registered in the console and bound to one server is one, and it sees only
tokens whose audience is that server. A dynamically registered client is never one, whatever auth method it
picked."""

import json
import time

from tests.test_oauth_flow import RESOURCE, _authorize_and_consent, _exchange, _register, _register_console


def _pat(owner_client, service, label="t"):
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 1,
                                                              "label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _other_service(owner_client):
    r = owner_client.post("/api/services", json={"name": "other-mcp", "host": "127.0.0.1", "port": 8124,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    assert r.status_code == 201, r.text
    return r.json()


def _creds(reg):
    return {"client_id": reg["client_id"], "client_secret": reg["client_secret"]}


# ---------------------------------------------------------------------------
# H-07: an anonymous DCR confidential client is not a resource server
# ---------------------------------------------------------------------------
def test_dcr_confidential_client_is_not_a_resource_server(owner_client, service):
    pat = _pat(owner_client, service)
    assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
    live = _pat(owner_client, service, "live")
    dcr = _register(owner_client, client_name="nosy", token_endpoint_auth_method="client_secret_basic")
    auth = (dcr["client_id"], dcr["client_secret"])

    r = owner_client.post("/oauth/revoked", auth=auth)
    assert r.status_code == 403 and r.json()["error"] == "unauthorized_client"

    peek = owner_client.post("/oauth/introspect", data={"token": live["access_token"]}, auth=auth).json()
    assert peek == {"active": False}

    events = [{"jti": live["jti"], "count": 999999, "last_seen": 4102444800}]
    r = owner_client.post("/oauth/usage", data={"events": json.dumps(events)}, auth=auth)
    assert r.status_code == 403
    tok = owner_client.get(f"/api/oauth/tokens/{live['jti']}").json()
    assert tok["use_count"] == 0 and tok["last_used_at"] is None


def test_dcr_client_still_introspects_its_own_tokens(owner_client, service):
    dcr = _register(owner_client, token_endpoint_auth_method="client_secret_post")
    code, verifier = _authorize_and_consent(owner_client, dcr["client_id"])
    tokens = owner_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": "http://localhost:9999/callback",
        "code_verifier": verifier, "resource": RESOURCE, **_creds(dcr)}).json()
    seen = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], **_creds(dcr)}).json()
    assert seen["active"] is True


# ---------------------------------------------------------------------------
# bound resource servers see only their own audience
# ---------------------------------------------------------------------------
def test_bound_resource_server_sees_only_its_audience(owner_client, service):
    other = _other_service(owner_client)
    rs = _register_console(owner_client, client_name="demo RS", resource_service_id=service["id"])
    assert owner_client.get(f"/api/oauth/clients/{rs['client_id']}").json()["resource_audience"] == RESOURCE
    mine, theirs = _pat(owner_client, service, "mine"), _pat(owner_client, other, "theirs")

    a = owner_client.post("/oauth/introspect", data={"token": mine["access_token"], **_creds(rs)}).json()
    assert a["active"] is True and a["aud"] == RESOURCE
    b = owner_client.post("/oauth/introspect", data={"token": theirs["access_token"], **_creds(rs)}).json()
    assert b == {"active": False}

    for t in (mine, theirs):
        assert owner_client.post(f"/api/oauth/tokens/{t['jti']}/revoke").status_code == 200
    feed = owner_client.post("/oauth/revoked", data=_creds(rs)).json()
    assert [x["jti"] for x in feed["revoked"]] == [mine["jti"]]

    now = int(time.time())
    events = [{"jti": mine["jti"], "count": 2, "last_seen": now}, {"jti": theirs["jti"], "count": 5}]
    r = owner_client.post("/oauth/usage", data={"events": json.dumps(events), **_creds(rs)})
    assert r.status_code == 200 and r.json() == {"accepted": 1, "unknown": [theirs["jti"]]}
    assert owner_client.get(f"/api/oauth/tokens/{theirs['jti']}").json()["use_count"] == 0


def test_resource_server_cannot_introspect_refresh_tokens_of_others(owner_client, service):
    rs = _register_console(owner_client, client_name="demo RS", resource_service_id=service["id"])
    app = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, app["client_id"])
    tokens = _exchange(owner_client, app["client_id"], code, verifier).json()
    seen = owner_client.post("/oauth/introspect", data={"token": tokens["refresh_token"], **_creds(rs)}).json()
    assert seen == {"active": False}
    seen = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], **_creds(rs)}).json()
    assert seen["active"] is True


def test_binding_can_be_changed_from_the_console(owner_client, service):
    other = _other_service(owner_client)
    rs = _register_console(owner_client, client_name="RS")
    r = owner_client.put(f"/api/oauth/clients/{rs['client_id']}/resource-server", json={"service_id": other["id"]})
    assert r.status_code == 200, r.text
    assert r.json()["resource_audience"] == other["effective_audience"]
    mine = _pat(owner_client, service)
    assert owner_client.post("/oauth/introspect", data={"token": mine["access_token"], **_creds(rs)}).json() == \
        {"active": False}
    r = owner_client.put(f"/api/oauth/clients/{rs['client_id']}/resource-server", json={"service_id": None})
    assert r.status_code == 200 and r.json()["resource_audience"] is None
    # an unbound console client is not a resource server either
    assert owner_client.post("/oauth/introspect", data={"token": mine["access_token"], **_creds(rs)}).json() == \
        {"active": False}
    assert owner_client.post("/oauth/revoked", data=_creds(rs)).status_code == 403


def test_binding_rules(owner_client, service):
    public = _register_console(owner_client, client_name="pub", token_endpoint_auth_method="none",
                               grant_types=["authorization_code"], redirect_uris=["http://localhost:9999/callback"])
    r = owner_client.put(f"/api/oauth/clients/{public['client_id']}/resource-server",
                         json={"service_id": service["id"]})
    assert r.status_code == 400
    dcr = _register(owner_client, token_endpoint_auth_method="client_secret_post")
    r = owner_client.put(f"/api/oauth/clients/{dcr['client_id']}/resource-server", json={"service_id": service["id"]})
    assert r.status_code == 400
    r = owner_client.post("/api/oauth/clients", json={
        "client_name": "x", "grant_types": ["client_credentials"], "token_endpoint_auth_method": "client_secret_post",
        "resource_service_id": "00000000-0000-0000-0000-000000000000"})
    assert r.status_code == 400
    # DCR cannot ask for a binding: the field is ignored
    r = owner_client.post("/oauth/register", json={
        "redirect_uris": ["http://localhost:9999/callback"], "token_endpoint_auth_method": "client_secret_post",
        "resource_service_id": service["id"]})
    assert r.status_code == 201
    assert owner_client.get(f"/api/oauth/clients/{r.json()['client_id']}").json()["resource_audience"] is None


# ---------------------------------------------------------------------------
# H-17a: usage report counts are validated
# ---------------------------------------------------------------------------
def test_usage_count_is_bounded(owner_client, service):
    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    pat = _pat(owner_client, service)
    for raw in ('[{"jti": "%s", "count": 1000000000000000000000000000000}]' % pat["jti"],
                '[{"jti": "%s", "count": 1e400}]' % pat["jti"],
                '[{"jti": "%s", "count": -5}]' % pat["jti"],
                '[{"jti": "%s", "count": 0}]' % pat["jti"],
                '[{"jti": "%s", "count": 1, "last_seen": 1e400}]' % pat["jti"],
                '[{"jti": "%s", "count": 1, "last_seen": 1e300}]' % pat["jti"]):
        r = owner_client.post("/oauth/usage", data={"events": raw, **_creds(rs)})
        assert r.status_code == 400, (raw, r.status_code, r.text)
        assert r.json()["error"] == "invalid_request"
    assert owner_client.get(f"/api/oauth/tokens/{pat['jti']}").json()["use_count"] == 0


def test_usage_last_seen_in_the_future(owner_client, service):
    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    pat = _pat(owner_client, service)
    events = [{"jti": pat["jti"], "count": 1, "last_seen": 4102444800}]  # 2100-01-01
    assert owner_client.post("/oauth/usage", data={"events": json.dumps(events), **_creds(rs)}).status_code == 400
    # a little clock skew is tolerated and clamped to now
    events = [{"jti": pat["jti"], "count": 1, "last_seen": int(time.time()) + 60}]
    assert owner_client.post("/oauth/usage", data={"events": json.dumps(events), **_creds(rs)}).status_code == 200
    tok = owner_client.get(f"/api/oauth/tokens/{pat['jti']}").json()
    assert tok["use_count"] == 1 and tok["last_used_at"].startswith(time.strftime("%Y-%m-%d"))
