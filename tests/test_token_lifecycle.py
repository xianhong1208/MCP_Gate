"""Tokens follow the lifecycle of what they were issued for: a deleted client, a disabled server, a disabled user."""

from tests.test_oauth_flow import RESOURCE, _authorize_and_consent, _exchange, _register, _register_console


def _rs(owner_client, service):
    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    return {"client_id": rs["client_id"], "client_secret": rs["client_secret"]}


def _disable(owner_client, service):
    r = owner_client.put(f"/api/services/{service['id']}", json={"is_active": False})
    assert r.status_code == 200, r.text


def test_deleting_a_client_revokes_its_tokens(owner_client, service):
    """H-11"""
    rs = _rs(owner_client, service)
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    assert owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], **rs}).json()["active"]

    assert owner_client.delete(f"/api/oauth/clients/{reg['client_id']}").status_code == 200
    assert owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], **rs}).json() == \
        {"active": False}
    listed = owner_client.get("/api/oauth/tokens", params={"include_inactive": True}).json()["tokens"]
    mine = [t for t in listed if t["client_deleted"]]
    assert len(mine) == 2 and all(t["status"] == "revoked" and t["revoke_reason"] == "client_deleted" for t in mine)
    feed = {x["jti"] for x in owner_client.post("/oauth/revoked", data=rs).json()["revoked"]}
    assert {t["jti"] for t in mine} <= feed


def test_refresh_refused_for_disabled_service(owner_client, service):
    """H-12"""
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    _disable(owner_client, service)
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant", r.text
    # re-enabling the server makes the (unrotated) refresh token usable again
    assert owner_client.put(f"/api/services/{service['id']}", json={"is_active": True}).status_code == 200
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200, r.text


def test_code_exchange_refused_for_service_disabled_after_consent(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    _disable(owner_client, service)
    r = _exchange(owner_client, reg["client_id"], code, verifier)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant", r.text


def test_no_personal_access_token_for_disabled_service(owner_client, service):
    _disable(owner_client, service)
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 1,
                                                               "label": "x"})
    assert r.status_code == 400, r.text


def test_refresh_refused_for_disabled_user(owner_client, service, db_session):
    from src.adapters import AdminUserAdapter

    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    user = AdminUserAdapter.get_by_email(db_session, "owner@example.com")
    AdminUserAdapter.set_active(db_session, user, False)
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"], "resource": RESOURCE})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant", r.text
