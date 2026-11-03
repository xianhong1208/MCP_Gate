"""The OAuth protocol surface leaves an audit trail: dynamic registrations, consent decisions, code / refresh
replays and failed client authentication."""

import json
from urllib.parse import parse_qs, urlparse

from tests.conftest import make_pkce
from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _exchange, _register


def _entries(db_session, action):
    from db.models import AuditLog

    db_session.expire_all()
    return db_session.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.created_at).all()


def _pending_request(client, client_id):
    _verifier, challenge = make_pkce()
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI, "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": RESOURCE,
    }, follow_redirects=False)
    return parse_qs(urlparse(r.headers["location"]).query)["rid"][0]


def test_dynamic_registration_is_audited(client, db_session):
    reg = _register(client)
    [entry] = _entries(db_session, "oauth_client_create")
    assert entry.resource_id == reg["client_id"] and entry.actor_type == "api"
    assert entry.status == "success"
    assert json.loads(entry.details)["created_via"] == "dcr"


def test_consent_approve_and_deny_are_audited(owner_client, service, db_session):
    reg = _register(owner_client)
    _authorize_and_consent(owner_client, reg["client_id"])
    [approved] = _entries(db_session, "oauth_consent_approve")
    assert approved.resource_id == reg["client_id"] and approved.actor_type == "admin"
    details = json.loads(approved.details)
    assert details["resource"] == RESOURCE and "mcp:tools:invoke" in details["scopes"]

    rid = _pending_request(owner_client, reg["client_id"])
    d = owner_client.post(f"/oauth/authorize/requests/{rid}/decision", json={"approve": False})
    assert d.status_code == 200 and "error=access_denied" in d.json()["redirect_to"]
    [denied] = _entries(db_session, "oauth_consent_deny")
    assert denied.resource_id == reg["client_id"] and json.loads(denied.details)["scopes"] == []


def test_code_replay_is_audited(owner_client, service, db_session):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange(owner_client, reg["client_id"], code, verifier).status_code == 200
    assert _entries(db_session, "oauth_code_replay") == []
    assert _exchange(owner_client, reg["client_id"], code, verifier).status_code == 400
    [entry] = _entries(db_session, "oauth_code_replay")
    assert entry.status == "failure" and entry.resource_id == reg["client_id"]
    assert json.loads(entry.details)["revoked_tokens"] == 2


def test_refresh_reuse_is_audited(owner_client, service, db_session):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    first = _exchange(owner_client, reg["client_id"], code, verifier).json()
    form = {"grant_type": "refresh_token", "client_id": reg["client_id"], "refresh_token": first["refresh_token"]}
    assert owner_client.post("/oauth/token", data=form).status_code == 200
    assert _entries(db_session, "oauth_refresh_replay") == []
    assert owner_client.post("/oauth/token", data=form).status_code == 400
    [entry] = _entries(db_session, "oauth_refresh_replay")
    assert entry.status == "failure" and entry.resource_id == reg["client_id"]
    assert json.loads(entry.details)["revoked_tokens"] >= 2


def test_failed_client_authentication_is_audited(client, db_session):
    reg = _register(client, token_endpoint_auth_method="client_secret_post")
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": "x",
                                          "client_id": reg["client_id"], "client_secret": "wrong"})
    assert r.status_code == 401
    r = client.post("/oauth/introspect", data={"token": "x"}, auth=("mcpc_nobody", "secret"))
    assert r.status_code == 401
    entries = _entries(db_session, "oauth_client_auth_failed")
    assert [e.resource_id for e in entries] == [reg["client_id"], "mcpc_nobody"]
    assert entries[0].request_path == "/oauth/token" and entries[1].request_path == "/oauth/introspect"
    assert all(e.status == "failure" for e in entries)


def test_successful_client_authentication_is_not_audited(client, db_session):
    reg = _register(client, token_endpoint_auth_method="client_secret_post")
    client.post("/oauth/introspect", data={"token": "x", "client_id": reg["client_id"],
                                           "client_secret": reg["client_secret"]})
    assert _entries(db_session, "oauth_client_auth_failed") == []
