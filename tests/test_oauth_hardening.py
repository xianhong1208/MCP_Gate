"""Guard tests added after the backend review: introspect scope, authorization code replay, client deletion keeping
history, session invalidation, third-party login state."""

from urllib.parse import parse_qs, urlparse

from tests.conftest import OWNER_PASSWORD
from tests.test_oauth_flow import _authorize_and_consent, _exchange, _register


def test_public_client_cannot_introspect_others_tokens(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()

    # Own token -> active
    own = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], "client_id": reg["client_id"]}).json()
    assert own["active"] is True

    # Another public client (casually registered via DCR) -> cannot see it
    other = _register(owner_client, client_name="Nosy public client")
    peek = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], "client_id": other["client_id"]}).json()
    assert peek == {"active": False}

    # Confidential client (= resource server, e.g. FastMCP IntrospectionTokenVerifier) -> allowed
    rs = _register(owner_client, client_name="Resource server", token_endpoint_auth_method="client_secret_basic",
                   grant_types=["client_credentials"], redirect_uris=[])
    seen = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"]},
                             auth=(rs["client_id"], rs["client_secret"])).json()
    assert seen["active"] is True and seen["client_id"] == reg["client_id"]


def test_authorization_code_replay_revokes_family(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    first = _exchange(owner_client, reg["client_id"], code, verifier).json()
    assert _exchange(owner_client, reg["client_id"], code, verifier).status_code == 400
    # Both access and refresh tokens are revoked
    intro = owner_client.post("/oauth/introspect", data={"token": first["access_token"], "client_id": reg["client_id"]}).json()
    assert intro["active"] is False
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": first["refresh_token"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_refresh_with_different_resource_is_rejected(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    first = _exchange(owner_client, reg["client_id"], code, verifier).json()
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": first["refresh_token"],
                                                "resource": "http://127.0.0.1:9999/other"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_deleting_client_keeps_token_history(owner_client, service):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"], remember=True)
    _exchange(owner_client, reg["client_id"], code, verifier)
    before = owner_client.get("/api/oauth/tokens", params={"include_inactive": True}).json()["total"]
    assert before >= 2

    assert owner_client.delete(f"/api/oauth/clients/{reg['client_id']}").status_code == 200
    after = owner_client.get("/api/oauth/tokens", params={"include_inactive": True}).json()
    assert after["total"] == before
    orphan = [t for t in after["tokens"] if t["client_deleted"]]
    assert orphan and orphan[0]["client_name"] == "Test MCP Client" and orphan[0]["client_id"] is None
    # Consent records disappear with the client (nothing left to authorize)
    assert owner_client.get("/api/oauth/consents").json()["total"] == 0


def test_session_invalidated_after_password_change(owner_client):
    import time

    old_cookie = owner_client.cookies.get("mcp_session")
    time.sleep(1.1)
    assert owner_client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                              "new_password": "another-password-9"}).status_code == 200
    owner_client.cookies.set("mcp_session", old_cookie)
    assert owner_client.get("/api/session/me").status_code == 401


def test_external_login_callback_rejects_bad_state(client, monkeypatch):
    from src.config import Config

    cfg = Config.get_config_model()
    monkeypatch.setattr(cfg.identity.github, "client_id", "gh-id")
    monkeypatch.setattr(cfg.identity.github, "client_secret", "gh-secret")
    start = client.get("/api/session/oauth/github/start", follow_redirects=False)
    assert start.status_code == 302 and "github.com/login/oauth/authorize" in start.headers["location"]
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

    bad = client.get("/api/session/oauth/github/callback", params={"code": "x", "state": state + "tampered"},
                     follow_redirects=False)
    assert bad.status_code == 302 and "error=auth.external_login_failed" in bad.headers["location"]
    missing = client.get("/api/session/oauth/github/callback", params={"code": "x"}, follow_redirects=False)
    assert "error=auth.external_login_failed" in missing.headers["location"]


def test_services_list_loads_tools_without_n_plus_one(owner_client, service, db_session):
    from sqlalchemy import event
    from db.database import get_engine

    counter = {"n": 0}
    def _count(*_):
        counter["n"] += 1
    engine = get_engine()
    event.listen(engine, "before_cursor_execute", _count)
    try:
        for i in range(3):
            owner_client.post("/api/services", json={"name": f"svc-{i}", "host": "127.0.0.1", "port": 9100 + i})
        counter["n"] = 0
        r = owner_client.get("/api/services")
        assert r.status_code == 200 and r.json()["total_count"] == 4
        # session validation + services + one selectinload of tools; must not grow linearly with the service count
        assert counter["n"] <= 4, counter["n"]
    finally:
        event.remove(engine, "before_cursor_execute", _count)
