"""Admin-console login / first-time setup / service registration API."""

from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD


def test_setup_then_login_flow(client):
    assert client.get("/api/session/status").json()["needs_setup"] is True
    r = client.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    assert r.status_code == 200 and r.json()["user"]["email"] == OWNER_EMAIL
    assert "mcp_session" in r.cookies
    assert client.get("/api/session/status").json()["needs_setup"] is False
    # setup can only be done once
    assert client.post("/api/session/setup", json={"email": "x@y.com", "password": "another-pass"}).status_code == 409

    me = client.get("/api/session/me").json()
    assert me["email"] == OWNER_EMAIL and me["has_password"] is True

    client.post("/api/session/logout")
    assert client.get("/api/session/me").status_code == 401

    bad = client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": "wrong"})
    assert bad.status_code == 401 and bad.json()["error"] == "auth.invalid_credentials"
    ok = client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
    assert ok.status_code == 200
    assert client.get("/api/session/me").status_code == 200


def test_setup_rejects_weak_password_and_bad_email(client):
    assert client.post("/api/session/setup", json={"email": "not-an-email", "password": OWNER_PASSWORD}).status_code == 400
    assert client.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": "short"}).status_code == 400


def test_change_password_invalidates_old_session(owner_client):
    import time

    old_cookie = owner_client.cookies.get("mcp_session")
    time.sleep(1.1)  # iat in the same second as password_changed_at still counts as valid (so a login right after a
    # password change is not misjudged)
    r = owner_client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                           "new_password": "new-password-456"})
    assert r.status_code == 200
    # The response set a new cookie; putting the old cookie back must be rejected
    owner_client.cookies.set("mcp_session", old_cookie)
    assert owner_client.get("/api/session/me").status_code == 401
    login = owner_client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": "new-password-456"})
    assert login.status_code == 200


def test_bearer_session_header_works(owner_client):
    token = owner_client.cookies.get("mcp_session")
    owner_client.cookies.clear()
    assert owner_client.get("/api/session/me").status_code == 401
    assert owner_client.get("/api/session/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_service_crud(owner_client):
    r = owner_client.post("/api/services", json={"name": "svc-a", "host": "localhost", "port": 9001, "tags": ["x"]})
    assert r.status_code == 201, r.text
    svc = r.json()
    # loopback normalization + effective audience
    assert svc["host"] == "127.0.0.1"
    assert svc["effective_audience"] == "http://127.0.0.1:9001/mcp"

    dup = owner_client.post("/api/services", json={"name": "svc-a", "host": "127.0.0.1", "port": 9001})
    assert dup.status_code == 409

    r = owner_client.put(f"/api/services/{svc['id']}", json={
        "oauth_audience": "https://mcp.example.com/mcp/", "oauth_scopes": ["mcp:tools:read"], "auth_token": "static-bearer",
    })
    assert r.status_code == 200
    updated = r.json()
    assert updated["oauth_audience"] == "https://mcp.example.com/mcp"
    assert updated["oauth_scopes"] == ["mcp:tools:read"] and updated["has_static_token"] is True

    listed = owner_client.get("/api/services").json()
    assert listed["total_count"] == 1
    assert owner_client.get("/api/services/does-not-exist").status_code == 404

    assert owner_client.delete(f"/api/services/{svc['id']}").status_code == 200
    assert owner_client.get("/api/services").json()["total_count"] == 0


def test_dashboard_and_stats(owner_client, service):
    dash = owner_client.get("/api/system/dashboard").json()
    assert dash["service_health"]["total"] == 1 and dash["admin_count"] == 1
    assert "oauth" in dash
    assert owner_client.get("/api/stats/summary").json()["total_all_time"] == 0
    daily = owner_client.get("/api/stats/daily", params={"days": 3}).json()
    assert len(daily["stats"]) == 3
    assert owner_client.get("/api/system/version").json()["version"]


def test_audit_logs_recorded(owner_client, service):
    logs = owner_client.get("/api/audit/logs").json()
    actions = {entry["action"] for entry in logs["logs"]}
    assert {"admin_setup", "create_service"} <= actions
