"""Per-server scopes: a service may declare scopes of its own next to the global registry."""

from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _exchange, _register


def _declare(owner_client, service_id, name, description="", is_default=False):
    r = owner_client.put(f"/api/oauth/services/{service_id}/scopes/{name}",
                         json={"description": description, "is_default": is_default})
    assert r.status_code == 200, r.text
    return r.json()


def _other_service(owner_client, port=8124):
    r = owner_client.post("/api/services", json={"name": f"other-{port}", "host": "127.0.0.1", "port": port,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    assert r.status_code == 201, r.text
    return r.json()


def test_declare_list_and_delete(owner_client, service):
    sid = service["id"]
    assert owner_client.get(f"/api/oauth/services/{sid}/scopes").json()["own"] == []
    _declare(owner_client, sid, "files:read", "Read files", is_default=True)
    _declare(owner_client, sid, "files:write", "Write files")
    body = owner_client.get(f"/api/oauth/services/{sid}/scopes").json()
    assert [s["name"] for s in body["own"]] == ["files:read", "files:write"]
    assert body["own"][0]["is_default"] is True and body["own"][0]["service_id"] == sid
    eff = {s["name"]: s["source"] for s in body["effective"]}
    assert eff["files:read"] == "service" and eff["mcp:tools:read"] == "global"

    # audited
    actions = [e for e in owner_client.get("/api/audit/logs").json()["logs"] if e["action"] == "oauth_scope_upsert"]
    assert len(actions) == 2 and actions[0]["details"]["scope"] == "service"

    assert owner_client.delete(f"/api/oauth/services/{sid}/scopes/files:write").status_code == 200
    assert owner_client.delete(f"/api/oauth/services/{sid}/scopes/files:write").status_code == 404
    assert [s["name"] for s in owner_client.get(f"/api/oauth/services/{sid}/scopes").json()["own"]] == ["files:read"]
    # invalid names / unknown service
    assert owner_client.put(f"/api/oauth/services/{sid}/scopes/bad%20name", json={}).status_code == 400
    assert owner_client.put("/api/oauth/services/00000000-0000-0000-0000-000000000000/scopes/x", json={}).status_code == 404


def test_global_and_service_names_stay_disjoint(owner_client, service):
    sid = service["id"]
    # a global name cannot be declared per server...
    r = owner_client.put(f"/api/oauth/services/{sid}/scopes/mcp:tools:read", json={})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "oauth.scope_is_global"
    # ...and a server-declared name cannot become global
    _declare(owner_client, sid, "files:read")
    r = owner_client.put("/api/oauth/scopes/files:read", json={"description": "x"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "oauth.scope_owned_by_service"
    # updating an existing global scope is unaffected
    assert owner_client.put("/api/oauth/scopes/mcp:tools:read", json={"description": "renamed"}).status_code == 200


def test_service_scope_grantable_only_for_its_server(owner_client, service):
    sid = service["id"]
    _declare(owner_client, sid, "files:read", "Read files")
    other = _other_service(owner_client)
    reg = _register(owner_client)

    # for the declaring server: granted, and the consent page knows the description
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"], scope="files:read mcp:tools:read")
    body = _exchange(owner_client, reg["client_id"], code, verifier).json()
    assert set(body["scope"].split()) == {"files:read", "mcp:tools:read"}

    # for another server: unknown scope
    from tests.conftest import make_pkce
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s",
        "resource": other["effective_audience"], "scope": "files:read",
    }, follow_redirects=False)
    assert r.status_code == 302 and "error=invalid_scope" in r.headers["location"]

    # discovery lists the union
    assert "files:read" in owner_client.get("/.well-known/oauth-authorization-server").json()["scopes_supported"]
    # and a client may register asking for it
    assert _register(owner_client, scope="files:read")["scope"] == "files:read"


def test_consent_page_describes_service_scope(owner_client, service):
    from urllib.parse import parse_qs, urlparse
    from tests.conftest import make_pkce

    _declare(owner_client, service["id"], "files:read", "Read files on this server")
    reg = _register(owner_client)
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s", "resource": RESOURCE,
        "scope": "files:read",
    }, follow_redirects=False)
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    info = owner_client.get(f"/oauth/authorize/requests/{rid}").json()
    assert info["scopes"] == [{"name": "files:read", "description": "Read files on this server"}]


def test_allow_list_restricts_globals_but_not_own_scopes(owner_client, service):
    sid = service["id"]
    _declare(owner_client, sid, "files:read", is_default=True)
    r = owner_client.put(f"/api/services/{sid}", json={"oauth_scopes": ["mcp:tools:read"]})
    assert r.status_code == 200, r.text
    reg = _register(owner_client)
    # explicit: own scope + allowed global ok, other global refused
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"], scope="files:read mcp:tools:read")
    assert set(_exchange(owner_client, reg["client_id"], code, verifier).json()["scope"].split()) == {"files:read", "mcp:tools:read"}
    from tests.conftest import make_pkce
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "s", "resource": RESOURCE,
        "scope": "mcp:tools:invoke",
    }, follow_redirects=False)
    assert "error=invalid_scope" in r.headers["location"]
    # defaults: own default scope is included, global defaults limited by the allow-list
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert set(_exchange(owner_client, reg["client_id"], code, verifier).json()["scope"].split()) == {"files:read", "mcp:tools:read"}


def test_personal_token_can_carry_service_scope(owner_client, service):
    _declare(owner_client, service["id"], "files:read")
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 1,
                                                               "scopes": ["files:read"]})
    assert r.status_code == 201, r.text
    assert r.json()["scope"] == "files:read"
    other = _other_service(owner_client, 8125)
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": other["id"], "expires_days": 1,
                                                               "scopes": ["files:read"]})
    assert r.status_code == 400


def test_deleting_service_removes_its_scopes(owner_client, service):
    other = _other_service(owner_client, 8126)
    _declare(owner_client, other["id"], "files:read")
    assert owner_client.delete(f"/api/services/{other['id']}").status_code == 200
    assert "files:read" not in owner_client.get("/.well-known/oauth-authorization-server").json()["scopes_supported"]
