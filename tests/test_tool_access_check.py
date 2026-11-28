"""Checking tool access (#37, 1.6 PR 5): GET /api/services/{id}/access/check answers, for one issued token or a
"what if" subject, what MCP Gate's evaluator decides for every tool of the server. Read only.

Expected verdicts come from the model in issue #37 (deny > only > scope; tools in no scope allowed by default;
unapproved tools hidden), not from running the evaluator."""

import uuid
from datetime import datetime, timedelta

import pytest

RESOURCE = "http://127.0.0.1:8123/mcp"


@pytest.fixture
def tools(service, db_session, owner_client):
    """Four tools; three approved, `purge` left pending, and `gone` listed once then removed."""
    from src.adapters import MCPToolAdapter
    names = ("delete_file", "read_file", "search", "purge")
    MCPToolAdapter.sync_tools(db_session, service["id"], [
        {"name": n, "description": n, "inputSchema": {"type": "object"}} for n in (*names, "gone")])
    MCPToolAdapter.sync_tools(db_session, service["id"], [
        {"name": n, "description": n, "inputSchema": {"type": "object"}} for n in names])
    db_session.expire_all()
    listed = owner_client.get(f"/api/services/{service['id']}?include_tools=true").json()["tools"]
    for t in listed:
        if t["name"] in ("delete_file", "read_file", "search"):
            r = owner_client.post(f"/api/services/{service['id']}/tools/{t['id']}/approve", json={"hash": t["hash"]})
            assert r.status_code == 200, r.text
    return {t["name"]: t["id"] for t in listed}


def _check(client, service, **params):
    return client.get(f"/api/services/{service['id']}/access/check", params=params)


def _ok(client, service, **params):
    r = _check(client, service, **params)
    assert r.status_code == 200, r.text
    return r.json()


def _by_tool(body):
    return {t["name"]: (t["decision"], t["reason"]) for t in body["tools"]}


def _error(r, status, code):
    assert r.status_code == status, r.text
    assert r.json()["detail"]["error"] == code, r.text


def _rule(client, service, **body):
    r = client.post(f"/api/services/{service['id']}/access-rules", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _pat(client, service, label="pat", scopes=None):
    body = {"service_id": service["id"], "label": label}
    if scopes is not None:
        body["scopes"] = scopes
    r = client.post("/api/oauth/tokens/personal", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _owner_id(client):
    return client.get("/api/session/me").json()["id"]


def _client(client, name="CI"):
    return client.post("/api/oauth/clients", json={
        "client_name": name, "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic"}).json()


def _bundles(client, service, tools):
    """files:write (global) on delete_file; files:read (this server's) on read_file; search in no bundle."""
    assert client.put("/api/oauth/scopes/files:write", json={}).status_code == 200
    assert client.put(f"/api/oauth/services/{service['id']}/scopes/files:read", json={}).status_code == 200
    for tool, scopes in (("delete_file", ["files:write"]), ("read_file", ["files:read"])):
        r = client.put(f"/api/services/{service['id']}/tools/{tools[tool]}/scopes", json={"scopes": scopes})
        assert r.status_code == 200, r.text


# ---- a real token -----------------------------------------------------------------------------------------------

def test_tchk_001_pat_verdict_per_tool(owner_client, service, tools):
    _bundles(owner_client, service, tools)
    pat = _pat(owner_client, service, "reader", ["files:read"])
    body = _ok(owner_client, service, jti=pat["jti"])
    assert _by_tool(body) == {
        "delete_file": ("needs_scope", "missing_scope"),
        "read_file": ("allowed", "ok"),
        "search": ("allowed", "ok"),
        "purge": ("hidden", "not_approved"),
    }
    delete = next(t for t in body["tools"] if t["name"] == "delete_file")
    assert delete["challenge"] == "files:write" and delete["scopes"] == ["files:write"]
    assert body["counts"] == {"allowed": 2, "needs_scope": 1, "hidden": 1}
    assert body["subject"]["token"]["label"] == "reader" and body["subject"]["token"]["kind"] == "pat"
    assert body["subject"]["token"]["status"] == "active"
    assert body["base_scopes"] == ["files:read"] and body["added_scopes"] == []
    assert body["rules_version"] == 1


def test_tchk_002_removed_tools_are_left_out(owner_client, service, tools):
    pat = _pat(owner_client, service)
    names = [t["name"] for t in _ok(owner_client, service, jti=pat["jti"])["tools"]]
    assert "gone" not in names and sorted(names) == ["delete_file", "purge", "read_file", "search"]


def test_tchk_003_added_scope_unlocks_a_step_up_tool(owner_client, service, tools):
    _bundles(owner_client, service, tools)
    pat = _pat(owner_client, service, "reader", ["files:read"])
    body = _ok(owner_client, service, jti=pat["jti"], scope="files:write files:read")
    assert _by_tool(body)["delete_file"] == ("allowed", "ok")
    assert body["added_scopes"] == ["files:write"] and body["scopes"] == ["files:read", "files:write"]


def test_tchk_004_rules_decide_and_are_named(owner_client, service, tools):
    pat = _pat(owner_client, service, "laptop")
    owner = _owner_id(owner_client)
    deny = _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]},
                 tools=["read_file"], note="no reading")
    only = _rule(owner_client, service, effect="only", subject={"kind": "user", "id": owner},
                 tools=["read_file", "delete_file"])
    body = _ok(owner_client, service, jti=pat["jti"])
    assert _by_tool(body) == {"delete_file": ("allowed", "ok"), "read_file": ("hidden", "denied_by_rule"),
                              "search": ("hidden", "outside_only_rule"), "purge": ("hidden", "not_approved")}
    rows = {t["name"]: t for t in body["tools"]}
    assert [r["id"] for r in rows["read_file"]["rules"]] == [deny["id"]]
    assert rows["read_file"]["rules"][0]["subject"]["label"] == "laptop"
    assert rows["read_file"]["rules"][0]["note"] == "no reading"
    assert [r["id"] for r in rows["search"]["rules"]] == [only["id"]]
    assert rows["delete_file"]["rules"] == []


def test_tchk_005_expired_rules_do_not_apply(owner_client, service, tools, db_session):
    from db.models import ToolAccessRule
    pat = _pat(owner_client, service)
    rule = _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]}, tools=["*"])
    db_session.query(ToolAccessRule).filter(ToolAccessRule.id == uuid.UUID(rule["id"])).update(
        {"expires_at": datetime.utcnow() - timedelta(minutes=1)})
    db_session.commit()
    assert _by_tool(_ok(owner_client, service, jti=pat["jti"]))["search"] == ("allowed", "ok")


def test_tchk_006_oauth_access_and_refresh_tokens(owner_client, service, tools, db_session):
    """An OAuth access token is checked with its own jti; a refresh token by its grant (client, subject, scope)."""
    from src.adapters import ServiceAdapter
    from src.oauth import service as oauth
    reg = _client(owner_client, "Agent")
    svc = ServiceAdapter.get_existing(db_session, service["id"])
    _, _, access = oauth.issue_access_token(db_session, sub="someone", client_id=reg["client_id"], scope="",
                                            audience=RESOURCE, service=svc)
    _, refresh = oauth.issue_refresh_token(db_session, sub="someone", client_id=reg["client_id"], scope="",
                                           audience=RESOURCE, service=svc, user=None)
    _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": reg["client_id"]},
          tools=["search"])
    for jti, kind in ((access.jti, "access"), (refresh.jti, "refresh")):
        body = _ok(owner_client, service, jti=jti)
        assert body["subject"]["token"]["kind"] == kind
        assert _by_tool(body)["search"] == ("hidden", "denied_by_rule")
        assert _by_tool(body)["read_file"] == ("allowed", "ok")


def test_tchk_007_revoked_token_is_still_checked_and_marked(owner_client, service, tools):
    pat = _pat(owner_client, service)
    assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
    body = _ok(owner_client, service, jti=pat["jti"])
    assert body["subject"]["token"]["status"] == "revoked"


# ---- what if ----------------------------------------------------------------------------------------------------

def test_tchk_010_what_if_client(owner_client, service, tools):
    """A client on its own is a client_credentials token (sub = client id): client rules apply, user rules don't."""
    reg = _client(owner_client)
    owner = _owner_id(owner_client)
    _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": reg["client_id"]},
          tools=["delete_file"])
    _rule(owner_client, service, effect="deny", subject={"kind": "user", "id": owner}, tools=["search"])
    body = _ok(owner_client, service, client_id=reg["client_id"])
    assert _by_tool(body)["delete_file"] == ("hidden", "denied_by_rule")
    assert _by_tool(body)["search"] == ("allowed", "ok")
    assert body["subject"]["client"] == {"id": reg["client_id"], "label": "CI"}
    assert body["subject"]["token"] is None and body["base_scopes"] == []


def test_tchk_011_what_if_user_through_a_client(owner_client, service, tools):
    reg = _client(owner_client)
    owner = _owner_id(owner_client)
    _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": reg["client_id"]},
          tools=["delete_file"])
    _rule(owner_client, service, effect="deny", subject={"kind": "user", "id": owner}, tools=["search"])
    alone = _ok(owner_client, service, user_id=owner.upper())
    assert _by_tool(alone)["search"] == ("hidden", "denied_by_rule")
    assert _by_tool(alone)["delete_file"] == ("allowed", "ok")
    assert alone["subject"]["user"] == {"id": owner, "label": "owner@example.com"}
    both = _ok(owner_client, service, user_id=owner, client_id=reg["client_id"])
    assert _by_tool(both)["search"] == ("hidden", "denied_by_rule")
    assert _by_tool(both)["delete_file"] == ("hidden", "denied_by_rule")


def test_tchk_012_what_if_group_member(owner_client, service, tools):
    """"A member of G" gets G's rules even while G has no members, and no stored user's own rules."""
    owner = _owner_id(owner_client)
    group = owner_client.post("/api/groups", json={"name": "Contractors"}).json()
    _rule(owner_client, service, effect="only", subject={"kind": "group", "id": group["id"]}, tools=["read_file"])
    _rule(owner_client, service, effect="deny", subject={"kind": "user", "id": owner}, tools=["read_file"])
    body = _ok(owner_client, service, group_id=group["id"])
    assert _by_tool(body) == {"delete_file": ("hidden", "outside_only_rule"), "read_file": ("allowed", "ok"),
                              "search": ("hidden", "outside_only_rule"), "purge": ("hidden", "not_approved")}
    assert body["subject"]["group"] == {"id": group["id"], "label": "Contractors"}
    # the hypothetical member is not added to what servers receive
    policy = owner_client.get(f"/api/services/{service['id']}/access").json()["policy"]
    assert [r["subject"] for r in policy["rules"]] == [{"kind": "user", "id": owner}]


def test_tchk_013_what_if_scopes_only_from_the_form(owner_client, service, tools):
    _bundles(owner_client, service, tools)
    reg = _client(owner_client)
    none = _ok(owner_client, service, client_id=reg["client_id"])
    assert _by_tool(none)["read_file"] == ("needs_scope", "missing_scope")
    some = _ok(owner_client, service, client_id=reg["client_id"], scope="files:read")
    assert _by_tool(some)["read_file"] == ("allowed", "ok") and some["added_scopes"] == ["files:read"]


# ---- refusals ---------------------------------------------------------------------------------------------------

def test_tchk_020_subject_combinations(owner_client, service, tools):
    pat = _pat(owner_client, service)
    reg = _client(owner_client)
    owner = _owner_id(owner_client)
    group = owner_client.post("/api/groups", json={"name": "G"}).json()
    for params in ({}, {"scope": "files:read"}, {"jti": pat["jti"], "client_id": reg["client_id"]},
                   {"jti": pat["jti"], "user_id": owner}, {"jti": pat["jti"], "group_id": group["id"]},
                   {"user_id": owner, "group_id": group["id"]}):
        _error(_check(owner_client, service, **params), 400, "access.check_subject")


@pytest.mark.parametrize("params", [
    {"jti": "no-such-jti"}, {"client_id": "no-such-client"}, {"user_id": "not-a-uuid"},
    {"user_id": str(uuid.UUID(int=1))}, {"group_id": str(uuid.UUID(int=2))},
])
def test_tchk_021_unknown_subjects(owner_client, service, tools, params):
    _error(_check(owner_client, service, **params), 400, "access.subject_not_found")


def test_tchk_022_token_of_another_server(owner_client, service, tools):
    other = owner_client.post("/api/services", json={"name": "other", "host": "127.0.0.1", "port": 8124,
                                                     "protocol": "http", "mcp_path": "/mcp"}).json()
    pat = _pat(owner_client, other)
    _error(_check(owner_client, service, jti=pat["jti"]), 400, "access.token_other_service")


@pytest.mark.parametrize("scope", ['bad"name', "back\\slash", "é"])
def test_tchk_023_scopes_must_be_scope_tokens(owner_client, service, tools, scope):
    pat = _pat(owner_client, service)
    _error(_check(owner_client, service, jti=pat["jti"], scope=f"files:read {scope}"), 400,
           "access.check_invalid_scope")


def test_tchk_024_scope_count_cap(owner_client, service, tools):
    from src.adapters.access_adapter import MAX_CHECK_SCOPES
    pat = _pat(owner_client, service)
    names = [f"s{i}" for i in range(MAX_CHECK_SCOPES)]
    assert _check(owner_client, service, jti=pat["jti"], scope=" ".join(names)).status_code == 200
    _error(_check(owner_client, service, jti=pat["jti"], scope=" ".join(names + ["one-more"])), 400,
           "access.check_invalid_scope")


def test_tchk_025_unknown_server_and_session(client, owner_client, service, tools):
    r = owner_client.get(f"/api/services/{uuid.uuid4()}/access/check", params={"user_id": _owner_id(owner_client)})
    assert r.status_code == 404
    from fastapi.testclient import TestClient
    anonymous = TestClient(owner_client.app, base_url="http://testserver")
    assert anonymous.get(f"/api/services/{service['id']}/access/check",
                         params={"user_id": _owner_id(owner_client)}).status_code == 401


# ---- read only --------------------------------------------------------------------------------------------------

def test_tchk_030_read_only(owner_client, service, tools, db_session, monkeypatch):
    """A check stores nothing (every table keeps its rows), signs nothing and writes no audit entry."""
    from sqlalchemy import inspect, text

    from src.oauth import service as oauth
    _bundles(owner_client, service, tools)
    pat = _pat(owner_client, service, "reader", ["files:read"])
    reg = _client(owner_client)
    group = owner_client.post("/api/groups", json={"name": "G"}).json()
    _rule(owner_client, service, effect="deny", subject={"kind": "group", "id": group["id"]}, tools=["search"])

    tables = inspect(db_session.get_bind()).get_table_names()

    def snapshot():
        db_session.expire_all()
        return {t: db_session.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() for t in tables}

    def no_signing(*a, **k):
        raise AssertionError("the check signed a token")

    before = snapshot()
    monkeypatch.setattr(oauth, "_sign", no_signing)
    for params in ({"jti": pat["jti"], "scope": "files:write"}, {"client_id": reg["client_id"]},
                   {"group_id": group["id"], "client_id": reg["client_id"]}, {"user_id": _owner_id(owner_client)}):
        _ok(owner_client, service, **params)
    assert snapshot() == before
