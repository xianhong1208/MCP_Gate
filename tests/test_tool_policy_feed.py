"""Tool policy feed and tool reports (#33): what a server's pinning middleware reads and sends, on MCP Gate's side."""

import json

import pytest

from src.adapters import MCPToolAdapter
from src.tool_pinning.hashing import HASH_VERSION, tool_hash
from tests.test_oauth_flow import _register, _register_console
from tests.test_schema_drift import _alembic_config, scratch_db  # noqa: F401  (fixture)


def _resource_server(client, service, name="Resource server"):
    reg = _register_console(client, client_name=name, token_endpoint_auth_method="client_secret_post",
                            resource_service_id=service["id"])
    return {"client_id": reg["client_id"], "client_secret": reg["client_secret"]}


def _tool(name, description="d", **kw):
    return {"name": name, "description": description, "inputSchema": {"type": "object"}, **kw}


def _scan(db_session, service, tools):
    """What a refresh / scan records (source "scan")."""
    MCPToolAdapter.sync_tools(db_session, service["id"], tools)
    db_session.expire_all()


def _report(client, rs, tools, **extra):
    return client.post("/oauth/tool-report", data={**rs, "tools": json.dumps(tools), **extra})


def _approve(client, service, name, digest):
    tools = client.get(f"/api/services/{service['id']}/tools").json()["tools"]
    tool_id = next(t["id"] for t in tools if t["name"] == name)
    r = client.post(f"/api/services/{service['id']}/tools/{tool_id}/approve", json={"hash": digest})
    assert r.status_code == 200, r.text


@pytest.fixture(autouse=True)
def _fresh_report_window(monkeypatch):
    from src.middleware.rate_limiter import SlidingWindowCounter
    from src.oauth import policy_feed

    monkeypatch.setattr(policy_feed, "_report_window", SlidingWindowCounter(window_size=60))


@pytest.fixture
def other_service(owner_client):
    r = owner_client.post("/api/services", json={"name": "other-mcp", "host": "127.0.0.1", "port": 8124,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    assert r.status_code == 201, r.text
    return r.json()


# ---- the feed ---------------------------------------------------------------------------------------------------

def test_tpol_001_feed_and_report_need_a_resource_server(owner_client, service):
    public = _register(owner_client)
    for path, extra in (("/oauth/policy", {}), ("/oauth/tool-report", {"tools": "[]"})):
        r = owner_client.post(path, data={"client_id": public["client_id"], **extra})
        assert r.status_code == 403 and r.json()["error"] == "unauthorized_client", path
    # an unbound console client is not a resource server either
    unbound = _register_console(owner_client, client_name="Unbound", token_endpoint_auth_method="client_secret_post")
    creds = {"client_id": unbound["client_id"], "client_secret": unbound["client_secret"]}
    assert owner_client.post("/oauth/policy", data=creds).status_code == 403
    # a wrong secret is a failed client authentication
    rs = _resource_server(owner_client, service)
    r = owner_client.post("/oauth/policy", data={**rs, "client_secret": "wrong"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    r = _report(owner_client, {**rs, "client_secret": "wrong"}, [_tool("a")])
    assert r.status_code == 401


def test_tpol_002_feed_lists_hashes_by_state(owner_client, service, db_session):
    rs = _resource_server(owner_client, service)
    a, b, c = _tool("a"), _tool("b"), _tool("c")
    _scan(db_session, service, [a, b, c])
    _approve(owner_client, service, "a", tool_hash(a))
    tools = owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]
    c_id = next(t["id"] for t in tools if t["name"] == "c")
    assert owner_client.post(f"/api/services/{service['id']}/tools/{c_id}/reject",
                             json={"hash": tool_hash(c)}).status_code == 200

    feed = owner_client.post("/oauth/policy", data=rs).json()
    assert feed["format"] == 1 and feed["hash_version"] == HASH_VERSION
    assert feed["audience"] == service["effective_audience"] and feed["service_id"] == service["id"]
    assert feed["tools"] == {"approved": [tool_hash(a)], "pending": [tool_hash(b)], "rejected": [tool_hash(c)]}
    assert feed["rules"] == [] and feed["unchanged"] is False and len(feed["etag"]) == 64


def test_tpol_003_feed_is_scoped_to_the_callers_server(owner_client, service, other_service, db_session):
    rs = _resource_server(owner_client, service)
    rs_other = _resource_server(owner_client, other_service, name="Other RS")
    mine, theirs = _tool("mine"), _tool("theirs")
    _scan(db_session, service, [mine])
    _scan(db_session, other_service, [theirs])
    feed = owner_client.post("/oauth/policy", data=rs).json()
    assert feed["tools"]["pending"] == [tool_hash(mine)]
    other = owner_client.post("/oauth/policy", data=rs_other).json()
    assert other["tools"]["pending"] == [tool_hash(theirs)]
    assert other["audience"] == other_service["effective_audience"]


def test_tpol_004_etag_makes_an_unchanged_poll_cheap(owner_client, service, db_session):
    rs = _resource_server(owner_client, service)
    a = _tool("a")
    _scan(db_session, service, [a])
    first = owner_client.post("/oauth/policy", data=rs).json()
    again = owner_client.post("/oauth/policy", data={**rs, "etag": first["etag"]}).json()
    assert again == {"unchanged": True, "etag": first["etag"], "now": again["now"]}
    _approve(owner_client, service, "a", tool_hash(a))
    changed = owner_client.post("/oauth/policy", data={**rs, "etag": first["etag"]}).json()
    assert changed["unchanged"] is False and changed["etag"] != first["etag"]
    assert changed["tools"]["approved"] == [tool_hash(a)]


def test_tpol_005_disabled_server_gets_empty_lists(owner_client, service, db_session):
    rs = _resource_server(owner_client, service)
    a = _tool("a")
    _scan(db_session, service, [a])
    _approve(owner_client, service, "a", tool_hash(a))
    assert owner_client.put(f"/api/services/{service['id']}", json={"is_active": False}).status_code == 200
    feed = owner_client.post("/oauth/policy", data=rs).json()
    assert feed["service_id"] is None and feed["tools"] == {"approved": [], "pending": [], "rejected": []}


def test_tpol_006_poll_time_shows_whether_the_server_enforces(owner_client, service):
    status = owner_client.get(f"/api/oauth/services/{service['id']}/policy-feed").json()
    assert status["state"] == "not_wired"
    rs = _resource_server(owner_client, service)
    assert owner_client.get(f"/api/oauth/services/{service['id']}/policy-feed").json()["state"] == "never_polled"
    # the revocation feed's poll does not count as enforcing tools, and the other way round
    assert owner_client.post("/oauth/revoked", data=rs).status_code == 200
    assert owner_client.get(f"/api/oauth/services/{service['id']}/policy-feed").json()["state"] == "never_polled"
    assert owner_client.post("/oauth/policy", data=rs).status_code == 200
    status = owner_client.get(f"/api/oauth/services/{service['id']}/policy-feed").json()
    assert status["state"] == "active" and status["last_poll"]
    assert status["resource_servers"][0]["client_id"] == rs["client_id"]
    client = owner_client.get(f"/api/oauth/clients/{rs['client_id']}").json()
    assert client["policy_polled_at"]


def test_tpol_007_metadata_names_the_endpoints(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["tool_policy_endpoint"].endswith("/oauth/policy")
    assert meta["tool_report_endpoint"].endswith("/oauth/tool-report")


# ---- reports ----------------------------------------------------------------------------------------------------

def test_tpol_010_report_records_pending_with_source_reported(owner_client, service, db_session):
    rs = _resource_server(owner_client, service)
    a = _tool("a", title="A", annotations={"readOnlyHint": True})
    r = _report(owner_client, rs, [{**a, "hash": tool_hash(a)}])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["recorded"] == [{"name": "a", "hash": tool_hash(a), "state": "pending", "new": True}]
    assert body["invalid"] == [] and body["hash_mismatch"] == []
    tools = owner_client.get(f"/api/services/{service['id']}/tools").json()
    assert tools["pending_count"] == 1 and tools["first_review"] is True
    version = tools["tools"][0]["versions"][0]
    assert version["source"] == "reported" and version["hash"] == tool_hash(a)
    assert tools["tools"][0]["title"] == "A"
    # the feed now lists it as pending, so the middleware stops reporting it
    assert owner_client.post("/oauth/policy", data=rs).json()["tools"]["pending"] == [tool_hash(a)]
    # audited, with the resource server as the actor
    logs = owner_client.get("/api/audit/logs", params={"action": "tool_report"}).json()["logs"]
    assert len(logs) == 1 and logs[0]["actor_id"] == rs["client_id"]
    assert logs[0]["resource_id"] == service["id"] and logs[0]["details"]["tools"][0]["name"] == "a"


def test_tpol_011_hash_is_recomputed_never_trusted(owner_client, service):
    rs = _resource_server(owner_client, service)
    a = _tool("a")
    fake = "0" * 64
    body = _report(owner_client, rs, [{**a, "hash": fake}]).json()
    assert body["recorded"][0]["hash"] == tool_hash(a) and body["hash_mismatch"] == ["a"]
    versions = owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"][0]["versions"]
    assert [v["hash"] for v in versions] == [tool_hash(a)]
    assert "hash" not in versions[0]["definition"]


def test_tpol_012_report_is_partial_and_shares_the_scan_path(owner_client, service, db_session):
    rs = _resource_server(owner_client, service)
    a, b = _tool("a"), _tool("b")
    _scan(db_session, service, [a, b])
    _approve(owner_client, service, "a", tool_hash(a))
    _approve(owner_client, service, "b", tool_hash(b))
    changed = _tool("a", description="Now also deletes files.")
    body = _report(owner_client, rs, [changed]).json()
    assert body["recorded"][0]["state"] == "pending" and body["recorded"][0]["new"] is True
    tools = {t["name"]: t for t in owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]}
    # b was not reported: still listed, not marked removed (a report is not a full list)
    assert tools["b"]["removed_at"] is None and tools["b"]["state"] == "approved"
    # a's change waits for review, compared with the approved version (the same rules as a refresh)
    assert tools["a"]["state"] == "pending" and tools["a"]["approved_version"]["hash"] == tool_hash(a)
    assert {v["source"] for v in tools["a"]["versions"]} == {"scan", "reported"}
    # reporting a definition MCP Gate already knows records nothing new and keeps its state and source
    again = _report(owner_client, rs, [a, b]).json()["recorded"]
    assert [(x["name"], x["state"], x["new"]) for x in again] == [("a", "approved", False), ("b", "approved", False)]
    again = _report(owner_client, rs, [changed]).json()["recorded"]
    assert [(x["state"], x["new"]) for x in again] == [("pending", False)]
    tools = {t["name"]: t for t in owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]}
    assert {v["hash"]: v["source"] for v in tools["a"]["versions"]} == {tool_hash(a): "scan",
                                                                       tool_hash(changed): "reported"}


def test_tpol_013_rejected_definition_stays_rejected_when_reported(owner_client, service, db_session):
    rs = _resource_server(owner_client, service)
    a = _tool("a")
    _scan(db_session, service, [a])
    tool_id = owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"][0]["id"]
    owner_client.post(f"/api/services/{service['id']}/tools/{tool_id}/reject", json={"hash": tool_hash(a)})
    assert _report(owner_client, rs, [a]).json()["recorded"][0]["state"] == "rejected"


@pytest.mark.parametrize("bad,reason", [
    ("not a tool", "not_an_object"),
    ({"description": "no name"}, "invalid_name"),
    ({"name": " padded "}, "invalid_name"),
    ({"name": "x" * 129}, "invalid_name"),
    ({"name": "t", "description": 5}, "wrong_type:description"),
    ({"name": "t", "inputSchema": []}, "wrong_type:inputSchema"),
    ({"name": "t", "description": "x" * (64 * 1024)}, "too_large"),
])
def test_tpol_014_invalid_definitions_are_refused_not_stored(owner_client, service, bad, reason):
    rs = _resource_server(owner_client, service)
    body = _report(owner_client, rs, [bad, _tool("ok")]).json()
    assert body["invalid"][0]["reason"] == reason and body["invalid"][0]["index"] == 0
    assert [x["name"] for x in body["recorded"]] == ["ok"]
    names = [t["name"] for t in owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]]
    assert names == ["ok"]


def test_tpol_015_duplicate_names_and_unhashable_values(owner_client, service):
    rs = _resource_server(owner_client, service)
    raw = '[{"name": "a"}, {"name": "a", "description": "again"}, {"name": "n", "inputSchema": {"x": NaN}}]'
    body = owner_client.post("/oauth/tool-report", data={**rs, "tools": raw}).json()
    assert [(x["index"], x["reason"]) for x in body["invalid"]] == [(1, "duplicate_name"), (2, "not_hashable")]
    assert [x["name"] for x in body["recorded"]] == ["a"]


def test_tpol_016_report_size_limits(owner_client, service):
    from src.oauth.policy_feed import MAX_REPORTED_TOOLS

    rs = _resource_server(owner_client, service)
    r = _report(owner_client, rs, [_tool(f"t{i}") for i in range(MAX_REPORTED_TOOLS + 1)])
    assert r.status_code == 400 and "at most" in r.json()["error_description"]
    assert owner_client.post("/oauth/tool-report", data={**rs, "tools": "{}"}).status_code == 400
    assert owner_client.post("/oauth/tool-report", data={**rs, "tools": "not json"}).status_code == 400
    huge = "x" * (2 * 1024 * 1024 + 1)
    r = owner_client.post("/oauth/tool-report", data={**rs, "tools": huge})
    assert r.status_code == 413
    assert owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"] == []


def test_tpol_017_reports_are_rate_limited_per_client(owner_client, service, other_service):
    from src.oauth.policy_feed import REPORTS_PER_MINUTE

    rs = _resource_server(owner_client, service)
    rs_other = _resource_server(owner_client, other_service, name="Other RS")
    for _ in range(REPORTS_PER_MINUTE):
        assert _report(owner_client, rs, [_tool("a")]).status_code == 200
    r = _report(owner_client, rs, [_tool("a")])
    assert r.status_code == 429 and r.json()["error"] == "slow_down"
    # another server's client has its own allowance
    assert _report(owner_client, rs_other, [_tool("a")]).status_code == 200


def test_tpol_018_report_for_a_deleted_server(owner_client, service):
    rs = _resource_server(owner_client, service)
    assert owner_client.put(f"/api/services/{service['id']}", json={"is_active": False}).status_code == 200
    r = _report(owner_client, rs, [_tool("a")])
    assert r.status_code == 404 and r.json()["error"] == "invalid_target"


def test_tpol_019_report_only_reaches_the_callers_server(owner_client, service, other_service):
    rs_other = _resource_server(owner_client, other_service, name="Other RS")
    assert _report(owner_client, rs_other, [_tool("sneaky")]).status_code == 200
    assert owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"] == []
    names = [t["name"] for t in owner_client.get(f"/api/services/{other_service['id']}/tools").json()["tools"]]
    assert names == ["sneaky"]


def test_tpol_020_concurrent_reports_of_the_same_new_tool(owner_client, service, db_session, monkeypatch):
    """The loser of a race on the unique tool name is retried once and finds the winner's rows."""
    from sqlalchemy.exc import IntegrityError

    from db.crud import MCPToolCRUD

    original = MCPToolCRUD.record_tools
    calls = {"n": 0}

    def flaky(db, service_id, tools, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            original(db, service_id, tools)  # the winner (a scan) commits first
            raise IntegrityError("insert", {}, Exception("duplicate"))
        return original(db, service_id, tools, **kw)

    monkeypatch.setattr(MCPToolCRUD, "record_tools", staticmethod(flaky))
    rs = _resource_server(owner_client, service)
    body = _report(owner_client, rs, [_tool("a")]).json()
    assert calls["n"] == 2 and body["recorded"][0]["new"] is False


def test_tpol_030_migration_marks_existing_versions_as_scanned(scratch_db):  # noqa: F811
    """e3a5c7d9f1b3: every version stored before the feed came from a refresh or scan; down and up again."""
    import sqlalchemy as sa
    from alembic import command

    from tests.test_tool_pinning_migration import LEGACY, _seed_legacy

    cfg = _alembic_config(scratch_db)
    command.upgrade(cfg, "d1f3a5c7e9b2")
    _seed_legacy(scratch_db)
    command.upgrade(cfg, "e3a5c7d9f1b3")
    eng = sa.create_engine(scratch_db)
    try:
        with eng.connect() as conn:
            sources = conn.execute(sa.text("SELECT source FROM mcp_tool_versions")).scalars().all()
            assert sources == ["scan"] * len(LEGACY)
            conn.execute(sa.text("SELECT policy_polled_at FROM oauth_clients"))
        command.downgrade(cfg, "f2b4d6a8c0e1")
        with eng.connect() as conn:
            cols = [c["name"] for c in sa.inspect(conn).get_columns("mcp_tool_versions")]
            assert "source" not in cols and len(conn.execute(sa.text("SELECT id FROM mcp_tool_versions")).all()) == 3
            assert "policy_polled_at" not in [c["name"] for c in sa.inspect(conn).get_columns("oauth_clients")]
        command.upgrade(cfg, "head")
        with eng.connect() as conn:
            assert conn.execute(sa.text("SELECT DISTINCT source FROM mcp_tool_versions")).scalars().all() == ["scan"]
    finally:
        eng.dispose()
