"""Tool access (#37): tools in scopes (bundles), per-subject deny / "only" rules, groups of users, the evaluator and
the policy MCP Gate builds for a server. No feed or middleware yet (1.6 PR 2)."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.tool_policy import validation
from src.tool_policy.evaluate import evaluate, expand_groups
from src.tool_policy.validation import is_scope_token

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "tool_policy_vectors.json").read_text(encoding="utf-8"))
RESOURCE = "http://127.0.0.1:8123/mcp"


# ---- the evaluator ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["label"] for v in VECTORS["vectors"]])
def test_tacc_001_golden_vectors(vector):
    got = evaluate(vector["policy"], vector["token"], vector["tool"], approved=vector["approved"], now=vector["now"])
    assert got == vector["expect"]


@pytest.mark.parametrize("case", VECTORS["expansions"], ids=[c["label"] for c in VECTORS["expansions"]])
def test_tacc_002_group_expansion_vectors(case):
    assert expand_groups(case["rules"], case["members"]) == case["expect"]


def test_tacc_003_vectors_cover_every_outcome():
    """The vectors must exercise every decision and reason the evaluator can return (a new outcome needs a
    vector the middleware can be checked against)."""
    from src.tool_policy import evaluate as ev
    reasons = {v["expect"]["reason"] for v in VECTORS["vectors"]}
    decisions = {v["expect"]["decision"] for v in VECTORS["vectors"]}
    assert reasons == {ev.REASON_OK, ev.REASON_NOT_APPROVED, ev.REASON_DENIED, ev.REASON_OUTSIDE_ONLY,
                       ev.REASON_MISSING_SCOPE, ev.REASON_UNSCOPED}
    assert decisions == {ev.ALLOWED, ev.HIDDEN, ev.NEEDS_SCOPE}
    assert VECTORS["rules_version"] == ev.RULES_VERSION


def test_tacc_004_evaluator_is_stdlib_only():
    """The middleware copies the evaluator into one stdlib-only file: it must not import the application."""
    source = (Path(__file__).parents[1] / "src" / "tool_policy" / "evaluate.py").read_text(encoding="utf-8")
    imports = [line.strip() for line in source.splitlines() if line.startswith(("import ", "from "))]
    assert imports == ["from __future__ import annotations", "from typing import Iterable, Optional"]


@pytest.mark.parametrize("name,ok", [
    ("files:read", True), ("mcp:tools:invoke", True), ("a/b?c=d#e", True), ("~!$%&'()*+,-./;<=>@[]^_`{|}", True),
    ("", False), ("has space", False), ('quo"te', False), ("back\\slash", False), ("tab\t", False),
    ("é", False), ("\x7f", False), (None, False),
])
def test_tacc_005_scope_token_charset(name, ok):
    assert is_scope_token(name) is ok


# ---- fixtures ---------------------------------------------------------------------------------------------------

@pytest.fixture
def tools(service, db_session):
    """The demo service lists three tools (recorded as a refresh would)."""
    from src.adapters import MCPToolAdapter
    listed = MCPToolAdapter.sync_tools(db_session, service["id"], [
        {"name": n, "description": n, "inputSchema": {"type": "object"}}
        for n in ("delete_file", "read_file", "search")])
    return {t.name: str(t.id) for t in listed}


def _scope(client, name, service_id=None, **body):
    path = f"/api/oauth/services/{service_id}/scopes/{name}" if service_id else f"/api/oauth/scopes/{name}"
    r = client.put(path, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _set(client, service, tool_id, scopes, challenge=None):
    body = {"scopes": scopes}
    if challenge is not None:
        body["challenge"] = challenge
    return client.put(f"/api/services/{service['id']}/tools/{tool_id}/scopes", json=body)


def _access(client, service):
    r = client.get(f"/api/services/{service['id']}/access")
    assert r.status_code == 200, r.text
    return r.json()


def _error(r, status, code):
    assert r.status_code == status, r.text
    assert r.json()["detail"]["error"] == code, r.text


def _audit(client, action):
    logs = client.get("/api/audit/logs", params={"limit": 200}).json()["logs"]
    return [e for e in logs if e["action"] == action]


def _pat(client, service, label="pat"):
    r = client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _second_service(client):
    r = client.post("/api/services", json={"name": "other", "host": "127.0.0.1", "port": 8124,
                                           "protocol": "http", "mcp_path": "/mcp"})
    assert r.status_code == 201, r.text
    return r.json()


def _owner_id(client):
    return client.get("/api/session/me").json()["id"]


def _rule(client, service, **body):
    return client.post(f"/api/services/{service['id']}/access-rules", json=body)


# ---- tool scopes ------------------------------------------------------------------------------------------------

def test_tacc_010_assign_scopes_to_a_tool(owner_client, service, tools):
    _scope(owner_client, "files:write")
    _scope(owner_client, "files:admin", service_id=service["id"])
    r = _set(owner_client, service, tools["delete_file"], ["files:write", "files:admin", "files:write"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted((s["scope"], s["source"]) for s in body["scopes"]) == [("files:admin", "service"),
                                                                       ("files:write", "global")]
    assert body["tool"] == "delete_file"
    got = owner_client.get(f"/api/services/{service['id']}/tools/{tools['delete_file']}/scopes").json()
    assert got["scopes"] == body["scopes"] and got["challenge"] == body["challenge"]
    entry = _audit(owner_client, "tool_scope_set")[0]
    assert entry["details"]["before"] == [] and entry["details"]["after"] == ["files:admin", "files:write"]
    assert entry["details"]["tool"] == "delete_file"

    # replaced, not merged; an empty list takes the tool out of every scope
    r = _set(owner_client, service, tools["delete_file"], ["files:admin"])
    assert [s["scope"] for s in r.json()["scopes"]] == ["files:admin"]
    r = _set(owner_client, service, tools["delete_file"], [])
    assert r.json()["scopes"] == [] and r.json()["challenge"] is None
    assert _audit(owner_client, "tool_scope_set")[0]["details"]["before"] == ["files:admin"]


def test_tacc_011_scope_must_exist_for_this_server(owner_client, service, tools):
    other = _second_service(owner_client)
    _scope(owner_client, "theirs", service_id=other["id"])
    _error(_set(owner_client, service, tools["search"], ["nope"]), 400, "access.unknown_scope")
    _error(_set(owner_client, service, tools["search"], ["theirs"]), 400, "access.unknown_scope")
    assert _access(owner_client, service)["policy"]["tool_scopes"] == {}


def test_tacc_012_global_scope_must_be_grantable_by_the_server(owner_client, service, tools):
    _scope(owner_client, "files:write")
    r = owner_client.put(f"/api/services/{service['id']}", json={"oauth_scopes": ["mcp:tools:read"]})
    assert r.status_code == 200, r.text
    _error(_set(owner_client, service, tools["search"], ["files:write"]), 400, "access.scope_not_permitted")
    assert _set(owner_client, service, tools["search"], ["mcp:tools:read"]).status_code == 200


def test_tacc_013_legacy_scope_name_a_challenge_cannot_carry(owner_client, service, tools, db_session):
    """A scope created before 1.6 may hold '"': it keeps working but cannot be assigned to a tool."""
    from db.models import OAuthScope
    db_session.add(OAuthScope(name='old"scope', description="legacy", is_default=False))
    db_session.commit()
    _error(_set(owner_client, service, tools["search"], ['old"scope']), 400, "access.scope_name_unsafe")
    # it can still be edited
    r = owner_client.put("/api/oauth/scopes/old%22scope", json={"description": "still here"})
    assert r.status_code == 200, r.text


def test_tacc_014_challenge_must_be_one_of_the_scopes(owner_client, service, tools):
    _scope(owner_client, "a:one")
    _error(_set(owner_client, service, tools["search"], ["a:one"], challenge="b:two"), 400,
           "access.challenge_not_in_scopes")


def test_tacc_015_too_many_scopes(owner_client, service, tools, monkeypatch):
    monkeypatch.setattr("src.adapters.access_adapter.MAX_SCOPES_PER_TOOL", 1)
    _scope(owner_client, "a:one")
    _scope(owner_client, "a:two")
    _error(_set(owner_client, service, tools["search"], ["a:one", "a:two"]), 400, "access.too_many_scopes")
    assert _set(owner_client, service, tools["search"], ["a:one"]).status_code == 200


def test_tacc_016_challenge_is_explicit_or_the_narrowest_scope(owner_client, service, tools):
    _scope(owner_client, "files:all")
    _scope(owner_client, "files:delete")
    # files:all holds three tools, files:delete one: the narrowest is files:delete
    for name in ("delete_file", "read_file", "search"):
        assert _set(owner_client, service, tools[name], ["files:all"]).status_code == 200
    r = _set(owner_client, service, tools["delete_file"], ["files:all", "files:delete"])
    assert r.json()["challenge"] == "files:delete"
    r = _set(owner_client, service, tools["delete_file"], ["files:all", "files:delete"], challenge="files:all")
    assert r.json()["challenge"] == "files:all"
    assert [s["challenge"] for s in r.json()["scopes"]] == [True, False]
    policy = _access(owner_client, service)["policy"]
    assert policy["tool_scopes"]["delete_file"] == {"any_of": ["files:all", "files:delete"], "challenge": "files:all"}
    assert policy["tool_scopes"]["search"] == {"any_of": ["files:all"], "challenge": "files:all"}


def test_tacc_017_narrowest_tie_breaks_by_name(owner_client, service, tools):
    _scope(owner_client, "b:scope")
    _scope(owner_client, "a:scope")
    r = _set(owner_client, service, tools["search"], ["b:scope", "a:scope"])
    assert r.json()["challenge"] == "a:scope"


def test_tacc_018_deleting_a_scope_takes_its_tools_out(owner_client, service, tools):
    _scope(owner_client, "files:write")
    _scope(owner_client, "own:scope", service_id=service["id"])
    _set(owner_client, service, tools["delete_file"], ["files:write", "own:scope"])
    _set(owner_client, service, tools["read_file"], ["files:write"])
    assert owner_client.delete("/api/oauth/scopes/files:write").status_code == 200
    entry = _audit(owner_client, "oauth_scope_delete")[0]
    assert sorted(t["tool"] for t in entry["details"]["tools"]) == ["delete_file", "read_file"]
    policy = _access(owner_client, service)["policy"]
    assert policy["tool_scopes"] == {"delete_file": {"any_of": ["own:scope"], "challenge": "own:scope"}}
    assert owner_client.delete(f"/api/oauth/services/{service['id']}/scopes/own:scope").status_code == 200
    assert _audit(owner_client, "oauth_scope_delete")[0]["details"]["tools"] == ["delete_file"]
    assert _access(owner_client, service)["policy"]["tool_scopes"] == {}


def test_tacc_019_a_recreated_global_scope_starts_empty(owner_client, service, tools):
    """Global memberships are keyed by name with no foreign key: deleting must remove them, or a scope created
    later under the same name would silently inherit the old tools."""
    _scope(owner_client, "files:write")
    _set(owner_client, service, tools["delete_file"], ["files:write"])
    owner_client.delete("/api/oauth/scopes/files:write")
    _scope(owner_client, "files:write")
    assert _access(owner_client, service)["policy"]["tool_scopes"] == {}


def test_tacc_020_tool_and_service_not_found(owner_client, service, tools):
    _error(_set(owner_client, service, str(uuid.uuid4()), []), 404, "tools.not_found")
    _error(owner_client.put(f"/api/services/{uuid.uuid4()}/tools/{tools['search']}/scopes", json={"scopes": []}),
           404, "service.not_found")
    other = _second_service(owner_client)
    _error(_set(owner_client, other, tools["search"], []), 404, "tools.not_found")


# ---- scope names and titles -------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ['bad"name', "bad\\name", "naïve"])
def test_tacc_025_new_scopes_must_be_scope_tokens(owner_client, service, name):
    from urllib.parse import quote
    _error(owner_client.put(f"/api/oauth/scopes/{quote(name)}", json={}), 400, "oauth.invalid_scope_name")
    _error(owner_client.put(f"/api/oauth/services/{service['id']}/scopes/{quote(name)}", json={}), 400,
           "oauth.invalid_scope_name")


def test_tacc_026_scope_title_kept_unless_sent(owner_client, service):
    assert _scope(owner_client, "files:write", title="Writers")["title"] == "Writers"
    assert _scope(owner_client, "files:write", description="d")["title"] == "Writers"
    assert _scope(owner_client, "files:write", title=None)["title"] is None
    assert _scope(owner_client, "own:x", service_id=service["id"], title="Own")["title"] == "Own"
    assert _scope(owner_client, "own:x", service_id=service["id"])["title"] == "Own"
    r = owner_client.put("/api/oauth/scopes/files:write", json={"title": "t" * 129})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "validation.too_long"


# ---- unscoped tools ---------------------------------------------------------------------------------------------

def test_tacc_030_unscoped_tools_setting(owner_client, service):
    assert _access(owner_client, service)["unscoped_tools"] == "allow"
    assert owner_client.get(f"/api/services/{service['id']}").json()["unscoped_tools"] == "allow"
    r = owner_client.put(f"/api/services/{service['id']}/access", json={"unscoped_tools": "require"})
    assert r.status_code == 200 and r.json() == {"service_id": service["id"], "unscoped_tools": "require",
                                                 "previous": "allow"}
    assert _access(owner_client, service)["policy"]["unscoped_tools"] == "require"
    details = _audit(owner_client, "service_unscoped_tools_set")[0]["details"]
    assert details["before"] == "allow" and details["after"] == "require"
    _error(owner_client.put(f"/api/services/{service['id']}/access", json={"unscoped_tools": "deny"}), 400,
           "access.invalid_unscoped_tools")
    assert owner_client.get(f"/api/services/{service['id']}").json()["unscoped_tools"] == "require"


# ---- rules ------------------------------------------------------------------------------------------------------

def test_tacc_040_rule_per_subject_kind(owner_client, service, tools):
    pat = _pat(owner_client, service)
    reg = owner_client.post("/api/oauth/clients", json={
        "client_name": "CI", "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic"}).json()
    owner = _owner_id(owner_client)
    group = owner_client.post("/api/groups", json={"name": "Ops"}).json()
    subjects = [("pat", pat["jti"], "pat"), ("client", reg["client_id"], "CI"),
                ("user", owner.upper(), "owner@example.com"), ("group", group["id"], "Ops")]
    for kind, sid, label in subjects:
        r = _rule(owner_client, service, effect="deny", subject={"kind": kind, "id": sid}, tools=["search"])
        assert r.status_code == 201, r.text
        assert r.json()["subject"]["kind"] == kind and r.json()["subject"]["label"] == label
    # user ids are stored in canonical form (a token's sub)
    rules = owner_client.get(f"/api/services/{service['id']}/access-rules").json()["rules"]
    assert [r["subject"]["id"] for r in rules][2] == owner
    assert len(_audit(owner_client, "tool_rule_create")) == 4


@pytest.mark.parametrize("body,code", [
    ({"effect": "allow", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["search"]},
     "access.invalid_effect"),
    ({"effect": "deny", "subject": {"kind": "role", "id": "x"}, "tools": ["search"]}, "access.invalid_subject_kind"),
    ({"effect": "deny", "subject": {"kind": "client", "id": "no-such-client"}, "tools": ["search"]},
     "access.subject_not_found"),
    ({"effect": "deny", "subject": {"kind": "pat", "id": "no-such-jti"}, "tools": ["search"]},
     "access.subject_not_found"),
    ({"effect": "deny", "subject": {"kind": "user", "id": "not-a-uuid"}, "tools": ["search"]},
     "access.subject_not_found"),
    ({"effect": "deny", "subject": {"kind": "user", "id": str(uuid.UUID(int=1))}, "tools": ["search"]},
     "access.subject_not_found"),
    ({"effect": "deny", "subject": {"kind": "group", "id": str(uuid.UUID(int=2))}, "tools": ["search"]},
     "access.subject_not_found"),
    ({"effect": "deny", "subject": {"kind": "client", "id": " "}, "tools": ["search"]}, "access.subject_not_found"),
    ({"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": []}, "access.no_tools"),
    ({"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["nope"]},
     "access.unknown_tool"),
    ({"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["*", "search"]},
     "access.wildcard_not_alone"),
    ({"effect": "only", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["*"]},
     "access.only_all_tools"),
    ({"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["search"],
      "expires_at": "2000-01-01T00:00:00Z"}, "access.expires_in_past"),
])
def test_tacc_041_rule_validation(owner_client, service, tools, body, code):
    _error(_rule(owner_client, service, **body), 400, code)
    assert owner_client.get(f"/api/services/{service['id']}/access-rules").json()["rules"] == []


def test_tacc_042_pat_must_belong_to_the_server(owner_client, service, tools):
    other = _second_service(owner_client)
    pat = _pat(owner_client, other)
    _error(_rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]}, tools=["*"]), 400,
           "access.pat_other_service")


def test_tacc_043_an_oauth_access_token_is_not_a_pat(owner_client, service, tools, db_session):
    """Per-token rules only make sense for personal access tokens: an OAuth access token's jti changes on every
    refresh."""
    from src.adapters import OAuthClientAdapter
    from src.oauth import service as oauth
    client = OAuthClientAdapter.get(db_session, "mcp-gate-console")
    from src.adapters import ServiceAdapter
    svc = ServiceAdapter.get_existing(db_session, service["id"])
    _, _, rec = oauth.issue_access_token(db_session, sub="x", client_id=client.client_id, scope="",
                                      audience=RESOURCE, service=svc)
    _error(_rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": rec.jti}, tools=["*"]), 400,
           "access.subject_not_found")


def test_tacc_044_tool_names_deduplicated_and_removed_tools_accepted(owner_client, service, tools, db_session):
    from src.adapters import MCPToolAdapter
    MCPToolAdapter.sync_tools(db_session, service["id"], [{"name": "search", "inputSchema": {"type": "object"}}])
    r = _rule(owner_client, service, effect="only", subject={"kind": "client", "id": "mcp-gate-console"},
              tools=["search", "delete_file", "search"])
    assert r.status_code == 201, r.text
    assert r.json()["tools"] == ["search", "delete_file"]


def test_tacc_045_too_many_tools(owner_client, service, tools, monkeypatch):
    monkeypatch.setattr("src.adapters.access_adapter.MAX_TOOLS_PER_RULE", 1)
    _error(_rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"},
                 tools=["search", "read_file"]), 400, "access.too_many_tools")


def test_tacc_046_note_length(owner_client, service, tools):
    r = _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"},
              tools=["search"], note="n" * 257)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "validation.too_long"
    r = _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"},
              tools=["search"], note="n" * 256)
    assert r.status_code == 201, r.text


def test_tacc_047_update_get_delete(owner_client, service, tools):
    base = {"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["search"]}
    rule = _rule(owner_client, service, **base).json()
    path = f"/api/services/{service['id']}/access-rules/{rule['id']}"
    expires = (datetime.now(timezone.utc) + timedelta(days=2)).replace(microsecond=0)
    r = owner_client.put(path, json={**base, "effect": "only", "tools": ["read_file"], "note": "ci only",
                                     "expires_at": expires.isoformat()})
    assert r.status_code == 200, r.text
    assert r.json()["effect"] == "only" and r.json()["tools"] == ["read_file"]
    assert r.json()["expires_at"] == expires.isoformat() and r.json()["expired"] is False
    assert owner_client.get(path).json()["note"] == "ci only"
    upd = _audit(owner_client, "tool_rule_update")[0]["details"]
    assert upd["before"]["effect"] == "deny" and upd["after"]["effect"] == "only"
    # a rule is only reachable through its own server
    other = _second_service(owner_client)
    _error(owner_client.get(f"/api/services/{other['id']}/access-rules/{rule['id']}"), 404, "access.rule_not_found")
    _error(owner_client.delete(f"/api/services/{other['id']}/access-rules/{rule['id']}"), 404,
           "access.rule_not_found")
    assert owner_client.delete(path).status_code == 200
    _error(owner_client.get(path), 404, "access.rule_not_found")
    _error(owner_client.put(path, json=base), 404, "access.rule_not_found")
    assert _audit(owner_client, "tool_rule_delete")[0]["details"]["effect"] == "only"


def test_tacc_048_naive_expiry_is_utc(owner_client, service, tools):
    naive = (datetime.now(timezone.utc) + timedelta(hours=3)).replace(tzinfo=None, microsecond=0)
    r = _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"},
              tools=["search"], expires_at=naive.isoformat())
    assert r.status_code == 201, r.text
    assert r.json()["expires_at"] == naive.replace(tzinfo=timezone.utc).isoformat()
    entry = _access(owner_client, service)["policy"]["rules"][0]
    assert entry["expires_at"] == int(naive.replace(tzinfo=timezone.utc).timestamp())


def test_tacc_049_rules_go_with_their_server(owner_client, service, tools, db_session):
    from db.models import ToolAccessRule
    _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"}, tools=["*"])
    assert owner_client.delete(f"/api/services/{service['id']}").status_code == 200
    assert db_session.query(ToolAccessRule).count() == 0


# ---- limits -----------------------------------------------------------------------------------------------------

def test_tacc_050_rule_count_limit_counts_group_members(owner_client, service, tools, monkeypatch, db_session):
    monkeypatch.setattr("src.adapters.access_adapter.MAX_RULES_PER_SERVICE", 2)
    from src.adapters import AdminUserAdapter
    second = AdminUserAdapter.create(db_session, email="second@example.com", username="second",
                                     password_hash=None, auth_provider="local")
    group = owner_client.post("/api/groups", json={"name": "Two"}).json()
    owner_client.put(f"/api/groups/{group['id']}/members/{_owner_id(owner_client)}")
    assert _rule(owner_client, service, effect="deny", subject={"kind": "group", "id": group["id"]},
                 tools=["search"]).status_code == 201
    # one more rule fits (1 member + 1), a second member would make 3
    assert _rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"},
                 tools=["search"]).status_code == 201
    _error(owner_client.put(f"/api/groups/{group['id']}/members/{second.id}"), 409, "access.rules_limit")
    # re-adding someone already in the group changes nothing, so the limit does not refuse it
    again = owner_client.put(f"/api/groups/{group['id']}/members/{_owner_id(owner_client)}")
    assert again.status_code == 200 and again.json()["added"] is False
    _error(_rule(owner_client, service, effect="deny", subject={"kind": "client", "id": "mcp-gate-console"},
                 tools=["read_file"]), 409, "access.rules_limit")
    assert len(owner_client.get(f"/api/groups/{group['id']}").json()["members"]) == 1


def test_tacc_051_rule_size_limit(owner_client, service, tools, monkeypatch):
    monkeypatch.setattr("src.adapters.access_adapter.MAX_RULES_BYTES_PER_SERVICE", 200)
    body = {"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["search"]}
    first = _rule(owner_client, service, **body)
    assert first.status_code == 201, first.text
    _error(_rule(owner_client, service, **body), 409, "access.rules_too_large")
    # replacing a rule counts it once, not twice
    r = owner_client.put(f"/api/services/{service['id']}/access-rules/{first.json()['id']}", json=body)
    assert r.status_code == 200, r.text


def test_tacc_052_expired_rules_do_not_count(owner_client, service, tools, monkeypatch, db_session):
    from db.models import ToolAccessRule
    monkeypatch.setattr("src.adapters.access_adapter.MAX_RULES_PER_SERVICE", 1)
    body = {"effect": "deny", "subject": {"kind": "client", "id": "mcp-gate-console"}, "tools": ["search"]}
    assert _rule(owner_client, service, **body).status_code == 201
    db_session.query(ToolAccessRule).update({"expires_at": datetime(2000, 1, 1)})
    db_session.commit()
    assert _rule(owner_client, service, **body).status_code == 201


# ---- groups -----------------------------------------------------------------------------------------------------

def test_tacc_060_group_crud_and_members(owner_client):
    owner = _owner_id(owner_client)
    r = owner_client.post("/api/groups", json={"name": " Ops ", "description": "on call"})
    assert r.status_code == 201, r.text
    group = r.json()
    assert group["name"] == "Ops" and group["members"] == [] and group["rules"] == []
    _error(owner_client.post("/api/groups", json={"name": "ops"}), 409, "groups.name_taken")
    r = owner_client.put(f"/api/groups/{group['id']}/members/{owner}")
    assert r.status_code == 200 and r.json()["added"] is True
    assert [m["email"] for m in r.json()["group"]["members"]] == ["owner@example.com"]
    r = owner_client.put(f"/api/groups/{group['id']}/members/{owner}")
    assert r.json()["added"] is False
    assert len(_audit(owner_client, "group_member_add")) == 1
    listed = owner_client.get("/api/groups").json()
    assert listed["total"] == 1 and listed["groups"][0]["member_count"] == 1
    r = owner_client.put(f"/api/groups/{group['id']}", json={"name": "Operators"})
    assert r.json()["name"] == "Operators" and r.json()["description"] == "on call"
    r = owner_client.put(f"/api/groups/{group['id']}", json={"description": None})
    assert r.json()["name"] == "Operators" and r.json()["description"] is None
    assert owner_client.delete(f"/api/groups/{group['id']}/members/{owner}").status_code == 200
    _error(owner_client.delete(f"/api/groups/{group['id']}/members/{owner}"), 404, "groups.member_not_found")
    assert owner_client.delete(f"/api/groups/{group['id']}").status_code == 200
    _error(owner_client.get(f"/api/groups/{group['id']}"), 404, "groups.not_found")
    actions = [e["action"] for e in owner_client.get("/api/audit/logs").json()["logs"]]
    for action in ("group_create", "group_update", "group_member_add", "group_member_remove", "group_delete"):
        assert action in actions


@pytest.mark.parametrize("name", ["", "   ", "x" * 65, "tab\there"])
def test_tacc_061_group_name_validation(owner_client, name):
    _error(owner_client.post("/api/groups", json={"name": name}), 400, "groups.invalid_name")


def test_tacc_062_rename_to_a_taken_name(owner_client):
    owner_client.post("/api/groups", json={"name": "A"})
    b = owner_client.post("/api/groups", json={"name": "B"}).json()
    _error(owner_client.put(f"/api/groups/{b['id']}", json={"name": "a"}), 409, "groups.name_taken")
    assert owner_client.put(f"/api/groups/{b['id']}", json={"name": "b"}).status_code == 200


def test_tacc_063_group_in_use_cannot_be_deleted(owner_client, service, tools):
    group = owner_client.post("/api/groups", json={"name": "G"}).json()
    rule = _rule(owner_client, service, effect="deny", subject={"kind": "group", "id": group["id"]},
                 tools=["*"]).json()
    _error(owner_client.delete(f"/api/groups/{group['id']}"), 409, "groups.in_use")
    detail = owner_client.get(f"/api/groups/{group['id']}").json()
    assert detail["rules"][0]["id"] == rule["id"] and detail["rules"][0]["service_name"] == "demo-mcp"
    owner_client.delete(f"/api/services/{service['id']}/access-rules/{rule['id']}")
    assert owner_client.delete(f"/api/groups/{group['id']}").status_code == 200


def test_tacc_064_unknown_user_or_group(owner_client):
    group = owner_client.post("/api/groups", json={"name": "G"}).json()
    _error(owner_client.put(f"/api/groups/{group['id']}/members/{uuid.uuid4()}"), 404, "auth.user_not_found")
    _error(owner_client.put(f"/api/groups/{group['id']}/members/not-a-uuid"), 404, "auth.user_not_found")
    _error(owner_client.put(f"/api/groups/{uuid.uuid4()}/members/{_owner_id(owner_client)}"), 404,
           "groups.not_found")
    _error(owner_client.delete(f"/api/groups/{group['id']}/members/not-a-uuid"), 404, "groups.member_not_found")


def test_tacc_065_membership_goes_with_the_user(owner_client, db_session):
    from db.models import AdminUser, UserGroupMember
    from src.adapters import AdminUserAdapter
    user = AdminUserAdapter.create(db_session, email="gone@example.com", username="gone", password_hash=None,
                                   auth_provider="local")
    group = owner_client.post("/api/groups", json={"name": "G"}).json()
    owner_client.put(f"/api/groups/{group['id']}/members/{user.id}")
    db_session.query(AdminUser).filter(AdminUser.id == user.id).delete()
    db_session.commit()
    assert db_session.query(UserGroupMember).count() == 0


def test_tacc_066_users_list(owner_client):
    users = owner_client.get("/api/users").json()["users"]
    assert [u["email"] for u in users] == ["owner@example.com"]
    assert "password_hash" not in users[0]


# ---- the policy a server gets -----------------------------------------------------------------------------------

def test_tacc_070_policy_expands_groups_and_drops_expired_rules(owner_client, service, tools, db_session):
    from db.models import ToolAccessRule
    owner = _owner_id(owner_client)
    group = owner_client.post("/api/groups", json={"name": "G"}).json()
    empty = owner_client.post("/api/groups", json={"name": "Empty"}).json()
    owner_client.put(f"/api/groups/{group['id']}/members/{owner}")
    g_rule = _rule(owner_client, service, effect="deny", subject={"kind": "group", "id": group["id"]},
                   tools=["delete_file"]).json()
    _rule(owner_client, service, effect="deny", subject={"kind": "group", "id": empty["id"]}, tools=["*"])
    old = _rule(owner_client, service, effect="only", subject={"kind": "client", "id": "mcp-gate-console"},
                tools=["search"]).json()
    db_session.query(ToolAccessRule).filter(ToolAccessRule.id == uuid.UUID(old["id"])).update(
        {"expires_at": datetime(2000, 1, 1)})
    db_session.commit()
    access = _access(owner_client, service)
    assert access["policy"]["rules"] == [{"id": g_rule["id"], "effect": "deny",
                                          "subject": {"kind": "user", "id": owner}, "tools": ["delete_file"],
                                          "expires_at": None}]
    assert [r["expired"] for r in access["rules"]] == [False, False, True]
    assert access["rules_version"] == 1 and access["limits"]["rules_per_service"] == 2000


def test_tacc_071_policy_end_to_end_with_a_real_pat(owner_client, service, tools):
    """Assign scopes and rules through the API, issue a real PAT, and evaluate the built policy against its
    claims: the same input PR 2's feed will carry."""
    import jwt as pyjwt
    _scope(owner_client, "files:write")
    _scope(owner_client, "files:read", service_id=service["id"])
    _set(owner_client, service, tools["delete_file"], ["files:write"])
    _set(owner_client, service, tools["read_file"], ["files:read"])
    pat = owner_client.post("/api/oauth/tokens/personal", json={
        "service_id": service["id"], "label": "reader", "scopes": ["files:read"]}).json()
    claims = pyjwt.decode(pat["access_token"], options={"verify_signature": False})
    policy = _access(owner_client, service)["policy"]
    verdicts = {t: evaluate(policy, claims, t)["decision"] for t in tools}
    assert verdicts == {"delete_file": "needs_scope", "read_file": "allowed", "search": "allowed"}
    assert evaluate(policy, claims, "delete_file")["challenge"] == "files:write"

    _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]}, tools=["read_file"])
    _rule(owner_client, service, effect="only", subject={"kind": "user", "id": claims["sub"]},
          tools=["read_file", "delete_file"])
    policy = _access(owner_client, service)["policy"]
    verdicts = {t: evaluate(policy, claims, t)["reason"] for t in tools}
    assert verdicts == {"delete_file": "missing_scope", "read_file": "denied_by_rule",
                        "search": "outside_only_rule"}

    owner_client.put(f"/api/services/{service['id']}/access", json={"unscoped_tools": "require"})
    access = _access(owner_client, service)
    tool_rows = {t["name"]: t for t in access["tools"]}
    assert tool_rows["read_file"]["scopes"][0]["source"] == "service"
    assert tool_rows["search"]["scopes"] == [] and tool_rows["search"]["challenge"] is None
    assert {s["name"]: s["challenge_safe"] for s in access["scopes"]}["files:read"] is True


# ---- scope strings longer than 512 characters -------------------------------------------------------------------

def test_tacc_080_long_scope_strings_are_stored(owner_client, service):
    """Scope columns are TEXT since #37: a client and its token may carry more than the old VARCHAR(512) (only
    PostgreSQL enforced it; run with TEST_DATABASE_URL)."""
    names = [f"bundle:{i:02d}-{'x' * 20}" for i in range(30)]
    for name in names:
        _scope(owner_client, name, service_id=service["id"])
    scope = " ".join(names)
    assert len(scope) > 512
    reg = owner_client.post("/api/oauth/clients", json={
        "client_name": "Many bundles", "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic", "scope": scope})
    assert reg.status_code == 201, reg.text
    r = owner_client.post("/oauth/token", data={"grant_type": "client_credentials", "resource": RESOURCE,
                                                "scope": scope},
                          auth=(reg.json()["client_id"], reg.json()["client_secret"]))
    assert r.status_code == 200, r.text
    assert set(r.json()["scope"].split()) == set(names)
    tokens = owner_client.get("/api/oauth/tokens", params={"client_id": reg.json()["client_id"]}).json()
    assert any(len(t["scope"] or "") > 512 for t in tokens["tokens"])


def test_tacc_081_scope_parameter_cap(owner_client, service):
    from db.models import MAX_SCOPE_STRING
    from src.oauth import service as oauth
    assert oauth.MAX_SCOPE_PARAM == MAX_SCOPE_STRING == 4096
    # a known scope repeated: only the length can refuse it
    too_long = " ".join(["mcp:tools:read"] * 300)
    assert len(too_long) > 4096
    reg = owner_client.post("/api/oauth/clients", json={
        "client_name": "Too much", "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic", "scope": too_long})
    assert reg.status_code == 400 and "too long" in reg.text, reg.text
    fits = " ".join(["mcp:tools:read"] * 270)
    assert len(fits) <= 4096
    ok = owner_client.post("/api/oauth/clients", json={
        "client_name": "Fits", "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic", "scope": fits})
    assert ok.status_code == 201, ok.text


# ---- the console guards -----------------------------------------------------------------------------------------

def test_tacc_090_session_and_origin_required(client, owner_client, service, tools):
    from fastapi.testclient import TestClient
    anonymous = TestClient(owner_client.app, base_url="http://testserver")
    for method, path in (("get", f"/api/services/{service['id']}/access"), ("get", "/api/groups"),
                         ("post", "/api/groups"), ("get", "/api/users"),
                         ("post", f"/api/services/{service['id']}/access-rules")):
        assert getattr(anonymous, method)(path).status_code == 401, path
    r = owner_client.post("/api/groups", json={"name": "X"}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403 and r.json()["detail"]["error"] == "auth.csrf_origin_denied"


def test_tacc_091_limits_are_the_documented_ones():
    assert validation.MAX_RULES_PER_SERVICE == 2000
    assert validation.MAX_RULES_BYTES_PER_SERVICE == 64 * 1024
    assert validation.MAX_TOOLS_PER_RULE == 500
    assert validation.MAX_SCOPES_PER_TOOL == 32
