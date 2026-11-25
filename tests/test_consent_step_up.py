"""The consent page for step-up (#37, 1.6 PR 3): each requested scope lists the approved tools it unlocks on the
server, and what the user had not agreed to before (a new scope, a tool new to them) is marked; remembering a
step-up keeps what was remembered before (the consent store merges); the consent audit records a step-up and the
scopes it added."""

from urllib.parse import parse_qs, urlparse

import pytest

from tests.conftest import make_pkce
from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _register


@pytest.fixture
def tools(owner_client, service, db_session):
    """Three approved tools; delete_file and move_file in files:write, read_file in files:read, one pending tool."""
    from src.adapters import MCPToolAdapter

    MCPToolAdapter.sync_tools(db_session, service["id"], [
        {"name": n, "description": n, "inputSchema": {"type": "object"}}
        for n in ("delete_file", "move_file", "read_file")])
    listed = owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]
    r = owner_client.post(f"/api/services/{service['id']}/tools/approve-all",
                          json={"hashes": [t["hash"] for t in listed]})
    assert r.status_code == 200, r.text
    MCPToolAdapter.sync_tools(db_session, service["id"], [
        {"name": n, "description": n, "inputSchema": {"type": "object"}}
        for n in ("delete_file", "move_file", "read_file", "wipe_disk")])
    ids = {t["name"]: t["id"] for t in owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]}
    for name in ("files:read", "files:write"):
        assert owner_client.put(f"/api/oauth/scopes/{name}", json={"description": name}).status_code == 200
    _set(owner_client, service, ids["read_file"], ["files:read"])
    _set(owner_client, service, ids["delete_file"], ["files:write"])
    _set(owner_client, service, ids["wipe_disk"], ["files:write"])  # pending: never shown as unlocked
    return ids


def _set(client, service, tool_id, scopes):
    r = client.put(f"/api/services/{service['id']}/tools/{tool_id}/scopes", json={"scopes": scopes})
    assert r.status_code == 200, r.text


def _request(client, client_id, scope):
    _verifier, challenge = make_pkce()
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI, "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": RESOURCE, "scope": scope}, follow_redirects=False)
    assert r.status_code == 302, r.text
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    return rid, client.get(f"/oauth/authorize/requests/{rid}").json()


def _exchange(client, client_id, code, verifier):
    r = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id,
                                          "redirect_uri": REDIRECT_URI, "code_verifier": verifier,
                                          "resource": RESOURCE})
    assert r.status_code == 200, r.text
    return r.json()


def _by_name(info):
    return {s["name"]: s for s in info["scopes"]}


def test_csup_001_first_consent_lists_tools_per_scope_without_marks(owner_client, service, tools):
    app = _register(owner_client)
    _rid, info = _request(owner_client, app["client_id"], "mcp:tools:invoke files:read files:write")
    scopes = _by_name(info)
    assert [t["name"] for t in scopes["files:read"]["tools"]] == ["read_file"]
    assert [t["name"] for t in scopes["files:write"]["tools"]] == ["delete_file"]  # wipe_disk is not approved
    assert scopes["mcp:tools:invoke"]["tools"] == []
    assert info["previous_grant"] is None and info["step_up"] is False
    assert not any(s["new"] for s in scopes.values())
    assert not any(t["new"] for s in scopes.values() for t in s["tools"])


def test_csup_002_a_step_up_marks_the_new_scope_and_its_tools(owner_client, service, tools):
    app = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, app["client_id"], scope="mcp:tools:invoke files:read")
    _exchange(owner_client, app["client_id"], code, verifier)  # the user now holds a token with files:read
    # the admin adds move_file to files:read after that consent: new to the user although the scope is not
    _set(owner_client, service, tools["move_file"], ["files:read"])
    _rid, info = _request(owner_client, app["client_id"], "mcp:tools:invoke files:read files:write")
    scopes = _by_name(info)
    assert info["step_up"] is True
    assert info["previous_grant"]["source"] == "token"
    assert info["previous_grant"]["scopes"] == ["files:read", "mcp:tools:invoke"]
    assert {n: s["new"] for n, s in scopes.items()} == {"mcp:tools:invoke": False, "files:read": False,
                                                       "files:write": True}
    assert {t["name"]: t["new"] for t in scopes["files:read"]["tools"]} == {"move_file": True, "read_file": False}
    assert {t["name"]: t["new"] for t in scopes["files:write"]["tools"]} == {"delete_file": True}
    # asking for no more than before is not a step-up
    _rid, info = _request(owner_client, app["client_id"], "files:read")
    assert info["step_up"] is False and _by_name(info)["files:read"]["new"] is False


def test_csup_003_remembering_a_step_up_keeps_what_was_remembered(owner_client, service, tools):
    app = _register(owner_client)
    _authorize_and_consent(owner_client, app["client_id"], scope="mcp:tools:invoke files:read", remember=True)
    # the client asks only for the challenged scope (it does not union): the page asks once
    rid, info = _request(owner_client, app["client_id"], "files:write")
    assert info["can_skip"] is False and info["step_up"] is True
    assert info["previous_grant"]["source"] == "consent"
    d = owner_client.post(f"/oauth/authorize/requests/{rid}/decision", json={"approve": True, "remember": True})
    assert d.status_code == 200, d.text
    consents = owner_client.get("/api/oauth/consents").json()
    consents = consents.get("consents", consents) if isinstance(consents, dict) else consents
    assert sorted(consents[0]["scopes"]) == ["files:read", "files:write", "mcp:tools:invoke"]
    # every earlier scope is still remembered: asking for all of them again needs no page
    _rid, info = _request(owner_client, app["client_id"], "mcp:tools:invoke files:read files:write")
    assert info["can_skip"] is True


def test_csup_004_the_consent_audit_records_a_step_up(owner_client, service, tools):
    app = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, app["client_id"], scope="mcp:tools:invoke")
    _exchange(owner_client, app["client_id"], code, verifier)
    rid, _info = _request(owner_client, app["client_id"], "mcp:tools:invoke files:write")
    assert owner_client.post(f"/oauth/authorize/requests/{rid}/decision",
                             json={"approve": True}).status_code == 200
    logs = owner_client.get("/api/audit/logs", params={"limit": 50}).json()["logs"]
    approvals = [e for e in logs if e["action"] == "oauth_consent_approve"]
    assert approvals[0]["details"]["step_up"] is True
    assert approvals[0]["details"]["added_scopes"] == ["files:write"]
    assert approvals[-1]["details"]["step_up"] is False and approvals[-1]["details"]["added_scopes"] == []


def test_csup_005_the_previous_grant_is_this_users_through_this_client_for_this_server(owner_client, service, tools,
                                                                                      db_session):
    from db.models import AdminUser
    from src.oauth.service import previous_grant

    app = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, app["client_id"], scope="files:read")
    _exchange(owner_client, app["client_id"], code, verifier)
    owner = db_session.query(AdminUser).one()
    assert previous_grant(db_session, owner, app["client_id"], RESOURCE)["scopes"] == {"files:read"}
    assert previous_grant(db_session, owner, app["client_id"], "http://127.0.0.1:9999/mcp") is None
    other = _register(owner_client)
    assert previous_grant(db_session, owner, other["client_id"], RESOURCE) is None
