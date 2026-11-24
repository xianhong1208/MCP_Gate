"""Tool access rules enforced on the server (#37, 1.6 PR 2): policy feed format 2 on MCP Gate's side, and the
copy of the evaluator plus list / call enforcement in MCPGateToolPinning (examples/mcp_gate_hooks.py)."""

import json
import logging
import pathlib
import random
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from src.tool_policy.evaluate import evaluate as gate_evaluate
from tests.test_offline_hooks import _load_hooks_module
from tests.test_tool_access import _owner_id, _pat, _rule, _scope, _set
from tests.test_tool_pinning_middleware import (
    _approved_hashes,
    _call,
    _failing_http,
    _names,
    _server,
    _stop,
    _verifier,
)
from tests.test_tool_policy_feed import _resource_server

VECTORS = json.loads((pathlib.Path(__file__).parent / "fixtures" / "tool_policy_vectors.json").read_text("utf-8"))
AUDIENCE = "http://127.0.0.1:8123/mcp"


@pytest.fixture(scope="module")
def hooks():
    return _load_hooks_module()


@pytest.fixture(autouse=True)
def _fresh_report_window(monkeypatch):
    from src.middleware.rate_limiter import SlidingWindowCounter
    from src.oauth import policy_feed

    monkeypatch.setattr(policy_feed, "_report_window", SlidingWindowCounter(window_size=60))


@pytest.fixture
def tools(service, db_session):
    from src.adapters import MCPToolAdapter
    listed = MCPToolAdapter.sync_tools(db_session, service["id"], [
        {"name": n, "description": n, "inputSchema": {"type": "object"}} for n in ("add", "hello", "search")])
    return {t.name: str(t.id) for t in listed}


def _feed(client, rs, **extra):
    r = client.post("/oauth/policy", data={**rs, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def _status(client, service):
    return client.get(f"/api/oauth/services/{service['id']}/policy-feed").json()


# ---- MCP Gate: feed format 2 ------------------------------------------------------------------------------------

def test_tpen_001_without_the_feature_the_answer_stays_format_1(owner_client, service, tools, db_session):
    rs = _resource_server(owner_client, service)
    pat = _pat(owner_client, service)
    assert _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]},
                 tools=["add"]).status_code == 201
    feed = _feed(owner_client, rs)
    assert feed["format"] == 1 and feed["rules"] == []
    assert not {"rules_version", "unscoped_tools", "tool_scopes"} & set(feed)
    # unknown features alone do not switch the format either
    assert _feed(owner_client, rs, features="rules2 other")["format"] == 1


def test_tpen_002_rules1_gets_the_built_policy(owner_client, service, tools, db_session):
    rs = _resource_server(owner_client, service)
    pat = _pat(owner_client, service)
    _scope(owner_client, "calc:write")
    assert _set(owner_client, service, tools["add"], ["calc:write"]).status_code == 200
    deny = _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]},
                 tools=["hello"]).json()
    group = owner_client.post("/api/groups", json={"name": "Ops"}).json()
    owner = _owner_id(owner_client)
    owner_client.put(f"/api/groups/{group['id']}/members/{owner}")
    only = _rule(owner_client, service, effect="only", subject={"kind": "group", "id": group["id"]},
                 tools=["search"]).json()

    feed = _feed(owner_client, rs, features="rules1")
    assert feed["format"] == 2 and feed["rules_version"] == 1 and feed["unscoped_tools"] == "allow"
    assert feed["tool_scopes"] == {"add": {"any_of": ["calc:write"], "challenge": "calc:write"}}
    assert feed["rules"] == [
        {"id": deny["id"], "effect": "deny", "subject": {"kind": "pat", "id": pat["jti"]}, "tools": ["hello"],
         "expires_at": None},
        {"id": only["id"], "effect": "only", "subject": {"kind": "user", "id": owner}, "tools": ["search"],
         "expires_at": None},
    ]
    # the approvals part is the same as format 1's
    assert feed["tools"] == _feed(owner_client, rs)["tools"]
    # it is exactly what MCP Gate's own evaluator is given
    from src.adapters import ServiceAdapter, ToolAccessAdapter
    built = ToolAccessAdapter.build_policy(db_session, ServiceAdapter.get_existing(db_session, service["id"]))
    assert {k: feed[k] for k in built} == built


def test_tpen_003_every_policy_change_changes_the_etag(owner_client, service, tools):
    rs = _resource_server(owner_client, service)
    pat = _pat(owner_client, service)
    _scope(owner_client, "calc:write")
    group = owner_client.post("/api/groups", json={"name": "Ops"}).json()
    owner = _owner_id(owner_client)
    etag = {"v": _feed(owner_client, rs, features="rules1")["etag"]}
    etag1 = _feed(owner_client, rs)["etag"]

    def changed():
        again = _feed(owner_client, rs, features="rules1", etag=etag["v"])
        assert again["unchanged"] is False, "the change must reach the server in the next poll"
        etag["v"] = again["etag"]
        return again

    assert _feed(owner_client, rs, features="rules1", etag=etag["v"])["unchanged"] is True
    rule = _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]},
                 tools=["hello"]).json()
    changed()
    r = owner_client.put(f"/api/services/{service['id']}/access-rules/{rule['id']}",
                         json={"effect": "deny", "subject": {"kind": "pat", "id": pat["jti"]}, "tools": ["add"]})
    assert r.status_code == 200, r.text
    assert changed()["rules"][0]["tools"] == ["add"]
    assert _set(owner_client, service, tools["add"], ["calc:write"]).status_code == 200
    changed()
    assert owner_client.put(f"/api/services/{service['id']}/access",
                            json={"unscoped_tools": "require"}).status_code == 200
    changed()
    _rule(owner_client, service, effect="only", subject={"kind": "group", "id": group["id"]}, tools=["search"])
    # a rule for an empty group expands to nothing: the server has nothing new to apply
    assert _feed(owner_client, rs, features="rules1", etag=etag["v"])["unchanged"] is True
    assert owner_client.put(f"/api/groups/{group['id']}/members/{owner}").status_code in (200, 201, 204)
    assert changed()["rules"][-1]["subject"] == {"kind": "user", "id": owner}  # until it has a member
    assert owner_client.delete(f"/api/groups/{group['id']}/members/{owner}").status_code in (200, 204)
    assert all(r["subject"]["kind"] != "user" for r in changed()["rules"])
    assert owner_client.delete("/api/oauth/scopes/calc:write").status_code in (200, 204)
    assert changed()["tool_scopes"] == {}
    assert owner_client.delete(f"/api/services/{service['id']}/access-rules/{rule['id']}").status_code in (200, 204)
    changed()
    assert _feed(owner_client, rs, features="rules1", etag=etag["v"])["unchanged"] is True
    # a 1.5 middleware is not made to re-download for changes it ignores
    assert _feed(owner_client, rs, etag=etag1)["unchanged"] is True


def test_tpen_004_expired_rules_leave_the_feed(owner_client, service, tools, db_session):
    rs = _resource_server(owner_client, service)
    pat = _pat(owner_client, service)
    soon = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]}, tools=["add"],
          expires_at=soon)
    feed = _feed(owner_client, rs, features="rules1")
    assert len(feed["rules"]) == 1 and feed["rules"][0]["expires_at"] > time.time()
    from db.models import ToolAccessRule
    db_session.query(ToolAccessRule).update({"expires_at": datetime(2000, 1, 1)})
    db_session.commit()
    again = _feed(owner_client, rs, features="rules1", etag=feed["etag"])
    assert again["unchanged"] is False and again["rules"] == []


@pytest.mark.parametrize("sent,stored", [
    ("rules1", "rules1"),
    ("RULES1, beta  rules1", "rules1 beta"),
    ("rules1 bad!token ../x", "rules1"),
    ("", None),
    ("!!!", None),
    (" ".join(f"feature{i:02d}" for i in range(20)) + " rules1",
     "rules1 feature00 feature01 feature02 feature03 feature04"),  # known features are never pushed out
])
def test_tpen_005_features_are_normalised_and_stored(owner_client, service, db_session, sent, stored):
    from src.oauth.policy_feed import FEATURES_MAX, normalize_features
    assert normalize_features(sent) == stored
    assert stored is None or len(stored) <= FEATURES_MAX
    rs = _resource_server(owner_client, service)
    _feed(owner_client, rs, features=sent)
    from db.models import OAuthClient
    db_session.expire_all()
    assert db_session.query(OAuthClient).filter_by(client_id=rs["client_id"]).one().policy_features == stored


def test_tpen_006_a_change_of_features_is_recorded_at_once(owner_client, service, db_session):
    """Poll times are written at most every 30 s; a server that went back to a 1.5 middleware must not keep
    showing "rules enforced" for that long."""
    from db.models import OAuthClient
    rs = _resource_server(owner_client, service)
    _feed(owner_client, rs, features="rules1")
    assert _status(owner_client, service)["rules_enforced"] is True
    _feed(owner_client, rs)
    db_session.expire_all()
    assert db_session.query(OAuthClient).filter_by(client_id=rs["client_id"]).one().policy_features is None
    assert _status(owner_client, service)["rules_enforced"] is False


def test_tpen_007_console_status_says_whether_rules_are_enforced(owner_client, service, tools):
    pat = _pat(owner_client, service)
    status = _status(owner_client, service)
    assert status["state"] == "not_wired" and status["rules_enforced"] is None
    assert status["has_access_policy"] is False
    rs = _resource_server(owner_client, service)
    other = _resource_server(owner_client, service, name="Second RS")
    status = _status(owner_client, service)
    assert status["state"] == "never_polled" and status["rules_enforced"] is None
    _feed(owner_client, rs, features="rules1")
    status = _status(owner_client, service)
    assert status["rules_enforced"] is True
    assert {s["client_id"]: s["features"] for s in status["resource_servers"]} == \
        {rs["client_id"]: ["rules1"], other["client_id"]: []}  # the second never polled: not counted
    _feed(owner_client, other)
    assert _status(owner_client, service)["rules_enforced"] is False  # one server ignores rules
    _feed(owner_client, other, features="rules1")
    assert _status(owner_client, service)["rules_enforced"] is True
    # something to enforce: a rule, a scoped tool or "require a scope"
    assert owner_client.put(f"/api/services/{service['id']}/access",
                            json={"unscoped_tools": "require"}).status_code == 200
    assert _status(owner_client, service)["has_access_policy"] is True
    assert owner_client.put(f"/api/services/{service['id']}/access",
                            json={"unscoped_tools": "allow"}).status_code == 200
    assert _status(owner_client, service)["has_access_policy"] is False
    _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]}, tools=["add"])
    assert _status(owner_client, service)["has_access_policy"] is True


def test_tpen_008_a_server_without_an_active_service_gets_an_empty_policy(owner_client, service, tools):
    rs = _resource_server(owner_client, service)
    _scope(owner_client, "calc:write")
    assert _set(owner_client, service, tools["add"], ["calc:write"]).status_code == 200
    r = owner_client.put(f"/api/services/{service['id']}", json={"is_active": False})
    assert r.status_code == 200, r.text
    feed = _feed(owner_client, rs, features="rules1")
    assert feed["format"] == 2 and feed["service_id"] is None and feed["unscoped_tools"] == "allow"
    assert feed["tool_scopes"] == {} and feed["rules"] == [] and feed["tools"]["approved"] == []


# ---- the middleware's copy of the evaluator ---------------------------------------------------------------------

@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["label"] for v in VECTORS["vectors"]])
def test_tpen_020_example_reproduces_every_golden_vector(hooks, vector):
    got = hooks.evaluate_access(vector["policy"], vector["token"], vector["tool"], approved=vector["approved"],
                                now=vector["now"])
    assert got == vector["expect"]
    assert hooks.RULES_VERSION == VECTORS["rules_version"]


def _random_policy(rng):
    tools = ["a", "b", "c", "d"]
    scopes = ["s1", "s2", "s3"]
    subject_ids = {"pat": ["j1", "j2", ""], "client": ["c1", "c2"], "user": ["u1", "u2"]}
    rules = []
    for i in range(rng.randint(0, 6)):
        kind = rng.choice(["pat", "client", "user", "user", "role", None])
        subject = rng.choice([{"kind": kind, "id": rng.choice(subject_ids.get(kind, ["x"]))}, "garbage"]) \
            if kind else rng.choice([None, {}])
        rule = {"id": f"r{i}", "effect": rng.choice(["deny", "only", "only", "allow", None]), "subject": subject,
                "tools": rng.choice([rng.sample(tools, rng.randint(0, 3)), ["*"], "a", None, [1, "b"]]),
                "expires_at": rng.choice([None, None, 100, 300, "x", 200.5])}
        rules.append(rule if rng.random() > 0.05 else "not-a-rule")
    tool_scopes = {}
    for tool in tools:
        if rng.random() < 0.5:
            any_of = rng.sample(scopes, rng.randint(0, 3)) + rng.choice([[], [""], [3]])
            tool_scopes[tool] = {"any_of": any_of, "challenge": rng.choice(scopes + [None, "zz"])}
    return {"unscoped_tools": rng.choice(["allow", "require", "other"]), "tool_scopes": tool_scopes, "rules": rules}


def _random_token(rng):
    token = {"jti": rng.choice(["j1", "j2", "", None]), "client_id": rng.choice(["c1", "c2", None]),
             "sub": rng.choice(["u1", "u2", None]),
             "scope": rng.choice([" ".join(rng.sample(["s1", "s2", "s3"], rng.randint(0, 3))), ["s1"], None, 5])}
    return {k: v for k, v in token.items() if v is not None or rng.random() < 0.5}


def test_tpen_021_example_agrees_with_mcp_gate_on_generated_policies(hooks):
    rng = random.Random(37)
    outcomes = set()
    for _ in range(5000):
        policy, token = _random_policy(rng), _random_token(rng)
        tool = rng.choice(["a", "b", "c", "d", "e"])
        approved = rng.random() > 0.1
        now = rng.choice([None, 0, 250, 1000])
        expected = gate_evaluate(policy, token, tool, approved=approved, now=now)
        assert hooks.evaluate_access(policy, token, tool, approved=approved, now=now) == expected, \
            (policy, token, tool, approved, now)
        outcomes.add(expected["reason"])
    assert len(outcomes) == 6, outcomes  # the generator reaches every reason


# ---- the middleware ---------------------------------------------------------------------------------------------

def _answer(approved, *, access=None, fmt=2, etag="1"):
    body = {"format": fmt, "hash_version": 1, "audience": AUDIENCE, "etag": etag, "unchanged": False,
            "tools": {"approved": approved, "pending": [], "rejected": []}, "rules": []}
    if access is not None:
        body.update(access)
    return body


def _access(rules=(), tool_scopes=None, unscoped="allow", version=1):
    return {"rules_version": version, "unscoped_tools": unscoped, "tool_scopes": tool_scopes or {},
            "rules": list(rules)}


def _mock_feed(answers, seen=None):
    """An httpx client whose POST /oauth/policy returns answers[-1] (a list, so a test can change it)."""
    def handler(request):
        if seen is not None:
            seen.append(dict(httpx.QueryParams(request.content.decode())))
        if answers[-1] is None:
            raise httpx.ConnectError("MCP Gate is down", request=request)
        return httpx.Response(200, json=answers[-1])
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _as(pinning, claims):
    pinning._token_claims = lambda: dict(claims)


PAT = {"jti": "pat-1", "client_id": "mcp-gate-console", "sub": "user-a", "scope": "mcp:tools:invoke"}
DENY_HELLO = {"id": "r1", "effect": "deny", "subject": {"kind": "pat", "id": "pat-1"}, "tools": ["hello"],
              "expires_at": None}
ADD_NEEDS = {"add": {"any_of": ["calc:admin", "calc:write"], "challenge": "calc:write"}}


@pytest.mark.asyncio
async def test_tpen_030_rules_hide_and_scopes_refuse_with_the_scope_named(hooks, tmp_path):
    approved = await _approved_hashes(hooks)
    seen = []
    answers = [_answer(approved, access=_access([DENY_HELLO], ADD_NEEDS))]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers, seen)), cache_file=None)
    _as(pinning, PAT)
    assert await _names(mcp) == ["add"]  # hello denied for this PAT, add listed (more scope would unlock it)
    assert seen[0]["features"] == "rules1"
    hidden = await _call(mcp, "hello", {"name": "x"})
    assert hidden == "ERROR: Tool 'hello' is not available on this server."
    refused = await _call(mcp, "add", {"a": 1, "b": 2})
    assert refused.startswith("ERROR: Tool 'add' requires the scope 'calc:write'")
    # the token gains the scope: allowed
    _as(pinning, {**PAT, "scope": "calc:admin"})
    assert await _call(mcp, "add", {"a": 1, "b": 2}) == "3"
    # another token is not concerned by the PAT's deny rule
    _as(pinning, {"jti": "oauth-x", "client_id": "app", "sub": "user-a", "scope": "calc:write"})
    assert await _names(mcp) == ["add", "hello"]
    assert await _call(mcp, "hello", {"name": "x"}) == "Hello, x!"
    await _stop(pinning)


@pytest.mark.asyncio
async def test_tpen_031_only_rules_user_rules_and_require_a_scope(hooks):
    approved = await _approved_hashes(hooks)
    only = {"id": "r2", "effect": "only", "subject": {"kind": "user", "id": "user-a"}, "tools": ["add"],
            "expires_at": None}
    answers = [_answer(approved, access=_access([only]))]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers)), cache_file=None)
    _as(pinning, PAT)
    assert await _names(mcp) == ["add"]
    assert (await _call(mcp, "hello", {"name": "x"})).endswith("is not available on this server.")
    _as(pinning, {**PAT, "sub": "user-b"})
    assert await _names(mcp) == ["add", "hello"]
    # the server requires a scope for every tool: unscoped tools disappear for everyone
    answers.append(_answer(approved, access=_access([], ADD_NEEDS, unscoped="require"), etag="2"))
    await pinning.poll_policy()
    assert await _names(mcp) == ["add"]
    await _stop(pinning)


@pytest.mark.asyncio
async def test_tpen_032_probe_tokens_still_see_every_tool(hooks):
    approved = await _approved_hashes(hooks)
    deny_all = {"id": "r3", "effect": "deny", "subject": {"kind": "user", "id": "mcp-gate-scanner"}, "tools": ["*"],
                "expires_at": None}
    answers = [_answer(approved[:1], access=_access([deny_all], unscoped="require"))]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers)), cache_file=None)
    _as(pinning, {"jti": "p", "client_id": "mcp-gate-scanner", "sub": "mcp-gate-scanner", "mcp_gate_probe": True})
    assert await _names(mcp) == ["add", "hello"]
    _as(pinning, {"jti": "p", "client_id": "mcp-gate-scanner", "sub": "mcp-gate-scanner"})
    assert await _names(mcp) == []
    await _stop(pinning)


@pytest.mark.asyncio
async def test_tpen_033_a_format_1_answer_enforces_approvals_only(hooks, caplog):
    """An MCP Gate older than 1.6 ignores ``features`` and answers format 1: no rules to apply."""
    approved = await _approved_hashes(hooks)
    answers = [_answer(approved, fmt=1)]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers)), cache_file=None)
    _as(pinning, PAT)
    with caplog.at_level(logging.INFO, logger="mcp_gate_hooks"):
        assert await _names(mcp) == ["add", "hello"]
    assert pinning.access_policy is None and pinning.state == "feed"
    assert any("no access rules" in r.getMessage() for r in caplog.records)
    await _stop(pinning)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [
    {"format": 3},
    {"rules_version": 2},
    {"rules": "deny everything"},
    {"tool_scopes": []},
    {"tool_scopes": {"add": "calc:write"}},
    {"unscoped_tools": None},
    {"rules": ["not-a-rule"]},
])
async def test_tpen_034_an_answer_this_file_cannot_apply_keeps_the_last_policy(hooks, bad):
    approved = await _approved_hashes(hooks)
    answers = [None]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers)), cache_file=None)
    _as(pinning, PAT)
    # never received anything usable: closed
    answers.append({**_answer(approved, access=_access([DENY_HELLO])), **bad})
    with pytest.raises(hooks.PolicyUnavailable):
        await pinning.poll_policy()
    assert pinning.state == "closed" and await _names(mcp) == []
    # a good answer, then a bad one: the good one stays in force
    answers.append(_answer(approved, access=_access([DENY_HELLO]), etag="good"))
    await pinning.poll_policy()
    answers.append({**_answer(approved, access=_access([]), etag="bad"), **bad})
    with pytest.raises(hooks.PolicyUnavailable):
        await pinning.poll_policy()
    assert await _names(mcp) == ["add"] and pinning._policy["etag"] == "good"
    await _stop(pinning)


@pytest.mark.asyncio
async def test_tpen_035_last_rules_apply_while_mcp_gate_is_down_and_after_a_restart(hooks, tmp_path):
    approved = await _approved_hashes(hooks)
    cache = tmp_path / "policy.json"
    answers = [_answer(approved, access=_access([DENY_HELLO], ADD_NEEDS))]
    verifier = _verifier(hooks, None, AUDIENCE, _mock_feed(answers))
    mcp, pinning = _server(hooks, verifier, cache_file=str(cache))
    _as(pinning, PAT)
    assert await _names(mcp) == ["add"]
    data = json.loads(cache.read_text())
    assert data["format"] == 2 and data["access"]["rules"] == [DENY_HELLO]
    assert data["access"]["tool_scopes"] == ADD_NEEDS
    answers.append(None)  # MCP Gate goes away
    with pytest.raises(httpx.ConnectError):
        await pinning.poll_policy()
    assert await _names(mcp) == ["add"]
    assert (await _call(mcp, "add", {"a": 1, "b": 1})).startswith("ERROR: Tool 'add' requires the scope 'calc:write'")
    await _stop(pinning)

    # restart while MCP Gate is down: the cache brings the rules back
    mcp2, pinning2 = _server(hooks, _verifier(hooks, None, AUDIENCE, _failing_http()), cache_file=str(cache))
    _as(pinning2, PAT)
    assert pinning2.state == "cache" and pinning2.access_policy["rules"] == [DENY_HELLO]
    assert await _names(mcp2) == ["add"]
    await _stop(pinning2)

    # a cache from a 1.5 middleware (format 1, approvals only) is still used, without rules
    data.pop("access")
    data["format"] = 1
    cache.write_text(json.dumps(data))
    mcp3, pinning3 = _server(hooks, _verifier(hooks, None, AUDIENCE, _failing_http()), cache_file=str(cache))
    _as(pinning3, PAT)
    assert pinning3.state == "cache" and pinning3.access_policy is None
    assert await _names(mcp3) == ["add", "hello"]
    await _stop(pinning3)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"rules_version": 2},
    {"rules": "x"},
    {"tool_scopes": None},
])
async def test_tpen_036_a_cache_with_rules_this_file_cannot_apply_is_ignored(hooks, tmp_path, caplog, change):
    approved = await _approved_hashes(hooks)
    cache = tmp_path / "policy.json"
    cache.write_text(json.dumps({
        "format": 2, "hash_version": 1, "issuer": "http://testserver", "audience": AUDIENCE, "etag": "e",
        "received_at": time.time(), "approved": approved, "pending": [], "rejected": [],
        "access": {**_access([DENY_HELLO]), **change}}))
    with caplog.at_level(logging.WARNING, logger="mcp_gate_hooks"):
        mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _failing_http()), cache_file=str(cache))
    assert pinning.state == "closed" and await _names(mcp) == []
    assert any("Ignoring the MCP Gate tool policy cache" in r.getMessage() for r in caplog.records)
    await _stop(pinning)


@pytest.mark.asyncio
async def test_tpen_037_an_expired_rule_stops_applying_without_a_poll(hooks, monkeypatch):
    approved = await _approved_hashes(hooks)
    expires = time.time() + 60
    answers = [_answer(approved, access=_access([{**DENY_HELLO, "expires_at": expires}]))]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers)), cache_file=None)
    _as(pinning, PAT)
    assert await _names(mcp) == ["add"]
    answers.append(None)  # no poll can succeed: the expiry alone lifts the rule
    real = time.time
    monkeypatch.setattr(hooks.time, "time", lambda: real() + 120)
    assert await _names(mcp) == ["add", "hello"]
    await _stop(pinning)


# ---- end to end with MCP Gate's app -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tpen_040_rules_from_the_console_reach_the_server_in_one_poll(hooks, owner_client, service, app,
                                                                         tmp_path):
    rs = _resource_server(owner_client, service)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as http:
        verifier = _verifier(hooks, rs, service["effective_audience"], http)
        mcp, pinning = _server(hooks, verifier, cache_file=str(tmp_path / "policy.json"))
        assert await _names(mcp) == []
        await pinning.flush_reports()
        listed = owner_client.get(f"/api/services/{service['id']}/tools").json()
        r = owner_client.post(f"/api/services/{service['id']}/tools/approve-all",
                              json={"hashes": [t["hash"] for t in listed["tools"]]})
        assert r.status_code == 200, r.text
        await pinning.poll_policy()
        pat = _pat(owner_client, service)
        owner = _owner_id(owner_client)
        claims = {"jti": pat["jti"], "client_id": "mcp-gate-console", "sub": owner, "scope": "mcp:tools:invoke"}
        _as(pinning, claims)
        assert await _names(mcp) == ["add", "hello"]
        assert _status(owner_client, service)["rules_enforced"] is True

        # a deny rule on the PAT: hidden after one poll
        rule = _rule(owner_client, service, effect="deny", subject={"kind": "pat", "id": pat["jti"]},
                     tools=["hello"]).json()
        await pinning.poll_policy()
        assert await _names(mcp) == ["add"]
        owner_client.delete(f"/api/services/{service['id']}/access-rules/{rule['id']}")

        # a group "only" rule: applies once the user joins the group, stops when they leave
        group = owner_client.post("/api/groups", json={"name": "Calc"}).json()
        _rule(owner_client, service, effect="only", subject={"kind": "group", "id": group["id"]}, tools=["add"])
        await pinning.poll_policy()
        assert await _names(mcp) == ["add", "hello"]
        owner_client.put(f"/api/groups/{group['id']}/members/{owner}")
        await pinning.poll_policy()
        assert await _names(mcp) == ["add"]
        owner_client.delete(f"/api/groups/{group['id']}/members/{owner}")
        await pinning.poll_policy()
        assert await _names(mcp) == ["add", "hello"]

        # a scope on a tool: listed, refused naming it
        tools = {t["name"]: t["id"] for t in owner_client.get(f"/api/services/{service['id']}/tools").json()["tools"]}
        _scope(owner_client, "calc:write")
        assert _set(owner_client, service, tools["add"], ["calc:write"]).status_code == 200
        await pinning.poll_policy()
        assert await _names(mcp) == ["add", "hello"]
        assert (await _call(mcp, "add", {"a": 1, "b": 1})).startswith(
            "ERROR: Tool 'add' requires the scope 'calc:write'")
        await _stop(pinning)
