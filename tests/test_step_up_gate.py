"""The step-up gate (#37, 1.6 PR 3): MCPGateScopeGate in examples/mcp_gate_hooks.py answers a tools/call that only
lacks a scope with a real HTTP 403 ``insufficient_scope`` challenge, before FastMCP starts its response, and passes
everything else through untouched. These tests drive the ASGI gate directly, in front of a recording app, with the
real pinning middleware and a real FastMCP server behind it (the end-to-end runs are in test_step_up_interop.py)."""

import json
from types import SimpleNamespace

import pytest

from tests.test_tool_pinning_middleware import _approved_hashes, _server, _stop, _verifier
from tests.test_tool_policy_enforcement import ADD_NEEDS, AUDIENCE, DENY_HELLO, _access, _answer, _mock_feed

USER = {"jti": "oauth-1", "client_id": "app", "sub": "user-a", "scope": "mcp:tools:invoke offline_access"}
PAT = {"jti": "pat-1", "client_id": "mcp-gate-console", "sub": "user-a", "scope": "mcp:tools:invoke"}
MACHINE = {"jti": "cc-1", "client_id": "ci-bot", "sub": "ci-bot", "scope": "mcp:tools:invoke"}


@pytest.fixture(scope="module")
def hooks():
    from tests.test_offline_hooks import _load_hooks_module
    return _load_hooks_module()


class _App:
    """The app behind the gate: records whether it ran and the body it read, and answers 200."""

    def __init__(self, stream=False):
        self.calls = 0
        self.body = None
        self.stream = stream

    async def __call__(self, scope, receive, send):
        self.calls += 1
        body = b""
        if scope["method"] == "POST":
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body"):
                    break
        self.body = body
        if self.stream:
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text/event-stream")]})
            for i in range(3):
                await send({"type": "http.response.body", "body": f"data: {i}\n\n".encode(), "more_body": True})
            await send({"type": "http.response.body", "body": b""})
            return
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"ok":true}'})


async def _gate(hooks, *, access=None, approved=None, **kw):
    approved = await _approved_hashes(hooks) if approved is None else approved
    answers = [_answer(approved, access=access if access is not None else _access([DENY_HELLO], ADD_NEEDS))]
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed(answers)), cache_file=None)
    app = _App(stream=kw.pop("stream", False))
    return hooks.MCPGateScopeGate(app, pinning=pinning, server=mcp, **kw), app, pinning


def _call(name="add", request_id=1, **params):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": {"a": 1, "b": 2}, **params}}


async def _send(gate, body=None, *, claims=USER, method="POST", headers=(), chunks=None, user=True):
    """Run one request through the gate. Returns (status, headers dict, body bytes, number of receive() calls)."""
    raw = json.dumps(body).encode() if body is not None and not isinstance(body, bytes) else (body or b"")
    parts = chunks if chunks is not None else [raw]
    messages = [{"type": "http.request", "body": p, "more_body": i < len(parts) - 1} for i, p in enumerate(parts)]
    reads = {"n": 0}

    async def receive():
        reads["n"] += 1
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    sent = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": "/mcp", "headers": [(k.encode(), v.encode()) for k, v in headers]}
    if user:
        scope["user"] = SimpleNamespace(access_token=SimpleNamespace(claims=dict(claims) if claims else None))
    await gate(scope, receive, send)
    start = sent[0]
    return (start["status"], {k.decode(): v.decode() for k, v in start["headers"]},
            b"".join(m.get("body", b"") for m in sent[1:]), reads["n"], sent)


def _challenge(header):
    assert header.startswith("Bearer ")
    out = {}
    for part in header[len("Bearer "):].split('", '):
        key, _, value = part.partition('="')
        out[key] = value.rstrip('"')
    return out


# ---- the challenge ----------------------------------------------------------------------------------------------

async def test_tsug_001_a_call_that_only_lacks_a_scope_gets_a_403_challenge(hooks):
    gate, app, pinning = await _gate(hooks)
    status, headers, body, _, _ = await _send(gate, _call(request_id=7))
    assert status == 403 and app.calls == 0
    challenge = _challenge(headers["www-authenticate"])
    assert challenge["error"] == "insufficient_scope"
    # default: only the scope the tool needs (MCP 2026-07-28; clients union it with what they hold)
    assert challenge["scope"] == "calc:write"
    assert challenge["resource_metadata"] == "http://127.0.0.1:8123/.well-known/oauth-protected-resource/mcp"
    assert challenge["error_description"].startswith("Tool 'add' requires the scope 'calc:write', which this access")
    reply = json.loads(body)
    assert reply["id"] == 7 and reply["error"]["data"] == {"error": "insufficient_scope", "scope": "calc:write"}
    assert reply["error"]["message"] == challenge["error_description"]
    assert headers["content-type"] == "application/json" and int(headers["content-length"]) == len(body)
    await _stop(pinning)


async def test_tsug_002_challenge_with_the_tokens_scopes_too(hooks):
    gate, app, pinning = await _gate(hooks, challenge_includes_token_scopes=True)
    status, headers, _, _, _ = await _send(gate, _call())
    assert status == 403
    # the token's scopes first, then the needed one; never offline_access (MCP 2026-07-28)
    assert _challenge(headers["www-authenticate"])["scope"] == "mcp:tools:invoke calc:write"
    await _stop(pinning)


async def test_tsug_015_a_call_sent_in_several_chunks_is_still_challenged(hooks):
    gate, app, pinning = await _gate(hooks)
    raw = json.dumps(_call()).encode()
    status, _, _, _, _ = await _send(gate, chunks=[raw[:7], raw[7:30], raw[30:]])
    assert status == 403 and app.calls == 0
    await _stop(pinning)


async def test_tsug_003_the_token_holding_the_scope_reaches_the_app_with_the_same_bytes(hooks):
    gate, app, pinning = await _gate(hooks)
    raw = json.dumps(_call()).encode()
    status, _, body, _, _ = await _send(gate, claims={**USER, "scope": "mcp:tools:invoke calc:admin"},
                                        chunks=[raw[:10], raw[10:25], raw[25:]])
    assert status == 200 and body == b'{"ok":true}'
    assert app.calls == 1 and app.body == raw  # replayed exactly, chunk by chunk
    await _stop(pinning)


@pytest.mark.parametrize("body", [
    _call("hello"),                     # hidden by a deny rule for... another token: allowed for USER
    _call("nope"),                      # unknown tool
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    b"{not json",
    b"\xff\xfe",
    [],
    _call(name=None),
])
async def test_tsug_004_anything_else_passes_through(hooks, body):
    gate, app, pinning = await _gate(hooks)
    status, _, _, _, _ = await _send(gate, body)
    assert status == 200 and app.calls == 1
    await _stop(pinning)


async def test_tsug_005_hidden_and_unapproved_tools_are_never_challenged(hooks):
    # hidden by a rule (needs-scope too, but the rule decides first): the middleware refuses it as unknown
    deny_add = {**DENY_HELLO, "tools": ["add"]}
    gate, app, pinning = await _gate(hooks, access=_access([deny_add], ADD_NEEDS))
    assert (await _send(gate, _call(), claims=PAT))[0] == 200
    await _stop(pinning)
    # approved list without "add": a call to it is not answered with a challenge (that would reveal the tool)
    gate, app, pinning = await _gate(hooks, approved=[])
    assert (await _send(gate, _call()))[0] == 200
    await _stop(pinning)
    # MCP Gate older than 1.6 (format 1, no rules): nothing is scoped
    approved = await _approved_hashes(hooks)
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE, _mock_feed([_answer(approved, fmt=1)])),
                           cache_file=None)
    gate = hooks.MCPGateScopeGate(_App(), pinning=pinning, server=mcp)
    assert (await _send(gate, _call()))[0] == 200
    await _stop(pinning)


# ---- body cap, batches, probe tokens, streams ---------------------------------------------------------------------

async def test_tsug_006_a_body_over_the_cap_passes_through_whole(hooks):
    gate, app, pinning = await _gate(hooks, max_body=64)
    raw = json.dumps(_call(padding="x" * 200)).encode()
    # without content-length: read up to the cap, then the rest is replayed after what was read
    status, _, _, _, _ = await _send(gate, chunks=[raw[:50], raw[50:100], raw[100:]])
    assert status == 200 and app.body == raw
    # with a content-length over the cap: not read at all by the gate
    read = gate._read

    async def must_not_read(receive):
        raise AssertionError("the gate read a body it knows is over the cap")
    gate._read = must_not_read
    status, _, _, _, _ = await _send(gate, raw, headers=[("content-length", str(len(raw)))])
    assert status == 200 and app.body == raw
    gate._read = read
    # the same call under the cap is challenged
    gate, app, pinning2 = await _gate(hooks, max_body=len(raw))
    assert (await _send(gate, raw))[0] == 403
    await _stop(pinning)
    await _stop(pinning2)


async def test_tsug_007_a_batch_is_refused_only_when_every_call_needs_the_same_scope(hooks):
    two_scoped = {**ADD_NEEDS, "hello": {"any_of": ["greet"], "challenge": "greet"}}
    gate, app, pinning = await _gate(hooks, access=_access([], two_scoped))
    status, headers, body, _, _ = await _send(gate, [_call(request_id=1), _call(request_id=2)])
    assert status == 403 and app.calls == 0
    assert [e["id"] for e in json.loads(body)] == [1, 2]
    # different scopes: passed through, the middleware refuses each call
    assert (await _send(gate, [_call(request_id=1), _call("hello", request_id=2)]))[0] == 200
    # one call allowed: passed through
    assert (await _send(gate, [_call(request_id=1), _call("add", request_id=2)],
                        claims={**USER, "scope": "calc:write"}))[0] == 200
    # a batch with something else than tools/call: passed through, even when it names a scoped tool
    assert (await _send(gate, [_call(), {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}]))[0] == 200
    other = {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"name": "add"}}
    assert (await _send(gate, [_call(), other]))[0] == 200
    await _stop(pinning)


async def test_tsug_008_probe_tokens_and_requests_without_a_token_pass_through(hooks):
    gate, app, pinning = await _gate(hooks)
    assert (await _send(gate, _call(), claims={**USER, "mcp_gate_probe": True}))[0] == 200
    assert (await _send(gate, _call(), user=False))[0] == 200
    assert (await _send(gate, _call(), claims=None))[0] == 200
    assert app.calls == 3
    await _stop(pinning)


async def test_tsug_009_a_token_without_the_servers_required_scopes_is_left_to_fastmcp(hooks):
    gate, app, pinning = await _gate(hooks)
    gate.server.auth = SimpleNamespace(required_scopes=["mcp:tools:invoke"])
    assert (await _send(gate, _call(), claims={**USER, "scope": "other"}))[0] == 200
    assert (await _send(gate, _call()))[0] == 403
    await _stop(pinning)


async def test_tsug_010_get_delete_and_other_named_methods_are_not_read(hooks):
    gate, app, pinning = await _gate(hooks, stream=True)
    status, _, body, reads, sent = await _send(gate, method="GET")
    assert status == 200 and reads == 0
    assert body == b"data: 0\n\ndata: 1\n\ndata: 2\n\n"
    assert len(sent) == 5 and all(m.get("more_body") for m in sent[1:4])  # the stream's messages, untouched
    assert (await _send(gate, method="DELETE"))[3] == 0
    # MCP 2026-07-28 names the method in a header: another method is passed on without the gate reading the body
    read = gate._read

    async def must_not_read(receive):
        raise AssertionError("the gate read the body")
    gate._read = must_not_read
    status, _, _, _, _ = await _send(gate, _call(), headers=[("mcp-method", "tools/list")])
    assert status == 200 and app.body == json.dumps(_call()).encode()
    gate._read = read
    assert (await _send(gate, _call(), headers=[("Mcp-Method", "tools/call")]))[0] == 403
    await _stop(pinning)


async def test_tsug_011_an_allowed_call_answered_as_a_stream_is_passed_through_untouched(hooks):
    gate, app, pinning = await _gate(hooks, stream=True)
    status, headers, body, _, sent = await _send(gate, _call(), claims={**USER, "scope": "calc:write"})
    assert status == 200 and headers["content-type"] == "text/event-stream"
    assert [m.get("more_body", False) for m in sent[1:]] == [True, True, True, False]
    await _stop(pinning)


# ---- the reason text --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("claims, expected", [
    (PAT, "this personal access token does not carry. A personal access token cannot gain scopes: issue a new one"),
    (MACHINE, "the token of client 'ci-bot' does not carry. Request a token with scope=calc:write from MCP Gate; "
              "if MCP Gate refuses it, an admin must allow that scope for this client."),
    (USER, "this access token does not carry. Sign in again and approve that scope"),
])
async def test_tsug_012_the_reason_says_what_this_kind_of_token_can_do(hooks, claims, expected):
    text = hooks.scope_refusal("add", "calc:write", claims)
    assert text.startswith("Tool 'add' requires the scope 'calc:write', which " + expected)
    gate, app, pinning = await _gate(hooks)
    _, headers, body, _, _ = await _send(gate, _call(), claims=claims)
    assert _challenge(headers["www-authenticate"])["error_description"] == text
    assert json.loads(body)["error"]["message"] == text
    await _stop(pinning)


async def test_tsug_013_header_values_stay_quotable(hooks):
    assert hooks._quoted('a "b" \\ cé\n') == "a ?b? ? c??"
    gate, app, pinning = await _gate(hooks, access=_access([], {"add": {"any_of": ['bad"scope'],
                                                                        "challenge": 'bad"scope'}}))
    # a scope a challenge cannot carry is left to the middleware's tool error
    assert (await _send(gate, _call()))[0] == 200
    await _stop(pinning)
    gate, app, pinning = await _gate(hooks, challenge_includes_token_scopes=True)
    _, headers, _, _, _ = await _send(gate, _call(), claims={**USER, "scope": 'mcp:tools:invoke x"y'})
    assert _challenge(headers["www-authenticate"])["scope"] == "mcp:tools:invoke calc:write"
    await _stop(pinning)


async def test_tsug_014_the_middleware_refusal_names_the_scope_for_each_kind_of_token(hooks):
    from tests.test_tool_pinning_middleware import _call as call_tool
    from tests.test_tool_policy_enforcement import _as

    approved = await _approved_hashes(hooks)
    mcp, pinning = _server(hooks, _verifier(hooks, None, AUDIENCE,
                                            _mock_feed([_answer(approved, access=_access([], ADD_NEEDS))])),
                           cache_file=None)
    for claims in (PAT, MACHINE, USER):
        _as(pinning, claims)
        assert await call_tool(mcp, "add", {"a": 1, "b": 2}) == \
            "ERROR: " + hooks.scope_refusal("add", "calc:write", claims)
    await _stop(pinning)
