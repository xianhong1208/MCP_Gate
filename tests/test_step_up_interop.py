"""Step-up end to end (#37, 1.6 PR 3): a real MCP Gate and a real FastMCP server running MCPGateVerifier,
MCPGateToolPinning and MCPGateScopeGate from examples/mcp_gate_hooks.py, called by real FastMCP clients.

- a client_credentials client steps up by itself: 403 insufficient_scope -> new token with the scope -> retry;
- a client_credentials client that may not have the scope fails once, with no loop;
- a personal access token cannot step up: one 403, and the error names the scope to issue a new token with;
- a server without the gate answers as before (tool error inside HTTP 200), and the text is the same."""

from __future__ import annotations

import json
import logging

import pytest

from tests import test_fastmcp_interop as interop
from tests.test_fastmcp_interop import _free_port, _mint_pat, _ThreadServer
from tests.test_offline_hooks import _load_hooks_module
from tests.test_tool_pinning_interop import _console, _tools_when, _wait_for

gate = interop.gate  # the real MCP Gate over HTTP (a fixture)


def _server(gate, tmp_path, *, with_gate=True, **gate_kw):
    from fastmcp import FastMCP
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.dependencies import get_access_token
    from starlette.middleware import Middleware

    hooks = _load_hooks_module()
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    mcp_url = f"{base_url}/mcp"
    with _console(gate) as c:
        r = c.post("/api/services", json={"name": f"step-up-{port}", "host": "127.0.0.1", "port": port,
                                          "mcp_path": "/mcp"})
        assert r.status_code == 201, r.text
        service = r.json()
        r = c.post("/api/oauth/clients", json={"client_name": f"step-up feed {port}", "redirect_uris": [],
                                                "grant_types": ["client_credentials"],
                                                "token_endpoint_auth_method": "client_secret_post",
                                                "resource_service_id": service["id"]})
        assert r.status_code == 201, r.text
        rs = r.json()
    verifier = hooks.MCPGateVerifier(
        jwks_uri=f"{gate['url']}/.well-known/jwks.json", issuer=gate["url"], audience=mcp_url,
        client_id=rs["client_id"], client_secret=rs["client_secret"], poll_interval=1, flush_interval=1,
        required_scopes=["mcp:tools:invoke"],
    )
    pinning = hooks.MCPGateToolPinning(verifier, cache_file=str(tmp_path / f"policy-{port}.json"), poll_interval=1)
    auth = RemoteAuthProvider(token_verifier=verifier, authorization_servers=[gate["url"]], base_url=base_url)
    mcp = FastMCP("step-up-demo", auth=auth, middleware=[pinning])

    @mcp.tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    @mcp.tool
    def whoami() -> list:
        """The caller's scopes."""
        return sorted(get_access_token().scopes)

    middleware = [Middleware(hooks.MCPGateScopeGate, pinning=pinning, server=mcp, **gate_kw)] if with_gate else []
    return _ThreadServer(mcp.http_app(path="/mcp", middleware=middleware), port), \
        {"url": mcp_url, "service": service, "pinning": pinning, "hooks": hooks}


async def _setup(gate, srv):
    """Approve the two tools and put `add` in the global scope calc:write."""
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    service_id = srv["service"]["id"]
    async with Client(srv["url"], auth=BearerAuth(_mint_pat(gate, service_id))) as client:
        await client.list_tools()  # makes the server report its tools
    listed = await _wait_for(lambda: _tools_when(gate, service_id, pending=2))
    with _console(gate) as c:
        assert c.post(f"/api/services/{service_id}/tools/approve-all",
                      json={"hashes": [t["hash"] for t in listed["tools"]]}).status_code == 200
        assert c.put("/api/oauth/scopes/calc:write", json={}).status_code == 200
        add_id = next(t["id"] for t in listed["tools"] if t["name"] == "add")
        assert c.put(f"/api/services/{service_id}/tools/{add_id}/scopes",
                     json={"scopes": ["calc:write"]}).status_code == 200
    await _wait_for(lambda: (srv["pinning"].access_policy or {}).get("tool_scopes"), timeout=10)


def _machine_client(gate, service, scope=None):
    body = {"client_name": "ci bot", "redirect_uris": [], "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post"}
    if scope:
        body["scope"] = scope
    with _console(gate) as c:
        r = c.post("/api/oauth/clients", json=body)
        assert r.status_code == 201, r.text
        return r.json()


def _logged_challenges(caplog):
    return [r for r in caplog.records if r.name == "mcp_gate_hooks" and "Step-up challenge" in r.getMessage()]


async def test_tsug_020_client_credentials_steps_up_and_keeps_its_scopes(gate, tmp_path, caplog):
    from fastmcp import Client
    from fastmcp.client.auth import ClientCredentialsOAuthProvider

    server, srv = _server(gate, tmp_path)
    with server, caplog.at_level(logging.INFO, logger="mcp_gate_hooks"):
        await _setup(gate, srv)
        bot = _machine_client(gate, srv["service"])
        auth = ClientCredentialsOAuthProvider(srv["url"], client_id=bot["client_id"],
                                              client_secret=bot["client_secret"], scopes="mcp:tools:invoke")
        async with Client(srv["url"], auth=auth) as client:
            result = await client.call_tool("add", {"a": 20, "b": 22})
            assert result.content[0].text == "42"
            # the new token keeps the base scope (union), so the session goes on working
            assert json.loads((await client.call_tool("whoami", {})).content[0].text) == \
                ["calc:write", "mcp:tools:invoke"]
        assert len(_logged_challenges(caplog)) == 1


async def test_tsug_021_a_client_that_may_not_have_the_scope_fails_once(gate, tmp_path, caplog):
    from fastmcp import Client
    from fastmcp.client.auth import ClientCredentialsOAuthProvider

    server, srv = _server(gate, tmp_path)
    with server, caplog.at_level(logging.INFO, logger="mcp_gate_hooks"):
        await _setup(gate, srv)
        bot = _machine_client(gate, srv["service"], scope="mcp:tools:invoke")
        auth = ClientCredentialsOAuthProvider(srv["url"], client_id=bot["client_id"],
                                              client_secret=bot["client_secret"], scopes="mcp:tools:invoke")
        with pytest.raises(BaseException) as raised:
            async with Client(srv["url"], auth=auth) as client:
                await client.call_tool("add", {"a": 1, "b": 2})
        assert len(_logged_challenges(caplog)) == 1, "no challenge loop"
        # MCP Gate's token endpoint refuses the scope; the client stops there with that reason
        assert "scope not permitted: calc:write" in str(raised.value)


async def test_tsug_022_a_personal_access_token_gets_one_readable_refusal(gate, tmp_path, caplog):
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    server, srv = _server(gate, tmp_path)
    with server, caplog.at_level(logging.INFO, logger="mcp_gate_hooks"):
        await _setup(gate, srv)
        pat = _mint_pat(gate, srv["service"]["id"])
        async with Client(srv["url"], auth=BearerAuth(pat)) as client:
            with pytest.raises(Exception) as raised:
                await client.call_tool("add", {"a": 1, "b": 2})
            assert await client.call_tool("whoami", {})  # the session is still usable
        assert "personal access token cannot gain scopes" in str(raised.value)
        assert len(_logged_challenges(caplog)) == 1


async def _raw_call(url, token):
    """One tools/call over plain HTTP, as a client that knows nothing about step-up sends it."""
    import httpx

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    async with httpx.AsyncClient() as http:
        init = await http.post(url, headers=headers, json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "raw", "version": "0"}}})
        if init.headers.get("mcp-session-id"):
            headers["Mcp-Session-Id"] = init.headers["mcp-session-id"]
        return await http.post(url, headers=headers, json={"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                                           "params": {"name": "add", "arguments": {"a": 1, "b": 2}}})


@pytest.mark.parametrize("with_gate", [False, True])
async def test_tsug_023_without_the_gate_the_server_answers_as_before(gate, tmp_path, with_gate):
    """Blast radius: a server that runs the 1.6 hooks but does not add MCPGateScopeGate answers a call that lacks a
    scope exactly as before, a tool error inside HTTP 200; with the gate it is a 403. The reason is the same text."""
    server, srv = _server(gate, tmp_path, with_gate=with_gate)
    with server:
        await _setup(gate, srv)
        pat = _mint_pat(gate, srv["service"]["id"])
        r = await _raw_call(srv["url"], pat)
        reason = "Tool 'add' requires the scope 'calc:write', which this personal access token does not carry."
        if with_gate:
            assert r.status_code == 403 and "insufficient_scope" in r.headers["www-authenticate"]
            assert json.loads(r.text)["error"]["message"].startswith(reason)
        else:
            assert r.status_code == 200 and "www-authenticate" not in r.headers
            assert reason in r.text and '"isError":true' in r.text.replace(" ", "")
