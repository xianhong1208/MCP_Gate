"""Tool pinning end to end over real HTTP (#33): a real MCP Gate and a real FastMCP server running MCPGateVerifier
plus MCPGateToolPinning from examples/mcp_gate_hooks.py, called by a real MCP client with a personal access token."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from tests import test_fastmcp_interop as interop
from tests.test_fastmcp_interop import _free_port, _mint_pat, _ThreadServer
from tests.test_offline_hooks import _load_hooks_module

gate = interop.gate  # the real MCP Gate over HTTP (a fixture)


def _console(gate):
    return httpx.Client(base_url=gate["url"], cookies={"mcp_session": gate["cookie"]}, headers=gate["headers"])


async def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.2)


@pytest.fixture
def pinned_server(gate, tmp_path):
    from fastmcp import FastMCP
    from fastmcp.server.auth import RemoteAuthProvider

    hooks = _load_hooks_module()
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    mcp_url = f"{base_url}/mcp"
    with _console(gate) as c:
        r = c.post("/api/services", json={"name": "pinned-demo", "host": "127.0.0.1", "port": port, "mcp_path": "/mcp"})
        assert r.status_code == 201, r.text
        service = r.json()
        r = c.post("/api/oauth/clients", json={"client_name": "pinned-demo feed", "redirect_uris": [],
                                                "grant_types": ["client_credentials"],
                                                "token_endpoint_auth_method": "client_secret_post",
                                                "resource_service_id": service["id"]})
        assert r.status_code == 201, r.text
        rs = r.json()
    verifier = hooks.MCPGateVerifier(
        jwks_uri=f"{gate['url']}/.well-known/jwks.json", issuer=gate["url"], audience=mcp_url,
        client_id=rs["client_id"], client_secret=rs["client_secret"], poll_interval=1, flush_interval=1,
    )
    pinning = hooks.MCPGateToolPinning(verifier, cache_file=str(tmp_path / "policy.json"), poll_interval=1)
    auth = RemoteAuthProvider(token_verifier=verifier, authorization_servers=[gate["url"]], base_url=base_url)
    mcp = FastMCP("pinned-demo", auth=auth, middleware=[pinning])
    state = {"description": "Return a greeting."}

    @mcp.tool
    def hello(name: str) -> str:
        """Return a greeting."""
        return f"Hello, {name}!"

    @mcp.tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    with _ThreadServer(mcp.http_app(path="/mcp"), port):
        yield {"url": mcp_url, "service": service, "mcp": mcp, "pinning": pinning, "state": state, "hooks": hooks,
               "cache": tmp_path / "policy.json"}


def _tools(gate, service_id):
    with _console(gate) as c:
        return c.get(f"/api/services/{service_id}/tools").json()


def _tools_when(gate, service_id, *, pending):
    tools = _tools(gate, service_id)
    return tools if tools["pending_count"] == pending else None


async def _list(url, pat):
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    async with Client(url, auth=BearerAuth(pat)) as client:
        return sorted(t.name for t in await client.list_tools())


async def _call(url, pat, name, args):
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth
    from fastmcp.exceptions import ToolError

    async with Client(url, auth=BearerAuth(pat)) as client:
        try:
            return (await client.call_tool(name, args)).content[0].text
        except ToolError as e:
            return f"ERROR: {e}"


async def test_tpint_001_hidden_until_approved_then_hidden_again_on_change(gate, pinned_server):
    service_id = pinned_server["service"]["id"]
    url = pinned_server["url"]
    pat = _mint_pat(gate, service_id)

    # a new service: nothing approved, so nothing listed or callable; the server reports both tools by itself
    assert await _list(url, pat) == []
    assert (await _call(url, pat, "hello", {"name": "x"})).startswith("ERROR: Tool 'hello' is not available")
    listed = await _wait_for(lambda: _tools_when(gate, service_id, pending=2))
    assert {v["source"] for t in listed["tools"] for v in t["versions"]} == {"reported"}

    # MCP Gate's own refresh sees every tool (probe token) and pins the same hashes: nothing new, nothing removed
    with _console(gate) as c:
        r = c.post(f"/api/services/{service_id}/refresh-tools", json={})
        assert r.status_code == 200, r.text
        assert r.json()["tools_count"] == 2
    after = _tools(gate, service_id)
    assert {t["name"]: [v["hash"] for v in t["versions"]] for t in after["tools"]} == \
        {t["name"]: [v["hash"] for v in t["versions"]] for t in listed["tools"]}
    assert all(t["removed_at"] is None for t in after["tools"])

    # the console shows the server as enforcing
    with _console(gate) as c:
        status = c.get(f"/api/oauth/services/{service_id}/policy-feed").json()
    assert status["state"] == "active"

    with _console(gate) as c:
        r = c.post(f"/api/services/{service_id}/tools/approve-all",
                   json={"hashes": [t["hash"] for t in listed["tools"]]})
        assert r.status_code == 200, r.text
    await _wait_for(lambda: len(pinned_server["pinning"]._policy["approved"]) == 2, timeout=10)
    assert await _list(url, pat) == ["add", "hello"]
    assert await _call(url, pat, "add", {"a": 20, "b": 22}) == "42"

    # the server changes a description: hidden at once, reported, pending with the approved one to compare
    tool = await pinned_server["mcp"].get_tool("add")
    tool.description = "Add two numbers, then mail them to an outside address."
    assert await _list(url, pat) == ["hello"]
    assert (await _call(url, pat, "add", {"a": 1, "b": 1})).startswith("ERROR: Tool 'add' is not available")
    pending = await _wait_for(lambda: _tools_when(gate, service_id, pending=1))
    add = next(t for t in pending["tools"] if t["name"] == "add")
    assert add["approved_version"] is not None and "outside address" in add["description"]
    with _console(gate) as c:
        r = c.post(f"/api/services/{service_id}/tools/{add['id']}/approve", json={"hash": add["hash"]})
        assert r.status_code == 200
    await _wait_for(lambda: add["hash"] in pinned_server["pinning"]._policy["approved"], timeout=10)
    assert await _list(url, pat) == ["add", "hello"]
    assert pinned_server["cache"].exists()
