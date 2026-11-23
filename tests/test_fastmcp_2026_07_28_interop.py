"""MCP 2026-07-28 end to end (#35): a real MCP Gate and a real *stateless* FastMCP server (no sessions) running
MCPGateVerifier + MCPGateToolPinning from examples/mcp_gate_hooks.py, called by real MCP clients pinned to the
modern era (server/discover, per-request _meta) and to the legacy handshake. MCP Gate's own scanner reads the same
server through server/discover and shows the protocol it spoke on the service page."""

from __future__ import annotations

import pytest

from tests import test_fastmcp_interop as interop
from tests.test_fastmcp_interop import _free_port, _mint_pat, _ThreadServer
from tests.test_offline_hooks import _load_hooks_module
from tests.test_tool_pinning_interop import _console, _tools_when, _wait_for

gate = interop.gate  # the real MCP Gate over HTTP (a fixture)

MODERN = "2026-07-28"


@pytest.fixture
def stateless_server(gate, tmp_path):
    from fastmcp import FastMCP
    from fastmcp.server.auth import RemoteAuthProvider

    hooks = _load_hooks_module()
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    mcp_url = f"{base_url}/mcp"
    with _console(gate) as c:
        r = c.post("/api/services", json={"name": "stateless-demo", "host": "127.0.0.1", "port": port,
                                          "mcp_path": "/mcp"})
        assert r.status_code == 201, r.text
        service = r.json()
        r = c.post("/api/oauth/clients", json={"client_name": "stateless-demo feed", "redirect_uris": [],
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
    mcp = FastMCP("stateless-demo", instructions="A stateless demo.", auth=auth, middleware=[pinning])

    @mcp.tool
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    with _ThreadServer(mcp.http_app(path="/mcp", stateless_http=True), port):
        yield {"url": mcp_url, "service": service, "pinning": pinning}


async def _session(url, pat, mode, fn):
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    async with Client(url, auth=BearerAuth(pat), mode=mode) as client:
        return client.protocol_version, await fn(client)


async def _names(client):
    return sorted(t.name for t in await client.list_tools())


async def _add(client):
    from fastmcp.exceptions import ToolError
    try:
        return (await client.call_tool("add", {"a": 20, "b": 22})).content[0].text
    except ToolError as e:
        return f"ERROR: {e}"


@pytest.mark.parametrize("mode", [MODERN, "legacy", "auto"])
async def test_m2607_001_pinning_works_on_a_stateless_server_in_every_era(gate, stateless_server, mode):
    service_id = stateless_server["service"]["id"]
    url = stateless_server["url"]
    pat = _mint_pat(gate, service_id)

    version, names = await _session(url, pat, mode, _names)
    assert names == []  # nothing approved yet: hidden, and reported to MCP Gate as pending
    assert (version == MODERN) == (mode != "legacy")  # auto picks the modern era on a modern server
    _, called = await _session(url, pat, mode, _add)
    assert called.startswith("ERROR: Tool 'add' is not available")
    listed = await _wait_for(lambda: _tools_when(gate, service_id, pending=1))

    with _console(gate) as c:
        r = c.post(f"/api/services/{service_id}/tools/approve-all",
                   json={"hashes": [t["hash"] for t in listed["tools"]]})
        assert r.status_code == 200, r.text
    await _wait_for(lambda: len(stateless_server["pinning"]._policy["approved"]) == 1, timeout=10)
    assert (await _session(url, pat, mode, _names))[1] == ["add"]
    assert (await _session(url, pat, mode, _add))[1] == "42"


async def test_m2607_002_scanner_reads_a_stateless_server_through_server_discover(gate, stateless_server):
    service_id = stateless_server["service"]["id"]
    pat = _mint_pat(gate, service_id)
    # the server reports its tool first (as a real client would make it), so refresh must pin the same hash
    await _session(stateless_server["url"], pat, MODERN, _names)
    reported = await _wait_for(lambda: _tools_when(gate, service_id, pending=1))
    with _console(gate) as c:
        r = c.post(f"/api/services/{service_id}/refresh-tools", json={})
        assert r.status_code == 200, r.text
        assert r.json()["tools_count"] == 1
        after = c.get(f"/api/services/{service_id}/tools").json()
        assert [v["hash"] for t in after["tools"] for v in t["versions"]] == \
            [v["hash"] for t in reported["tools"] for v in t["versions"]]

        health = c.post(f"/api/services/{service_id}/health-check").json()
        assert health["status"] == "online", health
        assert (health["protocol_version"], health["protocol_era"]) == (MODERN, "modern")
        detail = c.get(f"/api/services/{service_id}").json()
        assert detail["health"]["protocol_version"] == MODERN
        assert detail["health"]["protocol_era"] == "modern"
        assert detail["health"]["protocol_seen_at"]

        port = int(stateless_server["url"].rsplit(":", 1)[1].split("/")[0])
        r = c.post("/api/discovery/verify", json={"host": "127.0.0.1", "port": port, "mcp_path": "/mcp"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["success"] and body["protocol_version"] == MODERN and body["protocol_era"] == "modern"
        assert body["server_name"] == "stateless-demo"
