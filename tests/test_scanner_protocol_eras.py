"""Scanner speaks MCP 2026-07-28 (#35): `server/discover` and stateless `tools/list` for modern servers, the
`initialize` handshake for older ones, chosen the way the spec's Streamable HTTP "Backward Compatibility" section
says (a 4xx without a recognised modern JSON-RPC error = legacy). Runs against small local aiohttp servers that
record every request."""

from __future__ import annotations

import pytest
from aiohttp import web

from src.discovery.scanner import (
    ERA_LEGACY, ERA_MODERN, LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION, MCPScanner, ToolsListError,
)

TOOLS = [{"name": "add", "description": "Add two numbers.", "inputSchema": {"type": "object"}}]
META = "io.modelcontextprotocol/protocolVersion"


class FakeServer:
    """`modern` answers server/discover and stateless requests; `legacy` behaves like a 2025 SDK server with
    sessions (400 -32600 "Missing session ID" on anything but initialize without a session)."""

    def __init__(self, mode="modern", *, discover=None, initialize_status=200, require_bearer=None):
        self.mode = mode
        self.discover = discover          # override for the server/discover reply: (status, body)
        self.initialize_status = initialize_status
        self.require_bearer = require_bearer
        self.requests = []                # (method, headers, body)
        self.runner = None
        self.port = None

    async def handle(self, request):
        body = await request.json()
        method = body.get("method")
        self.requests.append((method, dict(request.headers), body))
        if self.require_bearer and request.headers.get("Authorization") != f"Bearer {self.require_bearer}":
            return web.Response(status=401, headers={"WWW-Authenticate": 'Bearer resource_metadata="x"'})
        if self.mode == "modern":
            if method == "initialize":  # a modern-only server rejects the handshake
                return web.json_response({"jsonrpc": "2.0", "id": body.get("id"), "error": {
                    "code": -32601, "message": "initialize is not supported; use 2026-07-28"}}, status=400)
            if method == "server/discover":
                if self.discover:
                    status, reply = self.discover
                    return web.json_response(reply, status=status)
                return web.json_response({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "resultType": "complete", "supportedVersions": [LATEST_MODERN_VERSION],
                    "capabilities": {"tools": {}},
                    "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "Modern", "version": "9.9"}},
                    "instructions": "A modern test server.", "ttlMs": 0, "cacheScope": "private"}})
            if method == "tools/list":
                return web.json_response({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "resultType": "complete", "tools": TOOLS, "ttlMs": 0, "cacheScope": "private"}})
            return web.json_response({"jsonrpc": "2.0", "id": body.get("id"),
                                      "error": {"code": -32601, "message": "Method not found"}}, status=404)
        # legacy
        if method == "initialize":
            if self.initialize_status != 200:
                return web.Response(status=self.initialize_status, text="nope")
            offered = body["params"]["protocolVersion"]
            return web.json_response({"jsonrpc": "2.0", "id": body["id"], "result": {
                "protocolVersion": offered if offered <= "2025-06-18" else "2025-06-18",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "Legacy", "version": "1.0"},
                "instructions": "An old test server."}}, headers={"mcp-session-id": "sess-1"})
        if request.headers.get("mcp-session-id") != "sess-1":
            if self.discover and method == "server/discover":
                status, reply = self.discover
                return web.json_response(reply, status=status)
            return web.json_response({"jsonrpc": "2.0", "id": "server-error", "error": {
                "code": -32600, "message": "Bad Request: Missing session ID"}}, status=400)
        if method == "notifications/initialized":
            return web.Response(status=202)
        if method == "tools/list":
            return web.json_response({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": TOOLS}})
        return web.json_response({"jsonrpc": "2.0", "id": body.get("id"),
                                  "error": {"code": -32601, "message": "Method not found"}})

    async def __aenter__(self):
        app = web.Application()
        app.router.add_post("/mcp", self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        await self.runner.cleanup()

    def methods(self):
        return [m for m, _, _ in self.requests]

    def url(self):
        return f"http://127.0.0.1:{self.port}/mcp"


def _error(code, message="x", data=None, status=400):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return status, {"jsonrpc": "2.0", "id": 1, "error": err}


async def test_era_001_modern_server_is_verified_with_server_discover_and_no_handshake():
    async with FakeServer("modern") as srv:
        scanner = MCPScanner(rpc_timeout=5)
        result = await scanner.verify_mcp_service("127.0.0.1", srv.port)
        tools = await scanner.get_tools_list("127.0.0.1", srv.port)
    assert result.success and result.protocol_version == LATEST_MODERN_VERSION and result.protocol_era == ERA_MODERN
    assert (result.server_name, result.server_version) == ("Modern", "9.9")
    assert result.server_description == "A modern test server."
    assert result.capabilities == {"tools": {}}
    assert [t.name for t in tools] == ["add"]
    assert "initialize" not in srv.methods() and "notifications/initialized" not in srv.methods()
    for method, headers, body in srv.requests:
        # every modern request carries its version in _meta and mirrors it (and the method) in headers
        assert body["params"]["_meta"][META] == LATEST_MODERN_VERSION
        assert body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"] == "mcp-gate-scanner"
        assert headers["MCP-Protocol-Version"] == LATEST_MODERN_VERSION
        assert headers["Mcp-Method"] == method
        assert "mcp-session-id" not in {k.lower() for k in headers}
    seen = scanner.protocol_seen(srv.url())
    assert (seen.version, seen.era) == (LATEST_MODERN_VERSION, ERA_MODERN)


async def test_era_002_legacy_server_falls_back_to_initialize():
    async with FakeServer("legacy") as srv:
        scanner = MCPScanner(rpc_timeout=5)
        result = await scanner.verify_mcp_service("127.0.0.1", srv.port)
        tools = await scanner.get_tools_list("127.0.0.1", srv.port)
    assert result.success and result.protocol_era == ERA_LEGACY and result.protocol_version == "2025-06-18"
    assert result.server_name == "Legacy" and result.server_description == "An old test server."
    assert [t.name for t in tools] == ["add"]
    # the probe came first, then the handshake offering the newest handshake-era revision
    assert srv.methods()[:2] == ["server/discover", "initialize"]
    assert srv.requests[1][2]["params"]["protocolVersion"] == LATEST_HANDSHAKE_VERSION
    # requests after initialize carry the session and the negotiated version (required since 2025-06-18)
    after = [(m, h) for m, h, _ in srv.requests if m in ("notifications/initialized", "tools/list")]
    assert after and all(h.get("mcp-session-id") == "sess-1" and h.get("MCP-Protocol-Version") == "2025-06-18"
                         for _, h in after)
    assert scanner.protocol_seen(srv.url()).era == ERA_LEGACY


@pytest.mark.parametrize("reply", [
    (404, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}),
    (405, {"detail": "Method Not Allowed"}),
    (200, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}),
    (400, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Unsupported protocol version"}}),
    (200, {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}),  # no supportedVersions: not a DiscoverResult
])
async def test_era_003_anything_but_a_modern_answer_means_legacy(reply):
    async with FakeServer("legacy", discover=reply) as srv:
        result = await MCPScanner(rpc_timeout=5).verify_mcp_service("127.0.0.1", srv.port)
    assert result.success and result.protocol_era == ERA_LEGACY
    assert srv.methods() == ["server/discover", "initialize"]


async def test_era_004_unsupported_version_with_handshake_versions_uses_initialize_with_that_version():
    reply = _error(-32022, "Unsupported protocol version", {"supported": ["2025-03-26"], "requested": "2026-07-28"})
    async with FakeServer("legacy", discover=reply) as srv:
        result = await MCPScanner(rpc_timeout=5).verify_mcp_service("127.0.0.1", srv.port)
    assert result.success and result.protocol_version == "2025-03-26"
    assert srv.requests[1][2]["params"]["protocolVersion"] == "2025-03-26"


async def test_era_005_unsupported_version_with_nothing_in_common_fails_without_a_handshake():
    reply = _error(-32022, "Unsupported protocol version", {"supported": ["2099-01-01"]})
    async with FakeServer("modern", discover=reply) as srv:
        result = await MCPScanner(rpc_timeout=5).verify_mcp_service("127.0.0.1", srv.port)
        with pytest.raises(ToolsListError, match="No protocol version in common"):
            await MCPScanner(rpc_timeout=5).get_tools_list("127.0.0.1", srv.port)
    assert not result.success and result.reachable and "2099-01-01" in result.error
    assert "initialize" not in srv.methods()


@pytest.mark.parametrize("code", [-32020, -32021])
async def test_era_006_other_modern_errors_never_fall_back(code):
    async with FakeServer("modern", discover=_error(code, "Header mismatch")) as srv:
        result = await MCPScanner(rpc_timeout=5).verify_mcp_service("127.0.0.1", srv.port)
    assert not result.success and result.error == "Header mismatch"
    assert srv.methods() == ["server/discover"]


async def test_era_007_modern_server_offering_another_modern_version_is_retried_with_it(monkeypatch):
    from src.discovery import scanner as scanner_module
    monkeypatch.setattr(scanner_module, "MODERN_PROTOCOL_VERSIONS", ("2026-07-28", "2027-01-01"))
    reply = _error(-32022, "Unsupported protocol version", {"supported": ["2027-01-01"]})
    async with FakeServer("modern", discover=reply) as srv:
        result = await MCPScanner(rpc_timeout=5).verify_mcp_service("127.0.0.1", srv.port)
    # the fake keeps refusing, so the second answer settles it as an error -- but it asked with the new version
    assert not result.success
    assert [b["params"]["_meta"][META] for m, _, b in srv.requests] == ["2026-07-28", "2027-01-01"]


async def test_era_008_the_era_is_remembered_and_probed_again_when_it_stops_working():
    async with FakeServer("legacy") as srv:
        scanner = MCPScanner(rpc_timeout=5)
        assert (await scanner.verify_mcp_service("127.0.0.1", srv.port)).protocol_era == ERA_LEGACY
        srv.requests.clear()
        assert (await scanner.verify_mcp_service("127.0.0.1", srv.port)).success
        assert srv.methods() == ["initialize"]  # no second probe for a server known to be legacy
        # the server is upgraded to a modern-only one: the remembered handshake fails, the scanner probes again
        srv.mode = "modern"
        srv.requests.clear()
        result = await scanner.verify_mcp_service("127.0.0.1", srv.port)
        assert result.success and result.protocol_era == ERA_MODERN
        assert srv.methods() == ["initialize", "server/discover"]
        srv.requests.clear()
        assert [t.name for t in await scanner.get_tools_list("127.0.0.1", srv.port)] == ["add"]
        assert srv.methods() == ["tools/list"]  # remembered as modern: straight to the stateless call
        # and back: a modern URL that now only speaks the handshake
        srv.mode = "legacy"
        srv.requests.clear()
        assert [t.name for t in await scanner.get_tools_list("127.0.0.1", srv.port)] == ["add"]
        assert srv.methods()[:3] == ["tools/list", "server/discover", "initialize"]
        assert scanner.protocol_seen(srv.url()).era == ERA_LEGACY


async def test_era_009_auth_challenge_on_server_discover_mints_a_token_and_retries():
    async with FakeServer("modern", require_bearer="minted") as srv:
        minted_for = []

        def factory(url):
            minted_for.append(url)
            return "minted"
        result = await MCPScanner(rpc_timeout=5).verify_mcp_service("127.0.0.1", srv.port, token_factory=factory)
    assert minted_for == [srv.url()]
    # a 401 is not evidence of an older server: the handshake is never tried, the probe is repeated with the token
    assert srv.methods() == ["server/discover", "server/discover"]
    assert result.success and result.requires_auth and result.auth_token == "minted"
    assert result.protocol_era == ERA_MODERN and result.server_name == "Modern"


async def test_era_010_401_on_tools_list_is_a_permission_error_in_both_eras():
    for mode in ("modern", "legacy"):
        async with FakeServer(mode, require_bearer="secret") as srv:
            with pytest.raises(PermissionError):
                await MCPScanner(rpc_timeout=5).get_tools_list("127.0.0.1", srv.port, auth_token="wrong")
