"""Scanner: a failed tools/list must raise, never look like "this server has no tools" (#34).

`get_tools_list` used to return [] on any non-200 or exception; "Refresh from Server" then synced that
empty list and wiped every stored tool while reporting "Refreshed 0 tools". These tests run the real
three-step flow against a small local aiohttp server.
"""
import socket
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from src.discovery.scanner import MCPScanner, MCPToolInfo, MCPVerifyResult, ToolsListError

_INIT = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "x"}}}


async def _serve(tools_reply, init_status=200, tools_status=200):
    """Start an MCP-ish server on a free port; returns (runner, port)."""
    async def mcp(request):
        body = await request.json()
        method = body.get("method")
        if method == "initialize":
            return web.json_response(_INIT, status=init_status)
        if method == "notifications/initialized":
            return web.Response(status=202)
        if tools_status != 200:
            return web.Response(status=tools_status, text="boom")
        return web.json_response(tools_reply)

    app = web.Application()
    app.router.add_post("/mcp", mcp)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


async def _tools(tools_reply, **kw):
    runner, port = await _serve(tools_reply, **kw)
    try:
        return await MCPScanner(rpc_timeout=5).get_tools_list("127.0.0.1", port)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_valid_tools_are_returned():
    tools = await _tools({"jsonrpc": "2.0", "id": 2, "result": {"tools": [
        {"name": "search", "description": "Search", "inputSchema": {"type": "object"}}]}})
    assert [t.name for t in tools] == ["search"]
    assert tools[0].input_schema == {"type": "object"}


@pytest.mark.asyncio
async def test_valid_empty_tools_list_is_empty():
    assert await _tools({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kw", [{"init_status": 500}, {"tools_status": 503}, {"tools_status": 404}])
async def test_http_errors_raise(kw):
    with pytest.raises(ToolsListError, match="HTTP"):
        await _tools({}, **kw)


@pytest.mark.asyncio
async def test_401_still_raises_permission_error():
    with pytest.raises(PermissionError):
        await _tools({}, tools_status=401)


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [
    {"jsonrpc": "2.0", "id": 2, "error": {"code": -32601, "message": "Method not found"}},
    {"jsonrpc": "2.0", "id": 2, "result": {}},
    {"jsonrpc": "2.0", "id": 2, "result": {"tools": "nope"}},
    {"jsonrpc": "2.0", "id": 2, "result": {"tools": ["not-an-object"]}},
    [],
])
async def test_malformed_replies_raise(reply):
    with pytest.raises(ToolsListError):
        await _tools(reply)


@pytest.mark.asyncio
async def test_transport_failure_raises():
    with socket.socket() as s:  # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(ToolsListError):
        await MCPScanner(rpc_timeout=5).get_tools_list("127.0.0.1", port)


@pytest.mark.asyncio
async def test_scan_keeps_service_when_tools_list_fails():
    """A verified server whose tools/list fails is still discovered (without tools); the scan goes on."""
    scanner = MCPScanner()
    scanner.scan_ports = AsyncMock(return_value=[8001, 8002])
    scanner.verify_mcp_service = AsyncMock(return_value=MCPVerifyResult(
        success=True, reachable=True, server_name="srv"))
    scanner.get_tools_list = AsyncMock(side_effect=[ToolsListError("tools/list failed: HTTP 500"),
                                                    [MCPToolInfo(name="t")]])
    found = await scanner.discover_services(["127.0.0.1"], [8001, 8002], verify=True, get_tools=True)
    assert [s.port for s in found] == [8001, 8002]
    assert found[0].tools == [] and [t.name for t in found[1].tools] == ["t"]
