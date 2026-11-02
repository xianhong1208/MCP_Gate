"""Scanner: outbound requests cannot be steered at addresses the SSRF check would refuse (#33).

Two ways around the address check existed: following an HTTP redirect from the peer (a 307 to
http://169.254.169.254/ is connected to without any check), and a host that failed to resolve at check time,
which was then handed to aiohttp by name -- so a DNS server answering "nothing" first and the metadata IP
second got through. Both now fail closed.
"""
import socket

import pytest
from aiohttp import web

from src.discovery import scanner as scanner_mod
from src.discovery.scanner import MCPScanner, ScannerResolveError, ScannerSSRFError, _resolve_validated_ip


def _fake_getaddrinfo(*addresses):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
                for a in addresses]
    return fake


@pytest.fixture
async def redirecting_peer():
    """An HTTP server whose /mcp answers every request with a 307 to /trap; /trap counts hits."""
    hits = {"trap": 0}

    async def mcp(request):
        raise web.HTTPTemporaryRedirect(f"http://127.0.0.1:{request.url.port}/trap")

    async def trap(request):
        hits["trap"] += 1
        return web.json_response({"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2024-11-05", "serverInfo": {"name": "trap"}, "tools": []}})

    app = web.Application()
    app.router.add_route("*", "/mcp", mcp)
    app.router.add_route("*", "/trap", trap)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield port, hits
    await runner.cleanup()


async def test_verify_does_not_follow_redirects(redirecting_peer):
    port, hits = redirecting_peer
    result = await MCPScanner().verify_mcp_service("127.0.0.1", port)
    assert not result.success and result.reachable and result.error == "HTTP 307"
    assert hits["trap"] == 0


async def test_tools_list_does_not_follow_redirects(redirecting_peer):
    port, hits = redirecting_peer
    assert await MCPScanner().get_tools_list("127.0.0.1", port) == []
    assert hits["trap"] == 0


def test_unresolvable_host_fails_closed(monkeypatch):
    def gaierror(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", gaierror)
    with pytest.raises(ScannerResolveError, match="could not be resolved"):
        _resolve_validated_ip("rebind.example")


def test_host_without_usable_address_fails_closed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo())
    with pytest.raises(ScannerResolveError, match="usable address"):
        _resolve_validated_ip("empty.example")


class _NoSession:
    def __init__(self, *args, **kwargs):
        raise AssertionError("the scanner must not open a connection to an unresolvable host")


async def test_unresolvable_host_is_never_contacted(monkeypatch):
    """verify reports the reason, scan finds nothing, tools/list raises -- none of them hand the name on."""
    def gaierror(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", gaierror)
    monkeypatch.setattr(scanner_mod.aiohttp, "ClientSession", _NoSession)

    async def no_connect(*args, **kwargs):
        raise AssertionError("port scan must not connect to an unresolvable host")
    monkeypatch.setattr(scanner_mod.asyncio, "open_connection", no_connect)

    scanner = MCPScanner()
    result = await scanner.verify_mcp_service("rebind.example", 8080)
    assert not result.success and not result.reachable and "could not be resolved" in result.error
    assert await scanner.scan_ports("rebind.example", [8080, 8081]) == []
    with pytest.raises(ScannerResolveError):
        await scanner.get_tools_list("rebind.example", 8080)


@pytest.mark.parametrize("address", ["169.254.169.254", "fd00:ec2::254", "100.100.100.200", "0.0.0.0"])
def test_metadata_and_reserved_addresses_are_blocked(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(address))
    with pytest.raises(ScannerSSRFError, match="disallowed address"):
        _resolve_validated_ip("meta.example")


async def test_blocked_address_is_reported_by_verify(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    monkeypatch.setattr(scanner_mod.aiohttp, "ClientSession", _NoSession)
    result = await MCPScanner().verify_mcp_service("meta.example", 80)
    assert not result.success and "disallowed address" in result.error


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.20", "fd12:3456::1"])
def test_local_and_private_addresses_stay_allowed(monkeypatch, address):
    """Scanning local managed servers and intranet hosts is the scanner's job."""
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(address))
    assert _resolve_validated_ip("svc.internal") == address
