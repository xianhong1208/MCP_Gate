"""Scanner: OAuth-protected MCP servers (the MCP authorization spec) are recognised and inspected.

A FastMCP server behind `RemoteAuthProvider` answers an unauthenticated request with an *empty* 401 and
`WWW-Authenticate: Bearer resource_metadata="..."`. The scanner used to require a JSON-RPC body on 401 and
therefore reported such servers as "not MCP"; it also retried over HTTPS against the plain-HTTP port,
which shows up as "Invalid HTTP request received" in the peer's log.
"""
from unittest.mock import AsyncMock

import pytest

from src.discovery.scanner import MCPScanner, MCPVerifyResult, _is_bearer_challenge


def test_bearer_challenge_detection():
    assert _is_bearer_challenge('Bearer resource_metadata="http://h/.well-known/oauth-protected-resource/mcp"')
    assert _is_bearer_challenge("bearer")
    assert not _is_bearer_challenge("Basic realm=x")
    assert not _is_bearer_challenge(None)
    assert not _is_bearer_challenge("")


@pytest.mark.asyncio
async def test_no_https_retry_when_http_answered():
    """A reachable peer that rejected us is not probed again over HTTPS."""
    scanner = MCPScanner()
    scanner.scan_ports = AsyncMock(return_value=[8123])
    scanner.verify_mcp_service = AsyncMock(
        return_value=MCPVerifyResult(success=False, reachable=True, error="HTTP 404"))
    await scanner.discover_services(["127.0.0.1"], [8123], verify=True, get_tools=False)
    assert scanner.verify_mcp_service.await_count == 1


@pytest.mark.asyncio
async def test_https_retry_when_port_did_not_speak_http():
    scanner = MCPScanner()
    scanner.scan_ports = AsyncMock(return_value=[8443])
    scanner.verify_mcp_service = AsyncMock(
        return_value=MCPVerifyResult(success=False, reachable=False, error="Connection failed: x"))
    await scanner.discover_services(["127.0.0.1"], [8443], verify=True, get_tools=False)
    assert scanner.verify_mcp_service.await_count == 2
    assert scanner.verify_mcp_service.await_args_list[1].args[3] == "https"


@pytest.mark.asyncio
async def test_tools_fetched_with_self_minted_token():
    """When verification succeeded with a minted token, tools/list reuses that token."""
    scanner = MCPScanner()
    scanner.scan_ports = AsyncMock(return_value=[5055])
    scanner.verify_mcp_service = AsyncMock(return_value=MCPVerifyResult(
        success=True, reachable=True, requires_auth=True, auth_token="minted", server_name="anydoc"))
    scanner.get_tools_list = AsyncMock(return_value=[])
    found = await scanner.discover_services(["127.0.0.1"], [5055], verify=True, get_tools=True)
    assert scanner.get_tools_list.await_args.args[4] == "minted"
    assert found[0].requires_auth is True


@pytest.mark.asyncio
async def test_tools_skipped_when_locked_out():
    scanner = MCPScanner()
    scanner.scan_ports = AsyncMock(return_value=[5055])
    scanner.verify_mcp_service = AsyncMock(return_value=MCPVerifyResult(
        success=True, reachable=True, requires_auth=True, server_name="(requires auth)"))
    scanner.get_tools_list = AsyncMock(return_value=[])
    found = await scanner.discover_services(["127.0.0.1"], [5055], verify=True, get_tools=True)
    scanner.get_tools_list.assert_not_awaited()
    assert found[0].requires_auth is True


def test_summarize_instructions_takes_first_paragraph():
    from src.discovery.scanner import summarize_instructions

    text = (
        "# AnyDoc — document format conversion service\n\n"
        "Converts the user's uploaded files into the format they need,\nand provides PDF splitting.\n\n"
        "## When to use\n\n| a | b |\n|---|---|\n\n- bullet\n"
    )
    assert summarize_instructions(text) == (
        "Converts the user's uploaded files into the format they need, and provides PDF splitting.")
    assert summarize_instructions("# Only a title\n\n## Section\n\n- list") == "Only a title"
    assert summarize_instructions("") is None and summarize_instructions(None) is None
    long = "x" * 500
    assert len(summarize_instructions(long)) == 200 and summarize_instructions(long).endswith("…")
