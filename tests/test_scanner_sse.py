"""Scanner: SSE responses over Streamable HTTP must be read incrementally

Background (conclusion from testing firecrawl-mcp + supergateway in practice):
Streamable HTTP responses are often `text/event-stream` + chunked, and **the connection stays open**.
The scanner previously used `response.read()/text()` to wait for the whole body -- which for SSE never
ends. The result was a timeout and a torn-down connection, and the peer (supergateway) then threw an
uncaught exception when writing back to a connection it could no longer find, crashing entirely. The
symptom was a service that stayed offline forever and whose tools could never be fetched.

This file pins down: when facing a never-ending SSE stream, return as soon as the first complete
JSON-RPC message is available.
"""
import asyncio
import json

import pytest

from src.discovery.scanner import MCPScanner


class _FakeContent:
    """Fake aiohttp response.content: after yielding the given chunks it **never ends** (like real SSE)."""

    def __init__(self, chunks, hang_forever=True):
        self._chunks = list(chunks)
        self._hang = hang_forever

    async def iter_any(self):
        for c in self._chunks:
            yield c
        if self._hang:
            await asyncio.sleep(3600)  # Stream stays open -- an implementation waiting for the body to end hangs


class _FakeResponse:
    def __init__(self, chunks, content_type="text/event-stream", json_body=None,
                 hang_forever=True):
        self.headers = {"Content-Type": content_type}
        self.content = _FakeContent(chunks, hang_forever)
        self._json_body = json_body

    async def json(self):
        return self._json_body


_MSG = {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "x", "version": "1"}}}


@pytest.mark.asyncio
async def test_sse_returns_before_stream_ends():
    """The stream never ends, but we must return once the first message arrives (must not hang)."""
    chunks = [f"event: message\ndata: {json.dumps(_MSG)}\n\n".encode()]
    scanner = MCPScanner()
    got = await asyncio.wait_for(
        scanner._read_jsonrpc(_FakeResponse(chunks)), timeout=5,
    )
    assert got == _MSG


@pytest.mark.asyncio
async def test_sse_message_split_across_chunks():
    """A message split across several chunks must be reassembled."""
    payload = f"event: message\ndata: {json.dumps(_MSG)}\n\n"
    mid = len(payload) // 2
    chunks = [payload[:mid].encode(), payload[mid:].encode()]
    scanner = MCPScanner()
    got = await asyncio.wait_for(
        scanner._read_jsonrpc(_FakeResponse(chunks)), timeout=5,
    )
    assert got == _MSG


@pytest.mark.asyncio
async def test_sse_skips_non_data_lines():
    """SSE event/id/comment lines are skipped; only data lines are taken."""
    chunks = [b": ping\nevent: message\nid: 7\n", f"data: {json.dumps(_MSG)}\n\n".encode()]
    scanner = MCPScanner()
    got = await asyncio.wait_for(
        scanner._read_jsonrpc(_FakeResponse(chunks)), timeout=5,
    )
    assert got == _MSG


@pytest.mark.asyncio
async def test_plain_json_response_still_works():
    """Non-SSE (application/json) keeps the original behaviour."""
    scanner = MCPScanner()
    resp = _FakeResponse([], content_type="application/json", json_body=_MSG)
    got = await asyncio.wait_for(scanner._read_jsonrpc(resp), timeout=5)
    assert got == _MSG


@pytest.mark.asyncio
async def test_stream_ends_without_message_returns_none():
    """Stream ends without a parseable message -> None (must not raise)."""
    scanner = MCPScanner()
    resp = _FakeResponse([b": comment only\n\n"], hang_forever=False)
    got = await asyncio.wait_for(scanner._read_jsonrpc(resp), timeout=5)
    assert got is None
