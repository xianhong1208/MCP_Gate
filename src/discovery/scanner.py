"""MCP service discovery scanner

Features:
- Port scanning (Python async socket)
- MCP service verification: `server/discover` (MCP 2026-07-28 and later, stateless) with a fallback to the
  `initialize` handshake for older servers
- Tool list retrieval (tools/list) in either era
- SSE format support
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Callable

import aiohttp

from src.utils.mcp_target import InvalidTargetError, build_mcp_url
from src.version import __version__

logger = logging.getLogger(__name__)

# Protocol revisions the scanner speaks, oldest to newest. Modern revisions carry the version in every request's
# _meta (no handshake, no session); handshake-era revisions negotiate it with `initialize`.
HANDSHAKE_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MODERN_PROTOCOL_VERSIONS = ("2026-07-28",)
LATEST_HANDSHAKE_VERSION = HANDSHAKE_PROTOCOL_VERSIONS[-1]
LATEST_MODERN_VERSION = MODERN_PROTOCOL_VERSIONS[-1]
ERA_MODERN = "modern"
ERA_LEGACY = "legacy"
# JSON-RPC errors only a modern server sends (2026-07-28 "Error codes"): HeaderMismatch,
# MissingRequiredClientCapability, UnsupportedProtocolVersion. Any of them means "do not fall back to initialize".
UNSUPPORTED_PROTOCOL_VERSION = -32022
MODERN_ERROR_CODES = frozenset({-32020, -32021, UNSUPPORTED_PROTOCOL_VERSION})
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
CLIENT_INFO = {"name": "mcp-gate-scanner", "version": __version__}


@dataclass(frozen=True)
class ProtocolSeen:
    """How this process last talked to an MCP URL: the protocol version, the era, and when."""
    version: Optional[str]
    era: str
    seen_at: datetime


@dataclass
class _Reply:
    status: int
    content_type: str
    www_authenticate: Optional[str]
    session_id: Optional[str]
    body: Any


def _base_headers(host: str, port: int, connect_host: str, auth_token: Optional[str]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if connect_host != host:
        headers["Host"] = f"{host}:{port}"
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    return headers


def _modern_headers(base: Dict[str, str], method: str, version: str) -> Dict[str, str]:
    """Streamable HTTP request headers of the modern era: the version and the method mirrored from the body."""
    return {**base, "MCP-Protocol-Version": version, "Mcp-Method": method}


def _modern_request(method: str, request_id: int, version: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {"_meta": {
        META_PROTOCOL_VERSION: version, META_CLIENT_INFO: CLIENT_INFO, META_CLIENT_CAPABILITIES: {},
    }}}


def _initialize_request(offer: Optional[str] = None) -> Dict[str, Any]:
    """The legacy handshake. Offers the newest handshake-era version; the server answers with one it supports."""
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": offer or LATEST_HANDSHAKE_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO,
    }}


def _pick_version(supported: List[str], requested: str) -> tuple:
    """Choose from the versions a modern server listed: another modern one -> ("retry", v); a handshake-era one ->
    ("legacy", v); none we know -> ("error", message)."""
    modern = [v for v in MODERN_PROTOCOL_VERSIONS if v in supported and v != requested]
    if modern:
        return ("retry", modern[-1])
    handshake = [v for v in HANDSHAKE_PROTOCOL_VERSIONS if v in supported]
    if handshake:
        return ("legacy", handshake[-1])
    listed = ", ".join(str(v)[:32] for v in supported[:8]) or "none listed"
    return ("error", f"No protocol version in common with the server (it supports: {listed})")


@dataclass
class MCPToolInfo:
    """MCP tool information: the fields of a tools/list entry that are stored and pinned (#32)."""
    name: str
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None
    title: Optional[str] = None
    output_schema: Optional[Dict[str, Any]] = None
    annotations: Optional[Dict[str, Any]] = None

    def to_mcp(self) -> Dict[str, Any]:
        """Back to the tools/list spelling, the form src/tool_pinning/hashing.py hashes."""
        return {"name": self.name, "title": self.title, "description": self.description,
                "inputSchema": self.input_schema, "outputSchema": self.output_schema,
                "annotations": self.annotations}


@dataclass
class MCPVerifyResult:
    """MCP service verification result"""
    success: bool
    protocol_version: Optional[str] = None
    protocol_era: Optional[str] = None  # ERA_MODERN (server/discover, stateless) or ERA_LEGACY (initialize)
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    server_description: Optional[str] = None  # Taken from serverInfo.description (if present)
    capabilities: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    response_time_ms: float = 0.0
    # The peer answered over HTTP (any status). Distinguishes "wrong protocol / port closed" from
    # "reachable but rejected", so callers do not retry over HTTPS against a plain-HTTP server.
    reachable: bool = False
    # The peer demanded a bearer token (401 with a Bearer challenge or a JSON-RPC 401 body).
    requires_auth: bool = False
    # Token that satisfied the peer during verification (self-minted); reused for tools/list.
    auth_token: Optional[str] = None


@dataclass
class DiscoveredService:
    """A discovered service"""
    host: str
    port: int
    protocol: str = "http"
    mcp_path: str = "/mcp"
    verify_result: Optional[MCPVerifyResult] = None
    tools: List[MCPToolInfo] = field(default_factory=list)

    @property
    def requires_auth(self) -> bool:
        """Determine whether the service requires authentication.

        Decided by the verification result alone: a 401 / Bearer challenge (or the "(requires auth)"
        placeholder) means auth is required; a successful initialize without one means it is not -- even
        when the server exposes no tools.
        """
        if self.verify_result:
            if self.verify_result.requires_auth:
                return True
            # server_name == "(requires auth)" means the service returned 401
            if self.verify_result.server_name == "(requires auth)":
                return True
            # initialize succeeded without a challenge, so no authentication is needed
            if self.verify_result.success:
                return False
        # Nothing verified: default to requiring authentication (the safer assumption)
        return True


class ScannerSSRFError(Exception):
    """Connection target address rejected by SSRF protection"""


class ScannerResolveError(ScannerSSRFError):
    """The target host did not resolve to any usable address. The scanner refuses it rather than letting the
    HTTP client resolve the name again at connect time, which would bypass the address check."""


# Cloud metadata endpoints the generic range checks below do not catch: AWS IMDS over IPv6 sits in the
# unique-local range (fd00::/8, otherwise allowed as an intranet address) and Alibaba Cloud's sits in the
# carrier-grade NAT range 100.64.0.0/10. 169.254.169.254 is already covered by the link-local check.
_BLOCKED_METADATA_ADDRESSES = {"fd00:ec2::254", "100.100.100.200"}


class ToolsListError(Exception):
    """tools/list could not be completed (HTTP error, transport failure or malformed reply).

    Raised instead of returning an empty list so callers never mistake a failed fetch for a server
    that has no tools (which would wipe the stored tool list).
    """


def _jsonrpc_error_text(data: Any) -> str:
    """Short reason for a JSON-RPC reply that carries no usable result."""
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return str(data["error"].get("message") or data["error"])
    return "empty response" if not data else "malformed response"


# audience (the peer's MCP URL) -> short-lived bearer token, or None when MCP Gate cannot mint one
TokenFactory = Callable[[str], Optional[str]]


def summarize_instructions(text: Optional[str], limit: int = 200) -> Optional[str]:
    """Reduce an MCP server's `instructions` (often a long Markdown brief for the model) to one line.

    Takes the first paragraph that is not a heading, table or list; falls back to the H1 text. The
    result is what the console shows as the service description, so it must stay short.
    """
    if not text:
        return None
    paragraphs = [p.strip() for p in text.replace("\r\n", "\n").split("\n\n")]
    title = None
    for para in paragraphs:
        if not para:
            continue
        first = para.lstrip()
        if first.startswith("#"):
            if title is None:
                title = first.lstrip("#").strip()
            continue
        if first.startswith(("|", "-", "*", "```", ">", "1.")):
            continue
        summary = " ".join(line.strip() for line in para.splitlines() if line.strip())
        break
    else:
        summary = title
    if not summary:
        return None
    summary = summary.strip("*_ ")
    return summary if len(summary) <= limit else summary[: limit - 1].rstrip() + "…"


def _is_bearer_challenge(www_authenticate: Optional[str]) -> bool:
    """True when a 401 carries the standard MCP/OAuth challenge (`WWW-Authenticate: Bearer ...`).

    MCP servers built on FastMCP (and the MCP authorization spec in general) answer unauthenticated
    requests with an empty 401 body and a Bearer challenge that points at their protected-resource
    metadata. That header, not a JSON-RPC body, is the signal that the peer speaks MCP behind OAuth.
    """
    return bool(www_authenticate) and www_authenticate.strip().lower().startswith("bearer")


def _resolve_validated_ip(host: str) -> str:
    """SSRF protection: resolve the host, validate every IP, and return a single IP that is safe to connect to.

    Rejects link-local (including the cloud metadata address 169.254.169.254), multicast, reserved and
    unspecified (0.0.0.0) addresses plus the metadata addresses in _BLOCKED_METADATA_ADDRESSES; allows
    loopback / private addresses (scanning local managed services and intranet MCP services is a legitimate
    use case).

    Key point: the *validated* IP is returned so the caller can pin the connection to it, avoiding DNS
    rebinding between "resolve at validation time" and "resolve again at connect time" (first answer is a
    benign IP that passes the check, second answer is the metadata IP). If the host is already an IP
    literal it is validated and returned directly. Resolution failure raises ScannerResolveError (fail
    closed): handing the bare hostname to the HTTP client would let it resolve the name again, unchecked.
    Addresses security audit item AUDIT-1 (SSRF) and #33.
    """
    import ipaddress as _ip
    import socket as _sock
    try:
        infos = _sock.getaddrinfo(host, None)
    except (_sock.gaierror, UnicodeError) as e:
        raise ScannerResolveError(f"Host {host} could not be resolved ({e}); refusing to connect")
    validated = None
    for info in infos:
        addr = info[4][0].split('%')[0]  # Strip the IPv6 scope id
        try:
            ip = _ip.ip_address(addr)
        except ValueError:
            continue
        # Loopback (127.0.0.1 / ::1) is a legitimate local scan target; allow it explicitly.
        # Note: for IPv6 ::1, Python reports is_reserved == True, so without this early allow it would be
        # wrongly rejected by the block below -- which happens whenever localhost resolves to both IPv4 and
        # IPv6 (common in containers/CI).
        if ip.is_loopback:
            if validated is None:
                validated = addr
            continue
        if (ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
                or str(ip) in _BLOCKED_METADATA_ADDRESSES):
            raise ScannerSSRFError(
                f"Refusing to connect to disallowed address {addr} "
                f"(link-local / cloud-metadata / reserved addresses are blocked)"
            )
        if validated is None:
            validated = addr
    if validated is None:
        raise ScannerResolveError(f"Host {host} did not resolve to a usable address; refusing to connect")
    return validated


class MCPScanner:
    """MCP service scanner"""

    def __init__(
        self,
        timeout: float = 5.0,
        max_concurrent: int = 50,
        rpc_timeout: Optional[float] = None,
    ):
        """Initialize the scanner.

        Args:
            timeout: Connection timeout (seconds) for **TCP port scanning**. A scan often covers
                hundreds of ports, most of them closed, so this must be short.
            max_concurrent: Maximum number of concurrent connections.
            rpc_timeout: Timeout (seconds) for **MCP JSON-RPC calls** (initialize / tools/list).
                This is a different beast from port scanning: the peer may be cold-starting (npx/uvx
                inside the container installing packages online for the first time). Reusing the short
                port-scan timeout would abort the connection before the peer answers -- in practice this
                made supergateway throw an uncaught exception when writing back later and crash
                entirely. The default is generous; tune it with MCP_RPC_TIMEOUT.
        """
        self.timeout = timeout
        self.rpc_timeout = rpc_timeout if rpc_timeout is not None else _default_rpc_timeout()
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        # MCP URL -> era that last worked, and what was seen there (see protocol_seen)
        self._eras: Dict[str, str] = {}
        self._seen: Dict[str, ProtocolSeen] = {}

    async def scan_ports(
        self,
        host: str,
        ports: List[int]
    ) -> List[int]:
        """Scan for open ports.

        Args:
            host: Host address
            ports: List of ports to scan

        Returns:
            List of open ports
        """
        # SSRF protection (AUDIT-1): resolve and validate once, then pin the connection to that IP
        # (prevents DNS rebinding). An unresolvable host has no open ports; a disallowed address still raises.
        try:
            connect_host = _resolve_validated_ip(host)
        except ScannerResolveError as e:
            logger.warning(f"Port scan skipped: {e}")
            return []
        tasks = [self._check_port(connect_host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for port, result in zip(ports, results):
            if result is True:
                open_ports.append(port)

        return open_ports

    async def _check_port(self, host: str, port: int) -> bool:
        """Check whether a single port is open."""
        async with self._semaphore:
            try:
                # Open a TCP connection with asyncio
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return False
            except Exception as e:
                logger.debug(f"Port scan error {host}:{port}: {e}")
                return False

    async def _read_sse_message(self, response) -> Optional[Dict[str, Any]]:
        """Incrementally read the first JSON-RPC message from a **still-open** SSE stream and return it.

        Streamable HTTP responses are usually `text/event-stream` + chunked, and the connection stays
        open (the server may keep pushing afterwards). Waiting for "the whole body to finish" with
        `response.read()/text()` never completes for SSE -- it waits until the timeout fires and the
        connection is torn down, and in practice the peer (supergateway) then throws an uncaught
        exception when writing back to a connection it can no longer find, crashing entirely. So we read
        chunk by chunk and stop as soon as one complete message has been assembled.
        """
        buf = ""
        try:
            async for chunk in response.content.iter_any():
                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line.startswith("data:"):
                        payload = line[5:].strip()
                        if not payload:
                            continue
                        try:
                            return json.loads(payload)
                        except json.JSONDecodeError:
                            continue  # An event may span multiple lines; keep collecting
        except Exception as e:
            logger.debug(f"SSE incremental read ended: {e}")
        return None

    async def _read_jsonrpc(self, response) -> Optional[Dict[str, Any]]:
        """Extract the JSON-RPC response based on Content-Type (SSE is read incrementally, JSON is parsed directly)."""
        content_type = response.headers.get("Content-Type", "")
        if "text/event-stream" in content_type:
            return await self._read_sse_message(response)
        try:
            return await response.json()
        except Exception:
            return None

    # ---- protocol eras (MCP 2026-07-28, SEP-2575) -------------------------------------------------------------
    # A modern server answers `server/discover`; a legacy one needs the `initialize` handshake. The era is a property
    # of the server, so it is remembered per MCP URL (the spec's "cache per origin") and probed again when the
    # remembered path stops working (a server upgraded, or replaced by an older one).

    def protocol_seen(self, mcp_url: Optional[str]) -> Optional[ProtocolSeen]:
        """The protocol version and era this process last talked to `mcp_url` with (None before the first check)."""
        return self._seen.get(mcp_url) if mcp_url else None

    def _remember(self, mcp_url: str, version: Optional[str], era: str) -> None:
        self._eras[mcp_url] = era
        self._seen[mcp_url] = ProtocolSeen(version=version, era=era, seen_at=datetime.now(timezone.utc))

    def _forget(self, mcp_url: str) -> None:
        self._eras.pop(mcp_url, None)

    async def _post(self, session, url: str, payload: dict, headers: dict, timeout) -> _Reply:
        """POST one JSON-RPC message and read the reply (JSON or the first SSE message) inside the request."""
        async with session.post(
            url, json=payload, headers=headers, timeout=timeout, ssl=False,
            # A redirect hands the peer control over where we connect next (e.g. a 307 to
            # http://169.254.169.254/), bypassing the address check: never follow one.
            allow_redirects=False,
        ) as response:
            content_type = response.headers.get("Content-Type", "")
            body = None
            if "json" in content_type or "text/event-stream" in content_type:
                try:
                    body = await self._read_jsonrpc(response)
                except Exception:
                    body = None
            else:
                await response.read()
            return _Reply(status=response.status, content_type=content_type,
                          www_authenticate=response.headers.get("WWW-Authenticate"),
                          session_id=response.headers.get("mcp-session-id"), body=body)

    async def _discover(self, session, url: str, headers: dict, timeout, version: str = LATEST_MODERN_VERSION):
        """Send `server/discover` and classify the answer.

        Returns (reply, outcome) where outcome is one of
        ("modern", version, result) -- a modern server; ("legacy", offer) -- not a modern server, use initialize
        (offer = a handshake-era version the server named, or None); ("error", message) -- a modern server that
        refused (no common version, header mismatch ...); ("auth", None) -- 401, the caller decides.
        """
        reply = await self._post(session, url, _modern_request("server/discover", 1, version),
                                 _modern_headers(headers, "server/discover", version), timeout)
        if reply.status == 401:
            return reply, ("auth", None)
        body = reply.body if isinstance(reply.body, dict) else None
        result = body.get("result") if body else None
        if reply.status == 200 and isinstance(result, dict) and isinstance(result.get("supportedVersions"), list):
            supported = [v for v in result["supportedVersions"] if isinstance(v, str)]
            if version in supported:
                return reply, ("modern", version, result)
            return reply, _pick_version(supported, version)
        error = body.get("error") if body else None
        if isinstance(error, dict) and error.get("code") in MODERN_ERROR_CODES:
            # A recognised modern error identifies a modern server: never fall back to initialize on it
            if error.get("code") == UNSUPPORTED_PROTOCOL_VERSION:
                data = error.get("data") if isinstance(error.get("data"), dict) else {}
                supported = [v for v in (data.get("supported") or []) if isinstance(v, str)]
                return reply, _pick_version(supported, version)
            return reply, ("error", str(error.get("message") or error))
        # Anything else (400 "missing session id", 404/405, a JSON-RPC "method not found", HTML ...) = legacy
        return reply, ("legacy", None)

    async def _negotiate(self, session, url: str, headers: dict, timeout) -> tuple:
        """Probe the era. Returns (reply, outcome) like `_discover`; a "modern" outcome for another version is
        retried once with that version."""
        reply, outcome = await self._discover(session, url, headers, timeout)
        if outcome[0] == "retry":
            reply, outcome = await self._discover(session, url, headers, timeout, version=outcome[1])
            if outcome[0] == "retry":  # the server keeps moving the goalposts
                outcome = ("error", "server/discover did not settle on a protocol version")
        return reply, outcome

    async def _unauthorized(self, reply: _Reply, *, elapsed_ms, public_url, auth_token, token_factory,
                            retry) -> MCPVerifyResult:
        """A 401 during verification. A 401 alone must not be taken as an MCP service (any protected HTTP endpoint
        may return one). Two signals confirm MCP behind auth: a Bearer challenge (the MCP authorization spec) or a
        JSON-RPC formatted 401 body."""
        is_mcp_auth = _is_bearer_challenge(reply.www_authenticate) or (
            isinstance(reply.body, dict) and ("jsonrpc" in reply.body or "error" in reply.body))
        if not is_mcp_auth:
            return MCPVerifyResult(
                success=False, reachable=True,
                error="HTTP 401 (not MCP - no Bearer challenge or JSON-RPC response)",
                response_time_ms=elapsed_ms,
            )
        # MCP Gate is the authorization server: mint a token for this URL and look inside
        if token_factory is not None and not auth_token:
            minted = token_factory(public_url)
            if minted:
                result = await retry(minted)
                if result.success:
                    result.requires_auth = True
                    result.auth_token = minted
                    return result
                logger.info(f"Self-minted scanner token rejected by {public_url}: {result.error}")
        return MCPVerifyResult(
            success=True, reachable=True, requires_auth=True,
            server_name="(requires auth)",
            error="Service requires authentication (401)",
            response_time_ms=elapsed_ms,
        )

    async def verify_mcp_service(
        self,
        host: str,
        port: int,
        path: str = "/mcp",
        protocol: str = "http",
        auth_token: Optional[str] = None,
        token_factory: Optional[TokenFactory] = None,
    ) -> MCPVerifyResult:
        """Verify an MCP service.

        Speaks both protocol eras: `server/discover` (MCP 2026-07-28 and later, stateless) first, and the
        `initialize` handshake for servers that do not answer it as a modern server would. When the peer answers
        401 with a Bearer challenge and `token_factory` is given, a token for the peer's MCP URL is minted (MCP Gate
        is the authorization server) and the probe is retried once, so servers protected by MCP Gate still report
        their real name, version and tools.
        """
        start_time = time.time()
        # Protocol, host and path come from the operator: an '@' in the path or a URL in the protocol
        # would move the authority away from the pinned IP below, so they are validated before anything
        # is resolved or contacted (a stored service that fails here is reported, never connected to).
        try:
            public_url = build_mcp_url(protocol, host, port, path)
        except InvalidTargetError as e:
            return MCPVerifyResult(success=False, error=str(e), response_time_ms=(time.time() - start_time) * 1000)
        # SSRF protection (AUDIT-1): resolve and validate once, pin the connection to that IP (prevents
        # DNS rebinding), and keep the original Host header so vhost routing is unaffected. A host that does
        # not resolve, or resolves to a blocked address, is reported as a failed check and never contacted.
        try:
            connect_host = _resolve_validated_ip(host)
        except ScannerSSRFError as e:
            return MCPVerifyResult(success=False, error=str(e), response_time_ms=(time.time() - start_time) * 1000)
        url = build_mcp_url(protocol, connect_host, port, path)
        headers = _base_headers(host, port, connect_host, auth_token)

        def elapsed() -> float:
            return (time.time() - start_time) * 1000

        async def retry(minted: str) -> MCPVerifyResult:
            return await self.verify_mcp_service(host, port, path, protocol, minted)

        try:
            timeout = aiohttp.ClientTimeout(total=self.rpc_timeout)
            async with aiohttp.ClientSession() as session:
                remembered = self._eras.get(public_url)
                offer = None
                if remembered != ERA_LEGACY:
                    reply, outcome = await self._negotiate(session, url, headers, timeout)
                    if outcome[0] == "auth":
                        return await self._unauthorized(reply, elapsed_ms=elapsed(), public_url=public_url,
                                                        auth_token=auth_token, token_factory=token_factory,
                                                        retry=retry)
                    if outcome[0] == "modern":
                        return self._modern_verified(public_url, outcome[1], outcome[2], elapsed())
                    if outcome[0] == "error":
                        self._forget(public_url)
                        return MCPVerifyResult(success=False, reachable=True, error=outcome[1],
                                               response_time_ms=elapsed())
                    offer = outcome[1]
                result = await self._verify_legacy(session, url, headers, timeout, offer, public_url, elapsed,
                                                   auth_token, token_factory, retry)
                if not result.success and remembered == ERA_LEGACY:
                    # The remembered handshake stopped working: the server may have moved to the modern era
                    self._forget(public_url)
                    return await self.verify_mcp_service(host, port, path, protocol, auth_token, token_factory)
                return result

        except asyncio.TimeoutError:
            return MCPVerifyResult(
                success=False,
                error="Connection timeout",
                response_time_ms=(time.time() - start_time) * 1000
            )
        except aiohttp.ClientError as e:
            return MCPVerifyResult(
                success=False,
                error=f"Connection failed: {str(e)}",
                response_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            logger.error(f"MCP verify error: {e}")
            return MCPVerifyResult(
                success=False,
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000
            )

    def _modern_verified(self, public_url: str, version: str, result: dict, elapsed_ms: float) -> MCPVerifyResult:
        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        server_info = meta.get(META_SERVER_INFO) if isinstance(meta.get(META_SERVER_INFO), dict) else {}
        server_name = server_info.get("name") if isinstance(server_info.get("name"), str) else None
        server_version = server_info.get("version") if isinstance(server_info.get("version"), str) else None
        instructions = result.get("instructions") if isinstance(result.get("instructions"), str) else None
        self._remember(public_url, version, ERA_MODERN)
        logger.info(f"MCP service verified: name={server_name}, version={server_version}, protocol={version}")
        return MCPVerifyResult(
            success=True, reachable=True,
            protocol_version=version, protocol_era=ERA_MODERN,
            server_name=server_name, server_version=server_version,
            server_description=summarize_instructions(instructions) or server_info.get("description"),
            capabilities=result.get("capabilities") if isinstance(result.get("capabilities"), dict) else None,
            response_time_ms=elapsed_ms,
        )

    async def _verify_legacy(self, session, url, headers, timeout, offer, public_url, elapsed, auth_token,
                             token_factory, retry) -> MCPVerifyResult:
        """The `initialize` handshake (protocol revisions up to 2025-11-25)."""
        reply = await self._post(session, url, _initialize_request(offer), headers, timeout)
        logger.info(f"MCP verify response: status={reply.status}, content-type={reply.content_type or 'N/A'}")
        if reply.status == 401:
            return await self._unauthorized(reply, elapsed_ms=elapsed(), public_url=public_url,
                                            auth_token=auth_token, token_factory=token_factory, retry=retry)
        if reply.status != 200:
            return MCPVerifyResult(success=False, reachable=True, error=f"HTTP {reply.status}",
                                   response_time_ms=elapsed())
        result = reply.body
        if not result:
            return MCPVerifyResult(success=False, reachable=True, error="Empty response", response_time_ms=elapsed())
        if not isinstance(result, dict):
            return MCPVerifyResult(success=False, reachable=True, error="Invalid response format",
                                   response_time_ms=elapsed())
        if "error" in result:
            error = result["error"]
            return MCPVerifyResult(success=False, reachable=True,
                                   error=error.get("message", str(error)) if isinstance(error, dict) else str(error),
                                   response_time_ms=elapsed())
        init_result = result.get("result")
        if not isinstance(init_result, dict):
            return MCPVerifyResult(success=False, reachable=True, error="Invalid response format",
                                   response_time_ms=elapsed())
        # An MCP initialize response carries protocolVersion and serverInfo; at least one confirms MCP
        protocol_version = init_result.get("protocolVersion")
        server_info = init_result.get("serverInfo") if isinstance(init_result.get("serverInfo"), dict) else {}
        server_name = server_info.get("name")
        if not protocol_version and not server_name:
            return MCPVerifyResult(
                success=False, reachable=True,
                error="Response missing MCP indicators (no protocolVersion or serverInfo.name)",
                response_time_ms=elapsed(),
            )
        server_version = server_info.get("version")
        self._remember(public_url, protocol_version if isinstance(protocol_version, str) else None, ERA_LEGACY)
        logger.info(f"MCP service verified: name={server_name}, version={server_version}, protocol={protocol_version}")
        return MCPVerifyResult(
            success=True, reachable=True,
            protocol_version=protocol_version, protocol_era=ERA_LEGACY,
            server_name=server_name,
            server_version=server_version,
            server_description=summarize_instructions(init_result.get("instructions")) or server_info.get("description"),
            capabilities=init_result.get("capabilities"),
            response_time_ms=elapsed(),
        )

    async def get_tools_list(
        self,
        host: str,
        port: int,
        path: str = "/mcp",
        protocol: str = "http",
        auth_token: Optional[str] = None
    ) -> List[MCPToolInfo]:
        """Get the tool list of an MCP service.

        Modern servers (MCP 2026-07-28 and later): one stateless `tools/list` carrying its protocol version in
        `_meta` and the MCP-Protocol-Version / Mcp-Method headers. Legacy servers: initialize -> initialized ->
        tools/list in one session. The era comes from `server/discover` (remembered per URL).

        Returns [] only when the server answered a valid tools/list with an empty `tools` array.
        Raises PermissionError on 401, InvalidTargetError for an unacceptable protocol / host / path,
        and ToolsListError on any other failure.
        """
        public_url = build_mcp_url(protocol, host, port, path)  # reject a bad target before resolving anything
        # SSRF protection (AUDIT-1): resolve and validate once, pin the connection to that IP (prevents
        # DNS rebinding), and keep the original Host header so vhost routing is unaffected. ScannerSSRFError
        # (blocked address or unresolvable host) propagates so the caller can say why.
        connect_host = _resolve_validated_ip(host)
        url = build_mcp_url(protocol, connect_host, port, path)
        headers = _base_headers(host, port, connect_host, auth_token)

        try:
            timeout = aiohttp.ClientTimeout(total=self.rpc_timeout)
            async with aiohttp.ClientSession() as session:
                remembered = self._eras.get(public_url)
                try:
                    return await self._tools_in_era(session, url, headers, timeout, public_url, remembered)
                except ToolsListError:
                    if remembered is None:
                        raise
                    # The remembered era stopped working: probe again once
                    self._forget(public_url)
                    return await self._tools_in_era(session, url, headers, timeout, public_url, None)
        except (PermissionError, ToolsListError):
            raise
        except asyncio.TimeoutError as e:
            raise ToolsListError("tools/list failed: connection timeout") from e
        except Exception as e:
            raise ToolsListError(f"tools/list failed: {e}") from e

    async def _tools_in_era(self, session, url, headers, timeout, public_url, era) -> List[MCPToolInfo]:
        offer = None
        version = self._seen[public_url].version if era == ERA_MODERN and public_url in self._seen else None
        if era is None:
            reply, outcome = await self._negotiate(session, url, headers, timeout)
            if outcome[0] == "auth":
                raise PermissionError("Service requires authentication. Please configure auth_token for this service.")
            if outcome[0] == "error":
                raise ToolsListError(f"server/discover failed: {outcome[1]}")
            if outcome[0] == "modern":
                era, version = ERA_MODERN, outcome[1]
            else:
                era, offer = ERA_LEGACY, outcome[1]
        if era == ERA_MODERN:
            version = version or LATEST_MODERN_VERSION
            reply = await self._post(session, url, _modern_request("tools/list", 2, version),
                                     _modern_headers(headers, "tools/list", version), timeout)
            tools = self._parse_tools(reply)
            self._remember(public_url, version, ERA_MODERN)
            return tools
        return await self._legacy_tools(session, url, headers, timeout, public_url, offer)

    async def _legacy_tools(self, session, url, headers, timeout, public_url, offer) -> List[MCPToolInfo]:
        # Step 1: initialize. SSE is read incrementally: a plain read() would wait for the stream to end and hang
        # forever (see the notes on _read_sse_message).
        init = await self._post(session, url, _initialize_request(offer), headers, timeout)
        if init.status == 401:
            raise PermissionError("Service requires authentication. Please configure auth_token for this service.")
        if init.status != 200:
            raise ToolsListError(f"initialize failed: HTTP {init.status}")
        if not isinstance(init.body, dict) or not isinstance(init.body.get("result"), dict):
            raise ToolsListError(f"initialize failed: {_jsonrpc_error_text(init.body)}")
        negotiated = init.body["result"].get("protocolVersion")
        session_headers = dict(headers)
        if init.session_id:  # Streamable HTTP carries the session in this header
            session_headers["mcp-session-id"] = init.session_id
        if isinstance(negotiated, str) and negotiated:
            # Required on every request after initialize since 2025-06-18; older servers ignore it
            session_headers["MCP-Protocol-Version"] = negotiated

        # Step 2: the initialized notification (its reply carries nothing we need)
        await self._post(session, url, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                         session_headers, timeout)
        # Step 3: the tool list
        reply = await self._post(session, url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                                 session_headers, timeout)
        tools = self._parse_tools(reply)
        self._remember(public_url, negotiated if isinstance(negotiated, str) else None, ERA_LEGACY)
        return tools

    @staticmethod
    def _parse_tools(reply: _Reply) -> List[MCPToolInfo]:
        if reply.status == 401:
            raise PermissionError("Service requires authentication. Please configure auth_token for this service.")
        if reply.status != 200:
            raise ToolsListError(f"tools/list failed: HTTP {reply.status}")
        data = reply.body
        result = data.get("result") if isinstance(data, dict) else None
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list) or not all(isinstance(t, dict) for t in tools):
            raise ToolsListError(f"tools/list failed: {_jsonrpc_error_text(data)}")
        return [
            MCPToolInfo(
                name=t.get("name", ""),
                description=t.get("description"),
                input_schema=t.get("inputSchema"),
                title=t.get("title"),
                output_schema=t.get("outputSchema"),
                annotations=t.get("annotations"),
            )
            for t in tools
        ]

    async def discover_services(
        self,
        hosts: List[str],
        ports: List[int],
        verify: bool = True,
        get_tools: bool = True,
        auth_token: Optional[str] = None,
        token_factory: Optional[TokenFactory] = None,
        host_errors: Optional[List[dict]] = None,
    ) -> List[DiscoveredService]:
        """Discover MCP services.

        Args:
            hosts: List of hosts
            ports: List of ports
            verify: Whether to verify MCP services
            get_tools: Whether to fetch the tool list
            auth_token: Bearer token (optional, for MCP services that require authentication)
            token_factory: Mints a token for a peer's MCP URL so servers protected by MCP Gate itself
                can be inspected without the caller supplying a token
            host_errors: When given, a host that may not be scanned (it resolves to a blocked address) is
                appended here as {host, error, params, fallback} and the scan goes on with the other hosts

        Returns:
            List of DiscoveredService
        """
        discovered = []

        for host in hosts:
            # Scan for open ports. A blocked host (link-local / metadata address) is skipped, not fatal:
            # one bad entry must not fail the scan of every other host (#16).
            try:
                open_ports = await self.scan_ports(host, ports)
            except ScannerSSRFError as e:
                logger.warning(f"Scan of {host} skipped: {e}")
                if host_errors is not None:
                    host_errors.append({
                        "host": host, "error": "discovery.address_blocked", "params": {"host": host},
                        "fallback": f"{host} resolves to a blocked address (link-local or cloud metadata); skipped.",
                    })
                continue
            logger.info(f"Found {len(open_ports)} open ports on {host}: {open_ports}")

            # Verify each open port
            for port in open_ports:
                service = DiscoveredService(
                    host=host,
                    port=port,
                    protocol="http"
                )

                if verify:
                    # Try HTTP first; only fall back to HTTPS when the port did not answer HTTP at all
                    # (a TLS handshake against a plain-HTTP server just produces noise in its logs).
                    result = await self.verify_mcp_service(host, port, "/mcp", "http", auth_token, token_factory)
                    if not result.success and not result.reachable:
                        result = await self.verify_mcp_service(host, port, "/mcp", "https", auth_token, token_factory)
                        if result.success:
                            service.protocol = "https"

                    service.verify_result = result

                    # Fetch tools when verification succeeded and we hold a token the peer accepts
                    # (the caller's, or the one minted during verification); a bare "(requires auth)"
                    # placeholder means we could not get in.
                    tools_token = auth_token or result.auth_token
                    can_list = not result.requires_auth or bool(tools_token)
                    if result.success and get_tools and can_list and result.server_name != "(requires auth)":
                        try:
                            tools = await self.get_tools_list(
                                host, port, "/mcp", service.protocol, tools_token
                            )
                            service.tools = tools
                        except PermissionError:
                            # Service requires authentication; skip fetching tools
                            pass
                        except ToolsListError as e:
                            # Verified but tools/list failed: keep the service, without tools
                            logger.warning(f"Tools not fetched from {host}:{port}: {e}")

                # Only add services that verified successfully, or all services when not verifying
                if not verify or (service.verify_result and service.verify_result.success):
                    discovered.append(service)

        return discovered


# Global scanner instance
_scanner_instance: Optional[MCPScanner] = None


def _default_rpc_timeout() -> float:
    """Default timeout (seconds) for MCP JSON-RPC calls.

    The peer may be cold-starting (npx/uvx inside the container installing online for the first time),
    so 5 seconds is nowhere near enough. BYO cold starts are already absorbed by the orchestrator's
    warm-up; a generous default is kept here as a safety net.
    """
    import os as _os
    try:
        return float(_os.environ.get("MCP_RPC_TIMEOUT", "60"))
    except ValueError:
        return 60.0


def _default_scan_timeout() -> float:
    """Default timeout (seconds) for scanning/verification.

    5s is more than enough for a service that is already ready, but too short for one that is still
    cold-starting. BYO cold starts are already absorbed by the orchestrator's warm-up (see
    Orchestrator._warmup_bridge); the environment variable is kept so deployments can fine-tune it.
    """
    import os as _os
    try:
        return float(_os.environ.get("MCP_SCAN_TIMEOUT", "5"))
    except ValueError:
        return 5.0


def get_scanner() -> MCPScanner:
    """Get the MCPScanner singleton instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = MCPScanner(timeout=_default_scan_timeout())
    return _scanner_instance
