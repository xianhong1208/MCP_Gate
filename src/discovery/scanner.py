"""MCP service discovery scanner

Features:
- Port scanning (Python async socket)
- MCP service verification (JSON-RPC initialize)
- Tool list retrieval (tools/list)
- SSE format support
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class MCPToolInfo:
    """MCP tool information"""
    name: str
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None


@dataclass
class MCPVerifyResult:
    """MCP service verification result"""
    success: bool
    protocol_version: Optional[str] = None
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

        If the verification result shows "(requires auth)" or a 401 error, authentication is required.
        If tools were fetched successfully (without an auth_token), authentication is not required.
        """
        if self.verify_result:
            if self.verify_result.requires_auth:
                return True
            # server_name == "(requires auth)" means the service returned 401
            if self.verify_result.server_name == "(requires auth)":
                return True
            # Tools were fetched successfully without an auth_token, so no authentication is needed
            if self.tools:
                return False
        # Default to requiring authentication (the safer assumption)
        return True


class ScannerSSRFError(Exception):
    """Connection target address rejected by SSRF protection"""


# audience (the peer's MCP URL) -> short-lived bearer token, or None when MCP Center cannot mint one
TokenFactory = Callable[[str], Optional[str]]


def _is_bearer_challenge(www_authenticate: Optional[str]) -> bool:
    """True when a 401 carries the standard MCP/OAuth challenge (`WWW-Authenticate: Bearer ...`).

    MCP servers built on FastMCP (and the MCP authorization spec in general) answer unauthenticated
    requests with an empty 401 body and a Bearer challenge that points at their protected-resource
    metadata. That header, not a JSON-RPC body, is the signal that the peer speaks MCP behind OAuth.
    """
    return bool(www_authenticate) and www_authenticate.strip().lower().startswith("bearer")


def _resolve_validated_ip(host: str) -> Optional[str]:
    """SSRF protection: resolve the host, validate every IP, and return a single IP that is safe to connect to.

    Rejects link-local (including the cloud metadata address 169.254.169.254), multicast, reserved and
    unspecified (0.0.0.0) addresses; allows loopback / private addresses (scanning local managed services
    and intranet MCP services is a legitimate use case).

    Key point: the *validated* IP is returned so the caller can pin the connection to it, avoiding DNS
    rebinding between "resolve at validation time" and "resolve again at connect time" (first answer is a
    benign IP that passes the check, second answer is the metadata IP). If the host is already an IP
    literal it is validated and returned directly. Resolution failure returns None (left to the connection
    phase's timeout/error handling rather than being rejected here). Addresses security audit item AUDIT-1
    (SSRF).
    """
    import ipaddress as _ip
    import socket as _sock
    try:
        infos = _sock.getaddrinfo(host, None)
    except _sock.gaierror:
        return None
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
        if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ScannerSSRFError(
                f"Refusing to connect to disallowed address {addr} "
                f"(link-local / cloud-metadata / reserved addresses are blocked)"
            )
        if validated is None:
            validated = addr
    return validated


def _url_host(host: str) -> str:
    """Host form for building URLs: IPv6 addresses need square brackets."""
    return f"[{host}]" if ":" in host else host


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
        # (prevents DNS rebinding)
        connect_host = _resolve_validated_ip(host) or host
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

        Uses a JSON-RPC initialize request to check whether the service is a valid MCP service.
        When the peer answers 401 with a Bearer challenge and `token_factory` is given, a token for the
        peer's MCP URL is minted (MCP Center is the authorization server) and the probe is retried once,
        so servers protected by MCP Center still report their real name, version and tools.
        """
        public_url = f"{protocol}://{_url_host(host)}:{port}{path}"
        # SSRF protection (AUDIT-1): resolve and validate once, pin the connection to that IP (prevents
        # DNS rebinding), and keep the original Host header so vhost routing is unaffected.
        connect_host = _resolve_validated_ip(host) or host
        url = f"{protocol}://{_url_host(connect_host)}:{port}{path}"
        start_time = time.time()

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"
        }
        if connect_host != host:
            headers["Host"] = f"{host}:{port}"
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-center-scanner",
                    "version": "1.0.0"
                }
            }
        }

        try:
            timeout = aiohttp.ClientTimeout(total=self.rpc_timeout)
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    ssl=False
                ) as response:
                    elapsed_ms = (time.time() - start_time) * 1000
                    logger.info(f"MCP verify response: status={response.status}, content-type={response.headers.get('Content-Type', 'N/A')}")

                    # Handle non-200 status codes
                    # Note: a 401 alone must not be taken as an MCP service, since any protected HTTP
                    # endpoint may return 401. Two signals confirm MCP behind auth: a Bearer challenge
                    # (the MCP authorization spec) or a JSON-RPC formatted 401 body.
                    if response.status == 401:
                        is_mcp_auth = _is_bearer_challenge(response.headers.get("WWW-Authenticate"))
                        if not is_mcp_auth:
                            try:
                                content_type = response.headers.get("Content-Type", "")
                                if "application/json" in content_type or "text/event-stream" in content_type:
                                    body = await self._read_jsonrpc(response)
                                    is_mcp_auth = bool(body) and isinstance(body, dict) and \
                                        ("jsonrpc" in body or "error" in body)
                            except Exception:
                                pass
                        if not is_mcp_auth:
                            return MCPVerifyResult(
                                success=False, reachable=True,
                                error="HTTP 401 (not MCP - no Bearer challenge or JSON-RPC response)",
                                response_time_ms=elapsed_ms,
                            )
                        # MCP Center is the authorization server: mint a token for this URL and look inside
                        if token_factory is not None and not auth_token:
                            minted = token_factory(public_url)
                            if minted:
                                retry = await self.verify_mcp_service(host, port, path, protocol, minted)
                                if retry.success:
                                    retry.requires_auth = True
                                    retry.auth_token = minted
                                    return retry
                                logger.info(f"Self-minted scanner token rejected by {public_url}: {retry.error}")
                        return MCPVerifyResult(
                            success=True, reachable=True, requires_auth=True,
                            server_name="(requires auth)",
                            error="Service requires authentication (401)",
                            response_time_ms=elapsed_ms,
                        )

                    if response.status != 200:
                        return MCPVerifyResult(
                            success=False, reachable=True,
                            error=f"HTTP {response.status}",
                            response_time_ms=elapsed_ms
                        )

                    # Handle the SSE or JSON response (SSE must be read incrementally -- see _read_sse_message)
                    result = await self._read_jsonrpc(response)

                    if not result:
                        return MCPVerifyResult(
                            success=False, reachable=True,
                            error="Empty response",
                            response_time_ms=elapsed_ms
                        )

                    if "error" in result:
                        return MCPVerifyResult(
                            success=False, reachable=True,
                            error=result["error"].get("message", str(result["error"])),
                            response_time_ms=elapsed_ms
                        )

                    if "result" in result:
                        init_result = result["result"]

                        # Verify that this is a valid MCP initialize response
                        # An MCP response must contain protocolVersion and serverInfo
                        protocol_version = init_result.get("protocolVersion")
                        server_info = init_result.get("serverInfo", {})
                        server_name = server_info.get("name")

                        # At least protocolVersion or serverInfo.name is needed to confirm MCP
                        if not protocol_version and not server_name:
                            return MCPVerifyResult(
                                success=False, reachable=True,
                                error="Response missing MCP indicators (no protocolVersion or serverInfo.name)",
                                response_time_ms=elapsed_ms
                            )

                        server_version = server_info.get("version")
                        server_description = init_result.get("instructions") or server_info.get("description")
                        logger.info(f"MCP service verified: name={server_name}, version={server_version}")
                        return MCPVerifyResult(
                            success=True, reachable=True,
                            protocol_version=protocol_version,
                            server_name=server_name,
                            server_version=server_version,
                            server_description=server_description,
                            capabilities=init_result.get("capabilities"),
                            response_time_ms=elapsed_ms
                        )

                    return MCPVerifyResult(
                        success=False, reachable=True,
                        error="Invalid response format",
                        response_time_ms=elapsed_ms
                    )

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

    async def get_tools_list(
        self,
        host: str,
        port: int,
        path: str = "/mcp",
        protocol: str = "http",
        auth_token: Optional[str] = None
    ) -> List[MCPToolInfo]:
        """Get the tool list of an MCP service (three-step flow: initialize -> initialized -> tools/list)."""
        # SSRF protection (AUDIT-1): resolve and validate once, pin the connection to that IP (prevents
        # DNS rebinding), and keep the original Host header so vhost routing is unaffected.
        connect_host = _resolve_validated_ip(host) or host
        url = f"{protocol}://{_url_host(connect_host)}:{port}{path}"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"
        }
        if connect_host != host:
            headers["Host"] = f"{host}:{port}"
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        try:
            timeout = aiohttp.ClientTimeout(total=self.rpc_timeout)
            async with aiohttp.ClientSession() as session:
                # Step 1: Initialize
                init_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-center-scanner", "version": "1.0.0"}
                    }
                }

                async with session.post(
                    url, json=init_request, headers=headers, timeout=timeout, ssl=False
                ) as init_response:
                    if init_response.status == 401:
                        raise PermissionError("Service requires authentication. Please configure auth_token for this service.")
                    if init_response.status != 200:
                        return []

                    # Get the session ID (Streamable HTTP carries the session in this header)
                    session_id = init_response.headers.get("mcp-session-id")

                    # Read the initialize response. SSE must be read incrementally: a plain read() waits
                    # for the stream to end and hangs forever (see the notes on _read_sse_message).
                    await self._read_jsonrpc(init_response)

                # Step 2: Send the initialized notification
                initialized_notification = {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {}
                }

                notify_headers = headers.copy()
                if session_id:
                    notify_headers["mcp-session-id"] = session_id

                async with session.post(
                    url, json=initialized_notification, headers=notify_headers, timeout=timeout, ssl=False
                ) as notify_response:
                    # Consume the response body (even though it is not needed, read it to avoid connection issues)
                    await notify_response.read()

                # Step 3: Fetch the tool list
                tools_request = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {}
                }

                tools_headers = headers.copy()
                if session_id:
                    tools_headers["mcp-session-id"] = session_id

                async with session.post(
                    url, json=tools_request, headers=tools_headers, timeout=timeout, ssl=False
                ) as response:
                    if response.status == 401:
                        raise PermissionError("Service requires authentication. Please configure auth_token for this service.")

                    if response.status == 200:
                        data = await self._read_jsonrpc(response)

                        if data and "result" in data and "tools" in data["result"]:
                            return [
                                MCPToolInfo(
                                    name=t.get("name", ""),
                                    description=t.get("description"),
                                    input_schema=t.get("inputSchema")
                                )
                                for t in data["result"]["tools"]
                            ]

        except PermissionError:
            raise
        except Exception as e:
            logger.error(f"Get tools list error: {e}")

        return []

    async def discover_services(
        self,
        hosts: List[str],
        ports: List[int],
        verify: bool = True,
        get_tools: bool = True,
        auth_token: Optional[str] = None,
        token_factory: Optional[TokenFactory] = None,
    ) -> List[DiscoveredService]:
        """Discover MCP services.

        Args:
            hosts: List of hosts
            ports: List of ports
            verify: Whether to verify MCP services
            get_tools: Whether to fetch the tool list
            auth_token: Bearer token (optional, for MCP services that require authentication)
            token_factory: Mints a token for a peer's MCP URL so servers protected by MCP Center itself
                can be inspected without the caller supplying a token

        Returns:
            List of DiscoveredService
        """
        discovered = []

        for host in hosts:
            # Scan for open ports
            open_ports = await self.scan_ports(host, ports)
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
