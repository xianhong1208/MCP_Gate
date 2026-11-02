"""MCP service discovery (/api/discovery/*) and the service status WebSocket."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser
from src.adapters import (
    MCPToolAdapter, ServiceAdapter, describe_server, fallback_service_description, fallback_service_name,
    sanitize_server_name,
)
from src.api.schemas import DiscoveredServiceInfo, ScanRequest, ScanResponse, VerifyRequest, VerifyResponse
from src.audit import ActorType, AuditService, AuditStatus, ResourceType
from src.discovery.scanner import get_scanner
from src.oauth import service as oauth_service
from src.discovery.websocket_manager import get_ws_manager
from src.identity import get_current_user
from src.identity.session import SESSION_COOKIE, resolve_user_from_token
from src.middleware.origin_check import request_origin_allowed
from src.utils.mcp_target import InvalidTargetError, build_mcp_url, validate_host

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/discovery", tags=["Discovery"])


def _scanner_token_factory(db: Session):
    """Give the scanner a way to mint tokens for peers protected by this authorization server.

    Registered services keep their own audience / scope limits; unknown peers get a token whose
    audience is their MCP URL, which is what a FastMCP server registered later would expect.
    """
    def mint(audience: str):
        try:
            service = ServiceAdapter.get_by_audience(db, audience)
            if service is not None:
                return oauth_service.mint_scanner_token(db, service)
            return oauth_service.mint_audience_token(db, audience)
        except Exception as e:  # never let token minting break a scan
            logger.warning(f"Scanner token for {audience} not minted: {e}")
            return None
    return mint


# Upper bound on hosts x ports per scan request: one full port range on one host. Each probe is a TCP
# connect, so an unbounded request (e.g. port_range_end=10**9) would build a huge list and tie the
# server up for hours.
MAX_SCAN_PROBES = 65536
_MIN_PORT, _MAX_PORT = 1, 65535


def _scan_error(code: str, fallback: str, **params) -> HTTPException:
    return HTTPException(status_code=422, detail={"error": f"discovery.{code}", "params": params,
                                                  "fallback": fallback})


def _scan_ports(request: ScanRequest) -> list:
    """Validate the scan request and return the sorted, de-duplicated ports to probe.

    Checked here rather than with pydantic constraints so the console gets the usual
    `{error, params, fallback}` envelope (a pydantic 422 is a bare list it cannot show).
    """
    if not request.hosts or any(not h or not h.strip() for h in request.hosts):
        raise _scan_error("no_hosts", "At least one host is required.")
    for host in request.hosts:
        try:
            validate_host(host.strip())
        except InvalidTargetError:
            raise _scan_error("invalid_host", f"'{host}' is not a bare host name or IP address.", host=host)
    for port in request.ports:
        if not _MIN_PORT <= port <= _MAX_PORT:
            raise _scan_error("invalid_port", f"Port {port} is out of range (1-65535).", port=port)
    start, end = request.port_range_start, request.port_range_end
    ports = set(request.ports)
    if start is not None or end is not None:
        if start is None or end is None or not _MIN_PORT <= start <= end <= _MAX_PORT:
            raise _scan_error("invalid_port_range",
                              "Port range must have 1 <= start <= end <= 65535.", start=start, end=end)
        ports.update(range(start, end + 1))
    if not ports:
        raise _scan_error("no_ports", "At least one port is required.")
    probes = len(request.hosts) * len(ports)
    if probes > MAX_SCAN_PROBES:
        raise _scan_error("too_many_probes",
                          f"Scan too large: {len(request.hosts)} hosts x {len(ports)} ports exceeds "
                          f"the limit of {MAX_SCAN_PROBES} probes.",
                          hosts=len(request.hosts), ports=len(ports), limit=MAX_SCAN_PROBES)
    return sorted(ports)


@router.post("/scan", response_model=ScanResponse)
async def scan_services(request: ScanRequest, http_request: Request, db: Session = Depends(get_db),
                        current_user: AdminUser = Depends(get_current_user)):
    """Scan hosts / ports to find MCP servers, optionally registering them automatically."""
    ports = _scan_ports(request)  # validated outside the try: its 422s must not become a 500
    try:
        scanner = get_scanner()
        discovered = await scanner.discover_services(
            hosts=request.hosts, ports=ports, verify=True, get_tools=True, auth_token=request.auth_token,
            token_factory=_scanner_token_factory(db),
        )

        discovered_info = []
        registered_count = 0
        for svc in discovered:
            vr = svc.verify_result
            info = DiscoveredServiceInfo(
                host=svc.host, port=svc.port, protocol=svc.protocol, mcp_path=svc.mcp_path,
                server_name=vr.server_name if vr else None, server_version=vr.server_version if vr else None,
                server_description=vr.server_description if vr else None,
                protocol_version=vr.protocol_version if vr else None, tools_count=len(svc.tools),
                requires_auth=svc.requires_auth,
            )
            if request.auto_register:
                if request.service_name:
                    service_name = request.service_name
                elif vr and vr.server_name and vr.server_name != "(requires auth)":
                    service_name = sanitize_server_name(vr.server_name)
                else:
                    service_name = fallback_service_name(svc.host, svc.port)

                existing = ServiceAdapter.get_by_host_port(db, svc.host, svc.port)
                if existing:
                    info.registered = False
                    info.service_name = existing.name
                    info.service_id = str(existing.id)
                else:
                    description = (describe_server(vr.server_name, vr.server_version, vr.server_description)
                                   if vr else None) or fallback_service_description(svc.host, svc.port)
                    new_service = ServiceAdapter.create(
                        db=db, name=service_name, description=description, host=svc.host, port=svc.port,
                        protocol=svc.protocol, mcp_path=svc.mcp_path, source="auto_discovered",
                        requires_auth=svc.requires_auth,
                    )
                    if svc.tools:
                        MCPToolAdapter.sync_tools(db, str(new_service.id), [
                            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                            for t in svc.tools
                        ])
                    ServiceAdapter.update_health(db=db, service_id=str(new_service.id), status="online",
                                                 response_time_ms=vr.response_time_ms if vr else None,
                                                 reset_fail_count=True)
                    info.registered = True
                    info.service_name = service_name
                    info.service_id = str(new_service.id)
                    registered_count += 1
                    await get_ws_manager().broadcast_service_added(
                        service_id=str(new_service.id), service_name=service_name,
                        service_data={"host": svc.host, "port": svc.port, "tools_count": len(svc.tools)},
                    )
            discovered_info.append(info)

        AuditService.log_from_request(
            db=db, request=http_request, action="scan_services", resource_type=ResourceType.SERVICE,
            status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(current_user.id),
            actor_name=current_user.audit_name,
            details={"hosts": request.hosts, "ports_count": len(ports), "discovered_count": len(discovered_info),
                     "registered_count": registered_count},
        )
        return ScanResponse(
            success=True, message=f"Scan completed. Found {len(discovered_info)} MCP services.",
            scanned_hosts=len(request.hosts), scanned_ports=len(ports), discovered=discovered_info,
            registered_count=registered_count,
        )
    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail={"error": "discovery.scan_failed", "fallback": "Scan failed."})


@router.post("/verify", response_model=VerifyResponse)
async def verify_service(request: VerifyRequest, db: Session = Depends(get_db),
                         _: AdminUser = Depends(get_current_user)):
    """Check whether host:port serves MCP and return its server info."""
    try:
        build_mcp_url(request.protocol, request.host, request.port, request.mcp_path)
    except InvalidTargetError as e:
        raise HTTPException(status_code=400, detail={"error": e.code, "fallback": e.fallback})
    try:
        result = await get_scanner().verify_mcp_service(
            host=request.host, port=request.port, path=request.mcp_path, protocol=request.protocol,
            auth_token=request.auth_token, token_factory=_scanner_token_factory(db),
        )
        return VerifyResponse(
            success=result.success, protocol_version=result.protocol_version, server_name=result.server_name,
            server_version=result.server_version, capabilities=result.capabilities, error=result.error,
            response_time_ms=result.response_time_ms,
        )
    except Exception as e:
        logger.error(f"Verify error: {e}")
        raise HTTPException(status_code=500, detail={"error": "discovery.verify_failed", "fallback": "Verify failed."})


ws_router = APIRouter(tags=["WebSocket"])


@ws_router.websocket("/ws/services")
async def websocket_services(websocket: WebSocket):
    """Real-time service status push. Auth: the console's session cookie, from the console's own origin.

    The cookie is attached to any page's WebSocket handshake (WebSockets are not covered by CORS), so a
    handshake whose Origin is not the console's is refused before the cookie is looked at. A token in the
    query string is not accepted: URLs end up in proxy and access logs.
    """
    from db.database import make_session

    if not request_origin_allowed(websocket.scope):
        await websocket.close(code=1008, reason="Origin not allowed")
        return
    token = websocket.cookies.get(SESSION_COOKIE)
    db = make_session()
    try:
        user = resolve_user_from_token(db, token)
    finally:
        db.close()
    if user is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    await get_ws_manager().handle_connection(websocket)
