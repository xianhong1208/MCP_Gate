"""MCP service discovery (/api/discovery/*) and the service status WebSocket."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser
from src.adapters import MCPToolAdapter, ServiceAdapter, fallback_service_name, sanitize_server_name
from src.api.schemas import DiscoveredServiceInfo, ScanRequest, ScanResponse, VerifyRequest, VerifyResponse
from src.audit import ActorType, AuditService, AuditStatus, ResourceType
from src.discovery.scanner import get_scanner
from src.oauth import service as oauth_service
from src.discovery.websocket_manager import get_ws_manager
from src.identity import get_current_user
from src.identity.session import SESSION_COOKIE, resolve_user_from_token

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


@router.post("/scan", response_model=ScanResponse)
async def scan_services(request: ScanRequest, http_request: Request, db: Session = Depends(get_db),
                        current_user: AdminUser = Depends(get_current_user)):
    """Scan hosts / ports to find MCP servers, optionally registering them automatically."""
    try:
        scanner = get_scanner()
        ports = list(request.ports)
        if request.port_range_start and request.port_range_end:
            ports.extend(range(request.port_range_start, request.port_range_end + 1))
        ports = sorted(set(ports))

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
                    if vr and vr.server_description:
                        description = vr.server_description
                    elif vr and vr.server_name:
                        description = f"{vr.server_name}{' v' + vr.server_version if vr.server_version else ''}"
                    else:
                        description = f"MCP service at {svc.host}:{svc.port}"
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
    """Real-time service status push. Auth: session cookie (SPA) or ?token= (session JWT)."""
    from db.database import make_session

    token = websocket.cookies.get(SESSION_COOKIE) or websocket.query_params.get("token")
    db = make_session()
    try:
        user = resolve_user_from_token(db, token)
    finally:
        db.close()
    if user is None:
        await websocket.close(code=4001, reason="Authentication required")
        return
    await get_ws_manager().handle_connection(websocket)
