"""Core API (/api/*): MCP service registration / tools / health, statistics, audit, system. Requires login (session)."""

from __future__ import annotations

import json
import platform
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser, Service, format_datetime
from src.adapters import (
    AdminUserAdapter, MCPToolAdapter, OAuthClientAdapter, OAuthTokenAdapter, ServiceAdapter, TokenUsageAdapter,
)
from src.adapters.exceptions import AdapterError
from src.api.schemas import (
    AuditLogInfo, AuditLogListResponse, AuditLogStatsResponse, BulkHealthCheckResponse, HealthResponse,
    ApproveAllToolsRequest, ApproveAllToolsResponse, MCPToolInfo, MCPToolVersionInfo, RefreshToolsRequest,
    RefreshToolsResponse, ServiceCreateRequest, ServiceHealthCheckResponse, ServiceHealthInfo, ServiceInfo,
    ServiceListResponse, ServiceUpdateRequest, ToolDecisionRequest, ToolDecisionResponse,
)
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.identity import get_current_user, get_optional_current_user
from src.logging import get_logger
from src.scheduler import get_scheduler
from src.tool_pinning.scan import SCAN_RULES_VERSION, freeze_registry, is_flagged, scan_tool, summarize
from src.utils.crypto import encrypt_token
from src.utils.field_limits import FieldTooLongError, check_max_length
from src.utils.mcp_target import InvalidTargetError, build_mcp_url
from src.version import __build_commit__, __build_time__, __version__

logger = get_logger("api")
router = APIRouter()


def _adapter_exc(e: AdapterError) -> HTTPException:
    return HTTPException(status_code=e.status_code, detail=e.to_detail())


# A static bearer token for a server MCP Gate does not protect: long enough for any realistic JWT, short enough to
# stop absurd payloads (it is stored encrypted, in a TEXT column)
MAX_STATIC_TOKEN_LENGTH = 8192


def _encrypt_static_token(token: str) -> str:
    try:
        check_max_length("auth_token", token, MAX_STATIC_TOKEN_LENGTH)
    except FieldTooLongError as e:
        raise HTTPException(status_code=400, detail=e.to_detail())
    return encrypt_token(token)


def _findings(tool, version, registry):
    """The poisoning scan of one version of a tool (#34): computed on read, never stored (see scan.py)."""
    return scan_tool(json.loads(version.definition), registry, str(tool.service_id))


def _version_info(tool, v, registry) -> MCPToolVersionInfo:
    return MCPToolVersionInfo(**v.to_dict(), findings=[f.to_dict() for f in _findings(tool, v, registry)])


def _tool_info(t, registry=None) -> MCPToolInfo:
    """A tool with its versions and their scan findings. `registry` is freeze_registry(MCPToolAdapter.registry(db)) (the tool names
    the mention rule looks for); read it once per request."""
    data = t.to_dict()
    approved = t.approved_version
    current = t.current_version
    current_findings = _findings(t, current, registry) if current is not None else []
    return MCPToolInfo(
        id=data["id"], name=t.name, title=t.title, description=t.description,
        input_schema=data["input_schema"], output_schema=data["output_schema"], annotations=data["annotations"],
        created_at=data["created_at"], hash=t.current_hash, state=t.state, removed_at=data["removed_at"],
        last_seen_at=format_datetime(t.last_seen_at),
        approved_version=(_version_info(t, approved, registry)
                          if approved is not None and approved.hash != t.current_hash else None),
        versions=[_version_info(t, v, registry) for v in t.versions],
        findings=[f.to_dict() for f in current_findings], flagged=is_flagged(current_findings),
    )


def _pending_flagged(tools, registry) -> int:
    """How many listed tools wait for approval with a warning or high finding on their current definition (#34)."""
    count = 0
    for t in tools:
        current = t.current_version
        if t.removed_at is None and current is not None and t.state == "pending" \
                and is_flagged(_findings(t, current, registry)):
            count += 1
    return count


def _protocol_seen(service: Service) -> dict:
    """How the scanner / health check last talked to this server since MCP Gate started (memory only)."""
    from src.discovery.scanner import get_scanner
    try:
        url = build_mcp_url(service.protocol, service.host, service.port, service.mcp_path)
    except (InvalidTargetError, TypeError, ValueError):
        return {}
    seen = get_scanner().protocol_seen(url)
    if seen is None:
        return {}
    return {"protocol_version": seen.version, "protocol_era": seen.era,
            "protocol_seen_at": format_datetime(seen.seen_at)}


def _service_info(service: Service, include_tools: bool = False, registry=None) -> ServiceInfo:
    data = service.to_dict(include_tools=False, include_health=True)
    data["health"] = ServiceHealthInfo(**data["health"], **_protocol_seen(service))
    listed = [t for t in service.tools if t.removed_at is None]
    data["tools_count"] = len(listed)
    data["tools_pending"] = sum(1 for t in listed if t.state == "pending")
    data["tools_flagged"] = _pending_flagged(listed, registry) if data["tools_pending"] else 0
    if include_tools:
        data["tools"] = [_tool_info(t, registry) for t in sorted(service.tools, key=lambda t: t.name)]
    return ServiceInfo(**data)


def _audit(db, request, user, action, resource_type, resource_id, details=None, status=AuditStatus.SUCCESS):
    AuditService.log_from_request(
        db=db, request=request, action=action, resource_type=resource_type, status=status,
        actor_type=ActorType.ADMIN, actor_id=str(user.id), actor_name=user.audit_name,
        resource_id=resource_id, details=details,
    )


# ==================== Public ====================

@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Liveness probe. Public."""
    return HealthResponse(status="ok", service="mcp-gate")


@router.get("/api/system/version", tags=["System"])
def get_version(user: Optional[AdminUser] = Depends(get_optional_current_user)):
    """Version and build information. The app version is public; build, Python and OS details need a session."""
    if user is None:
        return {"version": __version__}
    return {
        "version": __version__, "build_time": __build_time__, "build_commit": __build_commit__,
        "python_version": platform.python_version(), "platform": platform.system(),
    }


# ==================== Services ====================

@router.get("/api/services", response_model=ServiceListResponse, tags=["Services"])
async def list_services(
    health_status: Optional[str] = Query(None), source: Optional[str] = Query(None),
    tag: Optional[str] = Query(None), requires_auth: Optional[bool] = Query(None),
    include_inactive: bool = Query(False),
    db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user),
):
    """List registered MCP servers with health, audience and tool counts."""
    services = ServiceAdapter.get_all(db, include_inactive=include_inactive, health_status=health_status,
                                      source=source, tag=tag, requires_auth=requires_auth)
    # One more query, only when some tool waits for approval (the flagged count needs the names of every tool)
    pending = any(t.state == "pending" for s in services for t in s.tools if t.removed_at is None)
    registry = freeze_registry(MCPToolAdapter.registry(db)) if pending else None
    items = [_service_info(s, registry=registry) for s in services]
    return ServiceListResponse(services=items, total_count=len(items))


@router.post("/api/services", response_model=ServiceInfo, status_code=201, tags=["Services"])
async def create_service(request: ServiceCreateRequest, http_request: Request, db: Session = Depends(get_db),
                         user: AdminUser = Depends(get_current_user)):
    """Register an MCP server. The audience defaults to its MCP URL unless `oauth_audience` is given."""
    try:
        service = ServiceAdapter.create_checked(
            db, name=request.name, description=request.description, host=request.host, port=request.port,
            protocol=request.protocol, mcp_path=request.mcp_path,
            auth_token_encrypted=_encrypt_static_token(request.auth_token) if request.auth_token else None,
            tags=request.tags, source="manual", requires_auth=request.requires_auth,
            oauth_audience=request.oauth_audience, oauth_scopes=request.oauth_scopes,
        )
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, http_request, user, AuditAction.CREATE_SERVICE, ResourceType.SERVICE, str(service.id),
           {"name": service.name, "host": service.host, "port": service.port})
    return _service_info(service)


@router.get("/api/services/{service_id}", response_model=ServiceInfo, tags=["Services"])
async def get_service(service_id: str, include_tools: bool = Query(False), db: Session = Depends(get_db),
                      _: AdminUser = Depends(get_current_user)):
    """One MCP server; `include_tools=true` embeds its tool list."""
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    return _service_info(service, include_tools=include_tools, registry=freeze_registry(MCPToolAdapter.registry(db)))


@router.put("/api/services/{service_id}", response_model=ServiceInfo, tags=["Services"])
async def update_service(service_id: str, request: ServiceUpdateRequest, http_request: Request,
                         db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Update an MCP server. Send `auth_token` as an empty string to clear a stored static bearer token."""
    auth_token_encrypted = None
    if request.auth_token is not None:
        auth_token_encrypted = _encrypt_static_token(request.auth_token) if request.auth_token else ""
    try:
        service = ServiceAdapter.update_existing(
            db, service_id, name=request.name, description=request.description, is_active=request.is_active,
            host=request.host, port=request.port, protocol=request.protocol, mcp_path=request.mcp_path,
            auth_token_encrypted=auth_token_encrypted, tags=request.tags, requires_auth=request.requires_auth,
            oauth_audience=request.oauth_audience, oauth_scopes=request.oauth_scopes,
        )
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, http_request, user, AuditAction.UPDATE_SERVICE, ResourceType.SERVICE, service_id,
           {"name": service.name})
    return _service_info(service)


@router.delete("/api/services/{service_id}", tags=["Services"])
async def delete_service(service_id: str, http_request: Request, db: Session = Depends(get_db),
                         user: AdminUser = Depends(get_current_user)):
    """Delete an MCP server and its tool list and token events. A server run by a managed instance answers 409
    `service.managed_use_uninstall`: uninstall it from the Marketplace instead, which also stops it."""
    try:
        name = ServiceAdapter.delete_unmanaged(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, http_request, user, AuditAction.DELETE_SERVICE, ResourceType.SERVICE, service_id, {"name": name})
    return {"message": f"Service '{name}' deleted"}


# ==================== Tools / Health ====================

@router.get("/api/services/{service_id}/tools", tags=["Services"])
async def get_service_tools(service_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Tools last synced from the MCP server, with every pinned version and its approval state (#32).

    Tools the server no longer lists are included with `removed_at` set. `first_review` is true while no tool of
    the service has ever been approved: then "Approve all" is offered."""
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    registry = freeze_registry(MCPToolAdapter.registry(db))
    tools = [_tool_info(t, registry) for t in MCPToolAdapter.get_by_service(db, service_id)]
    listed = [t for t in tools if t.removed_at is None]
    return {"service_id": service_id, "service_name": service.name, "tools": tools, "count": len(listed),
            "pending_count": sum(1 for t in listed if t.state == "pending"),
            "flagged_count": sum(1 for t in listed if t.state == "pending" and t.flagged),
            "scan_rules_version": SCAN_RULES_VERSION,
            "first_review": not MCPToolAdapter.has_approved_version(db, service_id)}


@router.post("/api/services/{service_id}/tools/approve-all", response_model=ApproveAllToolsResponse,
             tags=["Services"])
async def approve_all_service_tools(service_id: str, body: ApproveAllToolsRequest, http_request: Request,
                                    db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Approve the first tool list of a service in one go (#32): the pending versions with these hashes. Refused
    with 409 once any tool of the service has been approved: later changes are reviewed one by one."""
    try:
        ServiceAdapter.get_existing(db, service_id)
        pairs = MCPToolAdapter.approve_first_list(db, service_id, body.hashes, user.audit_name)
    except AdapterError as e:
        raise _adapter_exc(e)
    registry = freeze_registry(MCPToolAdapter.registry(db))
    approved = []
    for t, v in pairs:
        approved.append({"name": t.name, "hash": v.hash, "findings": summarize(_findings(t, v, registry))})
    _audit(db, http_request, user, AuditAction.TOOL_APPROVE_ALL, ResourceType.SERVICE, service_id,
           {"tools": approved, "count": len(pairs),
            "findings": sum(a["findings"]["count"] for a in approved),
            "flagged": sum(1 for a in approved if a["findings"]["high"] or a["findings"]["warning"]),
            "scan_rules_version": SCAN_RULES_VERSION})
    tools = MCPToolAdapter.get_by_service(db, service_id)
    return ApproveAllToolsResponse(approved=len(pairs), tools=[_tool_info(t, registry) for t in tools])


def _decide_tool(service_id, tool_id, body, http_request, db, user, state, action):
    try:
        ServiceAdapter.get_existing(db, service_id)
        tool, version, previous = MCPToolAdapter.decide(db, service_id, tool_id, body.hash, state, user.audit_name)
    except AdapterError as e:
        raise _adapter_exc(e)
    registry = freeze_registry(MCPToolAdapter.registry(db))
    # The decision is recorded with what the poisoning scan showed the admin (#34): "approved with N findings"
    _audit(db, http_request, user, action, ResourceType.SERVICE, service_id,
           {"tool": tool.name, "tool_id": str(tool.id), "hash": version.hash, "previous_state": previous,
            "current": version.hash == tool.current_hash,
            "findings": summarize(_findings(tool, version, registry)), "scan_rules_version": SCAN_RULES_VERSION})
    return ToolDecisionResponse(tool=_tool_info(tool, registry), previous_state=previous)


@router.post("/api/services/{service_id}/tools/{tool_id}/approve", response_model=ToolDecisionResponse,
             tags=["Services"])
async def approve_service_tool(service_id: str, tool_id: str, body: ToolDecisionRequest, http_request: Request,
                               db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Approve one version of a tool (a pending or a rejected one), named by its hash (#32)."""
    return _decide_tool(service_id, tool_id, body, http_request, db, user, "approved", AuditAction.TOOL_APPROVE)


@router.post("/api/services/{service_id}/tools/{tool_id}/reject", response_model=ToolDecisionResponse,
             tags=["Services"])
async def reject_service_tool(service_id: str, tool_id: str, body: ToolDecisionRequest, http_request: Request,
                              db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Reject one version of a tool, or withdraw its approval (#32). A rejected version stays hidden and can be
    approved later."""
    return _decide_tool(service_id, tool_id, body, http_request, db, user, "rejected", AuditAction.TOOL_REJECT)


@router.post("/api/services/{service_id}/refresh-tools", response_model=RefreshToolsResponse, tags=["Services"])
async def refresh_service_tools(service_id: str, http_request: Request, body: Optional[RefreshToolsRequest] = None,
                                db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Connect to the service, fetch its tools list and sync it.

    By default services protected by MCP Gate OAuth are inspected with the anonymous scanner token. A server
    that shows different tools per caller can be inspected as one of its issued tokens (`identity=token` +
    `jti`): a short-lived copy of that token's claims is signed and presented.
    """
    from src.discovery.health_monitor import resolve_service_auth_token
    from src.discovery.scanner import get_scanner
    from src.oauth import service as oauth_service
    from src.oauth.errors import OAuthError

    body = body or RefreshToolsRequest()
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    if not service.host or not service.port:
        raise HTTPException(status_code=400, detail={"error": "service.no_host_port",
                                                     "fallback": "Service has no host or port configured"})
    if body.identity == "token":
        record = OAuthTokenAdapter.get(db, body.jti or "")
        if record is None:
            raise HTTPException(status_code=404, detail={"error": "oauth.token_not_found", "fallback": "Token not found"})
        try:
            auth_token = oauth_service.mint_probe_token_like(db, record=record, service=service)
        except OAuthError as e:
            raise HTTPException(status_code=400, detail={"error": f"oauth.{e.error}", "fallback": e.description})
    else:
        auth_token = resolve_service_auth_token(db, service)
    try:
        tools = await get_scanner().get_tools_list(
            host=service.host, port=service.port, path=service.mcp_path, protocol=service.protocol,
            auth_token=auth_token,
        )
    except InvalidTargetError as e:
        raise HTTPException(status_code=400, detail={"error": e.code, "fallback": e.fallback})
    except PermissionError:
        raise HTTPException(status_code=502, detail={"error": "service.remote_permission_denied",
                                                     "fallback": "Permission denied by remote MCP service."})
    except Exception as e:
        logger.warning(f"refresh tools failed for {service.name}: {e}")
        raise HTTPException(status_code=502, detail={"error": "service.remote_unreachable",
                                                     "fallback": f"Could not reach MCP service: {e}"})
    listed = MCPToolAdapter.sync_tools(db, service_id, [t.to_mcp() for t in tools])
    registry = freeze_registry(MCPToolAdapter.registry(db))
    infos = [_tool_info(t, registry) for t in listed]
    pending = sum(1 for t in infos if t.state == "pending")
    flagged = sum(1 for t in infos if t.state == "pending" and t.flagged)
    _audit(db, http_request, user, "refresh_tools", ResourceType.SERVICE, service_id,
           {"service_name": service.name, "tools_count": len(infos), "tools_pending": pending,
            "identity": body.identity,
            **({"jti": body.jti} if body.identity == "token" else {})})
    return RefreshToolsResponse(success=True, message=f"Refreshed {len(infos)} tools", tools_count=len(infos),
                                tools_pending=pending, tools_flagged=flagged, tools=infos)


@router.post("/api/services/health-check-all", response_model=BulkHealthCheckResponse, tags=["Services"])
async def check_all_services_health(_: AdminUser = Depends(get_current_user)):
    """Run the health check for every active MCP server now (same path as the scheduler)."""
    return BulkHealthCheckResponse(**(await get_scheduler().run_health_check_now()))


@router.get("/api/services/{service_id}/health", response_model=ServiceHealthCheckResponse, tags=["Services"])
async def get_service_health(service_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Last known health of one MCP server."""
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    return ServiceHealthCheckResponse(service_name=service.name, status=service.health_status or "unknown",
                                      response_time_ms=service.health_response_time_ms,
                                      error_message=service.health_error_message)


@router.post("/api/services/{service_id}/health-check", response_model=ServiceHealthCheckResponse, tags=["Services"])
async def check_service_health(service_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Run the health check for one MCP server now."""
    from src.discovery.health_monitor import resolve_service_auth_token
    from src.discovery.scanner import get_scanner

    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    if not service.host or not service.port:
        return ServiceHealthCheckResponse(service_name=service.name, status="unknown",
                                          error_message="Service has no host or port configured")
    result = await get_scanner().verify_mcp_service(
        host=service.host, port=service.port, path=service.mcp_path, protocol=service.protocol,
        auth_token=resolve_service_auth_token(db, service),
    )
    previous = service.health_status
    adopted = None
    if result.success:
        new_status, error_message = "online", None
        # A generated placeholder name (from a scan that could not read the server) is replaced by the
        # real name; a name the operator chose is never touched.
        adopted = ServiceAdapter.adopt_server_name(db, service, result.server_name)
        # Likewise the description is filled from serverInfo only while it is empty or generated; a
        # description the operator wrote is theirs.
        ServiceAdapter.adopt_server_description(db, service, result.server_name, result.server_version,
                                                result.server_description)
        ServiceAdapter.update_health(db, service_id, status=new_status, response_time_ms=result.response_time_ms,
                                     error_message=None, reset_fail_count=True)
    else:
        fail_count = (service.health_fail_count or 0) + 1
        new_status, error_message = ("offline" if fail_count >= 3 else "error"), result.error
        ServiceAdapter.update_health(db, service_id, status=new_status, response_time_ms=result.response_time_ms,
                                     error_message=error_message, increment_fail_count=True)
    return ServiceHealthCheckResponse(service_name=adopted or service.name, status=new_status,
                                      response_time_ms=result.response_time_ms, error_message=error_message,
                                      protocol_version=result.protocol_version, protocol_era=result.protocol_era,
                                      previous_status=previous, status_changed=new_status != previous)


# ==================== Stats ====================

@router.get("/api/stats/daily", tags=["Statistics"])
async def get_daily_stats(days: int = Query(7, ge=1, le=90), service_id: Optional[str] = Query(None),
                          event: Optional[str] = Query(None), db: Session = Depends(get_db),
                          _: AdminUser = Depends(get_current_user)):
    """Token events per day."""
    stats = TokenUsageAdapter.get_daily_stats(db, days=days, service_id=service_id, event=event)
    return {"stats": stats, "total": sum(s["total"] for s in stats), "days": days, "service_id_filter": service_id}


@router.get("/api/stats/hourly", tags=["Statistics"])
async def get_hourly_stats(hours: int = Query(24, ge=1, le=168), service_id: Optional[str] = Query(None),
                           event: Optional[str] = Query(None), db: Session = Depends(get_db),
                           _: AdminUser = Depends(get_current_user)):
    """Token events per hour."""
    stats = TokenUsageAdapter.get_hourly_stats(db, hours=hours, service_id=service_id, event=event)
    return {"stats": stats, "total": sum(s["total"] for s in stats), "hours": hours, "service_id_filter": service_id}


@router.get("/api/stats/services", tags=["Statistics"])
async def get_service_stats(days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db),
                            _: AdminUser = Depends(get_current_user)):
    """Token events per MCP server (audience) over the last N days."""
    stats = TokenUsageAdapter.get_service_stats(db, days=days)
    return {"stats": stats, "total": sum(s["total"] for s in stats), "days": days}


@router.get("/api/stats/summary", tags=["Statistics"])
async def get_stats_summary(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Token event totals: all time, 7 days, 24 hours."""
    return {
        "total_all_time": TokenUsageAdapter.get_total_count(db),
        "total_7_days": TokenUsageAdapter.get_total_count(db, days=7),
        "total_24_hours": TokenUsageAdapter.get_total_count(db, days=1),
    }


# ==================== Audit ====================

@router.get("/api/audit/logs", response_model=AuditLogListResponse, tags=["Audit"])
async def get_audit_logs(
    action: Optional[str] = Query(None), resource_type: Optional[str] = Query(None),
    actor_name: Optional[str] = Query(None), status: Optional[str] = Query(None),
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=10000),
    db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user),
):
    """Audit log entries, newest first, with filters and paging."""
    offset = (page - 1) * page_size
    logs = AuditService.get_logs(db=db, action=action, resource_type=resource_type, actor_name=actor_name,
                                 status=status, limit=page_size, offset=offset)
    total = AuditService.get_logs_count(db=db, action=action, resource_type=resource_type,
                                        actor_name=actor_name, status=status)
    return AuditLogListResponse(
        logs=[AuditLogInfo(**{**log.to_dict(), "created_at": format_datetime(log.created_at) or ""}) for log in logs],
        total_count=total, page=page, page_size=page_size,
    )


@router.get("/api/audit/stats", response_model=AuditLogStatsResponse, tags=["Audit"])
async def get_audit_stats(days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db),
                          _: AdminUser = Depends(get_current_user)):
    """Audit log counts by action and outcome."""
    return AuditLogStatsResponse(**AuditService.get_stats(db=db, days=days))


@router.delete("/api/audit/cleanup", tags=["Audit"])
async def cleanup_audit_logs(http_request: Request, days: int = Query(90, ge=7, le=365),
                             db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Delete audit log entries older than N days."""
    deleted = AuditService.cleanup_old_logs(db=db, days=days)
    _audit(db, http_request, user, AuditAction.CLEANUP_EXPIRED, ResourceType.SYSTEM, None,
           {"deleted_count": deleted, "retention_days": days})
    return {"message": f"Cleaned up {deleted} audit logs older than {days} days", "deleted_count": deleted}


# ==================== System ====================

@router.get("/api/system/scheduler/status", tags=["System"])
async def get_scheduler_status(_: AdminUser = Depends(get_current_user)):
    """Background jobs and their next run times."""
    scheduler = get_scheduler()
    jobs = []
    if scheduler.is_running():
        for job in scheduler.scheduler.get_jobs():
            jobs.append({"id": job.id, "name": job.name,
                         "next_run": job.next_run_time.isoformat() if job.next_run_time else None})
    return {
        "is_running": scheduler.is_running(), "jobs": jobs,
        "config": {
            "oauth_cleanup_hours": scheduler.oauth_cleanup_hours,
            "usage_retention_days": scheduler.usage_retention_days,
            "audit_retention_days": scheduler.audit_retention_days,
            "health_check_seconds": scheduler.health_check_seconds,
        },
    }


@router.get("/api/system/dashboard", tags=["System"])
async def get_dashboard_overview(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Everything the dashboard shows in one call."""
    services = ServiceAdapter.get_all(db)
    health_counts = {"online": 0, "offline": 0, "error": 0, "unknown": 0, "total": len(services)}
    offline_services = []
    for svc in services:
        status = svc.health_status or "unknown"
        health_counts[status if status in health_counts else "unknown"] += 1
        if status in ("offline", "error"):
            offline_services.append({
                "id": str(svc.id), "name": svc.name, "status": status, "host": svc.host, "port": svc.port,
                "last_health_check": format_datetime(svc.health_last_checked),
                "failure_count": svc.health_fail_count or 0,
            })
    scheduler = get_scheduler()
    return {
        "service_health": health_counts,
        "offline_services": offline_services[:5],
        "scheduler": {"is_running": scheduler.is_running(),
                      "jobs_count": len(scheduler.scheduler.get_jobs()) if scheduler.is_running() else 0},
        "admin_count": AdminUserAdapter.get_count(db),
        "oauth": {
            "clients": len(OAuthClientAdapter.list_all(db, status="approved")),
            "pending_clients": len(OAuthClientAdapter.list_all(db, status="pending")),
            "active_tokens": OAuthTokenAdapter.count_active(db),
            "active_pats": OAuthTokenAdapter.count_active(db, kind="pat"),
            "issued_24h": TokenUsageAdapter.get_total_count(db, days=1, event="issued"),
        },
    }


@router.post("/api/system/cleanup/run", tags=["System"])
async def run_cleanup_now(http_request: Request, db: Session = Depends(get_db),
                          user: AdminUser = Depends(get_current_user)):
    """Run the retention clean-up jobs now."""
    report = await get_scheduler().run_all_cleanup_now()
    results, errors = report["results"], report["errors"]
    if errors:
        # A failed job used to be counted as 0 and reported as success (#23)
        _audit(db, http_request, user, AuditAction.CLEANUP_EXPIRED, ResourceType.SYSTEM, None,
               {"results": results, "errors": errors}, status=AuditStatus.FAILURE)
        jobs = ", ".join(sorted(errors))
        raise HTTPException(status_code=500, detail={
            "error": "system.cleanup_failed", "params": {"jobs": jobs}, "results": results, "errors": errors,
            "fallback": f"Cleanup failed for: {jobs}. See the server log.",
        })
    _audit(db, http_request, user, AuditAction.CLEANUP_EXPIRED, ResourceType.SYSTEM, None, results)
    return {"message": "Cleanup completed", "results": results}


@router.get("/api/system/whitelist", tags=["System"])
async def get_ip_whitelist(_: AdminUser = Depends(get_current_user)):
    """Rate-limit whitelist and trusted proxies in effect."""
    from src.config import Config
    from src.middleware import RateLimiter

    limiter = RateLimiter.get_instance()
    sec = Config.get_security_config()
    return {
        "rate_limit": {"whitelist": list(limiter.config.whitelist) if limiter.config else []},
        "trusted_proxies": {"ips": sec.trusted_proxies},
    }
