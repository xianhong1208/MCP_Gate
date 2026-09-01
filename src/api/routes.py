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
    MCPToolInfo, RefreshToolsResponse, ServiceCreateRequest, ServiceHealthCheckResponse, ServiceHealthInfo,
    ServiceInfo, ServiceListResponse, ServiceUpdateRequest,
)
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.identity import get_current_user
from src.logging import get_logger
from src.scheduler import get_scheduler
from src.utils.crypto import encrypt_token
from src.version import __build_commit__, __build_time__, __version__

logger = get_logger("api")
router = APIRouter()


def _adapter_exc(e: AdapterError) -> HTTPException:
    return HTTPException(status_code=e.status_code, detail=e.to_detail())


def _tool_info(t) -> MCPToolInfo:
    return MCPToolInfo(
        id=str(t.id), name=t.name, description=t.description,
        input_schema=json.loads(t.input_schema) if t.input_schema else None,
        created_at=format_datetime(t.created_at),
    )


def _service_info(service: Service, include_tools: bool = False) -> ServiceInfo:
    data = service.to_dict(include_tools=False, include_health=True)
    data["health"] = ServiceHealthInfo(**data["health"])
    data["tools_count"] = len(service.tools)
    if include_tools:
        data["tools"] = [_tool_info(t) for t in service.tools]
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
    return HealthResponse(status="ok", service="mcp-center")


@router.get("/api/system/version", tags=["System"])
async def get_version():
    """Version and build information. Public."""
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
    items = [_service_info(s) for s in services]
    return ServiceListResponse(services=items, total_count=len(items))


@router.post("/api/services", response_model=ServiceInfo, status_code=201, tags=["Services"])
async def create_service(request: ServiceCreateRequest, http_request: Request, db: Session = Depends(get_db),
                         user: AdminUser = Depends(get_current_user)):
    """Register an MCP server. The audience defaults to its MCP URL unless `oauth_audience` is given."""
    try:
        service = ServiceAdapter.create_checked(
            db, name=request.name, description=request.description, host=request.host, port=request.port,
            protocol=request.protocol, mcp_path=request.mcp_path,
            auth_token_encrypted=encrypt_token(request.auth_token) if request.auth_token else None,
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
    return _service_info(service, include_tools=include_tools)


@router.put("/api/services/{service_id}", response_model=ServiceInfo, tags=["Services"])
async def update_service(service_id: str, request: ServiceUpdateRequest, http_request: Request,
                         db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Update an MCP server. Send `auth_token` as an empty string to clear a stored static bearer token."""
    auth_token_encrypted = None
    if request.auth_token is not None:
        auth_token_encrypted = encrypt_token(request.auth_token) if request.auth_token else ""
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
    """Delete an MCP server and its tool list and token events."""
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    name = service.name
    ServiceAdapter.delete(db, service_id)
    _audit(db, http_request, user, AuditAction.DELETE_SERVICE, ResourceType.SERVICE, service_id, {"name": name})
    return {"message": f"Service '{name}' deleted"}


# ==================== Tools / Health ====================

@router.get("/api/services/{service_id}/tools", tags=["Services"])
async def get_service_tools(service_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Tools last synced from the MCP server."""
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    tools = [_tool_info(t) for t in MCPToolAdapter.get_by_service(db, service_id)]
    return {"service_id": service_id, "service_name": service.name, "tools": tools, "count": len(tools)}


@router.post("/api/services/{service_id}/refresh-tools", response_model=RefreshToolsResponse, tags=["Services"])
async def refresh_service_tools(service_id: str, http_request: Request, db: Session = Depends(get_db),
                                user: AdminUser = Depends(get_current_user)):
    """Connect to the service, fetch its tools list and sync it.

    Services protected by MCP Center OAuth connect with a self-signed short-lived token.
    """
    from src.discovery.health_monitor import resolve_service_auth_token
    from src.discovery.scanner import get_scanner

    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    if not service.host or not service.port:
        raise HTTPException(status_code=400, detail={"error": "service.no_host_port",
                                                     "fallback": "Service has no host or port configured"})
    try:
        tools = await get_scanner().get_tools_list(
            host=service.host, port=service.port, path=service.mcp_path, protocol=service.protocol,
            auth_token=resolve_service_auth_token(db, service),
        )
    except PermissionError:
        raise HTTPException(status_code=502, detail={"error": "service.remote_permission_denied",
                                                     "fallback": "Permission denied by remote MCP service."})
    except Exception as e:
        logger.warning(f"refresh tools failed for {service.name}: {e}")
        raise HTTPException(status_code=502, detail={"error": "service.remote_unreachable",
                                                     "fallback": f"Could not reach MCP service: {e}"})
    MCPToolAdapter.sync_tools(db, service_id, [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools
    ])
    infos = [_tool_info(t) for t in MCPToolAdapter.get_by_service(db, service_id)]
    _audit(db, http_request, user, "refresh_tools", ResourceType.SERVICE, service_id,
           {"service_name": service.name, "tools_count": len(infos)})
    return RefreshToolsResponse(success=True, message=f"Refreshed {len(infos)} tools", tools_count=len(infos),
                                tools=infos)


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
    if result.success:
        new_status, error_message = "online", None
        # Refresh the description only for auto-discovered services (or when it is empty); a description
        # the operator wrote is theirs. The name is never touched.
        if result.server_name and result.server_name != "(requires auth)" \
                and (not service.description or service.source == "auto_discovered"):
            desc = result.server_description or f"{result.server_name}" + (
                f" v{result.server_version}" if result.server_version else "")
            ServiceAdapter.update(db, service_id, description=desc)
        ServiceAdapter.update_health(db, service_id, status=new_status, response_time_ms=result.response_time_ms,
                                     error_message=None, reset_fail_count=True)
    else:
        fail_count = (service.health_fail_count or 0) + 1
        new_status, error_message = ("offline" if fail_count >= 3 else "error"), result.error
        ServiceAdapter.update_health(db, service_id, status=new_status, response_time_ms=result.response_time_ms,
                                     error_message=error_message, increment_fail_count=True)
    return ServiceHealthCheckResponse(service_name=service.name, status=new_status,
                                      response_time_ms=result.response_time_ms, error_message=error_message,
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
    results = await get_scheduler().run_all_cleanup_now()
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
