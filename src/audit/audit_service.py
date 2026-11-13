"""Audit Log Service

Provides audit log recording and querying.
"""

import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi import Request

from db.models import AuditLog, local_now
from src.logging import get_logger
from src.utils.client_ip import resolve_client_ip
from src.utils.field_limits import clip


logger = get_logger("audit")


class AuditAction(str, Enum):
    """Audit action types"""
    # OAuth token
    TOKEN_ISSUE = "token_issue"
    TOKEN_REVOKE = "token_revoke"

    # OAuth client
    OAUTH_CLIENT_CREATE = "oauth_client_create"
    OAUTH_CLIENT_APPROVE = "oauth_client_approve"
    OAUTH_CLIENT_REVOKE = "oauth_client_revoke"
    OAUTH_CLIENT_DELETE = "oauth_client_delete"
    OAUTH_CLIENT_BIND = "oauth_client_bind"
    OAUTH_CONSENT_DELETE = "oauth_consent_delete"
    OAUTH_SCOPE_UPSERT = "oauth_scope_upsert"
    OAUTH_SCOPE_DELETE = "oauth_scope_delete"
    OAUTH_KEY_ROTATE = "oauth_key_rotate"
    OAUTH_KEY_ACTIVATE = "oauth_key_activate"
    OAUTH_KEY_REVOKE = "oauth_key_revoke"
    OAUTH_KEY_DELETE = "oauth_key_delete"
    OAUTH_CONSENT_APPROVE = "oauth_consent_approve"
    OAUTH_CONSENT_DENY = "oauth_consent_deny"
    OAUTH_CODE_REPLAY = "oauth_code_replay"
    OAUTH_REFRESH_REPLAY = "oauth_refresh_replay"
    OAUTH_CLIENT_AUTH_FAILED = "oauth_client_auth_failed"

    # Service operations
    CREATE_SERVICE = "create_service"
    DELETE_SERVICE = "delete_service"
    UPDATE_SERVICE = "update_service"

    # Admin-console accounts
    ADMIN_SETUP = "admin_setup"
    ADMIN_LOGIN = "admin_login"
    ADMIN_LOGOUT = "admin_logout"
    ADMIN_UPDATE = "admin_update"

    # System operations
    CLEANUP_EXPIRED = "cleanup_expired"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


class ResourceType(str, Enum):
    """Resource types"""
    TOKEN = "token"
    OAUTH_CLIENT = "oauth_client"
    OAUTH_CONSENT = "oauth_consent"
    OAUTH_SCOPE = "oauth_scope"
    SERVICE = "service"
    ADMIN = "admin"
    SYSTEM = "system"


class ActorType(str, Enum):
    """Actor types"""
    ADMIN = "admin"
    API = "api"
    SYSTEM = "system"


class AuditStatus(str, Enum):
    """Operation status"""
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


class AuditService:
    """Audit log service"""

    @staticmethod
    def log(
        db: Session,
        action: str,
        resource_type: str,
        status: str,
        resource_id: Optional[str] = None,
        actor_type: str = ActorType.API,
        actor_id: Optional[str] = None,
        actor_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None,
        request_method: Optional[str] = None,
        status_code: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Record an audit log entry.

        Several fields carry what a caller sent (the email of a failed login, a User-Agent, a path), so every
        bounded column is clipped to fit: an audit write must never fail the request it records.
        """
        fields = dict(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            request_method=request_method,
            status=status,
            status_code=status_code,
            error_message=error_message,
        )
        for name, value in fields.items():
            limit = getattr(AuditLog.__table__.c[name].type, "length", None)
            if limit and isinstance(value, str):
                fields[name] = clip(value, limit)
        audit_log = AuditLog(**fields, details=json.dumps(details) if details else None)
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        return audit_log

    @staticmethod
    def log_from_request(
        db: Session,
        request: Request,
        action: str,
        resource_type: str,
        status: str,
        resource_id: Optional[str] = None,
        actor_type: str = ActorType.API,
        actor_id: Optional[str] = None,
        actor_name: Optional[str] = None,
        status_code: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Record an audit log entry from a Request object"""
        # Forwarded headers count only when the direct peer is a trusted proxy (src.utils.client_ip):
        # otherwise anyone could write an arbitrary address into the audit trail.
        ip_address = resolve_client_ip(request)

        return AuditService.log(
            db=db,
            action=action,
            resource_type=resource_type,
            status=status,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            ip_address=ip_address,
            user_agent=request.headers.get("User-Agent", "")[:256],
            request_path=str(request.url.path)[:256],
            request_method=request.method,
            status_code=status_code,
            error_message=error_message,
            details=details,
        )

    @staticmethod
    def get_logs(
        db: Session,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        actor_name: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """Query audit logs"""
        query = db.query(AuditLog)

        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        if actor_name:
            query = query.filter(AuditLog.actor_name.ilike(f"%{actor_name}%"))
        if status:
            query = query.filter(AuditLog.status == status)
        if start_date:
            query = query.filter(AuditLog.created_at >= start_date)
        if end_date:
            query = query.filter(AuditLog.created_at <= end_date)

        return query.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit).all()

    @staticmethod
    def get_logs_count(
        db: Session,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        actor_name: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        """Get the audit log count"""
        query = db.query(AuditLog)

        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        if actor_name:
            query = query.filter(AuditLog.actor_name.ilike(f"%{actor_name}%"))
        if status:
            query = query.filter(AuditLog.status == status)
        if start_date:
            query = query.filter(AuditLog.created_at >= start_date)
        if end_date:
            query = query.filter(AuditLog.created_at <= end_date)

        return query.count()

    @staticmethod
    def get_stats(
        db: Session,
        days: int = 7,
    ) -> Dict[str, Any]:
        """Get audit log statistics"""
        start_date = local_now() - timedelta(days=days)

        # Count by action
        action_stats = {}
        logs = db.query(AuditLog).filter(AuditLog.created_at >= start_date).all()

        for log in logs:
            if log.action not in action_stats:
                action_stats[log.action] = {"total": 0, "success": 0, "failure": 0}
            action_stats[log.action]["total"] += 1
            if log.status == AuditStatus.SUCCESS:
                action_stats[log.action]["success"] += 1
            else:
                action_stats[log.action]["failure"] += 1

        # Total
        total = len(logs)
        success = sum(1 for log in logs if log.status == AuditStatus.SUCCESS)
        failure = total - success

        return {
            "period_days": days,
            "total": total,
            "success": success,
            "failure": failure,
            "success_rate": round(success / total * 100, 2) if total > 0 else 0,
            "by_action": action_stats,
        }

    @staticmethod
    def cleanup_old_logs(db: Session, days: int = 90) -> int:
        """Clean up old audit logs"""
        cutoff_date = local_now() - timedelta(days=days)
        deleted = db.query(AuditLog).filter(AuditLog.created_at < cutoff_date).delete()
        db.commit()
        return deleted


def record_oauth_event(db: Session, action: str, *, status: str = AuditStatus.SUCCESS,
                       resource_type: str = ResourceType.OAUTH_CLIENT, client_id: Optional[str] = None,
                       client_name: Optional[str] = None, ip_address: Optional[str] = None,
                       request_path: Optional[str] = None, error_message: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None) -> None:
    """Audit an event of the OAuth protocol surface, whose actor is a client (not a console user).

    Never raises: it runs next to protocol responses (often an error response that is already decided), and a
    failed audit write must not change what the client gets."""
    try:
        AuditService.log(
            db=db, action=action, resource_type=resource_type, status=status, resource_id=client_id,
            actor_type=ActorType.API, actor_id=client_id, actor_name=client_name, ip_address=ip_address,
            request_path=request_path, request_method="POST" if request_path else None,
            error_message=error_message, details=details,
        )
    except Exception as e:  # pragma: no cover - defensive
        db.rollback()
        logger.error(f"Failed to audit {action}: {e}")


def record_key_event(db: Session, action: "AuditAction", kid: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Audit what the scheduler's signing-key job did (system actor): an automatic rotation, a published key taking
    over, a retired key deleted. Never raises, like record_scheduled_purge."""
    try:
        AuditService.log(
            db=db, action=action, resource_type=ResourceType.SYSTEM, status=AuditStatus.SUCCESS, resource_id=kid,
            actor_type=ActorType.SYSTEM, actor_name="scheduler", details=details or {},
        )
    except Exception as e:  # pragma: no cover - defensive
        db.rollback()
        logger.error(f"Failed to audit signing key event {action} for {kid}: {e}")


def record_scheduled_purge(db: Session, target: str, deleted: int, details: Optional[Dict[str, Any]] = None) -> None:
    """Audit one scheduled purge run (system actor). No-op when nothing was deleted.

    Never raises: the purge itself has already been committed, and a failure to audit it must not make the
    scheduler report the run as failed.
    """
    if not deleted:
        return
    try:
        AuditService.log(
            db=db, action=AuditAction.CLEANUP_EXPIRED, resource_type=ResourceType.SYSTEM,
            status=AuditStatus.SUCCESS, resource_id=target, actor_type=ActorType.SYSTEM, actor_name="scheduler",
            details={"target": target, "deleted": deleted, **(details or {})},
        )
    except Exception as e:  # pragma: no cover - defensive
        db.rollback()
        logger.error(f"Failed to audit scheduled purge of {target}: {e}")
