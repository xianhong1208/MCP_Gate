"""Data access layer (pure CRUD, no HTTP / business rules). Only src/adapters may import this module."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload, selectinload

from db.models import (
    AdminUser, AuditLog, ManagedMcpProcess, MCPTool, OAuthAuthorizationCode,
    OAuthAuthorizationRequest, OAuthClient, OAuthConsent, OAuthScope, OAuthSigningKey,
    OAuthToken, Service, TokenUsage, UserMcpDefinition, local_now,
)

# Loopback aliases -> always stored / looked up as 127.0.0.1
_LOOPBACK_ALIASES = {"localhost", "0.0.0.0", "127.0.0.1", "::1", "[::1]"}


def normalize_service_host(host):
    if not host:
        return host
    return "127.0.0.1" if host.strip().lower() in _LOOPBACK_ALIASES else host


def normalize_audience(value: Optional[str]) -> Optional[str]:
    """Normalize a resource / audience: lowercase scheme+host, strip trailing slash, drop fragment."""
    if not value:
        return value
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(value.strip())
    except Exception:
        return value.strip()
    if not parts.scheme or not parts.netloc:
        return value.strip().rstrip("/")
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def _uuid(value) -> Optional[uuid.UUID]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


# ==================== Service ====================

class ServiceCRUD:

    @staticmethod
    def create(
        db: Session, name: str, description: Optional[str] = None,
        host: Optional[str] = None, port: Optional[int] = None, protocol: str = "http",
        mcp_path: str = "/mcp", auth_token_encrypted: Optional[str] = None,
        tags: Optional[List[str]] = None, source: str = "manual", requires_auth: bool = True,
        oauth_audience: Optional[str] = None, oauth_scopes: Optional[List[str]] = None,
    ) -> Service:
        service = Service(
            name=name, description=description, host=normalize_service_host(host), port=port,
            protocol=protocol, mcp_path=mcp_path, auth_token_encrypted=auth_token_encrypted,
            tags=",".join(tags) if tags else None, source=source, requires_auth=requires_auth,
            oauth_audience=normalize_audience(oauth_audience) or None,
            oauth_scopes=" ".join(oauth_scopes) if oauth_scopes else None,
        )
        db.add(service)
        db.commit()
        db.refresh(service)
        return service

    @staticmethod
    def get_by_host_port(db: Session, host: str, port: int) -> Optional[Service]:
        return db.query(Service).filter(
            Service.host == normalize_service_host(host), Service.port == port,
        ).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> Optional[Service]:
        return db.query(Service).filter(Service.name == name).first()

    @staticmethod
    def get_by_name_and_host_port(db: Session, name: str, host: str, port: int) -> Optional[Service]:
        return db.query(Service).filter(
            Service.name == name, Service.host == normalize_service_host(host), Service.port == port,
        ).first()

    @staticmethod
    def get_by_id(db: Session, service_id: str) -> Optional[Service]:
        sid = _uuid(service_id)
        if sid is None:
            return None
        return db.query(Service).filter(Service.id == sid).first()

    @staticmethod
    def get_by_audience(db: Session, audience: str) -> Optional[Service]:
        """Find a service by its effective audience (oauth_audience or MCP URL)."""
        target = normalize_audience(audience)
        if not target:
            return None
        # (1) An explicitly configured oauth_audience was normalized on write -> look it up directly via the index
        svc = db.query(Service).filter(Service.is_active.is_(True), Service.oauth_audience == target).first()
        if svc:
            return svc
        # (2) Services without oauth_audience use the MCP URL as audience: split host/port out of the URL, then compare
        from urllib.parse import urlsplit
        parts = urlsplit(target)
        if not parts.hostname or not parts.port:
            return None
        candidates = db.query(Service).filter(
            Service.is_active.is_(True), Service.oauth_audience.is_(None),
            Service.host == normalize_service_host(parts.hostname), Service.port == parts.port,
        ).all()
        for svc in candidates:
            if normalize_audience(svc.effective_audience) == target:
                return svc
        return None

    @staticmethod
    def get_all(
        db: Session, include_inactive: bool = False, health_status: Optional[str] = None,
        source: Optional[str] = None, tag: Optional[str] = None, requires_auth: Optional[bool] = None,
    ) -> List[Service]:
        # Eager-load tools: the list page shows the tool count, so avoid one query per row (N+1)
        query = db.query(Service).options(selectinload(Service.tools))
        if not include_inactive:
            query = query.filter(Service.is_active.is_(True))
        if health_status:
            query = query.filter(Service.health_status == health_status)
        if source:
            query = query.filter(Service.source == source)
        if tag:
            query = query.filter(Service.tags.contains(tag))
        if requires_auth is not None:
            query = query.filter(Service.requires_auth == requires_auth)
        return query.order_by(Service.name).all()

    @staticmethod
    def delete(db: Session, service_id: str) -> bool:
        service = ServiceCRUD.get_by_id(db, service_id)
        if not service:
            return False
        TokenUsageCRUD.delete_by_service_id(db, str(service.id))
        db.delete(service)
        db.commit()
        return True

    @staticmethod
    def update(
        db: Session, service_id: str, name: Optional[str] = None, description: Optional[str] = None,
        is_active: Optional[bool] = None, host: Optional[str] = None, port: Optional[int] = None,
        protocol: Optional[str] = None, mcp_path: Optional[str] = None,
        auth_token_encrypted: Optional[str] = None, tags: Optional[List[str]] = None,
        requires_auth: Optional[bool] = None, oauth_audience: Optional[str] = None,
        oauth_scopes: Optional[List[str]] = None,
    ) -> Optional[Service]:
        service = ServiceCRUD.get_by_id(db, service_id)
        if not service:
            return None
        if name is not None:
            service.name = name.replace(" ", "-").replace("/", "-")[:60]
        if description is not None:
            service.description = description
        if is_active is not None:
            service.is_active = is_active
        if host is not None:
            service.host = normalize_service_host(host)
        if port is not None:
            service.port = port
        if protocol is not None:
            service.protocol = protocol
        if mcp_path is not None:
            service.mcp_path = mcp_path
        if auth_token_encrypted is not None:
            service.auth_token_encrypted = auth_token_encrypted or None
        if tags is not None:
            service.tags = ",".join(tags) if tags else None
        if requires_auth is not None:
            service.requires_auth = requires_auth
        if oauth_audience is not None:
            service.oauth_audience = normalize_audience(oauth_audience) or None
        if oauth_scopes is not None:
            service.oauth_scopes = " ".join(oauth_scopes) if oauth_scopes else None
        db.commit()
        db.refresh(service)
        return service

    @staticmethod
    def update_health(
        db: Session, service_id: str, status: str, response_time_ms: Optional[float] = None,
        error_message: Optional[str] = None, increment_fail_count: bool = False,
        reset_fail_count: bool = False,
    ) -> Optional[Service]:
        service = ServiceCRUD.get_by_id(db, service_id)
        if not service:
            return None
        service.health_status = status
        service.health_last_checked = local_now()
        service.health_response_time_ms = response_time_ms
        service.health_error_message = error_message
        if reset_fail_count:
            service.health_fail_count = 0
        elif increment_fail_count:
            service.health_fail_count = (service.health_fail_count or 0) + 1
        db.commit()
        db.refresh(service)
        return service

    @staticmethod
    def get_services_for_health_check(db: Session) -> List[Service]:
        return db.query(Service).filter(
            Service.is_active.is_(True), Service.host.isnot(None), Service.port.isnot(None),
        ).all()


class MCPToolCRUD:

    @staticmethod
    def create(db: Session, service_id: str, name: str, description: Optional[str] = None,
               input_schema: Optional[str] = None) -> MCPTool:
        tool = MCPTool(service_id=_uuid(service_id), name=name, description=description, input_schema=input_schema)
        try:
            db.add(tool)
            db.commit()
            db.refresh(tool)
            return tool
        except IntegrityError:
            db.rollback()
            raise ValueError(f"Tool '{name}' already exists for this service")

    @staticmethod
    def get_by_service(db: Session, service_id: str) -> List[MCPTool]:
        return db.query(MCPTool).filter(MCPTool.service_id == _uuid(service_id)).all()

    @staticmethod
    def get_by_name(db: Session, service_id: str, name: str) -> Optional[MCPTool]:
        return db.query(MCPTool).filter(MCPTool.service_id == _uuid(service_id), MCPTool.name == name).first()

    @staticmethod
    def delete_by_service(db: Session, service_id: str) -> int:
        count = db.query(MCPTool).filter(MCPTool.service_id == _uuid(service_id)).delete()
        db.commit()
        return count

    @staticmethod
    def sync_tools(db: Session, service_id: str, tools: List[dict]) -> List[MCPTool]:
        sid = _uuid(service_id)
        db.query(MCPTool).filter(MCPTool.service_id == sid).delete()
        result = []
        for tool_data in tools:
            schema = tool_data.get("input_schema")
            tool = MCPTool(
                service_id=sid, name=tool_data["name"], description=tool_data.get("description"),
                input_schema=json.dumps(schema) if schema else None,
            )
            db.add(tool)
            result.append(tool)
        db.commit()
        for tool in result:
            db.refresh(tool)
        return result


# ==================== Token events / statistics ====================

class TokenUsageCRUD:
    """Token event stream. Statistics are bucketed in Python so SQLite and PostgreSQL behave identically."""

    @staticmethod
    def record(
        db: Session, *, event: str, jti: Optional[str] = None, grant_type: Optional[str] = None,
        client_id: Optional[str] = None, sub: Optional[str] = None, audience: Optional[str] = None,
        service_id: Optional[str] = None, success: bool = True, ip_address: Optional[str] = None,
    ) -> TokenUsage:
        usage = TokenUsage(
            event=event, jti=jti, grant_type=grant_type, client_id=client_id, sub=sub,
            audience=audience, service_id=_uuid(service_id), success=success, ip_address=ip_address,
        )
        db.add(usage)
        db.commit()
        return usage

    @staticmethod
    def _query(db: Session, since: datetime, service_id: Optional[str] = None,
               audience: Optional[str] = None, event: Optional[str] = None):
        q = db.query(TokenUsage).filter(TokenUsage.used_at >= since)
        if service_id:
            q = q.filter(TokenUsage.service_id == _uuid(service_id))
        elif audience:
            q = q.filter(TokenUsage.audience == audience)
        if event:
            q = q.filter(TokenUsage.event == event)
        return q

    @staticmethod
    def get_daily_stats(db: Session, days: int = 7, service_id: Optional[str] = None,
                        audience: Optional[str] = None, event: Optional[str] = None) -> List[dict]:
        # `days` calendar days including today, so days=7 yields exactly seven buckets
        end = local_now()
        start = (end - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        buckets: dict = {}
        for row in TokenUsageCRUD._query(db, start, service_id, audience, event).all():
            key = row.used_at.strftime("%Y-%m-%d")
            b = buckets.setdefault(key, {"total": 0, "success": 0})
            b["total"] += 1
            b["success"] += 1 if row.success else 0
        stats = []
        current = start.date()
        while current <= end.date():
            key = current.strftime("%Y-%m-%d")
            b = buckets.get(key, {"total": 0, "success": 0})
            stats.append({"date": key, "total": b["total"], "success": b["success"],
                          "failed": b["total"] - b["success"]})
            current += timedelta(days=1)
        return stats

    @staticmethod
    def get_hourly_stats(db: Session, hours: int = 24, service_id: Optional[str] = None,
                         audience: Optional[str] = None, event: Optional[str] = None) -> List[dict]:
        end = local_now()
        start = end - timedelta(hours=hours)
        buckets: dict = {}
        for row in TokenUsageCRUD._query(db, start, service_id, audience, event).all():
            key = row.used_at.replace(minute=0, second=0, microsecond=0)
            buckets[key] = buckets.get(key, 0) + 1
        stats = []
        current = start.replace(minute=0, second=0, microsecond=0)
        while current <= end:
            stats.append({"time": current.strftime("%Y-%m-%d %H:00"), "hour": current.strftime("%H:00"),
                          "total": buckets.get(current, 0)})
            current += timedelta(hours=1)
        return stats

    @staticmethod
    def get_service_stats(db: Session, days: int = 7) -> List[dict]:
        start = local_now() - timedelta(days=days)
        buckets: dict = {}
        for row in TokenUsageCRUD._query(db, start).all():
            key = row.audience or "-"
            b = buckets.setdefault(key, {"total": 0, "success": 0, "clients": set(), "service_id": None})
            b["total"] += 1
            b["success"] += 1 if row.success else 0
            if row.client_id:
                b["clients"].add(row.client_id)
            if row.service_id:
                b["service_id"] = str(row.service_id)
        return [
            {"audience": k, "service_id": v["service_id"], "total": v["total"], "success": v["success"],
             "failed": v["total"] - v["success"], "clients": len(v["clients"])}
            for k, v in sorted(buckets.items(), key=lambda kv: -kv[1]["total"])
        ]

    @staticmethod
    def get_total_count(db: Session, days: Optional[int] = None, event: Optional[str] = None) -> int:
        q = db.query(TokenUsage)
        if days:
            q = q.filter(TokenUsage.used_at >= local_now() - timedelta(days=days))
        if event:
            q = q.filter(TokenUsage.event == event)
        return q.count()

    @staticmethod
    def recent(db: Session, limit: int = 50) -> List[TokenUsage]:
        return db.query(TokenUsage).order_by(TokenUsage.used_at.desc()).limit(limit).all()

    @staticmethod
    def delete_by_service_id(db: Session, service_id: str) -> int:
        deleted = db.query(TokenUsage).filter(TokenUsage.service_id == _uuid(service_id)).delete(synchronize_session=False)
        db.commit()
        return deleted

    @staticmethod
    def delete_older_than(db: Session, cutoff: datetime) -> int:
        deleted = db.query(TokenUsage).filter(TokenUsage.used_at < cutoff).delete(synchronize_session=False)
        db.commit()
        return deleted


# ==================== Console users ====================

class AdminUserCRUD:

    @staticmethod
    def get_by_id(db: Session, user_id: str) -> Optional[AdminUser]:
        uid = _uuid(user_id)
        if uid is None:
            return None
        return db.query(AdminUser).filter(AdminUser.id == uid).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> Optional[AdminUser]:
        return db.query(AdminUser).filter(func.lower(AdminUser.email) == (email or "").lower()).first()

    @staticmethod
    def get_by_provider(db: Session, provider: str, sub: str) -> Optional[AdminUser]:
        return db.query(AdminUser).filter(
            AdminUser.auth_provider == provider, AdminUser.provider_sub == sub,
        ).first()

    @staticmethod
    def get_all(db: Session, include_inactive: bool = False) -> List[AdminUser]:
        q = db.query(AdminUser)
        if not include_inactive:
            q = q.filter(AdminUser.is_active.is_(True))
        return q.order_by(AdminUser.created_at).all()

    @staticmethod
    def get_count(db: Session, include_inactive: bool = False) -> int:
        q = db.query(AdminUser)
        if not include_inactive:
            q = q.filter(AdminUser.is_active.is_(True))
        return q.count()

    @staticmethod
    def create(db: Session, *, email: str, username: str, password_hash: Optional[str],
               auth_provider: str = "local", provider_sub: Optional[str] = None) -> AdminUser:
        user = AdminUser(
            email=email, username=username, password_hash=password_hash,
            auth_provider=auth_provider, provider_sub=provider_sub, is_active=True,
            password_changed_at=local_now() if password_hash else None,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise ValueError(f"Email '{email}' already exists")
        db.refresh(user)
        return user

    @staticmethod
    def set_password(db: Session, user: AdminUser, password_hash: str) -> AdminUser:
        user.password_hash = password_hash
        user.password_changed_at = local_now()
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def link_provider(db: Session, user: AdminUser, provider: str, sub: str) -> AdminUser:
        user.auth_provider = provider
        user.provider_sub = sub
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def touch_login(db: Session, user: AdminUser) -> None:
        user.last_login = local_now()
        db.commit()

    @staticmethod
    def update_profile(db: Session, user: AdminUser, *, username: str) -> AdminUser:
        user.username = username
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def set_active(db: Session, user: AdminUser, is_active: bool) -> AdminUser:
        user.is_active = is_active
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def delete(db: Session, user_id: str) -> bool:
        user = AdminUserCRUD.get_by_id(db, user_id)
        if not user:
            return False
        db.delete(user)
        db.commit()
        return True


# ==================== OAuth ====================

class OAuthSigningKeyCRUD:

    @staticmethod
    def get_active(db: Session) -> Optional[OAuthSigningKey]:
        return (db.query(OAuthSigningKey).filter(OAuthSigningKey.is_active.is_(True))
                .order_by(OAuthSigningKey.created_at.desc()).first())

    @staticmethod
    def get_by_kid(db: Session, kid: str) -> Optional[OAuthSigningKey]:
        return db.query(OAuthSigningKey).filter(OAuthSigningKey.kid == kid).first()

    @staticmethod
    def list_all(db: Session) -> List[OAuthSigningKey]:
        return db.query(OAuthSigningKey).order_by(OAuthSigningKey.created_at.desc()).all()

    @staticmethod
    def create(db: Session, *, kid: str, alg: str, public_jwk: str, private_pem_enc: str,
               make_active: bool = True) -> OAuthSigningKey:
        if make_active:
            for old in db.query(OAuthSigningKey).filter(OAuthSigningKey.is_active.is_(True)).all():
                old.is_active = False
                old.rotated_at = old.rotated_at or local_now()
        key = OAuthSigningKey(kid=kid, alg=alg, public_jwk=public_jwk,
                              private_pem_enc=private_pem_enc, is_active=make_active)
        db.add(key)
        db.commit()
        db.refresh(key)
        return key

    @staticmethod
    def delete(db: Session, kid: str) -> bool:
        key = OAuthSigningKeyCRUD.get_by_kid(db, kid)
        if not key:
            return False
        db.delete(key)
        db.commit()
        return True


class OAuthClientCRUD:

    @staticmethod
    def get(db: Session, client_id: str) -> Optional[OAuthClient]:
        return db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

    @staticmethod
    def list_all(db: Session, status: str = "all", include_system: bool = False) -> List[OAuthClient]:
        q = db.query(OAuthClient)
        if not include_system:
            q = q.filter(OAuthClient.created_via != "system")
        if status == "pending":
            q = q.filter(OAuthClient.is_approved.is_(False), OAuthClient.is_active.is_(True))
        elif status == "approved":
            q = q.filter(OAuthClient.is_approved.is_(True), OAuthClient.is_active.is_(True))
        elif status == "revoked":
            q = q.filter(OAuthClient.is_active.is_(False))
        return q.order_by(OAuthClient.created_at.desc()).all()

    @staticmethod
    def create(db: Session, **fields) -> OAuthClient:
        client = OAuthClient(**fields)
        db.add(client)
        db.commit()
        db.refresh(client)
        return client

    @staticmethod
    def save(db: Session, client: OAuthClient) -> OAuthClient:
        db.commit()
        db.refresh(client)
        return client

    @staticmethod
    def delete(db: Session, client_id: str) -> bool:
        client = OAuthClientCRUD.get(db, client_id)
        if not client:
            return False
        db.delete(client)
        db.commit()
        return True

    @staticmethod
    def touch(db: Session, client: OAuthClient) -> None:
        client.last_used_at = local_now()
        db.commit()


class OAuthAuthRequestCRUD:

    @staticmethod
    def create(db: Session, **fields) -> OAuthAuthorizationRequest:
        req = OAuthAuthorizationRequest(**fields)
        db.add(req)
        db.commit()
        db.refresh(req)
        return req

    @staticmethod
    def get(db: Session, request_id: str) -> Optional[OAuthAuthorizationRequest]:
        return (db.query(OAuthAuthorizationRequest).options(joinedload(OAuthAuthorizationRequest.client))
                .filter(OAuthAuthorizationRequest.id == request_id).first())

    @staticmethod
    def mark_decided(db: Session, req: OAuthAuthorizationRequest) -> None:
        req.decided_at = local_now()
        db.commit()

    @staticmethod
    def delete_expired(db: Session) -> int:
        deleted = db.query(OAuthAuthorizationRequest).filter(
            OAuthAuthorizationRequest.expires_at < local_now()
        ).delete(synchronize_session=False)
        db.commit()
        return deleted


class OAuthCodeCRUD:

    @staticmethod
    def create(db: Session, **fields) -> OAuthAuthorizationCode:
        code = OAuthAuthorizationCode(**fields)
        db.add(code)
        db.commit()
        return code

    @staticmethod
    def get_by_hash(db: Session, code_hash: str) -> Optional[OAuthAuthorizationCode]:
        return (db.query(OAuthAuthorizationCode).options(joinedload(OAuthAuthorizationCode.user))
                .filter(OAuthAuthorizationCode.code_hash == code_hash).first())

    @staticmethod
    def mark_used(db: Session, code: OAuthAuthorizationCode) -> None:
        code.used_at = local_now()
        db.commit()

    @staticmethod
    def delete_expired(db: Session) -> int:
        deleted = db.query(OAuthAuthorizationCode).filter(
            OAuthAuthorizationCode.expires_at < local_now() - timedelta(hours=1)
        ).delete(synchronize_session=False)
        db.commit()
        return deleted


class OAuthScopeCRUD:

    @staticmethod
    def list_all(db: Session) -> List[OAuthScope]:
        return db.query(OAuthScope).order_by(OAuthScope.name).all()

    @staticmethod
    def get(db: Session, name: str) -> Optional[OAuthScope]:
        return db.query(OAuthScope).filter(OAuthScope.name == name).first()

    @staticmethod
    def upsert(db: Session, *, name: str, description: Optional[str], is_default: bool) -> OAuthScope:
        scope = OAuthScopeCRUD.get(db, name)
        if scope is None:
            scope = OAuthScope(name=name)
            db.add(scope)
        scope.description = description
        scope.is_default = is_default
        db.commit()
        db.refresh(scope)
        return scope

    @staticmethod
    def delete(db: Session, name: str) -> bool:
        scope = OAuthScopeCRUD.get(db, name)
        if not scope:
            return False
        db.delete(scope)
        db.commit()
        return True


class OAuthTokenCRUD:

    @staticmethod
    def create(db: Session, **fields) -> OAuthToken:
        if fields.get("client_id") and not fields.get("client_name_snapshot"):
            client = db.query(OAuthClient).filter(OAuthClient.client_id == fields["client_id"]).first()
            if client:
                fields["client_name_snapshot"] = client.client_name
        token = OAuthToken(**fields)
        db.add(token)
        db.commit()
        db.refresh(token)
        return token

    @staticmethod
    def get(db: Session, jti: str) -> Optional[OAuthToken]:
        return (db.query(OAuthToken)
                .options(joinedload(OAuthToken.client), joinedload(OAuthToken.user), joinedload(OAuthToken.service))
                .filter(OAuthToken.jti == jti).first())

    @staticmethod
    def list_all(
        db: Session, *, kind: Optional[str] = None, client_id: Optional[str] = None,
        service_id: Optional[str] = None, user_id: Optional[str] = None,
        include_inactive: bool = False, limit: int = 200,
    ) -> List[OAuthToken]:
        q = (db.query(OAuthToken)
             .options(joinedload(OAuthToken.client), joinedload(OAuthToken.user), joinedload(OAuthToken.service)))
        if kind:
            q = q.filter(OAuthToken.kind == kind)
        if client_id:
            q = q.filter(OAuthToken.client_id == client_id)
        if service_id:
            q = q.filter(OAuthToken.service_id == _uuid(service_id))
        if user_id:
            q = q.filter(OAuthToken.user_id == _uuid(user_id))
        if not include_inactive:
            q = q.filter(OAuthToken.revoked_at.is_(None), OAuthToken.expires_at >= local_now())
        return q.order_by(OAuthToken.issued_at.desc()).limit(limit).all()

    @staticmethod
    def revoke(db: Session, token: OAuthToken, reason: str = "revoked") -> OAuthToken:
        if token.revoked_at is None:
            token.revoked_at = local_now()
            token.revoke_reason = reason
            db.commit()
        return token

    @staticmethod
    def revoke_family(db: Session, parent_jti: str, reason: str) -> int:
        """Revoke every still-valid token on the same grant chain (same parent_jti)."""
        now = local_now()
        count = 0
        for t in db.query(OAuthToken).filter(
            or_(OAuthToken.parent_jti == parent_jti, OAuthToken.jti == parent_jti),
            OAuthToken.revoked_at.is_(None),
        ).all():
            t.revoked_at = now
            t.revoke_reason = reason
            count += 1
        db.commit()
        return count

    @staticmethod
    def revoke_by_client(db: Session, client_id: str, reason: str = "client_revoked") -> int:
        now = local_now()
        count = 0
        for t in db.query(OAuthToken).filter(
            OAuthToken.client_id == client_id, OAuthToken.revoked_at.is_(None),
        ).all():
            t.revoked_at = now
            t.revoke_reason = reason
            count += 1
        db.commit()
        return count

    @staticmethod
    def touch(db: Session, token: OAuthToken, ip: Optional[str]) -> None:
        token.last_used_at = local_now()
        token.last_used_ip = ip
        token.use_count = (token.use_count or 0) + 1
        db.commit()

    @staticmethod
    def delete_expired(db: Session, grace: timedelta = timedelta(days=7)) -> int:
        deleted = db.query(OAuthToken).filter(
            OAuthToken.expires_at < local_now() - grace
        ).delete(synchronize_session=False)
        db.commit()
        return deleted

    @staticmethod
    def count_active(db: Session, kind: Optional[str] = None) -> int:
        q = db.query(OAuthToken).filter(OAuthToken.revoked_at.is_(None), OAuthToken.expires_at >= local_now())
        if kind:
            q = q.filter(OAuthToken.kind == kind)
        return q.count()


class OAuthConsentCRUD:

    @staticmethod
    def get(db: Session, user_id, client_id: str, audience: Optional[str]) -> Optional[OAuthConsent]:
        return db.query(OAuthConsent).filter(
            OAuthConsent.user_id == _uuid(user_id),
            OAuthConsent.client_id == client_id,
            OAuthConsent.audience == audience,
        ).first()

    @staticmethod
    def upsert(db: Session, user_id, client_id: str, audience: Optional[str], scope: str) -> OAuthConsent:
        consent = OAuthConsentCRUD.get(db, user_id, client_id, audience)
        if consent is None:
            consent = OAuthConsent(user_id=_uuid(user_id), client_id=client_id, audience=audience)
            db.add(consent)
        merged = set((consent.scope or "").split()) | set((scope or "").split())
        consent.scope = " ".join(sorted(merged))
        consent.granted_at = local_now()
        db.commit()
        db.refresh(consent)
        return consent

    @staticmethod
    def list_for_user(db: Session, user_id) -> List[OAuthConsent]:
        return (db.query(OAuthConsent).options(joinedload(OAuthConsent.client))
                .filter(OAuthConsent.user_id == _uuid(user_id))
                .order_by(OAuthConsent.granted_at.desc()).all())

    @staticmethod
    def delete(db: Session, consent_id: str) -> bool:
        consent = db.query(OAuthConsent).filter(OAuthConsent.id == _uuid(consent_id)).first()
        if not consent:
            return False
        db.delete(consent)
        db.commit()
        return True


# ==================== Managed / BYO MCP ====================

class ManagedMcpProcessCRUD:
    """Encryption boundary: create / update_env_vars accept plaintext env_vars and encrypt them before storing;
    decryption happens only in ManagedMcpProcess.get_env_vars() (used by the orchestrator to start containers)."""

    @staticmethod
    def _encrypt_env_vars(env_vars):
        if not env_vars:
            return None
        from src.utils.crypto import encrypt_token
        return encrypt_token(json.dumps(env_vars))

    @staticmethod
    def create(
        db: Session, name: str, catalog_id: str, docker_image: str, image_args: Optional[str] = None,
        image_command: Optional[list] = None, env_vars: Optional[dict] = None,
        port: Optional[int] = None, created_by: Optional[str] = None,
    ) -> ManagedMcpProcess:
        process = ManagedMcpProcess(
            name=name, catalog_id=catalog_id, docker_image=docker_image, image_args=image_args,
            image_command=json.dumps(image_command) if image_command else None,
            env_vars_encrypted=ManagedMcpProcessCRUD._encrypt_env_vars(env_vars),
            port=port, auto_port=(port is None), desired_state="stopped", actual_state="unknown",
            created_by=_uuid(created_by),
        )
        db.add(process)
        db.commit()
        db.refresh(process)
        return process

    @staticmethod
    def get_by_id(db: Session, process_id: str) -> Optional[ManagedMcpProcess]:
        pid = _uuid(process_id)
        if pid is None:
            return None
        return db.query(ManagedMcpProcess).filter(ManagedMcpProcess.id == pid).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> Optional[ManagedMcpProcess]:
        return db.query(ManagedMcpProcess).filter(ManagedMcpProcess.name == name).first()

    @staticmethod
    def list_all(db: Session, catalog_id: Optional[str] = None, desired_state: Optional[str] = None,
                 actual_state: Optional[str] = None) -> List[ManagedMcpProcess]:
        query = db.query(ManagedMcpProcess)
        if catalog_id:
            query = query.filter(ManagedMcpProcess.catalog_id == catalog_id)
        if desired_state:
            query = query.filter(ManagedMcpProcess.desired_state == desired_state)
        if actual_state:
            query = query.filter(ManagedMcpProcess.actual_state == actual_state)
        return query.order_by(ManagedMcpProcess.name).all()

    @staticmethod
    def update_env_vars(db: Session, process_id: str, env_vars: Optional[dict]) -> Optional[ManagedMcpProcess]:
        process = ManagedMcpProcessCRUD.get_by_id(db, process_id)
        if not process:
            return None
        process.env_vars_encrypted = ManagedMcpProcessCRUD._encrypt_env_vars(env_vars)
        db.commit()
        db.refresh(process)
        return process

    @staticmethod
    def update_state(
        db: Session, process_id: str, actual_state: Optional[str] = None, container_id: Optional[str] = None,
        bridge_container_id: Optional[str] = None, port: Optional[int] = None,
        last_error: Optional[str] = None, service_id: Optional[str] = None,
    ) -> Optional[ManagedMcpProcess]:
        """None = leave unchanged; pass an empty string to clear container_id / bridge_container_id / last_error;
        pass 0 to clear port."""
        process = ManagedMcpProcessCRUD.get_by_id(db, process_id)
        if not process:
            return None
        if actual_state is not None:
            process.actual_state = actual_state
        if container_id is not None:
            process.container_id = container_id or None
        if bridge_container_id is not None:
            process.bridge_container_id = bridge_container_id or None
        if port is not None:
            process.port = port if port > 0 else None
        if last_error is not None:
            process.last_error = last_error or None
        if service_id is not None:
            process.service_id = _uuid(service_id) if service_id else None
        db.commit()
        db.refresh(process)
        return process

    @staticmethod
    def set_desired_state(db: Session, process_id: str, desired_state: str) -> Optional[ManagedMcpProcess]:
        if desired_state not in ("running", "stopped"):
            raise ValueError(f"Invalid desired_state: {desired_state}")
        process = ManagedMcpProcessCRUD.get_by_id(db, process_id)
        if not process:
            return None
        process.desired_state = desired_state
        db.commit()
        db.refresh(process)
        return process

    @staticmethod
    def append_log_lines(db: Session, process_id: str, new_lines: List[str],
                         max_lines: int = 200) -> Optional[ManagedMcpProcess]:
        process = ManagedMcpProcessCRUD.get_by_id(db, process_id)
        if not process:
            return None
        existing = process.last_log_lines.split("\n") if process.last_log_lines else []
        process.last_log_lines = "\n".join((existing + new_lines)[-max_lines:])
        db.commit()
        db.refresh(process)
        return process

    @staticmethod
    def delete(db: Session, process_id: str) -> bool:
        process = ManagedMcpProcessCRUD.get_by_id(db, process_id)
        if not process:
            return False
        db.delete(process)
        db.commit()
        return True


class UserMcpDefinitionCRUD:

    @staticmethod
    def create(
        db: Session, name: str, command: str, args: Optional[list] = None, container_port: int = 8000,
        env_schema: Optional[list] = None, description: Optional[str] = None,
        created_by_id: Optional[str] = None,
    ) -> UserMcpDefinition:
        obj = UserMcpDefinition(
            name=name, command=command, args_json=json.dumps(args or []), container_port=container_port,
            env_schema_json=json.dumps(env_schema or []), description=description,
            created_by_id=_uuid(created_by_id),
        )
        db.add(obj)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise ValueError(f"MCP definition '{name}' already exists")
        db.refresh(obj)
        return obj

    @staticmethod
    def get_by_id(db: Session, definition_id: str) -> Optional[UserMcpDefinition]:
        did = _uuid(definition_id)
        if did is None:
            return None
        return db.query(UserMcpDefinition).filter(UserMcpDefinition.id == did).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> Optional[UserMcpDefinition]:
        return db.query(UserMcpDefinition).filter(UserMcpDefinition.name == name).first()

    @staticmethod
    def list_all(db: Session) -> list:
        return db.query(UserMcpDefinition).order_by(UserMcpDefinition.created_at.desc()).all()

    @staticmethod
    def delete(db: Session, definition_id: str) -> bool:
        obj = UserMcpDefinitionCRUD.get_by_id(db, definition_id)
        if not obj:
            return False
        db.delete(obj)
        db.commit()
        return True


# ==================== Audit ====================

class AuditLogCRUD:

    @staticmethod
    def delete_older_than(db: Session, cutoff: datetime) -> int:
        deleted = db.query(AuditLog).filter(AuditLog.created_at < cutoff).delete(synchronize_session=False)
        db.commit()
        return deleted
