"""Admin-console OAuth management API (/api/oauth/*, login required).

clients / scopes / tokens (incl. Personal Access Tokens) / consents / signing keys / activity / integration snippets.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser
from src.adapters import (
    OAuthClientAdapter, OAuthConsentAdapter, OAuthKeyAdapter, OAuthScopeAdapter, OAuthTokenAdapter,
    ServiceAdapter, TokenUsageAdapter,
)
from src.adapters.exceptions import AdapterError
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.config import Config
from src.identity import get_current_user
from src.oauth import service as oauth
from src.oauth import signing_keys
from src.oauth.errors import OAuthError

router = APIRouter(prefix="/api/oauth", tags=["OAuth Admin"])


def _adapter_exc(e: AdapterError) -> HTTPException:
    return HTTPException(status_code=e.status_code, detail=e.to_detail())


def _oauth_exc(e: OAuthError) -> HTTPException:
    return HTTPException(status_code=e.status_code, detail={"error": f"oauth.{e.error}", "fallback": e.description})


def _audit(db, request, user, action, resource_type, resource_id, details=None):
    AuditService.log_from_request(
        db=db, request=request, action=action, resource_type=resource_type, status=AuditStatus.SUCCESS,
        actor_type=ActorType.ADMIN, actor_id=str(user.id), actor_name=user.audit_name,
        resource_id=resource_id, details=details,
    )


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------
class ClientCreateRequest(BaseModel):
    client_name: str
    redirect_uris: List[str] = []
    grant_types: List[str] = ["authorization_code", "refresh_token"]
    token_endpoint_auth_method: str = "none"
    scope: Optional[str] = None
    client_uri: Optional[str] = None
    # Classic-client compatibility (confidential clients only): skip PKCE / assume a resource when absent
    require_pkce: bool = True
    default_resource: Optional[str] = None


@router.get("/clients")
async def list_clients(status: str = Query("all"), db: Session = Depends(get_db),
                       _: AdminUser = Depends(get_current_user)):
    """List OAuth clients. `status` = all | approved | pending | revoked."""
    clients = OAuthClientAdapter.list_all(db, status=status)
    return {"clients": [c.to_dict() for c in clients], "total": len(clients)}


@router.post("/clients", status_code=201)
async def create_client(body: ClientCreateRequest, request: Request, db: Session = Depends(get_db),
                        user: AdminUser = Depends(get_current_user)):
    """Manually register a trusted client from the admin console (auto-approved, consent page skipped). The secret is
    returned only once."""
    try:
        client, secret = oauth.register_client(db, body.model_dump(), created_via="manual",
                                               is_approved=True, owner_id=user.id)
    except OAuthError as e:
        raise _oauth_exc(e)
    _audit(db, request, user, AuditAction.OAUTH_CLIENT_CREATE, ResourceType.OAUTH_CLIENT, client.client_id)
    return oauth.registration_response(client, secret)


@router.get("/clients/{client_id}")
async def get_client(client_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """One client with its count of active tokens."""
    try:
        client = OAuthClientAdapter.get_existing(db, client_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    data = client.to_dict()
    data["active_tokens"] = len(OAuthTokenAdapter.list_all(db, client_id=client_id))
    return data


@router.post("/clients/{client_id}/approve")
async def approve_client(client_id: str, request: Request, db: Session = Depends(get_db),
                         user: AdminUser = Depends(get_current_user)):
    """Approve a dynamically registered client (only needed when OAUTH_DCR_AUTO_APPROVE=false)."""
    try:
        client = OAuthClientAdapter.get_existing(db, client_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    client.is_approved = True
    client.is_active = True
    OAuthClientAdapter.save(db, client)
    _audit(db, request, user, AuditAction.OAUTH_CLIENT_APPROVE, ResourceType.OAUTH_CLIENT, client_id)
    return client.to_dict()


@router.post("/clients/{client_id}/revoke")
async def revoke_client(client_id: str, request: Request, db: Session = Depends(get_db),
                        user: AdminUser = Depends(get_current_user)):
    """Deactivate the client and revoke all of its tokens."""
    try:
        client = OAuthClientAdapter.get_existing(db, client_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    if client.created_via == "system":
        raise HTTPException(status_code=400, detail={"error": "oauth.system_client", "fallback": "Built-in client"})
    client.is_active = False
    OAuthClientAdapter.save(db, client)
    revoked = OAuthTokenAdapter.revoke_by_client(db, client_id)
    _audit(db, request, user, AuditAction.OAUTH_CLIENT_REVOKE, ResourceType.OAUTH_CLIENT, client_id,
           {"tokens_revoked": revoked})
    return {**client.to_dict(), "tokens_revoked": revoked}


@router.delete("/clients/{client_id}")
async def delete_client(client_id: str, request: Request, db: Session = Depends(get_db),
                        user: AdminUser = Depends(get_current_user)):
    """Delete a client. Its token history is kept with the client name snapshotted; its remembered consents are removed."""
    try:
        client = OAuthClientAdapter.get_existing(db, client_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    if client.created_via == "system":
        raise HTTPException(status_code=400, detail={"error": "oauth.system_client", "fallback": "Built-in client"})
    OAuthClientAdapter.delete(db, client_id)
    _audit(db, request, user, AuditAction.OAUTH_CLIENT_DELETE, ResourceType.OAUTH_CLIENT, client_id)
    return {"message": "Client deleted"}


# ---------------------------------------------------------------------------
# scopes
# ---------------------------------------------------------------------------
class ScopeUpsertRequest(BaseModel):
    description: Optional[str] = None
    is_default: bool = False


@router.get("/scopes")
async def list_scopes(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """The scope registry (what tokens may be granted)."""
    scopes = OAuthScopeAdapter.list_all(db)
    return {"scopes": [s.to_dict() for s in scopes], "total": len(scopes)}


@router.put("/scopes/{name}")
async def upsert_scope(name: str, body: ScopeUpsertRequest, db: Session = Depends(get_db),
                       _: AdminUser = Depends(get_current_user)):
    """Create or update a scope and whether it is granted by default."""
    name = name.strip()
    if not name or " " in name:
        raise HTTPException(status_code=400, detail={"error": "oauth.invalid_scope_name", "fallback": "Invalid scope name"})
    return OAuthScopeAdapter.upsert(db, name=name, description=body.description, is_default=body.is_default).to_dict()


@router.delete("/scopes/{name}")
async def delete_scope(name: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Delete a scope from the registry."""
    if not OAuthScopeAdapter.delete(db, name):
        raise HTTPException(status_code=404, detail={"error": "oauth.scope_not_found", "fallback": "Scope not found"})
    return {"message": "Scope deleted"}


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------
class PersonalTokenRequest(BaseModel):
    service_id: str
    scopes: Optional[List[str]] = None
    expires_days: int = Field(30, ge=1)
    label: Optional[str] = None


@router.get("/tokens")
async def list_tokens(kind: Optional[str] = None, service_id: Optional[str] = None, client_id: Optional[str] = None,
                      include_inactive: bool = False, limit: int = Query(200, ge=1, le=1000),
                      db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Tokens issued by MCP Center. Filter by kind (access | refresh | pat), service, client; `include_inactive` adds revoked and expired ones."""
    tokens = OAuthTokenAdapter.list_all(db, kind=kind, service_id=service_id, client_id=client_id,
                                        include_inactive=include_inactive, limit=limit)
    return {"tokens": [t.to_dict() for t in tokens], "total": len(tokens)}


@router.post("/tokens/personal", status_code=201)
async def create_personal_token(body: PersonalTokenRequest, request: Request, db: Session = Depends(get_db),
                                user: AdminUser = Depends(get_current_user)):
    """Issue a Personal Access Token: paste it into the MCP client's Authorization: Bearer setting. The plaintext is
    returned only once."""
    try:
        service = ServiceAdapter.get_existing(db, body.service_id)
        jwt_value, rec = oauth.mint_personal_token(db, user=user, service=service, scopes=body.scopes,
                                                   days=body.expires_days, label=body.label)
    except AdapterError as e:
        raise _adapter_exc(e)
    except OAuthError as e:
        raise _oauth_exc(e)
    _audit(db, request, user, AuditAction.TOKEN_ISSUE, ResourceType.TOKEN, rec.jti,
           {"service": service.name, "scope": rec.scope, "days": body.expires_days})
    return {"access_token": jwt_value, "token_type": "Bearer", **rec.to_dict()}


@router.get("/tokens/{jti}")
async def get_token(jti: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """One token record (never the token value)."""
    try:
        return OAuthTokenAdapter.get_existing(db, jti).to_dict()
    except AdapterError as e:
        raise _adapter_exc(e)


@router.post("/tokens/{jti}/revoke")
async def revoke_token(jti: str, request: Request, db: Session = Depends(get_db),
                       user: AdminUser = Depends(get_current_user)):
    """Revoke a token. Revoking a refresh token revokes the access tokens derived from it."""
    try:
        rec = OAuthTokenAdapter.get_existing(db, jti)
    except AdapterError as e:
        raise _adapter_exc(e)
    OAuthTokenAdapter.revoke(db, rec, reason="admin_revoke")
    if rec.kind == "refresh":
        OAuthTokenAdapter.revoke_family(db, rec.parent_jti or rec.jti, reason="admin_revoke")
    _audit(db, request, user, AuditAction.TOKEN_REVOKE, ResourceType.TOKEN, jti)
    return rec.to_dict()


# ---------------------------------------------------------------------------
# consents
# ---------------------------------------------------------------------------
@router.get("/consents")
async def list_consents(db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Consents the signed-in owner has remembered (client + server + scopes)."""
    consents = OAuthConsentAdapter.list_for_user(db, user.id)
    return {"consents": [c.to_dict() for c in consents], "total": len(consents)}


@router.delete("/consents/{consent_id}")
async def delete_consent(consent_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Forget a remembered consent; the client will ask again next time."""
    if not OAuthConsentAdapter.delete(db, consent_id):
        raise HTTPException(status_code=404, detail={"error": "oauth.consent_not_found", "fallback": "Consent not found"})
    return {"message": "Consent removed"}


# ---------------------------------------------------------------------------
# signing keys
# ---------------------------------------------------------------------------
@router.get("/keys")
async def list_keys(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Signing keys published in JWKS, with the active one marked."""
    keys = OAuthKeyAdapter.list_all(db)
    return {"keys": [k.to_dict() for k in keys], "total": len(keys)}


@router.post("/keys/rotate")
async def rotate_key(request: Request, db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Create a new active signing key. Old keys stay in JWKS so existing tokens keep verifying."""
    key = signing_keys.rotate_signing_key(db)
    _audit(db, request, user, AuditAction.OAUTH_KEY_ROTATE, ResourceType.SYSTEM, key.kid)
    return key.to_dict()


# ---------------------------------------------------------------------------
# activity / overview
# ---------------------------------------------------------------------------
@router.get("/activity")
async def activity(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db),
                   _: AdminUser = Depends(get_current_user)):
    """Recent token events: issued, introspected, revoked."""
    rows = TokenUsageAdapter.recent(db, limit=limit)
    return {"events": [{
        "at": r.used_at.isoformat() if r.used_at else None,
        "event": r.event, "grant_type": r.grant_type, "client_id": r.client_id, "sub": r.sub,
        "audience": r.audience, "service_id": str(r.service_id) if r.service_id else None,
        "success": bool(r.success), "ip": r.ip_address,
    } for r in rows]}


@router.get("/overview")
async def overview(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Counts for the dashboard: clients, active tokens, tokens issued in the last day and week."""
    return {
        "issuer": oauth.issuer(),
        "clients": len(OAuthClientAdapter.list_all(db, status="approved")),
        "pending_clients": len(OAuthClientAdapter.list_all(db, status="pending")),
        "active_access_tokens": OAuthTokenAdapter.count_active(db, kind="access"),
        "active_pats": OAuthTokenAdapter.count_active(db, kind="pat"),
        "active_refresh_tokens": OAuthTokenAdapter.count_active(db, kind="refresh"),
        "issued_24h": TokenUsageAdapter.get_total_count(db, days=1, event="issued"),
        "issued_7d": TokenUsageAdapter.get_total_count(db, days=7, event="issued"),
        "dcr_auto_approve": Config.get_oauth_config().dcr_auto_approve,
    }


# ---------------------------------------------------------------------------
# Integration snippets (FastMCP server / MCP client configuration)
# ---------------------------------------------------------------------------
@router.get("/snippets/{service_id}")
async def integration_snippets(service_id: str, db: Session = Depends(get_db),
                               _: AdminUser = Depends(get_current_user)):
    """Ready-to-paste FastMCP server, FastMCP client, Claude Code and mcpServers JSON snippets for one MCP server."""
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    base = oauth.issuer()
    audience = service.effective_audience or "<your-mcp-server-url>"
    mcp_url = service.get_mcp_url() or audience
    fastmcp_server = f'''from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

auth = RemoteAuthProvider(
    token_verifier=JWTVerifier(
        jwks_uri="{base}/.well-known/jwks.json",
        issuer="{base}",
        audience="{audience}",
    ),
    authorization_servers=[AnyHttpUrl("{base}")],
    base_url="{audience}",
)

mcp = FastMCP(name="{service.name}", auth=auth)


@mcp.tool
def hello(name: str) -> str:
    return f"Hello, {{name}}!"


if __name__ == "__main__":
    mcp.run(transport="http", host="{service.host or '127.0.0.1'}", port={service.port or 8000})
'''
    claude_code = f'claude mcp add --transport http {service.name} {mcp_url}'
    claude_code_pat = (f'claude mcp add --transport http {service.name} {mcp_url} '
                       f'--header "Authorization: Bearer <PERSONAL_ACCESS_TOKEN>"')
    mcp_json = {"mcpServers": {service.name: {"type": "http", "url": mcp_url}}}
    mcp_json_pat = {"mcpServers": {service.name: {"type": "http", "url": mcp_url,
                                                   "headers": {"Authorization": "Bearer <PERSONAL_ACCESS_TOKEN>"}}}}
    fastmcp_client = f'''from fastmcp import Client

async with Client("{mcp_url}", auth="oauth") as client:
    print(await client.list_tools())
'''
    return {
        "issuer": base,
        "audience": audience,
        "mcp_url": mcp_url,
        "fastmcp_server": fastmcp_server,
        "fastmcp_client": fastmcp_client,
        "claude_code_oauth": claude_code,
        "claude_code_pat": claude_code_pat,
        "mcp_json_oauth": mcp_json,
        "mcp_json_pat": mcp_json_pat,
    }
