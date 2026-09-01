"""OAuth 2.1 Authorization Server core logic (HTTP-agnostic).

- client registration (RFC 7591) / authentication / redirect_uri allowlist
- resource (RFC 8707) -> audience binding to a registered MCP server
- authorization request -> consent -> authorization code (stored hashed, single-use, short TTL, PKCE S256)
- access / refresh token issuance (RS256, with iss/aud/scope/client_id/jti) and record keeping
- refresh rotation + replay detection, revocation (RFC 7009), introspection (RFC 7662)
- admin-console Personal Access Tokens, scanner self-signed tokens
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Iterable, Optional
from urllib.parse import urlencode, urlparse

from sqlalchemy.orm import Session

from db.models import (
    AdminUser, OAuthAuthorizationCode, OAuthAuthorizationRequest, OAuthClient, OAuthToken, Service, local_now,
)
from db.seed import CONSOLE_CLIENT_ID, SCANNER_CLIENT_ID
from src.adapters import (
    OAuthAuthRequestAdapter, OAuthClientAdapter, OAuthCodeAdapter, OAuthConsentAdapter, OAuthScopeAdapter,
    OAuthTokenAdapter, ServiceAdapter, TokenUsageAdapter, normalize_audience,
)
from src.config import Config
from src.oauth import signing_keys
from src.oauth.consent_policy import should_skip_consent
from src.oauth.errors import OAuthError
from src.oauth.jwt_utils import JWTVerifyError, decode_rs256, sign_rs256, unverified_header
from src.utils.crypto import hash_token

SERVER_GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"]
SERVER_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
CODE_CHALLENGE_METHOD = "S256"
AUTH_REQUEST_TTL = timedelta(minutes=10)
SCANNER_TOKEN_TTL_SECONDS = 120
DEFAULT_SCANNER_SCOPES = "mcp:tools:read mcp:tools:invoke mcp:resources:read mcp:prompts:read"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def issuer() -> str:
    return Config.get_oauth_config().issuer.rstrip("/")


def _now_ts() -> int:
    return int(local_now().timestamp())


def _exp_to_dt(exp: Optional[int]) -> datetime:
    return datetime.fromtimestamp(exp) if exp else local_now()


def _valid_redirect_uri(uri: str) -> bool:
    """Must be an absolute URL; http is only allowed for loopback (native / dev clients), everything else must be
    https or a custom scheme."""
    try:
        p = urlparse(uri)
    except Exception:
        return False
    if not p.scheme:
        return False
    if p.scheme == "https":
        return bool(p.netloc)
    if p.scheme == "http":
        return (p.hostname or "").lower() in ("localhost", "127.0.0.1", "::1")
    # Custom schemes (e.g. cursor://, claude://) are for desktop apps
    return p.scheme not in ("javascript", "data", "file")


def redirect_with(base: str, params: dict) -> str:
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode({k: v for k, v in params.items() if v is not None})}"


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------
def generate_client_id() -> str:
    return "mcpc_" + secrets.token_hex(12)


def register_client(
    db: Session, metadata: dict, *, created_via: str = "dcr", is_approved: Optional[bool] = None,
    owner_id=None,
) -> tuple[OAuthClient, Optional[str]]:
    """Validate metadata per RFC 7591 and create the client; a confidential client's secret is returned only once."""
    if not isinstance(metadata, dict):
        raise OAuthError("invalid_client_metadata", "client metadata must be a JSON object")
    client_name = (metadata.get("client_name") or "").strip()
    if not client_name:
        client_name = "Unnamed MCP client"

    grant_types = metadata.get("grant_types") or ["authorization_code", "refresh_token"]
    if not isinstance(grant_types, list):
        raise OAuthError("invalid_client_metadata", "grant_types must be an array")
    unsupported = set(grant_types) - set(SERVER_GRANT_TYPES)
    if unsupported:
        raise OAuthError("invalid_client_metadata", f"unsupported grant_types: {' '.join(sorted(unsupported))}")

    auth_method = metadata.get("token_endpoint_auth_method") or "none"
    if auth_method not in SERVER_AUTH_METHODS:
        raise OAuthError("invalid_client_metadata", f"unsupported token_endpoint_auth_method: {auth_method}")
    if "client_credentials" in grant_types and auth_method == "none":
        raise OAuthError("invalid_client_metadata", "client_credentials requires a confidential client")

    redirect_uris = metadata.get("redirect_uris") or []
    if not isinstance(redirect_uris, list):
        raise OAuthError("invalid_redirect_uri", "redirect_uris must be an array")
    if "authorization_code" in grant_types:
        if not redirect_uris:
            raise OAuthError("invalid_redirect_uri", "authorization_code requires at least one redirect_uri")
        for uri in redirect_uris:
            if not isinstance(uri, str) or not _valid_redirect_uri(uri):
                raise OAuthError("invalid_redirect_uri", f"invalid redirect_uri: {uri}")

    scope = metadata.get("scope")
    if scope:
        registry = {s.name for s in OAuthScopeAdapter.list_all(db)}
        unknown = set(str(scope).split()) - registry
        if unknown:
            raise OAuthError("invalid_client_metadata", f"unknown scope: {' '.join(sorted(unknown))}")

    if is_approved is None:
        is_approved = True if created_via != "dcr" else Config.get_oauth_config().dcr_auto_approve

    plaintext_secret = None
    secret_hash = None
    if auth_method != "none":
        plaintext_secret = secrets.token_urlsafe(32)
        secret_hash = hash_token(plaintext_secret)

    client = OAuthClientAdapter.create(
        db,
        client_id=generate_client_id(),
        client_secret_hash=secret_hash,
        client_name=client_name[:128],
        client_uri=(metadata.get("client_uri") or None),
        logo_uri=(metadata.get("logo_uri") or None),
        software_id=(metadata.get("software_id") or None),
        redirect_uris=json.dumps(redirect_uris),
        grant_types=json.dumps(grant_types),
        response_types=json.dumps(metadata.get("response_types") or ["code"]),
        scope=(scope or None),
        token_endpoint_auth_method=auth_method,
        created_via=created_via,
        is_approved=is_approved,
        owner_id=owner_id,
    )
    return client, plaintext_secret


def registration_response(client: OAuthClient, secret: Optional[str]) -> dict:
    body = {
        "client_id": client.client_id,
        "client_id_issued_at": int(client.created_at.timestamp()),
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uri_list(),
        "grant_types": client.grant_type_list(),
        "response_types": json.loads(client.response_types or '["code"]'),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
    }
    if client.scope:
        body["scope"] = client.scope
    if secret:
        body["client_secret"] = secret
        body["client_secret_expires_at"] = 0
    return body


def verify_client_secret(client: OAuthClient, secret: Optional[str]) -> bool:
    if not client.client_secret_hash or not secret:
        return False
    return secrets.compare_digest(client.client_secret_hash, hash_token(secret))


def authenticate_client(db: Session, *, authorization_header: str, form: dict) -> OAuthClient:
    """Client authentication for the token / revoke / introspect endpoints (Basic, form body, or public client)."""
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    if authorization_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(authorization_header[6:]).decode()
            client_id, _, client_secret = decoded.partition(":")
        except Exception:
            raise OAuthError("invalid_client", "malformed Basic authorization", 401)
    if not client_id:
        raise OAuthError("invalid_client", "missing client_id", 401)
    client = OAuthClientAdapter.get(db, client_id)
    if not client or not client.is_active:
        raise OAuthError("invalid_client", "unknown or revoked client", 401)
    if not client.is_approved:
        raise OAuthError("unauthorized_client", "client is pending approval", 403)
    if client.token_endpoint_auth_method != "none" and not verify_client_secret(client, client_secret):
        raise OAuthError("invalid_client", "client authentication failed", 401)
    return client


def validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> bool:
    return redirect_uri in client.redirect_uri_list()


# ---------------------------------------------------------------------------
# scope / resource
# ---------------------------------------------------------------------------
def scope_registry(db: Session) -> dict:
    return {s.name: s for s in OAuthScopeAdapter.list_all(db)}


def supported_scope_names(db: Session) -> list[str]:
    return [s.name for s in OAuthScopeAdapter.list_all(db)]


def resolve_scope(db: Session, requested: Optional[str], client: Optional[OAuthClient],
                  service: Optional[Service]) -> str:
    """Decide the scope actually granted.

    - unknown scope -> invalid_scope
    - client registered with a restricted scope -> cannot exceed it
    - service configured with oauth_scopes -> cannot exceed it
    - nothing requested -> default scope, intersected with the limits above
    """
    registry = scope_registry(db)
    allowed: Optional[set] = None
    if client and client.scope:
        allowed = set(client.scope.split())
    if service and service.oauth_scopes:
        svc_allowed = set(service.oauth_scopes.split())
        allowed = svc_allowed if allowed is None else (allowed & svc_allowed)

    if requested and requested.strip():
        req = set(requested.split())
        unknown = req - set(registry)
        if unknown:
            raise OAuthError("invalid_scope", f"unknown scope: {' '.join(sorted(unknown))}", redirectable=True)
        if allowed is not None:
            extra = req - allowed
            if extra:
                raise OAuthError("invalid_scope", f"scope not permitted: {' '.join(sorted(extra))}",
                                 redirectable=True)
    else:
        req = {name for name, s in registry.items() if s.is_default}
        if allowed is not None:
            req &= allowed
    return " ".join(sorted(req))


def resolve_resource(db: Session, resource: Optional[str]) -> tuple[Optional[str], Optional[Service]]:
    """RFC 8707 resource -> (aud, service). The resource must map to a registered MCP server."""
    if not resource:
        return None, None
    service = ServiceAdapter.get_by_audience(db, resource)
    if service is None:
        raise OAuthError("invalid_target", f"unknown resource: {resource}", redirectable=True)
    return normalize_audience(service.effective_audience), service


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------
def verify_pkce(code_verifier: str, code_challenge: str, method: str = CODE_CHALLENGE_METHOD) -> bool:
    if method != "S256" or not code_verifier or not code_challenge:
        return False
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, code_challenge)


# ---------------------------------------------------------------------------
# authorization request → consent → code
# ---------------------------------------------------------------------------
def begin_authorization(
    db: Session, *, response_type: str, client_id: str, redirect_uri: str, code_challenge: Optional[str],
    code_challenge_method: str, scope: Optional[str], state: Optional[str], resource: Optional[str],
) -> OAuthAuthorizationRequest:
    """Validate the /authorize parameters and persist them as a pending consent request.

    Errors for an invalid client_id / redirect_uri use redirectable=False (never redirect to an unverified address);
    all other errors may be redirected back to redirect_uri with an error parameter.
    """
    client = OAuthClientAdapter.get(db, client_id)
    if not client or not client.is_active:
        raise OAuthError("invalid_client", "unknown or revoked client")
    if not client.is_approved:
        raise OAuthError("access_denied", "client is pending approval", 403)
    if not redirect_uri or not validate_redirect_uri(client, redirect_uri):
        raise OAuthError("invalid_request", "redirect_uri is not registered for this client")

    if response_type != "code":
        raise OAuthError("unsupported_response_type", "only response_type=code is supported", redirectable=True)
    if "authorization_code" not in client.grant_type_list():
        raise OAuthError("unauthorized_client", "client may not use authorization_code", redirectable=True)
    if code_challenge_method != "S256" or not code_challenge:
        raise OAuthError("invalid_request", "PKCE code_challenge (S256) is required", redirectable=True)

    audience, service = resolve_resource(db, resource)
    granted_scope = resolve_scope(db, scope, client, service)

    return OAuthAuthRequestAdapter.create(
        db,
        id=secrets.token_urlsafe(24),
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=granted_scope,
        resource=audience,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=local_now() + AUTH_REQUEST_TTL,
    )


def get_pending_request(db: Session, request_id: str) -> OAuthAuthorizationRequest:
    req = OAuthAuthRequestAdapter.get(db, request_id)
    if not req:
        raise OAuthError("invalid_request", "authorization request not found", 404)
    if req.decided_at is not None:
        raise OAuthError("invalid_request", "authorization request already decided", 410)
    if req.expires_at < local_now():
        raise OAuthError("invalid_request", "authorization request expired", 410)
    return req


def describe_request(db: Session, req: OAuthAuthorizationRequest, user: AdminUser) -> dict:
    """Information shown on the consent page."""
    registry = scope_registry(db)
    scopes = req.scope.split() if req.scope else []
    service = ServiceAdapter.get_by_audience(db, req.resource) if req.resource else None
    return {
        "request_id": req.id,
        "client": {
            "client_id": req.client.client_id,
            "client_name": req.client.client_name,
            "client_uri": req.client.client_uri,
            "logo_uri": req.client.logo_uri,
            "created_via": req.client.created_via,
        },
        "scopes": [{"name": s, "description": registry[s].description if s in registry else None} for s in scopes],
        "resource": req.resource,
        "service": {"id": str(service.id), "name": service.name} if service else None,
        "redirect_host": urlparse(req.redirect_uri).netloc or req.redirect_uri,
        "expires_at": req.expires_at.isoformat(),
        "can_skip": should_skip_consent(db, user, req.client, req.resource, scopes),
    }


def approve_request(
    db: Session, req: OAuthAuthorizationRequest, user: AdminUser, *,
    granted_scopes: Optional[Iterable[str]] = None, remember: bool = False,
) -> str:
    """User consented -> generate the authorization code and return the full URL to redirect the client to."""
    requested = req.scope.split() if req.scope else []
    if granted_scopes is None:
        scope_list = requested
    else:
        scope_list = [s for s in requested if s in set(granted_scopes)]
    scope_str = " ".join(scope_list)

    code = secrets.token_urlsafe(32)
    OAuthCodeAdapter.create(
        db,
        code_hash=hash_token(code),
        client_id=req.client_id,
        user_id=user.id,
        redirect_uri=req.redirect_uri,
        scope=scope_str,
        resource=req.resource,
        code_challenge=req.code_challenge,
        code_challenge_method=req.code_challenge_method,
        expires_at=local_now() + timedelta(seconds=Config.get_oauth_config().auth_code_ttl_seconds),
    )
    if remember:
        OAuthConsentAdapter.upsert(db, user.id, req.client_id, req.resource, scope_str)
    OAuthAuthRequestAdapter.mark_decided(db, req)
    # RFC 9207: include iss in the response so the client can confirm which AS answered (prevents mix-up attacks)
    return redirect_with(req.redirect_uri, {"code": code, "state": req.state, "iss": issuer()})


def deny_request(db: Session, req: OAuthAuthorizationRequest) -> str:
    OAuthAuthRequestAdapter.mark_decided(db, req)
    return redirect_with(req.redirect_uri, {
        "error": "access_denied", "error_description": "The user denied the request",
        "state": req.state, "iss": issuer(),
    })


def error_redirect(redirect_uri: str, err: OAuthError, state: Optional[str]) -> str:
    return redirect_with(redirect_uri, {
        "error": err.error, "error_description": err.description, "state": state, "iss": issuer(),
    })


# ---------------------------------------------------------------------------
# token issuance
# ---------------------------------------------------------------------------
def _sign(db: Session, payload: dict, typ: str) -> str:
    key = signing_keys.ensure_active_signing_key(db)
    return sign_rs256(payload, signing_keys.load_private_pem(key), key.kid, typ=typ)


def issue_access_token(
    db: Session, *, sub: str, client_id: str, scope: str, audience: Optional[str],
    service: Optional[Service] = None, user: Optional[AdminUser] = None, kind: str = "access",
    ttl_seconds: Optional[int] = None, label: Optional[str] = None, parent_jti: Optional[str] = None,
    record: bool = True,
) -> tuple[str, int, Optional[OAuthToken]]:
    cfg = Config.get_oauth_config()
    now = _now_ts()
    expires_in = ttl_seconds or cfg.access_expire_minutes * 60
    jti = str(uuid.uuid4())
    payload = {
        "iss": issuer(), "sub": sub, "client_id": client_id, "scope": scope,
        "iat": now, "exp": now + expires_in, "jti": jti, "token_use": "access",
    }
    if audience:
        payload["aud"] = audience
    if user:
        payload["email"] = user.email
        payload["name"] = user.username
    token = _sign(db, payload, typ="at+jwt")
    rec = None
    if record:
        rec = OAuthTokenAdapter.create(
            db, jti=jti, kind=kind, client_id=client_id, user_id=user.id if user else None, sub=sub,
            audience=audience, service_id=service.id if service else None, scope=scope, label=label,
            parent_jti=parent_jti, expires_at=datetime.fromtimestamp(now + expires_in),
        )
    return token, expires_in, rec


def issue_refresh_token(
    db: Session, *, sub: str, client_id: str, scope: str, audience: Optional[str],
    service: Optional[Service], user: Optional[AdminUser], parent_jti: Optional[str] = None,
) -> tuple[str, OAuthToken]:
    cfg = Config.get_oauth_config()
    now = _now_ts()
    expires_in = cfg.refresh_expire_days * 86400
    jti = str(uuid.uuid4())
    payload = {
        "iss": issuer(), "sub": sub, "client_id": client_id, "scope": scope,
        "iat": now, "exp": now + expires_in, "jti": jti, "token_use": "refresh",
    }
    if audience:
        payload["aud"] = audience
    token = _sign(db, payload, typ="refresh+jwt")
    rec = OAuthTokenAdapter.create(
        db, jti=jti, kind="refresh", client_id=client_id, user_id=user.id if user else None, sub=sub,
        audience=audience, service_id=service.id if service else None, scope=scope,
        parent_jti=parent_jti, expires_at=datetime.fromtimestamp(now + expires_in),
    )
    return token, rec


def verify_jwt(db: Session, token: str, *, expect_use: Optional[str] = None) -> dict:
    """Look up the public key by the header kid, then verify signature + iss + exp; aud is not enforced here (the
    resource server verifies it itself)."""
    try:
        header = unverified_header(token)
    except JWTVerifyError as e:
        raise OAuthError("invalid_grant", str(e))
    kid = header.get("kid")
    key = signing_keys.get_key_by_kid(db, kid) if kid else None
    if not key:
        raise OAuthError("invalid_grant", "unknown signing key")
    try:
        claims = decode_rs256(token, signing_keys.public_jwk_of(key), issuer=issuer())
    except JWTVerifyError as e:
        raise OAuthError("invalid_grant", str(e))
    if expect_use and claims.get("token_use") != expect_use:
        raise OAuthError("invalid_grant", f"expected a {expect_use} token")
    return claims


def _token_response(access_token: str, expires_in: int, scope: str, refresh_token: Optional[str] = None) -> dict:
    body = {"access_token": access_token, "token_type": "Bearer", "expires_in": expires_in, "scope": scope}
    if refresh_token:
        body["refresh_token"] = refresh_token
    return body


def _record_event(db: Session, *, event: str, jti: Optional[str], grant_type: Optional[str], client_id: str,
                  sub: Optional[str], audience: Optional[str], service: Optional[Service],
                  success: bool = True, ip: Optional[str] = None) -> None:
    try:
        TokenUsageAdapter.record(
            db, event=event, jti=jti, grant_type=grant_type, client_id=client_id, sub=sub,
            audience=audience, service_id=str(service.id) if service else None, success=success, ip_address=ip,
        )
    except Exception:
        db.rollback()


# ---------------------------------------------------------------------------
# grants
# ---------------------------------------------------------------------------
def authorization_code_grant(
    db: Session, *, client: OAuthClient, code: str, redirect_uri: str, code_verifier: str,
    resource: Optional[str], ip: Optional[str] = None,
) -> dict:
    rec: Optional[OAuthAuthorizationCode] = OAuthCodeAdapter.get_by_hash(db, hash_token(code))
    if not rec:
        raise OAuthError("invalid_grant", "unknown authorization code")
    if rec.used_at is not None:
        # Authorization code replay -> possibly leaked; revoke every token previously exchanged from this code
        OAuthTokenAdapter.revoke_family(db, rec.code_hash, reason="code_replay")
        raise OAuthError("invalid_grant", "authorization code already used")
    if rec.expires_at < local_now():
        raise OAuthError("invalid_grant", "authorization code expired")
    if rec.client_id != client.client_id:
        raise OAuthError("invalid_grant", "authorization code was issued to another client")
    if rec.redirect_uri != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri mismatch")
    if not verify_pkce(code_verifier, rec.code_challenge, rec.code_challenge_method):
        raise OAuthError("invalid_grant", "PKCE verification failed")
    if resource and normalize_audience(resource) != (rec.resource or None):
        raise OAuthError("invalid_target", "resource does not match the authorization request")
    OAuthCodeAdapter.mark_used(db, rec)

    user = rec.user
    service = ServiceAdapter.get_by_audience(db, rec.resource) if rec.resource else None
    scope = rec.scope or ""
    access, expires_in, access_rec = issue_access_token(
        db, sub=str(user.id), client_id=client.client_id, scope=scope, audience=rec.resource,
        service=service, user=user, parent_jti=rec.code_hash,
    )
    refresh = None
    if "refresh_token" in client.grant_type_list():
        refresh, _ = issue_refresh_token(
            db, sub=str(user.id), client_id=client.client_id, scope=scope, audience=rec.resource,
            service=service, user=user, parent_jti=rec.code_hash,
        )
    OAuthClientAdapter.touch(db, client)
    _record_event(db, event="issued", jti=access_rec.jti if access_rec else None, grant_type="authorization_code",
                  client_id=client.client_id, sub=str(user.id), audience=rec.resource, service=service, ip=ip)
    return _token_response(access, expires_in, scope, refresh)


def refresh_token_grant(db: Session, *, client: OAuthClient, refresh_token: str, requested_scope: Optional[str],
                        resource: Optional[str] = None, ip: Optional[str] = None) -> dict:
    claims = verify_jwt(db, refresh_token, expect_use="refresh")
    if claims.get("client_id") != client.client_id:
        raise OAuthError("invalid_grant", "refresh token belongs to another client")
    rec = OAuthTokenAdapter.get(db, claims.get("jti", ""))
    if rec is None:
        raise OAuthError("invalid_grant", "unknown refresh token")
    # RFC 8707: a resource sent on refresh must match the original grant (the audience cannot change)
    if resource and normalize_audience(resource) != (rec.audience or None):
        raise OAuthError("invalid_target", "resource does not match the original grant")
    if rec.is_revoked:
        # An already-rotated refresh token was used again -> replay; revoke the whole chain
        if rec.revoke_reason == "rotated":
            OAuthTokenAdapter.revoke_family(db, rec.parent_jti or rec.jti, reason="refresh_replay")
        raise OAuthError("invalid_grant", "refresh token revoked")

    scope = rec.scope or ""
    if requested_scope:
        wanted = set(requested_scope.split())
        if not wanted <= set(scope.split()):
            raise OAuthError("invalid_scope", "requested scope exceeds the original grant")
        scope = " ".join(sorted(wanted))

    OAuthTokenAdapter.revoke(db, rec, reason="rotated")
    user = rec.user
    service = rec.service or (ServiceAdapter.get_by_audience(db, rec.audience) if rec.audience else None)
    family = rec.parent_jti or rec.jti
    access, expires_in, access_rec = issue_access_token(
        db, sub=rec.sub, client_id=client.client_id, scope=scope, audience=rec.audience,
        service=service, user=user, parent_jti=family,
    )
    new_refresh, _ = issue_refresh_token(
        db, sub=rec.sub, client_id=client.client_id, scope=scope, audience=rec.audience,
        service=service, user=user, parent_jti=family,
    )
    OAuthClientAdapter.touch(db, client)
    _record_event(db, event="issued", jti=access_rec.jti if access_rec else None, grant_type="refresh_token",
                  client_id=client.client_id, sub=rec.sub, audience=rec.audience, service=service, ip=ip)
    return _token_response(access, expires_in, scope, new_refresh)


def client_credentials_grant(db: Session, *, client: OAuthClient, scope: Optional[str],
                             resource: Optional[str], ip: Optional[str] = None) -> dict:
    audience, service = resolve_resource(db, resource)
    resolved = resolve_scope(db, scope, client, service)
    access, expires_in, rec = issue_access_token(
        db, sub=client.client_id, client_id=client.client_id, scope=resolved, audience=audience, service=service,
    )
    OAuthClientAdapter.touch(db, client)
    _record_event(db, event="issued", jti=rec.jti if rec else None, grant_type="client_credentials",
                  client_id=client.client_id, sub=client.client_id, audience=audience, service=service, ip=ip)
    return _token_response(access, expires_in, resolved)


# ---------------------------------------------------------------------------
# revoke / introspect
# ---------------------------------------------------------------------------
def revoke_token(db: Session, *, client: OAuthClient, token: str, ip: Optional[str] = None) -> None:
    """RFC 7009: only revoke tokens issued to this client; stay silent otherwise (the endpoint always returns 200)."""
    try:
        claims = verify_jwt(db, token)
    except OAuthError:
        return
    if claims.get("client_id") != client.client_id:
        return
    rec = OAuthTokenAdapter.get(db, claims.get("jti", ""))
    if rec is None:
        return
    OAuthTokenAdapter.revoke(db, rec, reason="client_revoke")
    if rec.kind == "refresh":
        # Revoking a refresh token also invalidates the access token exchanged from it
        OAuthTokenAdapter.revoke_family(db, rec.parent_jti or rec.jti, reason="client_revoke")
    _record_event(db, event="revoked", jti=rec.jti, grant_type=None, client_id=client.client_id,
                  sub=rec.sub, audience=rec.audience, service=rec.service, ip=ip)


def introspect_token(db: Session, token: str, *, caller: OAuthClient, ip: Optional[str] = None) -> dict:
    """RFC 7662. Revoked / expired / signature failure all yield active=false.

    Who may look: the client that owns the token, or a confidential client (has a secret, treated as a resource
    server -- FastMCP's IntrospectionTokenVerifier is exactly this). A public client can only introspect its own
    tokens, so nobody can register a throwaway client via DCR and read another token's sub / email / scope.
    """
    inactive = {"active": False}
    try:
        claims = verify_jwt(db, token)
    except OAuthError:
        return inactive
    is_owner = claims.get("client_id") == caller.client_id
    if not is_owner and not caller.client_secret_hash:
        return inactive
    rec = OAuthTokenAdapter.get(db, claims.get("jti", ""))
    if rec is not None:
        if rec.is_revoked or rec.is_expired:
            return inactive
        OAuthTokenAdapter.touch(db, rec, ip)
    result = {
        "active": True,
        "scope": claims.get("scope"),
        "client_id": claims.get("client_id"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "iss": claims.get("iss"),
        "token_type": "Bearer",
        "token_use": claims.get("token_use"),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "jti": claims.get("jti"),
    }
    for extra in ("email", "name"):
        if claims.get(extra):
            result[extra] = claims[extra]
    return result


# ---------------------------------------------------------------------------
# console helpers
# ---------------------------------------------------------------------------
def mint_personal_token(db: Session, *, user: AdminUser, service: Service, scopes: Optional[Iterable[str]],
                        days: int, label: Optional[str]) -> tuple[str, OAuthToken]:
    """Admin console issues a Personal Access Token (long-lived access token, aud = that service)."""
    cfg = Config.get_oauth_config()
    days = max(1, min(int(days), cfg.pat_max_days))
    audience = normalize_audience(service.effective_audience)
    if not audience:
        raise OAuthError("invalid_target", "service has no host/port or audience configured")
    scope = resolve_scope(db, " ".join(scopes) if scopes else None, None, service)
    token, _, rec = issue_access_token(
        db, sub=str(user.id), client_id=CONSOLE_CLIENT_ID, scope=scope, audience=audience, service=service,
        user=user, kind="pat", ttl_seconds=days * 86400, label=label,
    )
    _record_event(db, event="issued", jti=rec.jti, grant_type="personal_access_token", client_id=CONSOLE_CLIENT_ID,
                  sub=str(user.id), audience=audience, service=service)
    return token, rec


def mint_scanner_token(db: Session, service: Service) -> Optional[str]:
    """Short-lived token self-signed on the spot for scanning / health-checking OAuth-protected services (not
    recorded)."""
    audience = normalize_audience(service.effective_audience)
    if not audience:
        return None
    scope = resolve_scope(db, DEFAULT_SCANNER_SCOPES, None, service) if not service.oauth_scopes \
        else resolve_scope(db, None, None, service)
    token, _, _ = issue_access_token(
        db, sub=SCANNER_CLIENT_ID, client_id=SCANNER_CLIENT_ID, scope=scope, audience=audience,
        service=service, ttl_seconds=SCANNER_TOKEN_TTL_SECONDS, record=False,
    )
    return token


def mint_audience_token(db: Session, audience: str) -> Optional[str]:
    """Scanner token for a server that is not registered yet (audience = its MCP URL); not recorded.

    Used while scanning: a peer that answers 401 with a Bearer challenge may be protected by this very
    authorization server, in which case a token for its URL lets the scanner read its name and tools.
    """
    aud = normalize_audience(audience)
    if not aud:
        return None
    scope = resolve_scope(db, DEFAULT_SCANNER_SCOPES, None, None)
    token, _, _ = issue_access_token(
        db, sub=SCANNER_CLIENT_ID, client_id=SCANNER_CLIENT_ID, scope=scope, audience=aud,
        ttl_seconds=SCANNER_TOKEN_TTL_SECONDS, record=False,
    )
    return token


def build_metadata(db: Session) -> dict:
    """RFC 8414 Authorization Server Metadata。"""
    base = issuer()
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "introspection_endpoint": f"{base}/oauth/introspect",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "scopes_supported": supported_scope_names(db),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": SERVER_GRANT_TYPES,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": SERVER_AUTH_METHODS,
        "revocation_endpoint_auth_methods_supported": SERVER_AUTH_METHODS,
        "introspection_endpoint_auth_methods_supported": SERVER_AUTH_METHODS,
        "resource_parameter_supported": True,
        "authorization_response_iss_parameter_supported": True,
        "service_documentation": f"{base}/docs",
    }
