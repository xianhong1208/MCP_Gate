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
    AdminUser, OAuthAuthorizationCode, OAuthAuthorizationRequest, OAuthClient, OAuthToken, Service, format_datetime,
    local_now,
)
from db.database import make_session
from db.seed import CONSOLE_CLIENT_ID, SCANNER_CLIENT_ID
from src.audit import AuditAction, AuditStatus, ResourceType, record_oauth_event
from src.adapters import (
    OAuthAuthRequestAdapter, OAuthClientAdapter, OAuthCodeAdapter, OAuthConsentAdapter, OAuthScopeAdapter,
    ServiceScopeAdapter,
    OAuthTokenAdapter, ServiceAdapter, TokenUsageAdapter, normalize_audience,
)
from src.config import Config
from src.oauth import client_assertion, signing_keys
from src.oauth.consent_policy import should_skip_consent
from src.oauth.errors import OAuthError
from src.oauth.jwt_utils import JWTVerifyError, decode_rs256, sign_rs256, unverified_header
from src.utils import public_cache
from src.utils.crypto import hash_token
from src.utils.field_limits import column_limit

SERVER_GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"]
SERVER_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"]
ASSERTION_SIGNING_ALGS = ["RS256", "ES256"]
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


LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
# RFC 7591 informational URIs: shown to the owner (consent screen, OAuth Clients page), so web URLs only
INFO_URI_FIELDS = ("client_uri", "logo_uri", "tos_uri", "policy_uri")
MAX_REDIRECT_URIS = 20      # native/desktop MCP clients register one or two
MAX_RESPONSE_TYPES = 5
MAX_SCOPE_PARAM = 1024      # characters of a raw `scope` parameter
MAX_RESOURCE_PARAM = 512    # characters of a raw `resource` parameter


def _valid_info_uri(uri) -> bool:
    """https with a host, or http to a loopback host (local development); nothing else (javascript:, data:, file:,
    other hosts over plain http, scheme-relative ...)."""
    if not isinstance(uri, str):
        return False
    try:
        p = urlparse(uri)
        host = (p.hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if p.scheme == "https":
        return True
    return p.scheme == "http" and host in LOOPBACK_HOSTS


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
    client_name = metadata.get("client_name") or ""
    if not isinstance(client_name, str):
        raise OAuthError("invalid_client_metadata", "client_name must be a string")
    client_name = client_name.strip() or "Unnamed MCP client"

    grant_types = metadata.get("grant_types") or ["authorization_code", "refresh_token"]
    if not isinstance(grant_types, list) or not all(isinstance(g, str) for g in grant_types):
        raise OAuthError("invalid_client_metadata", "grant_types must be an array of strings")
    grant_types = list(dict.fromkeys(grant_types))
    response_types = metadata.get("response_types") or ["code"]
    if (not isinstance(response_types, list) or len(response_types) > MAX_RESPONSE_TYPES
            or not all(isinstance(r, str) and len(r) <= 32 for r in response_types)):
        raise OAuthError("invalid_client_metadata", "response_types must be a short array of strings")
    unsupported = set(grant_types) - set(SERVER_GRANT_TYPES)
    if unsupported:
        raise OAuthError("invalid_client_metadata", f"unsupported grant_types: {' '.join(sorted(unsupported))}")

    auth_method = metadata.get("token_endpoint_auth_method") or "none"
    if not isinstance(auth_method, str) or auth_method not in SERVER_AUTH_METHODS:
        raise OAuthError("invalid_client_metadata", f"unsupported token_endpoint_auth_method: {auth_method}")
    if "client_credentials" in grant_types and auth_method == "none":
        raise OAuthError("invalid_client_metadata", "client_credentials requires a confidential client")
    if "client_credentials" in grant_types and created_via == "dcr":
        # client_credentials issues a token with no human consent. Registration is anonymous, so a
        # self-registered client must never hold that grant (whatever dcr_auto_approve says); only a
        # client the owner registered in the console may.
        raise OAuthError("invalid_client_metadata",
                         "client_credentials is only available to clients registered in the console")

    # private_key_jwt: the client registers its public keys, inline or by reference (RFC 7591 jwks / jwks_uri)
    jwks_doc = metadata.get("jwks")
    jwks_uri = (metadata.get("jwks_uri") or "").strip() or None
    if auth_method == "private_key_jwt":
        if bool(jwks_doc) == bool(jwks_uri):
            raise OAuthError("invalid_client_metadata", "private_key_jwt requires exactly one of jwks or jwks_uri")
        if jwks_doc:
            if isinstance(jwks_doc, str):
                try:
                    jwks_doc = json.loads(jwks_doc)
                except ValueError:
                    raise OAuthError("invalid_client_metadata", "jwks must be a JSON object")
            client_assertion.validate_jwks_document(jwks_doc)
        else:
            # MCP Gate fetches this URL itself: public https only (loopback allowed on http-issuer dev setups, and
            # only for clients the owner registered: an anonymous client must not aim our fetcher at localhost)
            client_assertion.validate_jwks_uri(
                jwks_uri, allow_loopback=issuer().startswith("http://") and created_via != "dcr")
    else:
        jwks_doc, jwks_uri = None, None

    redirect_uris = metadata.get("redirect_uris") or []
    if not isinstance(redirect_uris, list):
        raise OAuthError("invalid_redirect_uri", "redirect_uris must be an array")
    if len(redirect_uris) > MAX_REDIRECT_URIS:
        raise OAuthError("invalid_redirect_uri", f"at most {MAX_REDIRECT_URIS} redirect_uris")
    if "authorization_code" in grant_types and not redirect_uris:
        raise OAuthError("invalid_redirect_uri", "authorization_code requires at least one redirect_uri")
    if redirect_uris:  # validated whenever present: whatever is stored is shown in the console
        redirect_limit = column_limit(OAuthAuthorizationRequest.redirect_uri)
        for uri in redirect_uris:
            if not isinstance(uri, str) or not _valid_redirect_uri(uri):
                raise OAuthError("invalid_redirect_uri", f"invalid redirect_uri: {uri}")
            if len(uri) > redirect_limit:
                # every authorization request stores the redirect_uri it was given
                raise OAuthError("invalid_redirect_uri", f"redirect_uri is too long (maximum {redirect_limit} characters)")

    scope = metadata.get("scope")
    if scope:
        # No server context at registration time: any scope some server may grant is acceptable here; the
        # per-server check happens at /authorize against the requested resource.
        unknown = set(str(scope).split()) - set(supported_scope_names(db))
        if unknown:
            raise OAuthError("invalid_client_metadata", f"unknown scope: {' '.join(sorted(unknown))}")

    _check_metadata_lengths(metadata, jwks_uri)
    for field in INFO_URI_FIELDS:
        value = metadata.get(field)
        if value is not None and value != "" and not _valid_info_uri(value):
            raise OAuthError("invalid_client_metadata",
                             f"{field} must be an https URL (http only for localhost / loopback)")

    if is_approved is None:
        is_approved = True if created_via != "dcr" else Config.get_oauth_config().dcr_auto_approve

    # Classic-client compatibility: only for confidential clients registered in the console. Public clients
    # have nothing but PKCE to prove they are the party that started the flow.
    require_pkce = metadata.get("require_pkce", True) is not False
    default_resource = (metadata.get("default_resource") or "").strip() or None
    if not require_pkce and (auth_method == "none" or created_via == "dcr"):
        raise OAuthError("invalid_client_metadata",
                         "require_pkce=false is only allowed for confidential clients registered in the console")
    if default_resource:
        default_resource, _ = resolve_resource(db, default_resource)  # must be a registered server

    # Resource-server binding: console only (a DCR request carrying the field has it ignored, RFC 7591 §2)
    resource_audience = None
    if created_via == "manual" and metadata.get("resource_service_id"):
        resource_audience = resource_server_audience_for(db, metadata["resource_service_id"], auth_method)

    plaintext_secret = None
    secret_hash = None
    if auth_method in ("client_secret_basic", "client_secret_post"):
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
        response_types=json.dumps(response_types),
        scope=(scope or None),
        token_endpoint_auth_method=auth_method,
        jwks=json.dumps(jwks_doc) if jwks_doc else None,
        jwks_uri=jwks_uri,
        require_pkce=require_pkce,
        default_resource=default_resource,
        resource_audience=resource_audience,
        created_via=created_via,
        is_approved=is_approved,
        owner_id=owner_id,
    )
    return client, plaintext_secret


def _check_metadata_lengths(metadata: dict, jwks_uri: Optional[str]) -> None:
    """RFC 7591 metadata values longer than the columns storing them -> invalid_client_metadata (a public endpoint:
    on PostgreSQL an over-long value would otherwise end in a 500). client_name is shortened instead, as before."""
    values = {
        "client_uri": (metadata.get("client_uri"), OAuthClient.client_uri),
        "logo_uri": (metadata.get("logo_uri"), OAuthClient.logo_uri),
        "software_id": (metadata.get("software_id"), OAuthClient.software_id),
        "scope": (metadata.get("scope"), OAuthClient.scope),
        "default_resource": (metadata.get("default_resource"), OAuthClient.default_resource),
        # not stored, but bounded like the URIs that are
        "tos_uri": (metadata.get("tos_uri"), OAuthClient.client_uri),
        "policy_uri": (metadata.get("policy_uri"), OAuthClient.client_uri),
        "jwks_uri": (jwks_uri, OAuthClient.jwks_uri),
    }
    for field, (value, column) in values.items():
        if value is None:
            continue
        if not isinstance(value, str):
            raise OAuthError("invalid_client_metadata", f"{field} must be a string")
        limit = column_limit(column)
        if len(value) > limit:
            raise OAuthError("invalid_client_metadata", f"{field} is too long (maximum {limit} characters)")


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
    if client.jwks_uri:
        body["jwks_uri"] = client.jwks_uri
    if client.jwks:
        body["jwks"] = json.loads(client.jwks)
    if secret:
        body["client_secret"] = secret
        body["client_secret_expires_at"] = 0
    return body


def resource_server_audience_for(db: Session, service_id, auth_method: str) -> str:
    """Validate a resource-server binding request and return the audience to store."""
    if auth_method == "none":
        raise OAuthError("invalid_client_metadata", "only a confidential client can act as a resource server")
    service = ServiceAdapter.get_by_id(db, str(service_id))
    audience = normalize_audience(service.effective_audience) if service else None
    if not audience:
        raise OAuthError("invalid_client_metadata", "resource_service_id must name a server with an audience")
    return audience


def resource_server_audience(client: OAuthClient) -> Optional[str]:
    """The audience a client may act for as a resource server (revocation feed, introspecting other clients'
    tokens, usage reports), or None when it is not one.

    Only a confidential client the owner registered in the console and bound to one server qualifies; it then
    only ever sees tokens whose audience is that server. Dynamically registered clients never qualify:
    registration is anonymous, so choosing a secret-based auth method must not buy any trust."""
    if client.created_via != "manual" or client.token_endpoint_auth_method == "none":
        return None
    return client.resource_audience or None


def verify_client_secret(client: OAuthClient, secret: Optional[str]) -> bool:
    if not client.client_secret_hash or not secret:
        return False
    return secrets.compare_digest(client.client_secret_hash, hash_token(secret))


def authenticate_client(db: Session, *, authorization_header: str, form: dict) -> OAuthClient:
    """Client authentication for the token / revoke / introspect endpoints: Basic, form body, a private_key_jwt
    assertion (RFC 7523), or a public client."""
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    assertion = form.get("client_assertion")
    assertion_type = form.get("client_assertion_type")
    if assertion or assertion_type:
        if assertion_type != client_assertion.CLIENT_ASSERTION_TYPE or not assertion:
            raise OAuthError("invalid_client", "unsupported client_assertion_type", 401)
        if client_secret or authorization_header.startswith("Basic "):
            raise OAuthError("invalid_client", "use one client authentication method only", 401)
        asserted = client_assertion.unverified_issuer(assertion)
        if client_id and asserted and client_id != asserted:
            raise OAuthError("invalid_client", "client_id does not match client_assertion", 401)
        client_id = client_id or asserted
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
    if client.token_endpoint_auth_method == "private_key_jwt":
        if not assertion:
            raise OAuthError("invalid_client", "client_assertion required", 401)
        client_assertion.verify_client_assertion(client, assertion, token_endpoint=f"{issuer()}/oauth/token",
                                                 issuer=issuer())
    elif assertion:
        raise OAuthError("invalid_client", "client is not registered for private_key_jwt", 401)
    elif client.token_endpoint_auth_method != "none" and not verify_client_secret(client, client_secret):
        raise OAuthError("invalid_client", "client authentication failed", 401)
    return client


def _loopback_key(uri: str) -> Optional[tuple]:
    """For an http redirect URI on a loopback host (127.0.0.1, [::1] or localhost), everything but the port; None
    for any other URI."""
    try:
        p = urlparse(uri)
        host = p.hostname
        p.port  # noqa: B018 -- raises on a malformed port
    except ValueError:
        return None
    if p.scheme != "http" or host not in LOOPBACK_HOSTS or p.username or p.password:
        return None
    return (p.scheme, host, p.path, p.params, p.query, p.fragment)


def validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> bool:
    """Exact match against the registered list, except that a loopback redirect URI (http://127.0.0.1/...,
    http://[::1]/... or http://localhost/...) matches on any port: native apps and CLI MCP clients bind an
    ephemeral port (RFC 8252 §7.3, RFC 9700 §2.1 and §4.1.3). Scheme, host, path and query must still match
    exactly, so 127.0.0.1 and localhost are not interchangeable."""
    registered = client.redirect_uri_list()
    if redirect_uri in registered:
        return True
    key = _loopback_key(redirect_uri)
    return key is not None and any(_loopback_key(r) == key for r in registered)


# ---------------------------------------------------------------------------
# scope / resource
# ---------------------------------------------------------------------------
def scope_registry(db: Session, service: Optional[Service] = None) -> dict:
    """Scopes that exist for a request: the global registry plus, when a server is known, that server's own
    scopes (names are disjoint by construction)."""
    registry = {s.name: s for s in OAuthScopeAdapter.list_all(db)}
    if service is not None:
        registry.update({s.name: s for s in ServiceScopeAdapter.list_for_service(db, service.id)})
    return registry


def supported_scope_names(db: Session) -> list[str]:
    """Every scope name any server may grant: the global registry plus all service-declared scopes."""
    names = {s.name for s in OAuthScopeAdapter.list_all(db)} | {s.name for s in ServiceScopeAdapter.list_all(db)}
    return sorted(names)


def effective_scopes(db: Session, service: Service) -> list[dict]:
    """What a token for ``service`` may carry, for the console: global scopes (restricted by
    Service.oauth_scopes when set) then the server's own scopes, each tagged with its source."""
    restricted = set(service.oauth_scopes.split()) if service.oauth_scopes else None
    out = [dict(s.to_dict(), source="global") for s in OAuthScopeAdapter.list_all(db)
           if restricted is None or s.name in restricted]
    out += [dict(s.to_dict(), source="service") for s in ServiceScopeAdapter.list_for_service(db, service.id)]
    return out


def resolve_scope(db: Session, requested: Optional[str], client: Optional[OAuthClient],
                  service: Optional[Service]) -> str:
    """Decide the scope actually granted.

    - unknown scope -> invalid_scope (the registry is the global one plus the server's own scopes)
    - client registered with a restricted scope -> cannot exceed it
    - service configured with oauth_scopes -> global scopes cannot exceed it; its own scopes are always allowed
    - nothing requested -> default scope, intersected with the limits above
    """
    registry = scope_registry(db, service)
    allowed: Optional[set] = None
    if client and client.scope:
        allowed = set(client.scope.split())
    if service and service.oauth_scopes:
        own = {s.name for s in ServiceScopeAdapter.list_for_service(db, service.id)}
        svc_allowed = set(service.oauth_scopes.split()) | own
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
    if len(redirect_uri) > column_limit(OAuthAuthorizationRequest.redirect_uri):
        # registered before registration checked the length: such a client cannot complete a flow
        raise OAuthError("invalid_request", "redirect_uri is too long")
    if state is not None and len(state) > column_limit(OAuthAuthorizationRequest.state):
        raise OAuthError("invalid_request", "state is too long", redirectable=True)
    if code_challenge:
        if code_challenge_method != "S256":
            raise OAuthError("invalid_request", "only code_challenge_method=S256 is supported", redirectable=True)
        if len(code_challenge) > column_limit(OAuthAuthorizationRequest.code_challenge):
            # RFC 7636: a code challenge is at most 128 characters (an S256 challenge is exactly 43)
            raise OAuthError("invalid_request", "code_challenge is too long", redirectable=True)
    elif client.require_pkce or not client.client_secret_hash:
        raise OAuthError("invalid_request", "PKCE code_challenge (S256) is required", redirectable=True)
    else:
        code_challenge_method = None  # classic confidential client: the secret proves identity at /token

    if resource is not None and len(resource) > MAX_RESOURCE_PARAM:
        raise OAuthError("invalid_target", "resource is too long", redirectable=True)
    if scope is not None and len(scope) > MAX_SCOPE_PARAM:
        raise OAuthError("invalid_scope", "scope is too long", redirectable=True)
    audience, service = resolve_resource(db, resource or client.default_resource)
    granted_scope = resolve_scope(db, scope, client, service)
    if granted_scope and len(granted_scope) > column_limit(OAuthAuthorizationRequest.scope):
        raise OAuthError("invalid_scope", "too many scopes requested", redirectable=True)

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
    scopes = req.scope.split() if req.scope else []
    service = ServiceAdapter.get_by_audience(db, req.resource) if req.resource else None
    registry = scope_registry(db, service)
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
        "expires_at": format_datetime(req.expires_at),
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
    record: bool = True, commit: bool = True,
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
            parent_jti=parent_jti, expires_at=datetime.fromtimestamp(now + expires_in), commit=commit,
        )
    return token, expires_in, rec


def refresh_token_audience() -> str:
    return f"{issuer()}/oauth/token"


def issue_refresh_token(
    db: Session, *, sub: str, client_id: str, scope: str, audience: Optional[str],
    service: Optional[Service], user: Optional[AdminUser], parent_jti: Optional[str] = None, commit: bool = True,
) -> tuple[str, OAuthToken]:
    cfg = Config.get_oauth_config()
    now = _now_ts()
    expires_in = cfg.refresh_expire_days * 86400
    jti = str(uuid.uuid4())
    # The audience is MCP Gate's own token endpoint, never the resource: a refresh token is presented only
    # here, so a resource server verifying aud (every JWTVerifier configured with its audience) refuses it as a
    # Bearer token. The resource it was granted for lives in the token record (rec.audience).
    payload = {
        "iss": issuer(), "sub": sub, "client_id": client_id, "scope": scope,
        "iat": now, "exp": now + expires_in, "jti": jti, "token_use": "refresh",
        "aud": refresh_token_audience(),
    }
    token = _sign(db, payload, typ="refresh+jwt")
    rec = OAuthTokenAdapter.create(
        db, jti=jti, kind="refresh", client_id=client_id, user_id=user.id if user else None, sub=sub,
        audience=audience, service_id=service.id if service else None, scope=scope,
        parent_jti=parent_jti, expires_at=datetime.fromtimestamp(now + expires_in), commit=commit,
    )
    return token, rec


def verify_jwt(db: Session, token: str, *, expect_use: Optional[str] = None, published_only: bool = False) -> dict:
    """Look up the public key by the header kid, then verify signature + iss + exp; aud is not enforced here (the
    resource server verifies it itself). ``published_only`` accepts only keys still in the JWKS (what a resource
    server would accept); refresh tokens are verified against any key MCP Gate still holds."""
    try:
        header = unverified_header(token)
    except JWTVerifyError as e:
        raise OAuthError("invalid_grant", str(e))
    kid = header.get("kid")
    key = signing_keys.get_key_by_kid(db, kid) if kid else None
    if not key or (published_only and not signing_keys.is_published(db, key)):
        raise OAuthError("invalid_grant", "unknown signing key")
    try:
        claims = decode_rs256(token, signing_keys.public_jwk_of(key), issuer=issuer())
    except JWTVerifyError as e:
        raise OAuthError("invalid_grant", str(e))
    if expect_use and claims.get("token_use") != expect_use:
        raise OAuthError("invalid_grant", f"expected a {expect_use} token")
    return claims


def _active_service_for(db: Session, audience: Optional[str]) -> Optional[Service]:
    """The active server a grant's audience names; a disabled or removed server gets no new tokens."""
    if not audience:
        return None
    service = ServiceAdapter.get_by_audience(db, audience)  # active services only
    if service is None:
        raise OAuthError("invalid_grant", "the server this grant was issued for is disabled or no longer registered")
    return service


def _signed_by_published_key(db: Session, token: str) -> bool:
    """For a token whose signature already verified: is its key still in the JWKS?"""
    try:
        kid = unverified_header(token).get("kid")
    except JWTVerifyError:
        return False
    key = signing_keys.get_key_by_kid(db, kid) if kid else None
    return key is not None and signing_keys.is_published(db, key)


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


def _code_replayed(db: Session, rec: OAuthAuthorizationCode, client: OAuthClient, ip: Optional[str], *,
                   concurrent: bool = False):
    """A used code was presented again: revoke everything exchanged from it, audit it, refuse."""
    revoked = OAuthTokenAdapter.revoke_family(db, rec.code_hash, reason="code_replay")
    record_oauth_event(db, AuditAction.OAUTH_CODE_REPLAY, status=AuditStatus.FAILURE, resource_type=ResourceType.TOKEN,
                       client_id=client.client_id, client_name=client.client_name, ip_address=ip,
                       request_path="/oauth/token", error_message="authorization code already used",
                       details={"revoked_tokens": revoked, "concurrent": concurrent,
                                "user_id": str(rec.user_id) if rec.user_id else None, "resource": rec.resource})
    raise OAuthError("invalid_grant", "authorization code already used")


def _refresh_replayed(db: Session, rec: OAuthToken, client: OAuthClient, ip: Optional[str], *,
                      concurrent: bool = False) -> None:
    """A rotated refresh token was presented again: revoke its whole family and audit it."""
    revoked = OAuthTokenAdapter.revoke_family(db, rec.parent_jti or rec.jti, reason="refresh_replay")
    record_oauth_event(db, AuditAction.OAUTH_REFRESH_REPLAY, status=AuditStatus.FAILURE,
                       resource_type=ResourceType.TOKEN, client_id=client.client_id, client_name=client.client_name,
                       ip_address=ip, request_path="/oauth/token", error_message="refresh token reused",
                       details={"jti": rec.jti, "revoked_tokens": revoked, "concurrent": concurrent,
                                "resource": rec.audience})


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
        _code_replayed(db, rec, client, ip)
    if rec.expires_at < local_now():
        raise OAuthError("invalid_grant", "authorization code expired")
    # Any failed check below burns the code (OAuth 2.1 §4.1.3): a code that met a wrong verifier, client or
    # redirect URI may be in an attacker's hands, so it must not stay redeemable for the rest of its lifetime.
    failure: Optional[OAuthError] = None
    if rec.client_id != client.client_id:
        failure = OAuthError("invalid_grant", "authorization code was issued to another client")
    elif rec.redirect_uri != redirect_uri:
        failure = OAuthError("invalid_grant", "redirect_uri mismatch")
    elif rec.code_challenge:
        if not verify_pkce(code_verifier, rec.code_challenge, rec.code_challenge_method):
            failure = OAuthError("invalid_grant", "PKCE verification failed")
    elif client.require_pkce or not client.client_secret_hash:
        # A code issued without PKCE can only be redeemed by an authenticated classic client
        failure = OAuthError("invalid_grant", "PKCE verification failed")
    if failure is None and resource and normalize_audience(resource) != (rec.resource or None):
        failure = OAuthError("invalid_target", "resource does not match the authorization request")

    signing_keys.ensure_active_signing_key(db)  # may commit: must happen before the claim below
    # Check-then-set would let two concurrent redemptions both pass the used_at check above: the claim is one
    # conditional UPDATE, and it stays uncommitted (holding the row / write lock) until the tokens are recorded,
    # so the loser waits, finds the code used and revokes the tokens the winner issued -- a replay, as above.
    if not OAuthCodeAdapter.claim(db, rec.code_hash):
        _code_replayed(db, rec, client, ip, concurrent=True)
    try:
        if failure is not None:
            raise failure
        user = rec.user
        if user is None or not user.is_active:
            raise OAuthError("invalid_grant", "the user who granted this code is no longer active")
        service = _active_service_for(db, rec.resource)
    except OAuthError:
        OAuthTokenAdapter.commit_grant(db)  # the code stays burned
        raise
    scope = rec.scope or ""
    access, expires_in, access_rec = issue_access_token(
        db, sub=str(user.id), client_id=client.client_id, scope=scope, audience=rec.resource,
        service=service, user=user, parent_jti=rec.code_hash, commit=False,
    )
    refresh = None
    if "refresh_token" in client.grant_type_list():
        refresh, _ = issue_refresh_token(
            db, sub=str(user.id), client_id=client.client_id, scope=scope, audience=rec.resource,
            service=service, user=user, parent_jti=rec.code_hash, commit=False,
        )
    OAuthTokenAdapter.commit_grant(db)
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
            _refresh_replayed(db, rec, client, ip)
        raise OAuthError("invalid_grant", "refresh token revoked")

    scope = rec.scope or ""
    if requested_scope:
        wanted = set(requested_scope.split())
        if not wanted <= set(scope.split()):
            raise OAuthError("invalid_scope", "requested scope exceeds the original grant")
        scope = " ".join(sorted(wanted))

    user = rec.user
    if user is None or not user.is_active:
        raise OAuthError("invalid_grant", "the user who granted this token is no longer active")
    service = _active_service_for(db, rec.audience)  # before rotating: a refused refresh keeps the token usable
    family = rec.parent_jti or rec.jti
    signing_keys.ensure_active_signing_key(db)  # may commit: must happen before the rotation below
    # Rotation is one conditional UPDATE, uncommitted until the new tokens are recorded: of two concurrent
    # refreshes with the same token one rotates it, the other waits, finds it rotated and treats it as a replay.
    if not OAuthTokenAdapter.rotate(db, rec.jti):
        _refresh_replayed(db, rec, client, ip, concurrent=True)
        raise OAuthError("invalid_grant", "refresh token revoked")
    access, expires_in, access_rec = issue_access_token(
        db, sub=rec.sub, client_id=client.client_id, scope=scope, audience=rec.audience,
        service=service, user=user, parent_jti=family, commit=False,
    )
    new_refresh, _ = issue_refresh_token(
        db, sub=rec.sub, client_id=client.client_id, scope=scope, audience=rec.audience,
        service=service, user=user, parent_jti=family, commit=False,
    )
    OAuthTokenAdapter.commit_grant(db)
    OAuthClientAdapter.touch(db, client)
    _record_event(db, event="issued", jti=access_rec.jti if access_rec else None, grant_type="refresh_token",
                  client_id=client.client_id, sub=rec.sub, audience=rec.audience, service=service, ip=ip)
    return _token_response(access, expires_in, scope, new_refresh)


def client_credentials_grant(db: Session, *, client: OAuthClient, scope: Optional[str],
                             resource: Optional[str], ip: Optional[str] = None) -> dict:
    if client.created_via != "manual" or client.token_endpoint_auth_method == "none":
        # Defence in depth for records stored before registration refused it: a token without consent is only
        # for confidential clients the owner registered in the console.
        raise OAuthError("unauthorized_client", "client may not use grant_type=client_credentials")
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

    Who may look: the client that owns the token (any of its tokens), or a resource server (a console-registered
    confidential client bound to a server -- FastMCP's IntrospectionTokenVerifier is exactly this), which only
    sees access tokens whose audience is its own server. Anyone else gets active=false, so nobody can register a
    throwaway client via DCR and read another token's sub / email / scope.
    """
    inactive = {"active": False}
    try:
        claims = verify_jwt(db, token)
    except OAuthError:
        return inactive
    if claims.get("token_use") != "refresh" and not _signed_by_published_key(db, token):
        return inactive  # a resource server would no longer accept it either
    is_owner = claims.get("client_id") == caller.client_id
    if not is_owner:
        rs_audience = resource_server_audience(caller)
        if rs_audience is None or claims.get("token_use") != "access":
            return inactive
        aud = claims.get("aud")
        if not isinstance(aud, str) or normalize_audience(aud) != rs_audience:
            return inactive
    rec = OAuthTokenAdapter.get(db, claims.get("jti", ""))
    if rec is None and claims.get("token_use") == "refresh":
        return inactive  # every refresh token MCP Gate issues is recorded; one without a record is not ours
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
# offline verifiers: revocation feed + usage reports
# ---------------------------------------------------------------------------
def revoked_feed(db: Session, *, caller: OAuthClient, since: Optional[float] = None) -> dict:
    """Tokens revoked but not yet expired, for MCP servers that verify JWTs offline and want revocation to take
    effect before expiry. Bounded by the access-token lifetime. Resource servers only, and only the tokens of
    the caller's own server."""
    audience = resource_server_audience(caller)
    if audience is None:
        raise OAuthError("unauthorized_client",
                         "only a client registered in the console as a server's resource server may read the "
                         "revocation feed", 403)
    since_dt = None
    if since is not None:
        try:
            since_dt = datetime.fromtimestamp(float(since))  # stored times are naive local time (local_now)
        except (TypeError, ValueError, OverflowError):
            raise OAuthError("invalid_request", "since must be a unix timestamp")
    now = local_now()
    # Revoked refresh tokens are listed too: refresh JWTs issued before 1.2 carry the server's audience and an
    # older verifier would accept them as Bearer tokens. Routine rotation is left out (it is not a revocation
    # anyone asked for, and listing it would grow the feed with every refresh).
    rows = OAuthTokenAdapter.list_revoked_unexpired(db, since=since_dt, audience=audience,
                                                    kinds=("access", "pat", "refresh"))
    return {
        "revoked": [{"jti": t.jti, "revoked_at": int(t.revoked_at.timestamp()),
                     "exp": int(t.expires_at.timestamp())} for t in rows],
        "now": int(now.timestamp()),
    }


MAX_USAGE_EVENTS = 1000
MAX_USAGE_COUNT = 1_000_000          # verifications of one token in one report
USAGE_CLOCK_SKEW = timedelta(minutes=5)


def _usage_count(raw) -> int:
    if isinstance(raw, bool):
        raise OAuthError("invalid_request", "count must be an integer")
    try:
        count = int(raw)
    except (TypeError, ValueError, OverflowError):
        raise OAuthError("invalid_request", "count must be an integer")
    if count != raw and not isinstance(raw, str):
        raise OAuthError("invalid_request", "count must be an integer")
    if not 1 <= count <= MAX_USAGE_COUNT:
        raise OAuthError("invalid_request", f"count must be between 1 and {MAX_USAGE_COUNT}")
    return count


def _usage_last_seen(raw) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        last_seen = datetime.fromtimestamp(float(raw))  # local naive, like every stored timestamp
    except (TypeError, ValueError, OverflowError, OSError):
        raise OAuthError("invalid_request", "last_seen must be a unix timestamp")
    now = local_now()
    if last_seen > now + USAGE_CLOCK_SKEW:
        raise OAuthError("invalid_request", "last_seen is in the future")
    return min(last_seen, now)


def report_usage(db: Session, *, caller: OAuthClient, events, ip: Optional[str] = None) -> dict:
    """Fold verifications an offline MCP server batched up into the token counters and the usage statistics.
    ``events`` is a list of {jti, count (1..MAX_USAGE_COUNT), last_seen (unix)}. Resource servers only; a jti
    that is unknown or belongs to another server's audience is returned as unknown, not stored."""
    audience = resource_server_audience(caller)
    if audience is None:
        raise OAuthError("unauthorized_client",
                         "only a client registered in the console as a server's resource server may report usage",
                         403)
    if not isinstance(events, list):
        raise OAuthError("invalid_request", "events must be an array")
    if len(events) > MAX_USAGE_EVENTS:
        raise OAuthError("invalid_request", f"at most {MAX_USAGE_EVENTS} events per report")
    parsed = []
    for ev in events:  # validate the whole batch before writing anything
        if not isinstance(ev, dict) or not isinstance(ev.get("jti"), str) or len(ev["jti"]) > 64:
            raise OAuthError("invalid_request", "each event needs a jti")
        parsed.append((ev["jti"], _usage_count(ev.get("count", 1)), _usage_last_seen(ev.get("last_seen"))))
    accepted, unknown = 0, []
    for jti, count, last_seen in parsed:
        rec = OAuthTokenAdapter.get(db, jti)
        if rec is None or rec.kind not in ("access", "pat") or rec.audience != audience:
            unknown.append(jti)
            continue
        OAuthTokenAdapter.apply_usage(db, rec, count=count, last_seen=last_seen)
        TokenUsageAdapter.record(
            db, event="verified", jti=rec.jti, client_id=rec.client_id, sub=rec.sub, audience=rec.audience,
            service_id=str(rec.service_id) if rec.service_id else None, success=True, ip_address=ip,
            count=count, used_at=last_seen,
        )
        accepted += 1
    return {"accepted": accepted, "unknown": unknown}


# ---------------------------------------------------------------------------
# console helpers
# ---------------------------------------------------------------------------
def mint_personal_token(db: Session, *, user: AdminUser, service: Service, scopes: Optional[Iterable[str]],
                        days: int, label: Optional[str]) -> tuple[str, OAuthToken]:
    """Admin console issues a Personal Access Token (long-lived access token, aud = that service)."""
    cfg = Config.get_oauth_config()
    days = max(1, min(int(days), cfg.pat_max_days))
    if not service.is_active:
        raise OAuthError("invalid_target", "the server is disabled")
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


def mint_probe_token_like(db: Session, *, record: OAuthToken, service: Service) -> str:
    """A short-lived copy of an issued token's claims (sub, client_id, scope, aud, email/name and the same jti),
    signed now, for inspecting a server that shows different tools per caller. The stored token itself cannot
    be read back (only its record exists), so this is how "refresh as that token" works; the server verifies
    the copy against the JWKS like the original and sees exactly what that token presents."""
    if record.kind not in ("access", "pat"):
        raise OAuthError("invalid_request", "only access tokens and personal access tokens can be used")
    if record.is_revoked or record.is_expired:
        raise OAuthError("invalid_request", "that token is no longer active")
    audience = normalize_audience(service.effective_audience)
    if not audience or normalize_audience(record.audience or "") != audience:
        raise OAuthError("invalid_request", "that token was not issued for this server")
    now = _now_ts()
    payload = {
        "iss": issuer(), "sub": record.sub, "client_id": record.client_id, "scope": record.scope or "",
        "iat": now, "exp": now + SCANNER_TOKEN_TTL_SECONDS, "jti": record.jti, "token_use": "access",
        "aud": audience,
    }
    if record.user:
        payload["email"] = record.user.email
        payload["name"] = record.user.username
    return _sign(db, payload, typ="at+jwt")


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


def cached_metadata() -> dict:
    """build_metadata from memory, for the public discovery endpoints; opens a session only on a cache miss.
    Keyed on the issuer; the scope adapters invalidate it when scopes_supported changes."""

    def build() -> dict:
        db = make_session()
        try:
            return build_metadata(db)
        finally:
            db.close()

    return public_cache.get_or_build(f"metadata:{issuer()}", build)


def build_metadata(db: Session) -> dict:
    """RFC 8414 Authorization Server Metadata."""
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
        "token_endpoint_auth_signing_alg_values_supported": ASSERTION_SIGNING_ALGS,
        "revocation_endpoint_auth_methods_supported": SERVER_AUTH_METHODS,
        "revocation_endpoint_auth_signing_alg_values_supported": ASSERTION_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": SERVER_AUTH_METHODS,
        "introspection_endpoint_auth_signing_alg_values_supported": ASSERTION_SIGNING_ALGS,
        "resource_parameter_supported": True,
        "authorization_response_iss_parameter_supported": True,
        # MCP Gate extensions for servers that verify tokens offline (see examples/mcp_gate_hooks.py)
        "revoked_tokens_endpoint": f"{base}/oauth/revoked",
        "usage_report_endpoint": f"{base}/oauth/usage",
        "service_documentation": f"{base}/docs",
    }
