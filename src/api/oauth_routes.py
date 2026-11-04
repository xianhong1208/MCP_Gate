"""OAuth 2.1 Authorization Server protocol endpoints (public; used by MCP clients / MCP servers).

  GET  /.well-known/oauth-authorization-server   RFC 8414 metadata
  GET  /.well-known/openid-configuration         same as above (for clients that only probe this path)
  GET  /.well-known/jwks.json                    public keys
  POST /oauth/register                           RFC 7591 dynamic registration
  GET  /oauth/authorize                          code + PKCE; not logged in / consent needed -> redirect to SPA /consent
  GET  /oauth/authorize/requests/{rid}           consent page data (login required)
  POST /oauth/authorize/requests/{rid}/decision  approve / deny -> returns redirect_to
  POST /oauth/token                              authorization_code / refresh_token / client_credentials
  POST /oauth/revoke                             RFC 7009
  POST /oauth/introspect                         RFC 7662
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import List, Optional
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from db import get_db
from db.models import AdminUser
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType, record_oauth_event
from src.identity import get_current_user
from src.logging import get_logger
from src.oauth import service as oauth
from src.oauth.errors import OAuthError
from src.oauth.signing_keys import cached_jwks
from src.utils.client_ip import resolve_client_ip

logger = get_logger("oauth")
router = APIRouter(tags=["OAuth 2.1"])

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _error_json(err: OAuthError) -> JSONResponse:
    headers = dict(NO_STORE)
    if err.error == "invalid_client":
        headers["WWW-Authenticate"] = 'Basic realm="oauth"'
    return JSONResponse(status_code=err.status_code, content=err.to_dict(), headers=headers)


def _client_ip(request: Request) -> Optional[str]:
    """Client address, honouring X-Forwarded-For only from security.trusted_proxies."""
    return resolve_client_ip(request)


# Request-body caps for the public OAuth endpoints (anonymous callers; nothing legitimate comes close)
REGISTRATION_BODY_LIMIT = 64 * 1024     # RFC 7591 metadata, including an inline jwks with a few keys
FORM_BODY_LIMIT = 64 * 1024             # token / revoke / introspect / revocation feed
USAGE_BODY_LIMIT = 512 * 1024           # up to MAX_USAGE_EVENTS usage events


async def _read_body(request: Request, limit: int, error: str = "invalid_request") -> bytes:
    """The request body, refused with 413 once it exceeds ``limit`` bytes (checked against Content-Length up front
    and while streaming, so an oversized body is never buffered whole)."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise OAuthError(error, f"request body too large (maximum {limit} bytes)", 413)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise OAuthError(error, f"request body too large (maximum {limit} bytes)", 413)
        chunks.append(chunk)
    return b"".join(chunks)


async def _form(request: Request, limit: int = FORM_BODY_LIMIT) -> dict:
    """application/x-www-form-urlencoded (per the OAuth spec) -- parsed by hand, no python-multipart needed."""
    raw = (await _read_body(request, limit)).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(raw).items() if v}


def _claimed_client_id(request: Request, form: dict) -> Optional[str]:
    """The client_id a request claims (Basic username or form field), for the audit log; never trusted."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            return base64.b64decode(header[6:], validate=True).decode("utf-8").partition(":")[0] or None
        except (binascii.Error, UnicodeDecodeError):
            return None
    return form.get("client_id") or None


def _authenticate_client(request: Request, db: Session, form: dict):
    """Called from the threadpool only: a private_key_jwt client may need its jwks_uri fetched, a blocking network
    call (DNS + HTTPS, up to the fetch timeout) that must not stall every other request.

    A failed client authentication (invalid_client) is audited before the error goes back."""
    try:
        return oauth.authenticate_client(db, authorization_header=request.headers.get("Authorization", ""),
                                         form=form)
    except OAuthError as e:
        if e.error == "invalid_client":
            db.rollback()
            record_oauth_event(db, AuditAction.OAUTH_CLIENT_AUTH_FAILED, status=AuditStatus.FAILURE,
                               client_id=_claimed_client_id(request, form), ip_address=_client_ip(request),
                               request_path=request.url.path, error_message=e.description)
        raise


async def _off_loop(request: Request, read_body, handler, *args):
    """Read the body on the loop (it is async), then run ``handler(request, *args, body)`` in the threadpool.
    A body that cannot be read (too large) is answered here."""
    try:
        body = await read_body(request)
    except OAuthError as e:
        return _error_json(e)
    return await run_in_threadpool(handler, request, *args, body)


# Every handler below keeps its synchronous DB work off the event loop (H-06): either the handler is a plain
# `def` (FastAPI runs it in the threadpool), or it awaits the request body and then hands the rest to
# run_in_threadpool. A pool checkout that blocks on the loop freezes the whole server, because the connections
# already checked out can only be returned by that same loop.


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/openid-configuration")
def authorization_server_metadata():
    """Authorization server metadata (RFC 8414). Lists every OAuth endpoint, supported grants, PKCE methods and scopes. Public."""
    return JSONResponse(content=oauth.cached_metadata(), headers={"Cache-Control": "public, max-age=300"})


@router.get("/.well-known/jwks.json")
def jwks():
    """Public signing keys (JWKS). MCP servers fetch these to verify tokens offline; a rotated-out key stays published while tokens it signed can still be valid. Public."""
    return JSONResponse(content=cached_jwks(), headers={"Cache-Control": "public, max-age=300"})


# ---------------------------------------------------------------------------
# dynamic client registration
# ---------------------------------------------------------------------------
@router.post("/oauth/register", status_code=201)
async def register(request: Request, db: Session = Depends(get_db)):
    """Dynamic client registration (RFC 7591). Returns a client_id (and a one-time client_secret for confidential clients). Public."""
    return await _off_loop(request, lambda r: _read_body(r, REGISTRATION_BODY_LIMIT, "invalid_client_metadata"),
                           _register, db)


def _register(request: Request, db: Session, raw: bytes) -> JSONResponse:
    try:
        try:
            metadata = json.loads(raw)
        except Exception:
            raise OAuthError("invalid_client_metadata", "request body must be a JSON object")
        client, secret = oauth.register_client(db, metadata, created_via="dcr")
        logger.info(f"DCR: registered client {client.client_id} ({client.client_name}) approved={client.is_approved}")
        record_oauth_event(db, AuditAction.OAUTH_CLIENT_CREATE, client_id=client.client_id,
                           client_name=client.client_name, ip_address=_client_ip(request),
                           request_path=request.url.path,
                           details={"created_via": "dcr", "approved": client.is_approved,
                                    "redirect_uris": client.redirect_uri_list(),
                                    "token_endpoint_auth_method": client.token_endpoint_auth_method})
        return JSONResponse(status_code=201, content=oauth.registration_response(client, secret), headers=NO_STORE)
    except OAuthError as e:
        db.rollback()
        return _error_json(e)


# ---------------------------------------------------------------------------
# authorization endpoint + consent
# ---------------------------------------------------------------------------
@router.get("/oauth/authorize")
def authorize(
    request: Request,
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    code_challenge: Optional[str] = None,
    code_challenge_method: str = "S256",
    scope: Optional[str] = None,
    state: Optional[str] = None,
    resource: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Validate params -> persist the authorization request -> redirect to the /consent page.

    Even when consent may be skipped (remembered, or a console-registered client) the code is not issued here: this
    is a top-level navigation, so it carries the session cookie but cannot carry the session binding, and a 302
    with the code in ``Location`` would hand the code to anyone replaying a leaked cookie. The consent page sees
    ``can_skip`` and approves on its own, with the full session."""
    try:
        req = oauth.begin_authorization(
            db, response_type=response_type, client_id=client_id, redirect_uri=redirect_uri,
            code_challenge=code_challenge, code_challenge_method=code_challenge_method,
            scope=scope, state=state, resource=resource,
        )
    except OAuthError as e:
        db.rollback()
        if e.redirectable and redirect_uri:
            return RedirectResponse(url=oauth.error_redirect(redirect_uri, e, state), status_code=302)
        return _error_json(e)

    return RedirectResponse(url=f"/consent?{urlencode({'rid': req.id})}", status_code=302)


@router.get("/oauth/authorize/requests/{request_id}")
def get_authorization_request(request_id: str, db: Session = Depends(get_db),
                              user: AdminUser = Depends(get_current_user)):
    """Details of a pending authorization request for the consent screen: client, target server, requested scopes. Requires a console session."""
    try:
        req = oauth.get_pending_request(db, request_id)
    except OAuthError as e:
        return _error_json(e)
    return oauth.describe_request(db, req, user)


class DecisionRequest(BaseModel):
    approve: bool
    scopes: Optional[List[str]] = None
    remember: bool = False


@router.post("/oauth/authorize/requests/{request_id}/decision")
def decide_authorization_request(request_id: str, body: DecisionRequest, request: Request,
                                 db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Approve or deny a pending authorization request. On approval an authorization code is issued; returns the URL to send the browser back to. Requires a console session."""
    try:
        req = oauth.get_pending_request(db, request_id)
    except OAuthError as e:
        return _error_json(e)
    client_id, client_name, resource, requested = req.client_id, req.client.client_name, req.resource, req.scope
    if body.approve:
        url = oauth.approve_request(db, req, user, granted_scopes=body.scopes, remember=body.remember)
        logger.info(f"consent granted: client={client_id} user={user.email} aud={resource}")
    else:
        url = oauth.deny_request(db, req)
        logger.info(f"consent denied: client={client_id} user={user.email}")
    granted = requested.split() if requested else []
    if body.approve and body.scopes is not None:
        granted = [s for s in granted if s in set(body.scopes)]
    try:
        AuditService.log_from_request(
            db=db, request=request,
            action=AuditAction.OAUTH_CONSENT_APPROVE if body.approve else AuditAction.OAUTH_CONSENT_DENY,
            resource_type=ResourceType.OAUTH_CONSENT, status=AuditStatus.SUCCESS, resource_id=client_id,
            actor_type=ActorType.ADMIN, actor_id=str(user.id), actor_name=user.audit_name,
            details={"client_id": client_id, "client_name": client_name, "resource": resource,
                     "scopes": granted if body.approve else [], "remember": bool(body.approve and body.remember)},
        )
    except Exception as e:  # the decision is already stored; the redirect must still go back
        db.rollback()
        logger.error(f"Failed to audit the consent decision: {e}")
    return {"redirect_to": url}


# ---------------------------------------------------------------------------
# token / revoke / introspect
# ---------------------------------------------------------------------------
@router.post("/oauth/token")
async def token(request: Request, db: Session = Depends(get_db)):
    """Token endpoint. Grants: `authorization_code` (with PKCE), `refresh_token` (rotating), `client_credentials`. Form-encoded body per OAuth 2.1."""
    return await _off_loop(request, _form, _token, db)


def _token(request: Request, db: Session, form: dict) -> JSONResponse:
    try:
        grant_type = form.get("grant_type")
        if not grant_type:
            raise OAuthError("invalid_request", "missing grant_type")
        if len(form.get("scope") or "") > oauth.MAX_SCOPE_PARAM:
            raise OAuthError("invalid_scope", "scope is too long")
        if len(form.get("resource") or "") > oauth.MAX_RESOURCE_PARAM:
            raise OAuthError("invalid_target", "resource is too long")
        client = _authenticate_client(request, db, form)
        if grant_type not in client.grant_type_list():
            raise OAuthError("unauthorized_client", f"client may not use grant_type={grant_type}")
        ip = _client_ip(request)

        if grant_type == "authorization_code":
            code, redirect_uri, verifier = form.get("code"), form.get("redirect_uri"), form.get("code_verifier")
            if not code or not redirect_uri:
                raise OAuthError("invalid_request", "missing code / redirect_uri")
            # code_verifier is validated by the grant: mandatory unless the code was issued to a classic client
            body = oauth.authorization_code_grant(
                db, client=client, code=code, redirect_uri=redirect_uri, code_verifier=verifier or "",
                resource=form.get("resource"), ip=ip,
            )
        elif grant_type == "refresh_token":
            refresh = form.get("refresh_token")
            if not refresh:
                raise OAuthError("invalid_request", "missing refresh_token")
            body = oauth.refresh_token_grant(db, client=client, refresh_token=refresh,
                                             requested_scope=form.get("scope"), resource=form.get("resource"), ip=ip)
        elif grant_type == "client_credentials":
            body = oauth.client_credentials_grant(db, client=client, scope=form.get("scope"),
                                                  resource=form.get("resource"), ip=ip)
        else:
            raise OAuthError("unsupported_grant_type", f"unsupported grant_type: {grant_type}")
        return JSONResponse(content=body, headers=NO_STORE)
    except OAuthError as e:
        db.rollback()
        logger.warning(f"/oauth/token {e.error}: {e.description}")
        return _error_json(e)


@router.post("/oauth/revoke")
async def revoke(request: Request, db: Session = Depends(get_db)):
    """Token revocation (RFC 7009). Only tokens issued to the authenticated client are revoked; always returns 200."""
    return await _off_loop(request, _form, _revoke, db)


def _revoke(request: Request, db: Session, form: dict) -> JSONResponse:
    try:
        client = _authenticate_client(request, db, form)
        if form.get("token"):
            oauth.revoke_token(db, client=client, token=form["token"], ip=_client_ip(request))
        return JSONResponse(content={}, status_code=200, headers=NO_STORE)
    except OAuthError as e:
        db.rollback()
        return _error_json(e)


@router.post("/oauth/revoked")
async def revoked_tokens(request: Request, db: Session = Depends(get_db)):
    """Revocation feed for MCP servers that verify JWTs offline: tokens revoked but not yet expired, optionally
    only those revoked since a unix timestamp (`since`). Requires a resource server: a console-registered
    confidential client bound to an MCP server; only that server's tokens are listed."""
    return await _off_loop(request, _form, _revoked_tokens, db)


def _revoked_tokens(request: Request, db: Session, form: dict) -> JSONResponse:
    try:
        caller = _authenticate_client(request, db, form)
        return JSONResponse(content=oauth.revoked_feed(db, caller=caller, since=form.get("since")), headers=NO_STORE)
    except OAuthError as e:
        return _error_json(e)


@router.post("/oauth/usage")
async def usage_report(request: Request, db: Session = Depends(get_db)):
    """Usage report from an MCP server that verifies JWTs offline: `events` is a JSON array of
    {jti, count (1..1,000,000), last_seen}. Feeds the token counters and the dashboard. Requires a resource server
    (a console-registered confidential client bound to an MCP server); other servers' jtis are returned as unknown."""
    return await _off_loop(request, lambda r: _form(r, USAGE_BODY_LIMIT), _usage_report, db)


def _usage_report(request: Request, db: Session, form: dict) -> JSONResponse:
    try:
        caller = _authenticate_client(request, db, form)
        try:
            events = json.loads(form.get("events") or "[]")
        except ValueError:
            raise OAuthError("invalid_request", "events must be JSON")
        return JSONResponse(content=oauth.report_usage(db, caller=caller, events=events, ip=_client_ip(request)),
                            headers=NO_STORE)
    except OAuthError as e:
        db.rollback()
        return _error_json(e)


@router.post("/oauth/introspect")
async def introspect(request: Request, db: Session = Depends(get_db)):
    """Requires client authentication. A client can introspect its own tokens; a resource server (a
    console-registered confidential client bound to an MCP server) can introspect access tokens for that server."""
    return await _off_loop(request, _form, _introspect, db)


def _introspect(request: Request, db: Session, form: dict) -> JSONResponse:
    try:
        caller = _authenticate_client(request, db, form)
        token_value = form.get("token")
        if not token_value:
            return JSONResponse(content={"active": False}, headers=NO_STORE)
        return JSONResponse(content=oauth.introspect_token(db, token_value, caller=caller, ip=_client_ip(request)),
                            headers=NO_STORE)
    except OAuthError as e:
        return _error_json(e)
