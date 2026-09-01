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

from typing import List, Optional
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser
from src.identity import get_current_user, get_optional_current_user
from src.logging import get_logger
from src.oauth import service as oauth
from src.oauth.errors import OAuthError
from src.oauth.signing_keys import get_jwks

logger = get_logger("oauth")
router = APIRouter(tags=["OAuth 2.1"])

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _error_json(err: OAuthError) -> JSONResponse:
    headers = dict(NO_STORE)
    if err.error == "invalid_client":
        headers["WWW-Authenticate"] = 'Basic realm="oauth"'
    return JSONResponse(status_code=err.status_code, content=err.to_dict(), headers=headers)


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


async def _form(request: Request) -> dict:
    """application/x-www-form-urlencoded (per the OAuth spec) -- parsed by hand, no python-multipart needed."""
    raw = (await request.body()).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(raw).items() if v}


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/openid-configuration")
async def authorization_server_metadata(db: Session = Depends(get_db)):
    """Authorization server metadata (RFC 8414). Lists every OAuth endpoint, supported grants, PKCE methods and scopes. Public."""
    return JSONResponse(content=oauth.build_metadata(db), headers={"Cache-Control": "public, max-age=300"})


@router.get("/.well-known/jwks.json")
async def jwks(db: Session = Depends(get_db)):
    """Public signing keys (JWKS). MCP servers fetch these to verify tokens offline; includes retired keys so older tokens still verify. Public."""
    return JSONResponse(content=get_jwks(db), headers={"Cache-Control": "public, max-age=300"})


# ---------------------------------------------------------------------------
# dynamic client registration
# ---------------------------------------------------------------------------
@router.post("/oauth/register", status_code=201)
async def register(request: Request, db: Session = Depends(get_db)):
    """Dynamic client registration (RFC 7591). Returns a client_id (and a one-time client_secret for confidential clients). Public."""
    try:
        try:
            metadata = await request.json()
        except Exception:
            raise OAuthError("invalid_client_metadata", "request body must be a JSON object")
        client, secret = oauth.register_client(db, metadata, created_via="dcr")
        logger.info(f"DCR: registered client {client.client_id} ({client.client_name}) approved={client.is_approved}")
        return JSONResponse(status_code=201, content=oauth.registration_response(client, secret), headers=NO_STORE)
    except OAuthError as e:
        db.rollback()
        return _error_json(e)


# ---------------------------------------------------------------------------
# authorization endpoint + consent
# ---------------------------------------------------------------------------
@router.get("/oauth/authorize")
async def authorize(
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
    user: Optional[AdminUser] = Depends(get_optional_current_user),
):
    """Validate params -> persist the authorization request -> issue the code directly (logged in and consent may be
    skipped), otherwise redirect to /consent."""
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

    if user is not None:
        info = oauth.describe_request(db, req, user)
        if info["can_skip"]:
            return RedirectResponse(url=oauth.approve_request(db, req, user), status_code=302)
    return RedirectResponse(url=f"/consent?{urlencode({'rid': req.id})}", status_code=302)


@router.get("/oauth/authorize/requests/{request_id}")
async def get_authorization_request(request_id: str, db: Session = Depends(get_db),
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
async def decide_authorization_request(request_id: str, body: DecisionRequest, db: Session = Depends(get_db),
                                       user: AdminUser = Depends(get_current_user)):
    """Approve or deny a pending authorization request. On approval an authorization code is issued; returns the URL to send the browser back to. Requires a console session."""
    try:
        req = oauth.get_pending_request(db, request_id)
    except OAuthError as e:
        return _error_json(e)
    if body.approve:
        url = oauth.approve_request(db, req, user, granted_scopes=body.scopes, remember=body.remember)
        logger.info(f"consent granted: client={req.client_id} user={user.email} aud={req.resource}")
    else:
        url = oauth.deny_request(db, req)
        logger.info(f"consent denied: client={req.client_id} user={user.email}")
    return {"redirect_to": url}


# ---------------------------------------------------------------------------
# token / revoke / introspect
# ---------------------------------------------------------------------------
@router.post("/oauth/token")
async def token(request: Request, db: Session = Depends(get_db)):
    """Token endpoint. Grants: `authorization_code` (with PKCE), `refresh_token` (rotating), `client_credentials`. Form-encoded body per OAuth 2.1."""
    try:
        form = await _form(request)
        grant_type = form.get("grant_type")
        if not grant_type:
            raise OAuthError("invalid_request", "missing grant_type")
        client = oauth.authenticate_client(db, authorization_header=request.headers.get("Authorization", ""), form=form)
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
    try:
        form = await _form(request)
        client = oauth.authenticate_client(db, authorization_header=request.headers.get("Authorization", ""), form=form)
        if form.get("token"):
            oauth.revoke_token(db, client=client, token=form["token"], ip=_client_ip(request))
        return JSONResponse(content={}, status_code=200, headers=NO_STORE)
    except OAuthError as e:
        db.rollback()
        return _error_json(e)


@router.post("/oauth/introspect")
async def introspect(request: Request, db: Session = Depends(get_db)):
    """Requires client authentication. A public client can only introspect its own tokens; a confidential client
    (resource server) can introspect any token."""
    try:
        form = await _form(request)
        caller = oauth.authenticate_client(db, authorization_header=request.headers.get("Authorization", ""), form=form)
        token_value = form.get("token")
        if not token_value:
            return JSONResponse(content={"active": False}, headers=NO_STORE)
        return JSONResponse(content=oauth.introspect_token(db, token_value, caller=caller, ip=_client_ip(request)),
                            headers=NO_STORE)
    except OAuthError as e:
        return _error_json(e)
