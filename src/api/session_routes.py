"""Admin-console login / first-time setup / profile (/api/session/*)."""

from __future__ import annotations

import secrets
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.config import Config
from src.identity import get_current_user, session_manager
from src.identity import service as identity_service
from src.identity.providers import describe_providers, get_enabled_providers
from src.identity.service import IdentityError
from src.logging import get_logger

logger = get_logger("api.session")
router = APIRouter(prefix="/api/session", tags=["Session"])

OAUTH_STATE_COOKIE = "mcp_login_state"


class LoginRequest(BaseModel):
    email: str
    password: str


class SetupRequest(BaseModel):
    email: str
    password: str
    username: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: Optional[str] = None
    new_password: str


class UpdateProfileRequest(BaseModel):
    username: str


def _identity_error(e: IdentityError) -> JSONResponse:
    return JSONResponse(status_code=e.status_code, content={"error": e.code, "params": {}, "message": str(e)})


def _login_response(user: AdminUser, extra: Optional[dict] = None) -> JSONResponse:
    token, expires_at = session_manager.issue(user)
    body = {"user": user.to_dict(), "idle_timeout_minutes": identity_service.session_idle_timeout_minutes()}
    if extra:
        body.update(extra)
    return session_manager.set_cookie(JSONResponse(content=body), token, expires_at)


@router.get("/status")
async def session_status(db: Session = Depends(get_db)):
    """What the login page needs: whether first-time setup is required and which login methods are available."""
    return {
        "needs_setup": identity_service.needs_setup(db),
        "providers": describe_providers(),
        "idle_timeout_minutes": identity_service.session_idle_timeout_minutes(),
    }


@router.post("/setup")
async def setup(request: SetupRequest, http_request: Request, db: Session = Depends(get_db)):
    """First boot: create the owner account and log in directly. Afterwards this endpoint always returns 409."""
    try:
        user = identity_service.setup_owner(db, email=request.email, password=request.password,
                                            username=request.username or "")
    except IdentityError as e:
        return _identity_error(e)
    AuditService.log_from_request(
        db=db, request=http_request, action=AuditAction.ADMIN_SETUP, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(user.id),
        actor_name=user.audit_name,
    )
    return _login_response(user)


@router.post("/login")
async def login(request: LoginRequest, http_request: Request, db: Session = Depends(get_db)):
    """Sign in with email and password; sets the `mcp_session` cookie."""
    try:
        user = identity_service.authenticate_local(db, email=request.email, password=request.password)
    except IdentityError as e:
        AuditService.log_from_request(
            db=db, request=http_request, action=AuditAction.ADMIN_LOGIN, resource_type=ResourceType.ADMIN,
            status=AuditStatus.FAILURE, actor_type=ActorType.ADMIN, actor_name=request.email,
            error_message=str(e),
        )
        return _identity_error(e)
    AuditService.log_from_request(
        db=db, request=http_request, action=AuditAction.ADMIN_LOGIN, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(user.id), actor_name=user.audit_name,
    )
    return _login_response(user)


@router.post("/logout")
async def logout():
    """Clear the session cookie."""
    return session_manager.clear_cookie(JSONResponse(content={"message": "Logged out"}))


@router.get("/me")
async def me(current_user: AdminUser = Depends(get_current_user)):
    """The signed-in user."""
    return {
        **current_user.to_dict(),
        "idle_timeout_minutes": identity_service.session_idle_timeout_minutes(),
    }


@router.put("/me/profile")
async def update_profile(request: UpdateProfileRequest, db: Session = Depends(get_db),
                         current_user: AdminUser = Depends(get_current_user)):
    """Change the display name of the signed-in user."""
    try:
        user = identity_service.update_profile(db, current_user, username=request.username)
    except IdentityError as e:
        return _identity_error(e)
    return user.to_dict()


@router.put("/me/password")
async def change_password(request: ChangePasswordRequest, http_request: Request, db: Session = Depends(get_db),
                          current_user: AdminUser = Depends(get_current_user)):
    """After a password change every old session is invalidated; the response also sets a new session cookie."""
    try:
        identity_service.change_password(db, current_user, current_password=request.current_password,
                                         new_password=request.new_password)
    except IdentityError as e:
        return _identity_error(e)
    AuditService.log_from_request(
        db=db, request=http_request, action=AuditAction.ADMIN_UPDATE, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(current_user.id),
        actor_name=current_user.audit_name, details={"action": "change_password"},
    )
    return _login_response(current_user, {"message": "Password changed"})


# ---------------------------------------------------------------------------
# Third-party login (GitHub / Google)
# ---------------------------------------------------------------------------
def _callback_url(provider: str) -> str:
    return f"{Config.get_oauth_config().issuer.rstrip('/')}/api/session/oauth/{provider}/callback"


def _safe_next(raw: Optional[str]) -> str:
    if not raw or not raw.startswith("/") or raw.startswith("//") or raw.startswith("/\\"):
        return "/"
    return raw


@router.get("/oauth/{provider}/start")
async def oauth_login_start(provider: str, next: Optional[str] = None):
    """Begin GitHub / Google sign-in: redirects to the provider with a CSRF state cookie."""
    providers = get_enabled_providers()
    if provider not in providers:
        raise HTTPException(status_code=404, detail={"error": "auth.provider_not_enabled",
                                                     "fallback": "Login provider not enabled"})
    state = secrets.token_urlsafe(24)
    url = providers[provider].authorize_url(state=state, redirect_uri=_callback_url(provider))
    response = RedirectResponse(url=url, status_code=302)
    sec = Config.get_security_config()
    response.set_cookie(
        key=OAUTH_STATE_COOKIE, value=f"{state}|{_safe_next(next)}", httponly=True,
        samesite="lax", secure=sec.secure_cookie, max_age=600, path="/api/session/oauth",
    )
    return response


@router.get("/oauth/{provider}/callback")
async def oauth_login_callback(provider: str, request: Request, db: Session = Depends(get_db),
                               code: Optional[str] = None, state: Optional[str] = None,
                               error: Optional[str] = None):
    """Provider callback: validates state, links or creates the account, sets the session cookie and redirects into the console."""
    providers = get_enabled_providers()
    if provider not in providers:
        raise HTTPException(status_code=404, detail={"error": "auth.provider_not_enabled",
                                                     "fallback": "Login provider not enabled"})
    raw_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
    expected_state, _, next_path = raw_state.partition("|")
    next_path = _safe_next(next_path)

    def fail(code_: str) -> RedirectResponse:
        return RedirectResponse(url=f"/login?{urlencode({'error': code_})}", status_code=302)

    if error or not code or not state or not expected_state or not secrets.compare_digest(state, expected_state):
        return fail("auth.external_login_failed")
    try:
        identity = await providers[provider].exchange(code=code, redirect_uri=_callback_url(provider))
        user = identity_service.login_external(db, identity)
    except IdentityError as e:
        return fail(e.code)
    except Exception as e:
        logger.warning(f"{provider} login failed: {e}")
        return fail("auth.external_login_failed")

    AuditService.log_from_request(
        db=db, request=request, action=AuditAction.ADMIN_LOGIN, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(user.id),
        actor_name=user.audit_name, details={"provider": provider},
    )
    token, expires_at = session_manager.issue(user)
    response = RedirectResponse(url=next_path, status_code=302)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/session/oauth")
    return session_manager.set_cookie(response, token, expires_at)
