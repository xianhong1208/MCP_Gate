"""Admin-console login / first-time setup / profile (/api/session/*)."""

from __future__ import annotations

import secrets
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
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
    return JSONResponse(status_code=e.status_code, content={"error": e.code, "params": e.params, "message": str(e)})


def _login_response(db: Session, user: AdminUser, extra: Optional[dict] = None) -> JSONResponse:
    issued = session_manager.issue(db, user)
    body = {
        "user": user.to_dict(), "idle_timeout_minutes": identity_service.session_idle_timeout_minutes(),
        # The second half of the session: the console keeps it in localStorage and sends it as X-Session-Binding
        "session_binding": issued.binding,
    }
    if extra:
        body.update(extra)
    return session_manager.set_cookie(JSONResponse(content=body), issued.token, issued.expires_at)


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
        # bcrypt (rounds=12) takes ~0.25 s of CPU: keep it off the event loop
        user = await run_in_threadpool(identity_service.setup_owner, db, email=request.email,
                                       password=request.password, username=request.username or "")
    except IdentityError as e:
        return _identity_error(e)
    AuditService.log_from_request(
        db=db, request=http_request, action=AuditAction.ADMIN_SETUP, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(user.id),
        actor_name=user.audit_name,
    )
    return _login_response(db, user)


@router.post("/login")
async def login(request: LoginRequest, http_request: Request, db: Session = Depends(get_db)):
    """Sign in with email and password; sets the `mcp_session` cookie."""
    try:
        # bcrypt verification is deliberately slow; on the event loop a login burst would stall every request
        user = await run_in_threadpool(identity_service.authenticate_local, db, email=request.email,
                                       password=request.password)
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
    return _login_response(db, user)


@router.post("/logout")
async def logout(http_request: Request, db: Session = Depends(get_db)):
    """End the session server-side (a copied cookie stops working too) and clear the cookie."""
    payload = session_manager.revoke(db, session_manager.token_from_request(http_request),
                                     session_manager.binding_from_request(http_request))
    if payload is not None:
        AuditService.log_from_request(
            db=db, request=http_request, action=AuditAction.ADMIN_LOGOUT, resource_type=ResourceType.ADMIN,
            status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=payload.user_id,
            actor_name=payload.email,
        )
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
        await run_in_threadpool(identity_service.change_password, db, current_user,
                                current_password=request.current_password, new_password=request.new_password)
    except IdentityError as e:
        return _identity_error(e)
    AuditService.log_from_request(
        db=db, request=http_request, action=AuditAction.ADMIN_UPDATE, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(current_user.id),
        actor_name=current_user.audit_name, details={"action": "change_password"},
    )
    # change_password deleted every session of this account (including any issued earlier within the same second)
    return _login_response(db, current_user, {"message": "Password changed"})


# ---------------------------------------------------------------------------
# Third-party login (GitHub / Google)
# ---------------------------------------------------------------------------
def _callback_url(provider: str) -> str:
    return f"{Config.get_oauth_config().issuer.rstrip('/')}/api/session/oauth/{provider}/callback"


def _safe_next(raw: Optional[str]) -> str:
    if not raw or not raw.startswith("/") or raw.startswith("//") or raw.startswith("/\\"):
        return "/"
    return raw


# Ours are secrets.token_urlsafe(24) (32 characters); anything far longer is not one of ours
_MAX_STATE_LENGTH = 128


def _state_matches(state: Optional[str], expected: str) -> bool:
    """Constant-time comparison of the callback ``state`` with the cookie's. compare_digest raises TypeError on a
    non-ASCII str (that was a 500), so both sides are compared as UTF-8 bytes, and over-long input is refused."""
    if not state or not expected or len(state) > _MAX_STATE_LENGTH:
        return False
    return secrets.compare_digest(state.encode("utf-8"), expected.encode("utf-8"))


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

    if error or not code or not _state_matches(state, expected_state):
        return fail("auth.external_login_failed")
    try:
        identity = None
        identity = await providers[provider].exchange(code=code, redirect_uri=_callback_url(provider))
        user = identity_service.login_external(db, identity)
    except IdentityError as e:
        AuditService.log_from_request(
            db=db, request=request, action=AuditAction.ADMIN_LOGIN, resource_type=ResourceType.ADMIN,
            status=AuditStatus.FAILURE, actor_type=ActorType.ADMIN, actor_name=identity.email if identity else None,
            error_message=str(e), details={"provider": provider, "error": e.code},
        )
        return fail(e.code)
    except Exception as e:
        logger.warning(f"{provider} login failed: {e}")
        return fail("auth.external_login_failed")

    AuditService.log_from_request(
        db=db, request=request, action=AuditAction.ADMIN_LOGIN, resource_type=ResourceType.ADMIN,
        status=AuditStatus.SUCCESS, actor_type=ActorType.ADMIN, actor_id=str(user.id),
        actor_name=user.audit_name,
        details={"provider": provider, **({"linked_provider_account": identity.sub} if identity.linked else {})},
    )
    issued = session_manager.issue(db, user)
    # No response body to carry the session binding here: it rides in the fragment, which the browser keeps on the
    # console's own origin (never sent to a server, not even this one); the console moves it into localStorage.
    response = RedirectResponse(url=f"{next_path.partition('#')[0]}#{urlencode({'mcp_sb': issued.binding})}",
                                status_code=302)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/session/oauth")
    return session_manager.set_cookie(response, issued.token, issued.expires_at)
