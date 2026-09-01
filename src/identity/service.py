"""Login / first-time setup / password change / third-party account mapping (HTTP-agnostic business logic)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from db.models import AdminUser
from src.adapters import AdminUserAdapter
from src.config import Config
from src.identity.passwords import hash_password, validate_password_strength, verify_password
from src.identity.providers.base import ExternalIdentity


class IdentityError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def needs_setup(db: Session) -> bool:
    """No account exists yet -> the owner must be created via /setup."""
    return AdminUserAdapter.get_count(db, include_inactive=True) == 0


def setup_owner(db: Session, *, email: str, password: str, username: str = "owner") -> AdminUser:
    if not needs_setup(db):
        raise IdentityError("auth.setup_already_done", "Setup already completed", 409)
    email = _normalize_email(email)
    err = validate_password_strength(password)
    if err:
        raise IdentityError(err, "Password too short")
    return AdminUserAdapter.create(
        db, email=email, username=username or email.split("@")[0],
        password_hash=hash_password(password), auth_provider="local",
    )


def authenticate_local(db: Session, *, email: str, password: str) -> AdminUser:
    if not Config.get_identity_config().local_enabled:
        raise IdentityError("auth.local_login_disabled", "Password login is disabled", 403)
    user = AdminUserAdapter.get_by_email(db, _normalize_email(email))
    if not user or not verify_password(password, user.password_hash):
        raise IdentityError("auth.invalid_credentials", "Invalid email or password", 401)
    if not user.is_active:
        raise IdentityError("auth.account_disabled", "Account disabled", 403)
    AdminUserAdapter.touch_login(db, user)
    return user


def login_external(db: Session, identity: ExternalIdentity) -> AdminUser:
    """Third-party login -> map to a local account.

    Order: (1) existing account with the same provider+sub, (2) existing account with the same email (auto-linked),
    (3) email on the allowed_emails allowlist -> auto-create; otherwise reject.
    """
    user = AdminUserAdapter.get_by_provider(db, identity.provider, identity.sub)
    if user is None and identity.email:
        user = AdminUserAdapter.get_by_email(db, identity.email)
        if user is not None:
            AdminUserAdapter.link_provider(db, user, identity.provider, identity.sub)
    if user is None:
        allowed = {e.strip().lower() for e in Config.get_identity_config().allowed_emails if e.strip()}
        if not identity.email or identity.email not in allowed or not identity.email_verified:
            raise IdentityError("auth.external_not_allowed",
                                "This account is not allowed to sign in", 403)
        user = AdminUserAdapter.create(
            db, email=identity.email, username=identity.name or identity.email.split("@")[0],
            password_hash=None, auth_provider=identity.provider, provider_sub=identity.sub,
        )
    if not user.is_active:
        raise IdentityError("auth.account_disabled", "Account disabled", 403)
    AdminUserAdapter.touch_login(db, user)
    return user


def change_password(db: Session, user: AdminUser, *, current_password: Optional[str], new_password: str) -> None:
    if user.password_hash and not verify_password(current_password or "", user.password_hash):
        raise IdentityError("auth.invalid_current_password", "Current password is incorrect", 400)
    err = validate_password_strength(new_password)
    if err:
        raise IdentityError(err, "Password too short")
    AdminUserAdapter.set_password(db, user, hash_password(new_password))


def update_profile(db: Session, user: AdminUser, *, username: str) -> AdminUser:
    username = (username or "").strip()
    if not username:
        raise IdentityError("auth.validation_username_required", "Username is required")
    return AdminUserAdapter.update_profile(db, user, username=username)


def _normalize_email(email: str) -> str:
    value = (email or "").strip().lower()
    if "@" not in value or "." not in value.split("@")[-1]:
        raise IdentityError("auth.validation_email_invalid", "A valid email address is required")
    return value


def session_idle_timeout_minutes() -> int:
    return Config.get_session_config().idle_timeout_minutes

