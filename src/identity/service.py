"""Login / first-time setup / password change / third-party account mapping (HTTP-agnostic business logic)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from db.models import AdminUser
from src.adapters import AdminSessionAdapter, AdminUserAdapter
from src.adapters.exceptions import AdapterError
from src.config import Config
from src.identity.passwords import (
    hash_password, password_error_message, validate_password_strength, verify_password,
)
from src.identity.providers.base import ExternalIdentity
from src.utils.field_limits import FieldTooLongError, check_max_length, clip, column_limit


class IdentityError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400, params: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.params = params or {}


def _check_length(field: str, value: Optional[str], column) -> Optional[str]:
    try:
        return check_max_length(field, value, column_limit(column))
    except FieldTooLongError as e:
        raise IdentityError(e.code, e.fallback, params=e.params)


def needs_setup(db: Session) -> bool:
    """No account exists yet -> the owner must be created via /setup."""
    return AdminUserAdapter.get_count(db, include_inactive=True) == 0


def setup_owner(db: Session, *, email: str, password: str, username: str = "owner") -> AdminUser:
    """Create the owner. Atomic: the early needs_setup() check only spares the bcrypt work; the account takes the
    unique owner slot, so of several concurrent calls exactly one succeeds and the others get 409."""
    if not needs_setup(db):
        raise IdentityError("auth.setup_already_done", "Setup already completed", 409)
    email = _normalize_email(email)
    username = (username or "").strip()
    _check_length("username", username, AdminUser.username)
    err = validate_password_strength(password)
    if err:
        raise IdentityError(err, password_error_message(err))
    password_hash = hash_password(password)
    try:
        return AdminUserAdapter.create(
            db, email=email, username=username or _default_username(email),
            password_hash=password_hash, auth_provider="local", owner=True,
        )
    except AdapterError as e:
        raise IdentityError("auth.setup_already_done" if e.code == "auth.setup_already_done" else e.code,
                            e.fallback, 409)


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

    Steps (2) and (3) trust the email, so they require the provider to have verified it: anyone can put any
    address on a GitHub profile or an unverified Google account, and linking on that would hand them the
    matching console account (the owner's). An unverified match is refused, not silently treated as "new".
    """
    user = AdminUserAdapter.get_by_provider(db, identity.provider, identity.sub)
    if user is None and identity.email:
        user = AdminUserAdapter.get_by_email(db, identity.email)
        if user is not None:
            if not identity.email_verified:
                raise IdentityError("auth.external_email_unverified",
                                    "The provider has not verified this email address", 403)
            AdminUserAdapter.link_provider(db, user, identity.provider, identity.sub)
            identity.linked = True
    if user is None:
        allowed = {e.strip().lower() for e in Config.get_identity_config().allowed_emails if e.strip()}
        if not identity.email or identity.email not in allowed or not identity.email_verified:
            raise IdentityError("auth.external_not_allowed",
                                "This account is not allowed to sign in", 403)
        # The display name comes from the provider profile: shorten it rather than refuse the sign-in
        user = AdminUserAdapter.create(
            db, email=identity.email,
            username=clip(identity.name, column_limit(AdminUser.username)) or _default_username(identity.email),
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
        raise IdentityError(err, password_error_message(err))
    AdminUserAdapter.set_password(db, user, hash_password(new_password))
    # Every existing session of this account ends now; the caller issues a fresh one for the current browser
    AdminSessionAdapter.delete_for_user(db, user.id)


def update_profile(db: Session, user: AdminUser, *, username: str) -> AdminUser:
    username = (username or "").strip()
    if not username:
        raise IdentityError("auth.validation_username_required", "Username is required")
    _check_length("username", username, AdminUser.username)
    return AdminUserAdapter.update_profile(db, user, username=username)


def _default_username(email: str) -> str:
    return email.split("@")[0][:column_limit(AdminUser.username)]


def _normalize_email(email: str) -> str:
    value = (email or "").strip().lower()
    if "@" not in value or "." not in value.split("@")[-1]:
        raise IdentityError("auth.validation_email_invalid", "A valid email address is required")
    return _check_length("email", value, AdminUser.email)


def session_idle_timeout_minutes() -> int:
    return Config.get_session_config().idle_timeout_minutes

