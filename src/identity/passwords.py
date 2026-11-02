"""Password hashing (bcrypt)."""

import bcrypt

MIN_PASSWORD_LENGTH = 8
# bcrypt only reads the first 72 bytes of its input; bcrypt >= 4.1 raises ValueError beyond that.
MAX_PASSWORD_BYTES = 72

_MESSAGES = {
    "auth.validation_password_short": f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
    "auth.validation_password_too_long": (
        f"Password is too long (max {MAX_PASSWORD_BYTES} bytes, about 24 Chinese characters)"),
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def check_password_length(password: str) -> str | None:
    """Reject passwords bcrypt cannot hash: longer than 72 bytes once encoded as UTF-8.

    The limit is in bytes, not characters. ASCII is one byte per character, but most CJK characters
    take three bytes in UTF-8, so a Traditional Chinese password reaches the limit at 24 characters
    (25 characters = 75 bytes is rejected). The bcrypt version we pin raises ValueError above 72 bytes
    instead of truncating, which surfaced as a 500 on setup and change-password.

    Returns the error code ``auth.validation_password_too_long`` or None.
    """
    if len((password or "").encode("utf-8")) > MAX_PASSWORD_BYTES:
        return "auth.validation_password_too_long"
    return None


def validate_password_strength(password: str) -> str | None:
    """Returns an error code (i18n key) or None. Every path that hashes a new password calls this first."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return "auth.validation_password_short"
    return check_password_length(password)


def password_error_message(code: str) -> str:
    """English fallback text for an error code returned by validate_password_strength."""
    return _MESSAGES.get(code, "Invalid password")
