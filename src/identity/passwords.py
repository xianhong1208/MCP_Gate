"""Password hashing (bcrypt)."""

import bcrypt

MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def validate_password_strength(password: str) -> str | None:
    """Returns an error code (i18n key) or None."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return "auth.validation_password_short"
    return None
