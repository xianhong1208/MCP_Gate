"""Passwords longer than bcrypt's 72-byte limit are rejected with a clear error, not a 500.

bcrypt 5 raises ValueError above 72 bytes; hash_password did not catch it, so /api/session/setup and
/api/session/me/password returned 500. The limit is in UTF-8 bytes: 24 Chinese characters fit, 25 do not.
"""
import pytest

from src.identity.passwords import (
    MAX_PASSWORD_BYTES, check_password_length, hash_password, validate_password_strength, verify_password,
)
from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD, SETUP_TOKEN

TOO_LONG = "auth.validation_password_too_long"

ASCII_72 = "a" * 72
ASCII_73 = "a" * 73
CJK_24 = "密" * 24  # 72 bytes
CJK_25 = "密" * 25  # 75 bytes


def test_limit_is_in_bytes():
    assert MAX_PASSWORD_BYTES == 72
    assert len(CJK_24.encode("utf-8")) == 72 and len(CJK_25.encode("utf-8")) == 75


@pytest.mark.parametrize("password", [ASCII_73, CJK_25, "a" * 70 + "密"])  # 70 + 3 = 73 bytes
def test_over_72_bytes_is_rejected(password):
    assert check_password_length(password) == TOO_LONG
    assert validate_password_strength(password) == TOO_LONG


@pytest.mark.parametrize("password", [ASCII_72, CJK_24, "a" * 69 + "密"])  # 69 + 3 = 72 bytes
def test_up_to_72_bytes_is_accepted(password):
    assert check_password_length(password) is None
    assert validate_password_strength(password) is None
    assert verify_password(password, hash_password(password))


def test_short_password_is_still_reported_first():
    assert validate_password_strength("short") == "auth.validation_password_short"


@pytest.mark.parametrize("password, status", [(ASCII_73, 400), (CJK_25, 400), (ASCII_72, 200), (CJK_24, 200)])
def test_setup(client, password, status):
    r = client.post("/api/session/setup", json={"setup_token": SETUP_TOKEN, "email": OWNER_EMAIL, "password": password})
    assert r.status_code == status, r.text
    if status == 400:
        assert r.json()["error"] == TOO_LONG


@pytest.mark.parametrize("password, status", [(ASCII_73, 400), (CJK_25, 400), (ASCII_72, 200), (CJK_24, 200)])
def test_change_password(owner_client, password, status):
    r = owner_client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                           "new_password": password})
    assert r.status_code == status, r.text
    if status == 400:
        assert r.json()["error"] == TOO_LONG


@pytest.mark.parametrize("password, created", [(ASCII_73, False), (CJK_25, False), (CJK_24, True), ("short", False)])
def test_env_bootstrap(db_session, password, created):
    """ADMIN_PASSWORD goes through the same policy; a bad one is skipped (owner via /setup), startup goes on."""
    from db.seed import seed_owner

    user = seed_owner(db_session, OWNER_EMAIL, password)
    assert (user is not None) is created
    if created:
        assert verify_password(password, user.password_hash)
