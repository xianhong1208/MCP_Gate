"""Console sessions are revocable server-side.

* Logout used to only clear the cookie: a copied cookie stayed valid for its full 12 hours (and logout was
  not audited).
* A password change compared integer-second ``iat`` with ``password_changed_at``, so a session issued in the
  same second as the change survived it.
* ``clear_cookie`` dropped the ``Secure`` attribute, so with ``SameSite=None`` the browser ignored the
  deletion and kept the cookie.
"""
import asyncio
from datetime import timedelta

import jwt
import pytest

from src.identity.session import SESSION_BINDING_HEADER
from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD, make_console_client


def _session(client, response=None):
    """(cookie, binding) of the client's current session, or of the one a login response just issued."""
    if response is not None:
        return response.cookies.get("mcp_session"), response.json()["session_binding"]
    return client.cookies.get("mcp_session"), client.headers.get(SESSION_BINDING_HEADER)


def _me_status(client, session):
    cookie, binding = session
    client.cookies.clear()
    client.cookies.set("mcp_session", cookie)
    return client.get("/api/session/me", headers={SESSION_BINDING_HEADER: binding or ""}).status_code


def test_logout_revokes_the_session_server_side(owner_client):
    cookie = _session(owner_client)
    assert _me_status(owner_client, cookie) == 200
    assert owner_client.post("/api/session/logout").status_code == 200
    # Replaying the copied cookie after logout must fail
    assert _me_status(owner_client, cookie) == 401


def test_logout_is_audited(owner_client, db_session):
    from db.models import AuditLog

    owner_client.post("/api/session/logout")
    actions = [a.action for a in db_session.query(AuditLog).all()]
    assert "admin_logout" in actions


def test_logout_only_revokes_its_own_session(client, owner_client):
    first = _session(owner_client)
    with make_console_client(client.app) as other:
        assert other.post("/api/session/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD}).status_code == 200
        second = _session(other)
        assert other.post("/api/session/logout").status_code == 200
    assert _me_status(owner_client, second) == 401
    assert _me_status(owner_client, first) == 200


def test_password_change_in_the_same_second_revokes_older_sessions(client, owner_client, monkeypatch):
    """Every session, and the password change, happen at the very same instant (the clock is frozen)."""
    from datetime import datetime

    import db.crud
    import db.models

    frozen = datetime.now()  # after the setup above; the logins and the change below all share this instant
    for mod in (db.crud, db.models):
        monkeypatch.setattr(mod, "local_now", lambda: frozen)
    owner_client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})

    old_cookie = _session(owner_client)
    with make_console_client(client.app) as other:
        other.post("/api/session/login", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
        other_cookie = _session(other)
    r = owner_client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                           "new_password": "new-password-456"})
    assert r.status_code == 200
    new_cookie = _session(owner_client, r)
    assert new_cookie[0] and new_cookie != old_cookie
    assert _me_status(owner_client, old_cookie) == 401
    assert _me_status(owner_client, other_cookie) == 401
    assert _me_status(owner_client, new_cookie) == 200


def test_tz_change_after_a_password_change_does_not_lock_the_owner_out(owner_client):
    """password_changed_at is naive local time. If the server restarts with a TZ further west, "now" is
    earlier than that stored value; sessions issued then must not look revoked (was: login 200, /me 401)."""
    from datetime import datetime, timedelta

    r = owner_client.put("/api/session/me/password", json={"current_password": OWNER_PASSWORD,
                                                           "new_password": "new-password-456"})
    assert r.status_code == 200
    # Simulate: the change was recorded under a TZ 8 h further east than the one the server now runs in
    from db.database import make_session
    from db.models import AdminUser
    s = make_session()
    try:
        user = s.query(AdminUser).first()
        user.password_changed_at = datetime.now() + timedelta(hours=8)
        s.commit()
    finally:
        s.close()
    login = owner_client.post("/api/session/login", json={"email": OWNER_EMAIL, "password": "new-password-456"})
    assert login.status_code == 200
    assert _me_status(owner_client, _session(owner_client, login)) == 200


def test_a_validly_signed_session_without_a_server_record_is_refused(owner_client):
    """A session JWT signed with the right key but unknown to the server (forged after a key leak, or issued
    by a version without the session table) does not authenticate."""
    from src.identity import session_manager

    cookie, binding = _session(owner_client)
    claims = jwt.decode(cookie, options={"verify_signature": False})
    claims["jti"] = "00000000-0000-0000-0000-000000000000"
    forged = jwt.encode(claims, session_manager.secret, algorithm="HS256")
    assert _me_status(owner_client, (forged, binding)) == 401


def test_expired_session_records_are_purged(owner_client, db_session):
    from db.models import AdminSession, utc_now
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    live = db_session.query(AdminSession).count()
    assert live == 1
    row = db_session.query(AdminSession).first()
    row.expires_at = utc_now() - timedelta(minutes=1)
    db_session.commit()
    assert asyncio.run(CleanupScheduler()._cleanup_oauth()) >= 1
    db_session.expire_all()
    assert db_session.query(AdminSession).count() == 0


@pytest.mark.parametrize("samesite", ["none", "lax", "strict"])
def test_clear_cookie_mirrors_the_attributes_it_was_set_with(samesite):
    from fastapi.responses import Response

    from src.config import Config
    from src.identity.session import SessionManager

    sec = Config.get_security_config()
    saved = (sec.secure_cookie, sec.cookie_samesite)
    sec.secure_cookie, sec.cookie_samesite = True, samesite
    try:
        header = SessionManager.clear_cookie(Response()).headers["set-cookie"].lower()
    finally:
        sec.secure_cookie, sec.cookie_samesite = saved
    assert "mcp_session=" in header and "max-age=0" in header
    assert "secure" in header and f"samesite={samesite}" in header and "path=/" in header and "httponly" in header
