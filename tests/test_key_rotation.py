"""#30: signing keys rotate on a publish-then-activate schedule, retire safely and can be revoked in an emergency.

- A rotation (automatic every 90 days, or "Rotate now") publishes the new key in the JWKS a day before it signs.
- A retired key is verify-only until every token it signed has expired (``signed_until``, raised with each recorded
  token; PATs live up to 365 days), then it is deleted.
- "Revoke key" drops it from the JWKS at once, revokes the tokens it signed and says how many.
"""

from datetime import datetime, timedelta

import jwt
import pytest

from tests.conftest import rotate_and_activate
from tests.test_oauth_flow import RESOURCE, _authorize_and_consent, _exchange, _register


def _kids(client):
    return {k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]}


def _keys(client):
    return {k["kid"]: k for k in client.get("/api/oauth/keys").json()["keys"]}


def _pat(client, service, days=30, label="rot"):
    r = client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": days,
                                                        "label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _kid(token):
    return jwt.get_unverified_header(token)["kid"]


def _key(db_session, kid):
    from db.models import OAuthSigningKey

    db_session.expire_all()
    return db_session.query(OAuthSigningKey).filter(OAuthSigningKey.kid == kid).one_or_none()


def _shift(db_session, kid, **deltas):
    """Move a key's timestamps (e.g. rotated_at=-60 minutes) as if time had passed."""
    from src.utils import public_cache

    key = _key(db_session, kid)
    for field, minutes in deltas.items():
        setattr(key, field, getattr(key, field) + timedelta(minutes=minutes))
    db_session.commit()
    public_cache.invalidate()


def _active_kid(client):
    return next(k for k, v in _keys(client).items() if v["is_active"])


# ---------------------------------------------------------------------------
# publish first, then sign
# ---------------------------------------------------------------------------
def test_rotate_now_publishes_before_signing(owner_client, service, db_session):
    """TC-KROT-01: "Rotate now" puts the new key in the JWKS at once, but tokens keep the old kid for a day."""
    old = _active_kid(owner_client)
    r = owner_client.post("/api/oauth/keys/rotate")
    assert r.status_code == 200, r.text
    new = r.json()["kid"]

    assert _kids(owner_client) == {old, new}
    keys = _keys(owner_client)
    assert keys[new]["is_pending"] and not keys[new]["is_active"] and keys[old]["is_active"]
    starts = datetime.fromisoformat(keys[new]["activates_at"])
    assert timedelta(hours=23, minutes=59) < starts - datetime.fromisoformat(keys[new]["created_at"]) \
        <= timedelta(hours=24, seconds=5)
    assert _kid(_pat(owner_client, service)["access_token"]) == old
    # Published for the whole window, not only for a retired key's grace period
    _shift(db_session, new, created_at=-12 * 60)
    assert new in _kids(owner_client)


def test_second_rotation_while_one_is_published_is_refused(owner_client):
    """TC-KROT-02: one published key at a time: 409 oauth.key_rotation_pending naming when it starts."""
    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    r = owner_client.post("/api/oauth/keys/rotate")
    assert r.status_code == 409
    body = r.json()["detail"]
    assert body["error"] == "oauth.key_rotation_pending" and body["params"]["activates_at"]
    assert len(_keys(owner_client)) == 2


def test_published_key_takes_over_at_its_time(owner_client, service, db_session):
    """TC-KROT-03: once activates_at has passed, the next token is signed by the new key; the old one is retired
    but still published, and a token it signed still verifies against the JWKS."""
    old_pat = _pat(owner_client, service)
    old = _kid(old_pat["access_token"])
    new = owner_client.post("/api/oauth/keys/rotate").json()["kid"]
    _shift(db_session, new, activates_at=-24 * 60 - 1)

    pat = _pat(owner_client, service)
    assert _kid(pat["access_token"]) == new
    logs = owner_client.get("/api/audit/logs", params={"action": "oauth_key_activate"}).json()["logs"]
    assert [entry["resource_id"] for entry in logs] == [new]
    keys = _keys(owner_client)
    assert keys[new]["is_active"] and not keys[old]["is_active"] and keys[old]["rotated_at"]
    assert keys[old]["published"] and _kids(owner_client) == {old, new}
    jwks = {k["kid"]: k for k in owner_client.get("/.well-known/jwks.json").json()["keys"]}
    key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks[old])
    assert jwt.decode(old_pat["access_token"], key, algorithms=["RS256"], audience=RESOURCE)["jti"] == old_pat["jti"]


def test_zero_prepublish_window_activates_at_once(owner_client, service, monkeypatch):
    """TC-KROT-04: signing_key_prepublish_minutes = 0 means rotate and sign at once (the pre-#30 behaviour)."""
    from src.config import Config

    monkeypatch.setattr(Config.get_oauth_config(), "signing_key_prepublish_minutes", 0)
    new = owner_client.post("/api/oauth/keys/rotate").json()["kid"]
    assert _keys(owner_client)[new]["is_active"]
    assert _kid(_pat(owner_client, service)["access_token"]) == new


def test_grant_in_progress_never_switches_keys(owner_client, db_session):
    """TC-KROT-05: inside a grant's transaction (commit=False) the current signer is used even if a published key
    is due -- promoting it would commit the grant half-way; the next standalone issuance switches."""
    from src.oauth import service as oauth

    old = _active_kid(owner_client)
    new = owner_client.post("/api/oauth/keys/rotate").json()["kid"]
    _shift(db_session, new, activates_at=-24 * 60 - 1)
    token, _, _ = oauth.issue_access_token(db_session, sub="s", client_id="c", scope="", audience=None,
                                           record=False, commit=False)
    assert _kid(token) == old
    db_session.rollback()
    token, _, _ = oauth.issue_access_token(db_session, sub="s", client_id="c", scope="", audience=None, record=False)
    assert _kid(token) == new


# ---------------------------------------------------------------------------
# automatic rotation (scheduler job)
# ---------------------------------------------------------------------------
def test_automatic_rotation_publishes_a_day_before_the_period_ends(owner_client, db_session):
    """TC-KROT-06: at 89 days the job publishes the next key, due to sign at exactly 90 days; before that it does
    nothing; the job audits it as the scheduler."""
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    active = _active_kid(owner_client)
    _shift(db_session, active, created_at=-(88 * 24 * 60))
    assert CleanupScheduler.run_signing_key_job(db_session)["published"] is None

    _shift(db_session, active, created_at=-(24 * 60 + 1))
    done = CleanupScheduler.run_signing_key_job(db_session)
    assert done["published"] and done["activated"] is None
    key, old = _key(db_session, done["published"]), _key(db_session, active)
    # On the 90-day cadence, but never with less than the full pre-publish window ahead
    assert key.is_pending
    assert abs(key.activates_at - (old.created_at + timedelta(days=90))) < timedelta(minutes=2)
    assert key.activates_at >= key.created_at + timedelta(days=1) - timedelta(seconds=1)
    assert done["published"] in _kids(owner_client)
    logs = owner_client.get("/api/audit/logs", params={"action": "oauth_key_rotate"}).json()["logs"]
    assert logs and logs[0]["actor_type"] == "system" and logs[0]["details"]["automatic"] is True

    # A second run neither publishes another key nor activates early
    assert CleanupScheduler.run_signing_key_job(db_session)["published"] is None


def test_automatic_rotation_can_be_disabled(owner_client, db_session, monkeypatch):
    """TC-KROT-07: signing_key_rotation_days = 0 turns the automatic rotation off."""
    from src.config import Config
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    monkeypatch.setattr(Config.get_oauth_config(), "signing_key_rotation_days", 0)
    _shift(db_session, _active_kid(owner_client), created_at=-(400 * 24 * 60))
    assert CleanupScheduler.run_signing_key_job(db_session)["published"] is None
    assert owner_client.get("/api/oauth/keys").json()["rotation"]["next_at"] is None


def test_job_promotes_a_due_key(owner_client, db_session):
    """TC-KROT-08: with no token issued, the scheduler's job still switches to the published key on time."""
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    new = owner_client.post("/api/oauth/keys/rotate").json()["kid"]
    assert CleanupScheduler.run_signing_key_job(db_session)["activated"] is None
    _shift(db_session, new, activates_at=-24 * 60 - 1)
    assert CleanupScheduler.run_signing_key_job(db_session)["activated"] == new
    assert _keys(owner_client)[new]["is_active"]


# ---------------------------------------------------------------------------
# what a key signed: kid on the record, signed_until on the key
# ---------------------------------------------------------------------------
def test_recorded_tokens_carry_their_kid_and_raise_signed_until(owner_client, service, db_session):
    """TC-KROT-09: each recorded token stores the kid; signed_until is the latest expiry, never lowered by a
    shorter token issued later; unrecorded scanner tokens do not touch it."""
    from src.oauth import service as oauth

    kid = _active_kid(owner_client)
    long = _pat(owner_client, service, days=200)
    assert long["kid"] == kid
    expiry = datetime.fromtimestamp(jwt.decode(long["access_token"], options={"verify_signature": False})["exp"])
    assert _key(db_session, kid).signed_until == expiry

    _pat(owner_client, service, days=1)
    assert _key(db_session, kid).signed_until == expiry
    oauth.mint_audience_token(db_session, "http://127.0.0.1:9/mcp")
    db_session.commit()
    assert _key(db_session, kid).signed_until == expiry


def test_refresh_tokens_count_towards_signed_until(owner_client, service, db_session):
    """TC-KROT-10: a refresh token (30 days) keeps its key: signed_until covers it."""
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    claims = jwt.decode(tokens["refresh_token"], options={"verify_signature": False})
    assert _key(db_session, _kid(tokens["refresh_token"])).signed_until == datetime.fromtimestamp(claims["exp"])


# ---------------------------------------------------------------------------
# deletion
# ---------------------------------------------------------------------------
def _retire_old_key(owner_client, db_session, minutes_ago):
    old = _active_kid(owner_client)
    rotate_and_activate(owner_client)
    _shift(db_session, old, rotated_at=-minutes_ago, created_at=-minutes_ago)
    return old


def test_retired_key_is_kept_until_everything_it_signed_expired(owner_client, service, db_session):
    """TC-KROT-11: out of the JWKS is not enough: a key whose refresh token (or any token) may still be presented is
    kept; once signed_until has passed and nothing it signed is live, the job deletes it (audited)."""
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    _exchange(owner_client, reg["client_id"], code, verifier)
    old = _retire_old_key(owner_client, db_session, 60)
    from db.models import OAuthToken
    for t in db_session.query(OAuthToken).filter(OAuthToken.kind == "access").all():
        t.expires_at = datetime.now() - timedelta(minutes=10)
    db_session.commit()
    assert old not in _kids(owner_client)  # access lifetime is over: out of the JWKS ...
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == []  # ... but the refresh token needs it

    # Every token it signed has expired
    key = _key(db_session, old)
    key.signed_until = datetime.now() - timedelta(minutes=10)
    for t in db_session.query(OAuthToken).filter(OAuthToken.kid == old).all():
        t.expires_at = datetime.now() - timedelta(minutes=10)
    db_session.commit()
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == [old]
    assert _key(db_session, old) is None
    logs = owner_client.get("/api/audit/logs", params={"action": "oauth_key_delete"}).json()["logs"]
    assert logs and logs[0]["resource_id"] == old


def test_signed_until_alone_keeps_a_key(owner_client, db_session):
    """TC-KROT-12: even with no recorded token left (records purged), a key is kept until signed_until."""
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    old = _retire_old_key(owner_client, db_session, 60)
    key = _key(db_session, old)
    key.signed_until = datetime.now() + timedelta(days=100)
    db_session.commit()
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == []
    key.signed_until = datetime.now() - timedelta(minutes=10)
    db_session.commit()
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == [old]


def test_key_retired_before_this_change_falls_back_to_the_longest_lifetime(owner_client, db_session):
    """TC-KROT-13: a key without signed_until (retired before #30) is kept for pat_max_days after retirement."""
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    old = _retire_old_key(owner_client, db_session, 60)
    key = _key(db_session, old)
    key.signed_until = None
    db_session.commit()
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == []
    _shift(db_session, old, rotated_at=-(365 * 24 * 60), created_at=-(365 * 24 * 60))
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == [old]


def test_recently_retired_key_is_never_deleted(owner_client, db_session, monkeypatch):
    """TC-KROT-14: within the unrecorded-token window (scanner / Inspect-as tokens) a key stays, whatever
    signed_until says -- even when it already left the JWKS (retired_key_publish_minutes = 0)."""
    from src.config import Config
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    monkeypatch.setattr(Config.get_oauth_config(), "retired_key_publish_minutes", 0)
    old = _retire_old_key(owner_client, db_session, 1)
    key = _key(db_session, old)
    key.signed_until = datetime.now() - timedelta(days=1)
    db_session.commit()
    assert old not in _kids(owner_client)
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == []


def test_active_and_published_keys_are_never_deleted(owner_client, db_session, monkeypatch):
    """TC-KROT-15: the active key and a published key waiting to sign are never deleted -- an explicit rule, not
    only a consequence of their being in the JWKS."""
    from src.oauth import signing_keys
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    monkeypatch.setattr(signing_keys, "is_published", lambda db, key: False)
    active = _active_kid(owner_client)
    new = owner_client.post("/api/oauth/keys/rotate").json()["kid"]
    for kid in (active, new):
        key = _key(db_session, kid)
        key.signed_until = datetime.now() - timedelta(days=1)
        key.created_at = key.created_at - timedelta(days=1)
    db_session.commit()
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == []


# ---------------------------------------------------------------------------
# emergency revocation
# ---------------------------------------------------------------------------
def test_revoke_key_drops_it_and_its_tokens(owner_client, service, db_session):
    """TC-KROT-16: "Revoke key" on a retired key: out of the JWKS at once, the console was told how many
    unexpired tokens it signed, those are revoked (feed reason key_revoked), introspection and refresh refuse
    them, the private key is wiped and the action is audited."""
    from src.oauth import service as oauth

    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    pats = [_pat(owner_client, service, label=f"p{i}") for i in range(2)]
    old = _kid(pats[0]["access_token"])
    rotate_and_activate(owner_client)

    assert _keys(owner_client)[old]["live_tokens"] == 4  # 2 PATs + access + refresh
    r = owner_client.post(f"/api/oauth/keys/{old}/revoke")
    assert r.status_code == 200, r.text
    assert r.json()["tokens_revoked"] == 4 and r.json()["active_kid"] is None

    assert old not in _kids(owner_client)
    keys = _keys(owner_client)
    assert keys[old]["is_revoked"] and not keys[old]["published"] and keys[old]["live_tokens"] == 0
    assert _key(db_session, old).private_pem_enc == ""
    records = owner_client.get("/api/oauth/tokens", params={"include_inactive": "true"}).json()["tokens"]
    assert {t["revoke_reason"] for t in records if t["kid"] == old} == {"key_revoked"}
    with pytest.raises(oauth.OAuthError):
        oauth.verify_jwt(db_session, pats[0]["access_token"])
    intro = owner_client.post("/oauth/introspect", data={"token": pats[0]["access_token"],
                                                         "client_id": reg["client_id"]}).json()
    assert intro == {"active": False}
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    logs = owner_client.get("/api/audit/logs", params={"action": "oauth_key_revoke"}).json()["logs"]
    assert logs and logs[0]["details"]["tokens_revoked"] == 4


def test_revoking_the_active_key_hands_over_at_once(owner_client, service):
    """TC-KROT-17: revoking the signer makes a new key active immediately (the published one if there is one)."""
    old = _active_kid(owner_client)
    pending = owner_client.post("/api/oauth/keys/rotate").json()["kid"]
    r = owner_client.post(f"/api/oauth/keys/{old}/revoke")
    assert r.status_code == 200 and r.json()["active_kid"] == pending
    assert _kid(_pat(owner_client, service)["access_token"]) == pending

    r = owner_client.post(f"/api/oauth/keys/{pending}/revoke")
    replacement = r.json()["active_kid"]
    assert replacement not in (None, old, pending)
    assert _kids(owner_client) == {replacement}
    assert _kid(_pat(owner_client, service)["access_token"]) == replacement


def test_revoke_errors(owner_client):
    """TC-KROT-18: unknown kid 404; a second revocation 409."""
    assert owner_client.post("/api/oauth/keys/nope/revoke").status_code == 404
    old = _active_kid(owner_client)
    assert owner_client.post(f"/api/oauth/keys/{old}/revoke").status_code == 200
    r = owner_client.post(f"/api/oauth/keys/{old}/revoke")
    assert r.status_code == 409 and r.json()["detail"]["error"] == "oauth.key_already_revoked"


def test_tokens_from_before_this_change_are_attributed_by_time(owner_client, service, db_session):
    """TC-KROT-19: a token record without a kid (issued before #30) counts for the key active when it was issued."""
    from db.models import OAuthToken

    pat = _pat(owner_client, service)
    rec = db_session.query(OAuthToken).filter(OAuthToken.jti == pat["jti"]).one()
    rec.kid = None
    db_session.commit()
    old = _kid(pat["access_token"])
    rotate_and_activate(owner_client)
    assert _keys(owner_client)[old]["live_tokens"] == 1
    _pat(owner_client, service)  # issued by the new key: not the old key's
    assert owner_client.post(f"/api/oauth/keys/{old}/revoke").json()["tokens_revoked"] == 1


def test_key_endpoints_need_a_session(client):
    """TC-KROT-20: rotating and revoking are console (owner) actions."""
    assert client.post("/api/oauth/keys/rotate").status_code == 401
    assert client.post("/api/oauth/keys/x/revoke").status_code == 401
    assert client.get("/api/oauth/keys").status_code == 401


def test_keys_listing_reports_the_schedule(owner_client):
    """TC-KROT-21: the listing carries the rotation period, the pre-publish window and the next rotation."""
    rotation = owner_client.get("/api/oauth/keys").json()["rotation"]
    assert rotation["every_days"] == 90 and rotation["prepublish_minutes"] == 1440
    active = _keys(owner_client)[_active_kid(owner_client)]
    expected = datetime.fromisoformat(active["created_at"]) + timedelta(days=89)
    assert abs(datetime.fromisoformat(rotation["next_at"]) - expected) < timedelta(seconds=2)


def test_a_live_token_record_keeps_a_key_whatever_signed_until_says(owner_client, service, db_session):
    """TC-KROT-22: defence in depth: a recorded, unexpired token signed by the key (here a PAT whose lifetime was
    extended in the database) keeps the key even after signed_until."""
    from db.models import OAuthToken
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    pat = _pat(owner_client, service)
    old = _retire_old_key(owner_client, db_session, 60)
    key = _key(db_session, old)
    key.signed_until = datetime.now() - timedelta(days=1)
    db_session.query(OAuthToken).filter(OAuthToken.jti == pat["jti"]).update(
        {OAuthToken.revoked_at: None, OAuthToken.kind: "refresh"})
    db_session.commit()
    assert CleanupScheduler.run_signing_key_job(db_session)["deleted"] == []
