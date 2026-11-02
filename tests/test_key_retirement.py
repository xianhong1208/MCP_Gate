"""H-14: a rotated signing key leaves the published JWKS once nothing it signed can still be valid."""

from datetime import timedelta

import jwt

from tests.test_oauth_flow import _authorize_and_consent, _exchange, _register


def _kids(client):
    return {k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]}


def _age_retired_keys(db_session, minutes):
    from db.models import OAuthSigningKey

    for key in db_session.query(OAuthSigningKey).filter(OAuthSigningKey.is_active.is_(False)).all():
        key.rotated_at = key.rotated_at - timedelta(minutes=minutes)
        key.created_at = key.created_at - timedelta(minutes=minutes)
    db_session.commit()


def _age_tokens(db_session, minutes, expire_access=False):
    """Move token records into the past; ``expire_access`` also lets short-lived access tokens run out."""
    from db.models import OAuthToken

    for t in db_session.query(OAuthToken).all():
        t.issued_at = t.issued_at - timedelta(minutes=minutes)
        if expire_access and t.kind == "access":
            t.expires_at = t.expires_at - timedelta(minutes=minutes)
    db_session.commit()


def test_retired_key_unpublished_after_access_lifetime(owner_client, service, db_session):
    old_kid = next(iter(_kids(owner_client)))
    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    assert old_kid in _kids(owner_client)  # tokens it signed minutes ago still verify
    _age_retired_keys(db_session, 60)       # access lifetime in tests is 5 minutes
    kids = _kids(owner_client)
    assert old_kid not in kids and len(kids) == 1
    keys = {k["kid"]: k for k in owner_client.get("/api/oauth/keys").json()["keys"]}
    assert keys[old_kid]["published"] is False and keys[old_kid]["is_active"] is False


def test_live_pat_keeps_its_key_published_until_revoked(owner_client, service, db_session):
    pat = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 30,
                                                                 "label": "long"}).json()
    old_kid = jwt.get_unverified_header(pat["access_token"])["kid"]
    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    _age_tokens(db_session, 60)
    _age_retired_keys(db_session, 60)
    assert old_kid in _kids(owner_client)
    assert owner_client.post(f"/api/oauth/tokens/{pat['jti']}/revoke").status_code == 200
    assert old_kid not in _kids(owner_client)


def test_unpublished_key_still_serves_refresh_but_not_introspection(owner_client, service, db_session):
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    _age_tokens(db_session, 60, expire_access=True)
    _age_retired_keys(db_session, 60)
    old_kid = jwt.get_unverified_header(tokens["access_token"])["kid"]
    assert old_kid not in _kids(owner_client)

    # a token signed by an unpublished key is no longer active anywhere (e.g. one forged with a leaked old key)
    from src.oauth import service as oauth
    from src.oauth.signing_keys import get_key_by_kid, load_private_pem
    from tests.test_oauth_flow import RESOURCE

    forged = jwt.encode({"iss": "http://testserver", "sub": "x", "client_id": reg["client_id"], "scope": "",
                         "aud": RESOURCE, "iat": 1, "exp": 4102444800, "jti": "forged", "token_use": "access"},
                        load_private_pem(get_key_by_kid(db_session, old_kid)), algorithm="RS256",
                        headers={"kid": old_kid, "typ": "at+jwt"})
    assert oauth.verify_jwt(db_session, forged)["jti"] == "forged"  # the signature itself is fine
    intro = owner_client.post("/oauth/introspect", data={"token": forged, "client_id": reg["client_id"]}).json()
    assert intro == {"active": False}
    # the refresh token (only ever checked by MCP Gate itself) still works and yields new-key tokens
    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200, r.text
    assert jwt.get_unverified_header(r.json()["access_token"])["kid"] != old_kid


def test_grace_is_configurable(owner_client, service, db_session, monkeypatch):
    from src.config import Config

    old_kid = next(iter(_kids(owner_client)))
    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    _age_retired_keys(db_session, 60)
    monkeypatch.setattr(Config.get_oauth_config(), "retired_key_publish_minutes", 24 * 60)
    assert old_kid in _kids(owner_client)
