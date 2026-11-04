"""OAuth access tokens default to 15 minutes; personal access tokens and scanner tokens keep their own lifetimes,
and refresh keeps working."""

import jwt

from src.config.model import OAuthConfig
from tests.test_oauth_flow import _authorize_and_consent, _exchange, _register


def test_default_access_lifetime_is_15_minutes():
    assert OAuthConfig().access_expire_minutes == 15


def test_issued_lifetimes(owner_client, service, monkeypatch):
    from src.config import Config

    monkeypatch.setattr(Config.get_oauth_config(), "access_expire_minutes", OAuthConfig().access_expire_minutes)
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    tokens = _exchange(owner_client, reg["client_id"], code, verifier).json()
    assert tokens["expires_in"] == 900
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 900

    r = owner_client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                                "refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200 and r.json()["expires_in"] == 900

    pat = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 30,
                                                                 "label": "ci"})
    assert pat.status_code in (200, 201), pat.text
    pat_claims = jwt.decode(pat.json()["access_token"], options={"verify_signature": False})
    assert pat_claims["exp"] - pat_claims["iat"] == 30 * 86400
