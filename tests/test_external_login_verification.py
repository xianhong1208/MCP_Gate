"""H-03: a GitHub / Google login may only take over an existing account through a *verified* email.

The hunt signed in with a Google identity whose unverified email equalled the owner's and got the owner's
console (``login_external`` linked by email and never looked at ``email_verified``). GitHub's public profile
email is not verified either. H-17b: a non-ASCII ``state`` on the callback crashed ``compare_digest`` (500).
"""
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from src.identity import service as identity_service
from src.identity.providers.base import ExternalIdentity
from src.identity.providers.github import GitHubLoginProvider
from src.identity.providers.google import GoogleLoginProvider
from src.identity.service import IdentityError
from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD, SETUP_TOKEN


@pytest.fixture
def owner(seeded, db_session):
    return identity_service.setup_owner(db_session, email=OWNER_EMAIL, password=OWNER_PASSWORD,
                                        setup_token=SETUP_TOKEN)


def test_unverified_email_does_not_link_to_the_owner(owner, db_session):
    attacker = ExternalIdentity(provider="google", sub="attacker-999", email=OWNER_EMAIL, name="x",
                                email_verified=False)
    with pytest.raises(IdentityError) as e:
        identity_service.login_external(db_session, attacker)
    assert e.value.code == "auth.external_email_unverified" and e.value.status_code == 403
    db_session.refresh(owner)
    assert owner.auth_provider == "local" and owner.provider_sub is None


def test_verified_email_links_and_says_so(owner, db_session):
    identity = ExternalIdentity(provider="google", sub="g-1", email=OWNER_EMAIL, name="o", email_verified=True)
    user = identity_service.login_external(db_session, identity)
    assert user.id == owner.id and user.provider_sub == "g-1"
    # Afterwards the provider+sub match is enough, verified or not (it is the same provider account)
    again = ExternalIdentity(provider="google", sub="g-1", email=OWNER_EMAIL, name="o", email_verified=False)
    assert identity_service.login_external(db_session, again).id == owner.id


def test_external_identity_is_unverified_unless_the_provider_says_so():
    assert ExternalIdentity(provider="x", sub="1", email="a@b.c", name=None).email_verified is False


@pytest.mark.parametrize("claim, expected", [
    (True, True), (False, False), ("true", True), ("false", False), (None, False), ("yes", False),
])
def test_google_email_verified_claim(claim, expected):
    data = {"sub": "1", "email": "A@B.example"}
    if claim is not None:
        data["email_verified"] = claim
    identity = GoogleLoginProvider("id", "secret").parse_identity(data)
    assert identity.email == "a@b.example" and identity.email_verified is expected


def _github(user, emails, emails_status=200):
    def handler(request):
        if request.url.path == "/user":
            return httpx.Response(200, json=user)
        if request.url.path == "/user/emails":
            return httpx.Response(emails_status, json=emails)
        return httpx.Response(404)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await GitHubLoginProvider("id", "secret").fetch_identity(client, "at", {})

    import asyncio
    return asyncio.run(run())


def test_github_public_profile_email_is_not_trusted():
    """The public profile email is free text as far as verification goes: only /user/emails says."""
    identity = _github({"id": 7, "login": "eve", "email": OWNER_EMAIL},
                       [{"email": "eve@example.net", "primary": True, "verified": True},
                        {"email": OWNER_EMAIL, "primary": False, "verified": False}])
    assert identity.email == "eve@example.net" and identity.email_verified is True


def test_github_unverified_primary_is_unverified():
    identity = _github({"id": 7, "login": "eve", "email": None},
                       [{"email": OWNER_EMAIL, "primary": True, "verified": False}])
    assert identity.email == OWNER_EMAIL and identity.email_verified is False


def test_github_without_email_list_is_unverified():
    identity = _github({"id": 7, "login": "eve", "email": OWNER_EMAIL}, [], emails_status=403)
    assert identity.email_verified is False


def test_non_ascii_state_is_a_failed_login_not_a_500(client, monkeypatch):
    from src.config import Config

    cfg = Config.get_config_model()
    monkeypatch.setattr(cfg.identity.google, "client_id", "g-id")
    monkeypatch.setattr(cfg.identity.google, "client_secret", "g-secret")
    client.cookies.set("mcp_login_state", "abc|/", path="/api/session/oauth")
    r = client.get("/api/session/oauth/google/callback", params={"code": "x", "state": "é"}, follow_redirects=False)
    assert r.status_code == 302
    assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["auth.external_login_failed"]
    # Over-long state is refused the same way
    r = client.get("/api/session/oauth/google/callback", params={"code": "x", "state": "a" * 5000},
                   follow_redirects=False)
    assert r.status_code == 302 and "auth.external_login_failed" in r.headers["location"]
