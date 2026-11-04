"""What a dynamically registered (DCR) client may do. Registration is anonymous, so nothing a DCR client asks for
at registration time may grant it trust the owner did not give on the consent screen."""

from tests.test_oauth_flow import RESOURCE


def test_dcr_cannot_register_client_credentials(client, service):
    """H-01: an anonymous DCR client used to get a consent-free token for any server via client_credentials."""
    r = client.post("/oauth/register", json={"grant_types": ["client_credentials"],
                                             "token_endpoint_auth_method": "client_secret_post"})
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "invalid_client_metadata"
    r = client.post("/oauth/register", json={
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic", "redirect_uris": ["http://localhost:9999/callback"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"


def test_dcr_auto_approve_does_not_change_the_rule(client, service, monkeypatch):
    from src.config import Config

    monkeypatch.setattr(Config.get_oauth_config(), "dcr_auto_approve", False)
    r = client.post("/oauth/register", json={"grant_types": ["client_credentials"],
                                             "token_endpoint_auth_method": "client_secret_post"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"


def test_token_endpoint_refuses_client_credentials_for_existing_dcr_client(owner_client, service, db_session):
    """A DCR client stored before the fix (grant already in its record) still gets nothing."""
    from src.oauth import service as oauth

    client, secret = oauth.register_client(db_session, {
        "grant_types": ["authorization_code"], "redirect_uris": ["http://localhost:9999/callback"],
        "token_endpoint_auth_method": "client_secret_post"}, created_via="dcr")
    client.grant_types = '["authorization_code", "client_credentials"]'  # as an older release would have stored
    db_session.commit()

    r = owner_client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": client.client_id, "client_secret": secret,
        "resource": RESOURCE, "scope": "mcp:tools:read mcp:tools:invoke"})
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "unauthorized_client"
    assert "access_token" not in r.json()


def test_console_client_keeps_client_credentials(owner_client, service):
    r = owner_client.post("/api/oauth/clients", json={
        "client_name": "Batch job", "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic"})
    assert r.status_code == 201, r.text
    reg = r.json()
    t = owner_client.post("/oauth/token", data={"grant_type": "client_credentials", "resource": RESOURCE},
                          auth=(reg["client_id"], reg["client_secret"]))
    assert t.status_code == 200, t.text


def test_metadata_still_advertises_client_credentials(client):
    # Console-registered clients may use it, so the server still supports the grant
    assert "client_credentials" in client.get("/.well-known/oauth-authorization-server").json()["grant_types_supported"]


def test_dcr_client_cannot_point_jwks_fetch_at_loopback(owner_client):
    """On a plain-http (development) issuer, loopback jwks_uri is an owner-only allowance."""
    body = {"client_name": "k", "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "http://127.0.0.1:9/jwks.json", "redirect_uris": ["http://localhost:9999/callback"]}
    r = owner_client.post("/oauth/register", json=body)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"
    r = owner_client.post("/api/oauth/clients", json=body)
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# H-09: registration is bounded
# ---------------------------------------------------------------------------
CB = "http://localhost:9999/callback"


def test_registration_body_is_capped(client):
    big = {"client_name": "x", "redirect_uris": [CB], "software_version": "v" * (200 * 1024)}
    r = client.post("/oauth/register", json=big)
    assert r.status_code == 413 and r.json()["error"] == "invalid_client_metadata", r.text


def test_registration_caps_redirect_uris(client):
    uris = [f"http://localhost:{9000 + i}/cb" for i in range(21)]
    r = client.post("/oauth/register", json={"redirect_uris": uris})
    assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"
    assert client.post("/oauth/register", json={"redirect_uris": uris[:20]}).status_code == 201


def test_redirect_uris_are_validated_without_authorization_code(client):
    r = client.post("/oauth/register", json={"grant_types": ["refresh_token"],
                                             "redirect_uris": ["javascript:alert(1)"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"


def test_registration_rejects_wrongly_typed_metadata_without_500(client):
    for body in ({"client_name": 123, "redirect_uris": [CB]},
                 {"grant_types": [{"a": 1}], "redirect_uris": [CB]},
                 {"grant_types": "authorization_code", "redirect_uris": [CB]},
                 {"response_types": ["code"] * 50, "redirect_uris": [CB]},
                 {"response_types": [["code"]], "redirect_uris": [CB]},
                 {"token_endpoint_auth_method": ["none"], "redirect_uris": [CB]},
                 {"scope": 5, "redirect_uris": [CB]},
                 [1, 2, 3], "x"):
        r = client.post("/oauth/register", json=body)
        assert r.status_code == 400, (body, r.status_code, r.text)
        assert r.json()["error"] in ("invalid_client_metadata", "invalid_redirect_uri")


def test_token_endpoint_body_is_capped(client):
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": "x" * (100 * 1024)})
    assert r.status_code == 413 and r.json()["error"] == "invalid_request"


def test_authorize_rejects_long_resource_and_scope(owner_client, service):
    reg = owner_client.post("/oauth/register", json={"redirect_uris": [CB]}).json()
    base = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CB,
            "code_challenge": "a" * 43, "code_challenge_method": "S256", "state": "s"}
    for extra in ({"resource": "http://127.0.0.1:8123/" + "a" * 600}, {"scope": "x" * 2000}):
        r = owner_client.get("/oauth/authorize", params={**base, **extra}, follow_redirects=False)
        assert r.status_code in (302, 400), r.text
        if r.status_code == 302:
            assert "error=" in r.headers["location"] and "code=" not in r.headers["location"]


# ---------------------------------------------------------------------------
# H-16: informational URIs must be web URLs
# ---------------------------------------------------------------------------
def test_metadata_uris_must_be_https_or_loopback_http(client):
    for field in ("client_uri", "logo_uri", "tos_uri", "policy_uri"):
        for bad in ("javascript:alert(document.cookie)", "data:image/svg+xml,<svg/onload=alert(1)>",
                    "http://evil.example/track.png", "file:///etc/passwd", "ftp://x/y", "//evil.example/x",
                    "https://", "notaurl", 42):
            r = client.post("/oauth/register", json={"redirect_uris": [CB], field: bad})
            assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata", (field, bad, r.text)
        for good in ("https://client.example/about", "http://localhost:3000/", "http://127.0.0.1/logo.png"):
            r = client.post("/oauth/register", json={"redirect_uris": [CB], field: good})
            assert r.status_code == 201, (field, good, r.text)


def test_console_client_uri_is_validated_too(owner_client):
    r = owner_client.post("/api/oauth/clients", json={"client_name": "x", "redirect_uris": [CB],
                                                      "client_uri": "javascript:alert(1)"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# H-09: never-used DCR clients are purged
# ---------------------------------------------------------------------------
def test_unused_dcr_clients_are_purged(owner_client, service, db_session):
    from datetime import timedelta

    from db.models import local_now
    from src.adapters import OAuthClientAdapter
    from tests.test_oauth_flow import _authorize_and_consent, _exchange

    stale = owner_client.post("/oauth/register", json={"redirect_uris": [CB]}).json()["client_id"]
    fresh = owner_client.post("/oauth/register", json={"redirect_uris": [CB]}).json()["client_id"]
    used = owner_client.post("/oauth/register", json={"redirect_uris": [CB]}).json()["client_id"]
    code, verifier = _authorize_and_consent(owner_client, used)
    assert _exchange(owner_client, used, code, verifier).status_code == 200
    manual = owner_client.post("/api/oauth/clients", json={"client_name": "m", "redirect_uris": [CB]}).json()
    old = local_now() - timedelta(days=31)
    for cid in (stale, used, manual["client_id"]):
        c = OAuthClientAdapter.get(db_session, cid)
        c.created_at = old
    db_session.commit()

    assert OAuthClientAdapter.delete_unused_dcr(db_session, older_than=timedelta(days=30)) == 1
    db_session.expire_all()
    assert OAuthClientAdapter.get(db_session, stale) is None
    for cid in (fresh, used, manual["client_id"]):
        assert OAuthClientAdapter.get(db_session, cid) is not None


def test_purge_job_honours_config(owner_client, monkeypatch, db_session):
    import asyncio
    from datetime import timedelta

    from db.models import local_now
    from src.adapters import OAuthClientAdapter
    from src.config import Config
    from src.scheduler.cleanup_scheduler import CleanupScheduler

    cid = owner_client.post("/oauth/register", json={"redirect_uris": [CB]}).json()["client_id"]
    c = OAuthClientAdapter.get(db_session, cid)
    c.created_at = local_now() - timedelta(days=400)
    db_session.commit()

    monkeypatch.setattr(Config.get_oauth_config(), "dcr_unused_client_days", 0)  # off
    asyncio.run(CleanupScheduler()._cleanup_oauth())
    db_session.expire_all()
    assert OAuthClientAdapter.get(db_session, cid) is not None
    monkeypatch.setattr(Config.get_oauth_config(), "dcr_unused_client_days", 30)
    asyncio.run(CleanupScheduler()._cleanup_oauth())
    db_session.expire_all()
    assert OAuthClientAdapter.get(db_session, cid) is None
