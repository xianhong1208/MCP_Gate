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
