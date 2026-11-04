"""Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-03, MCP authorization 2026-07-28):
an https URL as client_id, the client's metadata fetched from it instead of registered."""

import json
import time
from datetime import timedelta
from urllib.parse import parse_qs, quote, urlparse

import httpx
import jwt
import pytest

from src.config import Config
from src.oauth import client_assertion, client_metadata
from src.utils import public_cache
from tests.conftest import make_pkce
from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _exchange
from tests.test_oauth_private_key_jwt import ASSERTION_TYPE, make_assertion, rsa_keypair

CID = "https://client.example/oauth/metadata.json"
PUBLIC_IP = "93.184.215.14"
DROP = object()


def document(**overrides) -> dict:
    doc = {
        "client_id": CID, "client_name": "Example MCP Client", "client_uri": "https://client.example",
        "logo_uri": "https://client.example/logo.png", "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not DROP}


class FakeWeb:
    """Stands in for client_metadata._http_get: serves registered URLs, records every fetch."""

    def __init__(self):
        self.routes = {}
        self.calls = []

    def serve(self, url=CID, body=None, *, status=200, content_type="application/json", headers=None):
        if body is None:
            body = document()
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs = {"content-type": content_type, **(headers or {})}
        self.routes[url] = (status, hdrs, raw)

    def fail(self, url=CID, exc=None):
        self.routes[url] = exc or httpx.ConnectError("connection refused")

    def __call__(self, url, address, *, timeout, max_bytes):
        self.calls.append((url, address))
        route = self.routes.get(url)
        if route is None:
            return client_metadata._Response(404, httpx.Headers({}), b"")
        if isinstance(route, Exception):
            raise route
        status, headers, body = route
        if len(body) > max_bytes:
            raise client_metadata._TooLarge()
        return client_metadata._Response(status, httpx.Headers(headers), body if status == 200 else b"")


@pytest.fixture(autouse=True)
def _fresh():
    client_metadata.reset_caches()
    client_assertion.reset_caches()
    yield
    client_metadata.reset_caches()
    client_assertion.reset_caches()


@pytest.fixture
def web(monkeypatch):
    w = FakeWeb()
    w.serve()
    monkeypatch.setattr(client_metadata, "_http_get", w)
    monkeypatch.setattr(client_metadata, "_resolve_host", lambda host: [PUBLIC_IP])
    return w


@pytest.fixture
def cimd_cfg(monkeypatch):
    cfg = Config.get_oauth_config().cimd

    def set_(**values):
        for k, v in values.items():
            monkeypatch.setattr(cfg, k, v)
    return set_


def _authorize(client, client_id=CID, redirect_uri=REDIRECT_URI, **extra):
    _, challenge = make_pkce()
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz", "resource": RESOURCE}
    params.update(extra)
    return client.get("/oauth/authorize", params=params, follow_redirects=False)


def _refresh(client, refresh_token, client_id=CID, **extra):
    return client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": client_id,
                                             "refresh_token": refresh_token, **extra})


def _tokens(owner_client):
    code, verifier = _authorize_and_consent(owner_client, CID)
    r = _exchange(owner_client, CID, code, verifier)
    assert r.status_code == 200, r.text
    return r.json()


def _db():
    from db.database import make_session
    return make_session()


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
def test_discovery_advertises_support(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["client_id_metadata_document_supported"] is True
    assert meta["registration_endpoint"] == "http://testserver/oauth/register"  # DCR keeps working alongside


def test_discovery_when_disabled(client, cimd_cfg):
    cimd_cfg(enabled=False)
    public_cache.invalidate()
    try:
        meta = client.get("/.well-known/openid-configuration").json()
        assert meta["client_id_metadata_document_supported"] is False
    finally:
        public_cache.invalidate()


def test_disabled_refuses_url_client_ids(owner_client, service, web, cimd_cfg):
    cimd_cfg(enabled=False)
    r = _authorize(owner_client)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client"
    assert "not supported" in r.json()["error_description"]
    assert web.calls == []


# ---------------------------------------------------------------------------
# full flow
# ---------------------------------------------------------------------------
def test_full_flow_with_a_metadata_document_client(owner_client, service, web):
    verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": CID, "redirect_uri": REDIRECT_URI, "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz", "resource": RESOURCE}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/consent"), r.text
    assert web.calls == [(CID, PUBLIC_IP)]

    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    info = owner_client.get(f"/oauth/authorize/requests/{rid}").json()
    assert info["client"]["client_id"] == CID
    assert info["client"]["client_name"] == "Example MCP Client"
    assert info["client"]["created_via"] == "cimd"
    assert info["client"]["metadata_document"] is True
    assert info["client"]["identity_host"] == "client.example"
    assert info["can_skip"] is False  # never trusted like a console-registered client
    assert info["redirect_host"] == "localhost:9999" and info["redirect_loopback_only"] is True

    d = owner_client.post(f"/oauth/authorize/requests/{rid}/decision", json={"approve": True})
    q = parse_qs(urlparse(d.json()["redirect_to"]).query)
    assert q["iss"] == ["http://testserver"]  # §7
    tokens = _exchange(owner_client, CID, q["code"][0], verifier).json()
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert claims["client_id"] == CID and claims["aud"] == RESOURCE

    intro = owner_client.post("/oauth/introspect", data={"token": tokens["access_token"], "client_id": CID}).json()
    assert intro["active"] is True and intro["client_id"] == CID
    refreshed = _refresh(owner_client, tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.text
    owner_client.post("/oauth/revoke", data={"token": refreshed.json()["refresh_token"], "client_id": CID})
    assert _refresh(owner_client, refreshed.json()["refresh_token"]).status_code == 400

    # one fetch for the whole flow: the document is cached
    assert len(web.calls) == 1
    # the client is listed like any other, with the URL as its id
    listed = {c["client_id"]: c for c in owner_client.get("/api/oauth/clients").json()["clients"]}
    assert listed[CID]["created_via"] == "cimd" and listed[CID]["metadata_fetched_at"]
    assert listed[CID]["client_uri"] == "https://client.example"


def test_audited_on_first_sight(owner_client, service, web):
    _authorize(owner_client)
    logs = owner_client.get("/api/audit/logs", params={"action": "oauth_client_create"}).json()
    entries = logs.get("logs") or logs.get("items") or []
    assert any(e["resource_id"] == CID and e["details"]["created_via"] == "cimd" for e in entries)


def test_loopback_redirect_matches_on_any_port(owner_client, service, web):
    web.serve(body=document(redirect_uris=["http://127.0.0.1/callback"]))
    assert _authorize(owner_client, redirect_uri="http://127.0.0.1:51234/callback").status_code == 302
    r = _authorize(owner_client, redirect_uri="http://localhost:51234/callback")  # host must still match
    assert r.status_code == 400 and "redirect_uri" in r.json()["error_description"]


def test_unregistered_redirect_uri_is_refused_without_redirecting(owner_client, service, web):
    r = _authorize(owner_client, redirect_uri="https://attacker.example/cb")
    assert r.status_code == 400 and "location" not in r.headers


def test_grant_types_follow_the_document(owner_client, service, web):
    web.serve(body=document(grant_types=["authorization_code", "client_credentials", "urn:x"]))
    tokens = _tokens(owner_client)
    assert "refresh_token" not in tokens  # not declared: no refresh token
    r = owner_client.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": CID})
    assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"


def test_missing_grant_types_use_the_registration_default(owner_client, service, web):
    web.serve(body=document(grant_types=DROP, response_types=DROP))
    assert "refresh_token" in _tokens(owner_client)


# ---------------------------------------------------------------------------
# client authentication
# ---------------------------------------------------------------------------
def test_public_client_must_not_send_a_secret(owner_client, service, web):
    code, verifier = _authorize_and_consent(owner_client, CID)
    r = owner_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": CID, "client_secret": "s3cret", "code": code,
        "redirect_uri": REDIRECT_URI, "code_verifier": verifier, "resource": RESOURCE})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_private_key_jwt_client(owner_client, service, web):
    pem, jwk, alg = rsa_keypair()
    web.serve(body=document(token_endpoint_auth_method=DROP,
                            token_endpoint_auth_methods_supported=["private_key_jwt", "none"],
                            jwks={"keys": [jwk]}))
    code, verifier = _authorize_and_consent(owner_client, CID)
    base = {"grant_type": "authorization_code", "client_id": CID, "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier, "resource": RESOURCE}
    # declared and supported -> required (§5), even though none is declared too
    r = owner_client.post("/oauth/token", data=base)
    assert r.status_code == 401 and "client_assertion required" in r.json()["error_description"]
    code, verifier = _authorize_and_consent(owner_client, CID)
    r = owner_client.post("/oauth/token", data=dict(base, code=code, code_verifier=verifier,
                                                    client_assertion_type=ASSERTION_TYPE,
                                                    client_assertion=make_assertion(CID, pem, alg, jwk["kid"])))
    assert r.status_code == 200, r.text


def test_jwks_uri_in_a_document_must_be_public(owner_client, service, web, monkeypatch):
    web.serve(body=document(token_endpoint_auth_method="private_key_jwt", jwks_uri="https://keys.example/jwks"))
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["10.0.0.1"])
    r = _authorize(owner_client)
    assert r.status_code == 400 and "jwks_uri host keys.example resolves to a non-public address" in r.text
    web.serve(body=document(token_endpoint_auth_method="private_key_jwt", jwks_uri="https://localhost/jwks"))
    client_metadata.reset_caches()
    r = _authorize(owner_client)
    assert r.status_code == 400 and "may not point at this machine" in r.json()["error_description"]


def test_metadata_clients_never_get_loopback_jwks_fetches(monkeypatch):
    """verify_client_assertion lets only owner-registered clients aim the jwks fetch at loopback."""
    seen = {}

    def fake_keys(client, kid, alg, *, allow_loopback):
        seen["allow_loopback"] = allow_loopback
        raise client_assertion.OAuthError("invalid_client", "stop", 401)

    monkeypatch.setattr(client_assertion, "_client_keys", fake_keys)
    pem, jwk, alg = rsa_keypair()

    class C:
        client_id = CID
        created_via = "cimd"
    with pytest.raises(client_assertion.OAuthError):
        client_assertion.verify_client_assertion(C, make_assertion(CID, pem, alg, "rsa-1"),
                                                 token_endpoint="http://x/oauth/token", issuer="http://x")
    assert seen["allow_loopback"] is False


# ---------------------------------------------------------------------------
# URL validation (§3, §10.1, §10.8)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url, message", [
    ("https://client.example", "must have a path"),
    ("https://client.example/", "must have a path"),
    ("https://client.example/a/../metadata.json", "dot path segments"),
    ("https://client.example/./metadata.json", "dot path segments"),
    ("https://client.example/a/%2e%2e/metadata.json", "dot path segments"),
    ("https://client.example/metadata.json#frag", "fragment"),
    ("https://user:pw@client.example/metadata.json", "credentials"),
    ("https://user@client.example/metadata.json", "credentials"),
    ("https://client.example/" + "a" * 250, "too long"),
    ("https://client.example/meta data.json", "ASCII"),
    ("https://client.example/méta.json", "ASCII"),
    ("https://client.example:99999/metadata.json", "not a valid URL"),
    ("https://testserver/clients/metadata.json", "this authorization server"),
])
def test_client_id_url_rules(owner_client, service, web, url, message):
    web.serve(url, document(client_id=url))
    r = _authorize(owner_client, client_id=url)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client"
    assert message in r.json()["error_description"]
    assert web.calls == []


def test_http_client_id_is_not_a_metadata_document(owner_client, service, web):
    r = _authorize(owner_client, client_id="http://client.example/metadata.json")
    assert r.status_code == 400 and r.json()["error_description"] == "unknown or revoked client"
    assert web.calls == []


def test_allowed_hosts_trust_policy(owner_client, service, web, cimd_cfg):
    cimd_cfg(allowed_hosts=["*.example.org", "other.example"])
    r = _authorize(owner_client)
    assert r.status_code == 400 and "not accepted here" in r.json()["error_description"]
    cimd_cfg(allowed_hosts=["*.example"])
    assert _authorize(owner_client).status_code == 302


def test_allowed_hosts_accepts_a_comma_separated_string():
    from src.config.model import ClientMetadataConfig
    cfg = ClientMetadataConfig(allowed_hosts="A.example, *.b.example", private_network_hosts="")
    assert cfg.allowed_hosts == ["a.example", "*.b.example"] and cfg.private_network_hosts == []


# ---------------------------------------------------------------------------
# document validation (§4, §4.1, §5, MCP required fields)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("body, message", [
    (["not", "an", "object"], "JSON object"),
    (document(client_id="https://client.example/other.json"), "does not match"),
    (document(client_id=DROP), "does not match"),
    (document(client_name=DROP), "client_name is required"),
    (document(client_name="   "), "client_name is required"),
    (document(client_name=42), "client_name is required"),
    (document(redirect_uris=DROP), "redirect_uris is required"),
    (document(redirect_uris=[]), "redirect_uris is required"),
    (document(redirect_uris="http://localhost:9999/callback"), "array of strings"),
    (document(redirect_uris=["javascript:alert(1)"]), "invalid redirect_uri"),
    (document(redirect_uris=["http://client.example/cb"]), "invalid redirect_uri"),
    (document(redirect_uris=[f"http://localhost:{p}/cb" for p in range(1000, 1021)]), "at most 20"),
    (document(client_secret="shh"), "client_secret must not be present"),
    (document(client_secret_expires_at=0), "client_secret_expires_at must not be present"),
    (document(token_endpoint_auth_method="client_secret_basic"), "shared-secret"),
    (document(token_endpoint_auth_method=DROP, token_endpoint_auth_methods_supported=["none", "client_secret_post"]),
     "shared-secret"),
    (document(token_endpoint_auth_method="none", token_endpoint_auth_methods_supported=["private_key_jwt"]),
     "must be one of"),
    (document(token_endpoint_auth_method=DROP, token_endpoint_auth_methods_supported=[]), "must not be empty"),
    (document(token_endpoint_auth_method="tls_client_auth"), "no supported token endpoint authentication"),
    (document(token_endpoint_auth_method=7), "must be a string"),
    (document(token_endpoint_auth_method="private_key_jwt"), "requires jwks or jwks_uri"),
    (document(jwks={"keys": []}, jwks_uri="https://client.example/jwks"), "must not both be present"),
    (document(token_endpoint_auth_method="private_key_jwt", jwks={"keys": [{"kty": "oct", "k": "x"}]}),
     "RSA or EC"),
    (document(grant_types=["refresh_token"]), "must include authorization_code"),
    (document(grant_types=["client_credentials"]), "must include authorization_code"),
    (document(response_types=["token"]), "must include code"),
])
def test_invalid_documents(owner_client, service, web, body, message):
    web.serve(body=body)
    r = _authorize(owner_client)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client", r.text
    assert message in r.json()["error_description"]
    assert "location" not in r.headers  # never redirected to the client (§6.1)


@pytest.mark.parametrize("status, content_type, raw, message", [
    (302, "application/json", b"", "redirects are not followed"),
    (404, "application/json", b"", "HTTP 404"),
    (500, "application/json", b"", "HTTP 500"),
    (200, "text/html", json.dumps(document()).encode(), "application/json"),
    (200, "application/json", b"{not json", "not valid JSON"),
    (200, "application/json", b"\xff\xfe", "not valid JSON"),
    (200, "application/json", json.dumps(document(client_name="x" * 6000)).encode(), "larger than 5120 bytes"),
])
def test_fetch_failures(owner_client, service, web, status, content_type, raw, message):
    web.serve(body=raw, status=status, content_type=content_type)
    r = _authorize(owner_client)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client"
    assert message in r.json()["error_description"]


def test_json_subtypes_are_accepted(owner_client, service, web):
    web.serve(content_type="application/oauth-client-metadata+json; charset=utf-8")
    assert _authorize(owner_client).status_code == 302


def test_display_fields_are_sanitised(owner_client, service, web):
    web.serve(body=document(client_name="  " + "N" * 300, client_uri="javascript:alert(1)",
                            logo_uri="http://client.example/logo.png", scope="mcp:tools:read other-server:scope"))
    assert _authorize(owner_client).status_code == 302
    c = owner_client.get(f"/api/oauth/clients/{quote(CID, safe='')}").json()
    assert len(c["client_name"]) == 128
    assert c["client_uri"] is None and c["logo_uri"] is None  # informative only: dropped, not fatal
    assert c["scope"] is None  # a portable document does not restrict scopes here


# ---------------------------------------------------------------------------
# SSRF (§10.7)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
    "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "224.0.0.1", "192.0.2.10",
])
def test_non_public_addresses_are_refused(owner_client, service, web, monkeypatch, address):
    monkeypatch.setattr(client_metadata, "_resolve_host", lambda host: [address])
    r = _authorize(owner_client)
    assert r.status_code == 400 and "non-public address" in r.json()["error_description"]
    assert web.calls == []


def test_one_private_address_among_public_ones_is_refused(owner_client, service, web, monkeypatch):
    monkeypatch.setattr(client_metadata, "_resolve_host", lambda host: [PUBLIC_IP, "10.0.0.1"])
    assert _authorize(owner_client).status_code == 400
    assert web.calls == []


def test_unresolvable_host_is_transient(owner_client, service, web, monkeypatch):
    monkeypatch.setattr(client_metadata, "_resolve_host", lambda host: [])
    r = _authorize(owner_client)
    assert r.status_code == 400 and "does not resolve" in r.json()["error_description"]


def test_private_network_override(owner_client, service, web, monkeypatch, cimd_cfg):
    monkeypatch.setattr(client_metadata, "_resolve_host", lambda host: ["10.0.0.7"])
    cimd_cfg(private_network_hosts=["client.example"])
    assert _authorize(owner_client).status_code == 302
    assert web.calls == [(CID, "10.0.0.7")]


def test_loopback_override_only_when_the_issuer_is_on_loopback(owner_client, service, web, monkeypatch, cimd_cfg):
    monkeypatch.setattr(client_metadata, "_resolve_host", lambda host: ["127.0.0.1"])
    cimd_cfg(private_network_hosts=["client.example"])
    r = _authorize(owner_client)  # issuer http://testserver: not a loopback deployment
    assert r.status_code == 400 and "this machine" in r.json()["error_description"]
    monkeypatch.setattr(Config.get_oauth_config(), "issuer", "http://localhost:4568")
    assert client_metadata._pinned_address(CID) == "127.0.0.1"


def test_fetch_connects_to_the_checked_address(monkeypatch):
    """The connection goes to the address that passed the check, with the original Host, Accept: JSON and no
    cookies; redirects are not followed."""
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://169.254.169.254/latest/meta-data"})

    monkeypatch.setattr(client_metadata, "_make_client",
                        lambda timeout: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
    resp = client_metadata._http_get(CID, PUBLIC_IP, timeout=5, max_bytes=5120)
    assert resp.status_code == 302 and len(seen) == 1
    req = seen[0]
    assert req.url.host == PUBLIC_IP and req.url.path == "/oauth/metadata.json"
    assert req.headers["host"] == "client.example"
    assert req.headers["accept"] == "application/json"
    assert "cookie" not in req.headers and "authorization" not in req.headers


def test_real_http_client_settings():
    with client_metadata._make_client(5.0) as c:
        assert c.follow_redirects is False and c.trust_env is False and not c.cookies


def test_body_is_capped_while_streaming(monkeypatch):
    def chunks():
        for _ in range(100):
            yield b"x" * 1024

    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/json"}, content=chunks())

    monkeypatch.setattr(client_metadata, "_make_client",
                        lambda timeout: httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(client_metadata._TooLarge):
        client_metadata._http_get(CID, PUBLIC_IP, timeout=5, max_bytes=5120)


def test_declared_oversized_body_is_refused_up_front(monkeypatch):
    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/json", "content-length": "999999"},
                              content=b"{}")

    monkeypatch.setattr(client_metadata, "_make_client",
                        lambda timeout: httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(client_metadata._TooLarge):
        client_metadata._http_get(CID, PUBLIC_IP, timeout=5, max_bytes=5120)


def test_slow_body_hits_the_overall_deadline(monkeypatch):
    def slow():
        for _ in range(10):
            time.sleep(0.03)
            yield b" "

    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/json"}, content=slow())

    monkeypatch.setattr(client_metadata, "_make_client",
                        lambda timeout: httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(httpx.ReadTimeout):
        client_metadata._http_get(CID, PUBLIC_IP, timeout=0.1, max_bytes=5120)


# ---------------------------------------------------------------------------
# caching (§6.2) and failures (§6.1)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("headers, expected", [
    ({}, client_metadata.DEFAULT_CACHE_SECONDS),
    ({"cache-control": "public, max-age=600"}, 600),
    ({"cache-control": "max-age=600", "age": "100"}, 500),
    ({"cache-control": "max-age=5"}, 60),                 # minimum bound
    ({"cache-control": "max-age=99999999"}, 86400),       # maximum bound
    ({"cache-control": "no-store"}, 60),
    ({"cache-control": "no-cache, max-age=600"}, 60),
    ({"cache-control": "max-age=bogus"}, client_metadata.DEFAULT_CACHE_SECONDS),
    ({"expires": "Thu, 01 Jan 2099 00:00:00 GMT"}, client_metadata.DEFAULT_CACHE_SECONDS),
])
def test_cache_lifetime(headers, expected):
    assert client_metadata.cache_seconds(httpx.Headers(headers)) == expected


def test_cached_document_is_reused_until_stale(owner_client, service, web, cimd_cfg):
    assert _authorize(owner_client).status_code == 302
    assert _authorize(owner_client).status_code == 302
    assert len(web.calls) == 1
    cimd_cfg(cache_min_seconds=0)
    web.serve(headers={"cache-control": "max-age=0"})
    client_metadata.forget(CID)
    _authorize(owner_client)
    _authorize(owner_client)
    assert len(web.calls) == 3  # max-age=0 within a 0 s minimum: fetched every time


def test_refetch_updates_the_stored_client(owner_client, service, web):
    _authorize(owner_client)
    web.serve(body=document(client_name="Renamed"))
    client_metadata.forget(CID)
    _authorize(owner_client)
    assert owner_client.get(f"/api/oauth/clients/{quote(CID, safe='')}").json()["client_name"] == "Renamed"


def test_changed_redirect_uris_forget_remembered_consents(owner_client, service, web):
    code, verifier = _authorize_and_consent(owner_client, CID, remember=True)
    assert len(owner_client.get("/api/oauth/consents").json()["consents"]) == 1
    client_metadata.forget(CID)
    _authorize(owner_client)  # same document: consent kept
    assert len(owner_client.get("/api/oauth/consents").json()["consents"]) == 1
    web.serve(body=document(redirect_uris=[REDIRECT_URI, "https://new.client.example/cb"]))
    client_metadata.forget(CID)
    _authorize(owner_client)
    assert owner_client.get("/api/oauth/consents").json()["consents"] == []


def test_failure_backoff(owner_client, service, web, cimd_cfg):
    web.fail()
    r1, r2 = _authorize(owner_client), _authorize(owner_client)
    assert r1.status_code == r2.status_code == 400
    assert r1.json() == r2.json() and "could not be fetched" in r1.json()["error_description"]
    assert len(web.calls) == 1  # the second request did not fetch again
    # the error is not stored as metadata: once the backoff is over, a good document is used at once
    web.serve()
    client_metadata._failures.clear()
    assert _authorize(owner_client).status_code == 302


def test_failure_backoff_can_be_disabled(owner_client, service, web, cimd_cfg):
    cimd_cfg(failure_backoff_seconds=0)
    web.fail()
    _authorize(owner_client)
    _authorize(owner_client)
    assert len(web.calls) == 2


def test_authorize_aborts_on_failure_even_with_a_stored_copy(owner_client, service, web):
    assert _authorize(owner_client).status_code == 302
    web.fail()
    client_metadata.forget(CID)
    r = _authorize(owner_client)
    assert r.status_code == 400 and "could not be fetched" in r.json()["error_description"]


def test_token_endpoint_uses_the_stored_copy_on_transient_failure(owner_client, service, web):
    tokens = _tokens(owner_client)
    web.fail()
    client_metadata.forget(CID)
    r = _refresh(owner_client, tokens["refresh_token"])
    assert r.status_code == 200, r.text
    web.serve(status=503, body=b"")
    client_metadata.forget(CID)
    assert _refresh(owner_client, r.json()["refresh_token"]).status_code == 200


def test_token_endpoint_refuses_on_terminal_failure(owner_client, service, web):
    tokens = _tokens(owner_client)
    web.serve(body=document(redirect_uris=["javascript:x"]))
    client_metadata.forget(CID)
    r = _refresh(owner_client, tokens["refresh_token"])
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_token_endpoint_transient_failure_without_stored_copy_is_503(client, web):
    web.fail()
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": CID, "refresh_token": "x"})
    assert r.status_code == 503 and r.json()["error"] == "invalid_client"


def test_client_id_mismatch_revokes_outstanding_tokens(owner_client, service, web):
    from db.models import OAuthToken

    tokens = _tokens(owner_client)
    web.serve(body=document(client_id="https://elsewhere.example/metadata.json"))
    client_metadata.forget(CID)
    r = _refresh(owner_client, tokens["refresh_token"])
    assert r.status_code == 401 and "does not match" in r.json()["error_description"]
    db = _db()
    try:
        rows = db.query(OAuthToken).filter(OAuthToken.client_id == CID).all()
        assert rows and all(t.revoked_at is not None and t.revoke_reason == "metadata_mismatch" for t in rows)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# owner controls
# ---------------------------------------------------------------------------
def test_console_routes_accept_url_client_ids(owner_client, service, web):
    _tokens(owner_client)
    path = f"/api/oauth/clients/{quote(CID, safe='')}"
    assert owner_client.get(path).json()["client_id"] == CID
    r = owner_client.post(f"{path}/revoke")
    assert r.status_code == 200 and r.json()["tokens_revoked"] >= 1
    # a revoked metadata-document client stays revoked: no fetch, refused
    client_metadata.forget(CID)
    calls = len(web.calls)
    r = _authorize(owner_client)
    assert r.status_code == 400 and r.json()["error_description"] == "unknown or revoked client"
    assert len(web.calls) == calls
    assert owner_client.post(f"{path}/approve").json()["is_active"] is True
    assert owner_client.delete(path).status_code == 200
    assert owner_client.get(path).status_code == 404
    # deleted: the next authorization fetches and creates it again
    assert _authorize(owner_client).status_code == 302


def test_review_before_use(owner_client, service, web, cimd_cfg):
    cimd_cfg(auto_approve=False)
    r = _authorize(owner_client)
    assert r.status_code == 403 and r.json()["error"] == "access_denied"
    pending = owner_client.get("/api/oauth/clients", params={"status": "pending"}).json()["clients"]
    assert [c["client_id"] for c in pending] == [CID]
    owner_client.post(f"/api/oauth/clients/{quote(CID, safe='')}/approve")
    assert _authorize(owner_client).status_code == 302


def test_unused_metadata_clients_are_purged_but_revoked_ones_kept(owner_client, service, web):
    from db.models import OAuthClient, local_now
    from src.adapters import OAuthClientAdapter

    other = "https://other.example/metadata.json"
    web.serve(other, document(client_id=other))
    _authorize(owner_client)
    _authorize(owner_client, client_id=other)
    owner_client.post(f"/api/oauth/clients/{quote(other, safe='')}/revoke")
    db = _db()
    try:
        for c in db.query(OAuthClient).filter(OAuthClient.created_via == "cimd"):
            c.created_at = local_now() - timedelta(days=40)
        db.commit()
        assert OAuthClientAdapter.delete_unused_dcr(db, older_than=timedelta(days=30)) == 1
        remaining = {c.client_id for c in db.query(OAuthClient).filter(OAuthClient.created_via == "cimd")}
        assert remaining == {other}
    finally:
        db.close()


def test_long_client_ids_fit_every_column(owner_client, service, web):
    """255-character URL: stored in clients, requests, codes, tokens, consents, usage and audit rows (PostgreSQL
    enforces VARCHAR lengths; run with TEST_DATABASE_URL to check there)."""
    long_id = "https://client.example/" + "m" * (255 - len("https://client.example/") - 5) + ".json"
    assert len(long_id) == 255
    web.serve(long_id, document(client_id=long_id))
    code, verifier = _authorize_and_consent(owner_client, long_id, remember=True)
    assert _exchange(owner_client, long_id, code, verifier).status_code == 200
