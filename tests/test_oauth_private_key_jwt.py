"""private_key_jwt client authentication (RFC 7523): a client proves possession of a registered key instead of
sending a shared secret."""

import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from src.oauth import client_assertion
from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _register

TOKEN_ENDPOINT = "http://testserver/oauth/token"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


@pytest.fixture(autouse=True)
def _fresh_caches():
    client_assertion.reset_caches()
    yield
    client_assertion.reset_caches()


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def rsa_keypair(kid="rsa-1"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return _pem(key), jwk, "RS256"


def ec_keypair(kid="ec-1"):
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "ES256"})
    return _pem(key), jwk, "ES256"


def make_assertion(client_id, pem, alg, kid, **overrides):
    now = int(time.time())
    claims = {"iss": client_id, "sub": client_id, "aud": TOKEN_ENDPOINT, "iat": now, "exp": now + 120,
              "jti": uuid.uuid4().hex}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, pem, algorithm=alg, headers={"kid": kid})


def _register_pkjwt(client, jwk=None, **overrides):
    body = {"token_endpoint_auth_method": "private_key_jwt"}
    if jwk is not None:
        body["jwks"] = {"keys": [jwk]}
    body.update(overrides)
    return _register(client, **body)


def _exchange_with_assertion(client, client_id, code, verifier, assertion, **extra):
    data = {"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier, "resource": RESOURCE, "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion}
    data.update(extra)
    return client.post("/oauth/token", data=data)


# ---------------------------------------------------------------------------
# registration + discovery
# ---------------------------------------------------------------------------
def test_metadata_advertises_private_key_jwt(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert "private_key_jwt" in meta["token_endpoint_auth_methods_supported"]
    assert meta["token_endpoint_auth_signing_alg_values_supported"] == ["RS256", "ES256"]


def test_registration_needs_exactly_one_key_source(client):
    _, jwk, _ = rsa_keypair()
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT_URI],
                                             "token_endpoint_auth_method": "private_key_jwt"})
    assert r.status_code == 400 and "exactly one of jwks or jwks_uri" in r.json()["error_description"]
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT_URI],
                                             "token_endpoint_auth_method": "private_key_jwt",
                                             "jwks": {"keys": [jwk]}, "jwks_uri": "https://example.com/jwks"})
    assert r.status_code == 400
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT_URI],
                                             "token_endpoint_auth_method": "private_key_jwt",
                                             "jwks_uri": "http://insecure.example/jwks"})
    assert r.status_code == 400 and "https" in r.json()["error_description"]
    # a private key in the JWKS is refused
    bad = dict(jwk, d="AQAB")
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT_URI],
                                             "token_endpoint_auth_method": "private_key_jwt", "jwks": {"keys": [bad]}})
    assert r.status_code == 400
    # a key that only looks like one (truncated modulus) is refused too
    fake = dict(jwk, n="sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5AcQ6i3Hw")
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT_URI],
                                             "token_endpoint_auth_method": "private_key_jwt", "jwks": {"keys": [fake]}})
    assert r.status_code == 400 and "could not be parsed" in r.json()["error_description"]


def test_registration_returns_keys_and_no_secret(client):
    _, jwk, _ = rsa_keypair()
    reg = _register_pkjwt(client, jwk)
    assert "client_secret" not in reg
    assert reg["token_endpoint_auth_method"] == "private_key_jwt"
    assert reg["jwks"]["keys"][0]["kid"] == "rsa-1"


# ---------------------------------------------------------------------------
# token endpoint
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("keypair", [rsa_keypair, ec_keypair])
def test_assertion_authenticates_token_exchange(owner_client, service, keypair):
    pem, jwk, alg = keypair()
    reg = _register_pkjwt(owner_client, jwk)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                 make_assertion(reg["client_id"], pem, alg, jwk["kid"]))
    assert r.status_code == 200, r.text
    tokens = r.json()
    # ...and on introspection too, without client_id in the form (taken from the assertion)
    intro = owner_client.post("/oauth/introspect", data={
        "token": tokens["access_token"], "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": make_assertion(reg["client_id"], pem, alg, jwk["kid"]),
    }).json()
    assert intro["active"] is True and intro["client_id"] == reg["client_id"]


def test_assertion_via_jwks_uri_with_cache_and_rotation(owner_client, service, monkeypatch):
    pem1, jwk1, alg = rsa_keypair("k1")
    pem2, jwk2, _ = rsa_keypair("k2")
    served = {"doc": {"keys": [jwk1]}, "fetches": 0}

    class FakeResponse:
        def __init__(self, doc):
            self._doc = doc

        def raise_for_status(self):
            pass

        def json(self):
            return self._doc

    def fake_get(url, address):
        served["fetches"] += 1
        return FakeResponse(served["doc"])

    monkeypatch.setattr(client_assertion, "_get_pinned", fake_get)
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["93.184.216.34"])
    reg = _register_pkjwt(owner_client, jwks_uri="https://client.example/jwks.json")

    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                    make_assertion(reg["client_id"], pem1, alg, "k1")).status_code == 200
    assert served["fetches"] == 1
    # second request within the TTL is served from cache
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                    make_assertion(reg["client_id"], pem1, alg, "k1")).status_code == 200
    assert served["fetches"] == 1
    # the client rotates to k2: unknown kid triggers exactly one refetch
    served["doc"] = {"keys": [jwk2]}
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                    make_assertion(reg["client_id"], pem2, alg, "k2")).status_code == 200
    assert served["fetches"] == 2


@pytest.mark.parametrize("tamper, message", [
    ({"aud": "http://elsewhere.example/oauth/token"}, "aud"),
    ({"exp": int(time.time()) - 60}, "expired"),
    ({"exp": int(time.time()) + 3600}, "lifetime"),
    ({"jti": None}, "jti"),
    ({"sub": "someone-else"}, "iss and sub"),
])
def test_bad_assertion_claims_are_rejected(owner_client, service, tamper, message):
    pem, jwk, alg = rsa_keypair()
    reg = _register_pkjwt(owner_client, jwk)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                 make_assertion(reg["client_id"], pem, alg, jwk["kid"], **tamper))
    assert r.status_code == 401, r.text
    assert r.json()["error"] == "invalid_client" and message in r.json()["error_description"]


def test_wrong_key_and_replay_are_rejected(owner_client, service):
    pem, jwk, alg = rsa_keypair()
    other_pem, _, _ = rsa_keypair("rsa-1")  # same kid, different key
    reg = _register_pkjwt(owner_client, jwk)

    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                 make_assertion(reg["client_id"], other_pem, alg, "rsa-1"))
    assert r.status_code == 401 and "invalid client_assertion" in r.json()["error_description"]

    assertion = make_assertion(reg["client_id"], pem, alg, jwk["kid"])
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange_with_assertion(owner_client, reg["client_id"], code, verifier, assertion).status_code == 200
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = _exchange_with_assertion(owner_client, reg["client_id"], code, verifier, assertion)
    assert r.status_code == 401 and "replayed" in r.json()["error_description"]


def test_method_mismatch_is_rejected(owner_client, service):
    pem, jwk, alg = rsa_keypair()
    # a private_key_jwt client cannot fall back to a bare client_id
    reg = _register_pkjwt(owner_client, jwk)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = owner_client.post("/oauth/token", data={"grant_type": "authorization_code", "client_id": reg["client_id"],
                                                "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier,
                                                "resource": RESOURCE})
    assert r.status_code == 401 and "client_assertion required" in r.json()["error_description"]
    # a secret-based client cannot authenticate with an assertion, even a well-formed one
    secret_reg = _register(owner_client, token_endpoint_auth_method="client_secret_post")
    code, verifier = _authorize_and_consent(owner_client, secret_reg["client_id"])
    r = _exchange_with_assertion(owner_client, secret_reg["client_id"], code, verifier,
                                 make_assertion(secret_reg["client_id"], pem, alg, jwk["kid"]))
    assert r.status_code == 401 and "not registered for private_key_jwt" in r.json()["error_description"]
    # mixing an assertion with a secret is refused outright
    r = owner_client.post("/oauth/token", data={"grant_type": "authorization_code", "client_id": secret_reg["client_id"],
                                                "client_secret": secret_reg["client_secret"], "code": "x",
                                                "redirect_uri": REDIRECT_URI, "code_verifier": "y",
                                                "client_assertion_type": ASSERTION_TYPE, "client_assertion": "z"})
    assert r.status_code == 401 and "one client authentication method" in r.json()["error_description"]


def test_console_can_register_private_key_jwt_client(owner_client):
    _, jwk, _ = rsa_keypair()
    r = owner_client.post("/api/oauth/clients", json={"client_name": "CI job", "redirect_uris": [REDIRECT_URI],
                                                       "token_endpoint_auth_method": "private_key_jwt",
                                                       "jwks": {"keys": [jwk]}})
    assert r.status_code == 201, r.text
    assert "client_secret" not in r.json()
    listed = owner_client.get("/api/oauth/clients").json()["clients"]
    me = next(c for c in listed if c["client_id"] == r.json()["client_id"])
    assert me["is_confidential"] is True and me["jwks"]["keys"][0]["kid"] == "rsa-1" and me["jwks_uri"] is None


@pytest.mark.parametrize("uri, resolved, message", [
    ("https://localhost.evil.example/jwks", ["93.184.216.34"], "does not resolve"),   # prefix trick, unresolvable here
    ("https://internal.example/jwks", ["10.0.0.5"], "non-public"),
    ("https://meta.example/jwks", ["169.254.169.254"], "non-public"),
    ("https://user:pw@keys.example/jwks", ["93.184.216.34"], "credentials"),
    ("https://localhost/jwks", ["127.0.0.1"], "this machine"),
])
def test_jwks_uri_cannot_point_inside(client, monkeypatch, uri, resolved, message):
    """MCP Gate fetches jwks_uri itself, so it must never be steered at internal addresses (SSRF)."""
    from src.config import Config
    monkeypatch.setattr(Config.get_oauth_config(), "issuer", "https://auth.example")  # production: no loopback
    monkeypatch.setattr(client_assertion, "_resolve_host",
                        lambda host: [] if host == "localhost.evil.example" else resolved)
    r = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT_URI],
                                             "token_endpoint_auth_method": "private_key_jwt", "jwks_uri": uri})
    assert r.status_code == 400, r.text
    assert message in r.json()["error_description"]


def test_jwks_uri_rechecked_before_each_fetch(owner_client, service, monkeypatch):
    """A host that resolved publicly at registration but to a private address at fetch time is refused."""
    pem, jwk, alg = rsa_keypair("k1")
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["93.184.216.34"])
    reg = _register_pkjwt(owner_client, jwks_uri="https://client.example/jwks.json")
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["10.0.0.5"])  # DNS rebinding
    called = {"n": 0}
    monkeypatch.setattr(client_assertion, "_get_pinned", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    r = _exchange_with_assertion(owner_client, reg["client_id"], code, verifier,
                                 make_assertion(reg["client_id"], pem, alg, "k1"))
    assert r.status_code == 401 and called["n"] == 0


# ---------------------------------------------------------------------------
# jwks_uri fetch hardening (#33)
# ---------------------------------------------------------------------------
class _JwksClient:
    """The two attributes _client_keys reads from an OAuthClient."""
    jwks = None
    jwks_uri = "https://client.example/jwks.json"


def test_unknown_kid_refetch_is_throttled(monkeypatch):
    """An unknown kid forces one refetch; more unknown kids inside the interval are answered from cache."""
    _, jwk, _ = rsa_keypair("k1")
    fetches = []
    clock = {"now": 1000.0}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": [jwk]}

    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(client_assertion, "_get_pinned", lambda url, address: fetches.append(url) or FakeResponse())
    monkeypatch.setattr(client_assertion, "time", type("T", (), {"monotonic": staticmethod(lambda: clock["now"]),
                                                                  "time": staticmethod(time.time)}))
    client = _JwksClient()
    assert client_assertion._client_keys(client, "k1", "RS256", allow_loopback=False)["kid"] == "k1"
    assert len(fetches) == 1
    for _ in range(5):  # a flood of assertions with a kid the client never published
        with pytest.raises(client_assertion.OAuthError):
            client_assertion._client_keys(client, "nope", "RS256", allow_loopback=False)
    assert len(fetches) == 2  # one forced refetch, not five
    clock["now"] += client_assertion.JWKS_FORCED_REFETCH_INTERVAL + 1
    with pytest.raises(client_assertion.OAuthError):
        client_assertion._client_keys(client, "nope", "RS256", allow_loopback=False)
    assert len(fetches) == 3


def test_jwks_fetch_connects_to_the_validated_address(monkeypatch):
    """The fetch dials the address that passed the check, never re-resolving the name; Host and SNI keep the
    hostname so virtual hosting and certificate verification are unaffected."""
    import httpx
    _, jwk, _ = rsa_keypair("k1")
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"keys": [jwk]})

    real_client = httpx.Client
    monkeypatch.setattr(client_assertion.httpx, "Client",
                        lambda **kw: real_client(**kw, transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["93.184.216.34"])
    doc = client_assertion.fetch_jwks("https://client.example:8443/jwks.json")
    assert doc["keys"][0]["kid"] == "k1"
    (req,) = seen
    assert req.url.host == "93.184.216.34" and req.url.port == 8443 and req.url.path == "/jwks.json"
    assert req.headers["Host"] == "client.example:8443"
    assert req.extensions["sni_hostname"] == "client.example"


@pytest.mark.parametrize("address", ["100.100.100.200", "100.64.0.1", "fd00:ec2::254", "::ffff:10.0.0.5",
                                     "192.0.2.10"])
def test_jwks_uri_must_resolve_to_a_global_address(monkeypatch, address):
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: [address])
    with pytest.raises(client_assertion.OAuthError, match="non-public"):
        client_assertion.validate_jwks_uri("https://client.example/jwks", allow_loopback=False)


def test_loopback_jwks_uri_must_resolve_to_loopback(monkeypatch):
    """The development allowance covers this machine only, even for a *.localhost name."""
    monkeypatch.setattr(client_assertion, "_resolve_host", lambda host: ["10.0.0.5"])
    with pytest.raises(client_assertion.OAuthError, match="this machine"):
        client_assertion.validate_jwks_uri("http://keys.localhost/jwks", allow_loopback=True)


def _tls_server(tmp_path, cert_hostname, body):
    """A one-shot HTTPS server on 127.0.0.1 with a self-signed certificate for ``cert_hostname``."""
    import datetime
    import http.server
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cert_hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cert_hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_text(_pem(key))
    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received["host"] = self.headers.get("Host")
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_file, key_file)
    server_ctx.sni_callback = lambda sock, sni, ctx: received.__setitem__("sni", sni)
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, ssl.create_default_context(cafile=str(cert_file)), received


@pytest.mark.parametrize("cert_hostname, ok", [("keys.example", True), ("other.example", False)])
def test_pinned_fetch_over_real_tls_verifies_the_hostname(tmp_path, monkeypatch, cert_hostname, ok):
    """Against a real TLS server: connecting to the pinned IP still sends the hostname as SNI and Host, and the
    certificate is verified against the hostname (a certificate for another name is refused)."""
    import httpx
    httpd, client_ctx, received = _tls_server(tmp_path, cert_hostname, {"keys": []})
    real_client = httpx.Client
    # the only test-side change: trust the self-signed certificate instead of the system store
    monkeypatch.setattr(client_assertion.httpx, "Client", lambda **kw: real_client(**{**kw, "verify": client_ctx}))
    url = f"https://keys.example:{httpd.server_address[1]}/jwks.json"
    try:
        if ok:
            r = client_assertion._get_pinned(url, "127.0.0.1")
            assert r.status_code == 200 and r.json() == {"keys": []}
            assert received == {"sni": "keys.example", "host": f"keys.example:{httpd.server_address[1]}"}
        else:
            with pytest.raises(httpx.ConnectError, match="(?i)certificate|hostname"):
                client_assertion._get_pinned(url, "127.0.0.1")
    finally:
        httpd.shutdown()
