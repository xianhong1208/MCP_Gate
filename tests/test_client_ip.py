"""Client IP resolution (#35): forwarded headers only from trusted proxies, X-Forwarded-For read right to left.

The same resolver feeds the audit log, request logging, OAuth token events and the rate limiter.
"""

from types import SimpleNamespace

import pytest

from src.utils.client_ip import resolve_client_ip, resolve_client_ip_from

TRUSTED = ["127.0.0.1", "10.0.0.0/8"]


def _resolve(peer, headers=None, trusted=TRUSTED):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return resolve_client_ip_from(peer, headers.get, trusted)


@pytest.mark.parametrize("peer, headers, expected", [
    # Untrusted peer: headers are ignored entirely
    ("203.0.113.9", {}, "203.0.113.9"),
    ("203.0.113.9", {"X-Forwarded-For": "1.2.3.4"}, "203.0.113.9"),
    ("203.0.113.9", {"X-Real-IP": "1.2.3.4"}, "203.0.113.9"),
    # Trusted peer without headers: the peer itself
    ("127.0.0.1", {}, "127.0.0.1"),
    # Trusted peer, single hop
    ("127.0.0.1", {"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7"),
    # Client-supplied spoof on the left is skipped: the rightmost untrusted address wins
    ("127.0.0.1", {"X-Forwarded-For": "6.6.6.6, 198.51.100.7"}, "198.51.100.7"),
    # Chained trusted proxies are skipped
    ("127.0.0.1", {"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.1.2.3, 10.0.0.1"}, "198.51.100.7"),
    # Every hop trusted: the leftmost one
    ("127.0.0.1", {"X-Forwarded-For": "10.9.9.9, 10.0.0.1"}, "10.9.9.9"),
    # Malformed entry: stop at the last hop we can vouch for
    ("127.0.0.1", {"X-Forwarded-For": "not-an-ip, 10.0.0.1"}, "10.0.0.1"),
    ("127.0.0.1", {"X-Forwarded-For": "garbage"}, "127.0.0.1"),
    # X-Real-IP only as a fallback, and only if it parses
    ("127.0.0.1", {"X-Real-IP": "198.51.100.7"}, "198.51.100.7"),
    ("127.0.0.1", {"X-Real-IP": "nonsense"}, "127.0.0.1"),
    ("127.0.0.1", {"X-Forwarded-For": "198.51.100.7", "X-Real-IP": "6.6.6.6"}, "198.51.100.7"),
    # IPv6
    ("127.0.0.1", {"X-Forwarded-For": "2001:db8::1"}, "2001:db8::1"),
    # No peer at all
    (None, {"X-Forwarded-For": "1.2.3.4"}, None),
])
def test_resolution_matrix(peer, headers, expected):
    assert _resolve(peer, headers) == expected


def test_no_trusted_proxies_means_peer_only():
    assert _resolve("127.0.0.1", {"X-Forwarded-For": "1.2.3.4"}, trusted=[]) == "127.0.0.1"


def test_request_wrapper_defaults_to_configured_trusted_proxies():
    req = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={"x-forwarded-for": "198.51.100.7"})
    # Default security.trusted_proxies is ["127.0.0.1", "::1"]
    assert resolve_client_ip(req) == "198.51.100.7"
    req.client.host = "192.0.2.1"
    assert resolve_client_ip(req) == "192.0.2.1"


@pytest.fixture
def trust_testclient():
    """Make the TestClient peer ("testclient") a trusted proxy for the duration of a test."""
    from src.config import Config

    sec = Config.get_security_config()
    saved = list(sec.trusted_proxies)
    sec.trusted_proxies = ["testclient"]
    yield
    sec.trusted_proxies = saved


def _last_login_audit_ip(db_session):
    from db.models import AuditLog

    db_session.expire_all()
    row = db_session.query(AuditLog).filter(AuditLog.action == "admin_login").order_by(AuditLog.created_at.desc()).first()
    return row.ip_address


def test_audit_ignores_forwarded_for_from_untrusted_peer(client, db_session):
    r = client.post("/api/session/login", json={"email": "x@example.com", "password": "wrong-password"},
                    headers={"X-Forwarded-For": "6.6.6.6"})
    assert r.status_code == 401
    assert _last_login_audit_ip(db_session) == "testclient"


def test_audit_honours_forwarded_for_from_trusted_proxy(client, db_session, trust_testclient):
    r = client.post("/api/session/login", json={"email": "x@example.com", "password": "wrong-password"},
                    headers={"X-Forwarded-For": "6.6.6.6, 198.51.100.7"})
    assert r.status_code == 401
    assert _last_login_audit_ip(db_session) == "198.51.100.7"


def test_request_logging_and_oauth_routes_use_shared_resolver(trust_testclient):
    from src.api.oauth_routes import _client_ip
    from src.logging.middleware import RequestLoggingMiddleware

    req = SimpleNamespace(client=SimpleNamespace(host="testclient"),
                          headers={"x-forwarded-for": "6.6.6.6, 198.51.100.7"})
    assert _client_ip(req) == "198.51.100.7"
    assert RequestLoggingMiddleware._get_client_ip(None, req) == "198.51.100.7"


def test_rate_limiter_uses_rightmost_untrusted_hop():
    from src.middleware.rate_limiter import RateLimitConfig, RateLimitMiddleware, RateLimiter

    RateLimiter.reset_instance()
    try:
        mw = RateLimitMiddleware(app=None, config=RateLimitConfig(trusted_proxies=["127.0.0.1"]))
        spoofed = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                                  headers={"x-forwarded-for": "1.1.1.1, 198.51.100.7"})
        assert mw._get_client_ip(spoofed) == "198.51.100.7"
        direct = SimpleNamespace(client=SimpleNamespace(host="203.0.113.9"), headers={"x-forwarded-for": "1.1.1.1"})
        assert mw._get_client_ip(direct) == "203.0.113.9"
    finally:
        RateLimiter.reset_instance()


def test_issuer_check_uses_value_set_by_trusted_proxy():
    from src.middleware.issuer_check import external_base_url

    scope = {"scheme": "http", "client": ("127.0.0.1", 1234), "headers": [
        (b"host", b"internal:4568"),
        (b"x-forwarded-proto", b"http, https"),
        (b"x-forwarded-host", b"evil.example, auth.example.com"),
    ]}
    assert external_base_url(scope, ["127.0.0.1"]) == "https://auth.example.com"
