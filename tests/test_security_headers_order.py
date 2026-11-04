"""Security headers on every response (#35): SecurityHeadersMiddleware is the outermost user middleware, so
responses produced by other middleware (429, CORS preflight) carry the headers, and unhandled 500s get them
from the exception handler that runs inside ServerErrorMiddleware."""

import pytest
from fastapi.testclient import TestClient

EXPECTED = {
    "x-frame-options": "DENY",
    "content-security-policy": "frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def _assert_security_headers(response):
    for name, value in EXPECTED.items():
        assert response.headers.get(name) == value, f"{name} missing on {response.status_code}"


def test_security_headers_on_normal_response(client):
    _assert_security_headers(client.get("/health"))


def test_security_headers_on_cors_preflight(client, monkeypatch):
    from src.config import Config

    monkeypatch.setattr(Config.get_cors_config(), "allowed_origins", ["http://localhost:5173"])
    from main import create_app
    from tests.conftest import make_console_client

    with make_console_client(create_app()) as c:
        r = c.options("/api/session/status", headers={
            "Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
        })
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
    _assert_security_headers(r)


def test_security_headers_on_public_oauth_preflight(client):
    r = client.options("/oauth/token", headers={
        "Origin": "https://any-client.example", "Access-Control-Request-Method": "POST",
    })
    assert r.status_code in (200, 204)
    _assert_security_headers(r)


@pytest.fixture
def rate_limited_app(seeded):
    from main import create_app
    from src.config import Config
    from src.middleware.rate_limiter import RateLimiter

    rl = Config.get_rate_limit_config()
    saved = (rl.enabled, rl.requests_per_minute, list(rl.whitelist))
    rl.enabled, rl.requests_per_minute, rl.whitelist = True, 1, []
    RateLimiter.reset_instance()
    try:
        yield create_app()
    finally:
        rl.enabled, rl.requests_per_minute, rl.whitelist = saved
        RateLimiter.reset_instance()


def test_security_headers_on_rate_limit_429(rate_limited_app):
    with TestClient(rate_limited_app, base_url="http://testserver") as c:
        assert c.get("/api/session/status").status_code == 200
        r = c.get("/api/session/status")
    assert r.status_code == 429
    _assert_security_headers(r)


def test_security_headers_on_unhandled_500(app):
    async def boom():
        raise RuntimeError("kaboom")

    app.add_api_route("/__test_boom", boom, methods=["POST"])
    with TestClient(app, base_url="http://testserver", raise_server_exceptions=False) as c:
        r = c.post("/__test_boom")
    assert r.status_code == 500
    assert r.text == "Internal Server Error"
    _assert_security_headers(r)


def test_security_headers_middleware_is_outermost(app):
    from src.middleware import SecurityHeadersMiddleware

    # user_middleware[0] is the outermost (last added)
    assert app.user_middleware[0].cls is SecurityHeadersMiddleware


def test_existing_header_not_overwritten():
    from starlette.datastructures import MutableHeaders

    from src.middleware.security_headers import apply_security_headers

    headers = MutableHeaders({"X-Frame-Options": "SAMEORIGIN"})
    apply_security_headers(headers)
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-Content-Type-Options"] == "nosniff"
