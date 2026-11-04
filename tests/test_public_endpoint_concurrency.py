"""H-06: the public discovery surface must survive a burst of concurrent requests.

Every route used to run its synchronous SQLAlchemy queries on the event loop. Once the connection pool
(5 + 10) was exhausted, the next checkout blocked the loop itself, so the connections already checked out
could never be returned and the whole server froze (about 17 concurrent GETs of /.well-known/jwks.json were
enough on the default SQLite setup). These tests run a real uvicorn server against a file SQLite database,
i.e. the app's real pool, and fire the burst from another thread.
"""

import asyncio
import socket
import threading
import time
from datetime import timedelta

import httpx
import pytest


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(app):
    import uvicorn

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="off", log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


async def _burst(base: str, paths: list[str]) -> list:
    async with httpx.AsyncClient(timeout=10) as ac:
        return await asyncio.gather(*[ac.get(base + p) for p in paths], return_exceptions=True)


def test_fifty_concurrent_discovery_requests_do_not_freeze_the_server(live_server):
    paths = ["/.well-known/jwks.json"] * 50 + ["/.well-known/oauth-authorization-server"] * 25 \
        + ["/.well-known/openid-configuration"] * 25
    started = time.monotonic()
    results = asyncio.run(_burst(live_server, paths))
    elapsed = time.monotonic() - started

    failed = [r for r in results if isinstance(r, Exception) or r.status_code != 200]
    assert failed == [], f"{len(failed)} of {len(paths)} requests failed, e.g. {failed[:3]!r}"
    assert elapsed < 8, f"burst took {elapsed:.1f}s"
    # and the server still answers afterwards
    assert httpx.get(live_server + "/health", timeout=5).status_code == 200


def test_fifty_concurrent_token_requests_do_not_freeze_the_server(live_server):
    """Endpoints that do need the DB (client authentication) must not run it on the event loop either."""

    async def go():
        async with httpx.AsyncClient(timeout=10) as ac:
            return await asyncio.gather(*[
                ac.post(live_server + "/oauth/token",
                        data={"grant_type": "client_credentials", "client_id": "nope", "client_secret": "x"})
                for _ in range(50)
            ], return_exceptions=True)

    started = time.monotonic()
    results = asyncio.run(go())
    elapsed = time.monotonic() - started
    failed = [r for r in results if isinstance(r, Exception) or r.status_code != 401]
    assert failed == [], f"{len(failed)} of 50 requests failed, e.g. {failed[:3]!r}"
    assert elapsed < 8, f"burst took {elapsed:.1f}s"
    assert httpx.get(live_server + "/health", timeout=5).status_code == 200


def test_jwks_and_metadata_are_served_from_memory(client, monkeypatch):
    """After the first request neither document touches the database."""
    from src.adapters import OAuthKeyAdapter, OAuthScopeAdapter

    first_jwks = client.get("/.well-known/jwks.json").json()
    first_meta = client.get("/.well-known/oauth-authorization-server").json()

    def boom(*a, **k):
        raise AssertionError("hit the database")

    monkeypatch.setattr(OAuthKeyAdapter, "list_all", staticmethod(boom))
    monkeypatch.setattr(OAuthScopeAdapter, "list_all", staticmethod(boom))
    assert client.get("/.well-known/jwks.json").json() == first_jwks
    assert client.get("/.well-known/oauth-authorization-server").json() == first_meta
    assert client.get("/.well-known/openid-configuration").json() == first_meta


def test_key_rotation_invalidates_the_cached_jwks(owner_client):
    before = {k["kid"] for k in owner_client.get("/.well-known/jwks.json").json()["keys"]}
    r = owner_client.post("/api/oauth/keys/rotate")
    assert r.status_code == 200, r.text
    after = {k["kid"] for k in owner_client.get("/.well-known/jwks.json").json()["keys"]}
    assert before < after and len(after) == len(before) + 1


def test_scope_changes_invalidate_the_cached_metadata(owner_client, service):
    def scopes():
        return owner_client.get("/.well-known/oauth-authorization-server").json()["scopes_supported"]

    assert "reports:read" not in scopes()
    r = owner_client.put("/api/oauth/scopes/reports:read", json={"description": "x"})
    assert r.status_code in (200, 201), r.text
    assert "reports:read" in scopes()
    assert owner_client.delete("/api/oauth/scopes/reports:read").status_code in (200, 204)
    assert "reports:read" not in scopes()

    r = owner_client.put(f"/api/oauth/services/{service['id']}/scopes/demo:write", json={})
    assert r.status_code in (200, 201), r.text
    assert "demo:write" in scopes()
    assert owner_client.delete(f"/api/services/{service['id']}").status_code in (200, 204)
    assert "demo:write" not in scopes()


def test_cached_jwks_drops_a_retired_key_on_schedule(owner_client, monkeypatch):
    """The cache must not keep a retired key published past its grace period: it expires by itself at the next
    scheduled retirement (and never later than JWKS_CACHE_MAX_SECONDS), without needing another rotation."""
    from src.oauth import signing_keys
    from src.utils import public_cache

    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    assert len(owner_client.get("/.well-known/jwks.json").json()["keys"]) == 2
    expires_at = public_cache._entries["jwks"][1]
    assert expires_at - time.monotonic() <= signing_keys.JWKS_CACHE_MAX_SECONDS + 0.5

    # Jump past the retired key's grace period, on both clocks the cache and the key check use
    grace = signing_keys.retired_key_grace()
    real_now, real_mono = signing_keys.local_now, time.monotonic
    monkeypatch.setattr(signing_keys, "local_now", lambda: real_now() + grace + timedelta(minutes=1))
    monkeypatch.setattr(public_cache.time, "monotonic", lambda: real_mono() + grace.total_seconds() + 60)
    assert len(owner_client.get("/.well-known/jwks.json").json()["keys"]) == 1


def test_jwks_cache_lifetime_ends_at_the_next_retirement(owner_client, monkeypatch):
    from src.oauth import signing_keys
    from src.utils import public_cache

    assert owner_client.post("/api/oauth/keys/rotate").status_code == 200
    # a retired key due to leave in ~3 s: the cached JWKS must not outlive that
    monkeypatch.setattr(signing_keys, "retired_key_grace", lambda: timedelta(seconds=3))
    public_cache.invalidate()
    assert len(owner_client.get("/.well-known/jwks.json").json()["keys"]) == 2
    assert public_cache._entries["jwks"][1] - time.monotonic() <= 3.5
