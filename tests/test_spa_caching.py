"""SPA static asset caching policy

Background (hit in practice): index.html carried no Cache-Control -> browser heuristic caching -> after a
deploy, users loaded old bundles (already deleted by the new build) via the stale index -> blank page
until a hard refresh.

Policy:
  - index.html (no hash, content changes every build) -> no-cache (revalidated with an ETag conditional
    request every time)
  - /assets/* (filenames contain a content hash, never change) -> immutable long-term caching

Note: under pytest, main.STATIC_DIR is derived from the launching program and points to the wrong place
(the shared client fixture does not mount the frontend), so this file builds its own app and points
STATIC_DIR at the real static/web inside the repo.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REAL_STATIC = Path(__file__).resolve().parent.parent / "static" / "web"


@pytest.fixture
def spa_client(client, monkeypatch):
    """Reuse the DB/config setup done by the client fixture, but build a separate app with the frontend mounted."""
    if not (REAL_STATIC / "index.html").exists():
        pytest.skip("Frontend not built yet (static/web/index.html does not exist)")
    import main
    monkeypatch.setattr(main, "STATIC_DIR", REAL_STATIC)
    app = main.create_app()
    with TestClient(app) as c:
        yield c


class TestIndexHtmlCaching:
    @pytest.mark.parametrize("path", ["/", "/services", "/marketplace", "/tokens", "/consent"])
    def test_index_is_no_cache(self, spa_client, path):
        resp = spa_client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert resp.headers.get("cache-control") == "no-cache"
        # An ETag is still required so no-cache can use a cheap 304 conditional request
        assert resp.headers.get("etag")

    def test_index_revalidates_with_etag(self, spa_client):
        first = spa_client.get("/")
        etag = first.headers["etag"]
        again = spa_client.get("/", headers={"If-None-Match": etag})
        assert again.status_code == 304

    def test_api_prefix_is_not_swallowed_by_spa(self, spa_client):
        resp = spa_client.get("/api/definitely-not-a-route")
        assert resp.status_code in (401, 404)
        assert "text/html" not in resp.headers.get("content-type", "")


class TestHashedAssetsCaching:
    def test_hashed_asset_is_immutable(self, spa_client):
        js = sorted((REAL_STATIC / "assets").glob("index-*.js"))
        assert js, "build output should exist"
        resp = spa_client.get(f"/assets/{js[0].name}")
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "public, max-age=31536000, immutable"
