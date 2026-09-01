"""Interop with the real FastMCP (the acceptance test for the rewrite).

Starts two real HTTP servers:
  - MCP Center (this project) -> issuer = http://127.0.0.1:<port>
  - FastMCP demo server       -> RemoteAuthProvider(JWTVerifier(jwks_uri=<center>/.well-known/jwks.json))
Then:
  1. The RS's /.well-known/oauth-protected-resource points at MCP Center
  2. A Personal Access Token issued by the admin console can call a FastMCP tool directly; a bogus token is rejected
  3. FastMCP's own OAuth client (DCR + PKCE + consent page + token exchange) completes the full flow
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import uvicorn

from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ThreadServer:
    def __init__(self, app, port: int):
        self.port = port
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.time() + 15
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def center(seeded):
    """MCP Center over real HTTP; the issuer points at its own address."""
    from main import create_app
    from src.config import Config

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    cfg = Config.get_config_model()
    previous_issuer = cfg.oauth.issuer
    cfg.oauth.issuer = url
    try:
        with _ThreadServer(create_app(), port):
            with httpx.Client(base_url=url) as c:
                r = c.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD})
                assert r.status_code == 200, r.text
                cookie = r.cookies.get("mcp_session")
            yield {"url": url, "cookie": cookie}
    finally:
        cfg.oauth.issuer = previous_issuer


@pytest.fixture
def mcp_server(center):
    """FastMCP demo server that trusts only MCP Center's JWKS."""
    from fastmcp import FastMCP
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    from pydantic import AnyHttpUrl

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    mcp_url = f"{base_url}/mcp"
    auth = RemoteAuthProvider(
        token_verifier=JWTVerifier(jwks_uri=f"{center['url']}/.well-known/jwks.json",
                                   issuer=center["url"], audience=mcp_url),
        authorization_servers=[AnyHttpUrl(center["url"])],
        base_url=base_url,
    )
    mcp = FastMCP("interop-demo", auth=auth)

    @mcp.tool
    def hello(name: str) -> str:
        return f"Hello, {name}!"

    # Register this server in MCP Center (audience = MCP URL)
    with httpx.Client(base_url=center["url"], cookies={"mcp_session": center["cookie"]}) as c:
        r = c.post("/api/services", json={"name": "interop-demo", "host": "127.0.0.1", "port": port, "mcp_path": "/mcp"})
        assert r.status_code == 201, r.text
        service = r.json()
    assert service["effective_audience"] == mcp_url

    with _ThreadServer(mcp.http_app(path="/mcp"), port):
        yield {"url": mcp_url, "base_url": base_url, "service": service}


def _mint_pat(center, service_id: str, days: int = 1) -> str:
    with httpx.Client(base_url=center["url"], cookies={"mcp_session": center["cookie"]}) as c:
        r = c.post("/api/oauth/tokens/personal", json={"service_id": service_id, "expires_days": days})
        assert r.status_code == 201, r.text
        return r.json()["access_token"]


def test_protected_resource_metadata_points_to_center(center, mcp_server):
    r = httpx.get(f"{mcp_server['base_url']}/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200, r.text
    meta = r.json()
    assert center["url"] in [str(u).rstrip("/") for u in meta["authorization_servers"]]
    # No token -> 401 + WWW-Authenticate pointing at the resource metadata (per the MCP spec)
    r = httpx.post(mcp_server["url"], json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                   headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")


async def test_personal_access_token_works_with_fastmcp(center, mcp_server):
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    pat = _mint_pat(center, mcp_server["service"]["id"])
    async with Client(mcp_server["url"], auth=BearerAuth(pat)) as client:
        tools = await client.list_tools()
        assert [t.name for t in tools] == ["hello"]
        result = await client.call_tool("hello", {"name": "MCP Center"})
        assert "Hello, MCP Center!" in str(result.content[0].text)

    with pytest.raises(Exception):
        async with Client(mcp_server["url"], auth=BearerAuth("not-a-real-token")) as client:
            await client.list_tools()


async def test_revoked_pat_still_valid_offline_but_inactive_on_introspect(center, mcp_server):
    """An RS verifying offline via JWKS cannot see revocation (an inherent JWT limitation); introspect returns
    active=false."""
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth

    with httpx.Client(base_url=center["url"], cookies={"mcp_session": center["cookie"]}) as c:
        r = c.post("/api/oauth/tokens/personal", json={"service_id": mcp_server["service"]["id"], "expires_days": 1})
        pat, jti = r.json()["access_token"], r.json()["jti"]
        assert c.post(f"/api/oauth/tokens/{jti}/revoke").status_code == 200
        intro = c.post("/oauth/introspect", data={"token": pat, "client_id": "mcp-center-console"}).json()
        assert intro["active"] is False
    async with Client(mcp_server["url"], auth=BearerAuth(pat)) as client:
        assert await client.list_tools()


async def test_full_oauth_flow_with_fastmcp_client(center, mcp_server):
    """FastMCP's built-in OAuth client: discovery -> DCR -> PKCE authorize -> consent page -> callback -> token.

    redirect_handler would normally open a browser; here httpx simulates the user instead: hit the authorize URL
    with the admin console session, approve on the consent page, then call the client's callback URL back.
    """
    from fastmcp import Client
    from fastmcp.client.auth import OAuth

    class HeadlessOAuth(OAuth):
        async def redirect_handler(self, authorization_url: str) -> None:
            asyncio.get_running_loop().create_task(self._simulate_browser(authorization_url))

        async def _simulate_browser(self, authorization_url: str) -> None:
            await asyncio.sleep(0.3)  # wait for the callback server to come up
            async with httpx.AsyncClient(cookies={"mcp_session": center["cookie"]}, follow_redirects=False) as browser:
                r = await browser.get(authorization_url)
                assert r.status_code == 302, r.text
                location = r.headers["location"]
                if location.startswith("/consent"):
                    rid = parse_qs(urlparse(location).query)["rid"][0]
                    info = (await browser.get(f"{center['url']}/oauth/authorize/requests/{rid}")).json()
                    assert info["service"]["name"] == "interop-demo"
                    assert info["resource"] == mcp_server["url"]
                    d = await browser.post(f"{center['url']}/oauth/authorize/requests/{rid}/decision",
                                           json={"approve": True, "remember": True})
                    location = d.json()["redirect_to"]
                assert "code=" in location
                # This is the "browser gets redirected back to the client's localhost callback" step
                await browser.get(location)

    oauth = HeadlessOAuth(mcp_url=mcp_server["url"], client_name="interop-test-client", callback_timeout=30)
    async with Client(mcp_server["url"], auth=oauth) as client:
        tools = await client.list_tools()
        assert [t.name for t in tools] == ["hello"]
        result = await client.call_tool("hello", {"name": "OAuth"})
        assert "Hello, OAuth!" in str(result.content[0].text)

    # MCP Center now holds the DCR client, the remembered consent and the issued tokens
    with httpx.Client(base_url=center["url"], cookies={"mcp_session": center["cookie"]}) as c:
        clients = c.get("/api/oauth/clients").json()["clients"]
        assert any(cl["client_name"] == "interop-test-client" and cl["created_via"] == "dcr" for cl in clients)
        tokens = c.get("/api/oauth/tokens", params={"kind": "access"}).json()["tokens"]
        assert any(t["audience"] == mcp_server["url"] and t["client_name"] == "interop-test-client" for t in tokens)
        assert c.get("/api/oauth/consents").json()["total"] == 1
