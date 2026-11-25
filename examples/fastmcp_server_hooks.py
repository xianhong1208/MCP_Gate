"""A FastMCP server protected by MCP Gate, with the revocation feed, tool approvals, tool access rules and step-up.

Every request must carry an access token issued by MCP Gate for this server's audience. Tokens are verified
offline against MCP Gate's JWKS; MCP Gate is never on the request path. When a resource-server client is
configured (MCP_GATE_CLIENT_ID / MCP_GATE_CLIENT_SECRET):

- MCPGateVerifier polls MCP Gate's revocation feed, so a revoked token is refused within `poll_interval`
  seconds, and reports token usage to the console;
- MCPGateToolPinning lists and runs only the tools an admin approved in the console. A new or changed tool is
  hidden at once and shows up in the console as pending. The approved list is cached in MCP_GATE_POLICY_CACHE,
  so a restart while MCP Gate is down keeps it; with no list at all every tool stays hidden.
- The same middleware applies the server's tool access rules to each token: a tool denied to the caller (or
  outside its "only these tools" rule) is hidden; a tool that needs a scope the token lacks is listed, and calling
  it fails with an error naming the scope. Rules set in the console reach the server within one poll.
- MCPGateScopeGate turns that refusal into a real HTTP 403 `insufficient_scope` challenge (step-up), so a client
  that supports it asks the user for the scope and retries; the error text names the scope either way.

    pip install fastmcp httpx          # or: uv add fastmcp httpx
    cp examples/mcp_gate_hooks.py .    # MCPGateVerifier, MCPGateToolPinning and MCPGateScopeGate: one file
    MCP_GATE_URL=http://localhost:4568 python server.py

Before starting it, register the server in the MCP Gate console (Services -> Register Service: host
127.0.0.1, port 8000, path /mcp), so its audience is http://127.0.0.1:8000/mcp. For the feeds, also register
a confidential client with grant type client_credentials and "Resource server for" set to this server, and
export its id and secret. See the README's Quick start.
"""

import os

from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token
from starlette.middleware import Middleware

from mcp_gate_hooks import MCPGateScopeGate, MCPGateToolPinning, MCPGateVerifier

MCP_GATE = os.environ.get("MCP_GATE_URL", "http://localhost:4568").rstrip("/")  # MCP Gate's OAUTH_ISSUER
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))
BASE_URL = f"http://{HOST}:{PORT}"
AUDIENCE = os.environ.get("MCP_AUDIENCE", f"{BASE_URL}/mcp")  # must equal the audience shown in the console

verifier_settings = dict(
    jwks_uri=f"{MCP_GATE}/.well-known/jwks.json",
    issuer=MCP_GATE,
    audience=AUDIENCE,
    required_scopes=["mcp:tools:invoke"],
)

middleware = []
pinning = None
if os.environ.get("MCP_GATE_CLIENT_ID"):
    # Offline verification plus the revocation feed and usage reports.
    verifier = MCPGateVerifier(
        **verifier_settings,
        client_id=os.environ["MCP_GATE_CLIENT_ID"],
        client_secret=os.environ["MCP_GATE_CLIENT_SECRET"],
        poll_interval=15,   # seconds between revocation-feed polls
        flush_interval=30,  # seconds between usage reports
    )
    # Only tools approved in the console are listed and callable, and the access rules apply to each token.
    pinning = MCPGateToolPinning(
        verifier,
        cache_file=os.environ.get("MCP_GATE_POLICY_CACHE", "mcp_gate_policy.json"),  # last approvals + rules
        poll_interval=15,   # seconds between tool-policy polls
        fail_open=False,    # True: list every tool until the first list arrives (default: hide them all)
    )
    middleware.append(pinning)
else:
    # Offline verification only: a revoked token keeps working until it expires, and every tool is listed.
    verifier = JWTVerifier(**verifier_settings)

auth = RemoteAuthProvider(
    token_verifier=verifier,
    authorization_servers=[MCP_GATE],  # served at /.well-known/oauth-protected-resource for OAuth clients
    base_url=BASE_URL,
)

mcp = FastMCP(name="demo", instructions="A demo server protected by MCP Gate", auth=auth, middleware=middleware)


@mcp.tool
def hello(name: str) -> str:
    """Return a greeting."""
    return f"Hello, {name}!"


@mcp.tool
def whoami() -> dict:
    """Return who the caller's access token belongs to."""
    token = get_access_token()
    return {
        "subject": token.subject if token else None,
        "client_id": token.client_id if token else None,
        "scopes": token.scopes if token else [],
    }


if __name__ == "__main__":
    feeds = "on" if isinstance(verifier, MCPGateVerifier) else "off"
    print(f"MCP Gate: {MCP_GATE}   audience: {AUDIENCE}   revocation feed: {feeds}   "
          f"tool approvals, access rules and step-up: {feeds}")
    # Serves MCP 2026-07-28 (stateless) and older clients on the same endpoint. Add stateless_http=True to keep no
    # sessions for older clients either (e.g. behind a load balancer); MCPGateVerifier and the middleware work both ways.
    # The step-up gate sits in front of FastMCP's HTTP handler (an ASGI middleware), next to the pinning middleware.
    http_middleware = [Middleware(
        MCPGateScopeGate,
        pinning=pinning,
        server=mcp,
        challenge_includes_token_scopes=False,  # True: also name the token's scopes, for clients that do not union
    )] if pinning else []
    mcp.run(transport="http", host=HOST, port=PORT, middleware=http_middleware)
