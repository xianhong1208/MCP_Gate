"""A FastMCP server protected by MCP Gate.

    uv run python examples/fastmcp_server.py

Prerequisites: MCP Gate is running at http://localhost:4568 and this server is
registered in the console (Services -> Register Service) with host 127.0.0.1,
port 8000 and path /mcp, so its audience is http://127.0.0.1:8000/mcp.

Then connect any OAuth-capable MCP client to http://127.0.0.1:8000/mcp, e.g.
    claude mcp add --transport http demo http://127.0.0.1:8000/mcp
or use a personal access token issued from the console:
    claude mcp add --transport http demo http://127.0.0.1:8000/mcp --header "Authorization: Bearer <PAT>"
"""

import os

from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token

MCP_GATE = os.environ.get("MCP_GATE_URL", "http://localhost:4568").rstrip("/")
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))
BASE_URL = f"http://{HOST}:{PORT}"
AUDIENCE = os.environ.get("MCP_AUDIENCE", f"{BASE_URL}/mcp")

auth = RemoteAuthProvider(
    token_verifier=JWTVerifier(
        jwks_uri=f"{MCP_GATE}/.well-known/jwks.json",
        issuer=MCP_GATE,
        audience=AUDIENCE,
        # required_scopes=["mcp:tools:invoke"],  # uncomment to require a scope
    ),
    authorization_servers=[MCP_GATE],
    base_url=BASE_URL,
)

mcp = FastMCP(name="demo", instructions="MCP Gate demo server", auth=auth)


@mcp.tool
def hello(name: str) -> str:
    """Return a greeting."""
    return f"Hello, {name}!"


@mcp.tool
def whoami() -> dict:
    """Return the subject, client_id and scopes of the current access token."""
    token = get_access_token()
    return {
        "subject": token.subject,
        "client_id": token.client_id,
        "scopes": token.scopes,
        "email": (token.claims or {}).get("email"),
    }


if __name__ == "__main__":
    print(f"MCP Gate : {MCP_GATE}")
    print(f"MCP URL    : {BASE_URL}/mcp   (audience={AUDIENCE})")
    mcp.run(transport="http", host=HOST, port=PORT)
