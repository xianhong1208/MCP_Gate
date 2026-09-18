"""examples/fastmcp_server.py with MCP Center hooks: revocations take effect within seconds and usage shows up
in the console, without introspecting every request.

    MCP_CENTER_CLIENT_ID=mcpc_... MCP_CENTER_CLIENT_SECRET=... uv run python examples/fastmcp_server_hooks.py

Register a confidential client in the console first (OAuth Clients -> Register trusted client, any client
secret method) and put its credentials in the environment. See mcp_center_hooks.py for the details.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))  # so `mcp_center_hooks` resolves when run from the repo root

from fastmcp import FastMCP  # noqa: E402
from fastmcp.server.auth import RemoteAuthProvider  # noqa: E402
from mcp_center_hooks import MCPCenterVerifier  # noqa: E402
from pydantic import AnyHttpUrl  # noqa: E402

MCP_CENTER = os.environ.get("MCP_CENTER_URL", "http://localhost:4568").rstrip("/")
HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8000"))
BASE_URL = f"http://{HOST}:{PORT}"
AUDIENCE = os.environ.get("MCP_AUDIENCE", f"{BASE_URL}/mcp")

auth = RemoteAuthProvider(
    token_verifier=MCPCenterVerifier(
        jwks_uri=f"{MCP_CENTER}/.well-known/jwks.json",
        issuer=MCP_CENTER,
        audience=AUDIENCE,
        client_id=os.environ["MCP_CENTER_CLIENT_ID"],
        client_secret=os.environ.get("MCP_CENTER_CLIENT_SECRET"),
        private_key_pem=os.environ.get("MCP_CENTER_PRIVATE_KEY_PEM"),
        kid=os.environ.get("MCP_CENTER_KID"),
        poll_interval=float(os.environ.get("MCP_CENTER_POLL_INTERVAL", "15")),
        flush_interval=float(os.environ.get("MCP_CENTER_FLUSH_INTERVAL", "30")),
    ),
    authorization_servers=[AnyHttpUrl(MCP_CENTER)],
    base_url=BASE_URL,
)

mcp = FastMCP(name="demo", instructions="MCP Center demo server with revocation feed", auth=auth)


@mcp.tool
def hello(name: str) -> str:
    """Return a greeting."""
    return f"Hello, {name}!"


if __name__ == "__main__":
    print(f"MCP Center : {MCP_CENTER}")
    print(f"MCP URL    : {BASE_URL}/mcp   (audience={AUDIENCE})")
    mcp.run(transport="http", host=HOST, port=PORT)
