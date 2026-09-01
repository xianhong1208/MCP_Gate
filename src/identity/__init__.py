"""Admin-console identity (who may log in to the MCP Center admin console).

This is separate from `src/oauth` (MCP Center acting as an OAuth 2.1 Authorization Server that issues tokens to MCP
clients): this package answers "who is the person", that one answers "what may a client do against which MCP server".

- passwords    bcrypt
- session      HS256 JWT inside an httpOnly cookie, FastAPI dependency (get_current_user)
- providers    pluggable third-party login (GitHub / Google)
- service      login / first-time setup / password change / third-party account mapping
"""
from src.identity.session import (
    AuthenticationRequired,
    get_current_user,
    get_optional_current_user,
    session_manager,
)

__all__ = [
    "AuthenticationRequired",
    "get_current_user",
    "get_optional_current_user",
    "session_manager",
]
