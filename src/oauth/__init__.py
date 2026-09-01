"""MCP Center acting as an OAuth 2.1 Authorization Server.

- signing_keys   RS256 keys (private key stored AES-encrypted in the DB) + JWKS
- jwt_utils      RS256 sign / verify
- service        clients, authorization code + PKCE, token issuance / rotation / revocation / introspection,
                 resource -> aud binding
- consent_policy when the consent page may be skipped
- errors         RFC 6749 errors

An MCP server (FastMCP) only needs:
    JWTVerifier(jwks_uri="<issuer>/.well-known/jwks.json", issuer="<issuer>", audience="<service audience>")
"""
from src.oauth.errors import OAuthError

__all__ = ["OAuthError"]
