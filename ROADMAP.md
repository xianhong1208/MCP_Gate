# Roadmap

## Done (1.0.0)
- Complete OAuth 2.1 flow: discovery, dynamic client registration, PKCE, refresh rotation, revocation, introspection, consent.
- Personal access tokens, FastMCP integration snippets and an end-to-end interop test suite.
- Email/password sign-in with GitHub / Google provider hooks.
- SQLite by default, single initial migration, secrets generated on first start.

## Done (1.1.0)
- **`private_key_jwt` client authentication (RFC 7523)** for machine-to-machine clients: a registered JWKS or `jwks_uri`, RS256 / ES256 assertions with `jti` replay protection.
- **Orchestrator, steps 1–2:** the `Runtime` interface and a Docker-free process runtime (`MCP_RUNTIME=process`).

## Planned
- **Verify GitHub / Google sign-in against live accounts.** The providers are implemented and unit-tested but have not been exercised with real OAuth apps.
- **Orchestrator:** multiple hosts (a host registry and a remote agent speaking the `Runtime` interface).
