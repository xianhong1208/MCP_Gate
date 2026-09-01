# Changelog

All notable changes to MCP Center are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-09-01

First public release. MCP Center is an OAuth 2.1 authorization server and management console for Model Context Protocol servers.

### Authorization server
- RS256 signing keys with JWKS publishing and rotation; private keys encrypted at rest.
- Authorization server metadata (RFC 8414), dynamic client registration (RFC 7591), authorization code + PKCE (S256), refresh-token rotation with replay detection, revocation (RFC 7009), introspection (RFC 7662), resource indicators (RFC 8707), `iss` in authorization responses (RFC 9207).
- Consent screen with remembered decisions per client and server; trusted (manually registered) clients skip it.
- Personal access tokens minted from the console.
- Introspection is scoped: public clients may only introspect their own tokens; confidential clients (resource servers) may introspect any token.

### Console
- Email/password sign-in with a first-run setup wizard; pluggable GitHub and Google sign-in (experimental).
- Dashboard, MCP server registry with health monitoring and tool sync, token management, OAuth client management, scope registry, key rotation, audit log.
- Marketplace and bring-your-own MCP server deployment through Docker.
- Design system "Navy Trust" (dark-first, Fira Sans / Fira Code), app-shell layout with global search.

### Platform
- SQLite by default, PostgreSQL optional; UUID primary keys through SQLAlchemy's portable `Uuid` type.
- Secrets generated on first start and stored in `data/secrets.json`.
- Alembic migrations (`8813dec38e2b` initial schema, `1ee09c99d84d` keeps token history when a client is deleted).
- Verified against FastMCP 3.4 with an end-to-end interop test suite.

### Scope
- Tokens are standard RS256 JWTs that resource servers verify offline against the published JWKS; there is no opaque token format and no verification callback.
- The console is single-tenant: everyone who can sign in is an administrator, with no roles or per-service user membership (see `SECURITY.md`).
