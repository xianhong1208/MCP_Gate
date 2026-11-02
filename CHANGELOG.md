# Changelog

All notable changes to MCP Gate (formerly MCP Center) are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **Renamed MCP Center to MCP Gate.** The console, docs, package (`mcp-gate`), repository (`MCP_Gate`) and code identifiers follow the new name: `examples/mcp_center_hooks.py` is now `examples/mcp_gate_hooks.py` with `MCPGateVerifier`, and the exception base classes are `MCPGateError` / `MCPGateHTTPException`. The environment variables are now `MCP_GATE_CONFIG` and `MCP_GATE_SECRETS_FILE`; the old `MCP_CENTER_*` names are still read as a fallback.
- Identifiers that live in existing data keep their old spelling so nothing has to migrate: the built-in client ids `mcp-center-console` / `mcp-center-scanner` (stored in the database and carried in issued tokens) and the default database `data/mcp_center.db`. Tokens already issued stay valid — the issuer is the URL, not the name.

### Security
- **Dependencies with known advisories upgraded** (`pip-audit` / `npm audit --omit=dev` now clean): pyjwt 2.15, cryptography 50, starlette 1.10 / fastapi 0.162, aiohttp 3.14, urllib3 2.8, anyio, multidict, idna, certifi, python-dotenv, mako, pygments, dnspython; dev-only fastmcp 3.4.10 / mcp 1.30 / authlib / joserfc. The console moves to react-router 7, which fixes open-redirect advisories in v6. Minimum versions of pyjwt, cryptography and aiohttp are raised in `pyproject.toml`. (#32)

## [1.1.0] — 2026-09-18

### Added
- **Remembered consents page.** `/consents` lists the decisions you chose to remember on the consent screen and lets each one be forgotten; the delete endpoint is scoped to the signed-in owner and audited. (#3, #4)
- **Issuer mismatch detection.** Requests reaching `/.well-known/*` or `/oauth/*` through a scheme, host or port other than `OAUTH_ISSUER` are logged once per host, exposed on `GET /api/oauth/overview` as `issuer_mismatches`, and shown as a dashboard banner. Forwarded headers are honoured only from `security.trusted_proxies`. (#7, #8, #13, #19)
- **`private_key_jwt` client authentication (RFC 7523).** Clients may register a JWKS document or a `jwks_uri` instead of a secret and authenticate to the token, revocation and introspection endpoints with a signed assertion (RS256 / ES256, `jti` replay protection, key rotation via refetch). Console client form gains the option. Migration `9f3a6c2d7e18`. (#14, #20)
- **Revocation feed and usage reports for offline-verified MCP servers.** `POST /oauth/revoked` lists tokens revoked but not yet expired; `POST /oauth/usage` accepts batched verification counts. `examples/mcp_center_hooks.py` ships `MCPCenterVerifier`, a FastMCP `JWTVerifier` that polls the feed and reports usage, so revocation takes effect within the poll interval without per-request introspection. `token_usage.count` migration `b2c4d6e8f0a1`; new integration snippet variant. (#15, #21)
- **Per-server scopes.** A server can declare scopes of its own next to the global registry (`service_scopes`, migration `c3d5e7f9a1b2`); tokens for other servers can never carry them, and global and per-server names stay disjoint. New service detail card and API under `/api/oauth/services/{id}/scopes`; scope CRUD is now audited. (#16, #22)
- **Orchestrator runtime abstraction and a Docker-free process runtime.** Managed servers run behind a `Runtime` interface; `MCP_RUNTIME=process` runs bring-your-own servers as local subprocesses bridged by supergateway (pid and log files under `MCP_PROCESS_LOG_DIR`), `auto` falls back to it when Docker is absent. `GET /api/managed/runtime` reports the active runtime. (#18, #23)
- **Inspect tools as an issued token.** "Refresh from Server" can present one of the server's personal access tokens or OAuth access tokens (a short-lived copy of its claims) so servers that show different tools per caller can be inspected. (#24, #25, #26)
- Frontend ESLint flat config and `npm run lint`. (#9, #10)

### Changed
- Personal access tokens require a label. (#26)
- Token list pages at 10 by default (adjustable in Settings), with fixed-width columns and day-only dates so it never scrolls horizontally. (#26)
- MCP Tools card redesigned: one-line tool rows, markdown-rendered descriptions and a field list for input schemas on expand. Dashboard and OAuth Clients cards size to their content. (#26)
- Discovery metadata advertises `private_key_jwt`, the assertion signing algorithms and the MCP Center extension endpoints.
- `is_confidential` on clients now means "authenticates to the token endpoint" rather than "has a secret".

### Fixed
- `jwks_uri` is parsed and DNS-resolved before use (public https only, rechecked before every fetch) instead of prefix-matched, closing an SSRF path. (#21)
- Port allocation for managed servers compared the UUID id column with a string and failed on every re-allocation. (#23)
- Introspection treated key-authenticated clients as public clients. (#21)

### Security
- See "Fixed" for the `jwks_uri` hardening; `SECURITY.md` now describes the offline-revocation window as the poll interval.

## [1.0.1] — 2026-09-15

### Fixed
- Service detail page: token scopes now render on their own line under each token in the sidebar card and are visible at every breakpoint; previously they were hidden below the 2xl breakpoint. (#1, #2)

## [1.0.0] — 2026-09-01

First public release. MCP Center is an OAuth 2.1 authorization server and management console for Model Context Protocol servers.

### Authorization server
- RS256 signing keys with JWKS publishing and rotation; private keys encrypted at rest.
- Authorization server metadata (RFC 8414), dynamic client registration (RFC 7591), authorization code + PKCE (S256), refresh-token rotation with replay detection, revocation (RFC 7009), introspection (RFC 7662), resource indicators (RFC 8707), `iss` in authorization responses (RFC 9207).
- Consent screen with remembered decisions per client and server; trusted (manually registered) clients skip it.
- Personal access tokens minted from the console.
- Introspection is scoped: public clients may only introspect their own tokens; confidential clients (resource servers) may introspect any token.
- Classic-client compatibility for manually registered confidential clients: PKCE may be waived and a default resource assumed, so platforms with a plain client_id / client_secret OAuth module can sign in (migration `4b2c9d7e1f03`).

### Console
- Email/password sign-in with a first-run setup wizard; pluggable GitHub and Google sign-in (experimental).
- Dashboard, MCP server registry with health monitoring and tool sync, token management, OAuth client management, scope registry, key rotation, audit log.
- Marketplace and bring-your-own MCP server deployment through Docker.
- Network scan recognises OAuth-protected servers by their `WWW-Authenticate: Bearer` challenge and, for servers that trust this MCP Center, mints a scanner token to read their name and tools; no HTTPS retry against ports that already answered HTTP.
- Design system "Navy Trust" (dark-first, Fira Sans / Fira Code), app-shell layout with global search.

### Platform
- SQLite by default, PostgreSQL optional; UUID primary keys through SQLAlchemy's portable `Uuid` type.
- Secrets generated on first start and stored in `data/secrets.json`.
- Alembic migrations (`8813dec38e2b` initial schema, `1ee09c99d84d` keeps token history when a client is deleted).
- Verified against FastMCP 3.4 with an end-to-end interop test suite.

### Scope
- Tokens are standard RS256 JWTs that resource servers verify offline against the published JWKS; there is no opaque token format and no verification callback.
- The console is single-tenant: everyone who can sign in is an administrator, with no roles or per-service user membership (see `SECURITY.md`).
