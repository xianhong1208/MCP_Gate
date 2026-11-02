# Changelog

All notable changes to MCP Gate (formerly MCP Center) are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Continuous integration.** `.github/workflows/ci.yml` runs on pushes and pull requests to `dev` and `main`: the backend suite and ruff on SQLite, the same suite on PostgreSQL 16, the frontend lint / tests / build with a check that the committed `static/web` matches the build, and a build and smoke test of the `mcp-runtime` image as its runtime user.
- **The test suite runs on PostgreSQL.** Set `TEST_DATABASE_URL` to a throwaway database: the schema is rebuilt once per session and the tables are truncated before each test. SQLite stays the default.
- **Schema drift test.** `tests/test_schema_drift.py` migrates an empty database to head (and back down and up again) and compares it with the models using Alembic's autogenerate comparison.

### Changed
- **Renamed MCP Center to MCP Gate.** The console, docs, package (`mcp-gate`), repository (`MCP_Gate`) and code identifiers follow the new name: `examples/mcp_center_hooks.py` is now `examples/mcp_gate_hooks.py` with `MCPGateVerifier`, and the exception base classes are `MCPGateError` / `MCPGateHTTPException`. The environment variables are now `MCP_GATE_CONFIG` and `MCP_GATE_SECRETS_FILE`; the old `MCP_CENTER_*` names are still read as a fallback.
- Identifiers that live in existing data keep their old spelling so nothing has to migrate: the built-in client ids `mcp-center-console` / `mcp-center-scanner` (stored in the database and carried in issued tokens) and the default database `data/mcp_center.db`. Tokens already issued stay valid — the issuer is the URL, not the name.

### Fixed
- **Works with fastmcp 4 / mcp 2 clients.** The integration snippet, README and examples pass the issuer to `RemoteAuthProvider(authorization_servers=...)` as a plain string; `AnyHttpUrl` added a trailing slash that mcp 2 clients reject as an issuer mismatch. The dev/interop dependency moves to fastmcp 4, and troubleshooting covers the error. (#37)
- **"Refresh from Server" no longer wipes the stored tools when the server cannot be read.** A non-200, transport error or malformed `tools/list` reply now answers 502 and keeps the existing tools; only a valid empty `tools` result clears them. A scan that verifies a server but cannot list its tools still registers it, without tools. (#34)
- **Discovery scans are bounded.** Ports must be 1–65535 and a port range must satisfy `1 <= start <= end <= 65535` (a start of 0 or a reversed range used to be silently ignored); at least one host and one port are required, and one request may probe at most 65,536 host × port combinations. Rejections are 422s with `discovery.*` error codes the console shows in both languages. (#34)
- **Health checks keep the description you wrote.** The scheduled and manual health checks used to overwrite every service description with the server's `serverInfo`; they now fill it only while it is empty or still generated (the scan placeholder or the old health-check text). (#34)
- **A reachable server without auth and without tools is no longer reported as "requires auth".** The scan now decides from the verification result rather than from whether any tools came back. (#34)
- Stdlib logging (uvicorn, APScheduler, SQLAlchemy and modules using `logging.getLogger`) is routed into loguru and reaches the log files; uvicorn's access log is off because the request-logging middleware already records every request. (#35)
- bcrypt hashing and verification for setup, login and password change run in a worker thread instead of blocking the event loop. (#35)
- Scheduled purges of expired OAuth data, token events and old audit logs write a system audit entry when they delete anything. (#35)
- Downgrading migrations `4b2c9d7e1f03` and `1ee09c99d84d` no longer fails on data the newer schema allows: authorization requests/codes without PKCE and tokens of deleted clients are removed first. `oauth_clients.require_pkce` declares the same server default in the model as in the migration. (#35)
- The single-process requirement (in-memory rate limiter, in-process scheduler) is documented in `SECURITY.md` and `docs/deploy.md`, and startup warns when `WEB_CONCURRENCY` or `UVICORN_WORKERS` is greater than 1. (#35)
- **Over-long input is refused with a readable error instead of a 500 on PostgreSQL.** SQLite ignores `VARCHAR(n)`, PostgreSQL rejects the row. Service name, host, tags, audience and allowed scopes; the owner's email and display name; scope names and descriptions; bring-your-own and managed instance names; and the scan's host and service name now answer `validation.too_long` naming the field and its limit (shown in both console languages). Dynamic client registration refuses over-long `client_uri`, `logo_uri`, `software_id`, `scope`, `default_resource`, `jwks_uri` and redirect URIs with `invalid_client_metadata` / `invalid_redirect_uri`, and `/oauth/authorize` refuses an over-long `state` or `code_challenge` with `invalid_request`.
- **Text MCP Gate relays is shortened rather than failing the request.** Health-check error messages from the remote server are cut to 512 characters; audit entries clip the failed-login email, User-Agent and other bounded fields; a long GitHub / Google display name is shortened; and a scanned server's name is cut to fit.
- **One bad tool no longer fails "Refresh from Server" or a scan.** Tools with a missing, blank or over-long (more than 128 characters) name are skipped and repeated names keep their first entry, instead of a 500 on PostgreSQL that left a scanned service half-registered.
- **Static bearer tokens of any realistic length.** `services.auth_token_encrypted` is now `TEXT` (migration `d4e6f8a0b2c3`): once encrypted, the old `VARCHAR(1024)` held only about 740 bytes, less than a typical JWT. Tokens over 8,192 characters are refused.
- **The revocation feed and usage reports use real unix time on hosts outside UTC.** `revoked_at`, `exp`, `now`, `since` and `last_seen` treated stored local times as UTC, shifting them by the host's UTC offset.
- **Migrations work with a percent-encoded `DATABASE_URL`.** A password containing e.g. `%40` made Alembic's config parser fail, so startup migrations could not run.
- **`mcp-runtime` image: `uvx` works as the runtime user and `python` exists.** uv was installed under `/root/.local/bin`, which the unprivileged `mcp` user cannot reach, so every `uvx` bring-your-own server failed to start; `python` (on the bring-your-own allow-list) was missing. uv now comes from the official image into `/usr/local/bin`, `python-is-python3` is installed, and uv and supergateway versions are pinned.

### Security
- **Cross-site request forgery against the console is refused.** `SameSite=Lax` does not separate pages on other ports of the same host (or sibling subdomains), and body-less POSTs need no CORS preflight, so a page on any other `localhost` port could rotate the signing keys, revoke tokens, start managed servers or approve a consent with the owner's cookie. Every `POST` / `PUT` / `PATCH` / `DELETE` outside `/oauth/*` and `/.well-known/*`, and the consent decision, now needs an `Origin` (or else `Referer`) that is the console's own origin, `OAUTH_ISSUER` or an entry in `cors.allowed_origins`; anything else gets 403 `auth.csrf_origin_denied`. Requests without either header (not from a web page) and Bearer-only requests without the cookie are unaffected.
- **Dependencies with known advisories upgraded** (`pip-audit` / `npm audit --omit=dev` now clean): pyjwt 2.15, cryptography 50, starlette 1.10 / fastapi 0.162, aiohttp 3.14, urllib3 2.8, anyio, multidict, idna, certifi, python-dotenv, mako, pygments, dnspython; dev-only fastmcp 3.4.10 / mcp 1.30 / authlib / joserfc. The console moves to react-router 7, which fixes open-redirect advisories in v6. Minimum versions of pyjwt, cryptography and aiohttp are raised in `pyproject.toml`. (#32)
- **Outbound fetches can no longer be steered at internal addresses.** The discovery scanner, health checks and tools refresh never follow HTTP redirects, and a host that does not resolve is refused instead of being handed to the HTTP client by name; the cloud metadata addresses `fd00:ec2::254` and `100.100.100.200` are blocked too (loopback and private ranges stay scannable). The `jwks_uri` fetch connects to the exact address that passed the check (Host header, TLS SNI and certificate verification keep the hostname), accepts only globally routable addresses, ignores proxy environment variables, and refetches for an unknown `kid` at most once a minute per `jwks_uri`. Client authentication on the token, revocation, introspection and feed endpoints runs off the event loop. (#33)
- **Client IPs can no longer be forged.** One resolver now feeds the audit log, request logging, OAuth token events, the rate limiter and the issuer check: `X-Forwarded-For` / `X-Real-IP` count only when the direct peer is in `security.trusted_proxies`, and `X-Forwarded-For` is read right to left, skipping trusted proxies (previously the audit log and request log trusted the headers from anyone, the rate limiter took the client-controlled leftmost entry, and OAuth token events ignored proxies altogether). (#35)
- Security headers are now added by the outermost middleware, so rate-limit 429s, CORS preflight responses and unhandled 500s carry them too. (#35)
- **Managed servers keep their port across restarts.** A process reuses the port it already has whenever nothing else holds it (its own leftover container is removed first) instead of taking the lowest free port and silently moving its Service; when the port truly cannot be reused it is moved with a warning in the log and in `last_error`, and a manually chosen port that is in use fails the start. Ports are reserved in the database at allocation time so concurrent starts cannot collide. (#36)
- **Readiness means an MCP answer, not an open port.** After the port opens, start polls an MCP `initialize` on `/mcp` until the existing start timeout (still 300 s for stdio cold starts) and fails the start if it never gets a JSON-RPC response — Docker's port proxy accepts connections before the server is up. (#36)
- **Stop failures are no longer swallowed.** The Docker and process runtimes treat only "already gone" as success; any other failure leaves the process in `stop_failed` with `last_error` set, `POST /api/managed/{id}/stop` reports it, and uninstall aborts without deleting the record while the instance may still be running. (#36)
- **Failed deployments keep their logs.** The last 50 log lines are copied into `last_error` before the failed container or process is removed, and any failure after a successful launch (e.g. registering the Service) now tears the instance down instead of leaking it. (#36)
- **One slow start no longer blocks every managed server.** Locking is per process (plus a short global lock for shared state and port allocation). Updating env vars stops, writes and restarts as one locked operation, marks a failed restart `failed` and audits it, and now works for bring-your-own servers too. (#36)
- **Docker unavailable returns 503 `managed.runtime_unavailable`** instead of a generic 500 from start, stop, env-var updates and uninstall. (#36)
- **Catalog entries must declare `transport: http`.** Any other value is rejected when the catalog is loaded (the file is skipped with the reason logged) rather than failing at start time. (#36)
- **Dynamically registered clients can no longer use `client_credentials`.** Anonymous registration used to accept the grant, which gave anyone who could reach MCP Gate a consent-free token for every registered server. `POST /oauth/register` now rejects it (whatever `OAUTH_DCR_AUTO_APPROVE` says) and the token endpoint refuses it for any client not registered in the console, including DCR clients stored by earlier releases. A DCR client also may not point a `private_key_jwt` `jwks_uri` at loopback, even on a plain-http development issuer.
- **Resource servers must be bound to a server.** Any confidential client — including one anyone could register anonymously — used to be trusted as a resource server: it could read the whole revocation feed, introspect any token (including the owner's email) and forge usage counts. Now only a console-registered confidential client bound to one MCP server (`resource_service_id` on `POST /api/oauth/clients`, or `PUT /api/oauth/clients/{id}/resource-server`; stored as `oauth_clients.resource_audience`, migration `e5f7a9b1c3d4`) may do so, and only for access tokens whose audience is that server; refresh tokens are never shown to it. **Breaking:** an `MCPGateVerifier` / `IntrospectionTokenVerifier` client created before this release must be bound before its feed, introspection and usage calls work again. Usage reports reject counts outside 1–1,000,000 and `last_seen` more than five minutes in the future with `invalid_request` (a huge or infinite count used to answer 500).
- **Refresh tokens can no longer be used as Bearer access tokens.** They carried the same `iss`/`aud`/`scope` as access tokens, so a server verifying offline accepted them for their full 30 days. Refresh tokens now name MCP Gate's token endpoint (`<issuer>/oauth/token`) as their audience, so the generated `JWTVerifier` snippet refuses them, and `MCPGateVerifier` additionally rejects anything whose `token_use` is not `access`. Revoked refresh tokens (other than routine rotation) are listed in `/oauth/revoked`. Refresh tokens issued by earlier releases still carry the server's audience until they are next rotated or expire; rotating the signing key after upgrading retires them (see key retirement below). Clients treat refresh tokens as opaque, so nothing changes for them; rotation and reuse detection are unchanged.
- **Deleting an OAuth client revokes its tokens** (reason `client_deleted`, listed in the revocation feed) before keeping them as history; previously its access and refresh tokens stayed valid until expiry.
- **A disabled server gets no new tokens from any grant.** The refresh grant and the authorization-code exchange now re-check that the token's server is still active (and that the user who consented is still active) and answer `invalid_grant` otherwise; a refused refresh does not rotate the token, so re-enabling the server makes it usable again. Personal access tokens can no longer be issued for a disabled server.
- **Dynamic registration is bounded and type-checked.** `/oauth/register` bodies are capped at 64 KiB (413), `redirect_uris` at 20 entries (validated whenever present, not only with `authorization_code`), `response_types` at 5 short strings; a non-string `client_name`, `grant_types` entry or auth method is an `invalid_client_metadata` 400 instead of a 500. The token, revocation, introspection and feed endpoints cap form bodies at 64 KiB (usage reports at 512 KiB), and over-long `scope` / `resource` parameters on `/oauth/authorize` and `/oauth/token` are refused. Building on the column-length checks above, a 20 MB `client_uri` no longer lands in the database.
- **`client_uri`, `logo_uri`, `tos_uri` and `policy_uri` must be web URLs** — `https`, or `http` to `localhost` / loopback. `javascript:`, `data:`, `file:` and plain-http remote URLs are refused at registration (DCR and console), so the consent screen can no longer be handed a script URL or a tracking pixel on another host.
- **Dynamically registered clients that never obtained a token are purged** 30 days after registration by the OAuth cleanup job (`oauth.dcr_unused_client_days`, `0` disables it). Clients that completed a flow, console clients and built-in clients are never touched.
- `GET /api/oauth/activity` (`at`) and the consent-request details (`expires_at`) now carry their UTC offset like every other console timestamp; they were naive local times that a browser in another time zone misread.
- **Rotated signing keys are retired from the JWKS.** Every key ever created used to stay published forever, so a leaked old private key could mint tokens resource servers accept indefinitely. A rotated-out key now stays in `/.well-known/jwks.json` for the access-token lifetime plus 5 minutes (`oauth.retired_key_publish_minutes`), and longer only while a live access token or PAT it signed is still recorded; introspection treats tokens signed by an unpublished key as inactive. MCP Gate keeps the key to verify the refresh tokens it signed, so clients refresh without noticing. `GET /api/oauth/keys` reports `published` per key.
- **A failed code redemption burns the authorization code** (OAuth 2.1): a wrong PKCE verifier, client, redirect URI or resource used to leave the code redeemable for the rest of its 120 s.
- **Loopback IP redirect URIs match on any port** (RFC 8252 §7.3), so a native client registered with `http://127.0.0.1:<port>/cb` or `http://[::1]:<port>/cb` can listen on a fresh port each run; scheme, path and query must still match. `localhost` redirect URIs keep exact matching (RFC 8252 §8.3 calls them NOT RECOMMENDED and §7.3 relaxes the port for IP literals only).

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
