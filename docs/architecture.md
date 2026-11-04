# Architecture

## Roles

```
MCP client ──OAuth 2.1──▶ MCP Gate (authorization server) ──JWKS──▶ MCP server (resource server)
```

- **MCP Gate** issues tokens, publishes its public keys and hosts the console. It is never on the request path between a client and an MCP server.
- **MCP servers** verify tokens locally with the public key. They hold no user or client state.
- **The console** is a single-tenant admin UI: whoever signs in owns the instance.

## Layers

```
src/api/*          HTTP routers (FastAPI). Validate input, call adapters, shape responses.
src/oauth/*        Authorization-server logic (grants, keys, consent) — HTTP-agnostic.
src/identity/*     Console sign-in (passwords, sessions, external providers) — HTTP-agnostic.
src/adapters/*     Business rules on top of the data layer. The only layer that imports db.crud.
db/crud.py         Data access. Commits its own transactions.
db/models.py       SQLAlchemy models (SQLite and PostgreSQL through the generic Uuid type).
```

The rule `routes → adapters → db.crud` is enforced by `tests/test_architecture_layering.py`.

## Request flows

### Authorization code + PKCE

1. `GET /oauth/authorize` → `service.begin_authorization` validates client, redirect URI, PKCE, scope and resource, then stores an `OAuthAuthorizationRequest` (10-minute TTL).
2. If the owner is signed in and `consent_policy.should_skip_consent` returns true, a code is issued at once; otherwise the browser is sent to `/consent?rid=…`.
3. The console calls `GET /oauth/authorize/requests/{id}` to render the screen and `POST …/decision` to approve or deny. Approval writes an `OAuthAuthorizationCode` (hash only, 120-second TTL) and optionally an `OAuthConsent`.
4. `POST /oauth/token` (`authorization_code`) verifies PKCE, redirect URI and resource, marks the code used, then issues an access token and a refresh token that share a `parent_jti` (the code hash) — their *family*.

### Clients identified by a metadata document

When `client_id` is an https URL (and `oauth.cimd.enabled`), `/oauth/authorize` and the token, revocation and introspection endpoints resolve it through `src/oauth/client_metadata.py`: the URL is checked, the JSON document at it fetched (public addresses only, connection pinned to the checked address, no redirects, 5 KB / 5 s) and validated (`client_id` equals the URL, `client_name` and `redirect_uris` present, `none` or `private_key_jwt`), and an `OAuthClient` row keyed by the URL (`created_via = cimd`) is created or refreshed, so the rest of the flow is the one above. A per-process table remembers until when the stored copy is fresh (`Cache-Control: max-age`, bounded) and which URLs failed recently. An authorization request aborts on any fetch failure; the token endpoint keeps using the stored row when the failure is transient (503 when there is none). A document whose `client_id` stops matching its URL revokes the client's tokens; a change of redirect URIs, grant types, authentication method or keys forgets remembered consents.

### Refresh

`POST /oauth/token` (`refresh_token`) verifies the JWT, checks the `OAuthToken` record, revokes the presented token with reason `rotated`, and issues a new pair in the same family. Presenting an already-rotated token revokes the entire family (`refresh_replay`).

### Client credentials

Confidential clients exchange `client_id` + secret for an access token whose `sub` is the client itself. No refresh token is issued.

### Personal access tokens

`POST /api/oauth/tokens/personal` mints a long-lived access token (`kind = pat`) bound to one service, recorded like any other token so it can be listed and revoked.

## Tokens

| Property | Value |
|---|---|
| Format | JWT, RS256, `typ: at+jwt` (`refresh+jwt` for refresh tokens) |
| Claims | `iss`, `sub`, `aud`, `scope`, `client_id`, `jti`, `iat`, `exp`, `token_use`; `email`, `name` when a user is present |
| Refresh tokens | `token_use: refresh`, `aud` = `<issuer>/oauth/token` (never a resource), so a resource server checking `aud` refuses them as Bearer tokens; the granted resource is kept in the token record |
| Access lifetime | `OAUTH_ACCESS_EXPIRE_MINUTES` (15); personal access tokens choose their own, up to `pat_max_days` (365) |
| Refresh lifetime | `OAUTH_REFRESH_EXPIRE_DAYS` (30) |
| Verification | Signature against JWKS, `iss`, `exp`; `aud` and scopes by the resource server |
| Revocation | `OAuthToken.revoked_at`; visible through `/oauth/introspect`; offline verifiers see it only after expiry |

## Keys and secrets

- Signing keys are RSA-2048 by default. The private PEM is encrypted with AES-256-GCM (`ENCRYPTION_KEY`) before it is stored; `kid` is the RFC 7638 thumbprint. Rotation creates a new active key; the old one stays in JWKS for the access-token lifetime plus 5 minutes (`oauth.retired_key_publish_minutes`), and beyond that only while a live access token or PAT it signed is still recorded. Once dropped from JWKS, tokens it signed are inactive on introspection too; MCP Gate keeps the key to verify refresh tokens it signed.
- `ENCRYPTION_KEY` and `SESSION_SECRET_KEY` come from the environment or from `data/secrets.json` (created on first start, mode `0600`).
- Console sessions are HS256 JWTs in an HttpOnly cookie, signed with `SESSION_SECRET_KEY`, each backed by a row in `admin_sessions` (deleted on logout and, for all of the user's sessions, on a password change). A request must also send the session's binding secret in `X-Session-Binding`; the console keeps it in `localStorage`, because the cookie itself reaches every port of the host.

## Background jobs

`src/scheduler/cleanup_scheduler.py` (APScheduler) runs:

| Job | Schedule |
|---|---|
| Health check of every active service (self-minted token when the service requires auth) | every 30 s |
| Delete expired authorization requests, codes and tokens | every 6 h |
| Delete token events older than 30 days | daily 03:00 |
| Delete audit logs older than 90 days | daily 04:00 |

Health changes are broadcast to the console over `WS /ws/services`.

## Managed servers

`src/orchestrator` runs MCP servers behind a `Runtime` (`docker_runtime.py`: sibling containers, the default; `process_runtime.py`: local subprocesses for hosts without Docker, `MCP_RUNTIME=process`). Under the Docker runtime: catalog entries (`catalog/*.yaml`) are HTTP images started directly; bring-your-own definitions run inside `mcp-runtime:1`, where `supergateway` bridges the server's stdio to HTTP. Every launch argument passes `src/marketplace/argv_policy.py`. Successful launches register a `Service` row automatically so tokens, health checks and tool sync work the same as for external servers.
