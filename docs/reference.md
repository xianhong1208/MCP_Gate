# Reference

[繁體中文](reference.zh-TW.md)

How MCP Gate works, every setting you are likely to touch, the revocation feed, the console pages and the HTTP API. To get started, see the [README](../README.md).

## How it works

MCP Gate plays the **authorization server** role from the MCP specification. Your MCP servers are **resource servers**: they never issue or store tokens.

| Step | Who | What happens |
|---|---|---|
| Discovery | client → server → MCP Gate | The server answers `401` with a `WWW-Authenticate` header pointing at its protected-resource metadata, which names MCP Gate as the authorization server. The client fetches `/.well-known/oauth-authorization-server`. |
| Registration | client → MCP Gate | The client either uses the https URL of its metadata document as `client_id` (no registration; MCP Gate fetches the document) or registers dynamically (`POST /oauth/register`) and gets a `client_id`. Public clients use PKCE; confidential clients get a secret, or register a public key and authenticate with a signed JWT (`private_key_jwt`, RFC 7523). |
| Authorization | browser → MCP Gate | `/oauth/authorize` validates the request, binds it to the target server through the `resource` parameter, and shows the consent screen (or skips it for remembered or trusted clients). |
| Token | client → MCP Gate | `/oauth/token` exchanges the code — checking PKCE, redirect URI and resource — for an RS256 access token plus a refresh token. |
| Verification | server | The server fetches JWKS once, then verifies signature, issuer, audience, expiry and scopes locally. |
| Revocation | console or client | Revoking a refresh token invalidates its whole family, and `POST /oauth/introspect` reports `active: false` immediately. Tokens verified offline stay valid until they expire — an access token for its lifetime (15 minutes by default), a personal access token for up to `pat_max_days` — unless the server polls the [revocation feed](#revocation-feed) (`POST /oauth/revoked`) or uses FastMCP's `IntrospectionTokenVerifier`. |

Access-token claims: `iss`, `sub`, `aud`, `scope`, `client_id`, `jti`, `iat`, `exp`, `token_use`, and — for tokens issued to a signed-in owner — `email` and `name`.

To change when the consent screen appears, edit [`src/oauth/consent_policy.py`](../src/oauth/consent_policy.py); the policy is one small function.

### Terms

| Term | Meaning |
|---|---|
| Issuer | MCP Gate's public URL (`OAUTH_ISSUER`). Written into every token as `iss`; clients and servers use it for discovery. |
| Classic client | A manually registered confidential client allowed to skip PKCE and use a default resource, for platforms whose OAuth module only knows client_id / client_secret. |
| private_key_jwt | Client authentication without a shared secret: the client registers a JWKS (inline or by `jwks_uri`) and signs a short-lived JWT per token request. Meant for machine-to-machine clients such as CI jobs and backend services. |
| Audience | The MCP URL a token is valid for (the `aud` claim). Set per server in the console; the server's `JWTVerifier(audience=…)` must match. |
| Resource server | Your MCP server. It verifies tokens and never issues them. The console calls these *services*. |
| Scope | What a token may do on a server, for example `mcp:tools:invoke`. The console's global scope registry defines the shared set; a server can additionally declare scopes of its own that only tokens for that server may carry. |
| DCR | Dynamic client registration (RFC 7591): a client creates its own `client_id` on first connect. Deprecated by MCP 2026-07-28 in favour of CIMD; still supported. |
| CIMD | Client ID Metadata Document: the client's `client_id` is an https URL serving its metadata as JSON. Nothing is registered in advance. |
| PAT | Personal access token: a long-lived access token minted from the console, used as a plain bearer token. |

## Configuration

Settings live in five files under [`config/`](../config/), merged at startup:

| File | Holds |
|---|---|
| [`database.yaml`](../config/database.yaml) | `database`: connection and pool |
| [`oauth.yaml`](../config/oauth.yaml) | `oauth`: issuer, token lifetimes, dynamic client registration, Client ID Metadata Documents (`oauth.cimd`) |
| [`identity.yaml`](../config/identity.yaml) | `identity`: sign-in methods (local, GitHub, Google), bootstrap admin; `session`: console session |
| [`security.yaml`](../config/security.yaml) | `rate_limit`, `security` (trusted proxies, cookies, allowed hosts), `cors` |
| [`system.yaml`](../config/system.yaml) | `server`, `logging`, `scheduler` (cleanup, retention, health checks) |

A key may be set in one file only: the same key in two files, or a missing file, stops startup with an error naming them. `MCP_GATE_CONFIG_DIR` (or `main.py --config-dir`) points at another directory holding the five files. Every secret or per-machine value is a `${VAR:-default}` reference read from the environment (`.env`), so the files hold no secrets and are committed. The variables you are likely to touch:

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH_ISSUER` | `http://localhost:4568` | Public URL of MCP Gate. Also decides the port MCP Gate binds. **Change this for any non-local deployment.** |
| `DATABASE_URL` | `sqlite:///data/mcp_gate.db` | Point at `postgresql://…` to use PostgreSQL (`uv sync --extra postgres`). |
| `SESSION_SECRET_KEY`, `ENCRYPTION_KEY` | auto-generated | Stored in `secrets/secrets.json` when unset (see `MCP_GATE_SECRETS_DIR`). `ENCRYPTION_KEY` protects private keys and stored secrets; rotating it makes them unreadable. |
| `MCP_GATE_SECRETS_DIR` | `secrets` | Directory for the generated secrets, kept apart from `data/` (mode `0700`, the file `0600`). An existing `data/secrets.json` is moved here on the first start. Back it up separately from `data/`; in Docker give it its own volume. |
| `MCP_GATE_SECRETS_FILE` | — | An exact file to use instead (nothing is moved into it). |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | — | Create the owner account at first start instead of using `/setup`. |
| `MCP_GATE_SETUP_TOKEN` | auto-generated | The one-time token `/setup` asks for. Generated into `secrets/secrets.json` and printed in the log while no owner exists; set it when the log is hard to reach (a container). |
| `OAUTH_ACCESS_EXPIRE_MINUTES`, `OAUTH_REFRESH_EXPIRE_DAYS` | `15`, `30` | OAuth token lifetimes (personal access tokens choose their own). |
| `OAUTH_DCR_AUTO_APPROVE` | `true` | Whether dynamically registered clients are usable immediately (the consent screen still gates them) or must be approved in the console. |
| `OAUTH_CIMD_ENABLED`, `OAUTH_CIMD_AUTO_APPROVE` | `true`, `true` | Accept https URLs as `client_id` ([Client ID Metadata Documents](#client-id-metadata-documents)); whether such a client is usable at once or waits for approval in the console. |
| `OAUTH_CIMD_ALLOWED_HOSTS` | — | Comma-separated hosts whose `client_id` URLs are accepted (`*.example.com` for subdomains). Empty accepts any public host. |
| `GITHUB_CLIENT_ID/_SECRET`, `GOOGLE_CLIENT_ID/_SECRET` | — | Enable GitHub / Google sign-in for the console (experimental — the providers are implemented but not yet verified against live accounts). Callback: `<issuer>/api/session/oauth/<provider>/callback`. |
| `SECURE_COOKIE` | `false` | Set to `true` behind HTTPS. |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated extra origins given credentialed access to the console API. Leave empty unless another site must call it; the Vite dev server does not need it. |
| `ALLOWED_HOSTS` | — | Comma-separated host names MCP Gate answers to besides the `OAUTH_ISSUER` host, `localhost` and IP addresses (e.g. a container service name); `*.suffix` wildcards, `*` disables the check. Other names get 421. |
| `ENABLE_API_DOCS` | — | `true` exposes OpenAPI at `/docs`. Environment-only; not in the config files. |
| `MCP_GATE_CONFIG_DIR` | `config` | The directory holding the five config files. |

### Upgrading to 1.4

1.4 no longer reads `config/config.yaml`. If it is still there, MCP Gate logs an error at startup (in the log file too) and runs on the five files; its values are ignored. `MCP_GATE_CONFIG` is no longer read either: use `MCP_GATE_CONFIG_DIR`, which names a directory.

| Section of the old `config.yaml` | Now in |
|---|---|
| `database` | `config/database.yaml` |
| `oauth` (with `oauth.cimd`) | `config/oauth.yaml` |
| `identity`, `session` | `config/identity.yaml` |
| `rate_limit`, `security`, `cors` | `config/security.yaml` |
| `server`, `logging`, `scheduler` | `config/system.yaml` |

- **You never edited `config.yaml`** (you set everything through `.env`): nothing to do. The pull brings the five files and removes `config.yaml`; `.env` keeps working as it is.
- **You edited `config.yaml`**: move your edits into the matching file. `uv run python scripts/split_config.py --old <your old config.yaml> --force` does it for you: it copies each section, with its comments, into its file, then loads both configurations and checks that they are equal field by field. Then delete the old file.
- **You set `MCP_GATE_CONFIG`**: replace it with `MCP_GATE_CONFIG_DIR=<the directory>`. `python -m db.migrate --config` is now `--config-dir`, and so is `main.py --config`.

### Client ID Metadata Documents

The MCP authorization specification (2026-07-28) deprecates dynamic registration in favour of [Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (CIMD). A client publishes a JSON document at an https URL and uses that URL as its `client_id`; MCP Gate advertises `client_id_metadata_document_supported: true` and fetches the document when the client first shows up at `/oauth/authorize`:

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

- The document's `client_id` must equal the URL exactly; `client_name` and `redirect_uris` are required. Redirect URIs match exactly, except that loopback ones match on any port (as for registered clients).
- Public clients (`none`) use PKCE. A document declaring `private_key_jwt` (in `token_endpoint_auth_methods_supported` or `token_endpoint_auth_method`) must carry `jwks` or `jwks_uri`, and then must authenticate with a signed JWT. Shared-secret methods and `client_secret` are refused. `client_credentials` is not available to these clients.
- The client appears under **OAuth Clients** with the URL as its id (*Metadata document*). Revoking it blocks that URL until you delete it; deleting it lets the URL be fetched again. Tokens, consents and the audit log work as for any other client. Unused ones are purged after `dcr_unused_client_days`, like dynamically registered clients.
- The consent screen says the client is identified only by its URL's host: its name and links are unverified.
- MCP Gate fetches only public addresses (no loopback, private, link-local or metadata-service ranges), does not follow redirects, reads at most 5 KB within 5 seconds, and requires `application/json`. Documents are cached for their `Cache-Control: max-age`, between 1 minute and 1 day; a failed fetch is not retried for 30 seconds. Every limit is under `oauth.cimd` in `config/oauth.yaml`; `OAUTH_CIMD_PRIVATE_NETWORK_HOSTS` lets named hosts on a private network through (development or intranet only).

Dynamic registration (`/oauth/register`) keeps working alongside; set `OAUTH_CIMD_ENABLED=false` to accept registered clients only.

Advanced: `SERVER_HOST` / `SERVER_PORT` override the bind address when it must differ from the issuer, for example listening on `127.0.0.1` behind a reverse proxy. See [Deploy](deploy.md) for the full reverse-proxy and HTTPS procedure.

### Revocation feed

MCP servers verify tokens offline, so on its own a server keeps accepting a revoked token until it expires — 15 minutes for an access token, as long as its lifetime for a personal access token. A server that polls the revocation feed rejects it within one poll interval instead:

1. **Register a client for the server.** Under **OAuth Clients** → *Register*: grant type `client_credentials` only, no redirect URIs, token endpoint authentication *Client secret* (POST body or HTTP Basic) or `private_key_jwt`, and *Resource server for* set to the server. For an existing client use its *Resource server…* action, or `PUT /api/oauth/clients/{client_id}/resource-server` with `{"service_id": "<server id>"}`.
2. **Poll `POST /oauth/revoked`** with that client's credentials, optionally `since=<unix time>` for only the newer revocations. The answer is `{"revoked": [{"jti", "revoked_at", "exp"}, …], "now": …}`: revoked, unexpired access tokens, personal access tokens and refresh tokens of **that server only**. Unbound clients get `403`. The same binding lets the server call `/oauth/introspect` and report token usage, again only for its own tokens.
3. **Check it in the console.** The server's page shows a *Revocation feed* row: wired (with the last poll time), stopped polling, never polled, or not wired.

For your own FastMCP server, `MCPGateVerifier` in [`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) does the polling. [Folio](https://github.com/xianhong1208/folio-rag) and [Morphyard](https://github.com/xianhong1208/morphyard) have it built in; see their READMEs.

## Use the console

| Page | What you do there |
|---|---|
| **Dashboard** | Service health, token activity, recent events, system status. |
| **Services** | Register or scan MCP servers, set audience and allowed scopes, declare server-specific scopes, refresh tools, run health checks, copy integration snippets. |
| **Tokens · Issue Token** | Every token issued by MCP Gate — OAuth grants and PATs — with revoke, expiry and last-use information. |
| **OAuth Clients** | Dynamically registered, metadata-document and trusted clients: approve, revoke, delete; scope registry; signing-key rotation. |
| **Marketplace** | Deploy MCP servers from the catalog or bring your own `{command, args, env}`. |
| **Audit Logs** | Who did what, when, and from where. |

Sign in with email and password, or with GitHub / Google once configured. The console is single-tenant by design: whoever signs in is the administrator.

The console is in English by default; the switcher in the top bar changes it to Traditional Chinese, and the choice is remembered per browser.

## API reference

| Group | Endpoints |
|---|---|
| OAuth (public) | `GET /.well-known/oauth-authorization-server` · `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json` · `POST /oauth/register` · `GET /oauth/authorize` · `GET/POST /oauth/authorize/requests/{id}[/decision]` (consent screen) · `POST /oauth/token` · `POST /oauth/revoke` · `POST /oauth/introspect` |
| Resource servers | `POST /oauth/revoked` (revocation feed) · `POST /oauth/usage` (usage reports); a confidential client bound to the server, see [Revocation feed](#revocation-feed) |
| Console session | `GET /api/session/status` · `POST /api/session/setup` · `POST /api/session/login` · `POST /api/session/logout` · `GET /api/session/me` · `PUT /api/session/me/{profile,password}` · `GET /api/session/oauth/{github,google}/{start,callback}` |
| Management (authenticated) | `/api/services*` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| Operational | `GET /health` · `WS /ws/services` (live service status) |

Scripts that call the management API sign in with `POST /api/session/login` and then send, on every request, the `mcp_session` cookie, the `session_binding` value from the login response as `X-Session-Binding`, and a same-origin `Origin` header on writes.

Set `ENABLE_API_DOCS=true` for the full OpenAPI reference at `/docs`.
