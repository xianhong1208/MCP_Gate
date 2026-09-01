# MCP Center

**An open-source OAuth 2.1 authorization server and management console for your Model Context Protocol servers.**

MCP Center puts standards-based authentication in front of every MCP server you run. A [FastMCP](https://github.com/PrefectHQ/fastmcp) server becomes protected with one `RemoteAuthProvider`, and MCP clients such as Claude Code, Claude Desktop and Cursor connect through the OAuth flow they already implement — no custom tokens, no verification callbacks, no per-server auth code.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-green.svg)](pyproject.toml)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1-6366f1.svg)](#how-it-works)
[![Works with FastMCP](https://img.shields.io/badge/FastMCP-3.x-22c55e.svg)](https://gofastmcp.com)
[![Tests](https://img.shields.io/badge/tests-pytest-informational.svg)](CONTRIBUTING.md)

[繁體中文](README.zh-TW.md) · [Quick start](#quick-start) · [How it works](#how-it-works) · [Configuration](#configuration) · [Deploy](docs/deploy.md) · [Troubleshooting](docs/troubleshooting.md) · [Architecture](docs/architecture.md)

```
┌──────────────────────┐   ① 401 + protected-resource metadata   ┌──────────────────────┐
│      MCP client      │ ───────────────────────────────────────▶ │   your FastMCP server │
│ Claude Code / Cursor │ ◀─────────────────────────────────────── │   (resource server)   │
│  Claude Desktop / …  │   ⑤ Authorization: Bearer <JWT>          │                      │
└──────────┬───────────┘                                          └──────────┬───────────┘
           │ ② discovery + dynamic client registration                       │ ④ fetch JWKS once,
           │ ③ authorize (PKCE) → consent → code → token                     │    verify offline
           ▼                                                                 ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│  MCP Center — OAuth 2.1 authorization server + console                                    │
│  /.well-known/oauth-authorization-server   /.well-known/jwks.json                        │
│  /oauth/register  /oauth/authorize  /oauth/token  /oauth/revoke  /oauth/introspect       │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

## Key features

- **Standards-based authorization server.** Covers the authorization requirements of the [MCP specification (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization): RFC 8414 metadata, RFC 7591 dynamic client registration, authorization code + PKCE (S256), refresh-token rotation with replay detection, RFC 7009 revocation, RFC 7662 introspection, RFC 8707 resource indicators, RFC 9207 `iss` responses.
- **Asymmetric signing, offline verification.** RS256 keys with JWKS publishing and rotation. MCP servers verify tokens locally with the public key; MCP Center is never on the request path.
- **One-block FastMCP integration.** `RemoteAuthProvider` + `JWTVerifier(jwks_uri, issuer, audience)` protects a server. Tokens are bound to each server's audience, so a token for one server never works on another.
- **Consent screen.** Dynamically registered clients ask the owner for permission on first connect; decisions can be remembered per client and server. Clients you register yourself skip the prompt.
- **Personal access tokens (PATs).** Mint long-lived bearer tokens from the console for scripts, CI and clients that cannot run an OAuth flow, with ready-to-paste `claude mcp add` and `mcpServers` snippets.
- **Server registry and health.** Register or auto-discover MCP servers, sync their tool lists, monitor health every 30 seconds and stream status changes over WebSocket.
- **Marketplace and orchestrator.** Deploy MCP servers from a catalog with one click, or paste a standard `{command, args, env}` block and let MCP Center containerize it behind an HTTP bridge (requires Docker).
- **Zero-config start.** SQLite by default, secrets generated on first run, an in-browser setup wizard for the owner account. PostgreSQL and GitHub / Google sign-in are a few environment variables away.

## Install MCP Center

Prerequisites:

- Python 3.11 or later and [uv](https://docs.astral.sh/uv/).
- Docker — only if you use the Marketplace or bring-your-own servers.
- Node.js 18 or later — only if you work on the console UI.

```bash
git clone https://github.com/xianhong1208/MCP_Center.git
cd MCP_Center
uv sync
cp .env.example .env      # optional: every setting has a working default
uv run python main.py
```

The startup banner tells you where everything is:

```
╔══════════════════════════════════════════════════════╗
║   MCP Center — OAuth 2.1 AS for your MCP servers     ║
╚══════════════════════════════════════════════════════╝
  Version:    1.0.0
  Address:    http://0.0.0.0:4568
  Issuer:     http://localhost:4568
  Database:   sqlite:///data/mcp_center.db
  Metadata:   http://localhost:4568/.well-known/oauth-authorization-server
  JWKS:       http://localhost:4568/.well-known/jwks.json
  No admin account yet → open http://localhost:4568/setup to create the owner
```

Open <http://localhost:4568/setup>, create the owner account, and you are in the console.

> **Deploying somewhere other than `localhost`?** Set `OAUTH_ISSUER` to the public URL (for example `https://mcp.example.com`) before you issue any tokens. It is written into every token as `iss` and into the discovery document, so it must be reachable by your MCP servers and clients, and changing it later invalidates every token. See [Deploy](docs/deploy.md).

## Quick start

The order matters: **register the server first**. MCP Center only issues tokens for audiences it knows; a client that asks for an unregistered server gets `invalid_target`.

### 1. Register the server in the console

Open **Services → Register Service** and enter the server's host, port and path (the path is the MCP endpoint, `/mcp` by default). The server's *audience* — the URL a token is valid for — defaults to its MCP URL, for example `http://127.0.0.1:8000/mcp`.

### 2. Protect the FastMCP server

The **Integration** panel on the service page generates this for you:

```python
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

auth = RemoteAuthProvider(
    token_verifier=JWTVerifier(
        jwks_uri="http://localhost:4568/.well-known/jwks.json",
        issuer="http://localhost:4568",
        audience="http://127.0.0.1:8000/mcp",   # must match the audience in the console
    ),
    authorization_servers=[AnyHttpUrl("http://localhost:4568")],
    base_url="http://127.0.0.1:8000",
)

mcp = FastMCP(name="demo", auth=auth)

@mcp.tool
def hello(name: str) -> str:
    return f"Hello, {name}!"

mcp.run(transport="http", host="127.0.0.1", port=8000)
```

FastMCP serves `/.well-known/oauth-protected-resource` automatically, pointing clients at MCP Center. A complete, runnable version — including a `whoami` tool that returns the token's claims — is in [`examples/fastmcp_server.py`](examples/fastmcp_server.py).

### 3. Connect a client

**Clients that speak OAuth** (Claude Code, Claude Desktop, Cursor, the FastMCP `Client`) need nothing up front:

```bash
claude mcp add --transport http demo http://127.0.0.1:8000/mcp
```

On first use the client registers itself with MCP Center and opens the consent screen in your browser. The screen shows the client name, the target server, the requested scopes (`mcp:tools:read`, `mcp:tools:invoke`, `mcp:resources:read`, `mcp:prompts:read` by default) and a **Remember this decision** checkbox. Click **Allow**; the client receives a token and refreshes it by itself from then on.

```python
from fastmcp import Client

async with Client("http://127.0.0.1:8000/mcp", auth="oauth") as client:
    print(await client.list_tools())
```

**Everything else** — scripts, CI jobs, clients without OAuth — uses a personal access token issued from **Issue Token** in the console:

```bash
claude mcp add --transport http demo http://127.0.0.1:8000/mcp \
  --header "Authorization: Bearer <PERSONAL_ACCESS_TOKEN>"
```

```python
from fastmcp import Client
from fastmcp.client.auth import BearerAuth

async with Client("http://127.0.0.1:8000/mcp", auth=BearerAuth("<PERSONAL_ACCESS_TOKEN>")) as client:
    print(await client.list_tools())
```

### 4. Verify

```bash
curl -s http://localhost:4568/.well-known/oauth-authorization-server | python -m json.tool | head
claude mcp list          # expect:  demo: http://127.0.0.1:8000/mcp (HTTP) - ✓ Connected
```

In Claude Code, call the `whoami` tool from the example server. It returns the subject, client and scopes of the token that reached the server:

```json
{"subject": "9b76a95d-…", "client_id": "mcpc_6c68…", "scopes": ["mcp:prompts:read", "mcp:resources:read", "mcp:tools:invoke", "mcp:tools:read"], "email": "you@example.com"}
```

## How it works

MCP Center plays the **authorization server** role from the MCP specification. Your MCP servers are **resource servers**: they never issue or store tokens.

| Step | Who | What happens |
|---|---|---|
| Discovery | client → server → MCP Center | The server answers `401` with a `WWW-Authenticate` header pointing at its protected-resource metadata, which names MCP Center as the authorization server. The client fetches `/.well-known/oauth-authorization-server`. |
| Registration | client → MCP Center | The client registers dynamically (`POST /oauth/register`) and gets a `client_id`. Public clients use PKCE; confidential clients get a secret. |
| Authorization | browser → MCP Center | `/oauth/authorize` validates the request, binds it to the target server through the `resource` parameter, and shows the consent screen (or skips it for remembered or trusted clients). |
| Token | client → MCP Center | `/oauth/token` exchanges the code — checking PKCE, redirect URI and resource — for an RS256 access token plus a refresh token. |
| Verification | server | The server fetches JWKS once, then verifies signature, issuer, audience, expiry and scopes locally. |
| Revocation | console or client | Revoking a refresh token invalidates its whole family, and `POST /oauth/introspect` reports `active: false` immediately. Access tokens verified offline stay valid until they expire, so keep them short (60 minutes by default) or use FastMCP's `IntrospectionTokenVerifier` on servers that need instant revocation. |

Access-token claims: `iss`, `sub`, `aud`, `scope`, `client_id`, `jti`, `iat`, `exp`, `token_use`, and — for tokens issued to a signed-in owner — `email` and `name`.

To change when the consent screen appears, edit [`src/oauth/consent_policy.py`](src/oauth/consent_policy.py); the policy is one small function.

### Terms

| Term | Meaning |
|---|---|
| Issuer | MCP Center's public URL (`OAUTH_ISSUER`). Written into every token as `iss`; clients and servers use it for discovery. |
| Audience | The MCP URL a token is valid for (the `aud` claim). Set per server in the console; the server's `JWTVerifier(audience=…)` must match. |
| Resource server | Your MCP server. It verifies tokens and never issues them. The console calls these *services*. |
| Scope | What a token may do on a server, for example `mcp:tools:invoke`. The console's scope registry defines the set. |
| DCR | Dynamic client registration (RFC 7591): a client creates its own `client_id` on first connect. |
| PAT | Personal access token: a long-lived access token minted from the console, used as a plain bearer token. |

## Configuration

Settings live in [`config/config.yaml`](config/config.yaml) and read their secrets from environment variables (`.env`). The ones you are likely to touch:

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH_ISSUER` | `http://localhost:4568` | Public URL of MCP Center. Also decides the port MCP Center binds. **Change this for any non-local deployment.** |
| `DATABASE_URL` | `sqlite:///data/mcp_center.db` | Point at `postgresql://…` to use PostgreSQL (`uv sync --extra postgres`). |
| `SESSION_SECRET_KEY`, `ENCRYPTION_KEY` | auto-generated | Stored in `data/secrets.json` when unset. `ENCRYPTION_KEY` protects private keys and stored secrets; rotating it makes them unreadable. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | — | Create the owner account at first start instead of using `/setup`. |
| `OAUTH_ACCESS_EXPIRE_MINUTES`, `OAUTH_REFRESH_EXPIRE_DAYS` | `60`, `30` | Token lifetimes. |
| `OAUTH_DCR_AUTO_APPROVE` | `true` | Whether dynamically registered clients are usable immediately (the consent screen still gates them) or must be approved in the console. |
| `GITHUB_CLIENT_ID/_SECRET`, `GOOGLE_CLIENT_ID/_SECRET` | — | Enable GitHub / Google sign-in for the console (experimental — the providers are implemented but not yet verified against live accounts). Callback: `<issuer>/api/session/oauth/<provider>/callback`. |
| `SECURE_COOKIE` | `false` | Set to `true` behind HTTPS. |
| `ENABLE_API_DOCS` | — | `true` exposes OpenAPI at `/docs`. Environment-only; not in `config.yaml`. |

Advanced: `SERVER_HOST` / `SERVER_PORT` override the bind address when it must differ from the issuer, for example listening on `127.0.0.1` behind a reverse proxy. See [Deploy](docs/deploy.md) for the full reverse-proxy and HTTPS procedure.

## Use the console

| Page | What you do there |
|---|---|
| **Dashboard** | Service health, token activity, recent events, system status. |
| **Services** | Register or scan MCP servers, set audience and allowed scopes, refresh tools, run health checks, copy integration snippets. |
| **Tokens · Issue Token** | Every token issued by MCP Center — OAuth grants and PATs — with revoke, expiry and last-use information. |
| **OAuth Clients** | Dynamically registered and trusted clients: approve, revoke, delete; scope registry; signing-key rotation. |
| **Marketplace** | Deploy MCP servers from the catalog or bring your own `{command, args, env}`. |
| **Audit Logs** | Who did what, when, and from where. |

Sign in with email and password, or with GitHub / Google once configured. The console is single-tenant by design: whoever signs in is the administrator.

The console is in English by default; the switcher in the top bar changes it to Traditional Chinese, and the choice is remembered per browser.

## API reference

| Group | Endpoints |
|---|---|
| OAuth (public) | `GET /.well-known/oauth-authorization-server` · `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json` · `POST /oauth/register` · `GET /oauth/authorize` · `GET/POST /oauth/authorize/requests/{id}[/decision]` (consent screen) · `POST /oauth/token` · `POST /oauth/revoke` · `POST /oauth/introspect` |
| Console session | `GET /api/session/status` · `POST /api/session/setup` · `POST /api/session/login` · `POST /api/session/logout` · `GET /api/session/me` · `PUT /api/session/me/{profile,password}` · `GET /api/session/oauth/{github,google}/{start,callback}` |
| Management (authenticated) | `/api/services*` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| Operational | `GET /health` · `WS /ws/services` (live service status) |

Set `ENABLE_API_DOCS=true` for the full OpenAPI reference at `/docs`.

## Documentation

- [Deploy behind a reverse proxy with HTTPS](docs/deploy.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture](docs/architecture.md)
- [Security policy](SECURITY.md)
- [Contributing and development setup](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md) · [Roadmap](ROADMAP.md)

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the layering rule enforced in CI, and the pull-request checklist.

## License

[MIT](LICENSE)
