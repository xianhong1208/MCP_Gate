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
| `SESSION_SECRET_KEY`, `ENCRYPTION_KEY` | auto-generated | Stored in `secrets/secrets.json` when unset (see `MCP_GATE_SECRETS_DIR`). `ENCRYPTION_KEY` protects private keys and stored secrets; rotate it with `python -m src.cli encryption-key rotate`, never by editing it (that makes them unreadable). A key that does not open the stored signing keys, or a missing one on an existing database, stops startup ([Troubleshooting](troubleshooting.md#server)). |
| `ENCRYPTION_KEYS_PREVIOUS` | — | Older encryption keys, comma-separated, that still decrypt what they encrypted. Only needed while rotating a key kept in the environment; the rotation command keeps its own in the secrets file. |
| `MCP_GATE_SECRETS_DIR` | `secrets` | Directory for the generated secrets, kept apart from `data/` (mode `0700`, the file `0600`). An existing `data/secrets.json` is moved here on the first start. Back it up separately from `data/`; in Docker give it its own volume. |
| `MCP_GATE_SECRETS_FILE` | — | An exact file to use instead (nothing is moved into it). |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | — | Create the owner account at first start instead of using `/setup`. |
| `MCP_GATE_SETUP_TOKEN` | auto-generated | The one-time token `/setup` asks for. Generated into `secrets/secrets.json` and printed in the log while no owner exists; set it when the log is hard to reach (a container). |
| `OAUTH_ACCESS_EXPIRE_MINUTES`, `OAUTH_REFRESH_EXPIRE_DAYS` | `15`, `30` | OAuth token lifetimes (personal access tokens choose their own). |
| `OAUTH_SIGNING_KEY_ROTATION_DAYS`, `OAUTH_SIGNING_KEY_PREPUBLISH_MINUTES` | `90`, `1440` | Signing keys rotate on their own every N days (`0` = only with *Rotate now*); each new key is in the JWKS this many minutes before it signs, so resource servers cache it first. |
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

### Dynamic Client Registration

MCP 2026-07-28 deprecates Dynamic Client Registration (RFC 7591) in favour of [Client ID Metadata Documents](#client-id-metadata-documents). MCP Gate keeps `/oauth/register` working and listed in its metadata (`registration_endpoint`) for clients that do not use metadata documents yet; current clients prefer a metadata document when the server advertises `client_id_metadata_document_supported`, which MCP Gate does. The first registration through DCR after a start logs one warning saying so, and **OAuth Clients** shows how many active clients came in that way.

- **`application_type`.** The specification asks clients to send `application_type` (`native` for desktop apps, CLIs and loopback redirects; `web` for remote browser apps) when they register, because OpenID providers restrict redirect URIs by it. MCP Gate is not an OpenID provider: it accepts `native` and `web` from registrations and metadata documents, refuses any other value with `invalid_client_metadata` (or `invalid_client` for a document), and puts no extra rule on the redirect URIs. The value is not stored.

### MCP protocol versions

MCP Gate's scanner, health checks, *Refresh from server* and *Inspect as* speak both eras of the protocol:

- **2026-07-28 (stateless).** MCP Gate first sends `server/discover` with the protocol version, its client info and capabilities in `_meta` and the `MCP-Protocol-Version` / `Mcp-Method` headers. A server that answers it is read without a handshake or a session: one `tools/list` per refresh.
- **2024-11-05 to 2025-11-25 (`initialize` handshake).** Any other answer — a `400` such as "missing session id", `404`, `405`, a JSON-RPC "method not found" — means an older server, as the specification's backward-compatibility rules say: MCP Gate falls back to `initialize` (offering 2025-11-25; the server picks the version), then sends the session id and the negotiated `MCP-Protocol-Version` on the following requests.
- A modern error (`-32022` unsupported version, `-32020` header mismatch, `-32021` missing capability) is never a reason to fall back: an unsupported version is retried with one the server lists, or reported as "no protocol version in common".
- The era is remembered per server URL while MCP Gate runs and probed again when it stops working, so a server upgraded to 2026-07-28 (or rolled back) is picked up by the next check.
- The server's page shows the protocol it last answered with (for example *MCP version 2026-07-28 · stateless*) after the first health check, scan or refresh since MCP Gate started; it is kept in memory only. `POST /api/services/{id}/health-check`, `GET /api/services/{id}` (`health.protocol_version`, `health.protocol_era`, `health.protocol_seen_at`) and `POST /api/discovery/verify` report it.

Your own FastMCP server needs no change: FastMCP 4 serves both eras on one endpoint, and `MCPGateVerifier` and `MCPGateToolPinning` work in either, also with `stateless_http=True`.

### Revocation feed

MCP servers verify tokens offline, so on its own a server keeps accepting a revoked token until it expires — 15 minutes for an access token, as long as its lifetime for a personal access token. A server that polls the revocation feed rejects it within one poll interval instead:

1. **Register a client for the server.** Under **OAuth Clients** → *Register*: grant type `client_credentials` only, no redirect URIs, token endpoint authentication *Client secret* (POST body or HTTP Basic) or `private_key_jwt`, and *Resource server for* set to the server. For an existing client use its *Resource server…* action, or `PUT /api/oauth/clients/{client_id}/resource-server` with `{"service_id": "<server id>"}`.
2. **Poll `POST /oauth/revoked`** with that client's credentials, optionally `since=<unix time>` for only the newer revocations. The answer is `{"revoked": [{"jti", "revoked_at", "exp"}, …], "now": …}`: revoked, unexpired access tokens, personal access tokens and refresh tokens of **that server only**. Unbound clients get `403`. The same binding lets the server call `/oauth/introspect` and report token usage, again only for its own tokens.
3. **Check it in the console.** The server's page shows a *Revocation feed* row: wired (with the last poll time), stopped polling, never polled, or not wired.

For your own FastMCP server, `MCPGateVerifier` in [`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) does the polling. [Folio](https://github.com/xianhong1208/folio-rag) and [Morphyard](https://github.com/xianhong1208/morphyard) have it built in; see their READMEs.

### Tool pinning and approval

Every tool a server lists is pinned by a SHA-256 of its definition, and a new or changed definition waits for an admin before it counts as approved.

- **What is hashed.** The tool object as `tools/list` returns it, reduced to `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations` (other fields such as `_meta` and `icons` are ignored). A field that is absent or `null` is left out, so the two hash the same; an empty string or object is a value. The rest is serialised as JSON with keys sorted at every depth, no whitespace, non-ASCII characters written as UTF-8 (not `\uXXXX`), then hashed as UTF-8. The definition is `src/tool_pinning/hashing.py`; `tests/fixtures/tool_hash_vectors.json` holds golden vectors that any other implementation must reproduce.
- **States.** Each definition a tool has had is kept as a version with its hash and a state: *approved*, *pending* or *rejected*. A refresh (*Refresh from server*, a scan) adds a pending version for a new tool or a changed definition and keeps every earlier version, so the console compares the change with the approved one. A tool the server stops listing is marked *no longer listed*, not deleted; if it comes back it keeps its history. Refreshing with *Inspect as* another identity behaves the same: tools that identity does not see are marked, never lose their approval.
- **First approval.** On the upgrade to 1.5 every tool already stored is approved as the baseline (`decided_by: upgrade`). Those were stored without `title`, `outputSchema` and `annotations`, so the first refresh that lists a tool again completes its baseline with the full definition when `name`, `description` and `inputSchema` are unchanged; a change there is pending like any other. A server registered later starts with every tool pending, and the console offers **Approve all** on that first list only. After that each new or changed tool is approved or rejected on its own card, which shows a line diff of each changed field (or the whole definition of a new tool).
- **Decisions.** Approve and reject name the version by its hash, so the admin decides on exactly the definition shown. Rejected versions can be approved later, and an approval can be withdrawn by rejecting. Every approval, rejection and *Approve all* is in the audit log (`tool_approve`, `tool_reject`, `tool_approve_all`). The dashboard and the services list show how many tools wait.
- **API.** `GET /api/services/{id}/tools` lists tools with `state`, `hash`, `removed_at`, `versions` and `approved_version` (the version a pending change is compared with), plus `pending_count` and `first_review`. `POST /api/services/{id}/tools/{tool_id}/approve` and `…/reject` take `{"hash": "<64 hex>"}`; `POST /api/services/{id}/tools/approve-all` takes `{"hashes": [...]}` and answers `409 tools.approve_all_not_first` once anything of that service was approved.

MCP Gate records the decisions; it does not sit between clients and servers, so on its own it cannot hide an unapproved tool. A server that runs the pinning middleware does (next section); for any other server the console shows the state but clients still see every tool.

### Poisoning scan

A tool's description and schema are read by the model that calls it, so a server can hide instructions there. Every pinned definition is also checked by built-in rules (no model, no network; `src/tool_pinning/scan.py`), and what they find is shown on the approval card and next to an approved tool. **A finding never blocks anything**: an unapproved tool is hidden anyway (on a server that runs the middleware), and the decision stays the admin's.

- **What is scanned.** Every string and object key of the hashed fields (`name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`), recursively, so an instruction in a parameter description or a `default` is found too. The work is bounded: 2,000 strings, 200,000 characters, 32 levels and 200 findings per definition; beyond that a `scan-truncated` finding says so. Text is matched after NFKC normalisation (fullwidth letters become ASCII), with common Cyrillic and Greek look-alike letters mapped to Latin, case folded, and invisible characters removed, so `ig<U+200B>nore` still reads `ignore`. Offsets point into the original text.
- **The rules** (severity `high`, `warning` or `info`):

  | Rule | Flags | Severity |
  |---|---|---|
  | `invisible-characters` | Zero-width characters, bidirectional controls (U+202A–U+202E, U+2066–U+2069), Unicode tag characters (U+E0000–U+E007F, decoded and shown as *hidden text*), supplementary variation selectors, Hangul fillers. A single joiner between two non-ASCII characters (emoji sequences, Indic and Arabic scripts) is left alone. | high for bidi, tags, variation selectors, a run of 3+, or invisible characters between most letters (reported once); otherwise warning |
  | `instruction-phrase` | "ignore / disregard previous instructions", "do not tell the user", "without telling the user", `<IMPORTANT>`, `<system>`, `[INST]`, chat-template tokens, and Chinese variants (忽略之前的指示, 不要告訴使用者, 对用户保密 …) | high |
  | | "before using this tool", HTML comments, "do not mention that", "new instructions:", "system prompt:", "you are now a …", 使用這個工具之前 | warning |
  | | "you must", "very important", 你必須 | info |
  | `tool-mention` | A tool name registered in MCP Gate (any server) other than the tool's own. Only names with `_`, `-`, `.` or camelCase and at least 4 characters are looked for, so "search" or "fetch" alone never match. | warning when another server lists it (shadowing); info when only this server does |
  | `sensitive-data` | `~/.ssh`, `id_rsa` and other key files, `.aws/credentials`, `/etc/passwd`, `.netrc`, `.npmrc`, `.git-credentials`, `.kube/config`, `.env`, `mcp.json`, `claude_desktop_config.json`, `.cursor/` | high when near "read / send / include / pass …"; otherwise warning |
  | | "API key", "private key", "credentials", "password", 私鑰, 密碼 … near "read / send / include / pass …" | warning |
  | `url` | Any URL | info; warning for a raw IP address, plain `http` / `ftp` / `ws` (not loopback) or a link shortener, and for a URL in a `default` / `const` / `enum` / `examples` of a parameter named like a destination (webhook, callback, report, upload, backup …); high for such a URL in a value slot, or after "send / upload / post … to" |
  | `encoded-blob` | base64 of 60+ characters (mixed case and digits) or hex of 64+ | high when it decodes to readable text (shown); otherwise warning (base64) or info (hex, e.g. a SHA-256) |
  | `long-text` | A description over 4,000 characters (info) or a schema string over 1,000 characters (warning) | info / warning |
  | `scan-truncated` | The work bound was reached | info |

- **Flagged** means at least one `warning` or `high` finding; `info` alone is a note. The dashboard and the services list count pending tools that are flagged ("2 pending, 1 flagged").
- **On the card.** The findings are grouped by rule with a short explanation and the matched text (invisible characters shown as boxed `U+XXXX`), and the matched text is highlighted inside the diff. Approving a definition with a `high` finding asks for confirmation once, naming the findings; anything else is one click, and so is rejecting. The audit entry of every approval or rejection records the findings shown (`details.findings`: counts by severity and the rule ids, plus `scan_rules_version`); *Approve all* records them per tool.
- **Stored nowhere.** Findings are computed when the tool list is read (cached in memory per definition: about 1 ms per definition the first time, microseconds after), so an improved rule re-checks every old version, and `scan_rules_version` in the API says which rule set produced them.
- **API.** Every version in `GET /api/services/{id}/tools` carries `findings`: `[{rule, severity, path, start, end, match, excerpt, detail}]` (`path` into the canonical definition, e.g. `inputSchema.properties.url.default`; `start` / `end` are code-point offsets in that string; `excerpt` writes invisible characters as `<U+XXXX>`). Each tool also has `findings` and `flagged` for its current definition; the response adds `flagged_count` and `scan_rules_version`, and service responses add `tools_flagged`.
- **What it does not catch.** Rules match wording and characters, not intent: a paraphrased instruction, another language, an instruction split across fields, or a tool that behaves differently from its description passes. See [SECURITY.md](../SECURITY.md#known-limitations). Read the definition; the scan only points at places to read first.

### Tool approvals on the server

`MCPGateToolPinning` in [`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) is a FastMCP middleware that enforces the approvals on the server itself. It needs the same resource-server client as the revocation feed (see above) and sits next to `MCPGateVerifier`: `FastMCP(..., middleware=[MCPGateToolPinning(verifier)])`. [`examples/fastmcp_server_hooks.py`](../examples/fastmcp_server_hooks.py) is a complete server.

- **`tools/list`** hashes each of the server's tools (the definition above; the example carries its own copy and reproduces the golden vectors) and lists only approved ones. **`tools/call`** hashes the tool being called and refuses it unless approved, with `Tool '<name>' is not available on this server.`, the same answer as for a tool that does not exist; the reason goes to the server's log.
- **Reports.** A definition MCP Gate does not know yet is sent at once to `POST /oauth/tool-report`, so it appears as pending in the console (marked *Reported by the server*) without waiting for a refresh. A changed description is therefore hidden on the server's next `tools/list` and waiting in the console seconds later.
- **The policy.** Every `poll_interval` seconds (15 by default) it reads `POST /oauth/policy`. MCP Gate's own requests (refresh, scan, health check, *Inspect as*) carry a `mcp_gate_probe` claim in their short-lived token; the middleware shows them every tool, approved or not, so a refresh records the real list and never marks a hidden tool as removed. Calls with such a token are still refused.
- **When MCP Gate cannot be reached** the last list received keeps being used. It is also written to `cache_file` (default `mcp_gate_policy.json` in the working directory; written atomically, mode 600; `None` keeps it in memory only), so a restart while MCP Gate is down keeps it. A cache written for another issuer, audience or hash version is ignored, and so is one older than `max_cache_age` seconds when that is set. Once MCP Gate answers again, its list replaces the cache.
- **Never received a list** (MCP Gate down at the first start and no usable cache): every tool is hidden and not callable, and one log line says why. `fail_open=True` lists and runs every tool until the first list arrives instead.
- **Access rules (1.6).** The middleware polls with `features=rules1`, so MCP Gate answers with the server's [tool access rules](#tool-access-rules) too (format 2), and checks every approved tool against the caller's verified token (its `jti`, `client_id`, `sub` and `scope` claims) with its own copy of the evaluator (`evaluate_access`, which reproduces the golden vectors). On `tools/list` a tool the token may never call (`hidden`: a deny rule, outside an "only" rule, unscoped where the server requires a scope) is left out, and a tool that more scope would unlock (`needs_scope`) is listed. On `tools/call` a hidden tool is refused exactly like an unknown one, and a `needs_scope` tool with `Tool '<name>' requires the scope '<challenge>', which this access token does not carry. …`, a tool error. With [`MCPGateScopeGate`](#step-up) in front, the same call gets an HTTP `403 insufficient_scope` step-up challenge instead. An expired rule stops applying at its `expires_at` even without a poll. MCP Gate's probe tokens still see every tool.
- **Rules and the cache.** The rules are kept and cached with the approvals (cache format 2), so while MCP Gate is unreachable the last rules received keep applying, also across a restart; never received means closed, as above. A cache written for another rules version is ignored; a format 1 cache from a 1.5 middleware is read as approvals only. An answer this file cannot apply exactly (another format or rules version, a malformed policy) is refused as a whole and the previous policy stays in force. An MCP Gate older than 1.6 answers format 1: only approvals are enforced then, and the startup log says "no access rules".
- **Console.** The server's page shows a *Tool approvals* row like the revocation feed's: enforced by the server (with the last poll time), stopped polling, never polled, or not enforced. Under it, once the middleware has polled: **Access rules enforced**, or **Access rules not enforced — update the middleware** when a resource server of that server did not advertise `rules1` on its last poll (a 1.5 middleware lists every approved tool to every token whatever the rules say); shown as a warning when the server has rules, scoped tools or *require a scope*. The review card of a pending tool says whether the server enforces approvals.

The feed and the report, for other implementations (form-encoded `POST`, authenticated like `/oauth/revoked`; only the caller's own server):

- `POST /oauth/policy` (optional `etag`, optional `features`) answers `{"format": 1, "hash_version": 1, "audience", "service_id", "tools": {"approved": [...], "pending": [...], "rejected": [...]}, "rules": [], "unchanged": false, "etag", "now"}`, each list holding 64-hex hashes. Any other hash is unknown: hide it and report it. Ignore fields you do not know. Send back the `etag` you hold to get only `{"unchanged": true, "etag", "now"}` when nothing changed. When the server is disabled or deleted every list is empty.
- **Format 2.** `features` is a space- or comma-separated list of what your implementation enforces; MCP Gate stores it on the client (`policy_features`, lowercase tokens, known ones first, 64 characters at most) and shows it in the console. With `rules1` the answer is format 2: the same fields plus `"rules_version": 1`, `"unscoped_tools": "allow" | "require"`, `"tool_scopes": {"<tool>": {"any_of": [...], "challenge": "<scope>"}}` and `"rules": [{"id", "effect", "subject": {"kind": "pat" | "client" | "user", "id"}, "tools": [...] | ["*"], "expires_at": <unix seconds> | null}]`: exactly the evaluator's input (see [Tool access rules](#tool-access-rules)), unexpired rules only, groups already expanded into `user` rules. The etag covers it, so any change of a rule, a tool's scopes, *require a scope*, a group's members or a scope deleted reaches the server in its next poll; format 1 answers do not change when only rules change. Without `rules1` the answer stays format 1, as in 1.5. Apply a format 2 answer as a whole or not at all: an unknown `rules_version` must not be applied (keep the previous policy), and an unknown rule `effect` is a deny of the tools it names.
- `POST /oauth/tool-report` with `tools` = a JSON array of tool objects as `tools/list` returns them (at most 200, body up to 2 MiB, 30 reports a minute per client, each definition up to 64 KiB). MCP Gate hashes every definition itself: a `hash` sent along is only compared, and a difference is listed in `hash_mismatch`. The answer is `{"recorded": [{"name", "hash", "state", "new"}], "invalid": [{"index", "name", "reason"}], "hash_mismatch": [...]}`. A report goes through the same rules as a refresh, except that tools it does not mention are left alone. New definitions are audited as `tool_report`, with the resource server as the actor.

### Tool access rules

*1.6, in progress.* MCP Gate stores the rules and evaluates them, and a server running the 1.6 `MCPGateToolPinning` middleware receives them in the policy feed (format 2) and enforces them within one poll (see [Tool approvals on the server](#tool-approvals-on-the-server)). A server without that middleware, or with the 1.5 one, does not: the console says so on the server's page. A call that lacks a scope gets an HTTP 403 [step-up](#step-up) challenge when the server also runs `MCPGateScopeGate`, and otherwise a tool error naming the scope.

Who may call which tool of a server is decided in this order, first match wins:

1. **Not approved** ([tool pinning](#tool-pinning-and-approval)): hidden.
2. **A deny rule** for the token names the tool (or `*`, every tool): hidden.
3. **"Only" rules** for the token exist and the tool is outside one of them (several intersect): hidden.
4. **Scopes.** A tool can be put in scopes (global ones the server may grant, or the server's own). A token may call it when it holds **any** of them; otherwise the tool is listed but its call is refused naming one scope (the [step-up](#step-up) challenge). A tool in no scope is allowed, unless the server is set to **require a scope** (`unscoped_tools: require`), which hides it.
5. Otherwise allowed.

- **Bundles are scopes.** A scope with tools in it is a bundle; a tool can be in several, and a broad scope simply holds more tools. Each tool has one **challenge** scope, the one a step-up asks for: the one marked, or else the narrowest (fewest tools, then name). Deleting a scope takes every tool out of it. A scope assigned to a tool must be an RFC 6749 scope-token (printable ASCII without space, `"` or `\`), since it goes into `WWW-Authenticate: Bearer scope="…"`; new scopes must be one, and an older name that is not is reported by the 1.6 migration and cannot be assigned. A scope can have a `title` for display.
- **Rule subjects.** `pat` (a personal access token of this server, by its jti; an OAuth access token cannot be targeted on its own, its jti changes on every refresh), `client` (an OAuth client id; every PAT shares `mcp-gate-console`), `user` (a console account's id, which is the `sub` of its tokens; a `client_credentials` token's `sub` is its client id) and `group`. A rule names tools by name (they must be tools of the server, listed or not) or `["*"]` (deny only); it can have a `note` and an `expires_at` (UTC), after which it no longer applies.
- **Groups** are named sets of console accounts. A rule can name a group; MCP Gate expands it into one rule per member before the server receives it, so a server only ever matches token claims (`jti`, `client_id`, `sub`) and a membership change takes effect with the next poll. A group that a rule names cannot be deleted (that would lift its denies); a member goes when the account is deleted.
- **Limits.** 32 scopes per tool, 500 tools per rule; per server, after group expansion, 2,000 rules and 64 KiB of rules JSON (`409 access.rules_limit` / `access.rules_too_large`, also when adding a member would cross it). Expired rules do not count.
- **The evaluator** is one pure function, `src/tool_policy/evaluate.py` (stdlib only, so the server-side middleware can carry a copy), pinned by golden vectors in `tests/fixtures/tool_policy_vectors.json` that any other implementation must reproduce (`rules_version` 1). Input: `{"unscoped_tools", "tool_scopes": {"<tool>": {"any_of": [...], "challenge"}}, "rules": [{"id", "effect", "subject": {"kind", "id"}, "tools", "expires_at": <unix seconds> | null}]}`, the token's claims, the tool name, whether it is approved and the time. Output: `{"decision": "allowed" | "hidden" | "needs_scope", "reason": "ok" | "not_approved" | "denied_by_rule" | "outside_only_rule" | "missing_scope" | "unscoped_tool_requires_scope", "rule_ids", "scopes", "challenge"}`. A rule with an unknown effect acts as a deny of the tools it names (of every tool when it names none); a rule with an unknown subject kind matches every token.
- **API** (console session; writes audited and origin-checked like the rest of `/api`):
  - `GET /api/services/{id}/access`: `unscoped_tools`, every tool with its scopes and challenge, the rules (with subject labels and `expired`), the scopes a tool may be put in (`challenge_safe`), and `policy`, the evaluator's exact input for the server, groups expanded. `PUT /api/services/{id}/access` `{"unscoped_tools": "allow" | "require"}` (`service_unscoped_tools_set`).
  - `GET/PUT /api/services/{id}/tools/{tool_id}/scopes` `{"scopes": [...], "challenge": null | "<one of them>"}` replaces a tool's scopes (`tool_scope_set`, before and after). Errors: `400 access.unknown_scope`, `access.scope_not_permitted` (a global scope the server's allowed scopes exclude), `access.scope_name_unsafe`, `access.challenge_not_in_scopes`, `access.too_many_scopes`.
  - `GET/POST /api/services/{id}/access-rules`, `GET/PUT/DELETE /api/services/{id}/access-rules/{rule_id}` with `{"effect": "deny" | "only", "subject": {"kind", "id"}, "tools": [...], "note", "expires_at"}` (`tool_rule_create`, `tool_rule_update`, `tool_rule_delete`). Errors: `400 access.invalid_effect`, `access.invalid_subject_kind`, `access.subject_not_found`, `access.pat_other_service`, `access.no_tools`, `access.unknown_tool`, `access.wildcard_not_alone`, `access.only_all_tools`, `access.too_many_tools`, `access.expires_in_past`; `404 access.rule_not_found`.
  - `GET/POST /api/groups`, `GET/PUT/DELETE /api/groups/{id}`, `PUT/DELETE /api/groups/{id}/members/{user_id}` (`group_create`, `group_update`, `group_delete`, `group_member_add`, `group_member_remove`); `409 groups.name_taken` (names are unique ignoring case), `409 groups.in_use`, `404 groups.not_found` / `groups.member_not_found`. `GET /api/users` lists the console accounts to pick from.
- **Upgrading to 1.6.** Migration `b5d7f9a1c3e6` adds the tables `tool_scopes`, `tool_access_rules`, `user_groups` and `user_group_members`, the columns `services.unscoped_tools` (`allow` for every existing server), `oauth_clients.policy_features` and `title` on both scope tables, and turns the `scope` columns of clients, authorization requests and codes, tokens and consents into `TEXT` (a token with many bundle scopes outgrew `VARCHAR(512)` on PostgreSQL); a `scope` parameter may now be 4,096 characters. Nothing is backfilled, so nothing changes until an admin assigns a scope or adds a rule. Downgrading on PostgreSQL fails if a scope string longer than 512 characters was stored since.

### Step-up

*1.6.* A token that lacks the scope a tool needs gets that tool listed, and its call answered with **HTTP 403** and `WWW-Authenticate: Bearer error="insufficient_scope", scope="<challenge>", resource_metadata="<protected resource metadata URL>", error_description="<reason>"` (RFC 6750 §3.1, MCP authorization *step-up*). A client that supports step-up asks the user to authorize again with that scope added and retries the call. MCP clients start re-authorization only on a real 403: a tool error inside HTTP 200 never triggers it. That is why the 403 comes from an ASGI middleware that runs before FastMCP answers.

`MCPGateScopeGate` in [`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) is that middleware. It goes on the server's HTTP app next to `MCPGateToolPinning`, with the same evaluator: `mcp.run(transport="http", middleware=[Middleware(MCPGateScopeGate, pinning=pinning, server=mcp)])` (see the README's complete example).

- **What it answers.** For each `POST` it reads the JSON-RPC body before the app runs. Only a `tools/call` of an approved tool whose verdict is `needs_scope` gets the 403. The body is a JSON-RPC error (`code` -32001, `message` = the reason, `data` = `{"error": "insufficient_scope", "scope"}`) with the request's `id`. Everything else is passed on unchanged, byte for byte: other methods (with MCP 2026-07-28's `Mcp-Method` header the body is not even read), an unknown, unapproved or rule-hidden tool (the pinning middleware still refuses it as unknown, so a 403 never reveals a hidden tool), MCP Gate's probe tokens, a token without the server's `required_scopes` (FastMCP answers that itself), every `GET` (the SSE stream) and `DELETE`. The gate never changes a response the app has started, so streamed answers are untouched.
- **Body cap.** `max_body` (4 MiB by default). A larger body, by `Content-Length` or as it arrives, is passed through whole, and the pinning middleware refuses the call with the tool error below.
- **Legacy JSON-RPC batch.** Answered with a 403 only when every message is a `tools/call` that needs the same scope (the body is then an array of errors). Any other batch is passed through and refused call by call.
- **Challenge scope.** Only the tool's challenge scope by default, as MCP 2026-07-28 and RFC 6750 define it: the client re-authorizes with the union of that scope and what it already holds. Claude Code, FastMCP's `client_credentials` client and claude.ai all do so. `challenge_includes_token_scopes=True` also lists the token's current scopes (never `offline_access`), for a client that replaces its scopes with the challenge, which is the approach MCP 2025-11-25 recommends to servers for such clients. The cost: Claude Code with a personal access token then shows every listed scope as "required".
- **The reason** names the scope and says what this kind of token can do. A personal access token (`client_id` `mcp-gate-console`) cannot gain scopes: issue a new one with that scope (*Tokens → Issue token*). A `client_credentials` token (`sub` = `client_id`): request a token with that scope; if MCP Gate refuses it, an admin must allow the scope for the client. A user's token: sign in again and approve the scope, or use a personal access token issued with it. The same text is the pinning middleware's tool error (`Tool '<name>' requires the scope '<scope>', which …`), so a server without the gate, or a client that ignores the 403, still shows it.
- **Consent page.** Each requested scope lists the approved tools it unlocks on that server. When the user had agreed to this client for this server before (a remembered consent, or else their newest access token through it), the page says *Asking for more access* and marks the scopes that are new, and the tools they could not call before: a tool in a new scope, or one added to a granted scope after that agreement. *Remember this decision* keeps the union of what was remembered and what is approved (as before), so a step-up that asks only for the new scope does not drop the old ones. The consent audit records `step_up` and `added_scopes`. Manual (trusted) clients still skip the page, so their step-up is silent, limited by the client's allowed scopes.
- **No loop.** One call gets one 403. A client that cannot get the scope stops: MCP Gate's token endpoint answers `invalid_scope` (`scope not permitted: <scope>`) to a `client_credentials` client whose allowed scopes exclude it, and a personal access token cannot be upgraded.

**Clients tested** (2026-11-25, MCP Gate 1.6 development build and FastMCP 4.1.5, server = the README's complete example):

| Client | Signed in with | Result |
|---|---|---|
| Claude Code 2.1.318, interactive | OAuth (Client ID Metadata Document) | **Steps up.** Asks "needs additional permissions for this tool … Re-authenticate now?", opens the consent page for the challenge scope plus the scopes it already holds, then retries the call once, which succeeds. |
| Claude Code 2.1.318, `claude -p` (headless) | OAuth | Does not step up by itself. Reports `MCP server "<name>" needs additional permissions (scope: "<scope>") — run /mcp to re-authenticate`; after `claude mcp login <name>` (which asks for the union) the call succeeds. |
| Claude Code 2.1.318 | personal access token in a header | One 403, no loop. Shows `Insufficient scope: required "<scope>"`, not the reason text. Issue a new token with the scope. |
| FastMCP 4.1.5 `ClientCredentialsOAuthProvider` | `client_credentials` | **Steps up.** Requests a new token with the union of its scopes and the challenge, retries, succeeds. |
| same, client whose allowed scopes exclude it | `client_credentials` | One 403, then MCP Gate refuses the token request: `OAuthTokenError … invalid_scope … scope not permitted: <scope>`. No loop. |
| FastMCP 4.1.5 `BearerAuth` | personal access token | One 403. The call raises `MCPError` with the reason text ("A personal access token cannot gain scopes: issue a new one …"). |
| VS Code, Codex, Cursor | | Not tested: not installed on the test machine. Reports from February 2026 say Cursor does not step up. Their users get the reason text, or can be given the scope by default (a default scope is granted at first sign-in). |

### Connecting MCP clients

Each server's page has a **Connect a client** panel (also reached from the plug icon on the services list, and **Connect clients** there for every server at once) with ready-made configuration for **Claude Code, Cursor, VS Code and Codex**: one tab per client, the commands where the client has them, the file it reads (copy or download), and the steps. The server URL in every snippet is the server's **audience**: a client sends the URL it connects to as the RFC 8707 `resource`, and MCP Gate only accepts a registered audience, so any other address for the same server fails with `invalid_target`. An audience that is not an `http(s)` URL falls back to the server's own address.

| Client | Sign in (default) | Personal token | Follows |
|---|---|---|---|
| Claude Code | `claude mcp add --transport http <name> <url>`, then `claude mcp login <name>` (or `/mcp`); `.mcp.json` `{"mcpServers": {"<name>": {"type": "http", "url": …}}}` | `--header 'Authorization: Bearer ${MCP_GATE_PAT_<NAME>}'`; Claude Code expands the variable when it connects | [Claude Code MCP](https://code.claude.com/docs/en/mcp) |
| Cursor | **Add to Cursor** install link (`cursor://anysphere.cursor-deeplink/mcp/install`), or `~/.cursor/mcp.json` `{"mcpServers": {"<name>": {"url": …}}}`; sign in from *Needs login* | `"headers": {"Authorization": "Bearer ${env:MCP_GATE_PAT_<NAME>}"}` | [Cursor MCP](https://cursor.com/docs/context/mcp), [install links](https://cursor.com/docs/context/mcp/install-links) |
| VS Code | `code --add-mcp '{"name": …, "type": "http", "url": …}'`, or `.vscode/mcp.json` `{"servers": {…}}` | a `promptString` input with `password: true` and `${input:mcp-gate-pat-<name>}` in the header: VS Code asks once and keeps the token in its secret storage | [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| Codex | `codex mcp add <name> --url <url>`, then `codex mcp login <name>`; `~/.codex/config.toml` `[mcp_servers.<name>]` `url = …` | `bearer_token_env_var = "MCP_GATE_PAT_<NAME>"` | [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) |

**Sign in** needs nothing up front: every one of these clients reads the server's protected resource metadata, finds MCP Gate, registers itself (a Client ID Metadata Document or dynamic client registration) and opens the consent screen. Scopes are not pinned in the snippets; the client asks for what the server advertises and MCP Gate grants the defaults the server allows. When `dcr_auto_approve` is off, a new client waits for an admin under *OAuth Clients* first, and the panel says so. **Personal token** is for machines without a browser (CI, remote shells). No snippet ever contains a token: each references an environment variable named after the server (or VS Code's password prompt), and a personal access token works for one server only.

`GET /api/services/{id}/client-config?client=claude-code|cursor|vscode|codex&variant=oauth|pat` returns `file` (`format`, `path`, `filename`, `content`), `commands`, `install_links`, `servers` (name, config key, URL, accepted scopes, the PAT variable), `docs_url`, `issuer`, `dcr_auto_approve`, `requires_auth` and, for `pat`, `pat_page`; `&download=1` returns only the file as an attachment. `GET /api/client-config` does the same for every active server, sorted by name, and lists in `skipped` the ones without an address. Both need a console session, like reading a service, and answer `409 client_config.no_url` / `422 client_config.unknown_client` / `422 client_config.unknown_variant`. Config keys are the server name reduced to `A–Z a–z 0–9 - _` (numbered when two collide) and every value is quoted for the shell, JSON or TOML it lands in.

## Use the console

| Page | What you do there |
|---|---|
| **Dashboard** | Service health, token activity, recent events, system status. |
| **Services** | Register or scan MCP servers, set audience and allowed scopes, declare server-specific scopes, refresh tools and approve new or changed ones ([tool pinning](#tool-pinning-and-approval)), run health checks, copy integration snippets and client configuration ([Connecting MCP clients](#connecting-mcp-clients)). |
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
| Resource servers | `POST /oauth/revoked` (revocation feed) · `POST /oauth/usage` (usage reports) · `POST /oauth/policy` (tool policy feed) · `POST /oauth/tool-report` (tool reports); a confidential client bound to the server, see [Revocation feed](#revocation-feed) and [Tool approvals on the server](#tool-approvals-on-the-server) |
| Console session | `GET /api/session/status` · `POST /api/session/setup` · `POST /api/session/login` · `POST /api/session/logout` · `GET /api/session/me` · `PUT /api/session/me/{profile,password}` · `GET /api/session/oauth/{github,google}/{start,callback}` |
| Management (authenticated) | `/api/services*` (incl. `/api/services/{id}/access`, `…/access-rules*`, `…/tools/{tool_id}/scopes`, see [Tool access rules](#tool-access-rules)) · `/api/groups*` · `/api/users` · `/api/client-config` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| Operational | `GET /health` · `WS /ws/services` (live service status) |

Scripts that call the management API sign in with `POST /api/session/login` and then send, on every request, the `mcp_session` cookie, the `session_binding` value from the login response as `X-Session-Binding`, and a same-origin `Origin` header on writes.

Set `ENABLE_API_DOCS=true` for the full OpenAPI reference at `/docs`.
