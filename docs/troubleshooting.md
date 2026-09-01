# Troubleshooting

Symptoms are listed as you would see them in a client, a server log or the console.

## Client cannot connect

**`invalid_target: unknown resource: http://…/mcp`** (in the client, or as `error=invalid_target` on the redirect)
MCP Center only issues tokens for servers it knows. Register the server in **Services** and make sure its audience — `oauth_audience`, or the MCP URL if unset — matches what the client sent as `resource`. Trailing slashes and `localhost` vs `127.0.0.1` count as different audiences.

**`unauthorized_client: client is pending approval`**
`OAUTH_DCR_AUTO_APPROVE=false` and the client has not been approved. Open **OAuth Clients → Pending** and approve it, or set the variable to `true`.

**`invalid_request: redirect_uri is not registered for this client`**
The client is reusing a stale `client_id` whose redirect URIs changed. Delete the client in **OAuth Clients**; the client will register again on its next attempt.

**Consent screen never appears; client times out**
The browser cannot reach `OAUTH_ISSUER`. Check that the issuer is the address your browser can open, not an internal one, and that `/oauth/authorize` is proxied.

**`401` from the MCP server after a successful login**
The server's `JWTVerifier` settings do not match MCP Center: `issuer` must equal `OAUTH_ISSUER` exactly, `audience` must equal the audience shown on the service page, and `jwks_uri` must be reachable from the server. Compare with the **Integration** panel.

## Console

**`/setup` returns `409 setup_already_done`**
An owner account exists. Sign in at `/login`. If you lost the password, set `ADMIN_EMAIL`/`ADMIN_PASSWORD` in `.env` and start with a fresh database, or reset the password directly:

```bash
uv run python - <<'EOF'
from db.database import make_session
from src.adapters import AdminUserAdapter
from src.identity.passwords import hash_password
db = make_session()
user = AdminUserAdapter.get_by_email(db, "you@example.com")
AdminUserAdapter.set_password(db, user, hash_password("new-password"))
print("password reset for", user.email)
EOF
```

**`404 {"error": "Frontend not built"}` at `/`**
The console bundle is missing. Run `cd frontend && npm install && npm run build`, then restart.

**Scan does not find a server that is clearly running**
The scanner sends a JSON-RPC `initialize` to `/mcp`. A server that answers `401` with `WWW-Authenticate: Bearer …` (any FastMCP server with `RemoteAuthProvider`) is recognised as MCP behind OAuth; if it trusts this MCP Center, the scanner mints a short-lived token for `http://<host>:<port>/mcp` and reads the real name and tools. That token only matches when the host you scan is exactly the one the server uses as its audience (`127.0.0.1` vs `localhost` matters). Servers protected by a different authorization server, or by a static bearer token, show up as *requires authentication* — register them and add the token on the service page. A `401` without a Bearer challenge or JSON-RPC body is not treated as MCP.

**The scanned server logs `Invalid HTTP request received`**
That was the scanner's HTTPS probe hitting a plain-HTTP port; since 1.0.0 it is skipped whenever the HTTP probe got any answer. Update MCP Center if you still see it.

**Signed out unexpectedly**
Sessions expire after 12 hours, after 30 minutes idle in the UI, and immediately when the password changes. Behind HTTPS, `SECURE_COOKIE=true` is required or the cookie is dropped.

## Server

**`Address already in use`**
Another process is listening on the port derived from `OAUTH_ISSUER`. Stop it or set `SERVER_PORT`.

**Tokens stop verifying after a config change**
Changing `OAUTH_ISSUER` or `ENCRYPTION_KEY` invalidates tokens: the first changes `iss`, the second makes the stored private keys unreadable. Restore the old value or re-issue tokens.

**Health shows `error` / `offline` for a server that works**
The health check connects with a self-minted token for servers that require auth. If the server uses its own static bearer token instead, set it on the service (**Edit → Static bearer token**). For servers without auth, untick **Requires authentication**.

**Marketplace: `Image 'mcp-runtime:1' 尚未安裝` / bring-your-own deploy fails**
Build the runtime image once: `docker build -t mcp-runtime:1 deploy/mcp-runtime`. See [deploy.md](deploy.md#6-optional-marketplace-and-bring-your-own-servers).

## Get more detail

- Set `LOG_LEVEL=DEBUG` in `.env`; logs are written under `logs/`.
- Set `ENABLE_API_DOCS=true` and open `/docs` to call any endpoint by hand.
- `GET /api/oauth/activity` (signed in) lists recent token events with client, audience and outcome.
