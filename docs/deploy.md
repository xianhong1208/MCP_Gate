# Deploy MCP Gate

This guide takes MCP Gate from `localhost` to a public HTTPS address behind a reverse proxy. OAuth 2.1 requires HTTPS for every authorization-server endpoint, and MCP clients refuse `http://` issuers outside loopback.

## 1. Decide the public URL

Pick the address clients and servers will use, for example `https://mcp.example.com`. This is the **issuer**. It is written into every token as `iss` and into `/.well-known/oauth-authorization-server`, so:

- it must be reachable by every MCP server (to fetch JWKS) and every client (for discovery and the consent screen);
- changing it later invalidates every issued token.

## 2. Configure MCP Gate

`.env`:

```bash
OAUTH_ISSUER=https://mcp.example.com
SECURE_COOKIE=true            # cookies only over HTTPS
SERVER_HOST=127.0.0.1         # listen only for the proxy
SERVER_PORT=4568              # the issuer has no port, so bind explicitly
ADMIN_EMAIL=you@example.com   # optional: create the owner at first start
ADMIN_PASSWORD=...
```

How the bind port is chosen: `SERVER_PORT` if set, otherwise the port in `OAUTH_ISSUER`, otherwise `4568`.

`config/config.yaml`: add the proxy's address to `security.trusted_proxies` so audit logs record the real client IP from `X-Forwarded-For`:

```yaml
security:
  trusted_proxies:
    - "127.0.0.1"
    - "::1"
```

## 3. Reverse proxy

Everything is served from one origin. Forward these paths and keep WebSocket upgrades for `/ws/`:

| Path | Purpose |
|---|---|
| `/.well-known/` | OAuth discovery and JWKS (public) |
| `/oauth/` | Authorization, token, registration, revocation, introspection (public) |
| `/api/` | Console API (cookie-authenticated) |
| `/ws/` | Live service status (WebSocket) |
| `/` | Console single-page app |

### Caddy

```caddyfile
mcp.example.com {
    reverse_proxy 127.0.0.1:4568
}
```

Caddy obtains the certificate and proxies WebSockets automatically.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name mcp.example.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:4568;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade           $http_upgrade;   # WebSocket (/ws/services)
        proxy_set_header   Connection        "upgrade";
        proxy_read_timeout 300s;                              # long-running deploys
    }
}
```

Keep `Host` and `X-Forwarded-Proto` as shown: the console's WebSocket, and every console `POST` / `PUT` /
`PATCH` / `DELETE`, is only accepted when its `Origin` (or else `Referer`) is the address the browser used
(or `OAUTH_ISSUER`, or an entry in `cors.allowed_origins`), and MCP Gate reads that address from these
headers when the proxy is listed in `security.trusted_proxies`. A proxy that rewrites `Host` to the
upstream address without sending `X-Forwarded-Host` makes every console change fail with 403
`auth.csrf_origin_denied`.

MCP Gate only answers requests whose `Host` is the `OAUTH_ISSUER` host, `localhost` / `*.localhost`, or an IP
address (protection against DNS rebinding); anything else gets 421 `http.host_not_allowed` and one warning in the
log. A proxy that keeps `Host` (both examples above) or rewrites it to `127.0.0.1:4568` needs nothing. If MCP Gate is
also reached under another name — a Docker Compose service name such as `http://mcp-gate:4568` used by resource
servers to fetch the JWKS, an internal DNS alias — list it:

```bash
ALLOWED_HOSTS=mcp-gate,*.internal.example   # exact names or *.suffix; "*" turns the check off
```

### Local use without a proxy

Running on `http://localhost:4568` is fine for one person on one machine, but the browser shares the console's
cookie with every other `localhost` port (see `SECURITY.md`, *Known limitations*). MCP Gate does not accept the
cookie without the per-session binding the console keeps in its own origin's storage, so a local listener that
receives the cookie cannot use it. If other local services you do not trust run on the same machine, give the
console a host name of its own so the cookie is not sent to them at all: preferably HTTPS behind a proxy as below,
or `OAUTH_ISSUER=http://mcp-gate.localhost:4568` (browsers resolve `*.localhost` to loopback without DNS; check
that your MCP clients accept an `http` issuer that is not literally `localhost` / `127.0.0.1` first).

## 4. Run as a service

`/etc/systemd/system/mcp-gate.service`:

```ini
[Unit]
Description=MCP Gate
After=network.target

[Service]
User=mcp
WorkingDirectory=/opt/mcp-gate
EnvironmentFile=/opt/mcp-gate/.env
ExecStart=/opt/mcp-gate/.venv/bin/python main.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mcp-gate
```

Run **one process only** — do not add uvicorn/gunicorn workers or scale out replicas. The rate limiter keeps its counters in memory and the scheduler (token purges, audit retention, health checks) runs inside the process, so several processes would each enforce their own limit and run every job once per process. MCP Gate warns at startup when `WEB_CONCURRENCY` or `UVICORN_WORKERS` is greater than 1.

`data/` holds the SQLite database and `data/secrets.json`; back both up together. Losing `secrets.json` makes the encrypted private keys unreadable, which invalidates all tokens.

## 5. Optional: PostgreSQL

```bash
uv sync --extra postgres
```

```bash
DATABASE_URL=postgresql://mcp:password@localhost/mcp_gate
```

MCP Gate creates the database if the role has `CREATEDB`, runs migrations, and seeds default scopes at startup.

## 6. Optional: Marketplace and bring-your-own servers

These features run MCP servers in Docker on the same host and need:

- Docker Engine with the MCP Gate user in the `docker` group;
- the runtime image for bring-your-own servers, built once:

  ```bash
  docker build -t mcp-runtime:1 deploy/mcp-runtime
  ```

  Override the image name with `MCP_RUNTIME_IMAGE` if you tag it differently.

Managed servers bind to `127.0.0.1:<port>` on the host, so register them with host `127.0.0.1` and they stay reachable only from MCP Gate's machine.

### Without Docker

Set `MCP_RUNTIME=process` to run bring-your-own servers as local subprocesses instead of containers. MCP Gate then needs only `supergateway` on its `PATH` (`npm install -g supergateway`, or point `MCP_SUPERGATEWAY_BIN` at it) plus whatever the servers themselves need (`npx`, `uvx`, …). Each server gets a pid file and a log file under `MCP_PROCESS_LOG_DIR` (default `data/managed`), so a restarted MCP Gate finds, reads and stops servers it did not start itself. Catalog entries are Docker images and stay unavailable in this mode. `MCP_RUNTIME=auto` picks Docker when the daemon answers and falls back to the process runtime otherwise; `GET /api/managed/runtime` shows which one is active and whether it can start anything.

## 7. Check the deployment

```bash
curl -s https://mcp.example.com/.well-known/oauth-authorization-server | python -m json.tool
curl -s https://mcp.example.com/.well-known/jwks.json | python -m json.tool
```

`issuer` must equal `https://mcp.example.com` exactly, and every endpoint in the document must start with it. Then point a FastMCP server's `JWTVerifier(jwks_uri=..., issuer=...)` at those URLs and connect a client as in the [README](../README.md#quick-start).
