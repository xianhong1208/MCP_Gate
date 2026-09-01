# Deploy MCP Center

This guide takes MCP Center from `localhost` to a public HTTPS address behind a reverse proxy. OAuth 2.1 requires HTTPS for every authorization-server endpoint, and MCP clients refuse `http://` issuers outside loopback.

## 1. Decide the public URL

Pick the address clients and servers will use, for example `https://mcp.example.com`. This is the **issuer**. It is written into every token as `iss` and into `/.well-known/oauth-authorization-server`, so:

- it must be reachable by every MCP server (to fetch JWKS) and every client (for discovery and the consent screen);
- changing it later invalidates every issued token.

## 2. Configure MCP Center

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

## 4. Run as a service

`/etc/systemd/system/mcp-center.service`:

```ini
[Unit]
Description=MCP Center
After=network.target

[Service]
User=mcp
WorkingDirectory=/opt/mcp-center
EnvironmentFile=/opt/mcp-center/.env
ExecStart=/opt/mcp-center/.venv/bin/python main.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mcp-center
```

`data/` holds the SQLite database and `data/secrets.json`; back both up together. Losing `secrets.json` makes the encrypted private keys unreadable, which invalidates all tokens.

## 5. Optional: PostgreSQL

```bash
uv sync --extra postgres
```

```bash
DATABASE_URL=postgresql://mcp:password@localhost/mcp_center
```

MCP Center creates the database if the role has `CREATEDB`, runs migrations, and seeds default scopes at startup.

## 6. Optional: Marketplace and bring-your-own servers

These features run MCP servers in Docker on the same host and need:

- Docker Engine with the MCP Center user in the `docker` group;
- the runtime image for bring-your-own servers, built once:

  ```bash
  docker build -t mcp-runtime:1 deploy/mcp-runtime
  ```

  Override the image name with `MCP_RUNTIME_IMAGE` if you tag it differently.

Managed servers bind to `127.0.0.1:<port>` on the host, so register them with host `127.0.0.1` and they stay reachable only from MCP Center's machine.

## 7. Check the deployment

```bash
curl -s https://mcp.example.com/.well-known/oauth-authorization-server | python -m json.tool
curl -s https://mcp.example.com/.well-known/jwks.json | python -m json.tool
```

`issuer` must equal `https://mcp.example.com` exactly, and every endpoint in the document must start with it. Then point a FastMCP server's `JWTVerifier(jwks_uri=..., issuer=...)` at those URLs and connect a client as in the [README](../README.md#quick-start).
