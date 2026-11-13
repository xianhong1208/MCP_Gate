# Deploy MCP Gate

This guide takes MCP Gate from `localhost` to a public HTTPS address behind a reverse proxy. To run it in a container instead of a Python environment, read sections 1–3 and then [Docker](#docker). OAuth 2.1 requires HTTPS for every authorization-server endpoint, and MCP clients refuse `http://` issuers outside loopback.

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

`config/security.yaml`: add the proxy's address to `security.trusted_proxies` so audit logs record the real client IP from `X-Forwarded-For`:

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

`data/` holds the SQLite database; `secrets/` holds `secrets.json` with `ENCRYPTION_KEY` (directory mode `0700`, file `0600`; `MCP_GATE_SECRETS_DIR` moves it). They are kept apart on purpose, so a copy of `data/` alone does not carry the key that decrypts the private keys stored in it: **back up `secrets/` separately from `data/`** (another medium, or encrypted). You need both to restore; losing `secrets.json` makes the encrypted private keys unreadable, which invalidates all tokens. MCP Gate then refuses to start (`The encryption key does not match the database`) instead of generating a new key over the old data: restore `secrets/` or set the old `ENCRYPTION_KEY` (see [Troubleshooting](troubleshooting.md#server)). An install from before 1.4 kept the file at `data/secrets.json`; the first start moves it to `secrets/` and logs the move. In a container, mount `secrets/` as its own volume (or a Docker secret, with `MCP_GATE_SECRETS_FILE` pointing at it), never inside the data volume.

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

## Docker

The official image is **`tonyhuang1101/mcp-gate`** on Docker Hub, for `linux/amd64` and `linux/arm64`, published from 1.4.0 on for every release as `<version>` (for example `1.4.0`), `<major>.<minor>` and `latest`. It is built from the repository's `Dockerfile`, which you can also build yourself (`docker build -t mcp-gate:local .`).

What is in it: Python 3.13 (slim) with the locked dependencies, including the PostgreSQL driver; MCP Gate runs as the unprivileged user `mcpgate` (uid 10001) and listens on port **4568** inside the container whatever `OAUTH_ISSUER` says; a `HEALTHCHECK` calls `/health`; migrations run at every start, as without Docker.

### Run it

```bash
docker run -d --name mcp-gate --restart unless-stopped \
  -p 4568:4568 \
  -e OAUTH_ISSUER=http://localhost:4568 \
  -v mcp-gate-data:/app/data \
  -v mcp-gate-secrets:/app/secrets \
  tonyhuang1101/mcp-gate:1.4.0
docker logs mcp-gate | grep "Setup token"
```

Or with Compose, using `docker-compose.yml` from the repository (it runs `tonyhuang1101/mcp-gate:latest`; `MCP_GATE_VERSION=1.4.0` in `.env` pins a release):

```bash
cp .env.example .env      # OAUTH_ISSUER, optionally ADMIN_EMAIL / ADMIN_PASSWORD
docker compose up -d
```

To run your own build instead, uncomment `build: .` in `docker-compose.yml`, set `MCP_GATE_IMAGE=mcp-gate:local` and run `docker compose up -d --build`. Every setting is an environment variable, as in [section 2](#2-configure-mcp-gate): put them in `.env` (Compose reads it) or pass them with `-e`. Never put secrets in `docker-compose.yml`.

### OAUTH_ISSUER

`OAUTH_ISSUER` is the address clients and MCP servers use to reach MCP Gate, **outside** the container: the published port (`http://localhost:4568`, or `http://<host address>:4568` for other machines) or the reverse proxy's `https://` URL. It is written into every token, so it must match how they reach it, and changing it later invalidates every issued token. The container's own port stays 4568 (`SERVER_PORT` is set in the image): publish it on whatever host port you like. Compose defaults the issuer to `http://localhost:${MCP_GATE_PORT:-4568}`.

Resource servers in the same Compose project may fetch the JWKS through the service name (`http://mcp-gate:4568/.well-known/jwks.json`); list that name in `ALLOWED_HOSTS=mcp-gate`. They still check `iss` against `OAUTH_ISSUER`.

### Volumes

| Path in the container | Compose volume | Holds |
|---|---|---|
| `/app/data` | `mcp-gate-data` | the SQLite database (`mcp_gate.db`, with its `-wal` / `-shm` files) |
| `/app/secrets` | `mcp-gate-secrets` | `secrets.json`: `ENCRYPTION_KEY`, `SESSION_SECRET_KEY`, the setup token (mode `0700` / `0600`) |

They are separate on purpose: the database holds the signing private keys encrypted with `ENCRYPTION_KEY`, so a copy of the data volume alone does not expose them. Never mount the secrets inside the data volume. An install that kept `secrets.json` in `data/` (before 1.4) can be moved in as it is: on first start the file is moved to `/app/secrets` across the two volumes and the move is logged.

Configuration: the five files of `config/` are in the image. To change them, copy `config/` from the repository, edit it, mount it and point `MCP_GATE_CONFIG_DIR` at it (the directory must hold all five files):

```yaml
    volumes:
      - ./config:/config:ro
    environment:
      MCP_GATE_CONFIG_DIR: /config
```

Logs go to the console only (`docker logs`, `docker compose logs`): the image sets `LOG_DIR` empty, which turns the daily files off. `LOG_FORMAT=json` writes one JSON object per line for a log collector. For the files as well, set `LOG_DIR=/app/logs` and mount a volume there.

### Back up

Back up both volumes, and keep the secrets apart from the database (another medium, or encrypted): you need both to restore, and losing `secrets.json` makes the stored private keys unreadable, which invalidates every token. A container started on the data volume without its secrets volume (or with another install's) exits with `The encryption key does not match the database` rather than generating a new key and failing every token request: restore the secrets volume as below, or pass the old key as `ENCRYPTION_KEY` (see [Troubleshooting](troubleshooting.md#server)). With Compose (`docker run` users replace `docker compose exec -T mcp-gate` with `docker exec -i mcp-gate`):

```bash
umask 077
# SQLite: an online backup, consistent while MCP Gate runs
docker compose exec -T mcp-gate python -c "import sqlite3; d = sqlite3.connect('/tmp/backup.db'); sqlite3.connect('data/mcp_gate.db').backup(d); d.close()"
docker compose exec -T mcp-gate cat /tmp/backup.db > mcp_gate.db
docker compose exec -T mcp-gate rm /tmp/backup.db
# The secrets, to be stored somewhere else
docker compose exec -T mcp-gate cat /app/secrets/secrets.json > secrets.json
```

With PostgreSQL: `docker compose exec -T postgres pg_dump -U mcpgate mcp_gate > mcp_gate.sql`, plus `secrets.json` as above.

To restore into fresh volumes, write the files as the image's user before the first start:

```bash
docker compose run --rm -T --no-deps --entrypoint sh mcp-gate -c 'umask 077; cat > /app/data/mcp_gate.db' < mcp_gate.db
docker compose run --rm -T --no-deps --entrypoint sh mcp-gate -c 'umask 077; cat > /app/secrets/secrets.json' < secrets.json
docker compose up -d
```

### Upgrade

Back up first. Then pull the new image and recreate the container; the volumes stay, and migrations run on start:

```bash
docker compose pull && docker compose up -d      # or: docker pull tonyhuang1101/mcp-gate:<version>, then rm and run again
```

Migrations change the database, so going back to an older image needs the backup taken before the upgrade. Read the [changelog](../CHANGELOG.md) for anything a release asks you to do.

### Behind a reverse proxy

Publish the port on loopback only (`127.0.0.1:4568:4568`), set `OAUTH_ISSUER` to the public `https://` URL and `SECURE_COOKIE=true`, and point the proxy at `127.0.0.1:4568` as in [section 3](#3-reverse-proxy). The proxy's requests reach the container from the Docker network's gateway (for example `172.17.0.1`, or the Compose network's gateway: `docker network inspect <project>_default`), not from `127.0.0.1`: add that address to `security.trusted_proxies` in your mounted `config/security.yaml` so the audit log records the real client address. A proxy running in the same Compose project reaches `http://mcp-gate:4568` directly; list its container address the same way.

### Limits

- Run **one** container per database: the rate limiter and the scheduler live in the process (see [section 4](#4-run-as-a-service)).
- The Marketplace and bring-your-own servers are not supported in the container yet: managed servers are reached on `127.0.0.1` of MCP Gate's host. Run MCP Gate without Docker if you need them.

