# MCP Gate — the authorization server and its console in one image.
#
# Published as docker.io/tonyhuang1101/mcp-gate (amd64 + arm64) by .github/workflows/publish-image.yml.
#   docker compose up -d                  # see docker-compose.yml and docs/deploy.md
#   docker build -t mcp-gate:local .      # build it from this checkout
#
# Two volumes, kept apart on purpose (#29):
#   /app/data     the SQLite database (and nothing else you need to keep)
#   /app/secrets  secrets.json: ENCRYPTION_KEY, which decrypts the signing keys stored in the database
# Back them up separately. config/ is baked in; mount your own directory and point MCP_GATE_CONFIG_DIR at it to
# change it. Logs go to the console only (`docker logs`). Migrations run on every start.
#
# The console (static/web) is committed and checked against a fresh build in CI, so no Node stage is needed here.

# ---- Dependencies (uv, locked) --------------------------------------------------
FROM ghcr.io/astral-sh/uv:0.9.24 AS uv

FROM python:3.13-slim-trixie AS deps
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
# The application itself is not installed: main.py runs from /app. The postgres extra is included so DATABASE_URL
# can point at PostgreSQL without a custom image.
RUN uv sync --locked --no-dev --extra postgres --no-install-project --no-cache

# ---- Runtime ----------------------------------------------------------------------
FROM python:3.13-slim-trixie

# Set by the publish workflow; the version MCP Gate reports is read from pyproject.toml either way
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="MCP Gate" \
      org.opencontainers.image.description="OAuth 2.1 authorization server and control plane for MCP servers" \
      org.opencontainers.image.source="https://github.com/xianhong1208/MCP_Gate" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

RUN useradd --uid 10001 --user-group --create-home --home-dir /home/mcpgate --shell /usr/sbin/nologin mcpgate \
 && mkdir -p /app/data /app/secrets \
 && chown mcpgate:mcpgate /app/data /app/secrets \
 && chmod 0700 /app/secrets

WORKDIR /app
COPY --from=deps /app/.venv /app/.venv
COPY pyproject.toml main.py ./
COPY alembic/ alembic/
COPY catalog/ catalog/
COPY config/ config/
COPY db/ db/
COPY src/ src/
COPY static/web/ static/web/

# SERVER_PORT: inside the container MCP Gate always listens on 4568. OAUTH_ISSUER is the address clients use
# outside it (a published port or a reverse proxy), so its port must not decide the bind port.
# LOG_DIR empty: console only, `docker logs` has everything. Set LOG_DIR=/app/logs and mount a volume there for files.
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=4568 \
    LOG_DIR="" \
    MCP_GATE_SECRETS_DIR=/app/secrets

USER mcpgate
VOLUME ["/app/data", "/app/secrets"]
EXPOSE 4568
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % (os.environ.get('SERVER_PORT') or '4568'), timeout=4)"]

CMD ["python", "main.py"]
