#!/usr/bin/env python3
"""MCP Gate startup script.

OAuth 2.1 Authorization Server + MCP server admin console.

Usage:
    python main.py
    python main.py --config-dir config --port 4568
    python main.py --migrate-only status
"""

import argparse
import hashlib
import os
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

project_root = Path(os.path.abspath(sys.argv[0])).parent
load_dotenv(project_root / ".env")
sys.path.insert(0, str(project_root))

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, Response  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

from db import make_session, seed_database  # noqa: E402
from src.config import Config  # noqa: E402
from src.config.manager import default_config_dir  # noqa: E402
from src.discovery.websocket_manager import get_ws_manager  # noqa: E402
from src.exceptions.handlers import register_exception_handlers  # noqa: E402
from src.logging import RequestLoggingMiddleware, get_logger, setup_logging  # noqa: E402
from src.middleware import (  # noqa: E402
    CSRFOriginMiddleware, IssuerMismatchMiddleware, PublicOAuthCORSMiddleware, RateLimitConfig, RateLimitMiddleware,
    SecurityHeadersMiddleware, TrustedHostMiddleware,
)
from src.scheduler import get_scheduler  # noqa: E402
from src.utils.db_url import mask_db_url, redact_url_credentials  # noqa: E402
from src.version import __build_commit__, __build_time__, __version__  # noqa: E402

logger = get_logger("main")

STATIC_DIR = project_root / "static" / "web"

# API prefixes the SPA catch-all must not swallow
API_PREFIXES = ("api/", "oauth/", ".well-known/", "ws/", "health", "docs", "redoc", "openapi.json")


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = get_scheduler()
    scheduler.configure(**Config.get_scheduler_config().model_dump())
    scheduler.set_ws_manager(get_ws_manager())
    scheduler.start()

    try:
        from src.marketplace.loader import get_catalog_loader
        loader = get_catalog_loader()
        entries = loader.load_all()
        logger.info(f"Marketplace catalog loaded: {len(entries)} entries")
        if loader.errors:
            logger.warning(f"Marketplace catalog skipped {len(loader.errors)} invalid file(s): {', '.join(loader.errors)}")
    except Exception as e:
        logger.warning(f"Marketplace catalog preload skipped: {e}")

    # Off the startup path: reconcile restarts every dead managed server one after another (a stdio cold start can
    # take up to 300 s each), and the authorization server must answer from the first second.
    reconcile = start_managed_reconcile()

    yield
    scheduler.stop()
    reconcile.join(timeout=RECONCILE_SHUTDOWN_WAIT_SECONDS)


RECONCILE_SHUTDOWN_WAIT_SECONDS = 2


def reconcile_managed_servers() -> None:
    """Align managed servers with their desired state (src/orchestrator/manager.py reconcile). Never raises."""
    try:
        from src.orchestrator.manager import get_orchestrator
        db = make_session()
        try:
            get_orchestrator().reconcile(db)
        finally:
            db.close()
        logger.info("Managed MCP reconcile finished")
    except Exception as e:
        logger.warning(f"Managed MCP reconcile skipped: {e}")


def start_managed_reconcile() -> threading.Thread:
    """Run reconcile_managed_servers in a daemon thread (it blocks on the runtime and the database, so not on the
    event loop) and return the thread."""
    thread = threading.Thread(target=reconcile_managed_servers, name="managed-reconcile", daemon=True)
    thread.start()
    return thread


def create_app() -> FastAPI:
    enable_docs = os.environ.get("ENABLE_API_DOCS", "").lower() == "true"
    app = FastAPI(
        title="MCP Gate",
        description="OAuth 2.1 Authorization Server and control plane for MCP servers",
        version=__version__,
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
        lifespan=lifespan,
    )

    cors = Config.get_cors_config()
    app.add_middleware(
        CORSMiddleware, allow_origins=cors.allowed_origins, allow_methods=cors.allow_methods,
        allow_headers=cors.allow_headers, allow_credentials=cors.allow_credentials,
    )
    # Added after the console policy so it runs outside it: the OAuth protocol surface
    # (discovery, registration, token) is open to any origin, without credentials.
    app.add_middleware(PublicOAuthCORSMiddleware)
    # Cookie-authenticated state changes must come from the console's own origin (CSRF); see middleware/csrf.py
    app.add_middleware(CSRFOriginMiddleware)

    rl = Config.get_rate_limit_config()
    sec = Config.get_security_config()
    # Warn (once per host) when OAuth requests arrive through a host that is not OAUTH_ISSUER
    app.add_middleware(IssuerMismatchMiddleware, issuer=Config.get_oauth_config().issuer,
                       trusted_proxies=sec.trusted_proxies)
    # DNS rebinding: refuse foreign Host names before anything else looks at the request (outside the issuer check,
    # so a rebinding name is never recorded as an "issuer mismatch" or suggested as OAUTH_ISSUER)
    app.add_middleware(TrustedHostMiddleware)
    app.add_middleware(RateLimitMiddleware, config=RateLimitConfig(
        enabled=rl.enabled, requests_per_minute=rl.requests_per_minute, requests_per_hour=rl.requests_per_hour,
        whitelist=rl.whitelist, path_limits=rl.path_limits, trusted_proxies=sec.trusted_proxies,
    ))
    app.add_middleware(RequestLoggingMiddleware, exclude_paths=["/health", "/docs", "/redoc", "/openapi.json"])
    # Added last = outermost, so 429s from the rate limiter and CORS preflight answers get the headers too
    app.add_middleware(SecurityHeadersMiddleware)

    register_exception_handlers(app)

    from src.api import router
    from src.api.discovery_routes import router as discovery_router, ws_router as discovery_ws_router
    from src.api.managed_routes import router as managed_router
    from src.api.oauth_admin_routes import router as oauth_admin_router
    from src.api.oauth_routes import router as oauth_router
    from src.api.session_routes import router as session_router

    app.include_router(oauth_router)
    app.include_router(session_router)
    app.include_router(router)
    app.include_router(oauth_admin_router)
    app.include_router(discovery_router)
    app.include_router(discovery_ws_router)
    app.include_router(managed_router)

    if STATIC_DIR.exists():
        _mount_spa(app)

    return app


def _mount_spa(app: FastAPI) -> None:
    class HashedAssets(StaticFiles):
        def file_response(self, *args, **kwargs):
            resp = super().file_response(*args, **kwargs)
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp

    def _serve_index(request: Request):
        index_file = STATIC_DIR / "index.html"
        if not index_file.exists():
            return JSONResponse({"error": "Frontend not built. Run: cd frontend && npm run build"}, status_code=404)
        st = index_file.stat()
        etag = '"' + hashlib.md5(f"{st.st_mtime}-{st.st_size}".encode(), usedforsecurity=False).hexdigest() + '"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "no-cache"})
        return FileResponse(index_file, headers={"Cache-Control": "no-cache"})

    if (STATIC_DIR / "assets").is_dir():
        app.mount("/assets", HashedAssets(directory=STATIC_DIR / "assets"), name="web-assets")

    @app.get("/favicon.svg", include_in_schema=False)
    async def serve_favicon():
        favicon = STATIC_DIR / "favicon.svg"
        if favicon.exists():
            return FileResponse(favicon, media_type="image/svg+xml")
        return JSONResponse({"error": "Favicon not found"}, status_code=404)

    @app.get("/", include_in_schema=False)
    async def serve_root(request: Request):
        return _serve_index(request)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str, request: Request):
        if full_path.startswith(API_PREFIXES):
            return JSONResponse({"error": "Not found"}, status_code=404)
        return _serve_index(request)


def warn_if_multiple_workers(env=None) -> bool:
    """MCP Gate must run as a single process: the rate limiter counts in memory and APScheduler runs the purge
    and health-check jobs in-process. Warn when the environment asks for more workers. Returns True if warned."""
    env = os.environ if env is None else env
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS"):
        raw = (env.get(name) or "").strip()
        try:
            workers = int(raw)
        except ValueError:
            continue
        if workers > 1:
            logger.warning(
                f"{name}={workers}, but MCP Gate supports a single process only: the rate limiter keeps its counters "
                "in memory and the scheduler runs in-process, so extra workers would multiply the rate limit and run "
                "every scheduled job once per worker. Run one process."
            )
            return True
    return False


def parse_args():
    parser = argparse.ArgumentParser(description="MCP Gate")
    parser.add_argument("--config-dir", type=str, default=None,
                        help="Directory holding the five config files (default: $MCP_GATE_CONFIG_DIR or config)")
    parser.add_argument("--host", type=str)
    parser.add_argument("--port", type=int)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--no-migrate", action="store_true", help="Skip migrations (assumes the DB is already ready)")
    parser.add_argument("--migrate-only", nargs="?", const="auto", metavar="ACTION",
                        help="Run migrations only, without starting the server: auto, status, upgrade, downgrade, stamp, current, heads, history, generate")
    parser.add_argument("-m", "--message", help="Migration message (used with --migrate-only generate)")
    parser.add_argument("-r", "--revision", default="-1")
    return parser.parse_args()


def init_database(*, run_migrations: bool = True) -> dict:
    """bootstrap -> migrate -> seed. Returns the seed summary."""
    from src.utils.db_bootstrap import ensure_database_ready

    ensure_database_ready(Config.get_database_config().url, logger)
    if run_migrations:
        from db.migrate import run_migration_command
        if not run_migration_command("auto"):
            raise RuntimeError("Auto migration failed")

    identity = Config.get_identity_config()
    db = make_session()
    try:
        # Weak SESSION_SECRET_KEY / ENCRYPTION_KEY: warned always, refused only while the install is new (no
        # signing key yet, so nothing is encrypted with it); see src/utils/secret_policy.py
        from src.adapters import OAuthKeyAdapter
        from src.utils.secret_policy import check_startup_secrets
        check_startup_secrets(fresh_install=not OAuthKeyAdapter.list_all(db))
        summary = seed_database(db, bootstrap_email=identity.bootstrap_admin_email,
                                bootstrap_password=identity.bootstrap_admin_password)
        from src.oauth.signing_keys import ensure_active_signing_key
        key = ensure_active_signing_key(db)
        summary["signing_kid"] = key.kid
        warn_shared_audiences(db)
        return summary
    finally:
        db.close()



def warn_shared_audiences(db) -> None:
    """Log services that share one audience (possible before #21 refused it); the dashboard shows them too. They
    are left as they are: which service keeps the audience is the owner's call."""
    from src.adapters import ServiceAdapter
    for conflict in ServiceAdapter.audience_conflicts(db):
        names = ", ".join(f"'{s['name']}'" for s in conflict["services"])
        logger.warning(f"Services {names} share the OAuth audience {conflict['audience']}: the consent screen and "
                       "tokens resolve it to only one of them. Give each its own audience (Services → edit).")


def _print_banner(summary: dict, host: str, port: int) -> None:
    """Startup banner. The database URL is printed with its password masked (N1)."""
    config = Config.get_config_model()
    issuer = config.oauth.issuer
    logger.info("")
    logger.info("╔══════════════════════════════════════════════════════╗")
    logger.info("║   MCP Gate — OAuth 2.1 AS for your MCP servers     ║")
    logger.info("╚══════════════════════════════════════════════════════╝")
    logger.info(f"  Version:    {__version__} ({__build_commit__}, {__build_time__})")
    logger.info(f"  Address:    http://{host}:{port}")
    logger.info(f"  Issuer:     {issuer}")
    logger.info(f"  Database:   {mask_db_url(config.database.url)}")
    logger.info(f"  Metadata:   {issuer}/.well-known/oauth-authorization-server")
    logger.info(f"  JWKS:       {issuer}/.well-known/jwks.json  (kid={summary.get('signing_kid', '?')[:12]}…)")
    if summary.get("users", 0) == 0:
        from src.identity import setup_token
        # The issuer, not the bind port: in a container or behind a proxy the browser uses the published address
        logger.warning(f"  No admin account yet → open {issuer}/setup to create the owner")
        logger.warning(f"  Setup token: {setup_token.current()}  (also in {setup_token.location()} as "
                       f"{setup_token.NAME}; it stops working once the owner exists)")
    elif summary.get("owner_created"):
        logger.info("  Owner account created from ADMIN_EMAIL / ADMIN_PASSWORD")
    if os.environ.get("ENABLE_API_DOCS", "").lower() == "true":
        logger.info(f"  API Docs:   http://{host}:{port}/docs")
    logger.info("")

def main():
    args = parse_args()
    try:
        Config.set_config_dir(args.config_dir or default_config_dir())
        config = Config.get_config_model()
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    log_config = config.logging
    setup_logging(level=log_config.level, format_type=log_config.format, log_dir=log_config.log_dir,
                  rotation=log_config.rotation, rotation_max_size=log_config.rotation_max_size,
                  retention=log_config.retention, compression=log_config.compression)
    # Logged only now so they reach the log file too, not only the terminal
    for notice in Config.get_startup_notices():
        logger.error(notice)
    warn_if_multiple_workers()
    # Before anything reads a secret, and after logging is set up so the move lands in the log file (#29)
    from src.utils.secrets_store import migrate_legacy_store
    try:
        migrate_legacy_store()
    except OSError as e:
        logger.error(f"Could not move data/secrets.json into the secrets directory: {e}")
        sys.exit(1)

    if args.migrate_only:
        from db.migrate import run_migration_command
        from src.utils.db_bootstrap import ensure_database_ready
        ensure_database_ready(Config.get_database_config().url, logger)
        sys.exit(0 if run_migration_command(args.migrate_only, args.message, args.revision) else 1)

    from src.utils.secret_policy import WeakSecretError
    try:
        summary = init_database(run_migrations=not args.no_migrate)
    except WeakSecretError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to initialize database: {redact_url_credentials(str(e))}")
        sys.exit(1)

    app = create_app()
    host = args.host or config.server.host
    port = args.port or config.effective_port
    _print_banner(summary, host, port)

    if args.reload:
        uvicorn.run("main:create_app", host=host, port=port, reload=True, factory=True, log_config=None,
                    access_log=False)
    else:
        # log_config=None: uvicorn's loggers propagate to the loguru InterceptHandler installed by setup_logging.
        # access_log=False: RequestLoggingMiddleware already logs every request.
        uvicorn.run(app, host=host, port=port, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
