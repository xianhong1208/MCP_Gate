"""Refuse state-changing requests that a foreign page started (CSRF), by ``Origin`` / ``Referer``.

The console session is a cookie. ``SameSite=Lax`` keeps it off cross-*site* subrequests, but every port
of the same host, and every sibling subdomain, is the same site: a page on another localhost port gets the
cookie attached to its ``fetch``. Body-less POSTs (rotate keys, revoke a token, logout, start a server)
need no CORS preflight, and a form POST needs none either, so the cookie alone is not proof that the
console asked for the change.

Every ``POST`` / ``PUT`` / ``PATCH`` / ``DELETE`` therefore has to come from a trusted origin (see
``origin_check``): the request's own origin, the issuer's, or one listed in ``cors.allowed_origins``.

* ``Origin`` is checked when present (browsers send it on every non-GET ``fetch``, same-origin included).
* Otherwise ``Referer`` is checked, reduced to its origin.
* With neither header the request did not come from a web page (``curl``, a script), so it cannot be a
  forgery and is let through; it still needs a valid session to do anything.
* A request that carries no session cookie but an ``Authorization`` header is exempt: nothing ambient rides
  on it, and a browser cannot add that header cross-origin without a CORS preflight.

The OAuth protocol surface (``/oauth/*``, ``/.well-known/*``) is exempt: MCP clients call registration,
token, revocation and introspection from their own origins and authenticate with client credentials, not
the console cookie. The one exception is the consent decision, which *is* a cookie-authenticated click by
the owner and is checked like the console API.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from src.logging import get_logger

from .origin_check import header, is_trusted_origin

logger = get_logger("middleware.csrf")

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CONSENT_DECISION = re.compile(r"^/oauth/authorize/requests/[^/]+/decision/?$")
_EXEMPT_PREFIXES = ("/oauth/", "/.well-known/")
SESSION_COOKIE = "mcp_session"

ERROR_CODE = "auth.csrf_origin_denied"


def needs_origin_check(method: str, path: str) -> bool:
    if method.upper() not in UNSAFE_METHODS:
        return False
    if _CONSENT_DECISION.match(path):
        return True
    return not path.startswith(_EXEMPT_PREFIXES)


def _referer_origin(referer: str) -> str:
    """``scheme://netloc`` of a Referer, or "" when it is not an absolute http(s) URL."""
    try:
        parts = urlsplit(referer.strip())
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def _has_session_cookie(scope: dict) -> bool:
    cookie = header(scope, "cookie") or ""
    return any(part.strip().startswith(f"{SESSION_COOKIE}=") for part in cookie.split(";"))


def request_source_allowed(scope: dict) -> bool:
    """True when the request's Origin (or else Referer) is trusted, or the request is not from a web page."""
    from src.config import Config

    if not _has_session_cookie(scope) and header(scope, "authorization"):
        return True
    origin = header(scope, "origin")
    if origin is None:
        referer = header(scope, "referer")
        if referer is None:
            return True
        origin = _referer_origin(referer)
        if not origin:
            return False
    return is_trusted_origin(
        origin, scope,
        issuer=Config.get_oauth_config().issuer,
        allowed_origins=Config.get_cors_config().allowed_origins,
        trusted_proxies=Config.get_security_config().trusted_proxies,
    )


class CSRFOriginMiddleware:
    """ASGI middleware: 403 for a state-changing request whose Origin / Referer is not the console's."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and needs_origin_check(scope["method"], scope["path"]) \
                and not request_source_allowed(scope):
            logger.warning(
                f"Refused cross-site {scope['method']} {scope['path']} "
                f"(Origin={header(scope, 'origin')!r}, Referer={header(scope, 'referer')!r})"
            )
            body = json.dumps({"detail": {
                "error": ERROR_CODE, "params": {},
                "fallback": "Request refused: it did not come from the MCP Gate console (Origin check failed)",
            }}).encode()
            await send({"type": "http.response.start", "status": 403, "headers": [
                (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            ]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)
