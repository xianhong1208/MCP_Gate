"""Decide whether a browser request's ``Origin`` belongs to the console.

Cookie-authenticated endpoints that a browser can reach cross-site without a CORS preflight (WebSocket
handshakes, body-less POSTs) need their own origin check: the browser attaches the session cookie no
matter which page started the request, and ``SameSite=Lax`` does not separate same-site pages (another
port on the same host, a sibling subdomain).

An origin is trusted when it is

* the origin the request itself was sent to (``Origin`` equals the request's own scheme + host, as seen
  from outside a trusted reverse proxy) -- this is what a page served by MCP Gate always sends, whichever
  host name the operator typed: ``localhost`` and ``127.0.0.1`` are different origins, and someone who
  browses the console through the "other" one must not be locked out (the issuer mismatch is reported by
  ``issuer_check`` instead);
* the ``OAUTH_ISSUER`` origin; or
* listed in ``cors.allowed_origins`` (``CORS_ALLOWED_ORIGINS``; empty by default).

A request without an ``Origin`` header did not come from a browser page (browsers always send one on
WebSocket handshakes and cross-origin POSTs), so it cannot be a cross-site forgery; whether to accept it is
the caller's call, see ``request_origin_allowed``. The literal ``null`` origin (sandboxed iframes,
``file://``, some redirects) is never trusted.
"""

from __future__ import annotations

from typing import Iterable, Optional
from urllib.parse import urlsplit

from .issuer_check import external_base_url, issuer_base_url, normalize_base_url


def header(scope: dict, name: str) -> Optional[str]:
    """First value of a request header from an ASGI scope (``name`` in lower case)."""
    key = name.encode("latin-1")
    for k, v in scope.get("headers", []):
        if k.lower() == key:
            return v.decode("latin-1")
    return None


def normalize_origin(origin: str) -> Optional[str]:
    """``scheme://host[:port]`` in the same normal form as ``normalize_base_url``; None if it is not an origin."""
    try:
        parts = urlsplit(origin.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.path or parts.query \
            or parts.fragment or "@" in parts.netloc:
        return None
    return normalize_base_url(parts.scheme, parts.netloc)


def is_trusted_origin(origin: str, scope: dict, *, issuer: str, allowed_origins: Iterable[str] = (),
                      trusted_proxies: Iterable[str] = ()) -> bool:
    """True when ``origin`` is the request's own origin, the issuer's, or explicitly allowed."""
    candidate = normalize_origin(origin)
    if candidate is None:
        return False
    if candidate == external_base_url(scope, trusted_proxies):
        return True
    if issuer and candidate == issuer_base_url(issuer):
        return True
    return any(candidate == normalize_origin(o) for o in allowed_origins if o and o != "*")


def request_origin_allowed(scope: dict, *, allow_missing: bool = True) -> bool:
    """Check the ``Origin`` of an ASGI request against the running configuration.

    ``allow_missing`` decides what happens when there is no ``Origin`` header (a non-browser client).
    """
    from src.config import Config

    origin = header(scope, "origin")
    if origin is None:
        return allow_missing
    return is_trusted_origin(
        origin, scope,
        issuer=Config.get_oauth_config().issuer,
        allowed_origins=Config.get_cors_config().allowed_origins,
        trusted_proxies=Config.get_security_config().trusted_proxies,
    )
