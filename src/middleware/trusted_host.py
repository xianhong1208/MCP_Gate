"""Refuse requests addressed to a host name MCP Gate does not answer to (DNS rebinding).

A web page on ``http://evil.example:4568`` can have its DNS name re-pointed at ``127.0.0.1`` after it loaded. For the
browser it is then a same-origin page that talks to whatever listens on that port of the victim's machine: it reads
every response and may send any header. Origin checks do not help (the Origin *is* ``http://evil.example:4568``,
which is also the request's own Host), cookies are not involved (they belong to ``localhost``), but the
unauthenticated surface is enough: first-time setup on a fresh install, dynamic client registration, discovery.

What the browser cannot change is the ``Host`` header: it is the name it resolved. So a request is served only when
its Host is

* the ``OAUTH_ISSUER`` host,
* ``localhost`` or a ``*.localhost`` name (browsers resolve those to loopback themselves, never via DNS),
* an IP literal (an attacker cannot rebind an address, only a name), or
* listed in ``security.allowed_hosts`` / ``ALLOWED_HOSTS`` (exact names, ``*.suffix`` wildcards, or ``*`` to turn
  the check off), e.g. the service name other containers use to reach MCP Gate.

Behind a trusted reverse proxy the ``X-Forwarded-Host`` must pass too, but it never replaces the raw ``Host``: a
rebound page may set ``X-Forwarded-Host`` itself, and when the browser runs on the same machine its address is
``127.0.0.1``, which is a trusted proxy by default. A request without a Host header did not come from a browser and
is let through. ``/health`` is always served (monitoring often uses internal names).

Refusals are 421 Misdirected Request (WebSocket: close 1008), logged once per host name.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from typing import Iterable, Optional
from urllib.parse import urlsplit

from src.logging import get_logger
from src.utils.client_ip import is_ip_in_whitelist

from .origin_check import header

logger = get_logger("middleware.trusted_host")

ERROR_CODE = "http.host_not_allowed"
ALWAYS_SERVED = ("/health",)
_MAX_LOGGED = 50
_logged: set[str] = set()
_logged_lock = threading.Lock()


def hostname_of(host_header: str) -> Optional[str]:
    """The lower-case host name (or IP literal, without brackets) of a Host header value; None if malformed."""
    value = (host_header or "").strip()
    if not value or any(c.isspace() for c in value) or "@" in value or "/" in value:
        return None
    try:
        parts = urlsplit(f"//{value}")
        hostname = parts.hostname
        parts.port  # noqa: B018 -- raises ValueError on a malformed port
    except ValueError:
        return None
    return hostname.rstrip(".").lower() if hostname else None


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _name_allowed(hostname: Optional[str], *, issuer_host: Optional[str], allowed_hosts: Iterable[str]) -> bool:
    if not hostname:
        return False
    if _is_ip(hostname) or hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    if issuer_host and hostname == issuer_host:
        return True
    for entry in allowed_hosts:
        entry = (entry or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if entry == "*":
            return True
        if entry.startswith("*.") and hostname.endswith(entry[1:]) and hostname != entry[2:]:
            return True
        if hostname == entry:
            return True
    return False


def host_allowed(scope: dict, *, issuer: str, allowed_hosts: Iterable[str], trusted_proxies: Iterable[str]) -> bool:
    allowed_hosts = list(allowed_hosts or ())
    issuer_host = (urlsplit(issuer).hostname or "").lower() or None
    raw = header(scope, "host")
    if raw is None:
        return True
    if not _name_allowed(hostname_of(raw), issuer_host=issuer_host, allowed_hosts=allowed_hosts):
        return False
    client = scope.get("client")
    peer = client[0] if client else ""
    forwarded = header(scope, "x-forwarded-host")
    if forwarded and peer and is_ip_in_whitelist(peer, list(trusted_proxies or ())):
        # The proxy we talk to appends its value last (the leftmost may come from the client)
        return _name_allowed(hostname_of(forwarded.split(",")[-1]), issuer_host=issuer_host,
                             allowed_hosts=allowed_hosts)
    return True


def _log_once(raw_host: str) -> None:
    with _logged_lock:
        if raw_host in _logged or len(_logged) >= _MAX_LOGGED:
            return
        _logged.add(raw_host)
    logger.warning(
        f"Refused a request for Host {raw_host[:100]!r}: not the OAUTH_ISSUER host, localhost or an IP address. "
        "If MCP Gate is meant to answer to that name (a reverse proxy that rewrites Host, a container service name), "
        "add it to ALLOWED_HOSTS (security.allowed_hosts)."
    )


class TrustedHostMiddleware:
    """ASGI middleware: 421 for HTTP requests (1008 for WebSockets) addressed to a host name we do not serve."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket") or scope["path"] in ALWAYS_SERVED:
            await self.app(scope, receive, send)
            return
        from src.config import Config

        if host_allowed(scope, issuer=Config.get_oauth_config().issuer,
                        allowed_hosts=Config.get_security_config().allowed_hosts,
                        trusted_proxies=Config.get_security_config().trusted_proxies):
            await self.app(scope, receive, send)
            return
        _log_once(header(scope, "host") or "")
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008, "reason": "Host not allowed"})
            return
        body = json.dumps({"error": ERROR_CODE, "message": "This server does not answer to that host name"}).encode()
        await send({"type": "http.response.start", "status": 421, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        ]})
        await send({"type": "http.response.body", "body": body})
