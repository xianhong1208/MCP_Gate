"""Warn when the public OAuth surface is reached through a host that differs from OAUTH_ISSUER.

The issuer is the server's identity: it is written into every token's ``iss`` claim and into the
discovery document, and clients build every endpoint URL from it. When a request arrives through
another host (a reverse proxy that was not configured, a LAN IP instead of the domain,
``localhost`` versus ``127.0.0.1``), tokens verify against the wrong issuer and discovery hands out
URLs that do not resolve. The symptom shows up later and elsewhere, so this middleware names the
problem at the moment it happens: one warning per distinct observed base URL, never per request.

Forwarded headers (``X-Forwarded-Proto`` / ``X-Forwarded-Host``) are honoured only when the direct
peer is a trusted proxy, exactly like the rate limiter treats ``X-Forwarded-For``; anyone else could
otherwise silence or fake the warning.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional
from urllib.parse import urlsplit

from loguru import logger

from .public_cors import is_public_oauth_path
from .rate_limiter import is_ip_in_whitelist

_DEFAULT_PORTS = {"http": 80, "https": 443}

_lock = threading.Lock()
_observed: Dict[str, dict] = {}


def normalize_base_url(scheme: str, host: str) -> str:
    """``scheme://host[:port]`` with default ports dropped and the host lower-cased, so
    ``https://example.com:443`` and ``HTTPS://Example.com`` compare equal."""
    scheme = (scheme or "http").lower()
    host = (host or "").strip().lower()
    if not host:
        return f"{scheme}://"
    hostname, sep, port = host.rpartition(":")
    # "host:port" (but not a bare IPv6 literal, whose last ":" is inside the address)
    if sep and port.isdigit() and (hostname.startswith("[") or ":" not in hostname):
        if int(port) == _DEFAULT_PORTS.get(scheme):
            host = hostname
    return f"{scheme}://{host}"


def issuer_base_url(issuer: str) -> str:
    parts = urlsplit(issuer)
    return normalize_base_url(parts.scheme, parts.netloc)


def external_base_url(scope: dict, trusted_proxies: Iterable[str]) -> str:
    """The base URL the client used, seen from outside a trusted reverse proxy."""
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    scheme = scope.get("scheme", "http")
    host = headers.get("host", "")
    client = scope.get("client")
    peer = client[0] if client else ""
    if peer and is_ip_in_whitelist(peer, list(trusted_proxies)):
        forwarded_proto = headers.get("x-forwarded-proto")
        forwarded_host = headers.get("x-forwarded-host")
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip()
        if forwarded_host:
            host = forwarded_host.split(",")[0].strip()
    return normalize_base_url(scheme, host)


def observed_mismatches() -> list[dict]:
    """Distinct base URLs that reached the OAuth surface while differing from the issuer, oldest first."""
    with _lock:
        return [dict(v) for v in sorted(_observed.values(), key=lambda v: v["first_seen"])]


def reset_observed() -> None:
    with _lock:
        _observed.clear()


def record_mismatch(observed: str, issuer: str, path: str) -> bool:
    """Remember an observed base URL; return True the first time it is seen (the caller logs then)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        entry = _observed.get(observed)
        if entry is None:
            _observed[observed] = {"base_url": observed, "issuer": issuer, "first_seen": now, "last_seen": now,
                                   "count": 1, "first_path": path}
            return True
        entry["last_seen"] = now
        entry["count"] += 1
        return False


class IssuerMismatchMiddleware:
    """ASGI middleware: compare the external base URL of public OAuth requests with OAUTH_ISSUER."""

    def __init__(self, app, *, issuer: str, trusted_proxies: Optional[Iterable[str]] = None):
        self.app = app
        self.issuer = issuer.rstrip("/")
        self.issuer_base = issuer_base_url(self.issuer)
        self.trusted_proxies = list(trusted_proxies or ())

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and is_public_oauth_path(scope["path"]):
            observed = external_base_url(scope, self.trusted_proxies)
            if observed != self.issuer_base and record_mismatch(observed, self.issuer, scope["path"]):
                logger.warning(
                    "OAuth request to {path} arrived via {observed} but OAUTH_ISSUER is {issuer}. Tokens carry "
                    "iss={issuer} and discovery advertises {issuer}/..., so clients using {observed} will fail "
                    "verification or reach the wrong endpoints. Either set OAUTH_ISSUER to {observed}, or reach "
                    "the server through the issuer host (and list the proxy in security.trusted_proxies so "
                    "X-Forwarded-Proto/Host are honoured).",
                    path=scope["path"], observed=observed, issuer=self.issuer,
                )
        await self.app(scope, receive, send)
