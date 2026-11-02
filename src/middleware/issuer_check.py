"""Warn when the public OAuth surface is reached through a host that differs from OAUTH_ISSUER.

The issuer is the server's identity: it is written into every token's ``iss`` claim and into the
discovery document, and clients build every endpoint URL from it. When a request arrives through
another host (a reverse proxy that was not configured, a LAN IP instead of the domain,
``localhost`` versus ``127.0.0.1``), tokens verify against the wrong issuer and discovery hands out
URLs that do not resolve. The symptom shows up later and elsewhere, so this middleware names the
problem at the moment it happens: one warning per distinct observed base URL, never per request.

Forwarded headers (``X-Forwarded-Proto`` / ``X-Forwarded-Host``) are honoured only when the direct
peer is a trusted proxy, exactly like the rate limiter treats ``X-Forwarded-For``; anyone else could
otherwise silence or fake the warning. When a header carries a comma-separated list, the rightmost
value is used: it is the one written by the trusted proxy we are talking to, whereas the leftmost
one may have come from the client.

The Host header is client-controlled, so the registry is hardened against being fed garbage (H-10): only
syntactically valid ``http(s)://host[:port]`` values are recorded, at most ``MAX_OBSERVED`` of them (least
recently seen evicted first, entries from internet peers before those from local or proxied peers), each
expiring ``TTL_SECONDS`` after it was last seen. The "set OAUTH_ISSUER to ..." advice is given only for hosts
reached from a loopback / private address or a trusted proxy (``plausible``); a host named by an internet
client is reported neutrally, and those warnings are rate limited.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional
from urllib.parse import urlsplit

from loguru import logger

from src.utils.client_ip import is_ip_in_whitelist

from .public_cors import is_public_oauth_path

_DEFAULT_PORTS = {"http": 80, "https": 443}

MAX_OBSERVED = 20
TTL_SECONDS = 24 * 3600
MAX_UNTRUSTED_WARNINGS_PER_WINDOW = 20
_WARNING_WINDOW_SECONDS = 3600
_MAX_HOST_LEN = 253
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

# Address ranges a LAN client or a reverse proxy sits in. Spelled out rather than ip.is_private, which also
# covers documentation and other reserved ranges.
_LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
))

_lock = threading.Lock()
_observed: Dict[str, dict] = {}
_warn_window = {"start": 0.0, "count": 0, "suppressed": False}


def _now_real() -> float:
    return time.monotonic()


_now = _now_real  # patched by tests


def _valid_host(hostport: str) -> bool:
    """``host[:port]`` where host is a DNS name, an IPv4 address or a bracketed IPv6 literal."""
    if not hostport or len(hostport) > _MAX_HOST_LEN + 7:
        return False
    if hostport.startswith("["):
        literal, _, rest = hostport[1:].partition("]")
        if rest and not (rest.startswith(":") and _valid_port(rest[1:])):
            return False
        try:
            return ipaddress.ip_address(literal).version == 6
        except ValueError:
            return False
    host, sep, port = hostport.rpartition(":")
    if not sep:
        host = hostport
    elif not _valid_port(port):
        return False
    if not host or len(host) > _MAX_HOST_LEN:
        return False
    labels = host.rstrip(".").split(".")
    return all(_LABEL.match(label) for label in labels)


def _valid_port(port: str) -> bool:
    return port.isdigit() and 1 <= int(port) <= 65535


def is_recordable(base_url: str) -> bool:
    """A normalised base URL that could be a real address of this server."""
    scheme, sep, hostport = base_url.partition("://")
    return bool(sep) and scheme in ("http", "https") and _valid_host(hostport)


def _peer_is_local_or_proxy(peer: str, trusted_proxies: Iterable[str]) -> bool:
    """Loopback / private / link-local peers and trusted proxies: a mismatch seen from them is most likely a
    real misconfiguration (LAN address, unconfigured reverse proxy), not a forged Host header."""
    if not peer:
        return False
    if is_ip_in_whitelist(peer, list(trusted_proxies or ())):
        return True
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_link_local or any(ip in net for net in _LOCAL_NETWORKS if net.version == ip.version)


def _expire(now: float) -> None:
    for key in [k for k, v in _observed.items() if now - v["_seen_at"] > TTL_SECONDS]:
        del _observed[key]


def _evict_one() -> None:
    # Hosts named by internet clients go first, then the least recently seen.
    victim = min(_observed.values(), key=lambda v: (v["plausible"], v["_seen_at"]))
    del _observed[victim["base_url"]]


def _allow_untrusted_warning(now: float) -> Optional[bool]:
    """True: log it. None: log the one-off "suppressing" notice instead. False: stay quiet."""
    with _lock:
        if now - _warn_window["start"] > _WARNING_WINDOW_SECONDS:
            _warn_window.update(start=now, count=0, suppressed=False)
        if _warn_window["count"] < MAX_UNTRUSTED_WARNINGS_PER_WINDOW:
            _warn_window["count"] += 1
            return True
        if not _warn_window["suppressed"]:
            _warn_window["suppressed"] = True
            return None
        return False


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
    # A WebSocket scope carries ws / wss; its origin is the http(s) page that opened it.
    scheme = {"ws": "http", "wss": "https"}.get(scope.get("scheme", "http"), scope.get("scheme", "http"))
    host = headers.get("host", "")
    client = scope.get("client")
    peer = client[0] if client else ""
    if peer and is_ip_in_whitelist(peer, list(trusted_proxies)):
        forwarded_proto = headers.get("x-forwarded-proto")
        forwarded_host = headers.get("x-forwarded-host")
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[-1].strip()
        if forwarded_host:
            host = forwarded_host.split(",")[-1].strip()
    return normalize_base_url(scheme, host)


def observed_mismatches() -> list[dict]:
    """Distinct base URLs that reached the OAuth surface while differing from the issuer, oldest first
    (at most MAX_OBSERVED, none older than TTL_SECONDS since last seen)."""
    with _lock:
        _expire(_now())
        return [{k: v for k, v in e.items() if not k.startswith("_")}
                for e in sorted(_observed.values(), key=lambda v: (v["first_seen"], v["_seen_at"]))]


def reset_observed() -> None:
    with _lock:
        _observed.clear()
        _warn_window.update(start=0.0, count=0, suppressed=False)


def record_mismatch(observed: str, issuer: str, path: str, *, peer: str = "",
                    trusted_proxies: Iterable[str] = ()) -> bool:
    """Remember an observed base URL; return True the first time it is seen (the caller logs then).
    Values that cannot be a real address are ignored (False)."""
    if not is_recordable(observed):
        return False
    plausible = _peer_is_local_or_proxy(peer, trusted_proxies)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    now = _now()
    with _lock:
        _expire(now)
        entry = _observed.get(observed)
        if entry is None:
            while len(_observed) >= MAX_OBSERVED:
                _evict_one()
            _observed[observed] = {"base_url": observed, "issuer": issuer, "first_seen": stamp, "last_seen": stamp,
                                   "count": 1, "first_path": path, "plausible": plausible, "_seen_at": now}
            return True
        entry["last_seen"] = stamp
        entry["_seen_at"] = now
        entry["count"] += 1
        entry["plausible"] = entry["plausible"] or plausible
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
            client = scope.get("client")
            peer = client[0] if client else ""
            if observed != self.issuer_base and record_mismatch(
                    observed, self.issuer, scope["path"], peer=peer, trusted_proxies=self.trusted_proxies):
                self._warn(observed, peer, scope["path"])
        await self.app(scope, receive, send)

    def _warn(self, observed: str, peer: str, path: str) -> None:
        if _peer_is_local_or_proxy(peer, self.trusted_proxies):
            logger.warning(
                "OAuth request to {path} arrived via {observed} but OAUTH_ISSUER is {issuer}. Tokens carry "
                "iss={issuer} and discovery advertises {issuer}/..., so clients using {observed} will fail "
                "verification or reach the wrong endpoints. Either set OAUTH_ISSUER to {observed}, or reach "
                "the server through the issuer host (and list the proxy in security.trusted_proxies so "
                "X-Forwarded-Proto/Host are honoured).",
                path=path, observed=observed, issuer=self.issuer,
            )
            return
        allowed = _allow_untrusted_warning(_now())
        if allowed:
            logger.warning(
                "OAuth request to {path} from {peer} named host {observed}, which is not OAUTH_ISSUER ({issuer}). "
                "The Host header is chosen by the client; if your clients do not use this address, ignore it. "
                "If they do, see docs/troubleshooting.md (issuer mismatch).",
                path=path, peer=peer or "?", observed=observed, issuer=self.issuer,
            )
        elif allowed is None:
            logger.warning("Further issuer-mismatch warnings for hosts named by internet clients are suppressed "
                           "for the next hour.")
