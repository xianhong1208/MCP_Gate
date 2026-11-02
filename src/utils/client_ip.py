"""Client IP resolution behind (optional) trusted reverse proxies.

Everything that records or acts on "who sent this request" -- the audit log, request logging, OAuth
token events, the rate limiter -- resolves the address through :func:`resolve_client_ip`, so they all
agree and none of them can be fooled by a forged header.

The rules:

* ``X-Forwarded-For`` / ``X-Real-IP`` are only read when the direct TCP peer is listed in
  ``security.trusted_proxies``. From anyone else the headers are attacker-controlled and ignored.
* ``X-Forwarded-For`` is walked **right to left**: each proxy appends the address it received the
  request from, so the rightmost entries were written by our own proxies and the leftmost by whoever
  sent the first hop (possibly the client lying). Trusted proxies are skipped; the first address
  that is not a trusted proxy is the client. If every entry is a trusted proxy, the leftmost wins.
* A malformed entry stops the walk: the hop that handed it over is the last address we can vouch
  for, so that hop is returned instead of the garbage.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Iterable, List, Optional, Union

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _parse_ip(value: str) -> Optional[_IPAddress]:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def is_ip_in_whitelist(client_ip: str, whitelist: Iterable[str]) -> bool:
    """Whether ``client_ip`` matches an entry of ``whitelist`` (single IPs or CIDR ranges; the literal
    string ``localhost`` only matches itself)."""
    whitelist = list(whitelist or ())
    if client_ip in whitelist:
        return True

    ip = _parse_ip(client_ip) if client_ip else None
    if ip is None:
        return False
    for entry in whitelist:
        if entry == "localhost":
            continue
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def resolve_client_ip_from(peer: Optional[str], get_header: Callable[[str], Optional[str]],
                           trusted_proxies: Iterable[str]) -> Optional[str]:
    """Core algorithm, independent of the request type. ``get_header`` looks up a header by its
    lower-case name. Returns ``peer`` (possibly ``None``) when forwarded headers are not trusted."""
    trusted: List[str] = list(trusted_proxies or ())
    if not peer or not is_ip_in_whitelist(peer, trusted):
        return peer

    forwarded = get_header("x-forwarded-for")
    if forwarded:
        hops = [h.strip() for h in forwarded.split(",")]
        last_trusted = peer
        for hop in reversed(hops):
            if _parse_ip(hop) is None:
                return last_trusted
            if not is_ip_in_whitelist(hop, trusted):
                return str(_parse_ip(hop))
            last_trusted = hop
        return last_trusted

    real_ip = get_header("x-real-ip")
    if real_ip:
        parsed = _parse_ip(real_ip)
        if parsed is not None:
            return str(parsed)
    return peer


def resolve_client_ip(request, trusted_proxies: Optional[Iterable[str]] = None) -> Optional[str]:
    """The client address of a Starlette/FastAPI ``Request`` (or anything with ``.client`` and
    ``.headers``). ``trusted_proxies`` defaults to ``security.trusted_proxies`` from the config."""
    if trusted_proxies is None:
        trusted_proxies = _configured_trusted_proxies()
    client = getattr(request, "client", None)
    peer = client.host if client else None
    headers = request.headers
    return resolve_client_ip_from(peer, headers.get, trusted_proxies)


def _configured_trusted_proxies() -> List[str]:
    from src.config import Config

    return list(Config.get_security_config().trusted_proxies)
