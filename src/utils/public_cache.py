"""In-process cache for the public discovery documents (JWKS, authorization server metadata).

Every MCP client and resource server polls these, unauthenticated, so they must not need the database on the
hot path (H-06: a burst of JWKS requests used to exhaust the connection pool and freeze the server). Both
documents change only when a signing key or a scope changes; the adapters that write those rows call
``invalidate()`` after committing. The TTL is only a safety net for writes that bypass the adapters (another
process, a manual SQL fix).

No imports from the rest of the app, so the adapter layer can depend on it without an import cycle.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

DEFAULT_TTL_SECONDS = 60.0

_lock = threading.Lock()
_entries: dict[str, tuple[int, float, Any]] = {}  # name -> (generation, expires_at (monotonic), value)
_generation = 0


def invalidate() -> None:
    """Drop every cached document (call after a signing key or scope write has committed)."""
    global _generation
    with _lock:
        _generation += 1
        _entries.clear()


def get_or_build(name: str, builder: Callable[[], Any], ttl: float = DEFAULT_TTL_SECONDS) -> Any:
    """Return the cached value for ``name`` or build it. The builder runs outside the lock (it may hit the DB),
    and its result is discarded if an invalidation happened meanwhile, so a stale build never sticks."""
    return get_or_build_expiring(name, lambda: (builder(), ttl))


def get_or_build_expiring(name: str, builder: Callable[[], tuple[Any, float]]) -> Any:
    """Like get_or_build, but the builder returns ``(value, ttl_seconds)``: the document decides how long it stays
    valid (e.g. the JWKS until the next retired key is due to leave it)."""
    now = time.monotonic()
    with _lock:
        hit = _entries.get(name)
        if hit is not None and hit[0] == _generation and now < hit[1]:
            return hit[2]
        generation = _generation
    value, ttl = builder()
    with _lock:
        if generation == _generation and ttl > 0:
            _entries[name] = (generation, time.monotonic() + ttl, value)
    return value
