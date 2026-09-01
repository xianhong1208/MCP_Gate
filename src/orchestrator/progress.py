"""Progress registry for long-running operations (in-process, thread-safe)

Deploy / start / stop / load image all take tens of seconds to minutes, and the HTTP response
only returns once the whole thing is done. If the frontend only shows a spinner, the user cannot
tell "still downloading packages" from "already stuck".

Design:
  - Operators (orchestrator / routes) call stage(key, name) at each stage and end(key) when done.
  - Readers (GET /auth/managed/progress) take snapshot(); the frontend polls and turns stages into text.
  - Key convention: process:<process_id> (start/stop/deploy), catalog:<catalog_id> (load image).
  - Pure in-memory: MCP Center is a single process (Nuitka onefile), no cross-node needs;
    progress naturally disappears on restart, and the actual container state is aligned via
    the DB, so there is no consistency problem.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional


class ProgressRegistry:
    """Thread-safe progress table. Every method may be called from any thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, dict] = {}

    def begin(self, key: str, kind: str, stage: str = "queued") -> None:
        now = time.time()
        with self._lock:
            self._items[key] = {
                "key": key,
                "kind": kind,
                "stage": stage,
                "detail": None,
                "started_at": now,
                "updated_at": now,
            }

    def stage(self, key: str, stage: str, detail: Optional[str] = None) -> None:
        """Update the stage. If the key has not been begun yet, treat it as begin (kind is
        inferred from the key prefix) so the orchestrator need not know who called it."""
        now = time.time()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                kind = key.split(":", 1)[0] if ":" in key else "unknown"
                item = {"key": key, "kind": kind, "started_at": now}
                self._items[key] = item
            item["stage"] = stage
            item["detail"] = detail
            item["updated_at"] = now

    def end(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            item = self._items.get(key)
            return dict(item) if item else None

    def snapshot(self) -> List[dict]:
        with self._lock:
            return sorted((dict(v) for v in self._items.values()), key=lambda i: i["started_at"])

    @contextmanager
    def track(self, key: str, kind: str, stage: str = "queued") -> Iterator[None]:
        """with block: begin on enter, always end on exit (including exceptions) -- a failed
        operation never leaves zombie progress behind."""
        self.begin(key, kind, stage)
        try:
            yield
        finally:
            self.end(key)


_registry = ProgressRegistry()


def get_progress_registry() -> ProgressRegistry:
    return _registry


def process_key(process_id: str) -> str:
    return f"process:{process_id}"


def catalog_key(catalog_id: str) -> str:
    return f"catalog:{catalog_id}"
