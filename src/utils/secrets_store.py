"""Local secrets store: environment variables take precedence; otherwise generate and persist to data/secrets.json.

A personal project should "clone and run", so SESSION_SECRET_KEY / ENCRYPTION_KEY are no longer required to be
set by hand. On first start they are generated and written to data/secrets.json (mode 0600), and every later start
reads that same file -- this matters most for ENCRYPTION_KEY: once it changes, nothing encrypted in the DB can be
decrypted.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Dict, Optional

_DEFAULT_PATH = Path("data") / "secrets.json"
_cache: Dict[str, str] = {}


def _store_path() -> Path:
    override = os.environ.get("MCP_CENTER_SECRETS_FILE")
    return Path(override) if override else _DEFAULT_PATH


def _load_file() -> Dict[str, str]:
    path = _store_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_file(data: Dict[str, str]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def get_secret(name: str, *, env_var: Optional[str] = None, length: int = 32) -> str:
    """Get a secret: env -> cache -> data/secrets.json -> generate and persist."""
    env_name = env_var or name
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    if name in _cache:
        return _cache[name]
    data = _load_file()
    if data.get(name):
        _cache[name] = data[name]
        return data[name]
    generated = secrets.token_urlsafe(length)
    data[name] = generated
    _save_file(data)
    _cache[name] = generated
    return generated


def reset_cache() -> None:
    _cache.clear()
