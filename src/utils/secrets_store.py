"""Local secrets store: environment variables take precedence; otherwise generate and persist to secrets/secrets.json.

A personal project should "clone and run", so SESSION_SECRET_KEY / ENCRYPTION_KEY are no longer required to be
set by hand. On first start they are generated and written to secrets/secrets.json, and every later start reads
that same file -- this matters most for ENCRYPTION_KEY: once it changes, nothing encrypted in the DB can be
decrypted.

The file lives in its own directory, apart from data/ (#29): a copy of the data directory alone must not carry the
key that decrypts the signing keys and stored secrets in the database next to it. The directory is created with
mode 0700 and the file is written with mode 0600.

Where it is:
- ``MCP_GATE_SECRETS_FILE``: this exact file (nothing is moved into or out of it);
- otherwise ``MCP_GATE_SECRETS_DIR``/secrets.json, ``secrets/secrets.json`` by default.

Installs from before #29 kept the file at data/secrets.json. migrate_legacy_store() moves it into the secrets
directory once (never overwriting a file already there); it runs on the first read and explicitly at startup, after
logging is set up, so the move is logged to the log file too.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import secrets
import threading
from pathlib import Path
from contextlib import contextmanager
from typing import Callable, Dict, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - not on Linux
    fcntl = None

logger = logging.getLogger(__name__)

FILE_NAME = "secrets.json"
_DEFAULT_DIR = Path("secrets")
# Where installs before #29 kept it, next to the database
_LEGACY_PATH = Path("data") / FILE_NAME
DIR_MODE = 0o700
FILE_MODE = 0o600

_cache: Dict[str, str] = {}
_migration_lock = threading.Lock()
_migration_checked = False


def _explicit_file() -> Optional[Path]:
    override = os.environ.get("MCP_GATE_SECRETS_FILE", "").strip()
    return Path(override) if override else None


def secrets_dir() -> Path:
    """The directory that holds the generated secrets (MCP_GATE_SECRETS_DIR, default secrets/)."""
    explicit = _explicit_file()
    if explicit is not None:
        return explicit.parent
    configured = os.environ.get("MCP_GATE_SECRETS_DIR", "").strip()
    return Path(configured) if configured else _DEFAULT_DIR


def _store_path() -> Path:
    return _explicit_file() or secrets_dir() / FILE_NAME


def _ensure_dir() -> None:
    """Create the secrets directory with mode 0700. A directory MCP Gate owns (the default or
    MCP_GATE_SECRETS_DIR) is tightened to 0700 even when it already existed; the parent of an explicit
    MCP_GATE_SECRETS_FILE is someone else's choice and only created, never re-moded."""
    path = _store_path().parent
    path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    if _explicit_file() is None:
        try:
            os.chmod(path, DIR_MODE)
        except OSError:  # a read-only mount (a Docker secret, for example) keeps its own mode
            pass


def migrate_legacy_store() -> Optional[str]:
    """Move data/secrets.json into the secrets directory, once per process. Returns what was done (logged), or None.

    - Only without MCP_GATE_SECRETS_FILE: an explicit file is used where it is.
    - Raises if the file cannot be moved; startup then stops instead of generating a new key.
    - Never overwrites: if the new file already exists the old one is left alone and a warning says so.
    - The move is atomic where the two directories share a file system (a hard link, then the old name is
      removed); across file systems (data/ and secrets/ as separate Docker volumes) the content is written to a
      temporary file in the secrets directory and linked into place, so a crash leaves either the old file or
      both, never a half-written secrets file.
    """
    global _migration_checked
    with _migration_lock:
        if _migration_checked:
            return None
        # Marked done only when this returns: a move that raised is tried (and raises) again on the next read,
        # so a failed move can never fall through to generating a new ENCRYPTION_KEY
        message = _migrate_legacy_store()
        _migration_checked = True
        return message


def _migrate_legacy_store() -> Optional[str]:
    if _explicit_file() is not None or not _LEGACY_PATH.is_file():
        return None
    target = _store_path()
    try:
        if _LEGACY_PATH.resolve() == target.resolve():
            return None
    except OSError:
        pass
    if target.exists():
        message = (f"{_LEGACY_PATH} is no longer read: the secrets are kept in {target}. It was left in place "
                   f"because {target} already exists; delete it once you have checked it is not needed.")
        logger.warning(message)
        return message
    _ensure_dir()
    try:
        _link_into_place(_LEGACY_PATH, target)
    except FileExistsError:  # created between the check and the link: never overwrite it
        message = f"{target} appeared while moving {_LEGACY_PATH}; the old file was left in place."
        logger.warning(message)
        return message
    try:
        os.chmod(target, FILE_MODE)
    except OSError:
        pass
    _LEGACY_PATH.unlink()
    message = (f"Moved the generated secrets from {_LEGACY_PATH} to {target} (#29): back up "
               f"{target.parent}/ separately from data/.")
    logger.warning(message)
    return message


def _link_into_place(source: Path, target: Path) -> None:
    """Make ``target`` hold ``source``'s content without ever replacing an existing ``target``."""
    try:
        os.link(source, target)  # fails with EEXIST rather than overwrite
        return
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise FileExistsError(str(target)) from e
        if e.errno not in (errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP):
            raise
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    _write_private(tmp, source.read_bytes())
    try:
        os.link(tmp, target)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise FileExistsError(str(target)) from e
        raise
    finally:
        tmp.unlink(missing_ok=True)


def _write_private(path: Path, content: bytes) -> None:
    """Write ``content`` to ``path`` created with mode 0600 from the start (no window where it is readable)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        os.fchmod(fd, FILE_MODE)
        os.write(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)


def _load_file() -> Dict[str, str]:
    migrate_legacy_store()
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
    _ensure_dir()
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    _write_private(tmp, json.dumps(data, indent=2).encode("utf-8"))
    tmp.replace(path)


@contextmanager
def _file_lock():
    """Serialise read-modify-write of the secrets file across processes (a running server discarding the setup
    token while ``python -m src.cli encryption-key rotate`` writes the keyring must not lose either change)."""
    _ensure_dir()
    path = _store_path()
    lock_path = path.with_name(f".{path.name}.lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def update_file(mutate: Callable[[Dict[str, str]], None]) -> Dict[str, str]:
    """Apply ``mutate`` to the stored values under the file lock and write the result; returns it."""
    with _file_lock():
        data = _load_file()
        mutate(data)
        _save_file(data)
    for name in list(_cache):
        if data.get(name) != _cache[name]:
            _cache.pop(name)
    return data


def read_file() -> Dict[str, str]:
    """The stored values as they are on disk now (no cache, nothing generated)."""
    return _load_file()


def file_version() -> Optional[int]:
    """A cheap token that changes whenever the secrets file is rewritten (its mtime in ns and inode)."""
    try:
        st = os.stat(_store_path())
    except OSError:
        return None
    return hash((st.st_mtime_ns, st.st_ino, st.st_size))


def get_secret(name: str, *, env_var: Optional[str] = None, length: int = 32) -> str:
    """Get a secret: env -> cache -> secrets file -> generate and persist."""
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

    def add(values):
        if not values.get(name):  # another process may have generated it meanwhile: keep theirs
            values[name] = generated

    data = update_file(add)
    _cache[name] = data[name]
    return data[name]


def discard_secret(name: str) -> None:
    """Forget a generated secret: drop it from the cache and from the secrets file (an env value is untouched)."""
    _cache.pop(name, None)
    if name in _load_file():
        update_file(lambda values: values.pop(name, None))


def store_location() -> Path:
    """Where generated secrets are kept (secrets/secrets.json unless MCP_GATE_SECRETS_DIR / _FILE say otherwise)."""
    return _store_path()


def reset_cache() -> None:
    """For tests: forget cached values and check for a legacy file again on the next read."""
    global _migration_checked
    _cache.clear()
    _migration_checked = False
