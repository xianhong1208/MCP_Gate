"""Runtime path resolution for dev / Nuitka / Docker deployments.

Why this file exists
--------------------
`Path(__file__).parent / "xxx"` is correct in dev mode but breaks under Nuitka onefile:
- A Nuitka onefile binary extracts the whole archive into a temporary `/tmp/onefile_<pid>_<rnd>/` directory
- `__file__` then points at `/tmp/onefile_xxx/...`, not next to the real binary
- So what gets read is the "stale snapshot from packaging time" rather than the files the user actually deployed

`resolve_external_dir(name, dev_root)` handles this uniformly:
  1. Nuitka onefile: find the real location via the `NUITKA_ONEFILE_PARENT` env var + `/proc/<pid>/exe`
  2. Nuitka standalone: use `sys.executable` or `/proc/self/exe`
  3. Docker container: the `/app/{name}` convention
  4. Dev mode: the `dev_root` passed in by the caller
  5. Fall back to the bundled copy in the onefile extraction directory

`/app/{name}` comes before dev_root so that the real contents of a Docker volume mount win over the bundled snapshot.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional


def resolve_external_dir(name: str, dev_root: Path) -> Optional[Path]:
    """Locate an external resource directory across deployment modes

    Args:
        name: directory name (e.g. "alembic", "config", "catalog")
        dev_root: project root in dev mode

    Returns:
        The first candidate directory that exists, or None if none is found
    """
    candidates: List[Path] = []

    # (1) Nuitka onefile: NUITKA_ONEFILE_PARENT points at the parent process that launched the binary
    nuitka_parent = os.environ.get("NUITKA_ONEFILE_PARENT")
    if nuitka_parent:
        try:
            parent_exe = Path(f"/proc/{nuitka_parent}/exe").resolve()
            if parent_exe.exists():
                candidates.append(parent_exe.parent / name)
        except (OSError, ValueError):
            pass

    # (2) Generic Linux: /proc/self/exe always points at the binary the current process is really executing
    # Reject the bogus /tmp/onefile_* path (the binary inside the onefile extraction directory)
    if sys.platform.startswith("linux"):
        try:
            proc_exe = Path("/proc/self/exe").resolve()
            if not str(proc_exe).startswith("/tmp/onefile_"):
                candidates.append(proc_exe.parent / name)
        except (OSError, ValueError):
            pass

    # (3) Nuitka standalone (not onefile): sys.executable is the real binary
    try:
        exe_path = Path(sys.executable).resolve()
        if not str(exe_path).startswith("/tmp/onefile_"):
            candidates.append(exe_path.parent / name)
    except (OSError, ValueError):
        pass

    # (4) Docker container convention (deliberately placed before dev_root
    # so a volume mount wins over the onefile bundled copy)
    candidates.append(Path(f"/app/{name}"))

    # (5) Dev mode / onefile bundled fallback
    candidates.append(dev_root / name)

    for p in candidates:
        if p.is_dir():
            return p
    return None


def get_runtime_project_root() -> Path:
    """Get the runtime "external resource root" -- same logic as the corresponding line in main.py

    For cases that need a relative path but do not need the multi-directory search of `resolve_external_dir()`.
    Correct for both dev and Nuitka; but it cannot handle a "binary in A, resources in B" deployment layout --
    use `resolve_external_dir()` for that.
    """
    return Path(os.path.abspath(sys.argv[0])).parent
