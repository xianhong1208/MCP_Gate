"""MCP Center version information.

The single source of truth for the version is `[project].version` in `pyproject.toml`; this module reads it at
import time so it never has to be synced by hand in several places. Resolution order: pyproject.toml -> installed
package metadata -> "0.0.0+unknown".
"""

from pathlib import Path


def _read_version() -> str:
    # 1) Read pyproject.toml directly (single source of truth, always current during development)
    try:
        import tomllib
        for parent in Path(__file__).resolve().parents:
            pyproject = parent / "pyproject.toml"
            if pyproject.is_file():
                with pyproject.open("rb") as f:
                    v = tomllib.load(f).get("project", {}).get("version")
                if v:
                    return v
    except Exception:
        pass

    # 2) Installed package metadata (pip populates it from pyproject)
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version("mcp-center")
        except PackageNotFoundError:
            pass
    except Exception:
        pass

    # 3) Last-resort fallback so we never crash
    return "0.0.0+unknown"


# Version number -- follows Semantic Versioning (MAJOR.MINOR.PATCH), sourced from pyproject.toml
__version__ = _read_version()

# Build information (written by CI/CD or the Build Center at build time; defaults to dev)
__build_time__ = "dev"
__build_commit__ = "dev"
