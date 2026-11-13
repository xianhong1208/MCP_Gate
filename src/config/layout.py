"""Where each setting lives: the five files under ``config/``.

MCP Gate's configuration is five YAML files, merged into one tree at startup (see
``manager.load_config_dir``). Each file is written in the shape of the merged tree, so ``oauth.yaml`` starts
with ``oauth:``. A setting may be written in one file only; the same key in two files stops startup.

Secrets and per-machine values are ``${VAR:-default}`` references read from the environment or ``.env``, so every
file under ``config/`` is free of secrets and safe to commit.

Pure data, shared by the loader, ``scripts/split_config.py`` and the tests.
"""

from typing import Dict, Tuple

# File -> the top-level sections it holds
FILE_SECTIONS: Dict[str, Tuple[str, ...]] = {
    "database.yaml": ("database",),
    "oauth.yaml": ("oauth",),
    "identity.yaml": ("identity", "session"),
    "security.yaml": ("rate_limit", "security", "cors"),
    "system.yaml": ("server", "logging", "scheduler"),
}

CONFIG_FILES: Tuple[str, ...] = tuple(FILE_SECTIONS)

# The directory read by default (relative to the working directory) and the variable that overrides it
DEFAULT_CONFIG_DIR = "config"
CONFIG_DIR_ENV = "MCP_GATE_CONFIG_DIR"

# The single file used up to MCP Gate 1.3, and the variable that pointed at it. Neither is read any more; their
# presence is reported at startup.
LEGACY_CONFIG_FILE = "config.yaml"
LEGACY_CONFIG_ENV = "MCP_GATE_CONFIG"


def file_for(section: str) -> str | None:
    """The file a top-level section belongs to, or None for an unknown section."""
    for name, sections in FILE_SECTIONS.items():
        if section in sections:
            return name
    return None


__all__ = [
    "FILE_SECTIONS", "CONFIG_FILES", "DEFAULT_CONFIG_DIR", "CONFIG_DIR_ENV", "LEGACY_CONFIG_FILE",
    "LEGACY_CONFIG_ENV", "file_for",
]
