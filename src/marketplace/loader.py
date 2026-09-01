"""Marketplace catalog loader

Scans catalog/*.yaml, loads everything and caches it. Every YAML file goes through Pydantic validation.

Error-handling strategy: **skip broken files, never take down the whole marketplace**.
When a single catalog YAML fails validation, only logger.error is emitted and the file is skipped;
the error is kept in `errors` for debugging and the remaining entries are served as usual. Rationale:
MCP Center's primary job is issuing tokens, and a typo in one optional catalog file must not make
/auth/marketplace return 500 (or even block startup). main.py calls load_all() eagerly at startup, so
the problem shows up in the startup log instead of being discovered only when an admin opens the marketplace.

An installed process whose catalog has since become invalid takes the orchestrator's existing error path:
`_start_locked` raises OrchestratorError when the catalog entry cannot be found, and reconcile marks it
actual_state=failed and records last_error -- an explicit failure, never a silent one.
"""
import logging
from pathlib import Path
from typing import Dict, Optional

import yaml

from src.marketplace.schema import CatalogEntry

logger = logging.getLogger(__name__)


class CatalogLoadError(Exception):
    """Reading or validating a catalog YAML failed"""


class CatalogLoader:
    def __init__(self, catalog_dir: Path):
        self.catalog_dir = catalog_dir
        self._cache: Optional[Dict[str, CatalogEntry]] = None
        # filename -> error message; rebuilt on every load
        self._errors: Dict[str, str] = {}

    def load_all(self) -> Dict[str, CatalogEntry]:
        """Read all catalog YAML files and return a dict of id -> CatalogEntry.
        The result is cached; files are only actually read on the first call.
        """
        if self._cache is not None:
            return self._cache

        if not self.catalog_dir.exists():
            # Allow the catalog directory to be absent (early development); return an empty dict
            self._cache = {}
            self._errors = {}
            return self._cache

        entries: Dict[str, CatalogEntry] = {}
        errors: Dict[str, str] = {}
        for yaml_path in sorted(self.catalog_dir.glob("*.yaml")):
            try:
                with yaml_path.open("r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
                entry = CatalogEntry(**raw)
            except Exception as e:
                msg = f"{e}"
                logger.error(
                    f"Skipping invalid catalog entry {yaml_path.name}: {msg}"
                )
                errors[yaml_path.name] = msg
                continue

            if entry.id in entries:
                msg = f"Duplicate catalog id '{entry.id}'"
                logger.error(f"Skipping {yaml_path.name}: {msg}")
                errors[yaml_path.name] = msg
                continue

            entries[entry.id] = entry

        self._cache = entries
        self._errors = errors
        return entries

    @property
    def errors(self) -> Dict[str, str]:
        """Files skipped during the last load -> reason. Only meaningful after load_all()."""
        return dict(self._errors)

    def get(self, catalog_id: str) -> Optional[CatalogEntry]:
        return self.load_all().get(catalog_id)

    @property
    def images_dir(self) -> Path:
        """Directory holding the offline image tars (catalog_dir/images)."""
        return self.catalog_dir / "images"

    def image_tar_path(self, entry: CatalogEntry) -> Path:
        """Full path of a catalog entry's image tar (the file does not necessarily exist)."""
        return self.images_dir / entry.image_tar_name()

    def reload(self) -> Dict[str, CatalogEntry]:
        """Clear the cache and read again; for hot reload or tests"""
        self._cache = None
        self._errors = {}
        return self.load_all()


# -------- Singleton ----------

_default_loader: Optional[CatalogLoader] = None


def get_catalog_loader() -> CatalogLoader:
    """Get the default catalog loader

    Path precedence:
      1. the MCP_CATALOG_DIR environment variable (absolute path)
      2. project_root / catalog/  (consistent with the logic in main.py:
         project_root = Path(sys.argv[0]).parent)
    """
    global _default_loader
    if _default_loader is None:
        import os
        import sys
        env = os.environ.get("MCP_CATALOG_DIR")
        if env:
            catalog_dir = Path(env)
        else:
            project_root = Path(os.path.abspath(sys.argv[0])).parent
            catalog_dir = project_root / "catalog"
        _default_loader = CatalogLoader(catalog_dir)
    return _default_loader
