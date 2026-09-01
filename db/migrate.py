"""Database Migration Manager

Wraps Alembic operations and exposes a clean Python API for main.py and the CLI.

Design highlights:
  - Uses Alembic's high-level API (`command.*`) instead of parsing migration files ourselves
  - `auto_migrate()` handles three DB states: fresh / legacy without alembic history / already managed by alembic
  - The historical "schema ahead of alembic_version" baggage is repaired automatically (stamp to head)

CLI usage:
    python -m db.migrate                    # default: auto
    python -m db.migrate status             # show status
    python -m db.migrate upgrade            # upgrade to head
    python -m db.migrate downgrade -r -1    # roll back one revision
    python -m db.migrate generate -m "..."  # create a new migration (autogenerate)
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path
from typing import Optional, Tuple

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from src.config import Config
from src.logging import get_logger
from src.utils.runtime_paths import resolve_external_dir


def _env_flag_enabled(name: str) -> bool:
    """Parse a boolean env var safely.

    bool("false") is True in Python (non-empty string), so bool(os.environ.get) cannot be used.
    """
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")

# Project root in dev mode: db/migrate.py -> one level up is the project root
_dev_project_root = Path(__file__).resolve().parent.parent

logger = get_logger("db.migrate")


def _resolve_alembic_dir() -> Path:
    """Find the alembic/ directory across deployment modes

    Resolution order (provided by resolve_external_dir):
      (1) next to the real Nuitka onefile binary
      (2) next to /proc/self/exe
      (3) next to sys.executable
      (4) /app/alembic (Docker volume mount)
      (5) dev mode project_root / alembic
    """
    resolved = resolve_external_dir("alembic", dev_root=_dev_project_root)
    if resolved is None:
        raise FileNotFoundError(
            f"alembic/ directory not found. Looked in Nuitka binary dir, "
            f"/app/alembic, and {_dev_project_root / 'alembic'}"
        )
    return resolved


class DatabaseMigrator:
    """Single entry point wrapping Alembic operations

    Every public method is idempotent (safe to run any number of times), which suits the server startup flow.
    """

    # Criterion for "the DB has already been initialized by the app" -- any one of these tables present counts
    APP_TABLE_MARKERS = ("services", "admin_users", "oauth_clients")

    def __init__(self):
        self.alembic_dir = _resolve_alembic_dir()
        self.project_root = self.alembic_dir.parent

        self.db_url = Config.get_database_config().url

        # No alembic.ini -- all settings are injected via the pure Python API. The alembic CLI is no longer supported.
        self.alembic_cfg = AlembicConfig()
        self.alembic_cfg.set_main_option("script_location", str(self.alembic_dir))
        self.alembic_cfg.set_main_option("sqlalchemy.url", self.db_url)
        logger.debug(f"Alembic dir resolved to: {self.alembic_dir}")

    # ---- Internal helpers ----

    def _get_engine(self):
        """Get the engine lazily -- avoid connecting at import time"""
        from db.database import get_engine
        return get_engine()

    def _get_db_revision(self) -> Optional[str]:
        """Read the current revision from the alembic_version table (None if the table does not exist)"""
        engine = self._get_engine()
        inspector = inspect(engine)
        if "alembic_version" not in inspector.get_table_names():
            return None
        with engine.connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
            return row[0] if row else None

    def _get_head_revision(self) -> Optional[str]:
        """Read the head revision from the migration files"""
        script = ScriptDirectory.from_config(self.alembic_cfg)
        return script.get_current_head()

    def _classify_db_state(self) -> str:
        """Determine which state the DB is in; returns:
        - "fresh"         brand-new empty DB (neither alembic nor app tables)
        - "legacy"        old DB with app tables but no alembic history
        - "managed"       already managed by alembic (alembic_version table exists)
        """
        engine = self._get_engine()
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        has_alembic = "alembic_version" in tables
        has_app_tables = any(t in tables for t in self.APP_TABLE_MARKERS)

        if has_alembic:
            return "managed"
        if has_app_tables:
            return "legacy"
        return "fresh"

    # ---- Public API ----

    def auto_migrate(self) -> bool:
        """Automatic migration -- called by default at server startup

        Three cases are handled:
          fresh   -> run every migration from scratch
          legacy  -> stamp to head (treated as fully applied, but future migrations will still run)
          managed -> compare db_rev with head_rev and upgrade only when needed

        On automatic repair of DuplicateTable / DuplicateColumn:
          **Off** by default. If an upgrade hits a schema-already-exists conflict midway, it fails outright and
          requires manual intervention -- such errors may be:
            (a) historical baggage: leftovers from the old create_all() (safe to stamp)
            (b) a failed partial migration: the previous upgrade crashed halfway
            (c) a multi-process race: another server instance is running the migration at the same time
          In cases (b) and (c), stamping head would mark a broken DB as "up to date", and later autogenerate
          runs would silently drop things. To enable auto-stamp, set `ALEMBIC_AUTO_STAMP_ON_CONFLICT=true` and
          make sure your deployment can only hit (a).
        """
        try:
            state = self._classify_db_state()
            head_rev = self._get_head_revision()
            logger.info(f"DB state: {state}, head revision: {head_rev}")

            if state == "fresh":
                logger.info("Fresh database, running all migrations...")
                alembic_command.upgrade(self.alembic_cfg, "head")
                logger.info("All migrations applied")
                return True

            if state == "legacy":
                logger.info(f"Legacy database without alembic history, stamping to head ({head_rev})...")
                alembic_command.stamp(self.alembic_cfg, "head")
                logger.info("Stamped to head")
                return True

            # state == "managed"
            db_rev = self._get_db_revision()
            if db_rev == head_rev:
                logger.info(f"Database already at latest revision ({db_rev})")
                return True

            logger.info(f"Database at {db_rev}, upgrading to {head_rev}...")
            try:
                alembic_command.upgrade(self.alembic_cfg, "head")
                logger.info("Upgrade complete")
                return True
            except Exception as err:
                err_str = str(err)
                is_dup_conflict = any(
                    k in err_str for k in ("already exists", "DuplicateTable", "DuplicateColumn")
                )
                if not is_dup_conflict:
                    raise

                # Hit a schema-already-exists conflict -- no auto-stamp by default
                auto_stamp = _env_flag_enabled("ALEMBIC_AUTO_STAMP_ON_CONFLICT")
                if not auto_stamp:
                    logger.error(
                        f"Migration conflict (schema ahead of version): {err}"
                    )
                    logger.error(
                        f"  DB at revision {db_rev}, head is {head_rev}"
                    )
                    logger.error(
                        "  This may be a historical artifact OR a partial migration failure."
                    )
                    logger.error(
                        "  Manual investigation required. If you confirm the schema is correct,"
                    )
                    logger.error(
                        "  run: ALEMBIC_AUTO_STAMP_ON_CONFLICT=true python -m db.migrate auto"
                    )
                    logger.error(
                        f"  OR explicitly: python -m db.migrate stamp -r {head_rev}"
                    )
                    self._rollback_dirty_transaction()
                    raise

                logger.warning(
                    f"ALEMBIC_AUTO_STAMP_ON_CONFLICT=true — auto-stamping to {head_rev} "
                    f"despite migration conflict: {err}"
                )
                self._rollback_dirty_transaction()
                alembic_command.stamp(self.alembic_cfg, "head")
                logger.info(f"Stamped to {head_rev} (auto-recovery via env var)")
                return True

        except Exception as e:
            logger.error(f"Auto migration failed: {e}")
            traceback.print_exc()
            return False

    def _rollback_dirty_transaction(self) -> None:
        """A failed alembic upgrade may leave a dangling transaction; clear it proactively"""
        try:
            with self._get_engine().connect() as conn:
                conn.execute(text("ROLLBACK"))
        except Exception:
            pass

    def upgrade(self, revision: str = "head") -> bool:
        try:
            logger.info(f"Upgrading database to: {revision}")
            alembic_command.upgrade(self.alembic_cfg, revision)
            logger.info("Upgrade complete")
            return True
        except Exception as e:
            logger.error(f"Upgrade failed: {e}")
            return False

    def downgrade(self, revision: str = "-1") -> bool:
        try:
            logger.warning(f"Downgrading database to: {revision}")
            alembic_command.downgrade(self.alembic_cfg, revision)
            logger.info("Downgrade complete")
            return True
        except Exception as e:
            logger.error(f"Downgrade failed: {e}")
            return False

    def stamp(self, revision: str = "head") -> bool:
        try:
            logger.info(f"Stamping database at: {revision}")
            alembic_command.stamp(self.alembic_cfg, revision)
            return True
        except Exception as e:
            logger.error(f"Stamp failed: {e}")
            return False

    def status(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Return (is_up_to_date, current_rev, head_rev) -- and print a human-readable report"""
        db_rev = self._get_db_revision()
        head_rev = self._get_head_revision()
        is_up_to_date = (db_rev == head_rev and db_rev is not None)

        print("=" * 50)
        print("DATABASE MIGRATION STATUS")
        print("=" * 50)
        print(f"Current revision: {db_rev or '(none)'}")
        print(f"Head revision:    {head_rev or '(none)'}")
        print(f"DB state:         {self._classify_db_state()}")
        print(f"Up to date:       {is_up_to_date}")
        print("=" * 50)

        return is_up_to_date, db_rev, head_rev

    def current(self) -> bool:
        rev = self._get_db_revision()
        print(rev if rev else "(no revision - database not initialized)")
        return True

    def heads(self) -> bool:
        rev = self._get_head_revision()
        print(rev if rev else "(no head revision)")
        return True

    def history(self) -> bool:
        alembic_command.history(self.alembic_cfg)
        return True

    def create_migration(self, message: str) -> bool:
        try:
            logger.info(f"Creating migration: {message}")
            alembic_command.revision(self.alembic_cfg, message=message, autogenerate=True)
            logger.info("Migration created")
            return True
        except Exception as e:
            logger.error(f"Create migration failed: {e}")
            return False


def run_migration_command(action: str, message: Optional[str] = None,
                          revision: str = "-1") -> bool:
    """Dispatch migration action -- shared by main.py and the CLI

    Actions:
        auto       apply all pending migrations automatically (default)
        status     show status
        upgrade    upgrade to the given revision (--revision, default head)
        downgrade  downgrade to the given revision
        rollback   same as downgrade
        stamp      mark the revision without running it
        current    show the current revision
        heads      show the head revision
        history    show history
        generate   create a new migration (requires --message)
    """
    try:
        m = DatabaseMigrator()
    except Exception as e:
        logger.error(f"Failed to init migrator: {e}")
        return False

    actions = {
        "auto":      lambda: m.auto_migrate(),
        "status":    lambda: (m.status(), True)[1],
        "upgrade":   lambda: m.upgrade(revision if revision != "-1" else "head"),
        "downgrade": lambda: m.downgrade(revision),
        "rollback":  lambda: m.downgrade(revision),
        "stamp":     lambda: m.stamp(revision if revision != "-1" else "head"),
        "current":   lambda: m.current(),
        "heads":     lambda: m.heads(),
        "history":   lambda: m.history(),
    }

    if action == "generate":
        if not message:
            logger.error("Migration message required for generate (use -m)")
            return False
        return m.create_migration(message)

    handler = actions.get(action)
    if handler is None:
        valid = ", ".join(sorted(list(actions.keys()) + ["generate"]))
        logger.error(f"Unknown migration action: '{action}'. Valid: {valid}")
        return False

    return handler()


def main():
    """CLI entry point: python -m db.migrate [action]"""
    import argparse
    import os

    # The CLI is a standalone entry point and must load .env + config itself (main.py handles this in server mode)
    from dotenv import load_dotenv
    load_dotenv(_dev_project_root / ".env")

    parser = argparse.ArgumentParser(
        description="MCP Center Database Migration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python -m db.migrate                       # auto migrate
    python -m db.migrate status                # show status
    python -m db.migrate upgrade               # upgrade to head
    python -m db.migrate downgrade -r -1       # rollback one
    python -m db.migrate generate -m "add X"   # autogenerate migration
        """,
    )
    parser.add_argument("action", nargs="?", default="auto",
                       choices=["auto", "status", "upgrade", "downgrade", "rollback",
                                "stamp", "current", "heads", "history", "generate"])
    parser.add_argument("-m", "--message", help="Migration message (for generate)")
    parser.add_argument("-r", "--revision", default="-1",
                       help="Target revision for upgrade/downgrade/stamp")
    parser.add_argument("--config", default=os.environ.get("MCP_CENTER_CONFIG", "config/config.yaml"),
                       help="Path to config.yaml")
    args = parser.parse_args()

    Config.set_config(args.config)

    # Make sure the DB exists before connecting (generate is the exception: it needs no DB)
    if args.action != "generate":
        import logging
        cli_logger = logging.getLogger("db.migrate")
        if not cli_logger.handlers:
            logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        from src.utils.db_bootstrap import ensure_database_ready
        ensure_database_ready(Config.get_database_config().url, cli_logger)

    success = run_migration_command(args.action, args.message, args.revision)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
