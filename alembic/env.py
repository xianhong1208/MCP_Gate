"""Alembic migration environment configuration"""

import os
import sys
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load .env so DATABASE_URL etc. are available when running alembic CLI directly
# (mirrors the load_dotenv call in main.py)
try:
    from dotenv import load_dotenv
    load_dotenv(project_root / ".env")
except ImportError:
    pass

# Load application config
from src.config import Config

# Try to load config if not already loaded
config_path = os.environ.get("MCP_CENTER_CONFIG", "config/config.yaml")
try:
    Config.set_config(config_path)
except Exception:
    pass  # Config may already be loaded

# Import models for autogenerate support
from db.database import Base
from db import models  # noqa: F401 - ensure all models are imported

# Alembic Config object
config = context.config

# Get database URL from our config
try:
    db_config = Config.get_database_config()
    config.set_main_option("sqlalchemy.url", db_config.url)
except Exception:
    # Fallback to environment variable
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")
    config.set_main_option("sqlalchemy.url", database_url)

# Alembic logging is left to the host app's logger (loguru) — we don't load
# alembic.ini's [loggers] section because alembic.ini was removed.

# Model metadata for autogenerate support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # SQLite does not support most ALTER TABLE forms; batch mode lets the same migration run on both DBs
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
