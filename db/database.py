"""Database engine and session factory (fully lazy; works with SQLite and PostgreSQL).

Public API:
    Base            ORM declarative base
    get_engine()    singleton engine
    make_session()  obtain a Session (caller is responsible for closing it)
    get_db()        FastAPI dependency
    reset_engine()  for tests: rebuild after switching the URL
"""

from pathlib import Path
from typing import Generator

from sqlalchemy import MetaData, create_engine, event, make_url
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from src.config import Config

# Naming convention: SQLite ALTERs go through alembic batch mode, and constraints must be named to be dropped / rebuilt
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
Base = declarative_base(metadata=MetaData(naming_convention=NAMING_CONVENTION))

_engine = None
_session_factory = None

SQLITE_BUSY_TIMEOUT_MS = 5000


def is_sqlite_url(url: str) -> bool:
    return make_url(url).get_backend_name() == "sqlite"


def _ensure_sqlite_dir(url: str) -> None:
    db_path = make_url(url).database
    if db_path and db_path != ":memory:":
        Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)


def get_engine():
    global _engine
    if _engine is None:
        db_config = Config.get_database_config()
        url = db_config.url
        if is_sqlite_url(url):
            _ensure_sqlite_dir(url)
            _engine = create_engine(
                url,
                echo=db_config.echo,
                connect_args={"check_same_thread": False},
            )

            @event.listens_for(_engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):
                # Foreign-key enforcement (ON DELETE CASCADE) and WAL (concurrent reads/writes) are off by default
                # in SQLite. busy_timeout: a writer waits this long for another one instead of failing at once with
                # "database is locked" (set explicitly rather than relying on the driver's default).
                # synchronous=NORMAL is the recommended pairing with WAL: still durable against application
                # crashes, only a power loss can drop the last commits, and far fewer fsyncs than FULL.
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.close()
        else:
            _engine = create_engine(
                url,
                echo=db_config.echo,
                pool_size=db_config.pool_size,
                max_overflow=db_config.max_overflow,
                pool_pre_ping=True,
            )
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _session_factory


def make_session() -> Session:
    return _get_session_factory()()


def get_db() -> Generator[Session, None, None]:
    db = make_session()
    try:
        yield db
    finally:
        db.close()


def reset_engine() -> None:
    """Drop the singletons (used by tests when switching the DB URL), and the documents cached from the old DB."""
    from src.utils import public_cache

    global _engine, _session_factory
    public_cache.invalidate()
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
