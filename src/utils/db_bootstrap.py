"""DB Bootstrap -- make sure the target DB exists (runs before Alembic migrations)

Chicken-and-egg problem: `CREATE DATABASE` cannot be run from inside the database itself; we must first connect
to PostgreSQL's default `postgres` system DB to issue it. CREATE DATABASE also cannot run inside a transaction,
hence AUTOCOMMIT.

Flow:
  1. Parse DATABASE_URL, extract the target dbname and validate it
  2. Connect to the `postgres` system DB with a SQLAlchemy engine (AUTOCOMMIT)
  3. Query pg_database; CREATE DATABASE if it does not exist

Design notes:
  - Only needed for PostgreSQL; for SQLite we only make sure the directory exists.
  - Idempotent: safe to run any number of times; if someone else created the DB first under concurrency,
    the duplicate error is swallowed.
  - Always goes through SQLAlchemy (consistent with the rest of the project's DB access); the identifier is
    escaped per the SQL standard (wrapped in double quotes, embedded " doubled), and the dbname is additionally
    checked against the _validate_dbname allowlist first.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

from sqlalchemy import create_engine, make_url, text
from sqlalchemy.exc import ProgrammingError

# Postgres identifiers are limited to 63 bytes (NAMEDATALEN-1). Anything longer is **silently truncated**, so the
# name CREATE DATABASE produces differs from the name later connections use, causing errors that are hard to trace.
_MAX_IDENTIFIER_BYTES = 63

# dbname allowlist. Used to fail fast at the source:
#   1. Put an explicit sanitizer on the config -> SQL path.
#   2. Reject mistyped DATABASE_URLs (the whole URL taken as the dbname, over-long names getting truncated, etc.).
_DBNAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$-]*")


def _validate_dbname(dbname: str) -> str:
    """Validate the dbname parsed from DATABASE_URL; raise ValueError if it is invalid.

    The caller (main.py) already wraps bootstrap in try/except and sys.exit(1)s, so a configuration error fails
    loudly at startup instead of continuing to run with a strange name.
    """
    if not _DBNAME_RE.fullmatch(dbname):
        raise ValueError(
            f"Invalid database name in DATABASE_URL: {dbname!r}. "
            f"Only letters/digits/underscore/hyphen/$ are allowed, and it must start with a letter or underscore"
        )
    if len(dbname.encode("utf-8")) > _MAX_IDENTIFIER_BYTES:
        raise ValueError(
            f"Database name in DATABASE_URL exceeds the Postgres limit of "
            f"{_MAX_IDENTIFIER_BYTES} bytes (it would be silently truncated): {dbname!r}"
        )
    return dbname


def _parse_db_url(url: str) -> dict:
    parsed = urlparse(url)
    # urlparse does not decode percent-encoding, but SQLAlchemy's make_url (engine side) does -- they must agree
    # when credentials contain special characters (e.g. p%40ss = p@ss). Unquote user/password by hand to match make_url.
    return {
        "scheme": parsed.scheme,
        "user": unquote(parsed.username) if parsed.username else parsed.username,
        "password": unquote(parsed.password) if parsed.password else parsed.password,
        "host": parsed.hostname,
        "port": parsed.port or 5432,
        "dbname": parsed.path.lstrip("/"),
    }


def ensure_database_ready(db_url: str, logger) -> None:
    """Make sure the target DB exists (idempotent)

    When to call: must run before alembic migrations / any ORM operation.

    Args:
        db_url: SQLAlchemy DB URL, e.g. postgresql://user:pwd@host/dbname
        logger: the main program's logger instance

    Raises:
        sqlalchemy.exc.OperationalError: even connecting to the postgres system DB failed (bad password / service down)
        sqlalchemy.exc.ProgrammingError: no CREATEDB privilege, etc.
    """
    params = _parse_db_url(db_url)

    # Non-PostgreSQL (e.g. SQLite) needs no bootstrap -- SQLite creates the file on first open
    if not params["scheme"].startswith("postgres"):
        # SQLite: just make sure the directory exists; the file is created on first open
        if params["scheme"].startswith("sqlite"):
            from db.database import _ensure_sqlite_dir
            _ensure_sqlite_dir(db_url)
        logger.debug(f"DB scheme '{params['scheme']}' is not postgres, skipping bootstrap")
        return

    target_dbname = params["dbname"]
    if not target_dbname:
        logger.warning("⚠️ No database name in DATABASE_URL, skipping bootstrap")
        return

    # Validate the dbname before any connection / SQL (see the notes on _validate_dbname)
    target_dbname = _validate_dbname(target_dbname)

    logger.info(f"Bootstrapping database '{target_dbname}'...")

    # CREATE DATABASE requires connecting to the postgres system DB. make_url handles special characters in the
    # credentials safely and swaps the target dbname for postgres; AUTOCOMMIT because CREATE DATABASE cannot run
    # inside a transaction.
    admin_url = make_url(db_url).set(database="postgres")
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": target_dbname},
            ).scalar()
            if exists:
                logger.info(f"Database '{target_dbname}' already exists")
                return

            logger.warning(f"Database '{target_dbname}' not found, creating...")
            # CREATE DATABASE cannot take the identifier as a bind parameter. Escape per the SQL standard: wrap
            # the identifier in double quotes and double any embedded ". The dbname has also already passed the
            # _validate_dbname allowlist (it cannot contain " at all), so this is defense-in-depth.
            safe_name = target_dbname.replace('"', '""')
            conn.execute(text(f'CREATE DATABASE "{safe_name}"'))
            logger.info(f"Database '{target_dbname}' created successfully")
    except ProgrammingError as e:
        # Another process created it first under concurrency (duplicate_database) -> treat as success
        if "already exists" in str(e).lower():
            logger.info(f"Database '{target_dbname}' was created concurrently (by another process)")
            return
        raise
    finally:
        admin_engine.dispose()
