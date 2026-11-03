"""SQLite connections are configured for a concurrent server: WAL, synchronous=NORMAL, an explicit busy_timeout,
foreign keys on. PostgreSQL is left alone."""

import pytest
from sqlalchemy import text

from tests.conftest import using_postgres

pytestmark = pytest.mark.skipif(using_postgres(), reason="SQLite pragmas")


def test_every_sqlite_connection_gets_the_pragmas(engine):
    from db.database import SQLITE_BUSY_TIMEOUT_MS

    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"
        assert conn.execute(text("PRAGMA busy_timeout")).scalar() == SQLITE_BUSY_TIMEOUT_MS == 5000
        assert conn.execute(text("PRAGMA synchronous")).scalar() == 1  # NORMAL
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
