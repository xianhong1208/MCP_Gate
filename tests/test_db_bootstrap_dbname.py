"""dbname validation tests for db_bootstrap

Background: SAST flagged the CREATE DATABASE in db_bootstrap.py as a Second-Order SQL Injection. The SQL itself
is safe (psycopg2 `sql.Identifier`; the dbname is an Identifier object throughout, with no string concatenation),
but we still add an allowlist at the source:

  1. Put an explicit sanitizer on the config -> SQL path.
  2. Reject mistyped DATABASE_URLs -- in particular, over-long names are silently truncated by Postgres to 63
     bytes, so "the DB name that got created" and "the name later connections use" no longer match.
"""
import pytest

from src.utils.db_bootstrap import (
    _MAX_IDENTIFIER_BYTES,
    _parse_db_url,
    _validate_dbname,
)


@pytest.mark.parametrize(
    "dbname",
    ["mcp_center", "postgres", "mcp-center", "db$1", "_internal", "a"],
)
def test_valid_dbnames_accepted(dbname):
    assert _validate_dbname(dbname) == dbname


@pytest.mark.parametrize(
    "dbname",
    [
        pytest.param('mydb"; DROP DATABASE postgres; --', id="quote-escape"),
        pytest.param('a" WITH OWNER "evil', id="owner-injection"),
        pytest.param("mydb; DROP TABLE x", id="statement-separator"),
        pytest.param("has space", id="space"),
        pytest.param("1startswithdigit", id="leading-digit"),
        pytest.param("postgresql://u:p@h/db", id="whole-url-as-dbname"),
        pytest.param("db\n", id="trailing-newline"),
        pytest.param("", id="empty"),
    ],
)
def test_invalid_dbnames_rejected(dbname):
    with pytest.raises(ValueError):
        _validate_dbname(dbname)


def test_oversized_dbname_rejected():
    """Anything over 63 bytes is silently truncated by Postgres -- it must be rejected up front"""
    assert _validate_dbname("a" * _MAX_IDENTIFIER_BYTES)
    with pytest.raises(ValueError, match="exceeds"):
        _validate_dbname("a" * (_MAX_IDENTIFIER_BYTES + 1))


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://postgres:password@localhost:5432/mcp_center",
        "postgresql://mcp_center:pwd@localhost:5432/mcp_center",
        "postgresql://user:password@db:5432/mcp_center",
    ],
)
def test_readme_urls_parse_and_validate(url):
    """Every DATABASE_URL example in README / docs must pass"""
    dbname = _parse_db_url(url)["dbname"]
    assert _validate_dbname(dbname) == "mcp_center"
