"""N1: the startup banner printed DATABASE_URL with its password (stdout and logs/app_*.log)."""

import pytest

from src.utils.db_url import mask_db_url


@pytest.mark.parametrize("url, expected", [
    ("postgresql://app:s3cr3t@db:5432/mcp", "postgresql://app:***@db:5432/mcp"),
    ("postgresql+psycopg2://app:p%40ss@db/mcp", "postgresql+psycopg2://app:***@db/mcp"),
    ("postgresql://app:s3cr3t@db/mcp?sslmode=require&password=x2", "postgresql://app:***@db/mcp?sslmode=require&password=***"),
    ("postgresql://app@db/mcp", "postgresql://app@db/mcp"),
    ("sqlite:///data/mcp_gate.db", "sqlite:///data/mcp_gate.db"),
    ("not a url user:pw@host", "not a url user:pw@host"),
])
def test_mask_db_url(url, expected):
    assert mask_db_url(url) == expected


def test_startup_banner_does_not_print_the_password(monkeypatch):
    import main
    from src.config import Config

    lines = []
    monkeypatch.setattr(main.logger, "info", lambda msg, *a, **k: lines.append(str(msg)))
    monkeypatch.setattr(main.logger, "warning", lambda msg, *a, **k: lines.append(str(msg)))
    monkeypatch.setattr(Config.get_config_model().database, "url", "postgresql://app:hunter2@db:5432/mcp")
    main._print_banner({"users": 1, "signing_kid": "abc"}, "127.0.0.1", 4568)
    text = "\n".join(lines)
    assert "postgresql://app:***@db:5432/mcp" in text and "hunter2" not in text
