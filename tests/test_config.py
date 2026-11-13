"""Config loading: environment variable expansion, defaults, type coercion."""

import os

import pytest
import yaml

from src.config.layout import CONFIG_FILES
from src.config.manager import Config, expand_env_vars
from src.config.model import ConfigModel


def test_expand_env_vars_required_and_default(monkeypatch):
    monkeypatch.setenv("MCP_TEST_A", "hello")
    monkeypatch.delenv("MCP_TEST_B", raising=False)
    assert expand_env_vars("${MCP_TEST_A}") == "hello"
    assert expand_env_vars("${MCP_TEST_B:-fallback}") == "fallback"
    assert expand_env_vars("${MCP_TEST_B:-}") == ""
    assert expand_env_vars({"k": ["${MCP_TEST_A}", 1]}) == {"k": ["hello", 1]}
    with pytest.raises(ValueError):
        expand_env_vars("${MCP_TEST_B}")


def test_defaults_are_sqlite_and_localhost_issuer():
    m = ConfigModel()
    assert m.database.url.startswith("sqlite:///")
    assert m.oauth.issuer == "http://localhost:4568"
    assert m.oauth.dcr_auto_approve is True
    assert m.identity.local_enabled is True


def test_yaml_env_values_are_coerced(tmp_path, monkeypatch):
    """`${PORT:-4568}` expands to a string; pydantic must coerce it to int / bool."""
    monkeypatch.setenv("MCP_TEST_PORT", "5555")
    monkeypatch.setenv("MCP_TEST_DCR", "false")
    for name in CONFIG_FILES:
        (tmp_path / name).write_text("")
    (tmp_path / "system.yaml").write_text(yaml.safe_dump({"server": {"port": "${MCP_TEST_PORT:-4568}"}}))
    (tmp_path / "oauth.yaml").write_text(yaml.safe_dump(
        {"oauth": {"issuer": "http://x:5555", "dcr_auto_approve": "${MCP_TEST_DCR:-true}"}}))
    previous = Config.get_config_model()
    try:
        Config.set_config_dir(str(tmp_path))
        m = Config.get_config_model()
        assert m.server.port == 5555
        assert m.oauth.dcr_auto_approve is False
        assert m.database.url.startswith("sqlite:///")
    finally:
        Config.set_model(previous)


def test_shipped_config_files_load(monkeypatch):
    """The repo's five config/*.yaml files must load with no environment variables set at all."""
    for key in ("DATABASE_URL", "SERVER_PORT", "OAUTH_ISSUER", "SESSION_SECRET_KEY"):
        monkeypatch.delenv(key, raising=False)
    previous = Config.get_config_model()
    try:
        Config.set_config_dir(os.path.join(os.path.dirname(__file__), "..", "config"))
        m = Config.get_config_model()
        assert m.server.port == 0            # 0 = derive from issuer
        assert m.effective_port == 4568
        assert m.oauth.issuer == "http://localhost:4568"
        assert m.session.secret_key == ""
    finally:
        Config.set_model(previous)


def test_effective_port_follows_issuer():
    from src.config.model import OAuthConfig, ServerConfig
    assert ConfigModel(oauth=OAuthConfig(issuer="http://192.168.1.10:5000")).effective_port == 5000
    assert ConfigModel(oauth=OAuthConfig(issuer="https://mcp.example.com")).effective_port == 4568
    assert ConfigModel(oauth=OAuthConfig(issuer="http://x:5000"), server=ServerConfig(port=9000)).effective_port == 9000


def test_scheduler_section_defaults_and_yaml(tmp_path, monkeypatch):
    from src.config.model import SchedulerConfig

    d = SchedulerConfig()
    assert (d.oauth_cleanup_hours, d.usage_retention_days, d.audit_retention_days, d.health_check_seconds,
            d.health_check_concurrency, d.health_check_timeout_seconds, d.health_write_interval_minutes) == \
        (6, 30, 90, 30, 8, 10.0, 5)
    monkeypatch.delenv("AUDIT_RETENTION_DAYS", raising=False)
    monkeypatch.setenv("HEALTH_CHECK_SECONDS", "45")
    shipped = Config._load_config(os.path.join(os.path.dirname(__file__), "..", "config"))
    assert shipped.scheduler.audit_retention_days == 90 and shipped.scheduler.health_check_seconds == 45
    with pytest.raises(ValueError):
        SchedulerConfig(health_check_concurrency=0)


def test_lifespan_applies_the_scheduler_config(app, monkeypatch):
    from fastapi.testclient import TestClient

    from src.config import Config
    from src.scheduler import get_scheduler

    cfg = Config.get_config_model().scheduler
    monkeypatch.setattr(cfg, "audit_retention_days", 7)
    monkeypatch.setattr(cfg, "health_check_seconds", 120)
    monkeypatch.setattr(cfg, "health_check_concurrency", 3)
    scheduler = get_scheduler()
    try:
        with TestClient(app, base_url="http://testserver"):
            assert scheduler.audit_retention_days == 7
            assert scheduler.health_check_concurrency == 3
            job = scheduler.scheduler.get_job("health_check")
            assert job.trigger.interval.total_seconds() == 120
    finally:
        scheduler.configure()  # the singleton outlives this test
