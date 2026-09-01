"""Config loading: environment variable expansion, defaults, type coercion."""

import os

import pytest
import yaml

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
    cfg = {
        "server": {"port": "${MCP_TEST_PORT:-4568}"},
        "oauth": {"issuer": "http://x:5555", "dcr_auto_approve": "${MCP_TEST_DCR:-true}"},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    previous = Config.get_config_model()
    try:
        Config.set_config(str(path))
        m = Config.get_config_model()
        assert m.server.port == 5555
        assert m.oauth.dcr_auto_approve is False
        assert m.database.url.startswith("sqlite:///")
    finally:
        Config.set_model(previous)


def test_shipped_config_yaml_loads(monkeypatch):
    """The repo's config/config.yaml must load with no environment variables set at all."""
    for key in ("DATABASE_URL", "SERVER_PORT", "OAUTH_ISSUER", "SESSION_SECRET_KEY"):
        monkeypatch.delenv(key, raising=False)
    previous = Config.get_config_model()
    try:
        Config.set_config(os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml"))
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
