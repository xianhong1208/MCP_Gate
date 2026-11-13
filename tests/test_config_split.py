"""#55: the configuration is five files under config/, merged at startup; the old config.yaml is not read."""

import os
import shutil
from pathlib import Path

import pytest
import yaml

from src.config.layout import CONFIG_FILES, FILE_SECTIONS
from src.config.manager import (
    Config, ConfigFileError, default_config_dir, expand_env_vars, load_config_dir, startup_notices,
)
from src.config.model import ConfigModel

ROOT = Path(__file__).resolve().parent.parent
SHIPPED = ROOT / "config"
OLD_FILE = Path(__file__).resolve().parent / "fixtures" / "config-1.3.yaml"   # config/config.yaml as of 1.3


def write_dir(path: Path, **files) -> Path:
    """The five files under ``path``, empty unless given (file name without .yaml -> mapping or raw text)."""
    path.mkdir(parents=True, exist_ok=True)
    for name in CONFIG_FILES:
        content = files.get(name.removesuffix(".yaml"), "")
        (path / name).write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return path


@pytest.fixture
def restore_config():
    previous = Config.get_config_model()
    yield
    Config.set_model(previous)
    Config._startup_notices = []


def test_shipped_files_hold_exactly_their_sections():
    for name, sections in FILE_SECTIONS.items():
        data = yaml.safe_load((SHIPPED / name).read_text(encoding="utf-8"))
        assert sorted(data) == sorted(sections), name
    assert not (SHIPPED / "config.yaml").exists()
    # Every section of the model has a home
    assert sorted(s for secs in FILE_SECTIONS.values() for s in secs) == sorted(ConfigModel.model_fields)


def test_shipped_files_equal_the_old_single_file_field_by_field(monkeypatch):
    """With no environment and with every referenced variable set, the five files load to the same config as the
    1.3 config.yaml did."""
    for key in list(os.environ):
        if key.isupper() and key not in ("PATH", "HOME"):
            monkeypatch.delenv(key, raising=False)
    old_raw = yaml.safe_load(OLD_FILE.read_text(encoding="utf-8"))

    def both():
        old = ConfigModel(**expand_env_vars(old_raw)).model_dump()
        new = ConfigModel(**expand_env_vars(load_config_dir(SHIPPED))).model_dump()
        return old, new

    old, new = both()
    assert old == new
    for var, value in {"DATABASE_URL": "postgresql://u@h/d", "OAUTH_ISSUER": "https://a.example",
                       "OAUTH_ACCESS_EXPIRE_MINUTES": "7", "SESSION_EXPIRE_HOURS": "3", "ADMIN_EMAIL": "a@b.c",
                       "ALLOWED_HOSTS": "x,y", "CORS_ALLOWED_ORIGINS": "https://c", "SERVER_PORT": "4999",
                       "LOG_LEVEL": "DEBUG", "HEALTH_CHECK_SECONDS": "44", "OAUTH_CIMD_ENABLED": "false"}.items():
        monkeypatch.setenv(var, value)
    old, new = both()
    assert old == new
    assert new["oauth"]["access_expire_minutes"] == 7 and new["server"]["port"] == 4999


def test_sections_from_every_file_are_merged(tmp_path, restore_config):
    write_dir(tmp_path, database={"database": {"pool_size": 9}}, oauth={"oauth": {"issuer": "http://x:5001"}},
              identity={"identity": {"local_enabled": False}, "session": {"expire_hours": 2}},
              security={"cors": {"allowed_origins": "https://a, https://b"}}, system={"logging": {"level": "DEBUG"}})
    Config.set_config_dir(str(tmp_path))
    m = Config.get_config_model()
    assert (m.database.pool_size, m.oauth.issuer, m.identity.local_enabled, m.session.expire_hours) == \
        (9, "http://x:5001", False, 2)
    assert m.cors.allowed_origins == ["https://a", "https://b"] and m.logging.level == "DEBUG"
    assert m.effective_port == 5001


def test_different_keys_of_one_section_may_come_from_two_files(tmp_path):
    write_dir(tmp_path, oauth={"oauth": {"issuer": "http://x:5001"}},
              security={"oauth": {"cimd": {"enabled": False}}})
    raw = load_config_dir(tmp_path)
    assert raw["oauth"] == {"issuer": "http://x:5001", "cimd": {"enabled": False}}


@pytest.mark.parametrize("second, path", [
    ({"oauth": {"issuer": "http://y"}}, "oauth.issuer"),
    ({"oauth": "flat"}, "oauth"),
    ({"oauth": {"cimd": 1}}, "oauth.cimd"),
])
def test_a_key_in_two_files_stops_startup_naming_both(tmp_path, second, path):
    write_dir(tmp_path, oauth={"oauth": {"issuer": "http://x", "cimd": {"enabled": True}}}, system=second)
    with pytest.raises(ConfigFileError) as exc:
        load_config_dir(tmp_path)
    assert f"'{path}'" in str(exc.value)
    assert "oauth.yaml" in str(exc.value) and "system.yaml" in str(exc.value)


def test_a_missing_file_stops_startup_listing_every_missing_one(tmp_path):
    write_dir(tmp_path)
    (tmp_path / "oauth.yaml").unlink()
    (tmp_path / "system.yaml").unlink()
    with pytest.raises(ConfigFileError) as exc:
        load_config_dir(tmp_path)
    assert f"Missing config file(s) in {tmp_path}: oauth.yaml, system.yaml." in str(exc.value)


def test_an_old_config_yaml_alone_is_not_enough(tmp_path):
    shutil.copy(OLD_FILE, tmp_path / "config.yaml")
    with pytest.raises(ConfigFileError, match="Missing config file"):
        load_config_dir(tmp_path)


@pytest.mark.parametrize("text, match", [("oauth: [", "not valid YAML"), ("- a\n- b\n", "must be a mapping")])
def test_a_broken_file_stops_startup(tmp_path, text, match):
    write_dir(tmp_path, identity=text)
    with pytest.raises(ConfigFileError, match=match):
        load_config_dir(tmp_path)


def test_env_references_take_effect(tmp_path, monkeypatch, restore_config):
    monkeypatch.setenv("OAUTH_ACCESS_EXPIRE_MINUTES", "9")
    monkeypatch.setenv("OAUTH_ISSUER", "http://127.0.0.1:4600")
    Config.set_config_dir(str(SHIPPED))
    assert Config.get_oauth_config().access_expire_minutes == 9
    assert Config.get_config_model().effective_port == 4600


def test_default_config_dir_follows_the_variable():
    assert default_config_dir({}) == "config"
    assert default_config_dir({"MCP_GATE_CONFIG_DIR": "/etc/mcp-gate"}) == "/etc/mcp-gate"


def test_an_old_config_yaml_or_variable_is_reported_and_ignored(tmp_path, restore_config, monkeypatch):
    monkeypatch.delenv("MCP_GATE_CONFIG", raising=False)
    write_dir(tmp_path, oauth={"oauth": {"issuer": "http://new:5001"}})
    assert startup_notices(tmp_path, {}) == []
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"oauth": {"issuer": "http://old:9999"}}))
    notices = startup_notices(tmp_path, {"MCP_GATE_CONFIG": "config/config.yaml"})
    assert len(notices) == 2
    assert "config.yaml is no longer read" in notices[0] and "Upgrading to 1.4" in notices[0]
    assert "MCP_GATE_CONFIG is no longer read" in notices[1] and "MCP_GATE_CONFIG_DIR" in notices[1]
    Config.set_config_dir(str(tmp_path))
    assert Config.get_oauth_config().issuer == "http://new:5001"      # the old file's value is ignored
    assert len(Config.get_startup_notices()) == 1


def test_the_old_file_notice_reaches_the_log_file(tmp_path, monkeypatch, restore_config):
    """The notice is found before logging is set up; main() must log it once the log files exist (Folio logged
    its equivalent to stderr only)."""
    import main
    from loguru import logger

    log_dir = tmp_path / "logs"
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    for name in CONFIG_FILES:
        shutil.copy(SHIPPED / name, cfg / name)
    system = yaml.safe_load((cfg / "system.yaml").read_text())
    system["logging"]["log_dir"] = str(log_dir)
    system["logging"]["level"] = "WARNING"
    (cfg / "system.yaml").write_text(yaml.safe_dump(system))
    shutil.copy(OLD_FILE, cfg / "config.yaml")

    def stop(**_):
        raise RuntimeError("stop here")

    monkeypatch.setattr(main, "init_database", stop)
    monkeypatch.setattr("sys.argv", ["main.py", "--config-dir", str(cfg)])
    try:
        with pytest.raises(SystemExit):
            main.main()
        logger.complete()
    finally:
        logger.remove()
    text = "".join(p.read_text() for p in log_dir.glob("app_*.log"))
    assert "config.yaml is no longer read" in text
    assert "config.yaml is no longer read" in "".join(p.read_text() for p in log_dir.glob("error_*.log"))


# ---- scripts/split_config.py ----

def run_split(*args):
    import importlib.util
    spec = importlib.util.spec_from_file_location("split_config", ROOT / "scripts" / "split_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main(list(args))


def test_split_script_reproduces_the_old_file(tmp_path, capsys):
    out = tmp_path / "out"
    assert run_split("--old", str(OLD_FILE), "--out-dir", str(out), "--env-file", "") == 0
    assert "Check passed" in capsys.readouterr().out
    for name, sections in FILE_SECTIONS.items():
        text = (out / name).read_text()
        assert sorted(yaml.safe_load(text)) == sorted(sections)
    # Comments and ${VAR} references are copied verbatim
    oauth = (out / "oauth.yaml").read_text()
    assert "# Written into the iss of every JWT" in oauth and '"${OAUTH_ISSUER:-http://localhost:4568}"' in oauth
    assert "# Background jobs" in (out / "system.yaml").read_text()
    assert "MCP Gate configuration file" not in oauth   # the old file header is not copied into a section


def test_split_script_keeps_edits_and_refuses_to_overwrite(tmp_path, capsys):
    old = tmp_path / "config.yaml"
    old.write_text(OLD_FILE.read_text().replace("pool_size: 5", "pool_size: 17")
                   + "\n# trailing\nunknown_section:\n  a: 1\n")
    out = write_dir(tmp_path / "out")
    assert run_split("--old", str(old), "--out-dir", str(out), "--env-file", "") == 2
    assert "--force" in capsys.readouterr().err
    assert run_split("--old", str(old), "--out-dir", str(out), "--env-file", "", "--force") == 0
    printed = capsys.readouterr().out
    assert "unknown_section" in printed and "Check passed" in printed
    assert ConfigModel(**expand_env_vars(load_config_dir(out))).database.pool_size == 17


def test_split_script_rejects_a_section_written_twice(tmp_path):
    from src.config.split import split_text
    with pytest.raises(ValueError, match="twice"):
        split_text("database:\n  pool_size: 1\nserver:\n  port: 1\ndatabase:\n  echo: true\n")
    assert run_split("--old", str(tmp_path / "nope.yaml"), "--out-dir", str(tmp_path / "o")) == 2
