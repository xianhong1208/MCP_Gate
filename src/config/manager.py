"""Configuration manager.

The configuration is five files under one directory (``config/`` by default, ``MCP_GATE_CONFIG_DIR`` to change
it), merged into one tree at startup; see ``src/config/layout.py`` for which section lives where.

Supports environment variable expansion:
- ${VAR_NAME}           required environment variable
- ${VAR_NAME:-default}  optional, with a default value
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.config.layout import (
    CONFIG_DIR_ENV, CONFIG_FILES, DEFAULT_CONFIG_DIR, LEGACY_CONFIG_ENV, LEGACY_CONFIG_FILE,
)
from src.config.model import (
    ConfigModel,
    CORSConfig,
    DatabaseConfig,
    IdentityConfig,
    OAuthConfig,
    RateLimitConfig,
    SchedulerConfig,
    SecurityConfig,
    SessionConfig,
)

ENV_VAR_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} / ${VAR:-default}."""
    if isinstance(value, str):
        def replacer(match):
            var_name = match.group(1)
            default_value = match.group(2)
            env_value = os.environ.get(var_name)
            if env_value is not None:
                return env_value
            if default_value is not None:
                return default_value
            raise ValueError(
                f"Environment variable '{var_name}' is not set and has no default value. "
                f"Please set it or provide a default in config: ${{{var_name}:-default}}"
            )
        return ENV_VAR_PATTERN.sub(replacer, value)
    if isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    return value


class ConfigFileError(ValueError):
    """The config directory cannot be loaded: a missing file, invalid YAML, or a key set in two files."""


def _merge_into(target: Dict[str, Any], data: Dict[str, Any], name: str, origins: Dict[str, str],
                prefix: str = "") -> None:
    """Merge one file's tree into ``target``. Mappings merge key by key; any other value set by two files is an
    error naming both."""
    for key, value in data.items():
        path = f"{prefix}{key}"
        if key not in target:
            target[key] = value
            _record(origins, path, value, name)
            continue
        if isinstance(target[key], dict) and isinstance(value, dict):
            _merge_into(target[key], value, name, origins, path + ".")
            continue
        first = origins.get(path) or _first_origin(origins, path)
        raise ConfigFileError(f"'{path}' is set in both {first} and {name}: keep it in one file only")


def _record(origins: Dict[str, str], path: str, value: Any, name: str) -> None:
    origins[path] = name
    if isinstance(value, dict):
        for key, child in value.items():
            _record(origins, f"{path}.{key}", child, name)


def _first_origin(origins: Dict[str, str], path: str) -> str:
    return next((n for p, n in origins.items() if p.startswith(path + ".")), "another file")


def default_config_dir(env=None) -> str:
    """The config directory: MCP_GATE_CONFIG_DIR, else ``config`` (relative to the working directory)."""
    env = os.environ if env is None else env
    return env.get(CONFIG_DIR_ENV) or DEFAULT_CONFIG_DIR


def load_config_dir(config_dir) -> Dict[str, Any]:
    """Read and merge the five files of ``config_dir`` (no ${VAR} expansion).

    Raises ConfigFileError for a missing file, invalid YAML, a file that is not a mapping, or a key set in two
    files."""
    config_dir = Path(config_dir)
    missing = [n for n in CONFIG_FILES if not (config_dir / n).is_file()]
    if missing:
        raise ConfigFileError(
            f"Missing config file(s) in {config_dir}: {', '.join(missing)}. MCP Gate needs all five: "
            f"{', '.join(CONFIG_FILES)} (see docs/reference.md, Upgrading to 1.4).")
    merged: Dict[str, Any] = {}
    origins: Dict[str, str] = {}
    for name in CONFIG_FILES:
        try:
            data = yaml.safe_load((config_dir / name).read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise ConfigFileError(f"{config_dir / name} is not valid YAML: {e}") from None
        if data is None:
            continue
        if not isinstance(data, dict):
            raise ConfigFileError(f"{config_dir / name} must be a mapping of settings")
        _merge_into(merged, data, name, origins)
    return merged


def startup_notices(config_dir, env=None) -> List[str]:
    """Errors about configuration that is no longer read: an old single config.yaml left in the config directory,
    or the old MCP_GATE_CONFIG variable. MCP Gate keeps running on the five files; these only say so."""
    env = os.environ if env is None else env
    notices = []
    legacy = Path(config_dir) / LEGACY_CONFIG_FILE
    if legacy.is_file():
        notices.append(
            f"{legacy} is no longer read: since MCP Gate 1.4 the configuration is {', '.join(CONFIG_FILES)} in "
            f"{config_dir}. Its values are IGNORED. If you edited it, move your edits into the matching file "
            "(docs/reference.md, Upgrading to 1.4), then delete it.")
    if env.get(LEGACY_CONFIG_ENV):
        notices.append(
            f"{LEGACY_CONFIG_ENV} is no longer read: set MCP_GATE_CONFIG_DIR to the directory holding the five "
            "config files instead (docs/reference.md, Upgrading to 1.4).")
    return notices


class Config:
    """Configuration manager (singleton). Provides built-in defaults until set_config is called, for tests and
    zero-config startup."""

    _config_model: Optional[ConfigModel] = None
    # Errors found while loading (an old config.yaml, MCP_GATE_CONFIG). They are kept rather than logged, because
    # set_config_dir runs before main.py sets up the log files from this very config; main.py logs them once the
    # files exist so they reach the log file and not only the terminal.
    _startup_notices: List[str] = []

    @classmethod
    def set_config_dir(cls, config_dir: str):
        cls._config_model = cls._load_config(config_dir)
        cls._startup_notices = startup_notices(config_dir)

    @classmethod
    def get_startup_notices(cls) -> List[str]:
        return list(cls._startup_notices)

    @classmethod
    def set_model(cls, model: ConfigModel):
        """Inject a config object directly (for tests)."""
        cls._config_model = model

    @classmethod
    def reset(cls):
        cls._config_model = None

    @classmethod
    def _load_config(cls, config_dir: str) -> ConfigModel:
        raw = load_config_dir(config_dir)
        # `${PORT:-4568}` expands to a string; pydantic lax mode coerces it to int / bool per the field type
        return ConfigModel(**expand_env_vars(raw))

    @classmethod
    def get_config_model(cls) -> ConfigModel:
        if cls._config_model is None:
            cls._config_model = ConfigModel()
        return cls._config_model

    @classmethod
    def get_database_config(cls) -> DatabaseConfig:
        return cls.get_config_model().database

    @classmethod
    def get_session_config(cls) -> SessionConfig:
        return cls.get_config_model().session

    @classmethod
    def get_oauth_config(cls) -> OAuthConfig:
        return cls.get_config_model().oauth

    @classmethod
    def get_identity_config(cls) -> IdentityConfig:
        return cls.get_config_model().identity

    @classmethod
    def get_rate_limit_config(cls) -> RateLimitConfig:
        return cls.get_config_model().rate_limit

    @classmethod
    def get_security_config(cls) -> SecurityConfig:
        return cls.get_config_model().security

    @classmethod
    def get_cors_config(cls) -> CORSConfig:
        return cls.get_config_model().cors

    @classmethod
    def get_scheduler_config(cls) -> SchedulerConfig:
        return cls.get_config_model().scheduler
