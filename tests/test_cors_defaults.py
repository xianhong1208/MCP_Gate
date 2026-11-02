"""H-15: the shipped configuration must not give a dev-server origin credentialed access to the admin API.

``http://localhost:5173`` (Vite's default port) was in both the model default and config/config.yaml with
``allow_credentials: true``: any app served on that port (any project's dev server, a malicious dev dependency)
could read and drive the admin API from the owner's browser. The console is same-origin and needs no CORS at all;
the Vite dev server now proxies with the backend's own Origin (frontend/vite.config.js).
"""
import os

from src.config.manager import Config
from src.config.model import CORSConfig, ConfigModel


def test_model_default_allows_no_extra_origins():
    assert CORSConfig().allowed_origins == []


def test_shipped_config_allows_no_extra_origins(monkeypatch):
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    previous = Config.get_config_model()
    try:
        Config.set_config(os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml"))
        assert Config.get_cors_config().allowed_origins == []
    finally:
        Config.set_model(previous)


def test_origins_can_be_opted_in_from_the_environment(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173, https://console.example ")
    previous = Config.get_config_model()
    try:
        Config.set_config(os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml"))
        assert Config.get_cors_config().allowed_origins == ["http://localhost:5173", "https://console.example"]
    finally:
        Config.set_model(previous)
    # A YAML list keeps working too
    assert ConfigModel(cors={"allowed_origins": ["http://a.example"]}).cors.allowed_origins == ["http://a.example"]


def test_vite_origin_gets_no_credentialed_cors(owner_client):
    r = owner_client.get("/api/session/me", headers={"origin": "http://localhost:5173"})
    assert "access-control-allow-origin" not in r.headers
    pre = owner_client.options("/api/session/me", headers={
        "origin": "http://localhost:5173", "access-control-request-method": "GET"})
    assert pre.headers.get("access-control-allow-origin") is None
