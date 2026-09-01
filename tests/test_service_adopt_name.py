"""Health check replaces a generated placeholder name with the server's real name - and nothing else."""
from types import SimpleNamespace

from src.adapters import ServiceAdapter, fallback_service_name, sanitize_server_name


def _svc(name, source="auto_discovered", host="127.0.0.1", port=5055):
    return SimpleNamespace(id="sid", name=name, source=source, host=host, port=port)


def test_helpers():
    assert fallback_service_name("127.0.0.1", 5055) == "mcp-127-0-0-1-5055"
    assert fallback_service_name("localhost", 5055) == "mcp-127-0-0-1-5055"
    assert sanitize_server_name("My Server/v2") == "My-Server-v2"


def test_placeholder_is_replaced(monkeypatch):
    calls = {}
    monkeypatch.setattr(ServiceAdapter, "get_by_name", staticmethod(lambda db, name: None))
    monkeypatch.setattr(ServiceAdapter, "update", classmethod(lambda cls, db, sid, **kw: calls.update(kw)))
    assert ServiceAdapter.adopt_server_name(None, _svc("mcp-127-0-0-1-5055"), "AnyDoc") == "AnyDoc"
    assert calls == {"name": "AnyDoc"}


def test_operator_name_and_manual_services_are_left_alone(monkeypatch):
    monkeypatch.setattr(ServiceAdapter, "get_by_name", staticmethod(lambda db, name: None))
    monkeypatch.setattr(ServiceAdapter, "update", classmethod(lambda cls, db, sid, **kw: (_ for _ in ()).throw(AssertionError("must not rename"))))
    assert ServiceAdapter.adopt_server_name(None, _svc("my-docs"), "AnyDoc") is None
    assert ServiceAdapter.adopt_server_name(None, _svc("mcp-127-0-0-1-5055", source="manual"), "AnyDoc") is None
    assert ServiceAdapter.adopt_server_name(None, _svc("mcp-127-0-0-1-5055"), "(requires auth)") is None
    assert ServiceAdapter.adopt_server_name(None, _svc("mcp-127-0-0-1-5055"), None) is None


def test_taken_name_is_not_stolen(monkeypatch):
    monkeypatch.setattr(ServiceAdapter, "get_by_name", staticmethod(lambda db, name: object()))
    monkeypatch.setattr(ServiceAdapter, "update", classmethod(lambda cls, db, sid, **kw: (_ for _ in ()).throw(AssertionError("must not rename"))))
    assert ServiceAdapter.adopt_server_name(None, _svc("mcp-127-0-0-1-5055"), "AnyDoc") is None
