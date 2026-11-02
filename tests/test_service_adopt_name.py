"""Health check replaces a generated placeholder name with the server's real name - and nothing else."""
from types import SimpleNamespace

import pytest

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


# ---- description (#34): filled from serverInfo only while empty or generated ----

def _dsvc(description, host="127.0.0.1", port=5055):
    return SimpleNamespace(id="sid", description=description, host=host, port=port)


def _capture_updates(monkeypatch):
    calls = []
    monkeypatch.setattr(ServiceAdapter, "update", classmethod(lambda cls, db, sid, **kw: calls.append(kw)))
    return calls


def test_describe_server():
    from src.adapters import describe_server

    assert describe_server("AnyDoc", "1.2", "Converts documents") == "Converts documents"
    assert describe_server("AnyDoc", "1.2") == "AnyDoc v1.2"
    assert describe_server("AnyDoc") == "AnyDoc"
    assert describe_server("(requires auth)") is None and describe_server(None) is None


@pytest.mark.parametrize("current", [None, "", "MCP service at 127.0.0.1:5055",
                                     "MCP service: AnyDoc v1.0\n\nold text"])
def test_empty_or_generated_description_is_filled(monkeypatch, current):
    calls = _capture_updates(monkeypatch)
    assert ServiceAdapter.adopt_server_description(None, _dsvc(current), "AnyDoc", "1.2") == "AnyDoc v1.2"
    assert calls == [{"description": "AnyDoc v1.2"}]


def test_operator_description_is_never_overwritten(monkeypatch):
    calls = _capture_updates(monkeypatch)
    assert ServiceAdapter.adopt_server_description(None, _dsvc("Our document converter"), "AnyDoc", "1.2",
                                                   "Converts documents") is None
    # locked servers tell us nothing
    assert ServiceAdapter.adopt_server_description(None, _dsvc(None), "(requires auth)") is None
    assert ServiceAdapter.adopt_server_description(None, _dsvc(None), None) is None
    assert calls == []


def _online(monkeypatch):
    from unittest.mock import AsyncMock

    from src.discovery import scanner as scanner_mod
    from src.discovery.scanner import MCPVerifyResult

    monkeypatch.setattr(scanner_mod.get_scanner(), "verify_mcp_service", AsyncMock(return_value=MCPVerifyResult(
        success=True, reachable=True, server_name="AnyDoc", server_version="1.2",
        server_description="Converts documents")))


def test_health_checks_keep_the_operator_description(owner_client, service, monkeypatch):
    """Manual and scheduled health checks used to overwrite every description with serverInfo."""
    _online(monkeypatch)
    assert owner_client.post(f"/api/services/{service['id']}/health-check").json()["status"] == "online"
    assert owner_client.post("/api/services/health-check-all").json()["online"] == 1
    assert owner_client.get(f"/api/services/{service['id']}").json()["description"] == "demo"


@pytest.mark.parametrize("path", ["/api/services/{id}/health-check", "/api/services/health-check-all"])
def test_health_checks_fill_an_empty_description(owner_client, monkeypatch, path):
    _online(monkeypatch)
    r = owner_client.post("/api/services", json={"name": "bare", "host": "127.0.0.1", "port": 8125})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert owner_client.post(path.format(id=sid)).status_code == 200
    assert owner_client.get(f"/api/services/{sid}").json()["description"] == "Converts documents"
