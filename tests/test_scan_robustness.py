"""Known #16 / #20: one bad host or one bad server must not sink the whole scan.

#16: a host resolving to a blocked address (link-local / cloud metadata) raised ScannerSSRFError out of
     scan_ports, and the whole scan answered 500 "Scan failed" for every host.
#20: auto-register ran create -> sync tools -> health as separate commits; any failure aborted the scan with
     a 500 while the services registered before it (and the half-registered one) stayed in the database.
"""

import socket
from unittest.mock import AsyncMock

import pytest

from src.adapters import MCPToolAdapter, ServiceAdapter
from src.adapters.exceptions import ConflictError
from src.discovery import scanner as scanner_mod
from src.discovery.scanner import DiscoveredService, MCPScanner, MCPToolInfo, MCPVerifyResult


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- #16 -------------------------------------------------------------------------------------------
async def test_blocked_host_is_skipped_not_fatal():
    errors = []
    found = await MCPScanner(timeout=0.5).discover_services(
        hosts=["169.254.169.254", "127.0.0.1"], ports=[_closed_port()], host_errors=errors)
    assert found == []
    assert [(e["host"], e["error"]) for e in errors] == [("169.254.169.254", "discovery.address_blocked")]


def test_scan_reports_blocked_hosts_per_host(owner_client):
    r = owner_client.post("/api/discovery/scan", json={"hosts": ["169.254.169.254", "127.0.0.1"],
                                                       "ports": [_closed_port()], "auto_register": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert [(h["host"], h["error"]) for h in body["skipped_hosts"]] == [("169.254.169.254", "discovery.address_blocked")]
    assert body["skipped_hosts"][0]["params"] == {"host": "169.254.169.254"}


# ---- #20 -------------------------------------------------------------------------------------------
def _found(port, name):
    return DiscoveredService(host="127.0.0.1", port=port,
                             verify_result=MCPVerifyResult(success=True, server_name=name, reachable=True),
                             tools=[MCPToolInfo(name="t", description="d", input_schema={})])


@pytest.fixture
def three_servers(monkeypatch):
    monkeypatch.setattr(scanner_mod.get_scanner(), "discover_services",
                        AsyncMock(return_value=[_found(9301, "one"), _found(9302, "two"), _found(9303, "three")]))


def _services(owner_client):
    return {(s["host"], s["port"]): s for s in owner_client.get("/api/services").json()["services"]}


def test_one_failing_registration_does_not_abort_the_scan(owner_client, three_servers, monkeypatch):
    real_sync = MCPToolAdapter.sync_tools

    def flaky(db, service_id, tools):
        svc = ServiceAdapter.get_by_id(db, service_id)
        if svc.port == 9302:
            raise RuntimeError("database went away")
        return real_sync(db, service_id, tools)

    monkeypatch.setattr(MCPToolAdapter, "sync_tools", staticmethod(flaky))
    r = owner_client.post("/api/discovery/scan", json={"hosts": ["127.0.0.1"], "ports": [9301, 9302, 9303]})
    assert r.status_code == 200, r.text
    body = r.json()
    by_port = {d["port"]: d for d in body["discovered"]}
    assert by_port[9301]["registered"] and by_port[9303]["registered"]
    assert by_port[9302]["registered"] is False and by_port[9302]["service_id"] is None
    assert by_port[9302]["register_error"]["error"] == "discovery.register_failed"
    assert "database went away" not in r.text  # internal detail stays in the log
    assert body["registered_count"] == 2

    services = _services(owner_client)
    assert ("127.0.0.1", 9302) not in services  # rolled back, not half-registered
    assert {("127.0.0.1", 9301), ("127.0.0.1", 9303)} <= set(services)
    assert services[("127.0.0.1", 9301)]["health"]["status"] == "online"


def test_adapter_errors_keep_their_code(owner_client, three_servers, monkeypatch):
    real_create = ServiceAdapter.create

    def create(db, **kw):
        if kw["port"] == 9301:
            raise ConflictError(code="service.duplicate", fallback="dup")
        return real_create(db=db, **kw)

    monkeypatch.setattr(ServiceAdapter, "create", staticmethod(create))
    r = owner_client.post("/api/discovery/scan", json={"hosts": ["127.0.0.1"], "ports": [9301, 9302, 9303]})
    assert r.status_code == 200, r.text
    first = next(d for d in r.json()["discovered"] if d["port"] == 9301)
    assert first["register_error"]["error"] == "service.duplicate" and not first["registered"]
    assert r.json()["registered_count"] == 2
