"""POST /api/discovery/scan validates its ports and caps the work one request can ask for (#34).

Before: no bounds at all -- port_range_end=10**9 built a billion-element list, a reversed range or a
start of 0 was silently ignored, and ports above 65535 just "found 0".
"""
from unittest.mock import AsyncMock

import pytest

from src.api.discovery_routes import MAX_SCAN_PROBES
from src.discovery import scanner as scanner_mod


@pytest.fixture
def discover(monkeypatch):
    fake = AsyncMock(return_value=[])
    monkeypatch.setattr(scanner_mod.get_scanner(), "discover_services", fake)
    return fake


def _scan(client, **body):
    body.setdefault("auto_register", False)
    return client.post("/api/discovery/scan", json=body)


@pytest.mark.parametrize("body, code", [
    ({"ports": [0]}, "discovery.invalid_port"),
    ({"ports": [70000]}, "discovery.invalid_port"),
    ({"ports": [-1]}, "discovery.invalid_port"),
    ({"ports": [], "port_range_start": 0, "port_range_end": 10}, "discovery.invalid_port_range"),
    ({"ports": [], "port_range_start": 9000, "port_range_end": 8000}, "discovery.invalid_port_range"),
    ({"ports": [], "port_range_start": 1, "port_range_end": 10**9}, "discovery.invalid_port_range"),
    ({"ports": [], "port_range_start": 8000}, "discovery.invalid_port_range"),
    ({"ports": []}, "discovery.no_ports"),
    ({"hosts": [], "ports": [8000]}, "discovery.no_hosts"),
    ({"hosts": ["a", "b"], "ports": [], "port_range_start": 1, "port_range_end": 65535},
     "discovery.too_many_probes"),
])
def test_bad_scans_are_rejected(owner_client, discover, body, code):
    r = _scan(owner_client, **body)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["error"] == code and detail["fallback"]
    discover.assert_not_awaited()


def test_too_many_probes_reports_the_numbers(owner_client, discover):
    r = _scan(owner_client, hosts=["a", "b"], ports=[], port_range_start=1, port_range_end=65535)
    assert r.json()["detail"]["params"] == {"hosts": 2, "ports": 65535, "limit": MAX_SCAN_PROBES}


def test_valid_scan_merges_ports_and_range(owner_client, discover):
    r = _scan(owner_client, hosts=["127.0.0.1"], ports=[8080, 3000], port_range_start=3000, port_range_end=3002)
    assert r.status_code == 200, r.text
    assert discover.await_args.kwargs["ports"] == [3000, 3001, 3002, 8080]
    assert r.json()["scanned_ports"] == 4


def test_a_full_port_range_on_one_host_is_allowed(owner_client, discover):
    r = _scan(owner_client, hosts=["127.0.0.1"], ports=[], port_range_start=1, port_range_end=65535)
    assert r.status_code == 200, r.text


def test_absurd_payloads_are_refused_by_the_schema(owner_client, discover):
    assert _scan(owner_client, ports=list(range(1, 65537))).status_code == 422
    assert _scan(owner_client, hosts=["h" * 300], ports=[80]).status_code == 422
    discover.assert_not_awaited()
