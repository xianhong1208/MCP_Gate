"""One service whose health update fails must not sink the rest of the scheduled round.

On PostgreSQL a failed flush (e.g. an over-long error text, known #14) leaves the session needing a rollback;
without one every later service in the round failed too, and reading the failed service's name in the
error handler raised again and ended the round.
"""

import asyncio
from unittest.mock import AsyncMock

from src.adapters import ServiceAdapter
from src.discovery import scanner as scanner_mod
from src.discovery.scanner import MCPVerifyResult
from src.scheduler.cleanup_scheduler import CleanupScheduler


def _make(owner_client, name, port):
    r = owner_client.post("/api/services", json={"name": name, "host": "127.0.0.1", "port": port,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_failed_update_rolls_back_and_the_round_goes_on(owner_client, monkeypatch):
    bad = _make(owner_client, "bad", 9401)
    good = _make(owner_client, "good", 9402)
    monkeypatch.setattr(scanner_mod.get_scanner(), "verify_mcp_service",
                        AsyncMock(return_value=MCPVerifyResult(success=True, server_name="x", reachable=True)))
    real_update = ServiceAdapter.update_health

    def update_health(db, service_id, **kw):
        if service_id == bad:
            svc = ServiceAdapter.get_by_id(db, service_id)
            svc.name = None  # NOT NULL -> IntegrityError on flush: the session now needs a rollback
            db.flush()
        return real_update(db=db, service_id=service_id, **kw)

    monkeypatch.setattr(ServiceAdapter, "update_health", staticmethod(update_health))
    results = asyncio.run(CleanupScheduler()._health_check_task())
    assert results["online"] == 1 and results["error"] == 1, results

    services = {s["id"]: s for s in owner_client.get("/api/services").json()["services"]}
    assert services[good]["health"]["status"] == "online"
    assert services[bad]["name"] == "bad"
