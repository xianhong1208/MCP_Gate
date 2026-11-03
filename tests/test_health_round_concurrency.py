"""Health rounds check services concurrently (bounded), cut off a hanging server, and write a health row only when
the status changes, a failure streak is still counting, or the stored check is older than the write interval."""

import asyncio
import time
from datetime import timedelta

from src.adapters import ServiceAdapter
from src.discovery import scanner as scanner_mod
from src.discovery.scanner import MCPVerifyResult
from src.scheduler.cleanup_scheduler import CleanupScheduler


def _make(owner_client, name, port):
    r = owner_client.post("/api/services", json={"name": name, "host": "127.0.0.1", "port": port,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _health(owner_client, sid):
    return next(s for s in owner_client.get("/api/services").json()["services"] if s["id"] == sid)["health"]


def test_checks_run_concurrently_within_the_bound(owner_client, monkeypatch):
    for i in range(6):
        _make(owner_client, f"svc{i}", 9500 + i)
    in_flight, peak = [0], [0]

    async def verify(**kw):
        in_flight[0] += 1
        peak[0] = max(peak[0], in_flight[0])
        await asyncio.sleep(0.3)
        in_flight[0] -= 1
        return MCPVerifyResult(success=True, reachable=True)

    monkeypatch.setattr(scanner_mod.get_scanner(), "verify_mcp_service", verify)
    sched = CleanupScheduler()
    sched.health_check_concurrency = 3
    started = time.monotonic()
    results = asyncio.run(sched._health_check_task())
    elapsed = time.monotonic() - started
    assert results["online"] == 6, results
    assert peak[0] == 3
    assert elapsed < 6 * 0.3 * 0.75, elapsed  # serial would take 1.8 s; two waves of three take ~0.6 s


def test_a_hanging_server_is_cut_off(owner_client, monkeypatch):
    hung = _make(owner_client, "hung", 9601)
    fine = _make(owner_client, "fine", 9602)
    hung_port = 9601

    async def verify(**kw):
        if kw["port"] == hung_port:
            await asyncio.sleep(60)
        return MCPVerifyResult(success=True, reachable=True)

    monkeypatch.setattr(scanner_mod.get_scanner(), "verify_mcp_service", verify)
    sched = CleanupScheduler()
    sched.health_check_timeout_seconds = 0.2
    started = time.monotonic()
    results = asyncio.run(sched._health_check_task())
    assert time.monotonic() - started < 5
    assert results["online"] == 1 and results["error"] == 1, results
    assert _health(owner_client, fine)["status"] == "online"
    hung_health = _health(owner_client, hung)
    assert hung_health["status"] == "error" and "timed out" in hung_health["error_message"]


def test_unchanged_status_is_not_rewritten_every_round(owner_client, monkeypatch, db_session):
    sid = _make(owner_client, "steady", 9701)
    ok = [True]

    async def verify(**kw):
        return MCPVerifyResult(success=ok[0], reachable=True, error=None if ok[0] else "down")

    monkeypatch.setattr(scanner_mod.get_scanner(), "verify_mcp_service", verify)
    writes = []
    real_update = ServiceAdapter.update_health

    def update_health(db, service_id, **kw):
        writes.append(kw["status"])
        return real_update(db=db, service_id=service_id, **kw)

    monkeypatch.setattr(ServiceAdapter, "update_health", staticmethod(update_health))
    sched = CleanupScheduler()

    asyncio.run(sched._health_check_task())          # unknown -> online: written
    asyncio.run(sched._health_check_task())          # still online, fresh: skipped
    assert writes == ["online"]

    # once the stored check is older than the write interval it is refreshed
    svc = ServiceAdapter.get_by_id(db_session, sid)
    svc.health_last_checked -= timedelta(minutes=sched.health_write_interval_minutes + 1)
    db_session.commit()
    asyncio.run(sched._health_check_task())
    assert writes == ["online", "online"]

    # a failure streak is written check by check until it turns "offline", then only on the interval
    ok[0] = False
    for _ in range(5):
        asyncio.run(sched._health_check_task())
    assert writes == ["online", "online", "error", "error", "offline"]
    assert _health(owner_client, sid)["status"] == "offline"

    ok[0] = True                                     # status change: written at once
    asyncio.run(sched._health_check_task())
    assert writes[-1] == "online" and len(writes) == 6
