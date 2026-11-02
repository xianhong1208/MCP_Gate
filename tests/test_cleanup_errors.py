"""Known #23: a failing clean-up job was logged and counted as 0, and the API answered "Cleanup completed"."""

from src.adapters import TokenUsageAdapter
from src.scheduler.cleanup_scheduler import CleanupScheduler


def _boom(*a, **k):
    raise RuntimeError("disk I/O error")


def test_manual_cleanup_reports_failed_jobs(owner_client, monkeypatch):
    monkeypatch.setattr(TokenUsageAdapter, "delete_older_than", staticmethod(_boom))
    r = owner_client.post("/api/system/cleanup/run")
    assert r.status_code == 500, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "system.cleanup_failed"
    assert detail["params"]["jobs"] == "old_usage"
    assert detail["results"]["expired_oauth"] == 0 and detail["results"]["old_usage"] is None
    assert "disk I/O error" not in r.text

    logs = owner_client.get("/api/audit/logs", params={"action": "cleanup_expired"}).json()["logs"]
    assert logs and logs[0]["status"] == "failure"


def test_manual_cleanup_success_still_200(owner_client):
    r = owner_client.post("/api/system/cleanup/run")
    assert r.status_code == 200, r.text
    assert r.json()["results"] == {"expired_oauth": 0, "old_usage": 0, "old_audit_logs": 0}


async def test_scheduled_job_still_swallows_and_logs(monkeypatch, engine):
    monkeypatch.setattr(TokenUsageAdapter, "delete_older_than", staticmethod(_boom))
    assert await CleanupScheduler()._cleanup_old_usage() == 0
