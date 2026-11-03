"""Startup does not wait for managed servers: reconcile restarts dead servers one after another (up to 300 s each
for a stdio cold start), so it runs in the background and the authorization server answers at once."""

import threading

from fastapi.testclient import TestClient


class _SlowOrchestrator:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()

    def reconcile(self, db):
        self.started.set()
        self.release.wait(10)
        self.finished.set()


def test_server_answers_while_reconcile_is_still_running(app, monkeypatch):
    import main
    from src.orchestrator import manager

    slow = _SlowOrchestrator()
    monkeypatch.setattr(manager, "get_orchestrator", lambda: slow)
    try:
        with TestClient(app, base_url="http://testserver") as c:  # runs the lifespan
            assert slow.started.wait(5), "reconcile was not started"
            assert c.get("/health").status_code == 200
            assert c.get("/.well-known/oauth-authorization-server").status_code == 200
            assert not slow.finished.is_set(), "startup waited for reconcile"
            slow.release.set()
        assert slow.finished.wait(5)
    finally:
        slow.release.set()
    assert main.RECONCILE_SHUTDOWN_WAIT_SECONDS <= 5


def test_reconcile_failure_is_logged_not_raised(app, monkeypatch):
    import main
    from src.orchestrator import manager

    def boom():
        raise RuntimeError("no runtime")

    monkeypatch.setattr(manager, "get_orchestrator", boom)
    main.reconcile_managed_servers()  # must not raise
    thread = main.start_managed_reconcile()
    thread.join(5)
    assert not thread.is_alive()
