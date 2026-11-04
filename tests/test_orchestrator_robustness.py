"""Orchestrator robustness (#36): port reuse, MCP-level readiness, stop failures that must not be swallowed,
failure logs kept in last_error, per-process locking, atomic env-var restarts, 503 when the runtime is down,
and catalog transport validation. Everything runs against a fake runtime -- there is no Docker daemon here."""

import random
import socket
import threading
import uuid

import pytest
import requests
from docker import errors as docker_errors

from db.models import AuditLog, ManagedMcpProcess
from src.marketplace.loader import CatalogLoader
from src.marketplace.schema import DockerSpec
from src.orchestrator import docker_runtime as docker_runtime_mod
from src.orchestrator import manager as manager_mod
from src.orchestrator.docker_runtime import DockerRuntime, DockerRuntimeError, DockerUnavailableError
from src.orchestrator.manager import Orchestrator, OrchestratorError, _compose_last_error
from src.orchestrator.port_allocator import PortAllocator
from src.orchestrator.process_runtime import ProcessRuntime, ProcessRuntimeError
from src.orchestrator.runtime import RuntimeUnavailableError
from tests.test_orchestrator_runtime import FakeRuntime, _deploy_byo


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _SilentListener(threading.Thread):
    """Accepts TCP connections and closes them without a word -- what Docker's port proxy does while the
    server inside the container is not up yet."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(5)
        self._stop = threading.Event()

    def run(self):
        self.sock.settimeout(0.1)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            conn.close()

    def close(self):
        self._stop.set()
        self.join(timeout=2)
        self.sock.close()


class ProxyOnlyRuntime(FakeRuntime):
    """The port opens but nothing ever answers MCP; the instance logs plenty before dying."""

    def launch(self, request, progress):
        self.calls.append(("launch", request))
        srv = _SilentListener(request.host_port)
        srv.start()
        self.running[request.name] = srv

    def logs(self, name, tail=200):
        lines = [f"log line {i}" for i in range(1, 101)]
        return "\n".join(lines[-tail:])


def _free_range_allocator(size=20):
    """A random range below the kernel's ephemeral ports (outgoing connections would make it flaky)."""
    return PortAllocator(start_port=random.randrange(20000, 30000, size), range_size=size)


def _make_orchestrator(monkeypatch, runtime, timeout=10.0):
    orch = Orchestrator(port_allocator=_free_range_allocator(), runtime=runtime)
    monkeypatch.setattr(manager_mod, "_orchestrator", orch)
    monkeypatch.setattr(manager_mod, "_START_TIMEOUT_STDIO", timeout)
    monkeypatch.setattr(manager_mod, "_START_TIMEOUT_HTTP", timeout)
    return orch


@pytest.fixture
def fake(monkeypatch):
    rt = FakeRuntime()
    orch = _make_orchestrator(monkeypatch, rt)
    yield orch, rt
    rt.close_all()


def _process(db_session, process_id):
    db_session.expire_all()
    return db_session.query(ManagedMcpProcess).filter(ManagedMcpProcess.id == uuid.UUID(process_id)).first()


def _name_of(rt, process_id):
    return next(c[1].name for c in rt.calls if c[0] == "launch" and c[1].labels["mcp-gate.process"] == process_id)


# ---------------------------------------------------------------------------
# 1. port reuse
# ---------------------------------------------------------------------------
def test_restart_keeps_port_even_when_a_lower_one_frees_up(owner_client, fake):
    orch, rt = fake
    a = _deploy_byo(owner_client, "a")
    b = _deploy_byo(owner_client, "b")
    assert a["port"] < b["port"]
    assert owner_client.delete(f"/api/managed/{a['id']}").status_code == 200   # a's lower port is free again

    r = owner_client.post(f"/api/managed/{b['id']}/start")     # restart while running
    assert r.status_code == 200, r.text
    assert r.json()["process"]["port"] == b["port"]
    assert r.json()["process"]["last_error"] is None
    services = owner_client.get("/api/services").json()["services"]
    assert next(s for s in services if s["id"] == b["service_id"])["port"] == b["port"]

    # stop + start (not in memory any more) keeps it too
    assert owner_client.post(f"/api/managed/{b['id']}/stop").status_code == 200
    r = owner_client.post(f"/api/managed/{b['id']}/start")
    assert r.json()["process"]["port"] == b["port"]


def test_port_taken_by_someone_else_moves_visibly(owner_client, fake):
    orch, rt = fake
    a = _deploy_byo(owner_client, "a")
    assert owner_client.post(f"/api/managed/{a['id']}/stop").status_code == 200
    squatter = socket.socket()
    squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    squatter.bind(("127.0.0.1", a["port"]))
    squatter.listen(1)
    try:
        r = owner_client.post(f"/api/managed/{a['id']}/start")
    finally:
        squatter.close()
    assert r.status_code == 200, r.text
    proc = r.json()["process"]
    assert proc["port"] != a["port"] and proc["actual_state"] == "running"
    assert f"Port {a['port']} could not be reused" in proc["last_error"] and str(proc["port"]) in proc["last_error"]


def test_manual_port_in_use_fails_instead_of_moving(owner_client, fake):
    orch, rt = fake
    squatter = socket.socket()
    squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    squatter.bind(("127.0.0.1", 0))
    squatter.listen(1)
    port = squatter.getsockname()[1]
    try:
        r = owner_client.post("/api/byo-mcp", json={"name": "m", "command": "npx", "args": ["-y", "x"],
                                                    "env_schema": []})
        r = owner_client.post(f"/api/byo-mcp/{r.json()['id']}/deploy", json={"name": "m", "port": port})
    finally:
        squatter.close()
    body = r.json()
    assert body["success"] is False
    assert body["process"]["actual_state"] == "failed" and body["process"]["port"] == port
    assert f"Configured port {port} is not available" in body["process"]["last_error"]
    assert not [c for c in rt.calls if c[0] == "launch"]


def test_port_allocator_prefers_own_port(db_session):
    alloc = _free_range_allocator()
    first = alloc.allocate(db_session)
    assert alloc.allocate(db_session, preferred_port=first + 3) == first + 3
    assert alloc.unavailable_reason(db_session, first) is None


# ---------------------------------------------------------------------------
# 2 + 4. MCP-level readiness; logs kept and the instance removed on failure
# ---------------------------------------------------------------------------
def test_open_port_without_mcp_answer_fails_start_with_logs(owner_client, monkeypatch, db_session):
    rt = ProxyOnlyRuntime()
    orch = _make_orchestrator(monkeypatch, rt, timeout=1.5)
    try:
        r = owner_client.post("/api/byo-mcp", json={"name": "p", "command": "npx", "args": ["-y", "x"],
                                                    "env_schema": []})
        r = owner_client.post(f"/api/byo-mcp/{r.json()['id']}/deploy", json={"name": "p"})
        body = r.json()
        assert body["success"] is False
        proc = body["process"]
        assert proc["actual_state"] == "failed" and proc["container_id"] is None
        err = proc["last_error"]
        assert "MCP initialize" in err and "did not succeed" in err
        assert "--- last 50 log lines ---" in err and "log line 100" in err and "log line 50\n" not in err
        name = _name_of(rt, proc["id"])
        assert ("remove", name) in rt.calls and name not in rt.running
        assert proc["id"] not in orch._active
    finally:
        rt.close_all()


def test_failure_after_launch_tears_instance_down(owner_client, fake, monkeypatch):
    orch, rt = fake

    def broken(*args, **kwargs):
        raise RuntimeError("service table is on fire")
    monkeypatch.setattr(Orchestrator, "_ensure_service", staticmethod(broken))
    r = owner_client.post("/api/byo-mcp", json={"name": "s", "command": "npx", "args": ["-y", "x"], "env_schema": []})
    r = owner_client.post(f"/api/byo-mcp/{r.json()['id']}/deploy", json={"name": "s"})
    body = r.json()
    assert body["success"] is False
    proc = body["process"]
    assert proc["actual_state"] == "failed" and "service table is on fire" in proc["last_error"]
    assert "[fake]" in proc["last_error"]                 # the log tail made it in
    assert rt.running == {} and proc["id"] not in orch._active


def test_probe_accepts_jsonrpc_error_and_rejects_silence():
    class _Answer(threading.Thread):
        def __init__(self, payload):
            super().__init__(daemon=True)
            self.sock = socket.socket()
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(1)
            self.port = self.sock.getsockname()[1]
            self.payload = payload

        def run(self):
            conn, _ = self.sock.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(self.payload)
            self.sock.close()

    srv = _Answer(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 60\r\n\r\n'
                  b'{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"x"}}')
    srv.start()
    assert Orchestrator._probe_initialize(srv.port, "/mcp", 5)[0] is True
    srv = _Answer(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    srv.start()
    ok, detail = Orchestrator._probe_initialize(srv.port, "/mcp", 5)
    assert ok is False and "502" in detail


def test_compose_last_error_keeps_the_newest_output():
    text = _compose_last_error("boom", "x" * 10000 + "THE END")
    assert len(text) <= manager_mod._LAST_ERROR_MAX_CHARS
    assert text.startswith("boom\n") and text.endswith("THE END")


# ---------------------------------------------------------------------------
# 3 + 6. stop failures are not swallowed; the runtime being down is a 503
# ---------------------------------------------------------------------------
def test_stop_failure_keeps_record_and_reports(owner_client, fake, db_session):
    orch, rt = fake
    a = _deploy_byo(owner_client, "a")

    def refuse(name):
        raise RuntimeError("daemon said no")
    rt.stop = refuse

    r = owner_client.post(f"/api/managed/{a['id']}/stop")
    assert r.status_code == 500 and r.json()["detail"]["error"] == "managed.stop_failed"
    proc = _process(db_session, a["id"])
    assert proc.actual_state == "stop_failed" and "daemon said no" in proc.last_error
    assert a["id"] in orch._active

    r = owner_client.delete(f"/api/managed/{a['id']}")
    assert r.status_code == 500 and r.json()["detail"]["error"] == "managed.uninstall_stop_failed"
    assert owner_client.get(f"/api/managed/{a['id']}").status_code == 200   # record kept
    failures = db_session.query(AuditLog).filter(AuditLog.resource_id == a["id"],
                                                 AuditLog.status == "failure").all()
    assert failures


def test_runtime_unavailable_is_503(owner_client, fake, db_session):
    orch, rt = fake
    a = _deploy_byo(owner_client, "a")

    def down(*args, **kwargs):
        raise RuntimeUnavailableError("Cannot connect to Docker daemon")
    rt.stop = down
    rt.launch = down
    rt.availability = lambda: (False, "Cannot connect to Docker daemon")

    for method, url in (("post", f"/api/managed/{a['id']}/stop"), ("post", f"/api/managed/{a['id']}/start"),
                        ("delete", f"/api/managed/{a['id']}")):
        r = getattr(owner_client, method)(url)
        assert r.status_code == 503, (url, r.text)
        assert r.json()["detail"]["error"] == "managed.runtime_unavailable"
    assert owner_client.get(f"/api/managed/{a['id']}").status_code == 200


def test_generic_launch_error_with_runtime_down_is_503(owner_client, fake):
    orch, rt = fake
    a = _deploy_byo(owner_client, "a")
    assert owner_client.post(f"/api/managed/{a['id']}/stop").status_code == 200
    rt.fail_launch = True
    rt.availability = lambda: (False, "no daemon")
    r = owner_client.post(f"/api/managed/{a['id']}/start")
    assert r.status_code == 503 and "no daemon" in r.json()["detail"]["params"]["reason"]


class _FakeContainer:
    def __init__(self, exc=None):
        self.exc = exc

    def stop(self, timeout=10):
        if self.exc:
            raise self.exc

    def remove(self, force=False):
        if self.exc:
            raise self.exc


class _FakeContainers:
    def __init__(self, get_exc=None, op_exc=None):
        self.get_exc, self.op_exc = get_exc, op_exc

    def get(self, name):
        if self.get_exc:
            raise self.get_exc
        return _FakeContainer(self.op_exc)


class _FakeClient:
    def __init__(self, **kw):
        self.containers = _FakeContainers(**kw)


def _docker_with(**kw):
    rt = DockerRuntime()
    rt._docker = _FakeClient(**kw)
    return rt


def _api_error(status, message):
    resp = requests.Response()
    resp.status_code = status
    return docker_errors.APIError(message, response=resp, explanation=message)


def test_docker_runtime_stop_remove_error_classes(monkeypatch):
    gone = _docker_with(get_exc=docker_errors.NotFound("no such container"))
    gone.stop("x")
    gone.remove("x")
    _docker_with(op_exc=_api_error(409, "removal of container x is already in progress")).remove("x")

    broken = _docker_with(op_exc=_api_error(500, "driver failed"))
    with pytest.raises(DockerRuntimeError, match="driver failed"):
        broken.stop("x")
    with pytest.raises(DockerRuntimeError, match="driver failed"):
        broken.remove("x")

    down = _docker_with(get_exc=requests.exceptions.ConnectionError("refused"))
    with pytest.raises(DockerUnavailableError):
        down.stop("x")
    with pytest.raises(DockerUnavailableError):
        down.remove("x")

    def no_daemon():
        raise docker_errors.DockerException("Error while fetching server API version")
    monkeypatch.setattr(docker_runtime_mod.docker, "from_env", no_daemon)
    with pytest.raises(RuntimeUnavailableError):
        DockerRuntime().stop("x")
    assert DockerRuntime().availability()[0] is False


def test_process_runtime_stop_raises_when_it_cannot_signal(tmp_path, monkeypatch):
    rt = ProcessRuntime(state_dir=str(tmp_path))
    tmp_path.joinpath("n.pid").write_text("424242")
    monkeypatch.setattr(rt, "_pid_is_ours", lambda pid, name: True)

    def eperm(*args):
        raise PermissionError("Operation not permitted")
    monkeypatch.setattr("os.killpg", eperm)
    monkeypatch.setattr("os.kill", eperm)
    with pytest.raises(ProcessRuntimeError, match="cannot signal"):
        rt.stop("n")
    # nothing left to remove is fine; already-dead pids are fine
    rt.remove("missing")
    monkeypatch.setattr(rt, "_pid_is_ours", lambda pid, name: False)
    rt.stop("n")


# ---------------------------------------------------------------------------
# 5. per-process locks; atomic env update + restart (catalog-independent, so BYO works)
# ---------------------------------------------------------------------------
def test_one_busy_process_does_not_block_another(owner_client, fake, db_session):
    orch, rt = fake
    a = _deploy_byo(owner_client, "a")
    b = _deploy_byo(owner_client, "b")
    lock_a = orch._process_lock(a["id"])
    lock_a.acquire()                       # e.g. a 300 s cold start in progress for a
    try:
        done = threading.Event()
        errors = []

        def stop_b():
            from db.database import make_session
            s = make_session()
            try:
                orch.stop(s, b["id"])
            except Exception as e:  # pragma: no cover - reported below
                errors.append(e)
            finally:
                s.close()
                done.set()
        threading.Thread(target=stop_b, daemon=True).start()
        assert done.wait(10), "stopping b waited on a's lock"
        assert not errors
    finally:
        lock_a.release()
    assert _process(db_session, b["id"]).actual_state == "stopped"


def _deploy_byo_with_env(owner_client, name="envy"):
    r = owner_client.post("/api/byo-mcp", json={
        "name": name, "command": "npx", "args": ["-y", "@example/echo"],
        "env_schema": [{"name": "API_KEY", "secret": True, "required": False}],
    })
    assert r.status_code == 200, r.text
    r = owner_client.post(f"/api/byo-mcp/{r.json()['id']}/deploy", json={"name": name, "env_vars": {"API_KEY": "1"}})
    assert r.json()["success"] is True, r.text
    return r.json()["process"]


def test_byo_env_update_restarts_atomically(owner_client, fake, db_session):
    orch, rt = fake
    p = _deploy_byo_with_env(owner_client)

    r = owner_client.put(f"/api/managed/{p['id']}/env-vars", json={"env_vars": {"API_KEY": "2"}})
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "Env vars updated and restarted"
    assert r.json()["process"]["actual_state"] == "running" and r.json()["process"]["port"] == p["port"]
    launches = [c[1] for c in rt.calls if c[0] == "launch"]
    assert len(launches) == 2 and launches[-1].env == {"API_KEY": "2"}

    r = owner_client.put(f"/api/managed/{p['id']}/env-vars", json={"env_vars": {"NOPE": "x"}})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "byo.unknown_env_vars"


def test_failed_env_restart_is_marked_and_audited(owner_client, fake, db_session):
    orch, rt = fake
    p = _deploy_byo_with_env(owner_client)
    rt.fail_launch = True
    r = owner_client.put(f"/api/managed/{p['id']}/env-vars", json={"env_vars": {"API_KEY": "3"}})
    assert r.status_code == 500 and r.json()["detail"]["error"] == "managed.env_updated_restart_failed"
    proc = _process(db_session, p["id"])
    assert proc.actual_state == "failed" and "boom" in proc.last_error
    assert proc.get_env_vars() == {"API_KEY": "3"}
    audit = db_session.query(AuditLog).filter(AuditLog.resource_id == p["id"], AuditLog.status == "failure").all()
    assert audit


def test_env_update_when_stop_fails_writes_nothing(owner_client, fake, db_session):
    orch, rt = fake
    p = _deploy_byo_with_env(owner_client)

    def refuse(name):
        raise RuntimeError("cannot stop")
    rt.stop = refuse
    r = owner_client.put(f"/api/managed/{p['id']}/env-vars", json={"env_vars": {"API_KEY": "9"}})
    assert r.status_code == 500 and r.json()["detail"]["error"] == "managed.stop_failed"
    proc = _process(db_session, p["id"])
    assert proc.actual_state == "stop_failed" and proc.get_env_vars() == {"API_KEY": "1"}


def test_update_env_and_restart_on_stopped_process_only_writes(owner_client, fake, db_session):
    orch, rt = fake
    p = _deploy_byo_with_env(owner_client)
    assert owner_client.post(f"/api/managed/{p['id']}/stop").status_code == 200
    launches = len([c for c in rt.calls if c[0] == "launch"])
    proc, restarted = orch.update_env_and_restart(db_session, p["id"], {"API_KEY": "5"})
    assert restarted is False and proc.actual_state == "stopped" and proc.get_env_vars() == {"API_KEY": "5"}
    assert len([c for c in rt.calls if c[0] == "launch"]) == launches
    with pytest.raises(OrchestratorError):
        orch.update_env_and_restart(db_session, str(uuid.uuid4()), {})


# ---------------------------------------------------------------------------
# 7. catalog transport
# ---------------------------------------------------------------------------
def test_catalog_transport_must_be_http(tmp_path):
    assert DockerSpec(image="mcp/x", transport="http").transport == "http"
    with pytest.raises(ValueError, match="transport"):
        DockerSpec(image="mcp/x", transport="stdio")
    (tmp_path / "bad.yaml").write_text(
        "id: bad\nname: Bad\ndescription: d\ndocker:\n  image: mcp/x\n  transport: sse\n"
    )
    (tmp_path / "good.yaml").write_text("id: good\nname: Good\ndescription: d\ndocker:\n  image: mcp/x\n")
    loader = CatalogLoader(tmp_path)
    assert set(loader.load_all()) == {"good"}
    assert "transport" in loader.errors["bad.yaml"]
