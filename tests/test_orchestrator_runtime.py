"""The orchestrator behind a Runtime: a fake runtime drives start/stop/reconcile through the public API without
Docker, and the process runtime runs a bring-your-own server as a local subprocess."""

import json
import socket
import stat
import threading
import time

import pytest

from src.orchestrator import manager as manager_mod
from src.orchestrator.manager import Orchestrator, OrchestratorError
from src.orchestrator.process_runtime import ProcessRuntime, ProcessRuntimeError
from src.orchestrator.runtime import LaunchRequest, Runtime, bridge_argv, select_runtime


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _MiniMcpServer(threading.Thread):
    """Answers every HTTP request on the port with a JSON-RPC result, enough for the port wait + warm-up."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(5)
        self.port = port
        self._stop = threading.Event()

    def run(self):
        self.sock.settimeout(0.2)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}}).encode()
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    conn.settimeout(1.0)
                    conn.recv(65536)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                                 + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self.join(timeout=2)
        self.sock.close()


class FakeRuntime(Runtime):
    """Records calls; `launch` opens a real listener on the host port so the orchestrator sees it come up."""
    name = "fake"

    def __init__(self, *, fail_launch=False):
        self.calls = []
        self.running = {}          # name -> _MiniMcpServer
        self.fail_launch = fail_launch

    def availability(self):
        return True, "fake"

    def image_exists(self, image_ref):
        self.calls.append(("image_exists", image_ref))
        return True

    def load_image(self, tar_path):
        return ["fake:latest"]

    def launch(self, request: LaunchRequest, progress):
        self.calls.append(("launch", request))
        progress("creating", request.name)
        if self.fail_launch:
            raise RuntimeError("boom")
        srv = _MiniMcpServer(request.host_port)
        srv.start()
        self.running[request.name] = srv

    def stop(self, name):
        self.calls.append(("stop", name))
        srv = self.running.pop(name, None)
        if srv:
            srv.close()

    def remove(self, name):
        self.calls.append(("remove", name))

    def instance_id(self, name, running_only=False):
        return f"fake-{name}" if name in self.running else None

    def logs(self, name, tail=200):
        return f"[fake] {name}"

    def close_all(self):
        for srv in list(self.running.values()):
            srv.close()
        self.running.clear()


@pytest.fixture
def fake_orchestrator(monkeypatch):
    rt = FakeRuntime()
    orch = Orchestrator(runtime=rt)
    monkeypatch.setattr(manager_mod, "_orchestrator", orch)
    monkeypatch.setattr(manager_mod, "_START_TIMEOUT_STDIO", 10.0)
    monkeypatch.setattr(manager_mod, "_START_TIMEOUT_HTTP", 10.0)
    yield orch, rt
    rt.close_all()


def _deploy_byo(owner_client, name="echo-server"):
    r = owner_client.post("/api/byo-mcp", json={"name": name, "command": "npx", "args": ["-y", "@example/echo"],
                                                 "env_schema": []})
    assert r.status_code == 200, r.text
    definition_id = r.json()["id"]
    r = owner_client.post(f"/api/byo-mcp/{definition_id}/deploy", json={"name": name, "env_vars": {}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True, body["message"]
    return body["process"]


# ---------------------------------------------------------------------------
# orchestrator over a runtime
# ---------------------------------------------------------------------------
def test_byo_deploy_start_stop_through_runtime(owner_client, fake_orchestrator):
    orch, rt = fake_orchestrator
    info = _deploy_byo(owner_client)
    pid = info["id"]
    assert info["actual_state"] == "running" and info["port"]

    launches = [c for c in rt.calls if c[0] == "launch"]
    assert len(launches) == 1
    req = launches[0][1]
    assert req.transport == "stdio" and req.stdio_command == ["npx", "-y", "@example/echo"]
    assert req.host_port == info["port"] and req.name.startswith("mcp-managed-")
    assert req.restart_on_failure is True and req.labels["mcp-center.process"] == pid
    assert orch.is_running(pid)

    # a Service row was registered at 127.0.0.1:<port>/mcp
    services = owner_client.get("/api/services").json()["services"]
    svc = next(s for s in services if s["id"] == info["service_id"])
    assert svc["port"] == info["port"] and svc["mcp_path"] == "/mcp" and svc["source"] == "managed"

    assert "[fake]" in owner_client.get(f"/api/managed/{pid}/logs").json()["logs"]

    r = owner_client.post(f"/api/managed/{pid}/stop")
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True and r.json()["process"]["actual_state"] == "stopped"
    assert ("stop", req.name) in rt.calls and ("remove", req.name) in rt.calls
    assert not orch.is_running(pid)

    # start again reuses the runtime; the port is kept
    r = owner_client.post(f"/api/managed/{pid}/start")
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True and r.json()["process"]["port"] == info["port"]


def test_launch_failure_marks_process_failed(owner_client, monkeypatch):
    rt = FakeRuntime(fail_launch=True)
    orch = Orchestrator(runtime=rt)
    monkeypatch.setattr(manager_mod, "_orchestrator", orch)
    r = owner_client.post("/api/byo-mcp", json={"name": "bad", "command": "npx", "args": ["-y", "x"], "env_schema": []})
    r = owner_client.post(f"/api/byo-mcp/{r.json()['id']}/deploy", json={"name": "bad", "env_vars": {}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is False and "boom" in body["message"]
    assert body["process"]["actual_state"] == "failed" and "boom" in (body["process"]["last_error"] or "")


def test_reconcile_adopts_live_and_restarts_dead(owner_client, fake_orchestrator, db_session):
    orch, rt = fake_orchestrator
    a = _deploy_byo(owner_client, "a")
    b = _deploy_byo(owner_client, "b")
    # simulate an MCP Center restart: memory gone, instance a alive, instance b dead
    orch._active.clear()
    name_b = next(c[1].name for c in rt.calls if c[0] == "launch" and c[1].labels["mcp-center.process"] == b["id"])
    rt.running.pop(name_b).close()
    launches_before = len([c for c in rt.calls if c[0] == "launch"])

    orch.reconcile(db_session)
    launches_after = len([c for c in rt.calls if c[0] == "launch"])
    assert launches_after == launches_before + 1          # only b was relaunched
    assert a["id"] in orch._active and b["id"] in orch._active
    assert orch.is_running(a["id"]) and orch.is_running(b["id"])


def test_runtime_endpoint(owner_client, fake_orchestrator):
    r = owner_client.get("/api/managed/runtime")
    assert r.status_code == 200, r.text
    assert r.json() == {"runtime": "fake", "available": True, "detail": "fake"}


# ---------------------------------------------------------------------------
# process runtime
# ---------------------------------------------------------------------------
FAKE_SUPERGATEWAY = r'''#!/usr/bin/env python3
import json, socket, sys
args = sys.argv[1:]
port = int(args[args.index("--port") + 1])
assert args[args.index("--outputTransport") + 1] == "streamableHttp"
print("fake supergateway up on", port, "stdio:", args[args.index("--stdio") + 1], flush=True)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(5)
body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
while True:
    c, _ = s.accept()
    with c:
        try:
            c.recv(65536)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except OSError:
            pass
'''


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def fake_supergateway(tmp_path):
    script = tmp_path / "supergateway"
    script.write_text(FAKE_SUPERGATEWAY)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def _request(name, port, command=("npx", "-y", "@example/echo"), transport="stdio"):
    return LaunchRequest(name=name, transport=transport, image_ref="mcp-runtime:1", run_flags=["--init"],
                         entrypoint_args=[], stdio_command=list(command), env={"API_KEY": "k"},
                         host_port=port, container_port=8000)


def test_process_runtime_runs_and_stops_a_byo_server(tmp_path, fake_supergateway):
    rt = ProcessRuntime(state_dir=str(tmp_path / "state"), supergateway_bin=fake_supergateway)
    assert rt.availability()[0] is True
    port = _free_port()
    stages = []
    rt.launch(_request("mcp-managed-test", port), lambda stage, detail=None: stages.append(stage))
    assert stages == ["starting_process"]
    pid = rt.instance_id("mcp-managed-test", running_only=True)
    assert pid and (tmp_path / "state" / "mcp-managed-test.pid").read_text() == pid

    Orchestrator._wait_for_port("127.0.0.1", port, timeout=10)
    time.sleep(0.2)
    log = rt.logs("mcp-managed-test")
    assert "[process status: running]" in log and f"up on {port}" in log and "npx -y @example/echo" in log

    # a second runtime instance (MCP Center restarted) finds it through the pid file
    rt2 = ProcessRuntime(state_dir=str(tmp_path / "state"), supergateway_bin=fake_supergateway)
    assert rt2.instance_id("mcp-managed-test", running_only=True) == pid

    rt2.stop("mcp-managed-test")
    rt2.remove("mcp-managed-test")
    assert rt2.instance_id("mcp-managed-test") is None
    assert not (tmp_path / "state" / "mcp-managed-test.pid").exists()
    assert "[process status: exited]" in rt2.logs("mcp-managed-test")
    # the child really exited (reaped through the handle the first runtime still holds)
    assert rt._children["mcp-managed-test"].wait(timeout=5) is not None


def test_process_runtime_refuses_images_and_missing_bridge(tmp_path):
    rt = ProcessRuntime(state_dir=str(tmp_path), supergateway_bin=str(tmp_path / "nope"))
    ok, detail = rt.availability()
    assert ok is False and "npm install -g supergateway" in detail
    assert rt.image_exists("x:1") is False
    with pytest.raises(ProcessRuntimeError):
        rt.load_image("x.tar")
    with pytest.raises(ProcessRuntimeError, match="docker runtime"):
        rt.launch(_request("n", 1, transport="http"), lambda *_: None)
    with pytest.raises(ProcessRuntimeError, match="not found"):
        rt.launch(_request("n", 1), lambda *_: None)
    assert "never have been started" in rt.logs("n")


def test_bridge_argv_and_runtime_selection(monkeypatch, tmp_path):
    argv = bridge_argv(["uvx", "my-server"], 3457)
    assert argv[1:3] == ["--stdio", "uvx my-server"] and argv[-2:] == ["--port", "3457"]
    assert "--outputTransport" in argv and "streamableHttp" in argv and "--stateful" in argv

    monkeypatch.setenv("MCP_RUNTIME", "process")
    assert select_runtime().name == "process"
    monkeypatch.setenv("MCP_RUNTIME", "docker")
    assert select_runtime().name == "docker"
    monkeypatch.setenv("MCP_RUNTIME", "bogus")
    with pytest.raises(ValueError):
        select_runtime()
    # auto falls back to the process runtime when Docker does not answer
    monkeypatch.setenv("MCP_RUNTIME", "auto")
    from src.orchestrator import docker_runtime
    monkeypatch.setattr(docker_runtime.DockerRuntime, "availability", lambda self: (False, "no daemon"))
    assert select_runtime().name == "process"


def test_orchestrator_wraps_runtime_errors(fake_orchestrator):
    orch, rt = fake_orchestrator
    rt.load_image = lambda path: (_ for _ in ()).throw(RuntimeError("tar broken"))
    with pytest.raises(OrchestratorError, match="tar broken"):
        orch.load_image("x.tar")
