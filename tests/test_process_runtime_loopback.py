"""N2: under MCP_RUNTIME=process the supergateway bridge must listen on 127.0.0.1 only.

supergateway listens on every interface unless told otherwise (3.4.3, the version pinned in the runtime
image, has no flag for it; --host arrived in 4.2.0). The Docker runtime publishes the port on 127.0.0.1, but a
host process answered unauthenticated MCP calls on the LAN address. The process runtime now passes
`--host 127.0.0.1` (honoured by >= 4.2.0, ignored by older versions) and preloads a Node module that pins
every wildcard listen() to loopback, which covers any version.
"""

import json
import os
import shutil
import subprocess

import pytest

from src.orchestrator.process_runtime import LOOPBACK_HOST, ProcessRuntime
from src.orchestrator.runtime import LaunchRequest, bridge_argv


def test_bridge_argv_binds_loopback_when_asked():
    argv = bridge_argv(["npx", "-y", "srv"], 3457, host="127.0.0.1")
    i = argv.index("--host")
    assert argv[i + 1] == "127.0.0.1"
    assert argv[-2:] == ["--port", "3457"]
    # the Docker runtime keeps listening on all interfaces inside the container (published on 127.0.0.1)
    assert "--host" not in bridge_argv(["npx", "-y", "srv"], 3457)


def test_process_runtime_launches_supergateway_on_loopback(monkeypatch, tmp_path):
    captured = {}

    class FakePopen:
        pid = 4242

        def __init__(self, argv, **kwargs):
            captured["argv"], captured["env"] = argv, kwargs["env"]

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    rt = ProcessRuntime(state_dir=str(tmp_path), supergateway_bin="supergateway")
    monkeypatch.setattr(rt, "stop", lambda name: None)
    monkeypatch.setattr(rt, "remove", lambda name: None)
    req = LaunchRequest(name="n", transport="stdio", image_ref="", run_flags=[], entrypoint_args=[],
                        stdio_command=["npx", "-y", "srv"], env={"NODE_OPTIONS": "--max-old-space-size=256"},
                        host_port=3501, container_port=8000)
    rt.launch(req, lambda *a: None)

    argv = captured["argv"]
    assert argv[argv.index("--host") + 1] == LOOPBACK_HOST == "127.0.0.1"
    node_options = captured["env"]["NODE_OPTIONS"]
    assert "--max-old-space-size=256" in node_options and "--require" in node_options
    preload = node_options.split("--require", 1)[1].strip().strip('"')
    assert os.path.isfile(preload)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("listen_call", [
    "server.listen(0, cb)",
    "server.listen(0, '0.0.0.0', cb)",
    "server.listen(0, '::', cb)",
    "server.listen({port: 0}, cb)",
    "server.listen({port: 0, host: '0.0.0.0'}, cb)",
    "server.listen(cb)",
])
def test_preload_pins_wildcard_listens_to_loopback(tmp_path, listen_call):
    from src.orchestrator.process_runtime import write_loopback_preload

    preload = write_loopback_preload(tmp_path)
    script = ("const http = require('http'); const server = http.createServer();"
              "const cb = () => { console.log(JSON.stringify(server.address())); server.close() };" + listen_call)
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30,
                         env={**os.environ, "NODE_OPTIONS": f'--require "{preload}"'})
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["address"] == "127.0.0.1"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_preload_leaves_explicit_hosts_alone(tmp_path):
    from src.orchestrator.process_runtime import write_loopback_preload

    preload = write_loopback_preload(tmp_path)
    script = ("const server = require('net').createServer();"
              "server.listen(0, '::1', () => { console.log(JSON.stringify(server.address())); server.close() })")
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30,
                         env={**os.environ, "NODE_OPTIONS": f'--require "{preload}"'})
    if out.returncode != 0 and "EADDRNOTAVAIL" in out.stderr:
        pytest.skip("no IPv6 loopback here")
    assert json.loads(out.stdout)["address"] == "::1"

