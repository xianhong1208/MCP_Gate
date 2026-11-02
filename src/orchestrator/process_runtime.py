"""Process runtime: bring-your-own servers run as local subprocesses, no Docker.

The inner command (``npx …``, ``uvx …``, …) is bridged to Streamable HTTP by supergateway running on the
host, exactly as it does inside ``mcp-runtime:1`` under the Docker runtime, so services, health checks and
clients see the same 127.0.0.1:<port>/mcp endpoint. Catalog entries are images and cannot run here.

Each instance gets a pid file and a log file under ``MCP_PROCESS_LOG_DIR`` (default ``data/managed``),
so a restarted MCP Gate can find, read and stop instances it did not start itself. The child is put in
its own session so stopping it also stops whatever the bridge spawned.

The bridge must be reachable on 127.0.0.1 only (N2): MCP Gate's OAuth sits in front of the service, so a
bridge listening on the LAN address would serve the MCP server to anyone, unauthenticated. supergateway listens
on every interface by default and only >= 4.2.0 has ``--host``; so the runtime passes ``--host 127.0.0.1`` and
also preloads a tiny Node module (``NODE_OPTIONS=--require``) that rewrites every wildcard ``listen()`` to
127.0.0.1, which works whatever supergateway version is installed.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from src.orchestrator.runtime import (
    SUPERGATEWAY_BIN,
    LaunchRequest,
    ProgressFn,
    Runtime,
    RuntimeUnavailableError,
    bridge_argv,
)

logger = logging.getLogger(__name__)

LOOPBACK_HOST = "127.0.0.1"
_PRELOAD_NAME = "loopback-preload.cjs"
_PRELOAD_SOURCE = """'use strict'
// Written by MCP Gate's process runtime: pin every listen() without an explicit address (or with a
// wildcard one) to 127.0.0.1, so the supergateway bridge is not reachable from the network.
const net = require('net')
const LOOPBACK = '127.0.0.1'
const WILDCARD = new Set([undefined, null, '', '0.0.0.0', '::', '[::]', '::0'])
const listen = net.Server.prototype.listen
net.Server.prototype.listen = function (...args) {
  const first = args[0]
  if (args.length === 0 || typeof first === 'function') {
    args.unshift(0, LOOPBACK)
  } else if (first !== null && typeof first === 'object' && !Array.isArray(first)) {
    if (first.path === undefined && first.fd === undefined && first.handle === undefined && first._handle === undefined
        && WILDCARD.has(first.host)) {
      args[0] = Object.assign({}, first, { host: LOOPBACK })
    }
  } else if (typeof first === 'number' || (typeof first === 'string' && /^\\d+$/.test(first))) {
    if (typeof args[1] === 'string') {
      if (WILDCARD.has(args[1])) args[1] = LOOPBACK
    } else {
      args.splice(1, 0, LOOPBACK)
    }
  }
  return listen.apply(this, args)
}
"""


def write_loopback_preload(directory) -> Path:
    """Write the Node preload that pins wildcard listens to 127.0.0.1; returns its path."""
    path = Path(directory) / _PRELOAD_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text() != _PRELOAD_SOURCE:
        path.write_text(_PRELOAD_SOURCE)
    return path.resolve()

_LABEL_ENV = "MCP_MANAGED_INSTANCE"          # marks our children so a recycled pid is not mistaken for one
_BASE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "USERPROFILE",
                  "NODE_OPTIONS", "NPM_CONFIG_CACHE", "UV_CACHE_DIR", "XDG_CACHE_HOME")


class ProcessRuntimeError(Exception):
    """Raised when an instance cannot be started or stopped; the Orchestrator wraps it."""


class ProcessRuntimeUnavailableError(ProcessRuntimeError, RuntimeUnavailableError):
    """supergateway is not installed, so nothing can run under this runtime."""


class ProcessRuntime(Runtime):
    name = "process"

    def __init__(self, state_dir: Optional[str] = None, supergateway_bin: Optional[str] = None):
        self.state_dir = Path(state_dir or os.environ.get("MCP_PROCESS_LOG_DIR") or Path("data") / "managed")
        self.supergateway_bin = supergateway_bin or SUPERGATEWAY_BIN
        self._children: Dict[str, subprocess.Popen] = {}

    # ------------------------------------------------------------------ files
    def _pid_file(self, name: str) -> Path:
        return self.state_dir / f"{name}.pid"

    def _log_file(self, name: str) -> Path:
        return self.state_dir / f"{name}.log"

    def _read_pid(self, name: str) -> Optional[int]:
        try:
            return int(self._pid_file(name).read_text().strip())
        except (OSError, ValueError):
            return None

    def _pid_is_ours(self, pid: int, name: str) -> bool:
        """The pid is alive and, where /proc lets us check, carries our instance label (pids get recycled)."""
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        stat_file = Path(f"/proc/{pid}/stat")
        if stat_file.exists():
            try:  # a zombie (exited, not yet reaped by its parent) is dead for our purposes
                if stat_file.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                    return False
            except (OSError, IndexError):
                pass
        environ = Path(f"/proc/{pid}/environ")
        if environ.exists():
            try:
                return f"{_LABEL_ENV}={name}".encode() in environ.read_bytes()
            except OSError:
                return True  # alive but unreadable (different user): assume ours
        return True

    # ------------------------------------------------------------------ Runtime
    def availability(self) -> tuple[bool, str]:
        path = shutil.which(self.supergateway_bin)
        if path:
            return True, f"supergateway at {path}"
        return False, (f"{self.supergateway_bin} not found on PATH; install it with `npm install -g supergateway` "
                       "or point MCP_SUPERGATEWAY_BIN at it")

    def image_exists(self, image_ref: str) -> bool:
        return False

    def load_image(self, tar_path: str) -> List[str]:
        raise ProcessRuntimeError("catalog images need the docker runtime (MCP_RUNTIME=docker)")

    def launch(self, request: LaunchRequest, progress: ProgressFn) -> None:
        if request.transport != "stdio" or not request.stdio_command:
            raise ProcessRuntimeError("the process runtime runs bring-your-own servers only; "
                                      "catalog images need the docker runtime (MCP_RUNTIME=docker)")
        ok, detail = self.availability()
        if not ok:
            raise ProcessRuntimeUnavailableError(detail)
        self.stop(request.name)
        self.remove(request.name)

        argv = bridge_argv(request.stdio_command, request.host_port, host=LOOPBACK_HOST)
        argv[0] = shutil.which(self.supergateway_bin) or self.supergateway_bin
        env = {k: v for k, v in os.environ.items() if k in _BASE_ENV_KEYS}
        env.update(request.env)
        env[_LABEL_ENV] = request.name

        self.state_dir.mkdir(parents=True, exist_ok=True)
        preload = write_loopback_preload(self.state_dir)
        env["NODE_OPTIONS"] = f'{env.get("NODE_OPTIONS", "")} --require "{preload}"'.strip()
        progress("starting_process", request.name)
        log = open(self._log_file(request.name), "ab")
        try:
            child = subprocess.Popen(  # argv list, no shell; every token passed the argv policy
                argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env,
                cwd=str(self.state_dir), start_new_session=True,
            )
        except OSError as e:
            log.close()
            raise ProcessRuntimeError(f"could not start {argv[0]}: {e}") from e
        log.close()
        self._children[request.name] = child
        self._pid_file(request.name).write_text(str(child.pid))
        logger.info(f"Process started for {request.name}: pid={child.pid}")

    def _signal(self, pid: int, sig: int) -> None:
        """Signal the instance's process group (or the pid alone). A process that is already gone is fine;
        being refused (EPERM) is not -- the instance would keep running."""
        try:
            os.killpg(pid, sig)
            return
        except ProcessLookupError:
            pass
        except OSError:
            pass  # not a group leader / group gone: fall back to the pid
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        except OSError as e:
            raise ProcessRuntimeError(f"cannot signal pid {pid}: {e}") from e

    def _is_gone(self, pid: int, name: str, child: Optional[subprocess.Popen]) -> bool:
        if child is not None:
            return child.poll() is not None
        return not self._pid_is_ours(pid, name)

    def stop(self, name: str) -> None:
        pid = self._read_pid(name)
        child = self._children.pop(name, None)
        if pid is None or not self._pid_is_ours(pid, name):
            return
        self._signal(pid, signal.SIGTERM)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._is_gone(pid, name, child):
                return
            time.sleep(0.2)
        self._signal(pid, signal.SIGKILL)
        if child is not None:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        else:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not self._is_gone(pid, name, None):
                time.sleep(0.2)
        if not self._is_gone(pid, name, child):
            if child is not None:
                self._children[name] = child  # keep the handle: it is still ours and still alive
            raise ProcessRuntimeError(f"process {pid} for {name} is still alive after SIGKILL")

    def remove(self, name: str) -> None:
        self._children.pop(name, None)
        try:
            self._pid_file(name).unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            raise ProcessRuntimeError(f"cannot remove pid file for {name}: {e}") from e

    def instance_id(self, name: str, running_only: bool = False) -> Optional[str]:
        child = self._children.get(name)
        if child is not None:
            if child.poll() is None:
                return str(child.pid)
            self._children.pop(name, None)
        pid = self._read_pid(name)
        if pid is None:
            return None
        if self._pid_is_ours(pid, name):
            return str(pid)
        return None if running_only else str(pid)

    def logs(self, name: str, tail: int = 200) -> str:
        path = self._log_file(name)
        if not path.exists():
            return f"(no log for '{name}' -- it may never have been started under the process runtime)"
        try:
            lines = path.read_text(errors="replace").splitlines()[-tail:]
        except OSError as e:
            return f"(failed to read log: {e})"
        pid = self._read_pid(name)
        status = "running" if pid and self._pid_is_ours(pid, name) else "exited"
        return f"[process status: {status}]\n" + "\n".join(lines)
