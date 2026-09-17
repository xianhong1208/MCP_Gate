"""Managed MCP Orchestrator

Starts/stops/monitors MCP servers installed from the marketplace catalog or from a
user's BYO definition. External callers only go through the Orchestrator class; the
in-memory state is owned by this class.

How an instance actually runs is a Runtime's business (src/orchestrator/runtime):
  - DockerRuntime (default): a sibling container via the docker SDK. Tainted parameters
    are passed to the Engine API as typed arguments; nothing is ever shelled out.
  - ProcessRuntime (MCP_RUNTIME=process): a local subprocess, for hosts without Docker;
    bring-your-own servers only.

Two transports (source unified by LaunchSpec, see src/orchestrator/launch_spec):
  - http: the image ships its own HTTP server and is run directly (Docker only).
  - stdio: supergateway bridges the inner MCP command (npx/uvx/...) to **Streamable
    HTTP** (POST /mcp + mcp-session-id; not the legacy HTTP+SSE -- this project's scanner
    only speaks the former), inside the managed base image or on the host depending on
    the runtime. BYO inner commands go through the argv_policy command whitelist + args
    character whitelist before they reach any runtime.

Start flow (start):
  1. Read the process from the DB and the matching entry from the catalog
  2. Decrypt env vars
  3. Allocate a port with PortAllocator (if auto_port=True)
  4. Validate image/flags/command against the argv policy and hand a LaunchRequest to the runtime
     (127.0.0.1:<port> on the host; image/args/command/env from the catalog or definition)
  5. Wait for the port to listen (http 30s / stdio 300s, see _START_TIMEOUT_*)
  6. Ask the runtime for the instance id (container id / pid)
  7. Auto-create the Service row (host=127.0.0.1, port=<port>,
     mcp_path=/mcp, requires_auth=false, source=managed)
  8. Update the DB: port, container_id, service_id, actual_state=running

Stop flow (stop):
  1. runtime.stop + runtime.remove <instance name>
  2. Clear the in-memory entry
  3. Update the DB: actual_state=stopped, container_id=NULL

Design trade-offs:
  - The in-memory set is lost when MCP Center restarts; reconcile() asks the runtime
    which desired_state=running processes are still alive, adopts those and restarts the
    rest (self-healing)
  - No background health-check loop here (the existing health_monitor handles it via
    the Service row)
"""

from __future__ import annotations

import logging
import os
import socket
import time
from threading import Lock
from typing import Optional, Set

from sqlalchemy.orm import Session

from src.adapters import ManagedMcpProcessAdapter, ServiceAdapter
from db.models import ManagedMcpProcess
from src.marketplace.argv_policy import (
    ArgvPolicyError,
    validate_byo_launch,
    validate_command_tokens,
    validate_docker_args,
    validate_image_ref,
)
from src.orchestrator.docker_runtime import _flags_to_kwargs  # noqa: F401  (re-exported for callers and tests)
from src.orchestrator.progress import get_progress_registry, process_key
from src.orchestrator.launch_spec import resolve_launch_spec
from src.orchestrator.port_allocator import PortAllocator
from src.orchestrator.runtime import STDIO_HTTP_PATH as _STDIO_HTTP_PATH, LaunchRequest, Runtime, select_runtime

# Upper bound (seconds) to wait for the port to be listening after start.
# http: the image is already local, starting only runs the process -> 30s is enough.
# stdio (BYO): npx/uvx inside the container must **download packages online** before
# starting; a cold start often takes tens of seconds or more, so keeping 30s would make
# the first deployment time out almost every time. Both can be overridden via env vars.
_START_TIMEOUT_HTTP = float(os.environ.get("MCP_START_TIMEOUT_HTTP", "30"))
_START_TIMEOUT_STDIO = float(os.environ.get("MCP_START_TIMEOUT_STDIO", "300"))

logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """Orchestrator operation failed"""


def _container_name(process_id: str) -> str:
    """Naming rule for the sibling container: fixed prefix + first 8 chars of the UUID"""
    return f"mcp-managed-{process_id[:8]}"


class Orchestrator:
    """Managed MCP start/stop management (singleton)

    All DB writes go through ManagedMcpProcessAdapter; how an instance runs is the Runtime's business
    (Docker container or local process). Thread-safe via _lock (operations are infrequent, a
    coarse-grained lock is enough).
    """

    def __init__(self, port_allocator: Optional[PortAllocator] = None, runtime: Optional[Runtime] = None):
        self.port_allocator = port_allocator or PortAllocator()
        self.runtime: Runtime = runtime or select_runtime()
        # process ids this MCP Center instance has started (or adopted at reconcile) since it came up
        self._active: Set[str] = set()
        self._lock = Lock()

    # ---------- Public API ----------

    def runtime_info(self) -> dict:
        """Which runtime is in use and whether it can currently start anything."""
        ok, detail = self.runtime.availability()
        return {"runtime": self.runtime.name, "available": ok, "detail": detail}

    def image_exists(self, image_ref: str) -> bool:
        """Whether a catalog image is present locally (always False on runtimes without images)."""
        try:
            return self.runtime.image_exists(image_ref)
        except Exception as e:  # daemon down etc.: the marketplace lists the entry as not installed
            logger.debug(f"image_exists({image_ref}) -> False: {e}")
            return False

    def load_image(self, tar_path: str) -> list:
        """Load a catalog image tarball; returns the tags loaded. Raises OrchestratorError."""
        try:
            return self.runtime.load_image(tar_path)
        except Exception as e:
            raise OrchestratorError(str(e)) from e

    def container_logs(self, process_id: str, tail: int = 200) -> str:
        """The instance's recent output (including after a crash). Never raises: the caller is debugging and
        should not fail just because there is nothing to find."""
        try:
            return self.runtime.logs(_container_name(process_id), tail=tail)
        except Exception as e:
            return f"(failed to read logs: {e})"

    def start(self, db: Session, process_id: str) -> ManagedMcpProcess:
        """Start a Managed MCP process (stopping it first when this instance already started it)."""
        with self._lock, get_progress_registry().track(process_key(process_id), "start"):
            return self._start_locked(db, process_id)

    def stop(self, db: Session, process_id: str) -> ManagedMcpProcess:
        """Stop the instance (graceful -> forceful) and clean up what the runtime left behind"""
        with self._lock, get_progress_registry().track(process_key(process_id), "stop"):
            return self._stop_locked(db, process_id)

    def is_running(self, process_id: str) -> bool:
        """Whether the instance is really running, asked of the runtime rather than remembered in memory:
        memory is lost when MCP Center restarts while the container / process lives on."""
        with self._lock:
            return bool(self.runtime.instance_id(_container_name(process_id), running_only=True))

    def reconcile(self, db: Session) -> None:
        """Called at startup: align processes with desired_state=running to what the runtime reports.

        Three scenarios:
          (a) instance still alive -> adopt it, no restart (zero interruption)
          (b) instance gone -> start again
          (c) start failed -> mark actual_state=failed
        """
        targets = ManagedMcpProcessAdapter.list_all(
            db, desired_state="running"
        )
        for p in targets:
            process_id = str(p.id)
            container_name = _container_name(process_id)
            cid = self.runtime.instance_id(container_name, running_only=True)

            if cid:
                # (a) still alive; only the in-memory state was lost on MCP Center restart
                with self._lock:
                    self._active.add(process_id)
                logger.info(
                    f"Reconcile: recovered {p.name} ({process_id}), "
                    f"{self.runtime.name} instance {cid[:12]} still alive"
                )
                continue

            # (b) really gone -> restart
            try:
                logger.info(f"Reconcile: restarting managed process {p.name} ({process_id})")
                self.start(db, process_id)
            except Exception as e:
                # (c)
                logger.error(f"Reconcile failed for {process_id}: {e}")
                ManagedMcpProcessAdapter.update_state(
                    db, process_id,
                    actual_state="failed",
                    last_error=f"reconcile: {e}",
                )

    # ---------- Internal ----------

    def _start_locked(self, db: Session, process_id: str) -> ManagedMcpProcess:
        process = ManagedMcpProcessAdapter.get_by_id(db, process_id)
        if not process:
            raise OrchestratorError(f"Process {process_id} not found")

        # Resolve the launch description (from a catalog file or a user's BYO definition)
        try:
            spec = resolve_launch_spec(db, process)
        except LookupError as e:
            raise OrchestratorError(str(e)) from e

        # If this instance already started it, stop first
        if process_id in self._active:
            logger.info(f"Process {process_id} already started by this instance, stopping first")
            self._stop_locked(db, process_id)

        progress = get_progress_registry()
        pkey = process_key(process_id)

        # 1. Allocate port
        progress.stage(pkey, "allocating_port")
        if process.auto_port:
            port = self.port_allocator.allocate(db, exclude_process_id=process_id)
        else:
            if not process.port:
                raise OrchestratorError("auto_port=False but no port set")
            port = process.port

        # 2. Decrypt env vars
        env_vars = process.get_env_vars()

        # 3. Take launch parameters from the LaunchSpec (source-agnostic)
        transport = spec.transport
        container_port = spec.container_port
        container_name = _container_name(process_id)

        image_ref = spec.image_ref
        image_args = " ".join(spec.run_flags) or "--rm"
        image_command = list(spec.entrypoint_args)  # used by the http branch (catalog)

        # ------------------------------------------------------------------
        # argv policy check at the execution boundary (Stored Command/Argument Injection defence)
        #
        # All three values above come straight from the DB (image_ref / image_args /
        # image_command, the last one also went through json.loads) and are about to be
        # expanded directly into the `docker run` argv. DockerSpec already validated the
        # catalog at install time, but we must validate again here -- this is not redundant:
        #
        #   1. This is a *Stored* injection. The threat model includes "the attacker can
        #      already write to the DB" (SQL injection, leaked DB credentials, internal
        #      misuse of CRUD). That path bypasses the catalog entirely; validating only
        #      on the write side is no defence at all.
        #   2. Static scanning cannot connect "validated before writing to the DB" with
        #      "read from the DB and used"; the sanitizer must physically sit between the
        #      DB read and the subprocess.
        #
        # The policy itself lives in src/marketplace/argv_policy (shared with DockerSpec).
        # If validation fails, let start fail: the caller marks actual_state=failed and
        # writes last_error, which is clearly visible, instead of silently rewriting the
        # value to something "safe".
        # ------------------------------------------------------------------
        # Decide what runs inside the container by transport, and apply the argv policy
        # here (at the execution boundary):
        #   http  -> run the image directly, command = validated entrypoint args
        #   stdio -> run supergateway inside the managed base image, bridging the inner
        #            MCP command (BYO: inner command goes through the command whitelist +
        #            args character whitelist)
        # Both image_ref and docker flags must be validated.
        try:
            validate_image_ref(image_ref)
            image_args_tokens = validate_docker_args(image_args.split())
            entrypoint_args: list = []
            stdio_command: list = []
            if transport == "http":
                entrypoint_args = validate_command_tokens(image_command) or []
            elif transport == "stdio":
                inner_cmd, inner_args = validate_byo_launch(
                    spec.stdio_command[0] if spec.stdio_command else "",
                    spec.stdio_command[1:] if spec.stdio_command else [],
                )
                stdio_command = [inner_cmd] + inner_args
            else:
                raise ArgvPolicyError(f"Unsupported transport: {transport!r}")
        except ArgvPolicyError as e:
            logger.error(
                f"Refusing to start {process.name} ({process_id}): "
                f"argv policy check failed: {e}"
            )
            raise OrchestratorError(f"argv policy check failed: {e}") from e

        logger.info(
            f"Starting managed MCP {process.name}: "
            f"transport={transport}, port={port}, image={image_ref}, "
            f"env_count={len(env_vars)}"
        )

        # Hand the validated request to the runtime: a container (Docker) or a local process. Tainted data
        # (image/command/env/flags) travels as typed arguments; there is no OS-command sink anywhere.
        request = LaunchRequest(
            name=container_name, transport=transport, image_ref=image_ref, run_flags=list(image_args_tokens),
            entrypoint_args=entrypoint_args, stdio_command=stdio_command, env=dict(env_vars),
            host_port=port, container_port=container_port,
            # the stdio bridge (supergateway) can die on an upstream bug; let the runtime bring it back
            restart_on_failure=(transport == "stdio"),
            labels={"mcp-center.process": process_id, "mcp-center.name": process.name},
        )
        try:
            self.runtime.launch(request, lambda stage, detail=None: progress.stage(pkey, stage, detail))
        except OrchestratorError:
            raise
        except Exception as e:
            raise OrchestratorError(str(e)) from e
        logger.info(f"{self.runtime.name} instance started for {process.name}: {container_name}")
        self._active.add(process_id)

        # Wait for the port to start listening.
        # On the first start of stdio (BYO), npx/uvx inside the container must **download
        # packages on the spot**, which can take far longer than http mode (image already
        # local) -- use the longer timeout, otherwise the first deployment almost always
        # times out. Can be overridden via env vars.
        start_timeout = _START_TIMEOUT_STDIO if transport == "stdio" else _START_TIMEOUT_HTTP
        progress.stage(pkey, "waiting_port", str(port))
        try:
            logger.info(
                f"Waiting up to {start_timeout:.0f}s for port {port} "
                f"({process.name}, transport={transport})"
            )
            self._wait_for_port("127.0.0.1", port, timeout=start_timeout)
            logger.info(f"Port {port} is listening for {process.name}")
        except TimeoutError as e:
            logger.error(f"Port {port} did not open for {process.name}: {e}")
            self._stop_locked(db, process_id)
            raise OrchestratorError(f"Port {port} did not open: {e}") from e

        # stdio bridge: warm up once so npx/uvx inside the container finish downloading and
        # starting. supergateway's stateful mode "spawns the child only when the first
        # request arrives", and npx must install packages online on first use (tens of
        # seconds). If that cost were left to the later health check (timeout of only a few
        # seconds), it would disconnect first, and supergateway would then crash with an
        # uncaught exception when writing back to a connection it cannot find (observed in
        # practice). Here we absorb it with the long timeout the deploy stage already allows,
        # so all later requests are warm.
        if transport == "stdio":
            progress.stage(pkey, "warming_up")
            self._warmup_bridge(port, _STDIO_HTTP_PATH, start_timeout)

        # Fetch the runtime's id for the instance (container id / pid)
        sibling_container_id = self.runtime.instance_id(container_name)
        logger.info(f"Instance id for {process.name}: {sibling_container_id}")

        # Auto-create the Service row (if not there yet).
        # Path depends on transport: http images ship /mcp; stdio goes through supergateway -> /sse.
        if transport == "stdio":
            mcp_path = _STDIO_HTTP_PATH   # supergateway exposes Streamable HTTP
            description = f"Custom MCP (BYO): {' '.join(spec.stdio_command)}"
        else:
            mcp_path = "/mcp"
            description = f"Managed via marketplace catalog '{process.catalog_id}'"
        progress.stage(pkey, "registering_service")
        service_id = self._ensure_service(
            db, process, port, mcp_path=mcp_path, description=description,
        )

        # Update DB
        updated = ManagedMcpProcessAdapter.update_state(
            db, process_id,
            actual_state="running",
            container_id=sibling_container_id or "",
            bridge_container_id="",
            port=port,
            service_id=str(service_id) if service_id else None,
            last_error="",
        )
        logger.info(
            f"Managed MCP started: name={process.name}, port={port}, "
            f"container={sibling_container_id}, service_id={service_id}"
        )
        return updated

    @staticmethod
    def _warmup_bridge(port: int, path: str, timeout: float) -> None:
        """Send one initialize to the stdio bridge to trigger and wait for the in-container child to be truly ready.

        Best-effort: failures are only logged and never fail the deployment -- the warm-up
        is a performance and stability optimisation; the real health state is determined by
        the existing health check.
        """
        import json as _json

        body = _json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "mcp-center-warmup", "version": "1.0.0"},
            },
        })
        req = (
            f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Accept: application/json, text/event-stream\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode()
        deadline = time.monotonic() + timeout
        sock = None
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            sock.sendall(req)
            sock.settimeout(min(30.0, timeout))
            buf = b""
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                if b"data:" in buf or b'"result"' in buf or b'"error"' in buf:
                    logger.info(f"Bridge warmup done on port {port}")
                    return
            logger.warning(f"Bridge warmup on port {port} did not complete within {timeout:.0f}s")
        except OSError as e:
            logger.warning(f"Bridge warmup on port {port} failed: {e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _stop_locked(self, db: Session, process_id: str) -> ManagedMcpProcess:
        process = ManagedMcpProcessAdapter.get_by_id(db, process_id)
        if not process:
            raise OrchestratorError(f"Process {process_id} not found")

        logger.info(f"Stopping managed MCP: name={process.name}, id={process_id}")
        self._active.discard(process_id)

        container_name = _container_name(process_id)
        logger.info(f"Stopping {self.runtime.name} instance: {container_name}")
        get_progress_registry().stage(process_key(process_id), "stopping_container")
        try:
            self.runtime.stop(container_name)
            self.runtime.remove(container_name)
        except Exception as e:  # stop must not fail because the runtime is unreachable
            logger.warning(f"stop {container_name} on {self.runtime.name} ignored: {e}")
        logger.info(f"Managed MCP stopped: name={process.name}")

        # Update DB -- clear container refs but keep the port (user settings must survive stop)
        return ManagedMcpProcessAdapter.update_state(
            db, process_id,
            actual_state="stopped",
            container_id="",
            bridge_container_id="",
        )

    # ---------- Helpers ----------

    @staticmethod
    def _wait_for_port(host: str, port: int, timeout: float) -> None:
        """Poll until something is listening at host:port, or timeout."""
        deadline = time.monotonic() + timeout
        last_err = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    return
            except OSError as e:
                last_err = e
                time.sleep(0.3)
        raise TimeoutError(
            f"Port {host}:{port} did not become listening within {timeout}s "
            f"(last={last_err})"
        )

    @staticmethod
    def _ensure_service(
        db: Session, process: ManagedMcpProcess, port: int,
        mcp_path: str = "/mcp", description: Optional[str] = None,
    ):
        """Auto-create (or update) the Service row for a Managed Process

        The Service has host=127.0.0.1, port=<bridge port>, requires_auth=False,
        source="managed". Downstream agents connect directly to 127.0.0.1:port (because
        MCP Center runs with --network host, 127.0.0.1 is the host loopback).

        mcp_path is chosen by the caller based on transport -- http images ship /mcp;
        stdio goes through supergateway whose endpoint is /sse. Hard-coding a single path
        would make one of them unreachable forever.
        """
        # If service_id exists, update it (both port and path, so the wrong path in old data gets fixed)
        if process.service_id:
            existing = ServiceAdapter.get_by_id(db, str(process.service_id))
            if existing:
                ServiceAdapter.update(db, str(existing.id), port=port, mcp_path=mcp_path)
                logger.info(
                    f"Updated existing Service {existing.id}: port={port}, mcp_path={mcp_path}"
                )
                return existing.id

        # Create new
        logger.info(f"Creating new Service for managed process {process.name}")
        svc = ServiceAdapter.create(
            db=db,
            name=process.name,
            description=description or f"Managed via marketplace catalog '{process.catalog_id}'",
            host="127.0.0.1",
            port=port,
            protocol="http",
            mcp_path=mcp_path,
            source="managed",
            requires_auth=False,  # trust the host's local network; agents connect directly without a token
        )
        logger.info(f"Created Service {svc.id} for {process.name} at 127.0.0.1:{port}{mcp_path}")
        return svc.id


# -------- Singleton --------

_orchestrator: Optional[Orchestrator] = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator
