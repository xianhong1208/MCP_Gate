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
  3. Keep the process's port when it is still usable, else allocate one (auto_port=True) -- and say so
  4. Validate image/flags/command against the argv policy and hand a LaunchRequest to the runtime
     (127.0.0.1:<port> on the host; image/args/command/env from the catalog or definition)
  5. Wait for the port to listen, then for an MCP `initialize` to succeed on /mcp -- under Docker the
     port proxy accepts connections long before the server does (http 30s / stdio 300s in total, see
     _START_TIMEOUT_*)
  6. Ask the runtime for the instance id (container id / pid)
  7. Auto-create the Service row (host=127.0.0.1, port=<port>,
     mcp_path=/mcp, requires_auth=false, source=managed)
  8. Update the DB: port, container_id, service_id, actual_state=running
  Anything failing after the launch tears the instance down again, after copying its last log lines into
  last_error (actual_state=failed).

Stop flow (stop):
  1. runtime.stop + runtime.remove <instance name>
  2. Clear the in-memory entry
  3. Update the DB: actual_state=stopped, container_id=NULL
  When the runtime cannot stop it, the process is marked actual_state=stop_failed and the error is raised:
  the instance may still be running, so nothing may pretend it is gone.

Locking: one lock per process id serialises operations on that process (a 300 s stdio cold start no longer
blocks every other instance); a short global lock guards the shared in-memory structures and port
allocation + reservation.

Design trade-offs:
  - The in-memory set is lost when MCP Gate restarts; reconcile() asks the runtime
    which desired_state=running processes are still alive, adopts those and restarts the
    rest (self-healing)
  - No background health-check loop here (the existing health_monitor handles it via
    the Service row)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from threading import Lock
from typing import Dict, Optional, Set, Tuple

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
from src.orchestrator.port_allocator import PortAllocationError, PortAllocator
from src.orchestrator.runtime import (
    STDIO_HTTP_PATH as _STDIO_HTTP_PATH,
    LaunchRequest,
    Runtime,
    RuntimeUnavailableError,
    select_runtime,
)

# Upper bound (seconds) to wait for the port to be listening after start.
# http: the image is already local, starting only runs the process -> 30s is enough.
# stdio (BYO): npx/uvx inside the container must **download packages online** before
# starting; a cold start often takes tens of seconds or more, so keeping 30s would make
# the first deployment time out almost every time. Both can be overridden via env vars.
_START_TIMEOUT_HTTP = float(os.environ.get("MCP_START_TIMEOUT_HTTP", "30"))
_START_TIMEOUT_STDIO = float(os.environ.get("MCP_START_TIMEOUT_STDIO", "300"))

# How much of a failed instance's output is kept in last_error (the instance itself is removed).
_FAILURE_LOG_LINES = 50
_LAST_ERROR_MAX_CHARS = 4000

logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """Orchestrator operation failed.

    str(e) is a one-line reason fit for an API message; ``last_error`` is the full text recorded on the
    process, which may also carry the instance's last log lines."""

    def __init__(self, message: str, *, last_error: Optional[str] = None):
        super().__init__(message)
        self.last_error = last_error or message


class RuntimeUnavailable(OrchestratorError):
    """The runtime itself (Docker daemon, supergateway) cannot be reached; callers answer 503."""


def error_text(e: BaseException) -> str:
    """What to record as last_error for an exception raised by the orchestrator."""
    return getattr(e, "last_error", None) or str(e)


def _container_name(process_id: str) -> str:
    """Naming rule for the sibling container: fixed prefix + first 8 chars of the UUID"""
    return f"mcp-managed-{process_id[:8]}"


class Orchestrator:
    """Managed MCP start/stop management (singleton)

    All DB writes go through ManagedMcpProcessAdapter; how an instance runs is the Runtime's business
    (Docker container or local process). Operations on one process are serialised by that process's lock;
    _lock is only ever held briefly (shared structures, port allocation + reservation).
    """

    def __init__(self, port_allocator: Optional[PortAllocator] = None, runtime: Optional[Runtime] = None):
        self.port_allocator = port_allocator or PortAllocator()
        self.runtime: Runtime = runtime or select_runtime()
        # process ids this MCP Gate instance has started (or adopted at reconcile) since it came up
        self._active: Set[str] = set()
        self._lock = Lock()
        self._process_locks: Dict[str, Lock] = {}

    def _process_lock(self, process_id: str) -> Lock:
        with self._lock:
            return self._process_locks.setdefault(process_id, Lock())

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
        with self._process_lock(process_id), get_progress_registry().track(process_key(process_id), "start"):
            return self._start_locked(db, process_id)

    def stop(self, db: Session, process_id: str) -> ManagedMcpProcess:
        """Stop the instance (graceful -> forceful) and clean up what the runtime left behind.

        Raises OrchestratorError (RuntimeUnavailable when the runtime cannot be reached) when the instance
        could not be stopped; the process is then left in actual_state=stop_failed."""
        with self._process_lock(process_id), get_progress_registry().track(process_key(process_id), "stop"):
            return self._stop_locked(db, process_id)

    def update_env_and_restart(
        self, db: Session, process_id: str, env_vars: dict,
    ) -> Tuple[ManagedMcpProcess, bool]:
        """Replace the env vars and, when the process is running, restart it -- as one operation under the
        process's lock, so no start / stop can slip in between.

        Returns (process, restarted). A stop failure raises before anything is written; a start failure
        after the env vars were written leaves actual_state=failed with last_error set, and raises.
        """
        with self._process_lock(process_id), get_progress_registry().track(process_key(process_id), "restart"):
            process = ManagedMcpProcessAdapter.get_by_id(db, process_id)
            if not process:
                raise OrchestratorError(f"Process {process_id} not found")
            was_running = process.actual_state == "running"
            if was_running:
                self._stop_locked(db, process_id)
            ManagedMcpProcessAdapter.update_env_vars(db, process_id, env_vars)
            if not was_running:
                return ManagedMcpProcessAdapter.get_by_id(db, process_id), False
            try:
                return self._start_locked(db, process_id), True
            except OrchestratorError as e:
                self._mark_failed(db, process_id, error_text(e))
                raise

    def is_running(self, process_id: str) -> bool:
        """Whether the instance is really running, asked of the runtime rather than remembered in memory:
        memory is lost when MCP Gate restarts while the container / process lives on."""
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
                # (a) still alive; only the in-memory state was lost on MCP Gate restart
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
                    last_error=f"reconcile: {error_text(e)}",
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

        container_name = _container_name(process_id)

        # If this instance already started it, stop first. Otherwise clear whatever a previous MCP Gate run
        # left behind under the same name: it would hold the port this process is about to reuse.
        if process_id in self._active:
            logger.info(f"Process {process_id} already started by this instance, stopping first")
            self._stop_locked(db, process_id)
        else:
            try:
                self._teardown(container_name)
            except Exception as e:
                raise self._runtime_error(e, f"could not clear leftover instance {container_name}: {e}") from e

        progress = get_progress_registry()
        pkey = process_key(process_id)

        # 1. Port: keep the one the process has (clients use its URL), else allocate -- see _reserve_port
        progress.stage(pkey, "allocating_port")
        port, port_note = self._reserve_port(db, process)

        # 2. Decrypt env vars
        env_vars = process.get_env_vars()

        # 3. Take launch parameters from the LaunchSpec (source-agnostic)
        transport = spec.transport
        container_port = spec.container_port

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
            labels={"mcp-gate.process": process_id, "mcp-gate.name": process.name},
        )
        try:
            self.runtime.launch(request, lambda stage, detail=None: progress.stage(pkey, stage, detail))
        except Exception as e:
            err = self._runtime_error(e, str(e))
            # a launch can fail half way (container created, start refused): do not leave that behind
            try:
                self._teardown(container_name)
            except Exception as cleanup_err:
                logger.warning(f"cleanup after failed launch of {container_name}: {cleanup_err}")
            raise err from e
        logger.info(f"{self.runtime.name} instance started for {process.name}: {container_name}")
        with self._lock:
            self._active.add(process_id)

        # From here on the instance exists: any failure must tear it down again (keeping its last log lines),
        # or it would leak -- running, holding the port, and remembered in _active.
        try:
            return self._finish_start(db, process, spec, port, port_note, pkey)
        except Exception as e:
            raise self._abort_start(db, process_id, container_name, e) from e

    def _finish_start(
        self, db: Session, process: ManagedMcpProcess, spec, port: int, port_note: str, pkey: str,
    ) -> ManagedMcpProcess:
        process_id = str(process.id)
        container_name = _container_name(process_id)
        transport = spec.transport
        progress = get_progress_registry()

        # Path depends on transport: http images ship /mcp; stdio goes through supergateway's Streamable HTTP.
        if transport == "stdio":
            mcp_path = _STDIO_HTTP_PATH
            description = f"Custom MCP (BYO): {' '.join(spec.stdio_command)}"
        else:
            mcp_path = "/mcp"
            description = f"Managed via marketplace catalog '{process.catalog_id}'"

        # Wait for the port, then for the server itself.
        # On the first start of stdio (BYO), npx/uvx must **download packages on the spot**, which can take
        # far longer than http mode (image already local) -- use the longer timeout, otherwise the first
        # deployment almost always times out. Can be overridden via env vars. One deadline covers both phases.
        start_timeout = _START_TIMEOUT_STDIO if transport == "stdio" else _START_TIMEOUT_HTTP
        deadline = time.monotonic() + start_timeout
        progress.stage(pkey, "waiting_port", str(port))
        logger.info(
            f"Waiting up to {start_timeout:.0f}s for {process.name} to answer on port {port} "
            f"(transport={transport})"
        )
        try:
            self._wait_for_port("127.0.0.1", port, timeout=start_timeout)
        except TimeoutError as e:
            raise OrchestratorError(f"Port {port} did not open within {start_timeout:.0f}s") from e
        logger.info(f"Port {port} is listening for {process.name}")

        # A listening port proves nothing under Docker: the port proxy accepts connections as soon as the
        # container exists. Only a JSON-RPC answer to `initialize` means the server is up. For the stdio
        # bridge this request also does the warm-up: supergateway's stateful mode spawns the child only when
        # the first request arrives, and npx must install packages online on first use (tens of seconds).
        # Left to the later health check (a few seconds of timeout) it would disconnect first, and supergateway
        # would then crash writing back to a connection it cannot find (observed in practice) -- so the probe
        # keeps the connection open until the deadline.
        progress.stage(pkey, "warming_up" if transport == "stdio" else "waiting_ready")
        self._wait_ready(port, mcp_path, deadline)
        logger.info(f"MCP initialize answered on port {port} for {process.name}")

        # Fetch the runtime's id for the instance (container id / pid)
        sibling_container_id = self.runtime.instance_id(container_name)
        logger.info(f"Instance id for {process.name}: {sibling_container_id}")

        # Auto-create the Service row (if not there yet).
        progress.stage(pkey, "registering_service")
        service_id = self._ensure_service(
            db, process, port, mcp_path=mcp_path, description=description,
        )

        # Update DB (a port that had to move stays visible in last_error)
        updated = ManagedMcpProcessAdapter.update_state(
            db, process_id,
            actual_state="running",
            container_id=sibling_container_id or "",
            bridge_container_id="",
            port=port,
            service_id=str(service_id) if service_id else None,
            last_error=port_note,
        )
        logger.info(
            f"Managed MCP started: name={process.name}, port={port}, "
            f"container={sibling_container_id}, service_id={service_id}"
        )
        return updated

    def _abort_start(self, db: Session, process_id: str, container_name: str, e: Exception) -> OrchestratorError:
        """A start failed after the launch: keep the instance's last output, remove it, mark the process failed."""
        reason = str(e) if isinstance(e, OrchestratorError) else f"{type(e).__name__}: {e}"
        logger.error(f"Start of {container_name} failed after launch: {reason}")
        try:
            db.rollback()  # a DB error (e.g. in _ensure_service) must not poison the failure bookkeeping
        except Exception:
            pass
        logs = self._log_tail(container_name)
        removed = True
        try:
            self._teardown(container_name)
        except Exception as cleanup_err:
            removed = False
            reason = f"{reason} (cleanup failed, the instance may still exist: {cleanup_err})"
            logger.error(f"cleanup of {container_name} failed: {cleanup_err}")
        if removed:
            with self._lock:
                self._active.discard(process_id)
        last_error = _compose_last_error(reason, logs)
        self._mark_failed(db, process_id, last_error, clear_instance=removed)
        if isinstance(e, RuntimeUnavailable):
            return RuntimeUnavailable(reason, last_error=last_error)
        return OrchestratorError(reason, last_error=last_error)

    def _log_tail(self, container_name: str) -> str:
        try:
            return self.runtime.logs(container_name, tail=_FAILURE_LOG_LINES)
        except Exception as e:
            return f"(failed to read logs: {e})"

    @staticmethod
    def _mark_failed(db: Session, process_id: str, last_error: str, clear_instance: bool = False) -> None:
        """Best-effort: the original error matters more than a failure to record it."""
        try:
            if clear_instance:
                ManagedMcpProcessAdapter.update_state(
                    db, process_id, actual_state="failed", last_error=last_error,
                    container_id="", bridge_container_id="",
                )
            else:
                ManagedMcpProcessAdapter.update_state(db, process_id, actual_state="failed", last_error=last_error)
        except Exception as db_err:
            logger.error(f"Could not record failure of {process_id}: {db_err}")

    def _reserve_port(self, db: Session, process: ManagedMcpProcess) -> Tuple[int, str]:
        """Pick the port for this start and write it to the DB at once, under the global lock, so two
        concurrent starts can never pick the same one. Returns (port, note); note is non-empty when an
        auto_port process could not keep its previous port.

        A process keeps the port it has whenever nothing else uses it (its own leftover instance was already
        removed by the caller): clients have that URL configured. Only when it truly cannot be reused is a new
        one allocated -- logged and recorded in last_error, never silently.
        A manual port (auto_port=False) is never moved: an unusable one fails the start.
        """
        process_id = str(process.id)
        previous = process.port
        with self._lock:
            if process.auto_port:
                reason = (
                    self.port_allocator.unavailable_reason(db, previous, exclude_process_id=process_id)
                    if previous else None
                )
                if previous and reason is None:
                    return previous, ""
                try:
                    port = self.port_allocator.allocate(db, exclude_process_id=process_id)
                except PortAllocationError as e:
                    raise OrchestratorError(str(e)) from e
                note = ""
                if previous:
                    note = (
                        f"Port {previous} could not be reused ({reason}); moved to {port}. "
                        f"Clients configured with the old URL must be updated."
                    )
                    logger.warning(f"{process.name}: {note}")
                ManagedMcpProcessAdapter.update_state(db, process_id, port=port)
                return port, note

            if not previous:
                raise OrchestratorError("auto_port=False but no port set")
            reason = self.port_allocator.unavailable_reason(db, previous, exclude_process_id=process_id)
            if reason:
                raise OrchestratorError(f"Configured port {previous} is not available: {reason}")
            return previous, ""

    def _runtime_error(self, e: Exception, message: str) -> OrchestratorError:
        """Wrap a runtime exception; RuntimeUnavailable when the runtime itself is unreachable."""
        if isinstance(e, OrchestratorError):
            return e
        if isinstance(e, RuntimeUnavailableError):
            return RuntimeUnavailable(message)
        try:
            ok, detail = self.runtime.availability()
        except Exception as avail_err:
            ok, detail = False, str(avail_err)
        if not ok:
            return RuntimeUnavailable(f"{message} ({self.runtime.name} runtime unavailable: {detail})")
        return OrchestratorError(message)

    def _teardown(self, container_name: str) -> None:
        self.runtime.stop(container_name)
        self.runtime.remove(container_name)

    @classmethod
    def _wait_ready(cls, port: int, path: str, deadline: float) -> None:
        """Poll an MCP `initialize` until it gets a JSON-RPC answer, or raise OrchestratorError at the deadline."""
        last = "no attempt"
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OrchestratorError(
                    f"MCP initialize on 127.0.0.1:{port}{path} did not succeed in time (last: {last})"
                )
            ok, last = cls._probe_initialize(port, path, remaining)
            if ok:
                return
            time.sleep(max(0.0, min(0.5, deadline - time.monotonic())))

    @staticmethod
    def _probe_initialize(port: int, path: str, timeout: float) -> Tuple[bool, str]:
        """Send one MCP `initialize` (JSON-RPC over Streamable HTTP) and wait up to ``timeout`` for the answer.

        Returns (ready, detail). Ready means an HTTP response below 500 carrying a JSON-RPC envelope -- a
        JSON-RPC error still proves an MCP server is answering. The connection is kept open while waiting
        (see the stdio warm-up note in _finish_start)."""
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "mcp-gate-readiness", "version": "1.0.0"},
            },
        })
        req = (
            f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Accept: application/json, text/event-stream\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode()
        deadline = time.monotonic() + timeout
        buf = b""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=min(10.0, max(timeout, 0.1))) as sock:
                sock.sendall(req)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False, "timed out waiting for the initialize response"
                    sock.settimeout(min(30.0, remaining))
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    buf += chunk
                    status = _http_status(buf)
                    if status is not None and status < 500 and b'"jsonrpc"' in buf:
                        return True, f"HTTP {status}"
        except OSError as e:
            return False, f"{type(e).__name__}: {e}"
        status = _http_status(buf)
        if status is None:
            return False, "connection closed without an HTTP response"
        return False, f"HTTP {status} without a JSON-RPC answer"

    def _stop_locked(self, db: Session, process_id: str) -> ManagedMcpProcess:
        process = ManagedMcpProcessAdapter.get_by_id(db, process_id)
        if not process:
            raise OrchestratorError(f"Process {process_id} not found")

        logger.info(f"Stopping managed MCP: name={process.name}, id={process_id}")

        container_name = _container_name(process_id)
        logger.info(f"Stopping {self.runtime.name} instance: {container_name}")
        get_progress_registry().stage(process_key(process_id), "stopping_container")
        try:
            self._teardown(container_name)
        except Exception as e:
            # The instance may still be running: never record it as stopped (nor let uninstall forget it).
            err = self._runtime_error(
                e, f"Could not stop {container_name} on {self.runtime.name}; it may still be running: {e}"
            )
            logger.error(str(err))
            ManagedMcpProcessAdapter.update_state(
                db, process_id, actual_state="stop_failed", last_error=str(err),
            )
            raise err from e
        with self._lock:
            self._active.discard(process_id)
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
        MCP Gate runs with --network host, 127.0.0.1 is the host loopback).

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


def _http_status(buf: bytes) -> Optional[int]:
    """Status code of a raw HTTP response once its status line has arrived."""
    if not buf.startswith(b"HTTP/") or b"\r\n" not in buf:
        return None
    parts = buf.split(b"\r\n", 1)[0].split()
    try:
        return int(parts[1])
    except (IndexError, ValueError):
        return None


def _compose_last_error(reason: str, logs: str) -> str:
    """reason + the instance's last log lines, capped at _LAST_ERROR_MAX_CHARS (the newest output wins)."""
    header = f"{reason}\n--- last {_FAILURE_LOG_LINES} log lines ---\n"
    budget = _LAST_ERROR_MAX_CHARS - len(header)
    logs = (logs or "").strip()
    if budget <= 3:
        return header[:_LAST_ERROR_MAX_CHARS]
    if len(logs) > budget:
        logs = "..." + logs[-(budget - 3):]
    return header + logs


# -------- Singleton --------

_orchestrator: Optional[Orchestrator] = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator
