"""Managed MCP Orchestrator

Starts/stops/monitors MCP containers installed from the marketplace catalog or from a
user's BYO definition. External callers only go through the Orchestrator class; the
in-memory state is owned by this class.

All container operations go through the docker SDK (docker-py) to the Docker Engine
API; we never shell out to the docker CLI -- tainted parameters are passed to the API
as typed arguments, so there is no OS-command sink.

Two transports (source unified by LaunchSpec, see src/orchestrator/launch_spec):
  - http: the image ships its own HTTP server and is run directly.
  - stdio: supergateway inside the managed base image bridges via **Streamable HTTP**
    (POST /mcp + mcp-session-id; not the legacy HTTP+SSE -- this project's scanner only
    speaks the former). supergateway spawns the inner MCP command (npx/uvx/...) **inside
    the container**; we only hand "supergateway + inner command" to the docker SDK as a
    list -- no shell, no host subprocess (containerised bridging, which removes the
    subprocess sink that was taken out earlier). BYO inner commands go through the
    argv_policy command whitelist + args character whitelist.

Start flow (start):
  1. Read the process from the DB and the matching entry from the catalog
  2. Decrypt env vars
  3. Allocate a port with PortAllocator (if auto_port=True)
  4. Start the sibling container via docker SDK containers.run
     (-p 127.0.0.1:<port>:<container_port>; image/args/command/env from the catalog)
  5. Wait for the port to listen (http 30s / stdio 300s, see _START_TIMEOUT_*)
  6. Grab the sibling container_id
  7. Auto-create the Service row (host=127.0.0.1, port=<port>,
     mcp_path=/mcp, requires_auth=false, source=managed)
  8. Update the DB: port, container_id, service_id, actual_state=running

Stop flow (stop):
  1. docker SDK stop + force-remove <container_name>
  2. Clear the in-memory entry
  3. Update the DB: actual_state=stopped, container_id=NULL

Design trade-offs:
  - The in-memory dict is lost when MCP Center restarts; reconcile() scans at startup
    for processes with desired_state=running that are actually stopped and restarts
    them (self-healing)
  - No background health-check loop here (the existing health_monitor handles it via
    the Service row)
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
from threading import Lock
from typing import Dict, Optional

import docker
from docker import errors as docker_errors
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
from src.orchestrator.progress import get_progress_registry, process_key
from src.orchestrator.launch_spec import resolve_launch_spec
from src.orchestrator.port_allocator import PortAllocator

# supergateway listens inside the container; the port is mapped out to 127.0.0.1:<host port>
_SUPERGATEWAY_BIN = "supergateway"
# HTTP path exposed by the stdio bridge. Uses Streamable HTTP (not legacy SSE), the same
# protocol this project's scanner / health check speak, so it is /mcp just like http images.
_STDIO_HTTP_PATH = "/mcp"

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


def _flags_to_kwargs(flags):
    """Convert a `docker run` flag sequence that already passed the argv_policy whitelist
    into kwargs for docker SDK `containers.run/create`.

    Only flags in argv_policy._ALLOWED_* need handling (everything else was rejected at
    validation), so the mapping is closed and unambiguous. Returns (kwargs, pull_always).
    """
    kwargs = {}
    pull_always = False
    i = 0
    while i < len(flags):
        tok = flags[i]
        # Value-less flags -> boolean docker SDK parameters
        bool_flags = {
            "--rm": {"auto_remove": True},
            "-i": {"stdin_open": True},
            "-t": {"tty": True},
            "-it": {"stdin_open": True, "tty": True},
            "--init": {"init": True},
        }
        if tok in bool_flags:
            kwargs.update(bool_flags[tok])
            i += 1
            continue
        # Flags with a value: both `--flag=value` and `--flag value` (format already checked by argv_policy)
        flag, sep, inline = tok.partition("=")
        if sep:
            value = inline
            i += 1
        else:
            value = flags[i + 1]
            i += 2
        if flag == "--network":
            kwargs["network"] = value
        elif flag == "--memory":
            kwargs["mem_limit"] = value
        elif flag == "--cpus":
            kwargs["nano_cpus"] = int(float(value) * 1_000_000_000)
        elif flag == "--pull":
            pull_always = (value == "always")
    return kwargs, pull_always


class Orchestrator:
    """Managed MCP start/stop management (singleton)

    All DB writes go through ManagedMcpProcessAdapter; subprocess state lives in memory.
    Thread-safe via _lock (operations are infrequent, a coarse-grained lock is enough).
    """

    def __init__(self, port_allocator: Optional[PortAllocator] = None):
        self.port_allocator = port_allocator or PortAllocator()
        self._subprocesses: Dict[str, subprocess.Popen] = {}
        self._lock = Lock()
        self._docker = None

    def _client(self):
        """Get (and cache) the Docker Engine API client.

        Uses the docker SDK (over the Docker socket) instead of shelling out to the
        `docker` CLI: tainted data is passed to the API as typed arguments and is never
        assembled into an OS command string -- this eliminates the command injection
        sink at its root (SAST: Stored Command Injection).
        """
        if self._docker is None:
            try:
                self._docker = docker.from_env()
            except docker_errors.DockerException as e:
                raise OrchestratorError(f"Cannot connect to Docker daemon: {e}") from e
        return self._docker

    # ---------- Public API ----------

    def image_exists(self, image_ref: str) -> bool:
        """Check whether a docker image already exists locally (docker SDK, no CLI)."""
        try:
            self._client().images.get(image_ref)
            return True
        except docker_errors.ImageNotFound:
            return False

    def load_image(self, tar_path: str) -> list:
        """Load an image from a tar file (equivalent to `docker load -i`, but via the docker SDK).

        Returns:
            List of loaded image tags (e.g. ["mit2i:v1.0.0"]).

        Raises:
            OrchestratorError: tar missing / malformed / daemon error.
        """
        try:
            with open(tar_path, "rb") as f:
                images = self._client().images.load(f)
        except FileNotFoundError as e:
            raise OrchestratorError(f"image tar not found: {tar_path}") from e
        except docker_errors.DockerException as e:
            raise OrchestratorError(f"docker load failed: {e}") from e
        tags = []
        for img in images:
            tags.extend(img.tags or [])
        logger.info(f"Image loaded from {tar_path}: tags={tags}")
        return tags

    def container_logs(self, process_id: str, tail: int = 200) -> str:
        """Get the container's output (including exited containers).

        After a crash the cause of death only exists in the container's log, which is why
        BYO does not use --rm (auto_remove would delete the log along with it); stop/uninstall
        remove it explicitly. When the container no longer exists, return an explicit message
        instead of raising -- the caller is debugging and should not fail just because there
        is nothing to find.
        """
        name = _container_name(process_id)
        try:
            container = self._client().containers.get(name)
        except docker_errors.NotFound:
            return f"(container '{name}' does not exist -- it may have been removed or never created)"
        except docker_errors.DockerException as e:
            return f"(cannot connect to Docker: {e})"
        try:
            raw = container.logs(tail=tail, timestamps=True)
            status = container.status
        except docker_errors.DockerException as e:
            return f"(failed to read logs: {e})"
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        return f"[container status: {status}]\n{text}"

    def start(self, db: Session, process_id: str) -> ManagedMcpProcess:
        """Start a Managed MCP process

        If it is already in _subprocesses (i.e. in-memory state thinks it is still running),
        stop first, then start.
        """
        with self._lock, get_progress_registry().track(process_key(process_id), "start"):
            return self._start_locked(db, process_id)

    def stop(self, db: Session, process_id: str) -> ManagedMcpProcess:
        """Stop the process (graceful -> forceful) + clean up the sibling container"""
        with self._lock, get_progress_registry().track(process_key(process_id), "stop"):
            return self._stop_locked(db, process_id)

    def is_running(self, process_id: str) -> bool:
        """Check whether the process is really running.

        The real Docker state takes priority; the in-memory subprocess is only a fallback --
        because _subprocesses is cleared when MCP Center restarts, while the sibling container
        is still maintained by the host daemon. An earlier version only checked in-memory state,
        which misjudged on restart -> killed and restarted a live container.
        """
        with self._lock:
            container_name = _container_name(process_id)
            # HTTP mode: running if the container is running (running_only filters out exited)
            if self._lookup_container_id(container_name, running_only=True):
                return True
            # stdio mode: running if the supergateway subprocess is still alive
            proc = self._subprocesses.get(process_id)
            if proc is not None:
                return proc.poll() is None
            return False

    def reconcile(self, db: Session) -> None:
        """Called at startup: align processes with desired_state=running to the actual docker state.

        Three scenarios:
          (a) container still alive -> restore the in-memory sentinel, no restart (zero interruption)
          (b) container gone -> start again
          (c) start failed -> mark actual_state=failed
        """
        targets = ManagedMcpProcessAdapter.list_all(
            db, desired_state="running"
        )
        for p in targets:
            process_id = str(p.id)
            container_name = _container_name(process_id)
            cid = self._lookup_container_id(container_name, running_only=True)

            if cid:
                # (a) Container is still alive; only the in-memory state was lost on MCP Center restart
                with self._lock:
                    # HTTP mode sentinel = None; in stdio mode the supergateway child is an
                    # orphan after restart with no Popen handle to reclaim -- still store None
                    # and accept that stdio mode has no SIGTERM ability in this situation
                    # (the next stop still cleans the container via _force_remove_container)
                    self._subprocesses.setdefault(process_id, None)
                logger.info(
                    f"Reconcile: recovered {p.name} ({process_id}), "
                    f"container {cid[:12]} still alive"
                )
                continue

            # (b) Container is really gone -> restart
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

        # If already in memory, stop first
        if process_id in self._subprocesses:
            logger.info(f"Process {process_id} already in memory, stopping first")
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

        # Remove any leftover container with the same name before starting
        self._force_remove_container(container_name)

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
            if transport == "http":
                validated = validate_command_tokens(image_command)
                container_command = validated or None
            elif transport == "stdio":
                inner_cmd, inner_args = validate_byo_launch(
                    spec.stdio_command[0] if spec.stdio_command else "",
                    spec.stdio_command[1:] if spec.stdio_command else [],
                )
                # supergateway spawns the inner command inside the container and bridges
                # stdio<->HTTP. We only hand "supergateway + inner command" to the docker SDK
                # as a list -- no shell, no host subprocess (removes the sink taken out earlier).
                inner = " ".join([inner_cmd] + inner_args)
                # Output uses Streamable HTTP (not supergateway's default legacy HTTP+SSE):
                # MCP has two HTTP transports, and this project's scanner/health check speak
                # Streamable HTTP (POST /mcp + mcp-session-id header). Legacy SSE needs a
                # GET /sse to open the stream and then POST /message, which the scanner does
                # not support -- using the default would give "right address, wrong protocol":
                # the service stays offline forever and no tools are discovered.
                # --stateful: keeps the initialize state in a session so the scanner's
                # three-step flow (initialize -> initialized -> tools/list) works; in stateless
                # mode every request is independent and tools/list fails as not initialized.
                # supergateway has no --host flag; app.listen(port) already binds all
                # interfaces, while externally it is still bound to 127.0.0.1 only (via ports=).
                container_command = [
                    _SUPERGATEWAY_BIN, "--stdio", inner,
                    "--outputTransport", "streamableHttp",
                    "--stateful",
                    "--streamableHttpPath", _STDIO_HTTP_PATH,
                    "--port", str(container_port),
                ]
            else:
                raise ArgvPolicyError(f"Unsupported transport: {transport!r}")
        except ArgvPolicyError as e:
            logger.error(
                f"Refusing to start {process.name} ({process_id}): "
                f"docker argv policy check failed: {e}"
            )
            raise OrchestratorError(f"docker argv policy check failed: {e}") from e

        logger.info(
            f"Starting managed MCP {process.name}: "
            f"transport={transport}, port={port}, image={image_ref}, "
            f"env_count={len(env_vars)}"
        )

        # Create and start directly via the docker SDK (replaces the `docker run` shell-out).
        # Tainted data (image/command/env/flags) is passed to the Engine API as typed
        # arguments; there is no OS-command sink anywhere. stdio also runs as a container
        # (supergateway spawns the inner command inside it), sharing the same docker SDK
        # path as http. argv_policy whitelisted flags -> SDK kwargs.
        run_kwargs, pull_always = _flags_to_kwargs(image_args_tokens)

        # Resilience of the stdio bridge: supergateway throws an uncaught exception and exits
        # entirely when "the client disconnects first, the child answers later" (upstream bug,
        # reproducible in practice). Any single timed-out health check could kill the bridge,
        # so we let docker pull it back up automatically.
        # Note: restart_policy and auto_remove (--rm) are mutually exclusive, so only apply it
        # when --rm is not set (BYO now uses --init and no --rm).
        if transport == "stdio" and not run_kwargs.get("auto_remove"):
            run_kwargs["restart_policy"] = {"Name": "on-failure", "MaximumRetryCount": 10}
        client = self._client()
        if pull_always:
            progress.stage(pkey, "pulling_image", image_ref)
            try:
                client.images.pull(image_ref)
            except docker_errors.DockerException as e:
                raise OrchestratorError(f"docker pull failed: {image_ref}: {e}") from e
        progress.stage(pkey, "creating_container", image_ref)
        try:
            client.containers.run(
                image_ref,
                command=container_command,
                name=container_name,
                detach=True,
                environment=dict(env_vars),
                ports={f"{container_port}/tcp": ("127.0.0.1", port)},
                **run_kwargs,
            )
            logger.info(f"Container started for {process.name}: {container_name}")
        except docker_errors.ImageNotFound as e:
            raise OrchestratorError(f"docker image not found: {image_ref}") from e
        except docker_errors.APIError as e:
            raise OrchestratorError(
                f"docker run failed: {getattr(e, 'explanation', None) or e}"
            ) from e

        # The container runs on its own, there is no external bridge process; store a sentinel
        self._subprocesses[process_id] = None

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

        # Fetch container_id
        sibling_container_id = self._lookup_container_id(container_name)
        logger.info(f"Container ID for {process.name}: {sibling_container_id}")

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
        # http mode has no external bridge process (sentinel=None); remove the in-memory entry
        self._subprocesses.pop(process_id, None)

        # Clean up the container (docker stop + docker rm -f)
        container_name = _container_name(process_id)
        logger.info(f"Stopping container: {container_name}")
        get_progress_registry().stage(process_key(process_id), "stopping_container")
        self._docker_stop_container(container_name)
        self._force_remove_container(container_name)
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

    def _docker_stop_container(self, name: str) -> None:
        """Stop the given container (docker SDK); missing or failed are both ignored."""
        try:
            self._client().containers.get(name).stop(timeout=10)
        except docker_errors.NotFound:
            pass
        except docker_errors.DockerException as e:
            logger.debug(f"stop container {name} ignored: {e}")

    def _force_remove_container(self, name: str) -> None:
        """Force-remove the container (docker SDK); missing or failed are both ignored."""
        try:
            self._client().containers.get(name).remove(force=True)
        except docker_errors.NotFound:
            pass
        except docker_errors.DockerException as e:
            logger.debug(f"remove container {name} ignored: {e}")

    def _lookup_container_id(self, name: str, running_only: bool = False) -> Optional[str]:
        """Look up the container ID; return the first match or None (docker SDK).

        running_only=True: only return running ones; exited/created count as absent.
        running_only=False: include stopped/exited, only used to identify leftovers to clean.
        The name filter is a substring match, consistent with the original `docker ps -f name=`
        behaviour; container names are unique (mcp-managed-<uuid8>), so there is no mismatch.
        """
        try:
            matches = self._client().containers.list(
                all=not running_only, filters={"name": name}
            )
            return matches[0].id if matches else None
        except docker_errors.DockerException:
            return None

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
