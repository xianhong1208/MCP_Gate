"""Runtime abstraction for managed MCP servers.

The Orchestrator owns everything that is the same however a server runs: port allocation, the launch
spec, argv-policy validation, waiting for the port, service registration and DB state. A ``Runtime``
owns only how an instance is started, stopped, found and read: ``DockerRuntime`` runs it as a container,
``ProcessRuntime`` as a local subprocess. Both expose the stdio bridge (supergateway) on the same
Streamable-HTTP path so the rest of MCP Center cannot tell them apart.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# HTTP path exposed by the stdio bridge (Streamable HTTP, the protocol the scanner / health check speak)
STDIO_HTTP_PATH = "/mcp"
SUPERGATEWAY_BIN = os.environ.get("MCP_SUPERGATEWAY_BIN", "supergateway")

ProgressFn = Callable[[str, Optional[str]], None]


@dataclass
class LaunchRequest:
    """Everything a runtime needs to start one managed server. All argv fields have already passed the
    argv policy; runtimes must not re-interpret them through a shell."""
    name: str                       # instance name (container name / process label), unique per process
    transport: str                  # "http" (catalog image) or "stdio" (BYO command behind supergateway)
    image_ref: str                  # docker image; the process runtime ignores it
    run_flags: List[str]            # validated `docker run` flags; the process runtime ignores them
    entrypoint_args: List[str]      # http: validated container command (may be empty)
    stdio_command: List[str]        # stdio: validated inner command + args
    env: Dict[str, str]             # decrypted env vars for the server
    host_port: int                  # where MCP Center and clients reach it on 127.0.0.1
    container_port: int             # where the server listens inside a container
    restart_on_failure: bool = False
    labels: Dict[str, str] = field(default_factory=dict)


def bridge_argv(inner_command: List[str], port: int) -> List[str]:
    """supergateway argv bridging a stdio MCP server to Streamable HTTP on ``port``.

    --outputTransport streamableHttp (not legacy SSE) and --stateful are what this project's scanner and
    health check need; see the Docker runtime for the history."""
    return [
        SUPERGATEWAY_BIN, "--stdio", " ".join(inner_command),
        "--outputTransport", "streamableHttp",
        "--stateful",
        "--streamableHttpPath", STDIO_HTTP_PATH,
        "--port", str(port),
    ]


class Runtime(ABC):
    """How managed servers run. Instances are addressed by the ``name`` from their LaunchRequest."""

    name: str = "abstract"

    @abstractmethod
    def availability(self) -> tuple[bool, str]:
        """(usable, detail) -- e.g. whether the Docker daemon answers, or supergateway is installed."""

    @abstractmethod
    def image_exists(self, image_ref: str) -> bool:
        """Whether a catalog image is present locally (False for runtimes without images)."""

    @abstractmethod
    def load_image(self, tar_path: str) -> List[str]:
        """Load a catalog image tarball; return the tags loaded."""

    @abstractmethod
    def launch(self, request: LaunchRequest, progress: ProgressFn) -> None:
        """Start the instance and return once it has been created (not necessarily listening)."""

    @abstractmethod
    def stop(self, name: str) -> None:
        """Stop the instance gracefully; missing instances are ignored."""

    @abstractmethod
    def remove(self, name: str) -> None:
        """Remove whatever is left of the instance (container, pid file); missing is ignored."""

    @abstractmethod
    def instance_id(self, name: str, running_only: bool = False) -> Optional[str]:
        """An identifier for the instance (container id, pid) or None when absent / not running."""

    @abstractmethod
    def logs(self, name: str, tail: int = 200) -> str:
        """The instance's recent output, or an explanatory message when unavailable."""


def select_runtime(kind: Optional[str] = None) -> Runtime:
    """Pick the runtime from ``MCP_RUNTIME``: ``docker`` (default), ``process``, or ``auto`` (Docker when the
    daemon answers, else the process runtime)."""
    from src.orchestrator.docker_runtime import DockerRuntime
    from src.orchestrator.process_runtime import ProcessRuntime

    kind = (kind or os.environ.get("MCP_RUNTIME") or "docker").strip().lower()
    if kind == "docker":
        return DockerRuntime()
    if kind == "process":
        return ProcessRuntime()
    if kind == "auto":
        docker_rt = DockerRuntime()
        ok, _ = docker_rt.availability()
        return docker_rt if ok else ProcessRuntime()
    raise ValueError(f"unknown MCP_RUNTIME {kind!r}: expected docker, process or auto")
