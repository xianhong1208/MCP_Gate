"""Docker runtime: managed servers run as sibling containers via the Docker SDK.

Uses the SDK (over the Docker socket) instead of shelling out to the ``docker`` CLI: tainted data is
passed to the Engine API as typed arguments and is never assembled into an OS command string, which
removes the command-injection sink at its root.
"""

from __future__ import annotations

import logging
from typing import List, Optional

import docker
from docker import errors as docker_errors

from src.orchestrator.runtime import LaunchRequest, ProgressFn, Runtime, bridge_argv

logger = logging.getLogger(__name__)


class DockerRuntimeError(Exception):
    """Raised for daemon / image / container failures; the Orchestrator wraps it."""


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


class DockerRuntime(Runtime):
    name = "docker"

    def __init__(self):
        self._docker = None

    def _client(self):
        """Get (and cache) the Docker Engine API client."""
        if self._docker is None:
            try:
                self._docker = docker.from_env()
            except docker_errors.DockerException as e:
                raise DockerRuntimeError(f"Cannot connect to Docker daemon: {e}") from e
        return self._docker

    # ------------------------------------------------------------------ Runtime
    def availability(self) -> tuple[bool, str]:
        try:
            self._client().ping()
            return True, "Docker daemon reachable"
        except (DockerRuntimeError, docker_errors.DockerException) as e:
            return False, str(e)

    def image_exists(self, image_ref: str) -> bool:
        try:
            self._client().images.get(image_ref)
            return True
        except docker_errors.ImageNotFound:
            return False

    def load_image(self, tar_path: str) -> List[str]:
        try:
            with open(tar_path, "rb") as f:
                images = self._client().images.load(f)
        except FileNotFoundError as e:
            raise DockerRuntimeError(f"image tar not found: {tar_path}") from e
        except docker_errors.DockerException as e:
            raise DockerRuntimeError(f"docker load failed: {e}") from e
        tags: List[str] = []
        for img in images:
            tags.extend(img.tags or [])
        logger.info(f"Image loaded from {tar_path}: tags={tags}")
        return tags

    def launch(self, request: LaunchRequest, progress: ProgressFn) -> None:
        # Remove any leftover container with the same name before starting
        self.remove(request.name)

        if request.transport == "http":
            command = list(request.entrypoint_args) or None
        else:
            # supergateway runs inside the managed base image and bridges the inner command's stdio to
            # Streamable HTTP on the container port, which is mapped out to 127.0.0.1:<host port>.
            command = bridge_argv(request.stdio_command, request.container_port)

        run_kwargs, pull_always = _flags_to_kwargs(request.run_flags)
        # Resilience of the stdio bridge: supergateway exits on an upstream bug when "the client disconnects
        # first, the child answers later", so let docker pull it back up. restart_policy and auto_remove
        # (--rm) are mutually exclusive, so only apply it when --rm is not set.
        if request.restart_on_failure and not run_kwargs.get("auto_remove"):
            run_kwargs["restart_policy"] = {"Name": "on-failure", "MaximumRetryCount": 10}

        client = self._client()
        if pull_always:
            progress("pulling_image", request.image_ref)
            try:
                client.images.pull(request.image_ref)
            except docker_errors.DockerException as e:
                raise DockerRuntimeError(f"docker pull failed: {request.image_ref}: {e}") from e
        progress("creating_container", request.image_ref)
        try:
            client.containers.run(
                request.image_ref,
                command=command,
                name=request.name,
                detach=True,
                environment=dict(request.env),
                ports={f"{request.container_port}/tcp": ("127.0.0.1", request.host_port)},
                labels=dict(request.labels),
                **run_kwargs,
            )
            logger.info(f"Container started: {request.name}")
        except docker_errors.ImageNotFound as e:
            raise DockerRuntimeError(f"docker image not found: {request.image_ref}") from e
        except docker_errors.APIError as e:
            raise DockerRuntimeError(f"docker run failed: {getattr(e, 'explanation', None) or e}") from e

    def stop(self, name: str) -> None:
        try:
            self._client().containers.get(name).stop(timeout=10)
        except docker_errors.NotFound:
            pass
        except (DockerRuntimeError, docker_errors.DockerException) as e:
            logger.debug(f"stop container {name} ignored: {e}")

    def remove(self, name: str) -> None:
        try:
            self._client().containers.get(name).remove(force=True)
        except docker_errors.NotFound:
            pass
        except (DockerRuntimeError, docker_errors.DockerException) as e:
            logger.debug(f"remove container {name} ignored: {e}")

    def instance_id(self, name: str, running_only: bool = False) -> Optional[str]:
        """running_only=True: exited/created count as absent. The name filter is a substring match; names
        are unique (mcp-managed-<uuid8>), so there is no mismatch."""
        try:
            matches = self._client().containers.list(all=not running_only, filters={"name": name})
            return matches[0].id if matches else None
        except (DockerRuntimeError, docker_errors.DockerException):
            return None

    def logs(self, name: str, tail: int = 200) -> str:
        """Includes exited containers: after a crash the cause of death only exists in the container's log,
        which is why BYO does not use --rm."""
        try:
            container = self._client().containers.get(name)
        except docker_errors.NotFound:
            return f"(container '{name}' does not exist -- it may have been removed or never created)"
        except (DockerRuntimeError, docker_errors.DockerException) as e:
            return f"(cannot connect to Docker: {e})"
        try:
            raw = container.logs(tail=tail, timestamps=True)
            status = container.status
        except docker_errors.DockerException as e:
            return f"(failed to read logs: {e})"
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        return f"[container status: {status}]\n{text}"
