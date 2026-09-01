"""LaunchSpec: the orchestrator's unified launch description

Normalises both sources into one description so the orchestrator does not care whether
the source is a "file catalog" or a "user BYO definition":

  - catalog (repo YAML) -> existing http / stdio image.
  - user definition (BYO) -> managed base image + supergateway bridging the inner stdio command.

BYO execution model (design doc section 3-4): everything runs inside the container. The inner
MCP command (npx/uvx/node/python + args) is spawned by supergateway inside the base image,
which bridges stdio<->HTTP; we only hand "supergateway + inner command" to the docker SDK as
a **list** (no shell, no subprocess sink).
"""
import os
from dataclasses import dataclass, field
from typing import List, Optional

from db.models import ManagedMcpProcess

# Managed base image: contains node (supergateway) + python + uv, maintained by the platform with
# pinned versions. Offline environments must docker load it first (one-time platform setup).
# Can be overridden via env var.
MCP_RUNTIME_IMAGE = os.environ.get("MCP_RUNTIME_IMAGE", "mcp-runtime:1")

# BYO source prefix: ManagedMcpProcess.catalog_id = "user:<definition_uuid>"
USER_SOURCE_PREFIX = "user:"


@dataclass
class LaunchSpec:
    """Everything the orchestrator needs to start a managed process (source-agnostic)."""
    source_kind: str            # "catalog" | "user"
    source_id: str              # catalog id or definition uuid
    name: str
    transport: str              # "http" | "stdio"
    image_ref: str              # http: the user's image:tag; stdio-BYO: managed base image
    container_port: int
    run_flags: List[str] = field(default_factory=list)     # docker run flag tokens
    entrypoint_args: List[str] = field(default_factory=list)  # http: image entrypoint args
    stdio_command: List[str] = field(default_factory=list)    # stdio-BYO: inner MCP command tokens


def is_user_source(catalog_id: Optional[str]) -> bool:
    return bool(catalog_id) and catalog_id.startswith(USER_SOURCE_PREFIX)


def user_source_id(definition_id: str) -> str:
    """Wrap a definition uuid into the source string used as ManagedMcpProcess.catalog_id."""
    return f"{USER_SOURCE_PREFIX}{definition_id}"


def _definition_uuid(catalog_id: str) -> str:
    return catalog_id[len(USER_SOURCE_PREFIX):]


def resolve_launch_spec(db, process: ManagedMcpProcess) -> LaunchSpec:
    """Resolve a ManagedMcpProcess into a LaunchSpec (catalog or user source).

    Raises:
        LookupError: the source (catalog file or user definition) no longer exists.
    """
    import json

    catalog_id = process.catalog_id

    # ---- BYO user definition: managed base image + supergateway bridging the inner stdio command ----
    if is_user_source(catalog_id):
        # Access via adapter (keeps the "only src/adapters touches db.crud" invariant)
        from src.adapters.managed_adapter import BYODefinitionAdapter

        definition = BYODefinitionAdapter.get_by_id(db, _definition_uuid(catalog_id))
        if not definition:
            raise LookupError(f"BYO definition '{catalog_id}' not found")
        inner = [definition.command] + definition.get_args()
        return LaunchSpec(
            source_kind="user",
            source_id=str(definition.id),
            name=process.name,
            transport="stdio",
            image_ref=MCP_RUNTIME_IMAGE,
            container_port=definition.container_port or 8000,
            run_flags=(process.image_args or "--rm").split(),
            stdio_command=inner,
        )

    # ---- File catalog: use the existing http / stdio image ----
    from src.marketplace.loader import get_catalog_loader

    catalog = get_catalog_loader().get(catalog_id)
    if not catalog:
        raise LookupError(f"Catalog entry '{catalog_id}' not found")

    entrypoint_args = []
    if process.image_command:
        try:
            v = json.loads(process.image_command)
            if isinstance(v, list):
                entrypoint_args = v
        except Exception:
            entrypoint_args = []

    return LaunchSpec(
        source_kind="catalog",
        source_id=catalog_id,
        name=process.name,
        transport=getattr(catalog.docker, "transport", "http"),
        image_ref=process.docker_image,
        container_port=getattr(catalog.docker, "container_port", 8080),
        run_flags=(process.image_args or "--rm").split(),
        entrypoint_args=entrypoint_args,
    )
