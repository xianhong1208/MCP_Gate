"""Managed MCP / Tool domain adapter

Middle layer of the three-tier architecture: the API only calls methods here; the adapter is
responsible for "calling db.crud + business logic". Covers Managed MCP processes and
discovered MCP Tools.
"""

from sqlalchemy.exc import IntegrityError

from db.crud import ManagedMcpProcessCRUD, MCPToolCRUD, UserMcpDefinitionCRUD
from db.models import (
    TOOL_SOURCE_REPORTED, TOOL_STATE_APPROVED, TOOL_STATE_PENDING, TOOL_STATE_REJECTED, MCPTool, UserMcpDefinition,
)
from src.adapters.exceptions import ConflictError, NotFoundError, ValidationFailedError
from src.logging import get_logger
from src.tool_pinning.hashing import canonical_json, tool_hash
from src.utils.field_limits import FieldTooLongError, check_max_length, column_limit

logger = get_logger("adapters.managed")


# The value type each hashed MCP tool field must have when present (None is always allowed: it means absent)
_TOOL_FIELD_TYPES = {"title": str, "description": str, "inputSchema": dict, "outputSchema": dict, "annotations": dict}


def sanitize_tools(tools: list[dict]) -> list[dict]:
    """Keep the tools a remote tools/list result can safely be stored as.

    The list comes from the remote server and is not trusted: a tool whose name is missing, blank or longer
    than the column (MCP limits tool names to 128 characters) is dropped, and a repeated name keeps only its
    first entry. One malformed tool must not cost the rest of the list -- or, on PostgreSQL, fail the whole
    refresh or scan with a 500. A tool whose hashed fields have the wrong JSON type (or cannot be hashed) is
    dropped too: it could never be approved, and a server using the pinning hooks hides it anyway.
    """
    limit = column_limit(MCPTool.name)
    kept, seen = [], set()
    for tool in tools:
        name = tool.get("name")
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) > limit:
            logger.warning(f"Skipping remote tool with an invalid name ({len(name)} characters): {name[:40]!r}")
            continue
        if name in seen:
            logger.warning(f"Skipping duplicate remote tool {name!r}")
            continue
        bad = [k for k, kind in _TOOL_FIELD_TYPES.items() if tool.get(k) is not None and not isinstance(tool[k], kind)]
        if bad:
            logger.warning(f"Skipping remote tool {name!r}: wrong type for {', '.join(bad)}")
            continue
        cleaned = {**tool, "name": name}
        try:
            tool_hash(cleaned)
        except (TypeError, ValueError) as e:
            logger.warning(f"Skipping remote tool {name!r}: its definition cannot be hashed ({e})")
            continue
        seen.add(name)
        kept.append(cleaned)
    return kept


# A reported definition larger than this (its canonical JSON, UTF-8) is refused: nothing legitimate comes close, and
# every version is stored and shown in the console
MAX_TOOL_DEFINITION_BYTES = 64 * 1024


def check_reported_tool(tool) -> tuple[str | None, str | None]:
    """Validate one tool definition a server reported (#33). Returns (its hash, None) or (None, the reason it is
    refused). Unlike sanitize_tools nothing is repaired (a name is not stripped): the hash must be the one the server
    computed over exactly what it lists, so a definition that cannot be stored as sent is refused as a whole."""
    if not isinstance(tool, dict):
        return None, "not_an_object"
    name = tool.get("name")
    if not isinstance(name, str) or not name or name != name.strip() or len(name) > column_limit(MCPTool.name):
        return None, "invalid_name"
    bad = [k for k, kind in _TOOL_FIELD_TYPES.items() if tool.get(k) is not None and not isinstance(tool[k], kind)]
    if bad:
        return None, "wrong_type:" + ",".join(bad)
    try:
        text = canonical_json(tool)
    except (TypeError, ValueError):
        return None, "not_hashable"
    if len(text.encode("utf-8")) > MAX_TOOL_DEFINITION_BYTES:
        return None, "too_large"
    return tool_hash(tool), None


# Which approval state each decision may move a version out of (#32). Rejected can be approved later, and an
# approval can be withdrawn by rejecting.
_ALLOWED_FROM = {
    TOOL_STATE_APPROVED: (TOOL_STATE_PENDING, TOOL_STATE_REJECTED),
    TOOL_STATE_REJECTED: (TOOL_STATE_PENDING, TOOL_STATE_APPROVED),
}


class MCPToolAdapter(MCPToolCRUD):
    """MCP Tool adapter: the tool list of a service and the approval of each pinned tool version (#32)."""

    @classmethod
    def sync_tools(cls, db, service_id, tools):
        """Record the remote list (MCP field names), minus tools that cannot be stored. New and changed tools
        become pending versions; nothing is deleted (see MCPToolCRUD.sync_tools)."""
        return super().sync_tools(db, service_id, sanitize_tools(tools))

    @classmethod
    def record_reported(cls, db, service_id, tools):
        """Record definitions a server's pinning middleware reported (#33), already checked with
        check_reported_tool: the same path as a refresh (record_tools), but partial (tools not mentioned are left
        alone) and with source "reported". Returns the (tool, version, created) triples.

        Two reports of the same new tool can race (unique tool name / hash per service): the loser is retried once,
        and then finds the winner's rows."""
        for attempt in (1, 2):
            try:
                return cls.record_tools(db, service_id, tools, complete=False, source=TOOL_SOURCE_REPORTED)[1]
            except IntegrityError:
                db.rollback()
                if attempt == 2:
                    raise
        return []  # pragma: no cover - the loop returns or raises

    @classmethod
    def get_existing(cls, db, service_id, tool_id):
        tool = cls.get_in_service(db, service_id, tool_id)
        if tool is None:
            raise NotFoundError(code="tools.not_found", fallback="Tool not found on this service")
        return tool

    @classmethod
    def decide(cls, db, service_id, tool_id, version_hash, state, actor):
        """Approve or reject one version of a tool, named by its hash (so the admin decides on exactly the
        definition they looked at). Returns (tool, version, previous_state)."""
        if state not in _ALLOWED_FROM:
            raise ValidationFailedError(code="tools.invalid_state", fallback=f"Unknown decision {state!r}")
        tool = cls.get_existing(db, service_id, tool_id)
        version = next((v for v in tool.versions if v.hash == version_hash), None)
        if version is None:
            raise NotFoundError(code="tools.version_not_found", params={"name": tool.name},
                                fallback=f"Tool '{tool.name}' has no version with that hash")
        previous = version.state
        if previous not in _ALLOWED_FROM[state]:
            raise ConflictError(code=f"tools.already_{previous}", params={"name": tool.name},
                                fallback=f"This version of '{tool.name}' is already {previous}")
        cls.set_version_state(db, version, state, actor)
        return tool, version, previous

    @classmethod
    def approve_first_list(cls, db, service_id, hashes, actor):
        """Approve all: only for a service's first tool list (no version of it was ever approved), and only the
        pending current versions the admin was shown (their hashes). Later changes are approved one by one.
        Returns the approved (tool, version) pairs."""
        if cls.has_approved_version(db, service_id):
            raise ConflictError(code="tools.approve_all_not_first",
                                fallback="Approve all is only for a service's first tool list; "
                                         "approve later changes one by one.")
        wanted = set(hashes)
        pairs = []
        for tool in cls.get_by_service(db, service_id, include_removed=False):
            version = tool.current_version
            if version is not None and version.state == TOOL_STATE_PENDING and version.hash in wanted:
                pairs.append((tool, version))
        if not pairs:
            raise ConflictError(code="tools.nothing_to_approve",
                                fallback="None of these tool versions is pending on this service any more.")
        cls.set_states(db, [v for _, v in pairs], TOOL_STATE_APPROVED, actor)
        return pairs


class ManagedMcpProcessAdapter(ManagedMcpProcessCRUD):
    """Managed MCP process adapter."""

    @classmethod
    def get_existing(cls, db, process_id):
        """Get an existing process; missing -> NotFoundError (managed.process_not_found)."""
        process = cls.get_by_id(db, process_id)
        if not process:
            raise NotFoundError(
                code="managed.process_not_found", fallback="Managed process not found",
            )
        return process

    @classmethod
    def assert_not_installed(cls, db, catalog_id):
        """Single-instance check: same catalog already installed -> ConflictError (409)."""
        existing = cls.list_all(db, catalog_id=catalog_id)
        if existing:
            existing_id = str(existing[0].id)
            raise ConflictError(
                code="managed.catalog_already_installed",
                params={"catalog_id": catalog_id, "process_id": existing_id},
                fallback=(
                    f"Catalog '{catalog_id}' is already installed "
                    f"(process_id={existing_id}). Single-instance policy."
                ),
            )

    @classmethod
    def purge_with_service(cls, db, process, logger) -> None:
        """Data cleanup for uninstall: delete the associated Service (including event records) + process row.

        (The caller performs the orchestrator stop first; this only handles the DB data chain.)
        """
        from src.adapters.service_adapter import ServiceAdapter

        associated_service_id = str(process.service_id) if process.service_id else None
        if associated_service_id:
            try:
                ServiceAdapter.delete(db, associated_service_id)
            except Exception as e:
                logger.warning(f"Service cleanup during uninstall: {e}")
        cls.delete(db, str(process.id))


class BYODefinitionAdapter(UserMcpDefinitionCRUD):
    """Bring-your-own (BYO) MCP definition adapter.

    Applies the argv policy on create (command whitelist + args character whitelist);
    blocks deletion while "deployed".
    """

    @classmethod
    def create_definition(
        cls, db, *, name, command, args=None, container_port=8000,
        env_schema=None, description=None, created_by_id=None,
    ):
        """Validate + create a BYO definition.

        - command/args violate the policy -> ValidationFailedError (400)
        - name longer than its column -> ValidationFailedError (400, validation.too_long)
        - duplicate name -> ConflictError (409)
        """
        from src.marketplace.argv_policy import ArgvPolicyError, validate_byo_launch

        try:
            check_max_length("name", name, column_limit(UserMcpDefinition.name))
        except FieldTooLongError as e:
            raise ValidationFailedError(code=e.code, params=e.params, fallback=e.fallback)

        try:
            validated_cmd, validated_args = validate_byo_launch(command, args or [])
        except ArgvPolicyError as e:
            raise ValidationFailedError(
                code="byo.invalid_command",
                params={"reason": str(e)},
                fallback=f"Invalid BYO launch command: {e}",
            )
        try:
            return cls.create(
                db, name=name, command=validated_cmd, args=validated_args,
                container_port=container_port, env_schema=env_schema,
                description=description, created_by_id=created_by_id,
            )
        except ValueError:
            raise ConflictError(
                code="byo.name_exists",
                params={"name": name},
                fallback=f"MCP definition '{name}' already exists",
            )

    @classmethod
    def get_existing(cls, db, definition_id):
        """Get an existing definition; missing -> NotFoundError (404)."""
        definition = cls.get_by_id(db, definition_id)
        if not definition:
            raise NotFoundError(
                code="byo.definition_not_found", fallback="BYO MCP definition not found",
            )
        return definition

    @classmethod
    def delete_guarded(cls, db, definition_id):
        """Delete a definition; already deployed (a matching managed process exists) -> ConflictError (409)."""
        from src.orchestrator.launch_spec import user_source_id

        definition = cls.get_existing(db, definition_id)
        deployed = ManagedMcpProcessAdapter.list_all(
            db, catalog_id=user_source_id(str(definition.id))
        )
        if deployed:
            raise ConflictError(
                code="byo.definition_in_use",
                params={"process_id": str(deployed[0].id)},
                fallback="Definition is deployed; uninstall the process first.",
            )
        cls.delete(db, definition_id)
