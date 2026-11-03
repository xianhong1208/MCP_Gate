"""Managed MCP / Tool domain adapter

Middle layer of the three-tier architecture: the API only calls methods here; the adapter is
responsible for "calling db.crud + business logic". Covers Managed MCP processes and
discovered MCP Tools.
"""

from db.crud import ManagedMcpProcessCRUD, MCPToolCRUD, UserMcpDefinitionCRUD
from db.models import MCPTool, UserMcpDefinition
from src.adapters.exceptions import ConflictError, NotFoundError, ValidationFailedError
from src.logging import get_logger
from src.utils.field_limits import FieldTooLongError, check_max_length, column_limit

logger = get_logger("adapters.managed")


def sanitize_tools(tools: list[dict]) -> list[dict]:
    """Keep the tools a remote tools/list result can safely be stored as.

    The list comes from the remote server and is not trusted: a tool whose name is missing, blank or longer
    than the column (MCP limits tool names to 128 characters) is dropped, and a repeated name keeps only its
    first entry. One malformed tool must not cost the rest of the list -- or, on PostgreSQL, fail the whole
    refresh or scan with a 500.
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
        seen.add(name)
        kept.append({**tool, "name": name})
    return kept


class MCPToolAdapter(MCPToolCRUD):
    """MCP Tool adapter."""

    @classmethod
    def sync_tools(cls, db, service_id, tools):
        """Replace a service's tool list with the remote list, minus tools that cannot be stored."""
        return super().sync_tools(db, service_id, sanitize_tools(tools))


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
