"""Managed MCP / Tool domain adapter

Middle layer of the three-tier architecture: the API only calls methods here; the adapter is
responsible for "calling db.crud + business logic". Covers Managed MCP processes and
discovered MCP Tools.
"""

from db.crud import ManagedMcpProcessCRUD, MCPToolCRUD, UserMcpDefinitionCRUD
from src.adapters.exceptions import ConflictError, NotFoundError, ValidationFailedError


class MCPToolAdapter(MCPToolCRUD):
    """MCP Tool adapter."""


class ManagedMcpProcessAdapter(ManagedMcpProcessCRUD):
    """Managed MCP process adapter."""

    @classmethod
    def get_existing(cls, db, process_id):
        """Get an existing process; missing -> NotFoundError (managed.process_not_found)."""
        p = cls.get_by_id(db, process_id)
        if not p:
            raise NotFoundError(
                code="managed.process_not_found", fallback="Managed process not found",
            )
        return p

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
        - duplicate name -> ConflictError (409)
        """
        from src.marketplace.argv_policy import ArgvPolicyError, validate_byo_launch

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
        d = cls.get_by_id(db, definition_id)
        if not d:
            raise NotFoundError(
                code="byo.definition_not_found", fallback="BYO MCP definition not found",
            )
        return d

    @classmethod
    def delete_guarded(cls, db, definition_id):
        """Delete a definition; already deployed (a matching managed process exists) -> ConflictError (409)."""
        from src.orchestrator.launch_spec import user_source_id

        d = cls.get_existing(db, definition_id)
        deployed = ManagedMcpProcessAdapter.list_all(
            db, catalog_id=user_source_id(str(d.id))
        )
        if deployed:
            raise ConflictError(
                code="byo.definition_in_use",
                params={"process_id": str(deployed[0].id)},
                fallback="Definition is deployed; uninstall the process first.",
            )
        cls.delete(db, definition_id)
