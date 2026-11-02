"""Service domain adapter."""

import re
from typing import Optional

from db.crud import ServiceCRUD, normalize_audience, normalize_service_host
from db.models import Service
from src.adapters.exceptions import ConflictError, NotFoundError, ValidationFailedError
from src.logging import get_logger
from src.utils import public_cache
from src.utils.field_limits import FieldTooLongError, check_max_length, column_limit
from src.utils.mcp_target import InvalidTargetError, validate_host, validate_mcp_path, validate_port, validate_protocol


def fallback_service_name(host: str, port: int) -> str:
    """Name given to a scanned server whose real name could not be read (e.g. it was locked)."""
    return f"mcp-{normalize_service_host(host).replace('.', '-')}-{port}"


_logger = get_logger("services")

_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_server_name(server_name: str) -> str:
    """Turn an MCP serverInfo.name into a service name: ASCII letters, digits, '.', '_' and '-' only.

    The name is chosen by the remote server and ends up in copy-paste shell snippets (H-08), so anything else
    (spaces, ';', '$', quotes, newlines, non-ASCII) becomes '-'. Returns "" when nothing usable is left; the
    caller then falls back to the generated name.
    """
    return _UNSAFE_NAME_CHARS.sub("-", server_name or "").strip("-.")[:column_limit(Service.name)].strip("-.")


def fallback_service_description(host: str, port: int) -> str:
    """Description given to a scanned server whose serverInfo could not be read."""
    return f"MCP service at {host}:{port}"


def describe_server(server_name: Optional[str], server_version: Optional[str] = None,
                    server_description: Optional[str] = None) -> Optional[str]:
    """Service description derived from MCP serverInfo / instructions; None when there is nothing to say."""
    if server_description:
        return server_description
    if server_name and server_name != "(requires auth)":
        return f"{server_name}{' v' + server_version if server_version else ''}"
    return None


# Prefix the scheduled health check used to stamp on every service description (#34). Such a
# description was written by MCP Gate, not the operator, so it may still be replaced.
_LEGACY_HEALTH_DESCRIPTION_PREFIX = "MCP service: "


def _validated_target(fields: dict) -> dict:
    """Check the operator-supplied fields among `fields` (only those present and not None) before they are stored.

    The scanner builds outbound URLs from protocol / host / port / path, so an '@' in the path or a URL in the
    protocol would redirect health checks and tool fetches to an arbitrary host: those raise
    ValidationFailedError with a `service.invalid_*` code. Text longer than its column raises
    `validation.too_long` (PostgreSQL would otherwise refuse the row with a 500). Returns the fields with the
    protocol normalised to lower case.
    """
    out = dict(fields)
    try:
        if out.get("protocol") is not None:
            out["protocol"] = validate_protocol(out["protocol"])
        if out.get("mcp_path") is not None:
            validate_mcp_path(out["mcp_path"])
        if out.get("host"):
            out["host"] = out["host"].strip()
            check_max_length("host", out["host"], column_limit(Service.host))
            validate_host(out["host"])
        if out.get("port") is not None:
            validate_port(out["port"])
        _check_lengths(out)
    except InvalidTargetError as e:
        raise ValidationFailedError(code=e.code, fallback=e.fallback)
    except FieldTooLongError as e:
        raise ValidationFailedError(code=e.code, fallback=e.fallback, params=e.params)
    return out


def _check_lengths(fields: dict) -> None:
    """Raise FieldTooLongError for a value that would not fit its column once stored the way ServiceCRUD
    stores it (lists comma- / space-joined, the audience normalised)."""
    if fields.get("name") is not None:
        check_max_length("name", fields["name"], column_limit(Service.name))
    if fields.get("tags"):
        check_max_length("tags", ",".join(fields["tags"]), column_limit(Service.tags))
    if fields.get("oauth_audience"):
        check_max_length("oauth_audience", normalize_audience(fields["oauth_audience"]),
                         column_limit(Service.oauth_audience))
    if fields.get("oauth_scopes"):
        check_max_length("oauth_scopes", " ".join(fields["oauth_scopes"]), column_limit(Service.oauth_scopes))


class ServiceAdapter(ServiceCRUD):

    @classmethod
    def delete(cls, db, service_id):
        """Delete a service; its declared scopes go with it (cascade), so the cached discovery metadata too."""
        deleted = super().delete(db, service_id)
        public_cache.invalidate()
        return deleted

    @classmethod
    def adopt_server_name(cls, db, service, server_name: Optional[str]) -> Optional[str]:
        """Replace a generated fallback name with the server's real name, once it becomes readable.

        Only auto-discovered services still carrying the `mcp-<host>-<port>` placeholder are renamed,
        and only when the new name is free; a name the operator chose is never touched.
        Returns the new name when a rename happened.
        """
        if not server_name or server_name == "(requires auth)":
            return None
        if service.source != "auto_discovered" or service.name != fallback_service_name(service.host, service.port):
            return None
        candidate = sanitize_server_name(server_name)
        if not candidate or candidate == service.name or cls.get_by_name(db, candidate):
            return None
        cls.update(db, str(service.id), name=candidate)
        return candidate

    @classmethod
    def adopt_server_description(cls, db, service, server_name: Optional[str], server_version: Optional[str] = None,
                                 server_description: Optional[str] = None) -> Optional[str]:
        """Fill the description from the server's serverInfo while it is still empty or generated.

        Generated means the scan placeholder (`MCP service at <host>:<port>`) or the text the health
        check used to stamp on every service; anything else was written by the operator and is never
        touched. Returns the new description when it changed.
        """
        if not server_name or server_name == "(requires auth)":
            return None
        current = (service.description or "").strip()
        generated = (not current or current == fallback_service_description(service.host, service.port)
                     or current.startswith(_LEGACY_HEALTH_DESCRIPTION_PREFIX))
        if not generated:
            return None
        desc = describe_server(server_name, server_version, server_description)
        if not desc or desc == current:
            return None
        cls.update(db, str(service.id), description=desc)
        return desc

    @classmethod
    def register_discovered(cls, db, *, tools: list, response_time_ms=None, **fields):
        """Register one scanned server with its tools and an `online` health stamp, all or nothing (#20).

        The CRUD steps commit separately, so a failure after the service row was written is undone by
        deleting that row again (tools cascade). The error is re-raised for the caller to report per server.
        """
        from src.adapters.managed_adapter import MCPToolAdapter

        created_id = None
        try:
            service = cls.create(db=db, **fields)
            created_id = str(service.id)
            if tools:
                MCPToolAdapter.sync_tools(db, created_id, tools)
            cls.update_health(db=db, service_id=created_id, status="online", response_time_ms=response_time_ms,
                              reset_fail_count=True)
            return service
        except Exception:
            db.rollback()
            if created_id is not None:
                try:
                    cls.delete(db, created_id)
                except Exception as cleanup_error:  # leave the original error in charge
                    db.rollback()
                    _logger.error(f"Could not remove half-registered service {created_id}: {cleanup_error}")
            raise

    @classmethod
    def create_checked(cls, db, **kwargs):
        """Create a service; same name + host:port already exists -> 409 service.duplicate.

        An invalid protocol / host / port / MCP path -> 400 service.invalid_*.
        """
        kwargs = _validated_target(kwargs)
        name, host, port = kwargs.get("name"), kwargs.get("host"), kwargs.get("port")
        if name and host and port and cls.get_by_name_and_host_port(db, name, host, port):
            raise ConflictError(
                code="service.duplicate",
                fallback="Service with the same name and host:port already exists.",
            )
        return cls.create(db=db, **kwargs)

    @classmethod
    def get_existing(cls, db, service_id):
        service = cls.get_by_id(db, service_id)
        if not service:
            raise NotFoundError(code="service.not_found", fallback="Service not found")
        return service

    @classmethod
    def update_existing(cls, db, service_id, **kwargs):
        kwargs = _validated_target(kwargs)
        service = cls.update(db=db, service_id=service_id, **kwargs)
        if not service:
            raise NotFoundError(code="service.not_found", fallback="Service not found")
        return service
