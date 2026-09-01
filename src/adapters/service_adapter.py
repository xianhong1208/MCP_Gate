"""Service domain adapter."""

from typing import Optional

from db.crud import ServiceCRUD, normalize_service_host
from src.adapters.exceptions import ConflictError, NotFoundError


def fallback_service_name(host: str, port: int) -> str:
    """Name given to a scanned server whose real name could not be read (e.g. it was locked)."""
    return f"mcp-{normalize_service_host(host).replace('.', '-')}-{port}"


def sanitize_server_name(server_name: str) -> str:
    """Turn an MCP serverInfo.name into a service name (no spaces or slashes)."""
    return server_name.replace(" ", "-").replace("/", "-")


class ServiceAdapter(ServiceCRUD):

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
    def create_checked(cls, db, **kwargs):
        """Create a service; same name + host:port already exists -> 409 service.duplicate."""
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
        service = cls.update(db=db, service_id=service_id, **kwargs)
        if not service:
            raise NotFoundError(code="service.not_found", fallback="Service not found")
        return service
