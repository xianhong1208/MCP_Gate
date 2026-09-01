"""Service domain adapter."""

from db.crud import ServiceCRUD
from src.adapters.exceptions import ConflictError, NotFoundError


class ServiceAdapter(ServiceCRUD):

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
