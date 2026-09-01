"""Service-related Exceptions"""

from typing import Optional
from src.exceptions.base import MCPCenterHTTPException


class ServiceError(MCPCenterHTTPException):
    """Base service error"""

    code = "SERVICE_ERROR"
    message = "Service operation failed"
    status_code = 400


class ServiceNotFoundError(MCPCenterHTTPException):
    """Service does not exist"""

    code = "SERVICE_NOT_FOUND"
    message = "Service not found"
    status_code = 404

    def __init__(
        self,
        service_name: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if service_name:
            details["service_name"] = service_name
        super().__init__(details=details, **kwargs)


class ServiceAlreadyExistsError(MCPCenterHTTPException):
    """Service already exists"""

    code = "SERVICE_ALREADY_EXISTS"
    message = "Service already exists"
    status_code = 409

    def __init__(
        self,
        service_name: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if service_name:
            details["service_name"] = service_name
        super().__init__(details=details, **kwargs)
