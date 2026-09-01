"""Database-related Exceptions"""

from typing import Optional
from src.exceptions.base import MCPCenterHTTPException


class DatabaseError(MCPCenterHTTPException):
    """Base database error"""

    code = "DATABASE_ERROR"
    message = "Database operation failed"
    status_code = 500


class RecordNotFoundError(MCPCenterHTTPException):
    """Record does not exist in database"""

    code = "RECORD_NOT_FOUND"
    message = "Record not found"
    status_code = 404

    def __init__(
        self,
        model: Optional[str] = None,
        identifier: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if model:
            details["model"] = model
        if identifier:
            details["identifier"] = identifier
        super().__init__(details=details, **kwargs)


class DuplicateRecordError(MCPCenterHTTPException):
    """Record already exists (unique constraint violation)"""

    code = "DUPLICATE_RECORD"
    message = "Record already exists"
    status_code = 409

    def __init__(
        self,
        model: Optional[str] = None,
        field: Optional[str] = None,
        value: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if model:
            details["model"] = model
        if field:
            details["field"] = field
        if value:
            details["value"] = value
        super().__init__(details=details, **kwargs)
