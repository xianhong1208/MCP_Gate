"""Base Exception Classes"""

from typing import Optional, Any
from fastapi import HTTPException


class MCPCenterError(Exception):
    """Base exception for all MCP Center errors

    Attributes:
        code: Error code for programmatic handling
        message: Human-readable error message
        details: Additional error context
    """

    code: str = "INTERNAL_ERROR"
    message: str = "An internal error occurred"
    status_code: int = 500

    def __init__(
        self,
        message: Optional[str] = None,
        code: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        self.message = message or self.__class__.message
        self.code = code or self.__class__.code
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API response"""
        result = {
            "error": self.code,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result

    def to_http_exception(self) -> HTTPException:
        """Convert to FastAPI HTTPException"""
        return HTTPException(
            status_code=self.status_code,
            detail=self.to_dict(),
        )


class MCPCenterHTTPException(MCPCenterError):
    """Base exception that can be directly raised as HTTP response"""

    def __init__(
        self,
        message: Optional[str] = None,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message=message, code=code, details=details)
        if status_code is not None:
            self.status_code = status_code
