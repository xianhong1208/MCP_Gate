"""Authentication and Authorization Exceptions"""

from typing import Optional
from src.exceptions.base import MCPCenterHTTPException


class AuthenticationError(MCPCenterHTTPException):
    """Base authentication error"""

    code = "AUTHENTICATION_ERROR"
    message = "Authentication failed"
    status_code = 401


class TokenNotFoundError(MCPCenterHTTPException):
    """Token does not exist"""

    code = "TOKEN_NOT_FOUND"
    message = "Token not found"
    status_code = 404

    def __init__(
        self,
        token_preview: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if token_preview:
            details["token_preview"] = token_preview
        super().__init__(details=details, **kwargs)


class TokenExpiredError(MCPCenterHTTPException):
    """Token has expired"""

    code = "TOKEN_EXPIRED"
    message = "Token has expired"
    status_code = 401

    def __init__(
        self,
        expired_at: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if expired_at:
            details["expired_at"] = expired_at
        super().__init__(details=details, **kwargs)


class TokenRevokedError(MCPCenterHTTPException):
    """Token has been revoked"""

    code = "TOKEN_REVOKED"
    message = "Token has been revoked"
    status_code = 401

    def __init__(
        self,
        revoked_at: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if revoked_at:
            details["revoked_at"] = revoked_at
        super().__init__(details=details, **kwargs)


class InvalidTokenError(MCPCenterHTTPException):
    """Token is malformed or invalid"""

    code = "INVALID_TOKEN"
    message = "Invalid token format"
    status_code = 401

    def __init__(
        self,
        reason: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if reason:
            details["reason"] = reason
        super().__init__(details=details, **kwargs)


class InvalidCredentialsError(MCPCenterHTTPException):
    """Invalid username or password"""

    code = "INVALID_CREDENTIALS"
    message = "Invalid username or password"
    status_code = 401


class InsufficientScopeError(MCPCenterHTTPException):
    """Token lacks required scopes"""

    code = "INSUFFICIENT_SCOPE"
    message = "Token does not have required permissions"
    status_code = 403

    def __init__(
        self,
        required_scopes: Optional[list[str]] = None,
        token_scopes: Optional[list[str]] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if required_scopes:
            details["required_scopes"] = required_scopes
        if token_scopes:
            details["token_scopes"] = token_scopes
        super().__init__(details=details, **kwargs)


class ServiceMismatchError(MCPCenterHTTPException):
    """Token does not belong to the requested service"""

    code = "SERVICE_MISMATCH"
    message = "Token does not match the requested service"
    status_code = 403

    def __init__(
        self,
        expected_service: Optional[str] = None,
        token_service: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if expected_service:
            details["expected_service"] = expected_service
        if token_service:
            details["token_service"] = token_service
        super().__init__(details=details, **kwargs)
