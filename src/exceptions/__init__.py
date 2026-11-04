"""MCP Gate custom exceptions."""

from src.exceptions.base import (
    MCPGateError,
    MCPGateHTTPException,
)
from src.exceptions.auth import (
    AuthenticationError,
    TokenNotFoundError,
    TokenExpiredError,
    TokenRevokedError,
    InvalidTokenError,
    InvalidCredentialsError,
    InsufficientScopeError,
    ServiceMismatchError,
)
from src.exceptions.service import (
    ServiceError,
    ServiceNotFoundError,
    ServiceAlreadyExistsError,
)
from src.exceptions.database import (
    DatabaseError,
    RecordNotFoundError,
    DuplicateRecordError,
)

__all__ = [
    # Base
    "MCPGateError",
    "MCPGateHTTPException",
    # Auth
    "AuthenticationError",
    "TokenNotFoundError",
    "TokenExpiredError",
    "TokenRevokedError",
    "InvalidTokenError",
    "InvalidCredentialsError",
    "InsufficientScopeError",
    "ServiceMismatchError",
    # Service
    "ServiceError",
    "ServiceNotFoundError",
    "ServiceAlreadyExistsError",
    # Database
    "DatabaseError",
    "RecordNotFoundError",
    "DuplicateRecordError",
]
