"""Adapter-layer domain exceptions

The adapter (middle layer) only raises these **HTTP-independent** domain exceptions; the
route (HTTP boundary) is responsible for translating them into HTTPException. Each exception
carries three attributes, status_code / code / fallback, so a route can translate generically
with a **single** except, matching the response format of the original inline HTTPException:

    from fastapi import HTTPException
    from src.adapters.exceptions import AdapterError
    ...
    try:
        ...
    except AdapterError as e:
        raise HTTPException(status_code=e.status_code,
                            detail={"error": e.code, "fallback": e.fallback})

This keeps the adapter pure (no fastapi import) while the route fully preserves the
original response contract (status code + {"error", "fallback"}).
"""

from typing import Optional


class AdapterError(Exception):
    """Base of adapter-layer domain exceptions (HTTP-agnostic).

    Subclasses set the default status_code as a class attribute; each call site specifies
    code / fallback matching the original error code and message, so the response after
    route translation stays identical word for word.
    """

    status_code: int = 400
    code: str = "adapter.error"
    fallback: str = "Operation failed"

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        fallback: Optional[str] = None,
        params: Optional[dict] = None,
    ):
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        if fallback is not None:
            self.fallback = fallback
        # params maps to the "params" of the original HTTPException detail (only some errors have it);
        # the route includes it only when non-empty, to keep the original response format.
        self.params = params or {}
        super().__init__(message or self.fallback)

    def to_detail(self) -> dict:
        """Build the same detail dict as the original inline HTTPException."""
        detail = {"error": self.code, "fallback": self.fallback}
        if self.params:
            detail["params"] = self.params
        return detail


class NotFoundError(AdapterError):
    """Resource does not exist."""
    status_code = 404
    code = "not_found"
    fallback = "Resource not found"


class PermissionDeniedError(AdapterError):
    """Insufficient permission / not the owner."""
    status_code = 403
    code = "permission.denied"
    fallback = "Permission denied"


class ConflictError(AdapterError):
    """State conflict (e.g. duplicate, already exists)."""
    status_code = 409
    code = "conflict"
    fallback = "Conflict"


class ValidationFailedError(AdapterError):
    """Input validation failed."""
    status_code = 400
    code = "validation_failed"
    fallback = "Validation failed"
