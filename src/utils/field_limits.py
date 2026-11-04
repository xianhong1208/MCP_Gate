"""Length limits for values stored in bounded ``String(n)`` columns.

SQLite ignores the ``n`` in ``VARCHAR(n)``, PostgreSQL enforces it: an over-long value raises
``StringDataRightTruncation`` at flush time and the request ends in a 500 (and, mid-way through a multi-step
operation, leaves half of it committed). So:

- **input** from a person or a client is checked up front with ``check_max_length`` and refused with a
  ``validation.too_long`` error naming the field and its limit; it is never silently shortened;
- **text MCP Gate generates or relays** (remote error messages, log fields, names read from a remote server)
  is shortened with ``clip`` before it is stored.

The limits come from the model columns (``column_limit(Service.name)``), so a migration that widens a column
widens the check with it.
"""

from __future__ import annotations

from typing import Optional

TOO_LONG_CODE = "validation.too_long"


class FieldTooLongError(ValueError):
    """A value is longer than the column that stores it. Carries the console error code, its params and an
    English fallback, like the adapter errors."""

    code = TOO_LONG_CODE

    def __init__(self, field: str, limit: int):
        self.field = field
        self.limit = limit
        self.params = {"field": field, "max": limit}
        self.fallback = f"{field} is too long (maximum {limit} characters)."
        super().__init__(self.fallback)

    def to_detail(self) -> dict:
        return {"error": self.code, "params": self.params, "fallback": self.fallback}


def column_limit(column) -> int:
    """The ``n`` of a ``String(n)`` model attribute or table column."""
    return column.type.length


def check_max_length(field: str, value: Optional[str], limit: int) -> Optional[str]:
    """Return ``value`` unchanged, or raise FieldTooLongError when it is longer than ``limit`` characters."""
    if value is not None and len(value) > limit:
        raise FieldTooLongError(field, limit)
    return value


def clip(value: Optional[str], limit: int) -> Optional[str]:
    """Shorten generated or relayed text to ``limit`` characters, marking the cut with an ellipsis."""
    if value is None or len(value) <= limit:
        return value
    return value[: limit - 1] + "…"
