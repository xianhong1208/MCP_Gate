"""Credential masking for database URLs before they are logged or printed (N1)."""

from __future__ import annotations

import re

# scheme://user:password@  ->  scheme://user:***@
_USERINFO_PASSWORD = re.compile(r"(?P<head>[A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]*:)[^@\s]*(?P<tail>@)")
# ?password=...  /  &password=...  (libpq also takes the password as a query parameter)
_QUERY_PASSWORD = re.compile(r"(?P<head>[?&](?:password|passwd|pwd)=)[^&#\s]*", re.I)


def redact_url_credentials(text: str) -> str:
    """Mask every URL password inside ``text`` (also usable on exception messages)."""
    text = _USERINFO_PASSWORD.sub(lambda m: f"{m.group('head')}***{m.group('tail')}", text or "")
    return _QUERY_PASSWORD.sub(lambda m: f"{m.group('head')}***", text)


def mask_db_url(url: str) -> str:
    """DATABASE_URL with its password replaced by ``***``; anything else is kept as written."""
    return redact_url_credentials(url)
