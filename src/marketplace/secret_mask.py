"""Masking of secrets in BYO launch argv (known #8).

A pasted MCP config often carries credentials in its args (`--api-key=sk-...`, `--token sk-...`,
`API_KEY=sk-...`). The stored definition keeps the real values because the launcher needs them; every copy
that leaves the server (API responses, audit details) goes through ``mask_argv``.

Rule, applied per argv element:
  * ``--flag=value`` / ``-flag=value`` whose flag name looks sensitive -> ``--flag=****``
  * ``--flag value`` whose flag name looks sensitive -> the following element is masked, unless it is
    itself a flag (starts with ``-``)
  * ``NAME=value`` (env-style, NAME an identifier) whose NAME looks sensitive -> ``NAME=****``
  * a URL with a password in its userinfo (``scheme://user:pass@host``) -> the password is masked
A name looks sensitive when it contains key, token, secret, password / passwd / pwd, auth, credential or
private (case-insensitive). Masking errs on the side of hiding: a non-secret value after such a flag is
masked too, which only affects display.
"""

from __future__ import annotations

import re
from typing import Iterable, List

MASK = "****"

_SENSITIVE = re.compile(r"key|token|secret|passw(or)?d|pwd|auth|credential|private", re.I)
_FLAG_WITH_VALUE = re.compile(r"^(-{1,2}[^=\s]+)=(.*)$", re.S)
_ENV_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
_URL_PASSWORD = re.compile(r"(?P<head>[A-Za-z][A-Za-z0-9+.-]*://[^/:@\s]*:)(?P<pw>[^@/\s]+)(?P<tail>@)")


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE.search(name or ""))


def _mask_url_password(value: str) -> str:
    return _URL_PASSWORD.sub(lambda m: f"{m.group('head')}{MASK}{m.group('tail')}", value)


def mask_argv(argv: Iterable[str]) -> List[str]:
    out: List[str] = []
    mask_next = False
    for raw in argv or []:
        arg = str(raw)
        if mask_next and not arg.startswith("-"):
            out.append(MASK)
            mask_next = False
            continue
        mask_next = False
        m = _FLAG_WITH_VALUE.match(arg)
        if m:
            out.append(f"{m.group(1)}={MASK}" if is_sensitive_name(m.group(1)) else _mask_url_password(arg))
            continue
        if arg.startswith("-"):
            mask_next = is_sensitive_name(arg)
            out.append(arg)
            continue
        m = _ENV_ASSIGNMENT.match(arg)
        if m and is_sensitive_name(m.group(1)):
            out.append(f"{m.group(1)}={MASK}")
            continue
        out.append(_mask_url_password(arg))
    return out
