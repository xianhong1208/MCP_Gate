"""Quoting for the copy-paste snippets the console generates (H-08).

Every value interpolated into a snippet can come from outside: a scanned MCP server picks its own
serverInfo.name, which becomes the service name. Snippets are pasted into a shell or a Python file by the
admin, so each value is quoted for the language it lands in, and the name a CLI uses as an identifier is
reduced to a slug first.
"""

from __future__ import annotations

import json
import re
import shlex

_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9_-]+")
SLUG_MAX_LEN = 64
FALLBACK_SLUG = "mcp-server"


def snippet_server_name(name: str | None) -> str:
    """The name `claude mcp add` / an mcpServers key gets: ASCII letters, digits, '-' and '_' only."""
    slug = _SLUG_UNSAFE.sub("-", name or "").strip("-_")[:SLUG_MAX_LEN].strip("-_")
    return slug or FALLBACK_SLUG


def shell_quote(value: str) -> str:
    """One POSIX shell word (bash / zsh / sh), whatever ``value`` contains."""
    return shlex.quote(str(value))


def shell_command(*argv: str) -> str:
    return " ".join(shell_quote(a) for a in argv)


def py_str(value: str) -> str:
    """A Python string literal for ``value`` (JSON string syntax is valid Python and escapes newlines/quotes)."""
    return json.dumps(str(value))
