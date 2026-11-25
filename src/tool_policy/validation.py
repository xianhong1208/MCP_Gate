"""Limits and name checks for tool access (#37). Pure, no database."""

from __future__ import annotations

import json
import re

# RFC 6749 §3.3 scope-token: %x21 / %x23-5B / %x5D-7E. Excludes space, '"' and '\', so a scope can be put as is in
# WWW-Authenticate: Bearer error="insufficient_scope", scope="…" (RFC 6750 §3).
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")

# Per tool: how many scopes it may belong to
MAX_SCOPES_PER_TOOL = 32
# Per rule: how many tool names it may list
MAX_TOOLS_PER_RULE = 500
# Per server, after group rules are expanded to their members: the rules a server receives. Single tenant, so these
# are generous; they bound what one policy-feed answer can grow to.
MAX_RULES_PER_SERVICE = 2000
MAX_RULES_BYTES_PER_SERVICE = 64 * 1024
# Group names
GROUP_NAME_MAX = 64
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def is_scope_token(name) -> bool:
    """Whether ``name`` is an RFC 6749 scope-token (safe inside a quoted step-up challenge)."""
    return isinstance(name, str) and bool(_SCOPE_TOKEN.match(name))


def has_control_chars(value: str) -> bool:
    return bool(_CONTROL.search(value))


def rules_size(rules: list) -> int:
    """Bytes of the rules as the policy feed will serialise them (compact JSON, UTF-8)."""
    return len(json.dumps(rules, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
