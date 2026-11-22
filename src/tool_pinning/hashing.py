"""The pin of one MCP tool: a SHA-256 over its canonical definition (#32).

This module is deliberately self-contained (standard library only, no database or web imports): the FastMCP hooks a
server runs (#33) carry a copy of the same canonicalisation, and both sides must produce the same digest byte for
byte. The golden vectors in ``tests/fixtures/tool_hash_vectors.json`` pin the definition; any change to it is a
breaking change for every approved tool.

Definition (version 1):

1. Take the tool object exactly as ``tools/list`` returns it (MCP field names, camelCase).
2. Keep only these six fields: ``name``, ``title``, ``description``, ``inputSchema``, ``outputSchema``,
   ``annotations``. Every other field (``_meta``, ``icons``, vendor extensions, ...) is ignored.
3. A field that is **absent or JSON ``null``** is left out. Absent and ``null`` therefore hash the same; an empty
   string or an empty object is a value and is kept (``"description": ""`` differs from no description).
4. Serialise as JSON with keys sorted at every depth, no whitespace (``","`` and ``":"`` separators), non-ASCII
   characters written as themselves (``ensure_ascii=False``, not ``\\uXXXX`` escapes), NaN / Infinity refused.
   Array order is kept: it is part of the meaning (``required``, ``enum``).
5. Encode that text as UTF-8 and take the SHA-256; the pin is its lowercase hex digest (64 characters).

Numbers are written the way Python's ``json`` writes them (``1`` and ``1.0`` differ); a server re-serialising the
same schema always produces the same Python values, so this is stable for one server.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

HASH_VERSION = 1

# The MCP tool fields the pin covers, in the spelling tools/list uses
HASHED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def canonical_tool(tool: Mapping[str, Any]) -> dict:
    """The part of a tool the pin covers: the six hashed fields, absent and ``null`` ones left out."""
    return {key: tool[key] for key in HASHED_FIELDS if tool.get(key) is not None}


def canonical_json(tool: Mapping[str, Any]) -> str:
    """The canonical JSON text of a tool (see the module docstring)."""
    return json.dumps(canonical_tool(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def tool_hash(tool: Mapping[str, Any]) -> str:
    """The pin of a tool: lowercase hex SHA-256 of its canonical JSON, UTF-8 encoded."""
    return hashlib.sha256(canonical_json(tool).encode("utf-8")).hexdigest()
