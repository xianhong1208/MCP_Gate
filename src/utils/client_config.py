"""Ready-made configuration for connecting MCP clients to servers MCP Gate protects (#36).

One generator for the console and for scripts (``GET /api/services/{id}/client-config`` and
``GET /api/client-config``). Pure functions: no database, no network, no secrets.

Each client is told only the URL of the MCP server. The URL is the service's audience (its RFC 8707
resource): a client sends the URL it connects to as ``resource``, and MCP Gate maps that back to the
service, so any other spelling of the address fails with ``invalid_target``. Sign-in then runs through
OAuth discovery (RFC 9728 protected resource metadata -> MCP Gate) with dynamic client registration or a
Client ID Metadata Document, which all four clients do on their own.

The ``pat`` variant is for setups without a browser (CI, remote shells). It never carries a token: the
snippet references an environment variable (or, in VS Code, a password prompt), and the person creates a
personal access token in the console and sets that variable themselves.

Client documentation these shapes follow (checked 2026-11-22):
- Claude Code: https://code.claude.com/docs/en/mcp
- Cursor: https://cursor.com/docs/context/mcp and https://cursor.com/docs/context/mcp/install-links
- VS Code: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- Codex: https://learn.chatgpt.com/docs/extend/mcp?surface=cli
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

from src.utils.snippets import shell_command, shell_quote, snippet_server_name

CLIENTS = ("claude-code", "cursor", "vscode", "codex")
VARIANTS = ("oauth", "pat")

DOCS = {
    "claude-code": "https://code.claude.com/docs/en/mcp",
    "cursor": "https://cursor.com/docs/context/mcp",
    "vscode": "https://code.visualstudio.com/docs/agents/reference/mcp-configuration",
    "codex": "https://learn.chatgpt.com/docs/extend/mcp?surface=cli",
}

# Where each client reads the snippet from, and the name the downloaded file gets (no leading dot, so it is
# not hidden after download; the console says where to put it).
FILES = {
    "claude-code": {"format": "json", "filename": "mcp.json", "path": ".mcp.json"},
    "cursor": {"format": "json", "filename": "mcp.json", "path": "~/.cursor/mcp.json"},
    "vscode": {"format": "json", "filename": "mcp.json", "path": ".vscode/mcp.json"},
    "codex": {"format": "toml", "filename": "config.toml", "path": "~/.codex/config.toml"},
}

_ENV_UNSAFE = re.compile(r"[^A-Z0-9]+")


@dataclass(frozen=True)
class Server:
    """One MCP server as a client sees it."""
    name: str                 # display name (the service name)
    url: str                  # the URL the client connects to = the service's audience
    scopes: tuple = ()        # scopes the service accepts (informational; clients discover them)


def pat_env_var(key: str) -> str:
    """The environment variable a PAT snippet reads, one per server (a PAT is bound to one audience)."""
    return "MCP_GATE_PAT_" + (_ENV_UNSAFE.sub("_", key.upper()).strip("_") or "SERVER")


def vscode_input_id(key: str) -> str:
    return f"mcp-gate-pat-{key}"


def _keys(servers: list[Server]) -> list[str]:
    """Config keys / CLI names: slugs, made unique by a numeric suffix."""
    seen: set[str] = set()
    out = []
    for s in servers:
        base = snippet_server_name(s.name)
        key, n = base, 2
        while key in seen:
            key, n = f"{base}-{n}", n + 1
        seen.add(key)
        out.append(key)
    return out


def _bearer(ref: str) -> str:
    return f"Bearer {ref}"


def _toml_str(value: str) -> str:
    # A JSON string is a valid TOML basic string (same escapes; json.dumps never emits "\/").
    return json.dumps(str(value))


def _claude_code(servers, keys, pat):
    entries, commands = {}, []
    for s, k in zip(servers, keys):
        entry = {"type": "http", "url": s.url}
        add = shell_command("claude", "mcp", "add", "--transport", "http", k, s.url)
        if pat:
            # Claude Code expands ${VAR} in headers when it connects; single quotes keep the shell from doing it.
            header = f"Authorization: {_bearer('${' + pat_env_var(k) + '}')}"
            entry["headers"] = {"Authorization": _bearer("${" + pat_env_var(k) + "}")}
            commands.append(f"{add} --header {shell_quote(header)}")
        else:
            commands.append(add)
            commands.append(shell_command("claude", "mcp", "login", k))
        entries[k] = entry
    return {"mcpServers": entries}, commands, None


def _cursor(servers, keys, pat):
    entries, links = {}, []
    for s, k in zip(servers, keys):
        entry = {"url": s.url}
        if pat:
            entry["headers"] = {"Authorization": _bearer("${env:" + pat_env_var(k) + "}")}
        entries[k] = entry
        encoded = base64.b64encode(json.dumps(entry, separators=(",", ":")).encode()).decode()
        links.append(f"cursor://anysphere.cursor-deeplink/mcp/install?name={quote(k, safe='')}"
                     f"&config={quote(encoded, safe='')}")
    return {"mcpServers": entries}, [], links


def _vscode(servers, keys, pat):
    entries, commands, inputs = {}, [], []
    for s, k in zip(servers, keys):
        entry = {"type": "http", "url": s.url}
        if pat:
            # A password prompt: VS Code asks once and keeps the value in its secret storage, not in the file.
            inputs.append({"type": "promptString", "id": vscode_input_id(k),
                           "description": f"MCP Gate personal access token for {s.name}", "password": True})
            entry["headers"] = {"Authorization": _bearer("${input:" + vscode_input_id(k) + "}")}
        else:
            commands.append(shell_command("code", "--add-mcp", json.dumps({"name": k, **entry},
                                                                         separators=(",", ":"))))
        entries[k] = entry
    doc = {"inputs": inputs, "servers": entries} if pat else {"servers": entries}
    return doc, commands, None


def _codex(servers, keys, pat):
    blocks, commands = [], []
    for s, k in zip(servers, keys):
        lines = [f"[mcp_servers.{k}]", f"url = {_toml_str(s.url)}"]
        if pat:
            lines.append(f"bearer_token_env_var = {_toml_str(pat_env_var(k))}")
        else:
            commands.append(shell_command("codex", "mcp", "add", k, "--url", s.url))
            commands.append(shell_command("codex", "mcp", "login", k))
        blocks.append("\n".join(lines) + "\n")
    return "\n".join(blocks), commands, None


_BUILDERS = {"claude-code": _claude_code, "cursor": _cursor, "vscode": _vscode, "codex": _codex}


def generate(client: str, variant: str, servers: list[Server], *, issuer: Optional[str] = None,
             pat_page: Optional[str] = None) -> dict:
    """The configuration one client needs for ``servers`` (one, or all a person can see)."""
    if client not in CLIENTS:
        raise ValueError(f"unknown client: {client}")
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant: {variant}")
    pat = variant == "pat"
    keys = _keys(servers)
    doc, commands, links = _BUILDERS[client](servers, keys, pat)
    content = doc if isinstance(doc, str) else json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    return {
        "client": client,
        "variant": variant,
        "issuer": issuer,
        "docs_url": DOCS[client],
        "servers": [
            {"name": s.name, "key": k, "url": s.url, "scopes": list(s.scopes),
             **({"pat_env": pat_env_var(k)} if pat and client != "vscode" else {}),
             **({"pat_input": vscode_input_id(k)} if pat and client == "vscode" else {})}
            for s, k in zip(servers, keys)
        ],
        "file": {**FILES[client], "content": content},
        "commands": commands,
        "install_links": links or [],
        "pat_page": pat_page if pat else None,
    }
