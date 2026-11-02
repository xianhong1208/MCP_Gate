"""H-08: generated copy-paste snippets must be safe to paste, whatever the service is called.

A scanned MCP server picks its own serverInfo.name, which used to land verbatim in
`claude mcp add --transport http <name> <url>`; `pwn;touch${IFS}X;#` ran a command in the admin's shell.
"""

import ast
import json
import shlex
import subprocess

import pytest

from src.adapters import sanitize_server_name
from src.utils.snippets import shell_quote, snippet_server_name

EVIL_NAMES = [
    "pwn;touch${IFS}X;#",
    "a'b\"c",
    "line1\nline2",
    "$(touch X)",
    "`touch X`",
    "x && rm -rf ~",
    "名稱 with space",
    "",
]


@pytest.mark.parametrize("name", EVIL_NAMES)
def test_snippet_server_name_is_a_safe_slug(name):
    slug = snippet_server_name(name)
    assert slug and all(c.isascii() and (c.isalnum() or c in "-_") for c in slug), slug
    assert len(slug) <= 64


@pytest.mark.parametrize("value", EVIL_NAMES + ["http://h:1/mcp?a=1&b=$(id)"])
def test_shell_quote_round_trips_through_a_posix_shell(value):
    assert shlex.split(shell_quote(value)) == [value]
    out = subprocess.run(["bash", "-c", f"printf %s {shell_quote(value)}"], capture_output=True, text=True)
    assert out.stdout == value


@pytest.mark.parametrize("name", ["pwn;touch${IFS}X;#", "a'b\"c", "line1\nline2", "$(touch X)"])
def test_sanitize_server_name_only_keeps_safe_characters(name):
    out = sanitize_server_name(name)
    assert out and all(c.isascii() and (c.isalnum() or c in "-_.") for c in out), out


def _rename(owner_client, service, name):
    # Names reach the DB through scans (serverInfo.name); the admin API is just the shortest way to store one.
    from db.database import make_session
    from src.adapters import ServiceAdapter

    db = make_session()
    try:
        ServiceAdapter.update(db, service["id"], name=name)
    finally:
        db.close()


@pytest.mark.parametrize("name", ["pwn;touch${IFS}SNIPPET_RCE;#", "a'b\"c", "x\ny", "$(id)"])
def test_snippets_are_safe_to_paste(owner_client, service, name, tmp_path):
    _rename(owner_client, service, name)
    r = owner_client.get(f"/api/oauth/snippets/{service['id']}")
    assert r.status_code == 200, r.text
    s = r.json()

    for key in ("claude_code_oauth", "claude_code_pat"):
        cmd = s[key]
        assert "\n" not in cmd
        argv = shlex.split(cmd)
        assert argv[:4] == ["claude", "mcp", "add", "--transport"]
        assert argv[5] == snippet_server_name(name)
        # run it for real with `claude` stubbed out: no side effects, argv as intended
        stub = tmp_path / "claude"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        stub.chmod(0o755)
        out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, cwd=tmp_path,
                             env={"PATH": f"{tmp_path}:/usr/bin:/bin"})
        assert out.returncode == 0, out.stderr
        assert out.stdout.splitlines()[:4] == ["mcp", "add", "--transport", "http"]
        assert not (tmp_path / "SNIPPET_RCE").exists()

    assert list(s["mcp_json_oauth"]["mcpServers"]) == [snippet_server_name(name)]
    assert list(s["mcp_json_pat"]["mcpServers"]) == [snippet_server_name(name)]

    # Python snippets parse, and the name is one string literal, not code
    for key in ("fastmcp_server", "fastmcp_hooks", "fastmcp_client"):
        tree = ast.parse(s[key].replace("async with", "with").replace("await ", ""))
        assert tree is not None
    for key in ("fastmcp_server", "fastmcp_hooks"):
        calls = [n for n in ast.walk(ast.parse(s[key])) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", None) == "FastMCP"]
        assert calls and ast.literal_eval(calls[0].keywords[0].value) == name
    assert json.dumps(s["mcp_json_oauth"])  # still plain JSON
