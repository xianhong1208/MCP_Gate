"""#36: client configuration export for Claude Code, Cursor, VS Code and Codex.

Golden files in tests/fixtures/client_config/ hold the exact output for three servers (two with the same name,
to cover key de-duplication). The API tests check the URL is the service's audience, permissions, the PAT
variant never carries a token, and that every snippet is safe to paste whatever the service is called.
"""

import base64
import json
import pathlib
import shlex
import subprocess
import tomllib
from urllib.parse import parse_qs, urlsplit

import pytest

from src.utils.client_config import CLIENTS, VARIANTS, Server, generate, pat_env_var

GOLDEN = pathlib.Path(__file__).parent / "fixtures" / "client_config"
SERVERS = [Server("Folio", "https://folio.example.com/mcp", ("rag:read",)),
           Server("Morph yard", "http://127.0.0.1:5055/mcp"),
           Server("Folio", "https://other.example.com/mcp")]


def _gen(client, variant, servers=SERVERS):
    return generate(client, variant, servers, issuer="https://gate.example.com",
                    pat_page="https://gate.example.com/tokens/create")


def _parse(result):
    f = result["file"]
    return tomllib.loads(f["content"]) if f["format"] == "toml" else json.loads(f["content"])


# --------------------------------------------------------------------------- generator (golden files)

@pytest.mark.parametrize("client", CLIENTS)
@pytest.mark.parametrize("variant", VARIANTS)
def test_cc_001_output_matches_golden_file(client, variant):
    want = json.loads((GOLDEN / f"{client}-{variant}.json").read_text())
    assert _gen(client, variant) == want


def test_cc_002_claude_code_shape():
    doc = _parse(_gen("claude-code", "oauth"))
    assert doc == {"mcpServers": {
        "Folio": {"type": "http", "url": "https://folio.example.com/mcp"},
        "Morph-yard": {"type": "http", "url": "http://127.0.0.1:5055/mcp"},
        "Folio-2": {"type": "http", "url": "https://other.example.com/mcp"}}}
    cmds = [shlex.split(c) for c in _gen("claude-code", "oauth")["commands"]]
    assert cmds[0] == ["claude", "mcp", "add", "--transport", "http", "Folio", "https://folio.example.com/mcp"]
    assert cmds[1] == ["claude", "mcp", "login", "Folio"]


def test_cc_003_claude_code_pat_references_an_env_var():
    r = _gen("claude-code", "pat")
    doc = _parse(r)
    assert doc["mcpServers"]["Folio"]["headers"] == {"Authorization": "Bearer ${MCP_GATE_PAT_FOLIO}"}
    argv = shlex.split(r["commands"][0])
    assert argv[-2:] == ["--header", "Authorization: Bearer ${MCP_GATE_PAT_FOLIO}"]
    assert r["servers"][0]["pat_env"] == "MCP_GATE_PAT_FOLIO"
    assert r["pat_page"] == "https://gate.example.com/tokens/create"


def test_cc_004_cursor_shape_and_install_link():
    r = _gen("cursor", "oauth")
    assert _parse(r) == {"mcpServers": {"Folio": {"url": "https://folio.example.com/mcp"},
                                        "Morph-yard": {"url": "http://127.0.0.1:5055/mcp"},
                                        "Folio-2": {"url": "https://other.example.com/mcp"}}}
    assert r["commands"] == []
    link = urlsplit(r["install_links"][1])
    assert (link.scheme, link.netloc, link.path) == ("cursor", "anysphere.cursor-deeplink", "/mcp/install")
    q = parse_qs(link.query)
    assert q["name"] == ["Morph-yard"]
    assert json.loads(base64.b64decode(q["config"][0])) == {"url": "http://127.0.0.1:5055/mcp"}


def test_cc_005_cursor_pat_uses_env_interpolation():
    r = _gen("cursor", "pat")
    assert _parse(r)["mcpServers"]["Folio"]["headers"] == {"Authorization": "Bearer ${env:MCP_GATE_PAT_FOLIO}"}
    cfg = json.loads(base64.b64decode(parse_qs(urlsplit(r["install_links"][0]).query)["config"][0]))
    assert cfg["headers"] == {"Authorization": "Bearer ${env:MCP_GATE_PAT_FOLIO}"}


def test_cc_006_vscode_shape_and_command():
    r = _gen("vscode", "oauth")
    assert _parse(r) == {"servers": {"Folio": {"type": "http", "url": "https://folio.example.com/mcp"},
                                     "Morph-yard": {"type": "http", "url": "http://127.0.0.1:5055/mcp"},
                                     "Folio-2": {"type": "http", "url": "https://other.example.com/mcp"}}}
    argv = shlex.split(r["commands"][0])
    assert argv[:2] == ["code", "--add-mcp"]
    assert json.loads(argv[2]) == {"name": "Folio", "type": "http", "url": "https://folio.example.com/mcp"}


def test_cc_007_vscode_pat_prompts_for_the_token():
    doc = _parse(_gen("vscode", "pat"))
    assert doc["inputs"][0] == {"type": "promptString", "id": "mcp-gate-pat-Folio",
                                "description": "MCP Gate personal access token for Folio", "password": True}
    assert doc["servers"]["Folio"]["headers"] == {"Authorization": "Bearer ${input:mcp-gate-pat-Folio}"}
    assert [i["id"] for i in doc["inputs"]] == ["mcp-gate-pat-Folio", "mcp-gate-pat-Morph-yard",
                                                "mcp-gate-pat-Folio-2"]


def test_cc_008_codex_toml_shape_and_commands():
    r = _gen("codex", "oauth")
    assert _parse(r) == {"mcp_servers": {"Folio": {"url": "https://folio.example.com/mcp"},
                                         "Morph-yard": {"url": "http://127.0.0.1:5055/mcp"},
                                         "Folio-2": {"url": "https://other.example.com/mcp"}}}
    assert [shlex.split(c) for c in r["commands"][:2]] == [
        ["codex", "mcp", "add", "Folio", "--url", "https://folio.example.com/mcp"],
        ["codex", "mcp", "login", "Folio"]]
    pat = _parse(_gen("codex", "pat"))
    assert pat["mcp_servers"]["Morph-yard"] == {"url": "http://127.0.0.1:5055/mcp",
                                                "bearer_token_env_var": "MCP_GATE_PAT_MORPH_YARD"}


def test_cc_009_keys_are_unique_and_env_vars_safe():
    r = _gen("codex", "pat")
    assert [s["key"] for s in r["servers"]] == ["Folio", "Morph-yard", "Folio-2"]
    assert pat_env_var("a.b-c d") == "MCP_GATE_PAT_A_B_C_D"
    assert pat_env_var("---") == "MCP_GATE_PAT_SERVER"


def test_cc_010_unknown_client_or_variant_is_refused():
    with pytest.raises(ValueError):
        generate("windsurf", "oauth", SERVERS)
    with pytest.raises(ValueError):
        generate("cursor", "apikey", SERVERS)


def test_cc_011_oauth_variant_has_no_auth_header_and_no_pat_page():
    for client in CLIENTS:
        r = _gen(client, "oauth")
        assert "Authorization" not in r["file"]["content"]
        assert not any("Authorization" in c for c in r["commands"])
        assert r["pat_page"] is None


@pytest.mark.parametrize("url", ['https://h.example/mcp?a="x"&b=\\y', "http://h:1/mcp?q=$(id)"])
def test_cc_012_odd_urls_survive_every_format(url):
    servers = [Server("x", url)]
    assert _parse(_gen("codex", "oauth", servers))["mcp_servers"]["x"]["url"] == url
    for client in ("claude-code", "cursor"):
        assert _parse(_gen(client, "oauth", servers))["mcpServers"]["x"]["url"] == url
    assert _parse(_gen("vscode", "oauth", servers))["servers"]["x"]["url"] == url
    assert shlex.split(_gen("codex", "oauth", servers)["commands"][0])[-1] == url


# --------------------------------------------------------------------------- API

def _set(service, **fields):
    """Write fields straight to the row (the API never stores some of these combinations, e.g. no address)."""
    import uuid

    from db.database import make_session
    from db.models import Service

    db = make_session()
    try:
        row = db.get(Service, uuid.UUID(service["id"]))
        for k, v in fields.items():
            setattr(row, k, v)
        db.commit()
    finally:
        db.close()


def test_cc_020_requires_sign_in(app, service):
    from tests.conftest import make_console_client

    with make_console_client(app) as anon:
        assert anon.get("/api/client-config?client=cursor").status_code == 401
        assert anon.get(f"/api/services/{service['id']}/client-config?client=cursor").status_code == 401


def test_cc_021_service_endpoint_uses_the_audience(owner_client, service):
    r = owner_client.put(f"/api/services/{service['id']}",
                         json={"oauth_audience": "https://Demo.Example.com/mcp/"})
    assert r.status_code == 200, r.text
    _set(service, oauth_scopes="a:read")
    for client in CLIENTS:
        r = owner_client.get(f"/api/services/{service['id']}/client-config", params={"client": client})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["servers"] == [{"name": "demo-mcp", "key": "demo-mcp", "url": "https://demo.example.com/mcp",
                                    "scopes": ["a:read"]}]
        assert "https://demo.example.com/mcp" in body["file"]["content"]
        assert "127.0.0.1:8123" not in body["file"]["content"]
        assert body["issuer"] and body["requires_auth"] is True
        assert isinstance(body["dcr_auto_approve"], bool)


def test_cc_022_falls_back_to_the_mcp_url(owner_client, service):
    body = owner_client.get(f"/api/services/{service['id']}/client-config", params={"client": "codex"}).json()
    assert body["servers"][0]["url"] == "http://127.0.0.1:8123/mcp"


def test_cc_023_audience_that_is_not_a_url_falls_back_to_the_address(owner_client, service):
    _set(service, oauth_audience="urn:demo")
    body = owner_client.get(f"/api/services/{service['id']}/client-config", params={"client": "codex"}).json()
    assert body["servers"][0]["url"] == "http://127.0.0.1:8123/mcp"


def test_cc_024_no_url_is_409(owner_client, service):
    _set(service, host=None, port=None, oauth_audience=None)
    r = owner_client.get(f"/api/services/{service['id']}/client-config", params={"client": "cursor"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "client_config.no_url"


def test_cc_025_bad_parameters(owner_client, service):
    sid = service["id"]
    r = owner_client.get(f"/api/services/{sid}/client-config", params={"client": "windsurf"})
    assert r.status_code == 422 and r.json()["detail"]["error"] == "client_config.unknown_client"
    r = owner_client.get(f"/api/services/{sid}/client-config", params={"client": "cursor", "variant": "key"})
    assert r.status_code == 422 and r.json()["detail"]["error"] == "client_config.unknown_variant"
    r = owner_client.get("/api/services/00000000-0000-0000-0000-000000000000/client-config",
                         params={"client": "cursor"})
    assert r.status_code == 404


def test_cc_026_download_returns_the_file(owner_client, service):
    r = owner_client.get(f"/api/services/{service['id']}/client-config",
                         params={"client": "codex", "download": "true"})
    assert r.status_code == 200
    assert r.headers["content-disposition"] == 'attachment; filename="config.toml"'
    assert r.headers["content-type"].startswith("application/toml")
    assert tomllib.loads(r.text) == {"mcp_servers": {"demo-mcp": {"url": "http://127.0.0.1:8123/mcp"}}}
    r = owner_client.get(f"/api/services/{service['id']}/client-config",
                         params={"client": "vscode", "download": "1", "variant": "pat"})
    assert r.headers["content-disposition"] == 'attachment; filename="mcp.json"'
    assert "inputs" in r.json()


def test_cc_027_pat_variant_never_contains_a_token(owner_client, service):
    r = owner_client.post("/api/oauth/tokens/personal", json={"service_id": service["id"], "expires_days": 30,
                                                              "label": "cc"})
    assert r.status_code == 201, r.text
    token = r.json().get("access_token") or r.json().get("token")
    assert token
    for client in CLIENTS:
        for path in (f"/api/services/{service['id']}/client-config", "/api/client-config"):
            text = owner_client.get(path, params={"client": client, "variant": "pat"}).text
            assert token not in text and token[:16] not in text
    body = owner_client.get(f"/api/services/{service['id']}/client-config",
                            params={"client": "cursor", "variant": "pat"}).json()
    assert body["pat_page"].endswith(f"/tokens/create?service_id={service['id']}")


def test_cc_028_all_services_export(owner_client, service):
    r = owner_client.post("/api/services", json={"name": "zeta", "host": "127.0.0.1", "port": 8124,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    zeta = r.json()
    r = owner_client.post("/api/services", json={"name": "alpha", "host": "127.0.0.1", "port": 8125,
                                                 "protocol": "http", "mcp_path": "/mcp"})
    _set(r.json(), host=None, port=None)
    off = owner_client.post("/api/services", json={"name": "off", "host": "127.0.0.1", "port": 8126,
                                                   "protocol": "http", "mcp_path": "/mcp"}).json()
    _set(off, is_active=False)
    body = owner_client.get("/api/client-config", params={"client": "claude-code"}).json()
    assert [s["key"] for s in body["servers"]] == ["demo-mcp", "zeta"]
    assert body["skipped"] == ["alpha"]
    assert body["pat_page"] is None
    doc = json.loads(body["file"]["content"])
    assert doc["mcpServers"]["zeta"]["url"] == f"http://127.0.0.1:{zeta['port']}/mcp"
    pat = owner_client.get("/api/client-config", params={"client": "claude-code", "variant": "pat"}).json()
    assert pat["pat_page"].endswith("/tokens/create")


EVIL_NAMES = ["pwn;touch${IFS}CC_RCE;#", "a'b\"c", "x\ny", "$(touch CC_RCE)", "名稱 ]\n[evil]"]


@pytest.mark.parametrize("name", EVIL_NAMES)
def test_cc_029_snippets_are_safe_to_paste(owner_client, service, name, tmp_path):
    _set(service, name=name)
    for exe in ("claude", "code", "codex"):
        stub = tmp_path / exe
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        stub.chmod(0o755)
    for client in CLIENTS:
        for variant in VARIANTS:
            body = owner_client.get(f"/api/services/{service['id']}/client-config",
                                    params={"client": client, "variant": variant}).json()
            key = body["servers"][0]["key"]
            assert all(c.isascii() and (c.isalnum() or c in "-_") for c in key)
            doc = _parse(body)
            top = doc["mcp_servers"] if client == "codex" else doc["servers" if client == "vscode" else "mcpServers"]
            assert list(top) == [key]
            for cmd in body["commands"]:
                assert "\n" not in cmd
                out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, cwd=tmp_path,
                                     env={"PATH": f"{tmp_path}:/usr/bin:/bin"})
                assert out.returncode == 0, out.stderr
            assert not (tmp_path / "CC_RCE").exists()


def test_cc_030_stored_audience_is_normalised_like_token_audiences(owner_client, service):
    # rows written before audiences were normalised on save keep their spelling; tokens carry the normalised one
    _set(service, oauth_audience="https://Legacy.Example.com/mcp/")
    body = owner_client.get(f"/api/services/{service['id']}/client-config", params={"client": "cursor"}).json()
    assert body["servers"][0]["url"] == "https://legacy.example.com/mcp"
