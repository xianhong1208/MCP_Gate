"""MCP server URLs cannot be steered to another host through the protocol, host or path.

The scanner pins each connection to an IP it has checked, but used to build the URL by concatenation,
so `mcp_path="@169.254.169.254/x"` (or a protocol of `http://169.254.169.254/#`) turned the pinned IP
into userinfo and sent the request to the metadata address. Every entry point now validates those
components, and the scanner refuses a stored row that fails validation without connecting.
"""
from urllib.parse import urlsplit

import pytest

from src.discovery import scanner as scanner_mod
from src.discovery.scanner import MCPScanner
from src.utils.mcp_target import (
    InvalidTargetError, build_mcp_url, validate_host, validate_mcp_path, validate_protocol,
)

BAD_PATHS = [
    "@169.254.169.254/x", "/@169.254.169.254", "//169.254.169.254/x", "mcp", "", "http://169.254.169.254/",
    "/mcp?x=1", "/mcp#frag", "/a\\b", "/a b", "/a\tb", "/a\r\nHost: evil", "/a\x00", "/%zz", "/%2",
    "/" + "a" * 128,
]
GOOD_PATHS = ["/", "/mcp", "/mcp/", "/api/v1/mcp", "/a-b_c.d~e", "/x%20y", "/a:b;c=d,e"]
BAD_PROTOCOLS = ["http://169.254.169.254/#", "ftp", "file", "gopher", "", None, "http:", "https://"]
BAD_HOSTS = ["a@b", "169.254.169.254/x", "evil.com#", "host:8080", "h st", "", "fe80::1%eth0", "a..b",
             "-bad", "http://x"]
GOOD_HOSTS = ["localhost", "127.0.0.1", "::1", "[::1]", "mcp.example.com", "my_host", "10.0.0.5"]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_bad_paths_are_rejected(path):
    with pytest.raises(InvalidTargetError) as e:
        validate_mcp_path(path)
    assert e.value.code == "service.invalid_mcp_path"


@pytest.mark.parametrize("path", GOOD_PATHS)
def test_good_paths_are_kept_verbatim(path):
    assert validate_mcp_path(path) == path


@pytest.mark.parametrize("protocol", BAD_PROTOCOLS)
def test_bad_protocols_are_rejected(protocol):
    with pytest.raises(InvalidTargetError) as e:
        validate_protocol(protocol)
    assert e.value.code == "service.invalid_protocol"


def test_protocol_is_case_insensitive():
    assert validate_protocol("HTTPS") == "https"


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_bad_hosts_are_rejected(host):
    with pytest.raises(InvalidTargetError) as e:
        validate_host(host)
    assert e.value.code == "service.invalid_host"


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_good_hosts_are_accepted(host):
    assert validate_host(host) == host


@pytest.mark.parametrize("protocol, path", [("http", p) for p in BAD_PATHS if p] +
                         [(p, "/mcp") for p in BAD_PROTOCOLS])
def test_built_url_never_leaves_the_pinned_ip(protocol, path):
    """Whatever is passed, the result is either an error or a URL whose authority is the given IP."""
    try:
        url = build_mcp_url(protocol, "10.1.2.3", 8080, path)
    except InvalidTargetError:
        return
    parts = urlsplit(url)
    assert (parts.hostname, parts.port, parts.username) == ("10.1.2.3", 8080, None)


def test_built_url_shape():
    assert build_mcp_url("http", "127.0.0.1", 80, "/mcp") == "http://127.0.0.1:80/mcp"
    assert build_mcp_url("https", "::1", 8443, "/m") == "https://[::1]:8443/m"
    assert build_mcp_url("http", "svc", 9000, None) == "http://svc:9000/"


class _NoSession:
    def __init__(self, *args, **kwargs):
        raise AssertionError("the scanner must not connect to an invalid target")


@pytest.fixture
def no_network(monkeypatch):
    monkeypatch.setattr(scanner_mod.aiohttp, "ClientSession", _NoSession)

    def no_resolve(*args, **kwargs):
        raise AssertionError("an invalid target must be rejected before it is resolved")
    monkeypatch.setattr(scanner_mod, "_resolve_validated_ip", no_resolve)


@pytest.mark.parametrize("protocol, path", [
    ("http", "@169.254.169.254/latest/meta-data/"),
    ("http://169.254.169.254/#", "/mcp"),
    ("http", "//169.254.169.254/"),
])
async def test_scanner_refuses_bypass_payloads(no_network, protocol, path):
    scanner = MCPScanner()
    result = await scanner.verify_mcp_service("127.0.0.1", 8080, path, protocol)
    assert not result.success and not result.reachable and "must" in result.error
    with pytest.raises(InvalidTargetError):
        await scanner.get_tools_list("127.0.0.1", 8080, path, protocol)


# ---------------------------------------------------------------- API entry points

@pytest.mark.parametrize("field, value, code", [
    ("mcp_path", "@169.254.169.254/x", "service.invalid_mcp_path"),
    ("mcp_path", "//evil/x", "service.invalid_mcp_path"),
    ("protocol", "http://169.254.169.254/#", "service.invalid_protocol"),
    ("host", "evil@169.254.169.254", "service.invalid_host"),
    ("port", 70000, "service.invalid_port"),
])
def test_create_and_update_reject_bad_targets(owner_client, service, field, value, code):
    body = {"name": "svc-bad", "host": "127.0.0.1", "port": 9001, field: value}
    r = owner_client.post("/api/services", json=body)
    assert r.status_code == 400 and r.json()["detail"]["error"] == code, r.text
    r = owner_client.put(f"/api/services/{service['id']}", json={field: value})
    assert r.status_code == 400 and r.json()["detail"]["error"] == code, r.text
    assert owner_client.get(f"/api/services/{service['id']}").json()[field] == service[field]


def test_create_normalises_protocol_case(owner_client):
    r = owner_client.post("/api/services", json={"name": "svc-up", "host": "127.0.0.1", "port": 9002,
                                                 "protocol": "HTTPS", "mcp_path": "/api/mcp"})
    assert r.status_code == 201 and r.json()["protocol"] == "https"


def test_verify_rejects_bad_targets(owner_client, no_network):
    r = owner_client.post("/api/discovery/verify", json={"host": "127.0.0.1", "port": 80,
                                                         "mcp_path": "@169.254.169.254/x"})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "service.invalid_mcp_path"


def test_scan_rejects_bad_hosts(owner_client, no_network):
    r = owner_client.post("/api/discovery/scan", json={"hosts": ["evil@169.254.169.254"], "ports": [80],
                                                       "auto_register": False})
    assert r.status_code == 422 and r.json()["detail"]["error"] == "discovery.invalid_host"
    assert r.json()["detail"]["params"] == {"host": "evil@169.254.169.254"}


@pytest.fixture
def legacy_bad_service(owner_client):
    """A row stored before validation existed (written below the adapter's checks)."""
    from db.database import make_session
    from src.adapters import ServiceAdapter

    db = make_session()
    try:
        svc = ServiceAdapter.create(db, name="legacy", host="127.0.0.1", port=8080,
                                    mcp_path="@169.254.169.254/latest", requires_auth=False)
        return str(svc.id)
    finally:
        db.close()


def test_stored_bad_row_is_reported_not_contacted(owner_client, legacy_bad_service, no_network):
    r = owner_client.post(f"/api/services/{legacy_bad_service}/health-check")
    assert r.status_code == 200 and r.json()["status"] == "error"
    assert "MCP path" in r.json()["error_message"]
    r = owner_client.post(f"/api/services/{legacy_bad_service}/refresh-tools")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "service.invalid_mcp_path"


async def test_scheduled_health_check_skips_stored_bad_row(owner_client, legacy_bad_service, no_network):
    from src.scheduler import get_scheduler

    results = await get_scheduler().run_health_check_now()
    assert results["checked"] == 1 and results["error"] == 1
