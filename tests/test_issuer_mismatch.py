"""Requests that reach the OAuth surface through a host other than OAUTH_ISSUER are flagged once per host."""

import pytest

from src.middleware.issuer_check import (
    external_base_url, issuer_base_url, normalize_base_url, observed_mismatches, reset_observed,
)


@pytest.fixture(autouse=True)
def _clean_observed():
    reset_observed()
    yield
    reset_observed()


def _scope(host, *, scheme="http", peer="10.0.0.9", extra=None):
    headers = [(b"host", host.encode())] + [(k.encode(), v.encode()) for k, v in (extra or {}).items()]
    return {"type": "http", "scheme": scheme, "path": "/.well-known/oauth-authorization-server",
            "headers": headers, "client": (peer, 12345)}


def test_normalisation_drops_default_ports_and_case():
    assert normalize_base_url("HTTPS", "Example.com:443") == "https://example.com"
    assert normalize_base_url("http", "example.com:80") == "http://example.com"
    assert normalize_base_url("http", "example.com:4568") == "http://example.com:4568"
    assert normalize_base_url("https", "[::1]:443") == "https://[::1]"
    assert normalize_base_url("http", "[::1]") == "http://[::1]"
    assert issuer_base_url("https://auth.example.com/") == "https://auth.example.com"
    assert issuer_base_url("http://localhost:4568") == "http://localhost:4568"


def test_forwarded_headers_only_honoured_from_trusted_proxy():
    fwd = {"x-forwarded-proto": "https", "x-forwarded-host": "auth.example.com"}
    trusted = ["127.0.0.1"]
    # Through the proxy: the public address wins
    assert external_base_url(_scope("127.0.0.1:4568", peer="127.0.0.1", extra=fwd), trusted) == "https://auth.example.com"
    # Same headers from an untrusted peer are ignored
    assert external_base_url(_scope("127.0.0.1:4568", peer="203.0.113.5", extra=fwd), trusted) == "http://127.0.0.1:4568"


def test_matching_host_records_nothing(client):
    # conftest sets OAUTH_ISSUER=http://testserver and TestClient uses that base_url
    assert client.get("/.well-known/oauth-authorization-server").status_code == 200
    assert client.post("/oauth/token", data={}).status_code in (400, 401, 422)
    assert observed_mismatches() == []


def test_mismatching_host_is_recorded_once_and_visible_in_overview(owner_client, monkeypatch):
    from src.config import Config

    # A host *name* other than the issuer must be allowed explicitly first (DNS-rebinding check, test_trusted_host)
    monkeypatch.setattr(Config.get_security_config(), "allowed_hosts", ["mcp.lan"])
    for _ in range(3):
        r = owner_client.get("/.well-known/oauth-authorization-server", headers={"Host": "192.168.1.20:4568"})
        assert r.status_code == 200
    owner_client.get("/.well-known/jwks.json", headers={"Host": "mcp.lan"})

    seen = observed_mismatches()
    assert [m["base_url"] for m in seen] == ["http://192.168.1.20:4568", "http://mcp.lan"]
    assert seen[0]["count"] == 3 and seen[0]["issuer"] == "http://testserver"
    assert seen[0]["first_path"] == "/.well-known/oauth-authorization-server"

    overview = owner_client.get("/api/oauth/overview").json()
    assert [m["base_url"] for m in overview["issuer_mismatches"]] == ["http://192.168.1.20:4568", "http://mcp.lan"]


def test_console_paths_are_not_checked(owner_client):
    assert owner_client.get("/api/session/status", headers={"Host": "192.168.1.30:4568"}).status_code == 200
    assert observed_mismatches() == []


# ---- H-10: the registry is fed by client-controlled Host headers ------------------------------------
from src.middleware import issuer_check  # noqa: E402


def _record(host, peer="192.168.1.7", **kw):
    scope = _scope(host, peer=peer)
    observed = external_base_url(scope, [])
    return issuer_check.record_mismatch(observed, "http://testserver", scope["path"], peer=peer, **kw)


def test_registry_is_bounded_and_keeps_the_most_recent_hosts(owner_client):
    # IP literals pass the trusted-host check (an address cannot be rebound), so they reach the registry
    for i in range(issuer_check.MAX_OBSERVED + 50):
        assert owner_client.get("/.well-known/jwks.json", headers={"Host": f"10.0.0.{i + 1}"}).status_code == 200
    seen = observed_mismatches()
    assert len(seen) == issuer_check.MAX_OBSERVED
    assert seen[-1]["base_url"] == f"http://10.0.0.{issuer_check.MAX_OBSERVED + 50}"
    overview = owner_client.get("/api/oauth/overview")
    assert len(overview.content) < 50_000


def test_foreign_host_name_is_refused_before_it_can_be_recorded(owner_client):
    """The trusted-host check runs first: a host name MCP Gate does not answer to gets 421 and never reaches the
    registry; an IP-literal mismatch still does (within the bounds above)."""
    r = owner_client.get("/.well-known/jwks.json", headers={"Host": "mcp-gate.attacker.example"})
    assert r.status_code == 421
    assert observed_mismatches() == []
    assert owner_client.get("/.well-known/jwks.json", headers={"Host": "192.168.1.20:4568"}).status_code == 200
    assert [m["base_url"] for m in observed_mismatches()] == ["http://192.168.1.20:4568"]


@pytest.mark.parametrize("host", [
    "x" + "a" * 4000 + ".example",           # far beyond a DNS name
    "evil.example\r\nX-Injected: 1",         # control characters
    "a b.example",                           # space
    "<script>.example",
    "host:99999",                            # port out of range
    "host:abc",
    "-leading.example",
    "",
])
def test_implausible_host_syntax_is_not_recorded(host):
    assert _record(host) is False
    assert observed_mismatches() == []


@pytest.mark.parametrize("host", ["192.168.1.20:4568", "mcp.lan", "[::1]:4568", "auth.example.com", "localhost:8080"])
def test_valid_hosts_are_recorded(host):
    assert _record(host) is True
    assert len(observed_mismatches()) == 1


def test_stale_entries_expire(monkeypatch):
    _record("old.example")
    monkeypatch.setattr(issuer_check, "_now", lambda: issuer_check._now_real() + issuer_check.TTL_SECONDS + 1)
    assert observed_mismatches() == []


def test_advice_only_for_hosts_from_local_or_proxied_peers(caplog):
    from loguru import logger

    messages = []
    sink = logger.add(lambda m: messages.append(str(m)), level="WARNING")
    try:
        mw = issuer_check.IssuerMismatchMiddleware(_noop_app, issuer="http://testserver", trusted_proxies=["10.9.9.9"])
        import asyncio
        # LAN peer: a real misconfiguration is likely, so the fix is suggested
        asyncio.run(mw(_scope("192.168.1.20:4568", peer="192.168.1.7"), None, None))
        # internet peer: the Host header is the attacker's choice, no "set OAUTH_ISSUER to ..." advice
        asyncio.run(mw(_scope("mcp-gate.attacker.example", peer="203.0.113.5"), None, None))
    finally:
        logger.remove(sink)
    lan = [m for m in messages if "192.168.1.20" in m]
    attacker = [m for m in messages if "attacker.example" in m]
    assert lan and "set OAUTH_ISSUER to http://192.168.1.20:4568" in lan[0]
    assert attacker and "set OAUTH_ISSUER to" not in attacker[0]
    entries = {m["base_url"]: m for m in observed_mismatches()}
    assert entries["http://192.168.1.20:4568"]["plausible"] is True
    assert entries["http://mcp-gate.attacker.example"]["plausible"] is False


def test_untrusted_entries_are_evicted_first():
    _record("lan-host.lan", peer="192.168.1.7")
    for i in range(issuer_check.MAX_OBSERVED + 5):
        _record(f"x{i}.attacker.example", peer="203.0.113.5")
    hosts = [m["base_url"] for m in observed_mismatches()]
    assert "http://lan-host.lan" in hosts and len(hosts) == issuer_check.MAX_OBSERVED


def test_warnings_from_internet_peers_are_rate_limited():
    from loguru import logger

    messages = []
    sink = logger.add(lambda m: messages.append(str(m)), level="WARNING")
    try:
        mw = issuer_check.IssuerMismatchMiddleware(_noop_app, issuer="http://testserver")
        import asyncio
        for i in range(200):
            asyncio.run(mw(_scope(f"x{i}.attacker.example", peer="203.0.113.5"), None, None))
    finally:
        logger.remove(sink)
    assert len(messages) <= issuer_check.MAX_UNTRUSTED_WARNINGS_PER_WINDOW + 1


async def _noop_app(scope, receive, send):
    return None
