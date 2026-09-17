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


def test_mismatching_host_is_recorded_once_and_visible_in_overview(owner_client):
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
    assert owner_client.get("/api/session/status", headers={"Host": "elsewhere.example"}).status_code == 200
    assert observed_mismatches() == []
