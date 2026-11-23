"""Client registration under MCP 2026-07-28 (#35): `application_type` (SEP-837) is accepted from DCR clients and
metadata documents and checked against OpenID's two values, without redirect-URI constraints (MCP Gate is not an
OpenID provider); Dynamic Client Registration keeps working but is announced as deprecated once per process."""

from __future__ import annotations

import pytest

from src.oauth import service as oauth
from tests.test_cimd import _authorize, document, web  # noqa: F401  (web is a fixture)
from tests.test_oauth_flow import REDIRECT_URI

NATIVE_REDIRECTS = ["http://127.0.0.1:33418/callback", "cursor://anysphere.cursor-mcp/oauth/callback"]


def _register(client, **extra):
    body = {"client_name": "Example", "redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"}
    body.update(extra)
    return client.post("/oauth/register", json=body)


@pytest.mark.parametrize("value", ["native", "web", None])
def test_apptype_001_dcr_accepts_native_web_and_absent(client, value):
    extra = {} if value is None else {"application_type": value}
    r = _register(client, **extra)
    assert r.status_code == 201, r.text
    assert "client_id" in r.json()


@pytest.mark.parametrize("value", ["browser", "NATIVE", "", 1, ["native"], {"type": "web"}])
def test_apptype_002_dcr_refuses_other_values(client, value):
    r = _register(client, application_type=value)
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "invalid_client_metadata"
    assert "application_type" in r.json()["error_description"]


@pytest.mark.parametrize("value, redirects", [
    ("web", NATIVE_REDIRECTS),       # an OpenID provider would refuse loopback / custom schemes for "web"
    ("native", ["https://app.example/callback"]),
])
def test_apptype_003_no_openid_redirect_constraints(client, value, redirects):
    r = _register(client, application_type=value, redirect_uris=redirects)
    assert r.status_code == 201, r.text
    assert r.json()["redirect_uris"] == redirects


@pytest.mark.parametrize("value, ok", [("native", True), ("web", True), ("app", False), (7, False)])
def test_apptype_004_metadata_documents(owner_client, service, web, value, ok):  # noqa: F811
    web.serve(body=document(application_type=value))
    r = _authorize(owner_client)
    if ok:
        assert r.status_code == 302, r.text
    else:
        assert r.status_code == 400 and r.json()["error"] == "invalid_client", r.text
        assert "application_type" in r.json()["error_description"]


@pytest.fixture
def fresh_notice(monkeypatch):
    monkeypatch.setattr(oauth, "_dcr_notice_logged", False)
    logged = []
    monkeypatch.setattr(oauth.logger, "warning", lambda msg, *a, **k: logged.append(msg))
    return logged


def test_dcrnote_001_first_dcr_registration_logs_the_deprecation_once(client, fresh_notice):
    assert _register(client).status_code == 201
    assert _register(client).status_code == 201
    assert fresh_notice == [oauth.DCR_DEPRECATION_NOTICE]
    assert "deprecated" in fresh_notice[0] and "Client ID Metadata Documents" in fresh_notice[0]


def test_dcrnote_002_failed_or_console_registrations_do_not_log_it(client, owner_client, fresh_notice):
    assert _register(client, application_type="bogus").status_code == 400
    r = owner_client.post("/api/oauth/clients", json={"client_name": "x", "redirect_uris": [REDIRECT_URI]})
    assert r.status_code == 201, r.text
    assert fresh_notice == []


def test_dcrnote_003_dcr_stays_advertised(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["registration_endpoint"].endswith("/oauth/register")
    assert meta["client_id_metadata_document_supported"] is True
    assert meta["authorization_response_iss_parameter_supported"] is True
