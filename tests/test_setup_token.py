"""First-run setup needs the one-time setup token (#12).

Until an owner exists, POST /api/session/setup creates one. It used to need no
credential, and MCP Gate listens on every interface by default, so on a fresh
install whoever reached the server first became the owner. The token is printed
in the startup log and kept in data/secrets.json; setup requires it and discards
it once the owner exists.
"""

import json

import pytest

from tests.conftest import OWNER_EMAIL, OWNER_PASSWORD, SETUP_TOKEN


def _setup(client, **extra):
    return client.post("/api/session/setup", json={"email": OWNER_EMAIL, "password": OWNER_PASSWORD, **extra})


@pytest.mark.parametrize("extra", [{}, {"setup_token": ""}, {"setup_token": "   "}, {"setup_token": "wrong-token"},
                                   {"setup_token": SETUP_TOKEN[:-1]}])
def test_setup_without_the_token_creates_nothing(client, extra):
    r = _setup(client, **extra)

    assert r.status_code == 403 and r.json()["error"] == "auth.setup_token_invalid"
    assert "/" not in r.json()["message"].split("(")[0]  # no server path for an anonymous caller
    assert "mcp-gate-test-secrets" not in r.json()["message"]
    assert "mcp_session" not in r.cookies
    assert client.get("/api/session/status").json()["needs_setup"] is True


def test_setup_with_the_token_creates_the_owner(client):
    # Pasted from a terminal, with the spaces around it
    r = _setup(client, setup_token=f"  {SETUP_TOKEN}\n")

    assert r.status_code == 200 and r.json()["user"]["email"] == OWNER_EMAIL
    assert client.get("/api/session/status").json()["needs_setup"] is False


def test_after_setup_it_is_409_whatever_the_token(client):
    assert _setup(client, setup_token=SETUP_TOKEN).status_code == 200

    for extra in ({}, {"setup_token": SETUP_TOKEN}):
        r = client.post("/api/session/setup", json={"email": "x@example.com", "password": "another-pass-123", **extra})
        assert r.status_code == 409 and r.json()["error"] == "auth.setup_already_done"


@pytest.fixture
def generated_token(monkeypatch, tmp_path):
    """No MCP_GATE_SETUP_TOKEN: the token is generated into a fresh secrets file."""
    from src.utils import secrets_store

    secrets_file = tmp_path / "secrets.json"
    monkeypatch.delenv("MCP_GATE_SETUP_TOKEN", raising=False)
    monkeypatch.setenv("MCP_GATE_SECRETS_FILE", str(secrets_file))
    secrets_store.reset_cache()
    yield secrets_file
    secrets_store.reset_cache()


def test_the_token_is_generated_kept_and_discarded_after_setup(client, generated_token):
    from src.identity import setup_token

    token = setup_token.current()
    assert len(token) >= 32
    assert json.loads(generated_token.read_text())["SETUP_TOKEN"] == token
    assert setup_token.current() == token  # the same token across calls (and restarts: it is in the file)
    assert (generated_token.stat().st_mode & 0o777) == 0o600

    assert _setup(client, setup_token=token).status_code == 200

    assert "SETUP_TOKEN" not in json.loads(generated_token.read_text())


def test_the_startup_banner_prints_the_token_while_no_owner_exists(generated_token):
    from loguru import logger

    import main
    from src.identity import setup_token

    messages = []
    sink = logger.add(lambda m: messages.append(str(m)), level="WARNING")
    try:
        main._print_banner({"users": 0, "signing_kid": "kid"}, "0.0.0.0", 4568)
        with_owner = len(messages)
        main._print_banner({"users": 1, "signing_kid": "kid"}, "0.0.0.0", 4568)
    finally:
        logger.remove(sink)

    printed = "".join(messages[:with_owner])
    assert setup_token.current() in printed and str(generated_token) in printed
    assert setup_token.current() not in "".join(messages[with_owner:])
