"""Known #8: BYO argv secrets must not be shown in the API or written to the audit log.

The stored definition keeps the real values (the launcher needs them); only what leaves the server is masked.
"""

import json

import pytest

from src.marketplace.secret_mask import MASK, mask_argv

SECRET = "sk-live-0123456789abcdef"


@pytest.mark.parametrize("argv, expected", [
    (["--api-key=" + SECRET], ["--api-key=" + MASK]),
    (["--token", SECRET, "--port", "8000"], ["--token", MASK, "--port", "8000"]),
    (["-y", "server", "--client-secret", SECRET], ["-y", "server", "--client-secret", MASK]),
    (["--password=" + SECRET], ["--password=" + MASK]),
    (["--auth", SECRET], ["--auth", MASK]),
    (["API_KEY=" + SECRET, "DEBUG=1"], ["API_KEY=" + MASK, "DEBUG=1"]),
    (["GITHUB_PERSONAL_ACCESS_TOKEN=" + SECRET], ["GITHUB_PERSONAL_ACCESS_TOKEN=" + MASK]),
    (["--db", "postgres://app:" + SECRET + "@db:5432/x"], ["--db", "postgres://app:" + MASK + "@db:5432/x"]),
    # a following flag is not a value
    (["--token", "--verbose"], ["--token", "--verbose"]),
    # nothing sensitive: untouched
    (["-y", "@modelcontextprotocol/server-filesystem", "/data", "--port=8000"],
     ["-y", "@modelcontextprotocol/server-filesystem", "/data", "--port=8000"]),
    ([], []),
])
def test_mask_argv(argv, expected):
    assert mask_argv(argv) == expected


def test_byo_secrets_are_masked_in_api_and_audit_but_kept_for_launch(owner_client):
    args = ["-y", "some-mcp", "--api-key=" + SECRET, "--token", SECRET, "API_SECRET=" + SECRET]
    r = owner_client.post("/api/byo-mcp", json={"name": "leaky", "command": "npx", "args": args, "env_schema": []})
    assert r.status_code == 200, r.text
    assert SECRET not in r.text
    assert r.json()["args"] == ["-y", "some-mcp", "--api-key=" + MASK, "--token", MASK, "API_SECRET=" + MASK]

    listed = owner_client.get("/api/byo-mcp")
    assert listed.status_code == 200 and SECRET not in listed.text

    logs = owner_client.get("/api/audit/logs", params={"limit": 100})
    assert logs.status_code == 200
    assert SECRET not in logs.text
    assert any((e.get("details") or {}).get("action") == "create_byo_definition"
               for e in logs.json()["logs"]), logs.text[:500]

    # the stored definition still carries the real argv for the launcher
    from db.database import make_session
    from src.adapters import BYODefinitionAdapter

    db = make_session()
    try:
        stored = BYODefinitionAdapter.get_existing(db, r.json()["id"])
        assert stored.get_args() == args
        assert json.loads(stored.args_json) == args
    finally:
        db.close()
