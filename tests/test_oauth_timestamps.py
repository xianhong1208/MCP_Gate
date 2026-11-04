"""H-13 (remainder): OAuth timestamps on the wire carry their UTC offset, so they mean the same instant wherever
they are read. (The revocation feed and usage reports are covered in test_offline_hooks.)"""

import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse

from tests.conftest import make_pkce
from tests.test_offline_hooks import utc_plus_8  # noqa: F401  (fixture)
from tests.test_oauth_flow import REDIRECT_URI, RESOURCE, _authorize_and_consent, _exchange, _register


def _aware(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    assert dt.tzinfo is not None, value
    return dt


def test_activity_times_carry_an_offset(owner_client, service, utc_plus_8):  # noqa: F811
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange(owner_client, reg["client_id"], code, verifier).status_code == 200
    events = owner_client.get("/api/oauth/activity").json()["events"]
    assert events and abs(_aware(events[0]["at"]).timestamp() - time.time()) < 10


def test_consent_request_expiry_carries_an_offset(owner_client, service, utc_plus_8):  # noqa: F811
    reg = _register(owner_client)
    _verifier, challenge = make_pkce()
    r = owner_client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE}, follow_redirects=False)
    rid = parse_qs(urlparse(r.headers["location"]).query)["rid"][0]
    info = owner_client.get(f"/oauth/authorize/requests/{rid}").json()
    assert abs(_aware(info["expires_at"]).timestamp() - (time.time() + 600)) < 10
