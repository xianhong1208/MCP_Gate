"""The console can tell whether a revocation reaches a server before the token expires: resource servers record
when they last polled the revocation feed, and the status is served per service and per audience."""

from datetime import timedelta

from tests.test_oauth_flow import RESOURCE, _register_console


def _status(owner_client, service_id):
    r = owner_client.get(f"/api/oauth/services/{service_id}/revocation-feed")
    assert r.status_code == 200, r.text
    return r.json()


def test_feed_status_follows_polls(owner_client, service, db_session):
    from src.adapters import OAuthClientAdapter

    assert _status(owner_client, service["id"])["state"] == "not_wired"

    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    st = _status(owner_client, service["id"])
    assert st["state"] == "never_polled" and st["last_poll"] is None
    assert [c["client_id"] for c in st["resource_servers"]] == [rs["client_id"]]

    r = owner_client.post("/oauth/revoked", auth=(rs["client_id"], rs["client_secret"]))
    assert r.status_code == 200, r.text
    st = _status(owner_client, service["id"])
    assert st["state"] == "active" and st["last_poll"]
    assert st["resource_servers"][0]["last_poll"] == st["last_poll"]

    # by audience (what the revoke dialog asks with)
    r = owner_client.get("/api/oauth/revocation-feed", params={"audience": RESOURCE})
    assert r.status_code == 200 and r.json()["state"] == "active"
    assert owner_client.get("/api/oauth/revocation-feed",
                            params={"audience": "http://other.example/mcp"}).json()["state"] == "not_wired"

    # a server that stopped polling is stale
    client = OAuthClientAdapter.get(db_session, rs["client_id"])
    client.revocation_polled_at -= timedelta(minutes=11)
    db_session.commit()
    assert _status(owner_client, service["id"])["state"] == "stale"


def test_polls_are_written_at_most_every_30_seconds(owner_client, service, db_session):
    from src.adapters import OAuthClientAdapter

    rs = _register_console(owner_client, client_name="RS", resource_service_id=service["id"])
    owner_client.post("/oauth/revoked", auth=(rs["client_id"], rs["client_secret"]))
    first = OAuthClientAdapter.get(db_session, rs["client_id"]).revocation_polled_at
    owner_client.post("/oauth/revoked", auth=(rs["client_id"], rs["client_secret"]))
    db_session.expire_all()
    assert OAuthClientAdapter.get(db_session, rs["client_id"]).revocation_polled_at == first


def test_unbound_or_refused_callers_do_not_count(owner_client, service):
    """Only a bound resource server's successful poll counts; a refused caller leaves the status alone."""
    other = _register_console(owner_client, client_name="not bound")
    r = owner_client.post("/oauth/revoked", auth=(other["client_id"], other["client_secret"]))
    assert r.status_code == 403
    assert _status(owner_client, service["id"])["state"] == "not_wired"


def test_status_requires_a_session(client, service):
    client.post("/api/session/logout")
    assert client.get(f"/api/oauth/services/{service['id']}/revocation-feed").status_code == 401
    assert client.get("/api/oauth/revocation-feed", params={"audience": RESOURCE}).status_code == 401
