"""One audience, one service (#21).

The audience is what a token is for: the consent screen and token issuance resolve it to a single service, and a
resource server accepts any token carrying it. QA registered a second service with an audience the first already had
(201); the consent screen then named the first, and a personal access token "for" the second carried the first one's
audience. The same happened without any explicit audience: two services at one host:port and MCP path both default to
the same MCP URL.
"""

import pytest


def _create(client, name, **fields):
    body = {"name": name, "host": "127.0.0.1", "port": 9100, "mcp_path": "/mcp", **fields}
    return client.post("/api/services", json=body)


def _refused(response, holder_name):
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "service.audience_taken"
    assert detail["params"]["name"] == holder_name
    return detail


@pytest.mark.parametrize("second", [
    "https://mcp.example.com/mcp",
    "https://mcp.example.com/mcp/",          # trailing slash
    "HTTPS://MCP.Example.com/mcp",          # scheme / host case
    " https://mcp.example.com/mcp#frag ",   # whitespace, fragment
])
def test_an_explicit_audience_already_in_use_is_refused(owner_client, second):
    assert _create(owner_client, "first", oauth_audience="https://mcp.example.com/mcp").status_code == 201
    detail = _refused(_create(owner_client, "second", port=9101, oauth_audience=second), "first")
    assert detail["params"]["audience"] == "https://mcp.example.com/mcp"
    assert len(owner_client.get("/api/services").json()["services"]) == 1


def test_two_services_at_one_mcp_url_are_refused(owner_client):
    assert _create(owner_client, "first").status_code == 201
    _refused(_create(owner_client, "second", host="localhost"), "first")  # localhost is stored as 127.0.0.1


def test_an_explicit_audience_equal_to_another_services_mcp_url_is_refused(owner_client):
    assert _create(owner_client, "first").status_code == 201
    _refused(_create(owner_client, "second", port=9101, oauth_audience="http://127.0.0.1:9100/mcp"), "first")


def test_an_mcp_url_equal_to_another_services_explicit_audience_is_refused(owner_client):
    assert _create(owner_client, "first", port=9101, oauth_audience="http://127.0.0.1:9100/mcp").status_code == 201
    _refused(_create(owner_client, "second"), "first")


def test_an_mcp_path_with_a_trailing_slash_is_the_same_audience(owner_client):
    """Lookups normalise the MCP URL (no trailing slash), so the check must too, in both directions."""
    assert _create(owner_client, "first", mcp_path="/mcp/").status_code == 201
    _refused(_create(owner_client, "second", port=9101, oauth_audience="http://127.0.0.1:9100/mcp"), "first")


def test_a_new_mcp_url_is_normalised_before_comparing(owner_client):
    assert _create(owner_client, "first", port=9101, oauth_audience="http://127.0.0.1:9100/mcp").status_code == 201
    _refused(_create(owner_client, "second", mcp_path="/mcp/"), "first")


def test_one_host_port_with_distinct_audiences_is_fine(owner_client):
    """Two servers behind one address are fine as long as each has its own audience."""
    assert _create(owner_client, "first", oauth_audience="https://a.example.com/mcp").status_code == 201
    assert _create(owner_client, "second", oauth_audience="https://b.example.com/mcp").status_code == 201


def test_an_inactive_service_keeps_its_audience(owner_client):
    first = _create(owner_client, "first", oauth_audience="https://a.example.com/mcp").json()
    assert owner_client.put(f"/api/services/{first['id']}", json={"is_active": False}).status_code == 200
    _refused(_create(owner_client, "second", oauth_audience="https://a.example.com/mcp"), "first")


class TestUpdate:

    def test_taking_another_services_audience_is_refused(self, owner_client):
        assert _create(owner_client, "first", oauth_audience="https://a.example.com/mcp").status_code == 201
        second = _create(owner_client, "second", port=9101).json()
        _refused(owner_client.put(f"/api/services/{second['id']}",
                                  json={"oauth_audience": "https://a.example.com/mcp/"}), "first")
        assert owner_client.get(f"/api/services/{second['id']}").json()["oauth_audience"] is None

    def test_moving_onto_another_services_mcp_url_is_refused(self, owner_client):
        assert _create(owner_client, "first").status_code == 201
        second = _create(owner_client, "second", port=9101).json()
        _refused(owner_client.put(f"/api/services/{second['id']}", json={"port": 9100}), "first")

    def test_clearing_an_audience_onto_a_taken_mcp_url_is_refused(self, owner_client):
        assert _create(owner_client, "first").status_code == 201
        second = _create(owner_client, "second", oauth_audience="https://b.example.com/mcp").json()
        _refused(owner_client.put(f"/api/services/{second['id']}", json={"oauth_audience": ""}), "first")

    def test_a_service_can_keep_and_restate_its_own_audience(self, owner_client):
        svc = _create(owner_client, "first", oauth_audience="https://a.example.com/mcp").json()
        r = owner_client.put(f"/api/services/{svc['id']}",
                             json={"oauth_audience": "https://a.example.com/mcp/", "description": "x"})
        assert r.status_code == 200, r.text

    def test_a_duplicate_from_before_does_not_block_unrelated_edits(self, owner_client, db_session):
        """Existing duplicates are reported, not rewritten, and the services stay editable."""
        from db.crud import ServiceCRUD

        ServiceCRUD.create(db_session, name="old-a", host="127.0.0.1", port=9100, oauth_audience="https://x.example/mcp")
        old_b = ServiceCRUD.create(db_session, name="old-b", host="127.0.0.1", port=9101,
                                   oauth_audience="https://x.example/mcp")
        r = owner_client.put(f"/api/services/{old_b.id}", json={"name": "old-b-renamed", "tags": ["t"]})
        assert r.status_code == 200, r.text


class TestOtherWaysIn:
    """Scans and the Marketplace create services through the same adapter."""

    def test_a_scanned_server_cannot_take_a_registered_audience(self, owner_client, db_session):
        from src.adapters import ServiceAdapter
        from src.adapters.exceptions import ConflictError

        assert _create(owner_client, "first", port=9101, oauth_audience="http://127.0.0.1:9100/mcp").status_code == 201
        with pytest.raises(ConflictError) as e:
            ServiceAdapter.register_discovered(db_session, name="scanned", host="127.0.0.1", port=9100,
                                               mcp_path="/mcp", source="auto_discovered", tools=[])
        assert e.value.code == "service.audience_taken"
        assert [s.name for s in ServiceAdapter.get_all(db_session, include_inactive=True)] == ["first"]

    def test_a_managed_service_cannot_take_a_registered_audience(self, owner_client, db_session):
        from src.adapters import ServiceAdapter
        from src.adapters.exceptions import ConflictError

        assert _create(owner_client, "first").status_code == 201
        with pytest.raises(ConflictError):
            ServiceAdapter.create(db=db_session, name="managed", host="127.0.0.1", port=9100, protocol="http",
                                  mcp_path="/mcp", source="managed", requires_auth=False)


class TestExistingDuplicates:

    @pytest.fixture
    def duplicates(self, owner_client, db_session):
        from db.crud import ServiceCRUD

        ServiceCRUD.create(db_session, name="dup-a", host="127.0.0.1", port=9100, oauth_audience="https://x.example/mcp")
        ServiceCRUD.create(db_session, name="dup-b", host="127.0.0.1", port=9101, oauth_audience="https://x.example/mcp/")
        ServiceCRUD.create(db_session, name="alone", host="127.0.0.1", port=9102)

    def test_they_are_listed(self, duplicates, db_session):
        from src.adapters import ServiceAdapter

        conflicts = ServiceAdapter.audience_conflicts(db_session)
        assert [(c["audience"], sorted(s["name"] for s in c["services"])) for c in conflicts] == [
            ("https://x.example/mcp", ["dup-a", "dup-b"])]

    def test_the_dashboard_overview_reports_them(self, duplicates, owner_client):
        conflicts = owner_client.get("/api/oauth/overview").json()["audience_conflicts"]
        assert len(conflicts) == 1 and {s["name"] for s in conflicts[0]["services"]} == {"dup-a", "dup-b"}

    def test_startup_logs_them(self, duplicates, db_session):
        from loguru import logger

        import main

        messages = []
        handler_id = logger.add(lambda m: messages.append(str(m)), level="WARNING")
        try:
            main.warn_shared_audiences(db_session)
        finally:
            logger.remove(handler_id)
        assert any("dup-a" in m and "dup-b" in m and "https://x.example/mcp" in m for m in messages)

    def test_nothing_is_reported_without_duplicates(self, owner_client):
        assert _create(owner_client, "first").status_code == 201
        assert owner_client.get("/api/oauth/overview").json()["audience_conflicts"] == []
