"""Known #22: deleting a managed server's Service left its container / process running, unregistered and
without OAuth in front of it (ManagedMcpProcess.service_id is ON DELETE SET NULL). The Services page must
refuse and point to Marketplace -> Uninstall, which stops the instance first."""

from db.database import make_session
from src.adapters import ManagedMcpProcessAdapter


def _link_process(service_id):
    db = make_session()
    try:
        p = ManagedMcpProcessAdapter.create(db, name="fs", catalog_id="user:x", docker_image="mcp-runtime:1")
        ManagedMcpProcessAdapter.update_state(db, str(p.id), service_id=service_id)
        return str(p.id)
    finally:
        db.close()


def test_service_of_a_managed_instance_cannot_be_deleted(owner_client, service):
    process_id = _link_process(service["id"])
    r = owner_client.delete(f"/api/services/{service['id']}")
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "service.managed_use_uninstall"
    assert detail["params"]["process_id"] == process_id
    assert owner_client.get(f"/api/services/{service['id']}").status_code == 200


def test_orphaned_managed_service_can_still_be_deleted(owner_client, service):
    assert owner_client.delete(f"/api/services/{service['id']}").status_code == 200
