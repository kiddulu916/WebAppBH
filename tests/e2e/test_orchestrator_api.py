"""E2E tests for the orchestrator control-plane API.

Covers:
    POST  /api/v1/kill
    POST  /api/v1/control
    POST  /api/v1/targets/{id}/rescan
    POST  /api/v1/targets/{id}/clean-slate
    DELETE /api/v1/targets/{id}
    GET   /health
    POST  /api/v1/targets  (validation)
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    _BASE_URL,  # noqa: F401 — imported for module documentation
    _read_api_key,  # noqa: F401
    create_target,
    cleanup_target,
    wait_for_worker_status,
    seed_asset,
)

pytestmark = pytest.mark.e2e


class TestControlPlane:
    """Orchestrator API control-plane contract tests."""

    @pytest.fixture(autouse=True)
    async def _teardown(self, client):
        """After each test: kill all active jobs then delete all targets."""
        yield
        await client.post("/api/v1/kill")
        res = await client.get("/api/v1/targets")
        for t in res.json().get("targets", []):
            await client.delete(f"/api/v1/targets/{t['id']}")

    async def test_kill_all_marks_jobs_killed(self, client):
        """POST /api/v1/kill transitions active jobs to a terminal state."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Kill-Test")
        await wait_for_worker_status(
            client, target_id, "info_gathering", {"QUEUED", "RUNNING"}, timeout=60
        )
        res = await client.post("/api/v1/kill")
        assert res.status_code == 200
        body = res.json()
        assert body["success"] is True
        assert isinstance(body["killed_count"], int)
        assert body["killed_count"] >= 0
        assert isinstance(body["containers"], list)

    async def test_control_invalid_container_rejected(self, client):
        """POST /api/v1/control with a container_name not starting with 'webbh-' returns 400."""
        res = await client.post("/api/v1/control", json={
            "container_name": "not-webbh-anything",
            "action": "pause",
        })
        assert res.status_code == 400

    async def test_control_unknown_action_rejected(self, client):
        """POST /api/v1/control with an unknown action returns 400."""
        res = await client.post("/api/v1/control", json={
            "container_name": "webbh-info_gathering",
            "action": "explode",
        })
        assert res.status_code == 400

    async def test_rescan_queues_snapshot(self, client):
        """POST /api/v1/targets/{id}/rescan returns 201 with scan_number."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Rescan-Test")
        await wait_for_worker_status(
            client, target_id, "info_gathering", {"COMPLETED"}, timeout=600
        )
        await client.post("/api/v1/kill")
        res = await client.post(f"/api/v1/targets/{target_id}/rescan")
        assert res.status_code == 201
        body = res.json()
        assert body["target_id"] == target_id
        assert body["status"] == "queued"
        assert isinstance(body["scan_number"], int)
        assert body["scan_number"] >= 1

    async def test_clean_slate_wipes_data(self, client):
        """POST /api/v1/targets/{id}/clean-slate removes assets and jobs."""
        target_id = await create_target(client, "e2e_info_gathering", "API-CleanSlate")
        await seed_asset(target_id)
        await client.post("/api/v1/kill")
        res = await client.post(f"/api/v1/targets/{target_id}/clean-slate")
        assert res.status_code == 200
        body = res.json()
        assert body["success"] is True
        assert body["target_id"] == target_id
        assets_res = await client.get("/api/v1/assets", params={"target_id": target_id})
        assert assets_res.status_code == 200
        assert assets_res.json()["total"] == 0

    async def test_delete_target_removes_it(self, client):
        """DELETE /api/v1/targets/{id} removes the target from the targets list."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Delete-Test")
        await client.post("/api/v1/kill")
        res = await client.delete(f"/api/v1/targets/{target_id}")
        assert res.status_code == 200
        body = res.json()
        assert body["success"] is True
        assert body["target_id"] == target_id
        targets_res = await client.get("/api/v1/targets")
        assert targets_res.status_code == 200
        target_ids = [t["id"] for t in targets_res.json().get("targets", [])]
        assert target_id not in target_ids

    async def test_health_endpoint(self, client):
        """GET /health returns 200 with status ok."""
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json().get("status") == "ok"

    async def test_target_create_empty_company_name_rejected(self, client):
        """POST /api/v1/targets with empty company_name returns 422."""
        res = await client.post("/api/v1/targets", json={
            "company_name": "",
            "base_domain": "testphp.vulnweb.com",
        })
        assert res.status_code == 422

    async def test_target_create_short_domain_rejected(self, client):
        """POST /api/v1/targets with base_domain shorter than 3 chars returns 422."""
        res = await client.post("/api/v1/targets", json={
            "company_name": "Test Corp",
            "base_domain": "x",
        })
        assert res.status_code == 422
