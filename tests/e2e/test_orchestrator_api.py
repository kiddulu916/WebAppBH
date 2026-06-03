"""E2E tests for the orchestrator control-plane API.

Covers:
    POST  /api/v1/kill
    POST  /api/v1/control
    POST  /api/v1/targets/{id}/rescan
    POST  /api/v1/targets/{id}/clean-slate
    DELETE /api/v1/targets/{id}
    GET   /health
    POST  /api/v1/targets  (validation)
    POST  /api/v1/bounties
    GET   /api/v1/bounties
    PATCH /api/v1/bounties/{id}
    GET   /api/v1/bounties/stats
    POST  /api/v1/campaigns
    GET   /api/v1/campaigns/{id}
    PATCH /api/v1/campaigns/{id}
    GET   /api/v1/campaigns
    GET   /api/v1/search
    GET   /api/v1/targets/{id}/graph
    GET   /api/v1/vulnerabilities/{id}/draft
    GET   /api/v1/playbooks
    POST  /api/v1/schedules
    GET   /api/v1/schedules
    PATCH /api/v1/schedules/{id}
    GET   /api/v1/queue_health
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
    seed_vulnerability,
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


class TestDataAPIs:
    """Tests for bounties, campaigns, search, attack graph, playbooks, schedules."""

    @pytest.fixture(autouse=True)
    async def _teardown(self, client):
        yield
        await client.post("/api/v1/kill")
        res = await client.get("/api/v1/targets")
        for t in res.json().get("targets", []):
            await client.delete(f"/api/v1/targets/{t['id']}")

    async def test_bounty_crud_lifecycle(self, client):
        """POST → GET → PATCH lifecycle for bounty submissions."""
        target_id = await create_target(client, "e2e_info_gathering", "Bounty-CRUD-Test")
        vuln = await seed_vulnerability(target_id)
        vuln_id = vuln["id"]

        # POST /api/v1/bounties
        create_res = await client.post("/api/v1/bounties", json={
            "target_id": target_id,
            "vulnerability_id": vuln_id,
            "platform": "hackerone",
            "status": "submitted",
            "expected_payout": 500.0,
            "notes": "e2e test bounty",
        })
        assert create_res.status_code == 201, f"POST /api/v1/bounties: {create_res.status_code} {create_res.text}"
        body = create_res.json()
        assert body["target_id"] == target_id
        assert body["vulnerability_id"] == vuln_id
        assert body["platform"] == "hackerone"
        assert body["status"] == "submitted"
        assert body["expected_payout"] == 500.0
        bounty_id = body["id"]

        # GET /api/v1/bounties
        list_res = await client.get("/api/v1/bounties", params={"target_id": target_id})
        assert list_res.status_code == 200, f"GET /api/v1/bounties: {list_res.status_code}"
        bounties = list_res.json()
        assert isinstance(bounties, list)
        assert any(b["id"] == bounty_id for b in bounties)

        # PATCH /api/v1/bounties/{bounty_id}
        patch_res = await client.patch(f"/api/v1/bounties/{bounty_id}", json={
            "status": "accepted",
            "actual_payout": 750.0,
        })
        assert patch_res.status_code == 200, f"PATCH /api/v1/bounties/{bounty_id}: {patch_res.status_code} {patch_res.text}"
        patched = patch_res.json()
        assert patched["status"] == "accepted"
        assert patched["actual_payout"] == 750.0
        assert patched["id"] == bounty_id

    async def test_bounty_stats_returns_roi(self, client):
        """GET /api/v1/bounties/stats returns a stats dict."""
        res = await client.get("/api/v1/bounties/stats")
        assert res.status_code == 200, f"GET /api/v1/bounties/stats: {res.status_code} {res.text}"
        body = res.json()
        assert "total_submitted" in body
        assert "total_accepted" in body
        assert "total_paid" in body
        assert "total_payout" in body
        assert "by_platform" in body
        assert "by_target" in body
        assert isinstance(body["total_submitted"], int)
        assert isinstance(body["total_payout"], (int, float))

    async def test_campaign_crud(self, client):
        """POST → GET → PATCH lifecycle for campaigns."""
        # POST /api/v1/campaigns
        create_res = await client.post("/api/v1/campaigns", json={
            "name": "E2E-Campaign-Test",
            "description": "Integration test campaign",
            "rate_limit": 30,
            "has_credentials": False,
        })
        assert create_res.status_code == 201, f"POST /api/v1/campaigns: {create_res.status_code} {create_res.text}"
        campaign = create_res.json()
        assert campaign["name"] == "E2E-Campaign-Test"
        assert campaign["rate_limit"] == 30
        assert campaign["status"] is not None
        campaign_id = campaign["id"]

        # GET /api/v1/campaigns/{campaign_id}
        get_res = await client.get(f"/api/v1/campaigns/{campaign_id}")
        assert get_res.status_code == 200, f"GET /api/v1/campaigns/{campaign_id}: {get_res.status_code}"
        fetched = get_res.json()
        assert fetched["id"] == campaign_id
        assert fetched["name"] == "E2E-Campaign-Test"
        assert "targets" in fetched

        # GET /api/v1/campaigns
        list_res = await client.get("/api/v1/campaigns")
        assert list_res.status_code == 200, f"GET /api/v1/campaigns: {list_res.status_code}"
        campaigns = list_res.json()
        assert isinstance(campaigns, list)
        assert any(c["id"] == campaign_id for c in campaigns)

        # PATCH /api/v1/campaigns/{campaign_id}
        patch_res = await client.patch(f"/api/v1/campaigns/{campaign_id}", json={
            "name": "E2E-Campaign-Updated",
            "status": "active",
        })
        assert patch_res.status_code == 200, f"PATCH /api/v1/campaigns/{campaign_id}: {patch_res.status_code} {patch_res.text}"
        updated = patch_res.json()
        assert updated["name"] == "E2E-Campaign-Updated"
        assert updated["status"] == "active"

    async def test_campaign_not_found_returns_404(self, client):
        """GET /api/v1/campaigns/999999 returns 404."""
        res = await client.get("/api/v1/campaigns/999999")
        assert res.status_code == 404, f"Expected 404, got {res.status_code}"

    async def test_search_finds_seeded_asset(self, client):
        """GET /api/v1/search finds an asset by its value."""
        target_id = await create_target(client, "e2e_info_gathering", "Search-Test")
        seeded = await seed_asset(target_id)
        # asset_value is http://testphp.vulnweb.com/seeded-{target_id}
        query = f"seeded-{target_id}"

        res = await client.get("/api/v1/search", params={"target_id": target_id, "q": query})
        assert res.status_code == 200, f"GET /api/v1/search: {res.status_code} {res.text}"
        body = res.json()
        assert "query" in body
        assert "results" in body
        assert body["query"] == query
        assert isinstance(body["results"], list)
        assert len(body["results"]) >= 1, f"Expected ≥1 search result for q={query!r}, got {body['results']}"
        result_values = [r["value"] for r in body["results"]]
        assert any(query in v for v in result_values), (
            f"Expected to find '{query}' in search results, got: {result_values}"
        )

    async def test_attack_graph_returns_nodes(self, client):
        """GET /api/v1/targets/{id}/graph returns nodes including a target node."""
        target_id = await create_target(client, "e2e_info_gathering", "Graph-Test")
        await seed_asset(target_id)

        res = await client.get(f"/api/v1/targets/{target_id}/graph")
        assert res.status_code == 200, f"GET /api/v1/targets/{target_id}/graph: {res.status_code} {res.text}"
        body = res.json()
        assert "nodes" in body, f"Response missing 'nodes' key: {body}"
        assert "edges" in body, f"Response missing 'edges' key: {body}"
        nodes = body["nodes"]
        assert len(nodes) >= 1, f"Expected ≥1 node in attack graph, got {len(nodes)}"
        # Verify the target node is present
        target_node_ids = [n["id"] for n in nodes if n.get("type") == "target"]
        assert len(target_node_ids) >= 1, (
            f"Expected a node with type='target', got node types: {[n.get('type') for n in nodes]}"
        )
        assert f"target-{target_id}" in target_node_ids

    async def test_vuln_draft_report_hackerone(self, client):
        """GET /api/v1/vulnerabilities/{id}/draft returns non-empty draft."""
        target_id = await create_target(client, "e2e_info_gathering", "Draft-Test")
        vuln = await seed_vulnerability(target_id)
        vuln_id = vuln["id"]

        res = await client.get(f"/api/v1/vulnerabilities/{vuln_id}/draft", params={"platform": "hackerone"})
        assert res.status_code == 200, f"GET /api/v1/vulnerabilities/{vuln_id}/draft: {res.status_code} {res.text}"
        body = res.json()
        assert "vuln_id" in body
        assert "platform" in body
        assert "draft" in body
        assert body["vuln_id"] == vuln_id
        assert body["platform"] == "hackerone"
        assert isinstance(body["draft"], str)
        assert len(body["draft"]) > 0, "Draft report should not be empty"

    async def test_playbook_list_includes_wide_recon(self, client):
        """GET /api/v1/playbooks returns list including 'wide_recon'."""
        res = await client.get("/api/v1/playbooks")
        assert res.status_code == 200, f"GET /api/v1/playbooks: {res.status_code} {res.text}"
        body = res.json()
        assert isinstance(body, list), f"Expected list, got {type(body)}"
        assert len(body) >= 1, "Expected at least one playbook"
        names = [pb.get("name") for pb in body]
        assert "wide_recon" in names, f"Expected 'wide_recon' in playbooks, got: {names}"
        # Verify wide_recon has required fields
        wide_recon = next(pb for pb in body if pb.get("name") == "wide_recon")
        assert wide_recon.get("builtin") is True

    async def test_unknown_playbook_rejected_on_target_create(self, client):
        """POST /api/v1/targets with unknown playbook is rejected."""
        res = await client.post("/api/v1/targets", json={
            "company_name": "Playbook-Reject-Test",
            "base_domain": "testphp.vulnweb.com",
            "playbook": "nonexistent_playbook_xyz_12345",
        })
        # Orchestrator raises HTTPException(404) for unknown playbooks
        assert res.status_code in (400, 404, 422), (
            f"Expected 400/404/422 for unknown playbook, got {res.status_code}: {res.text}"
        )

    async def test_scheduled_scan_crud(self, client):
        """POST → GET → PATCH lifecycle for scheduled scans."""
        target_id = await create_target(client, "e2e_info_gathering", "Schedule-CRUD-Test")

        # POST /api/v1/schedules
        create_res = await client.post("/api/v1/schedules", json={
            "target_id": target_id,
            "cron_expression": "0 2 * * *",
            "playbook": "wide_recon",
        })
        assert create_res.status_code == 201, f"POST /api/v1/schedules: {create_res.status_code} {create_res.text}"
        schedule = create_res.json()
        assert schedule["target_id"] == target_id
        assert schedule["cron_expression"] == "0 2 * * *"
        assert schedule["playbook"] == "wide_recon"
        assert schedule["enabled"] is True
        assert "next_run_at" in schedule
        schedule_id = schedule["id"]

        # GET /api/v1/schedules
        list_res = await client.get("/api/v1/schedules", params={"target_id": target_id})
        assert list_res.status_code == 200, f"GET /api/v1/schedules: {list_res.status_code}"
        schedules = list_res.json()
        assert isinstance(schedules, list)
        assert any(s["id"] == schedule_id for s in schedules)

        # PATCH /api/v1/schedules/{schedule_id}
        patch_res = await client.patch(f"/api/v1/schedules/{schedule_id}", json={
            "enabled": False,
            "cron_expression": "0 3 * * 0",
        })
        assert patch_res.status_code == 200, f"PATCH /api/v1/schedules/{schedule_id}: {patch_res.status_code} {patch_res.text}"
        patched = patch_res.json()
        assert patched["enabled"] is False
        assert patched["cron_expression"] == "0 3 * * 0"
        assert patched["id"] == schedule_id

    async def test_queue_health_returns_all_queues(self, client):
        """GET /api/v1/queue_health returns health info for known queues."""
        res = await client.get("/api/v1/queue_health")
        assert res.status_code == 200, f"GET /api/v1/queue_health: {res.status_code} {res.text}"
        body = res.json()
        assert "queues" in body, f"Response missing 'queues' key: {body}"
        queues = body["queues"]
        assert isinstance(queues, dict)

        expected_queues = [
            "info_gathering_queue",
            "authentication_queue",
            "authorization_queue",
            "input_validation_queue",
            "chain_worker_queue",
            "reporting_worker_queue",
        ]
        for queue_name in expected_queues:
            assert queue_name in queues, (
                f"Expected queue '{queue_name}' in queue_health response, got keys: {list(queues.keys())}"
            )
            queue_info = queues[queue_name]
            assert "pending" in queue_info, f"Queue '{queue_name}' missing 'pending' field"
            assert "health" in queue_info, f"Queue '{queue_name}' missing 'health' field"
            assert isinstance(queue_info["pending"], int)
            assert isinstance(queue_info["health"], str)
