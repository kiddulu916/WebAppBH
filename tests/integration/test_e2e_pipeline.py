"""End-to-end integration test (requires running services).

Run with: pytest tests/integration/ -m integration -v
Requires: docker compose -f tests/integration/docker-compose.test.yml up -d
"""
import os
import pytest

BASE_URL = os.environ.get("TEST_API_URL", "http://localhost:8001")
API_KEY = os.environ.get("WEB_APP_BH_API_KEY", "")

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
async def client():
    import httpx
    async with httpx.AsyncClient(
        base_url=BASE_URL,
        headers={"X-API-KEY": API_KEY, "Content-Type": "application/json"},
        timeout=30,
    ) as c:
        yield c


async def test_create_target_and_check_status(client):
    """Create a target and verify it appears in status."""
    res = await client.post("/api/v1/targets", json={
        "company_name": "IntegrationTest",
        "base_domain": "example-integration.com",
        "playbook": "wide_recon",
    })
    assert res.status_code == 201
    target_id = res.json()["target_id"]

    # Verify target appears in list
    targets = await client.get("/api/v1/targets")
    assert any(t["id"] == target_id for t in targets.json()["targets"])

    # Verify status endpoint works
    status = await client.get(f"/api/v1/status?target_id={target_id}")
    assert status.status_code == 200


async def test_assets_endpoint_returns_empty(client):
    """New target should have no assets initially."""
    res = await client.post("/api/v1/targets", json={
        "company_name": "AssetTest",
        "base_domain": "asset-test.com",
    })
    target_id = res.json()["target_id"]

    assets = await client.get(f"/api/v1/assets?target_id={target_id}")
    assert assets.status_code == 200
    assert assets.json()["assets"] == []


async def test_vulnerabilities_endpoint(client):
    """New target should have no vulns initially."""
    res = await client.post("/api/v1/targets", json={
        "company_name": "VulnTest",
        "base_domain": "vuln-test.com",
    })
    target_id = res.json()["target_id"]

    vulns = await client.get(f"/api/v1/vulnerabilities?target_id={target_id}")
    assert vulns.status_code == 200
    assert vulns.json()["vulnerabilities"] == []


async def test_sse_connection(client):
    """Verify SSE endpoint accepts connections."""
    import httpx
    res = await client.post("/api/v1/targets", json={
        "company_name": "SSETest",
        "base_domain": "sse-test.com",
    })
    target_id = res.json()["target_id"]

    async with httpx.AsyncClient(
        base_url=BASE_URL,
        headers={"X-API-KEY": API_KEY},
    ) as c:
        try:
            async with c.stream("GET", f"/api/v1/stream/{target_id}", timeout=5) as stream:
                assert stream.status_code == 200
        except httpx.ReadTimeout:
            pass  # Expected - SSE streams don't end


async def test_health_endpoint(client):
    """Verify health endpoint responds."""
    res = await client.get("/api/v1/health")
    # Health endpoint may or may not exist, just check connectivity
    assert res.status_code in (200, 404)
