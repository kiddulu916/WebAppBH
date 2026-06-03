"""E2E health + functional tests for callback worker (OOB interaction listener)."""
import subprocess
import pytest
import httpx

pytestmark = pytest.mark.e2e

CONTAINER = "webbh-callback"
# Port 9091 is the callback management/polling REST API (api.py via create_app).
# Port 9090 is the raw HTTP interaction listener (not the CRUD API).
_CALLBACK_BASE = "http://localhost:9091"


def test_callback_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    assert result.stdout.strip() == "running", (
        f"Expected '{CONTAINER}' to be running, got: {result.stdout.strip()}"
    )


def test_callback_logs_clean():
    result = subprocess.run(
        ["docker", "logs", CONTAINER, "--tail", "100"],
        capture_output=True, text=True, timeout=15,
    )
    combined = result.stdout + result.stderr
    bad_lines = [
        line for line in combined.splitlines()
        if ("Traceback (most recent call last)" in line
            or " ERROR " in line or " CRITICAL " in line)
        and "Retrying" not in line
        and "TimeoutError" not in line
        and "ConnectionError" not in line
    ]
    assert bad_lines == [], f"Unexpected errors in {CONTAINER} logs:\n" + "\n".join(bad_lines)


async def test_callback_register_poll_delete_lifecycle():
    """Register a callback ID, poll it, record an interaction, then delete it.

    Routes (from workers/callback/api.py):
      POST   /callbacks                    → 201 {"id": "<cb_id>"}
      GET    /callbacks/{cb_id}            → 200 {id, protocols, interactions, created_at}
      POST   /callbacks/{cb_id}/interaction → 200 {"recorded": True}
      DELETE /callbacks/{cb_id}            → 200 {"deleted": "<cb_id>"}
    """
    async with httpx.AsyncClient(base_url=_CALLBACK_BASE, timeout=10.0) as client:
        # Register
        res = await client.post("/callbacks", json={"protocols": ["http", "dns"]})
        assert res.status_code == 201, f"POST /callbacks returned {res.status_code}: {res.text}"
        body = res.json()
        assert "id" in body, f"Expected 'id' in register response: {body}"
        cb_id = body["id"]

        # Poll — verify the registered callback is retrievable
        res = await client.get(f"/callbacks/{cb_id}")
        assert res.status_code == 200, f"GET /callbacks/{cb_id} returned {res.status_code}"
        poll_body = res.json()
        assert poll_body["id"] == cb_id
        assert "interactions" in poll_body

        # Record an interaction
        res = await client.post(
            f"/callbacks/{cb_id}/interaction",
            json={"protocol": "http", "source_ip": "1.2.3.4", "data": "ping"},
        )
        assert res.status_code == 200, (
            f"POST /callbacks/{cb_id}/interaction returned {res.status_code}: {res.text}"
        )
        assert res.json().get("recorded") is True

        # Verify the interaction was stored
        res = await client.get(f"/callbacks/{cb_id}")
        assert res.status_code == 200
        interactions = res.json().get("interactions", [])
        assert len(interactions) == 1, f"Expected 1 interaction, got {len(interactions)}"

        # Delete
        res = await client.delete(f"/callbacks/{cb_id}")
        assert res.status_code == 200, (
            f"DELETE /callbacks/{cb_id} returned {res.status_code}: {res.text}"
        )
        assert res.json().get("deleted") == cb_id


async def test_callback_poll_nonexistent_returns_404():
    """GET on an unregistered callback ID returns 404."""
    async with httpx.AsyncClient(base_url=_CALLBACK_BASE, timeout=10.0) as client:
        res = await client.get("/callbacks/nonexistent-id-12345")
        assert res.status_code == 404, (
            f"Expected 404 for unknown callback, got {res.status_code}: {res.text}"
        )


async def test_callback_interaction_on_nonexistent_returns_404():
    """POST interaction to an unregistered callback ID returns 404."""
    async with httpx.AsyncClient(base_url=_CALLBACK_BASE, timeout=10.0) as client:
        res = await client.post(
            "/callbacks/nonexistent-id-99999/interaction",
            json={"protocol": "http", "source_ip": "0.0.0.0", "data": "x"},
        )
        assert res.status_code == 404, (
            f"Expected 404 for unknown callback interaction, got {res.status_code}: {res.text}"
        )
