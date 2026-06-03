"""E2E tests for event engine dispatch logic.

Observes which workers get dispatched (via GET /api/v1/status) to verify
dependency ordering and credential-gating without mocking.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest

from conftest import (
    _BASE_URL, _read_api_key, _REPO_ROOT,
    cleanup_target, create_target,
    wait_for_worker_status,
)

pytestmark = pytest.mark.e2e

# Workers that require credentials.json to be present (mirrors CREDENTIAL_REQUIRED)
_CREDENTIAL_GATED = {"identity_mgmt", "authentication", "authorization", "session_mgmt", "input_validation"}


@pytest.fixture(scope="module")
async def client(stack):
    async with httpx.AsyncClient(
        base_url=_BASE_URL,
        headers={"X-API-KEY": _read_api_key(), "Content-Type": "application/json"},
        timeout=30.0,
    ) as c:
        yield c


async def _kill_and_delete_all(client: httpx.AsyncClient) -> None:
    """Hard-kill all active workers and delete all known targets."""
    await client.post("/api/v1/kill")
    res = await client.get("/api/v1/targets")
    if res.status_code == 200:
        for t in res.json().get("targets", []):
            await client.delete(f"/api/v1/targets/{t['id']}")


async def _poll_dispatched_workers(
    client: httpx.AsyncClient,
    target_id: int,
    wait_seconds: int = 30,
) -> set[str]:
    """Return set of worker container_names that appeared in job list within wait_seconds."""
    deadline = time.monotonic() + wait_seconds
    seen: set[str] = set()
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        if res.status_code == 200:
            jobs = res.json().get("jobs", [])
            seen.update(j["container_name"] for j in jobs)
        await asyncio.sleep(2)
    return seen


def _delete_credentials(target_id: int) -> None:
    """Remove the credentials.json file for the given target from the shared volume."""
    creds_path = _REPO_ROOT / "shared" / "config" / str(target_id) / "credentials.json"
    if creds_path.exists():
        creds_path.unlink()


def _write_credentials(target_id: int) -> None:
    """Write a stub credentials.json for the given target into the shared volume."""
    config_dir = _REPO_ROOT / "shared" / "config" / str(target_id)
    config_dir.mkdir(parents=True, exist_ok=True)
    creds_path = config_dir / "credentials.json"
    creds_path.write_text(json.dumps({"tester": None, "testing_user": None}))


@pytest.mark.e2e
async def test_no_credentials_skips_credential_gated_workers(client):
    """Without credentials.json, the event engine must not dispatch any credential-gated worker.

    create_target writes stub credentials by default, so we delete the file
    immediately after creation (before the first event-engine poll at t+5s).
    """
    target_id = None
    try:
        target_id = await create_target(client, playbook="wide_recon", company="EventEngineNoCreds")

        # Remove credentials before the event engine's next 5-second poll cycle.
        _delete_credentials(target_id)

        # Poll for 30 seconds; info_gathering (no creds needed) may appear but
        # credential-gated workers must never appear.
        seen = await _poll_dispatched_workers(client, target_id, wait_seconds=30)

        unexpected = _CREDENTIAL_GATED & seen
        assert not unexpected, (
            f"Credential-gated workers were dispatched without credentials.json: {unexpected}"
        )
    finally:
        if target_id is not None:
            await _kill_and_delete_all(client)


@pytest.mark.e2e
async def test_with_credentials_dispatches_auth_workers(client):
    """With credentials.json present after info_gathering completes,
    the event engine should dispatch at least one credential-gated worker
    (identity_mgmt appears first in the gated chain after config_mgmt).
    """
    target_id = None
    try:
        # create_target already writes stub credentials; keep them in place.
        target_id = await create_target(
            client,
            playbook="wide_recon",
            company="EventEngineWithCreds",
            worker="info_gathering",
        )

        # Ensure credentials are present (create_target writes them, but be explicit).
        _write_credentials(target_id)

        # Wait for info_gathering to complete (up to 300 s) so dependencies unlock.
        await wait_for_worker_status(
            client,
            target_id,
            "info_gathering",
            {"COMPLETED"},
            timeout=300,
        )

        # After info_gathering completes, config_mgmt should be dispatched next,
        # and once config_mgmt completes, identity_mgmt should appear.
        # Poll for up to 120 s to observe at least one credential-gated worker.
        seen = await _poll_dispatched_workers(client, target_id, wait_seconds=120)

        dispatched_gated = _CREDENTIAL_GATED & seen
        assert dispatched_gated, (
            f"No credential-gated workers were dispatched after info_gathering completed. "
            f"Seen workers: {seen}"
        )
    finally:
        if target_id is not None:
            await _kill_and_delete_all(client)


@pytest.mark.e2e
async def test_dependency_config_mgmt_waits_for_info_gathering(client):
    """config_mgmt must never enter QUEUED or RUNNING state while
    info_gathering is not yet COMPLETED.

    Polls /api/v1/status continuously for up to 300 s and asserts that
    no config_mgmt dispatch is observed before info_gathering finishes.
    """
    target_id = None
    try:
        target_id = await create_target(
            client,
            playbook="wide_recon",
            company="EventEngineDepsOrdering",
            worker="info_gathering",
        )

        deadline = time.monotonic() + 300
        violation_found = False

        while time.monotonic() < deadline:
            res = await client.get("/api/v1/status", params={"target_id": target_id})
            if res.status_code != 200:
                await asyncio.sleep(2)
                continue

            jobs = res.json().get("jobs", [])
            jobs_by_worker = {j["container_name"]: j for j in jobs}

            ig_status = jobs_by_worker.get("info_gathering", {}).get("status")
            cm_status = jobs_by_worker.get("config_mgmt", {}).get("status")

            # config_mgmt dispatched (QUEUED/RUNNING) while info_gathering not COMPLETED
            if cm_status in ("QUEUED", "RUNNING") and ig_status != "COMPLETED":
                violation_found = True
                break

            # Once info_gathering is completed we can stop checking the ordering invariant.
            if ig_status == "COMPLETED":
                break

            await asyncio.sleep(2)

        assert not violation_found, (
            "config_mgmt was dispatched before info_gathering reached COMPLETED status"
        )
    finally:
        if target_id is not None:
            await _kill_and_delete_all(client)


@pytest.mark.e2e
async def test_disabled_worker_never_dispatched(client):
    """When using the e2e_info_gathering playbook (only info_gathering enabled),
    chain_worker must never be dispatched even after info_gathering finishes.
    """
    target_id = None
    try:
        target_id = await create_target(
            client,
            playbook="e2e_info_gathering",
            company="EventEngineDisabledWorker",
            worker="info_gathering",
        )

        # Wait for info_gathering to complete (or time out).
        try:
            await wait_for_worker_status(
                client,
                target_id,
                "info_gathering",
                {"COMPLETED"},
                timeout=300,
            )
        except TimeoutError:
            pass  # Even if info_gathering never finishes, chain_worker must not appear.

        # Poll 30 more seconds after info_gathering is done.
        seen = await _poll_dispatched_workers(client, target_id, wait_seconds=30)

        assert "chain_worker" not in seen, (
            "chain_worker was dispatched even though it is disabled in the e2e_info_gathering playbook"
        )
    finally:
        if target_id is not None:
            await _kill_and_delete_all(client)


@pytest.mark.e2e
async def test_event_engine_resumes_after_kill(client):
    """After killing target A and creating target B, the event engine must
    dispatch info_gathering for target B within 60 seconds.
    """
    target_a_id = None
    target_b_id = None
    try:
        # Create target A and let it start.
        target_a_id = await create_target(
            client,
            playbook="e2e_info_gathering",
            company="EventEngineKillTargetA",
            worker="info_gathering",
        )

        # Wait a moment so the engine has dispatched at least one job for A.
        await asyncio.sleep(10)

        # Kill and delete target A.
        await _kill_and_delete_all(client)
        target_a_id = None  # already deleted

        # Create target B.
        target_b_id = await create_target(
            client,
            playbook="e2e_info_gathering",
            company="EventEngineResumeTargetB",
            worker="info_gathering",
        )

        # The event engine polls every 5 s; within 60 s info_gathering must appear.
        seen = await _poll_dispatched_workers(client, target_b_id, wait_seconds=60)

        assert "info_gathering" in seen, (
            f"info_gathering was not dispatched for target B within 60 s after kill. "
            f"Seen workers: {seen}"
        )
    finally:
        await _kill_and_delete_all(client)
