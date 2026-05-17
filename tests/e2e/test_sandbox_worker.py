"""E2E health test for sandbox_worker (infrastructure worker, no pipeline stages)."""
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "sandbox_worker"


def test_sandbox_worker_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    assert result.stdout.strip() == "running", (
        f"Expected '{CONTAINER}' to be running, got: {result.stdout.strip()}"
    )


def test_sandbox_worker_logs_clean():
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
    ]
    assert bad_lines == [], f"Unexpected errors in {CONTAINER} logs:\n" + "\n".join(bad_lines)
