"""E2E health + functional tests for sandbox_worker (infrastructure worker)."""
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "webbh-sandbox-worker"


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
        and "TimeoutError" not in line
        and "ConnectionError" not in line
    ]
    assert bad_lines == [], f"Unexpected errors in {CONTAINER} logs:\n" + "\n".join(bad_lines)


async def test_sandbox_mutate_endpoint_returns_variants(client):
    """POST /api/v1/sandbox/mutate returns a non-empty variant list for an XSS payload.

    Response schema (from orchestrator/main.py):
      {"vuln_type": str, "variants": list[str], "count": int}
    """
    res = await client.post(
        "/api/v1/sandbox/mutate",
        json={"vuln_type": "xss", "base_payload": "<script>alert(1)</script>"},
    )
    assert res.status_code == 200, f"returned {res.status_code}: {res.text}"
    data = res.json()
    assert isinstance(data.get("variants"), list), f"Expected list of variants: {data}"
    assert len(data["variants"]) >= 1, f"Expected at least 1 variant: {data}"
    assert data.get("vuln_type") == "xss"
    assert isinstance(data.get("count"), int)


async def test_sandbox_mutate_requires_base_payload(client):
    """POST /api/v1/sandbox/mutate with missing base_payload returns 400."""
    res = await client.post(
        "/api/v1/sandbox/mutate",
        json={"vuln_type": "xss"},
    )
    assert res.status_code == 400, f"Expected 400 for missing payload, got {res.status_code}"


async def test_sandbox_waf_fingerprint_endpoint(client):
    """POST /api/v1/sandbox/fingerprint returns a waf_profile dict.

    Response schema: {"waf_profile": str | dict | None}
    """
    res = await client.post(
        "/api/v1/sandbox/fingerprint",
        json={"headers": {"Server": "cloudflare"}, "body": "error 1020", "status_code": 403},
    )
    assert res.status_code == 200, f"returned {res.status_code}: {res.text}"
    data = res.json()
    assert "waf_profile" in data, f"Expected 'waf_profile' key in response: {data}"


async def test_sandbox_corpus_endpoint(client):
    """GET /api/v1/sandbox/corpus returns a non-empty corpus dict for vuln_type=xss.

    Response schema: {"corpus": {"<vuln_type>:<context>": list[str], ...}}
    """
    res = await client.get("/api/v1/sandbox/corpus", params={"vuln_type": "xss"})
    assert res.status_code == 200, f"returned {res.status_code}: {res.text}"
    data = res.json()
    assert "corpus" in data, f"Expected 'corpus' key in response: {data}"
    assert isinstance(data["corpus"], dict), f"Expected dict corpus: {data}"
    assert len(data["corpus"]) >= 1, f"Expected at least one corpus entry: {data}"


async def test_sandbox_waf_profiles_endpoint(client):
    """GET /api/v1/sandbox/waf-profiles returns a list of known WAF profile names.

    Response schema: {"profiles": list[str]}
    """
    res = await client.get("/api/v1/sandbox/waf-profiles")
    assert res.status_code == 200, f"returned {res.status_code}: {res.text}"
    data = res.json()
    assert "profiles" in data, f"Expected 'profiles' key in response: {data}"
    assert isinstance(data["profiles"], list), f"Expected list of profiles: {data}"
    assert len(data["profiles"]) >= 1, f"Expected at least one WAF profile: {data}"
