"""E2E health + functional tests for proxy worker (mitmproxy + rule manager API)."""
import json
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "webbh-proxy"
_RULE_API = "http://localhost:8081"


def _exec_curl(path: str, method: str = "GET", data: str | None = None) -> dict:
    """Run curl inside the proxy container and return parsed JSON."""
    cmd = ["docker", "exec", CONTAINER, "curl", "-s", "-X", method]
    if data:
        cmd += ["-H", "Content-Type: application/json", "-d", data]
    cmd.append(f"{_RULE_API}{path}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, f"curl failed: {result.stderr}"
    return json.loads(result.stdout)


def test_proxy_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    assert result.stdout.strip() == "running", (
        f"Expected '{CONTAINER}' to be running, got: {result.stdout.strip()}"
    )


def test_proxy_logs_clean():
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


def test_proxy_rule_manager_api_responds():
    """Rule manager REST API (port 8081 internal) returns a list on GET /rules."""
    data = _exec_curl("/rules")
    assert isinstance(data, list), f"Expected list of rules, got: {data}"


def test_proxy_rule_manager_add_and_delete_rule():
    """Add a rule, verify it appears in the rule list, then delete it.

    The rule format mirrors the RuleStore schema: a ``match`` dict with
    ``url_pattern`` and an ``action`` dict with ``type`` plus any
    action-specific keys.
    """
    rule_payload = json.dumps({
        "match": {"url_pattern": "*.example.com*"},
        "action": {"type": "inject_header", "name": "X-Test-Injected", "value": "1"},
    })
    created = _exec_curl("/rules", method="POST", data=rule_payload)
    assert "id" in created, f"Expected 'id' in created rule response: {created}"
    rule_id = created["id"]

    rules = _exec_curl("/rules")
    ids = [r["id"] for r in rules]
    assert rule_id in ids, f"Newly created rule {rule_id} not found in rule list: {ids}"

    deleted = _exec_curl(f"/rules/{rule_id}", method="DELETE")
    assert "deleted" in deleted, f"Expected 'deleted' in delete response: {deleted}"

    rules_after = _exec_curl("/rules")
    ids_after = [r["id"] for r in rules_after]
    assert rule_id not in ids_after, (
        f"Rule {rule_id} still present after deletion: {ids_after}"
    )


def test_proxy_rule_manager_delete_nonexistent_returns_404():
    """Deleting a rule that does not exist returns a 404 error body."""
    cmd = [
        "docker", "exec", CONTAINER,
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "-X", "DELETE",
        f"{_RULE_API}/rules/nonexistent-rule-id",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, f"curl failed: {result.stderr}"
    assert result.stdout.strip() == "404", (
        f"Expected 404 for nonexistent rule, got: {result.stdout.strip()}"
    )
