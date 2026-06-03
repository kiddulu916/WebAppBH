"""E2E health + functional tests for proxy worker (mitmproxy + rule manager API)."""
import json
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "webbh-proxy"
_RULE_API = "http://localhost:8081"


def _exec_http(path: str, method: str = "GET", data: str | None = None) -> tuple[int, object]:
    """HTTP request inside proxy container via python3 stdlib. Returns (status_code, parsed_body)."""
    script = "\n".join([
        "import urllib.request, urllib.error, json, sys",
        f"url = 'http://localhost:8081{path}'",
        f"method = '{method}'",
        f"body = {repr(data.encode()) if data else 'None'}",
        "headers = {'Content-Type': 'application/json'} if body else {}",
        "req = urllib.request.Request(url, data=body, headers=headers, method=method)",
        "try:",
        "    with urllib.request.urlopen(req) as r:",
        "        sys.stdout.write(str(r.status) + '\\n' + r.read().decode())",
        "except urllib.error.HTTPError as e:",
        "    sys.stdout.write(str(e.code) + '\\n' + (e.read().decode() or '{}'))",
    ])
    result = subprocess.run(
        ["docker", "exec", CONTAINER, "python3", "-c", script],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, f"python3 exec failed: {result.stderr}"
    out_lines = result.stdout.strip().split("\n", 1)
    status = int(out_lines[0])
    body_str = out_lines[1].strip() if len(out_lines) > 1 else "{}"
    try:
        body = json.loads(body_str)
    except json.JSONDecodeError:
        body = {}
    return status, body


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
    status, body = _exec_http("/rules")
    assert status == 200, f"Expected 200, got {status}"
    assert isinstance(body, list), f"Expected list of rules, got: {body}"


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
    status, created = _exec_http("/rules", method="POST", data=rule_payload)
    assert status == 201, f"Expected 201, got {status}: {created}"
    assert "id" in created, f"Expected 'id' in created rule response: {created}"
    rule_id = created["id"]

    _, rules = _exec_http("/rules")
    ids = [r["id"] for r in rules]
    assert rule_id in ids, f"Newly created rule {rule_id} not found in rule list: {ids}"

    status, deleted = _exec_http(f"/rules/{rule_id}", method="DELETE")
    assert status == 200, f"Expected 200 on delete, got {status}"
    assert "deleted" in deleted, f"Expected 'deleted' in delete response: {deleted}"

    _, rules_after = _exec_http("/rules")
    ids_after = [r["id"] for r in rules_after]
    assert rule_id not in ids_after, (
        f"Rule {rule_id} still present after deletion: {ids_after}"
    )


def test_proxy_rule_manager_delete_nonexistent_returns_404():
    """Deleting a rule that does not exist returns 404."""
    status, _ = _exec_http("/rules/nonexistent-rule-id", method="DELETE")
    assert status == 404, f"Expected 404 for nonexistent rule, got {status}"
