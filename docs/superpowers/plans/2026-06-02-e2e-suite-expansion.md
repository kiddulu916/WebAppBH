# E2E Suite Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the backend e2e suite from "did stages fire?" to "did the pipeline produce real findings?", cover the orchestrator's full API surface, add event engine dispatch assertions, and add functional tests for the three infrastructure workers.

**Architecture:** Option A — extend existing `test_<worker>.py` files in-place; add `test_orchestrator_api.py` and `test_event_engine.py` as new modules; add API key middleware to the orchestrator as a prerequisite for auth tests. No directory restructure.

**Tech Stack:** pytest-asyncio, httpx, lib_webbh (asyncpg, get_session), Docker SDK (via subprocess), aiohttp (for callback/proxy tests)

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `orchestrator/main.py` | Add API key middleware (Task 1) |
| Modify | `tests/conftest.py` | Add 4 new helpers (Task 2) |
| Modify | `tests/e2e/test_authentication.py` | Last-stage assertion + edge-case test (Task 3) |
| Modify | `tests/e2e/test_authorization.py` | Last-stage assertion + edge-case test (Task 3) |
| Modify | `tests/e2e/test_session_mgmt.py` | Last-stage assertion + edge-case test (Task 3) |
| Modify | `tests/e2e/test_input_validation.py` | Last-stage assertion + edge-case test (Task 4) |
| Modify | `tests/e2e/test_error_handling.py` | Last-stage assertion + edge-case test (Task 4) |
| Modify | `tests/e2e/test_cryptography.py` | Last-stage assertion + edge-case test (Task 4) |
| Modify | `tests/e2e/test_business_logic.py` | Last-stage assertion + edge-case test (Task 4) |
| Modify | `tests/e2e/test_client_side.py` | Last-stage assertion + edge-case test (Task 5) |
| Modify | `tests/e2e/test_config_mgmt.py` | Last-stage assertion + edge-case test (Task 5) |
| Modify | `tests/e2e/test_identity_mgmt.py` | Last-stage assertion + edge-case test (Task 5) |
| Modify | `tests/e2e/test_info_gathering.py` | Asset-type diversity edge-case test (Task 5) |
| Modify | `tests/e2e/test_chain_worker.py` | Last-stage assertion + edge-case test (Task 6) |
| Modify | `tests/e2e/test_reporting_worker.py` | Report-downloadable edge-case test (Task 6) |
| Modify | `tests/e2e/test_proxy.py` | Rule-manager API + mitmproxy health tests (Task 7) |
| Modify | `tests/e2e/test_callback.py` | Register/poll/delete callback lifecycle test (Task 7) |
| Modify | `tests/e2e/test_sandbox_worker.py` | Mutate endpoint + WAF fingerprint tests (Task 7) |
| Create | `tests/e2e/test_orchestrator_api.py` | Control plane, data APIs, edge cases (Tasks 8–10) |
| Create | `tests/e2e/test_event_engine.py` | Dispatch ordering and credential-gating tests (Task 11) |

---

## Task 1: Add API key middleware to orchestrator

The orchestrator currently has no `X-API-KEY` enforcement — clients send it but it is never checked. The auth-rejection tests in Tasks 8–10 require this to exist.

**Files:**
- Modify: `orchestrator/main.py` (add middleware after the CORS middleware section, around line 435)

- [ ] **Step 1: Write the failing test first**

Create a temporary scratch file to confirm the current behavior:

```bash
# Run against the live stack (requires --e2e flag)
cd C:\Users\dat1k\Projects\WebAppBH\tests
python -c "
import urllib.request
req = urllib.request.Request('http://localhost:8001/api/v1/targets')
try:
    resp = urllib.request.urlopen(req, timeout=5)
    print('Status (no key):', resp.status)   # Expect 401 — currently returns 200
except Exception as e:
    print('Error:', e)
"
```

Expected current result: 200 (no enforcement yet). After Task 1: 401.

- [ ] **Step 2: Add the API key middleware to `orchestrator/main.py`**

Read the file around line 393–434 (the middleware section) then add after the existing middlewares:

```python
# API key auth middleware — must come AFTER CORSMiddleware but BEFORE routing
_FRAMEWORK_API_KEY = os.environ.get("WEB_APP_BH_API_KEY", "")
_UNPROTECTED_PATHS = {"/health", "/metrics"}


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in _UNPROTECTED_PATHS:
        return await call_next(request)
    if not _FRAMEWORK_API_KEY:
        # Key not configured — allow all (development mode)
        return await call_next(request)
    incoming = request.headers.get("X-API-KEY", "")
    if incoming != _FRAMEWORK_API_KEY:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)
```

Place this block **after** `app.add_middleware(CORSMiddleware, ...)` and **before** `@app.get("/metrics", ...)`.

- [ ] **Step 3: Verify middleware triggers**

```bash
python -c "
import urllib.request
req = urllib.request.Request('http://localhost:8001/api/v1/targets')
try:
    resp = urllib.request.urlopen(req, timeout=5)
    print('Status:', resp.status)
except urllib.error.HTTPError as e:
    print('HTTP Error:', e.code)  # Expected: 401
"
```

Expected: `HTTP Error: 401`. Health endpoint must still return 200:

```bash
python -c "
import urllib.request
resp = urllib.request.urlopen('http://localhost:8001/health', timeout=5)
print('Health:', resp.status)  # Expected: 200
"
```

- [ ] **Step 4: Restart the orchestrator container and re-run the full e2e suite to confirm nothing broke**

```bash
docker compose restart orchestrator
pytest tests/e2e/ --e2e -v -x --timeout=120 -k "not test_orchestrator_api and not test_event_engine"
```

Expected: all previously-passing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat(orchestrator): add X-API-KEY enforcement middleware"
```

---

## Task 2: Add conftest helpers

**Files:**
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add `assert_chain_findings` helper**

Append after `assert_vulnerabilities` in `tests/conftest.py`:

```python
async def assert_chain_findings(
    client: httpx.AsyncClient,
    target_id: int,
    min_count: int = 1,
) -> list:
    """Assert ≥ min_count vulnerabilities with worker_type='chain_worker' exist."""
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "chain_worker"},
    )
    assert res.status_code == 200, f"GET /api/v1/vulnerabilities returned {res.status_code}"
    data = res.json()
    assert data["total"] >= min_count, (
        f"Expected ≥{min_count} chain findings for target {target_id}, got {data['total']}"
    )
    return data["vulnerabilities"]
```

- [ ] **Step 2: Add `assert_reports` helper**

```python
async def assert_reports(
    client: httpx.AsyncClient,
    target_id: int,
    min_count: int = 1,
) -> list:
    """Assert ≥ min_count report files are listed for target."""
    res = await client.get(f"/api/v1/targets/{target_id}/reports")
    assert res.status_code == 200, f"GET /api/v1/targets/{target_id}/reports returned {res.status_code}"
    data = res.json()
    assert len(data["reports"]) >= min_count, (
        f"Expected ≥{min_count} report files for target {target_id}, got {len(data['reports'])}"
    )
    return data["reports"]
```

- [ ] **Step 3: Add `wait_for_worker_status` helper**

```python
async def wait_for_worker_status(
    client: httpx.AsyncClient,
    target_id: int,
    worker: str,
    expected_statuses: set[str],
    poll_interval: int = 5,
    timeout: int = 300,
) -> str:
    """Poll /api/v1/status until worker reaches one of expected_statuses."""
    import asyncio as _asyncio
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        job = next((j for j in jobs if j["container_name"] == worker), None)
        if job and job["status"] in expected_statuses:
            return job["status"]
        await _asyncio.sleep(poll_interval)
    raise TimeoutError(
        f"Worker '{worker}' did not reach {expected_statuses} within {timeout}s for target {target_id}"
    )
```

- [ ] **Step 4: Add `seed_vulnerability` helper**

```python
async def seed_vulnerability(target_id: int, asset_id: int | None = None) -> dict:
    """Insert a Vulnerability row directly via lib_webbh for use in orchestrator tests.

    Does NOT use the /api/v1/test/seed endpoint — that seeds a full fixture.
    Requires _load_env_file() to have been called (happens at module import).
    """
    from lib_webbh import get_session, Vulnerability, Asset
    from sqlalchemy import select as _select

    async with get_session() as session:
        if asset_id is None:
            result = await session.execute(
                _select(Asset).where(Asset.target_id == target_id).limit(1)
            )
            asset = result.scalar_one_or_none()
            if asset:
                asset_id = asset.id

        vuln = Vulnerability(
            target_id=target_id,
            asset_id=asset_id,
            severity="medium",
            title="Seeded Test Vulnerability",
            description="Inserted directly for orchestrator API testing",
            source_tool="test_seed",
            worker_type="test",
            vuln_type="informational",
            confirmed=True,
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)
        return {"id": vuln.id, "title": vuln.title, "severity": vuln.severity, "target_id": target_id}
```

- [ ] **Step 5: Add `seed_asset` helper** (needed by `seed_vulnerability` and data API tests)

```python
async def seed_asset(target_id: int) -> dict:
    """Insert an Asset row directly via lib_webbh."""
    from lib_webbh import get_session, Asset

    async with get_session() as session:
        asset = Asset(
            target_id=target_id,
            asset_type="url",
            asset_value=f"http://testphp.vulnweb.com/seeded-{target_id}",
            source_tool="test_seed",
            scope_classification="in-scope",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        return {"id": asset.id, "asset_value": asset.asset_value, "target_id": target_id}
```

- [ ] **Step 6: Verify helpers are importable**

```bash
cd C:\Users\dat1k\Projects\WebAppBH\tests
python -c "from conftest import assert_chain_findings, assert_reports, wait_for_worker_status, seed_vulnerability, seed_asset; print('OK')"
```

Expected: `OK`

- [ ] **Step 7: Commit**

```bash
git add tests/conftest.py
git commit -m "test(e2e): add assert_chain_findings, assert_reports, wait_for_worker_status, seed_vulnerability, seed_asset helpers"
```

---

## Task 3: Worker result assertions — vuln workers part 1

Target workers: `authentication`, `authorization`, `session_mgmt`.

**Files:**
- Modify: `tests/e2e/test_authentication.py`
- Modify: `tests/e2e/test_authorization.py`
- Modify: `tests/e2e/test_session_mgmt.py`

### authentication

- [ ] **Step 1: Update `test_authentication.py` STAGE_ASSERTIONS and imports**

```python
# Add to imports
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

# Change LAST_STAGE assertion
STAGE_ASSERTIONS = {
    "default_credentials":   None,
    "lockout_mechanism":     None,
    "auth_bypass":           None,
    "remember_password":     None,
    "browser_cache":         None,
    "weak_password_policy":  None,
    "security_questions":    None,
    "password_change":       None,
    "multi_channel_auth":    lambda c, tid: assert_vulnerabilities(c, tid),
}
```

- [ ] **Step 2: Add edge-case test to `test_authentication.py`**

Append at end of file:

```python
async def test_authentication_all_vulns_have_severity(client, pipeline_result):
    """Assert every vulnerability from authentication has a non-null severity."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "authentication"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No authentication vulnerabilities found — worker did not produce findings"
    for v in vulns:
        assert v["severity"] is not None and v["severity"] != "", (
            f"Vulnerability {v['id']} ({v['title']!r}) has null/empty severity"
        )
```

- [ ] **Step 3: Update `test_authorization.py` STAGE_ASSERTIONS and add edge-case test**

```python
# Add to imports
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

# Change LAST_STAGE assertion
STAGE_ASSERTIONS = {
    "directory_traversal":  None,
    "authz_bypass":         None,
    "privilege_escalation": None,
    "idor":                 lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_authorization_all_vulns_have_description(client, pipeline_result):
    """Assert every authorization vulnerability has a non-empty description."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "authorization"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No authorization vulnerabilities found"
    for v in vulns:
        assert v["description"] is not None and v["description"].strip() != "", (
            f"Vulnerability {v['id']} ({v['title']!r}) has empty description"
        )
```

- [ ] **Step 4: Update `test_session_mgmt.py` STAGE_ASSERTIONS and add edge-case test**

```python
# Add to imports
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

# Change LAST_STAGE assertion
STAGE_ASSERTIONS = {
    "session_scheme":       None,
    "cookie_attributes":    None,
    "session_fixation":     None,
    "exposed_variables":    None,
    "csrf":                 None,
    "logout_functionality": None,
    "session_timeout":      None,
    "session_puzzling":     None,
    "session_hijacking":    lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_session_mgmt_vulns_have_source_tool(client, pipeline_result):
    """Assert every session_mgmt vulnerability records which tool found it."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "session_mgmt"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No session_mgmt vulnerabilities found"
    for v in vulns:
        assert v["source_tool"] is not None and v["source_tool"].strip() != "", (
            f"Vulnerability {v['id']} has null source_tool"
        )
```

- [ ] **Step 5: Run to confirm test structure is correct** (tests will skip without `--e2e`)

```bash
cd C:\Users\dat1k\Projects\WebAppBH\tests
pytest e2e/test_authentication.py e2e/test_authorization.py e2e/test_session_mgmt.py -v --collect-only
```

Expected: all new test functions appear in the collection output with `SKIP` marker.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/test_authentication.py tests/e2e/test_authorization.py tests/e2e/test_session_mgmt.py
git commit -m "test(e2e): add result assertions and edge-case tests for auth/authz/session workers"
```

---

## Task 4: Worker result assertions — vuln workers part 2

Target workers: `input_validation`, `error_handling`, `cryptography`, `business_logic`.

**Files:**
- Modify: `tests/e2e/test_input_validation.py`
- Modify: `tests/e2e/test_error_handling.py`
- Modify: `tests/e2e/test_cryptography.py`
- Modify: `tests/e2e/test_business_logic.py`

- [ ] **Step 1: Update `test_input_validation.py`**

```python
# Add to imports
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

# Change LAST_STAGE assertion (websocket_injection)
STAGE_ASSERTIONS = {
    "reflected_xss":         None,
    "stored_xss":            None,
    "http_verb_tampering":   None,
    "http_param_pollution":  None,
    "sql_injection":         None,
    "ldap_injection":        None,
    "xml_injection":         None,
    "ssti":                  None,
    "xpath_injection":       None,
    "imap_smtp_injection":   None,
    "code_injection":        None,
    "command_injection":     None,
    "format_string":         None,
    "host_header_injection": None,
    "ssrf":                  None,
    "file_inclusion":        None,
    "buffer_overflow":       None,
    "http_smuggling":        None,
    "websocket_injection":   lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_input_validation_vuln_types_diverse(client, pipeline_result):
    """Assert input_validation produced ≥2 distinct vuln_type values (multiple tool categories ran)."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "input_validation", "page_size": 500},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No input_validation vulnerabilities found"
    vuln_types = {v["vuln_type"] for v in vulns if v.get("vuln_type")}
    assert len(vuln_types) >= 2, (
        f"Expected ≥2 distinct vuln_type values, got {vuln_types}"
    )
```

- [ ] **Step 2: Update `test_error_handling.py`**

```python
# Add assert_vulnerabilities to imports (already imports assert_assets)
from conftest import (
    assert_assets, assert_job_completed, assert_vulnerabilities,
    cleanup_target, create_target,
)

# Change LAST_STAGE assertion (stack_traces)
STAGE_ASSERTIONS = {
    "error_codes":  lambda c, tid: assert_assets(c, tid),
    "stack_traces": lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_error_handling_vulns_have_poc(client, pipeline_result):
    """Assert error_handling vulnerabilities include evidence (poc field non-null)."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "error_handling"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No error_handling vulnerabilities found"
    vulns_with_poc = [v for v in vulns if v.get("poc")]
    assert len(vulns_with_poc) > 0, (
        "At least one error_handling vulnerability should have a poc/evidence field"
    )
```

- [ ] **Step 3: Update `test_cryptography.py`**

```python
# Add assert_vulnerabilities to imports (already imports assert_assets)
from conftest import (
    assert_assets, assert_job_completed, assert_vulnerabilities,
    cleanup_target, create_target,
)

# Change LAST_STAGE assertion (weak_crypto)
STAGE_ASSERTIONS = {
    "tls_testing":            lambda c, tid: assert_assets(c, tid),
    "padding_oracle":         None,
    "plaintext_transmission": None,
    "weak_crypto":            lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_cryptography_vuln_severity_set(client, pipeline_result):
    """Assert all cryptography vulnerabilities have a non-null severity."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "cryptography"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No cryptography vulnerabilities found"
    for v in vulns:
        assert v["severity"] is not None and v["severity"] != "", (
            f"Crypto vulnerability {v['id']} has null severity"
        )
```

- [ ] **Step 4: Update `test_business_logic.py`**

```python
# Add assert_vulnerabilities to imports
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

# Change LAST_STAGE assertion (malicious_file_upload)
STAGE_ASSERTIONS = {
    "data_validation":        None,
    "request_forgery":        None,
    "integrity_checks":       None,
    "process_timing":         None,
    "rate_limiting":          None,
    "workflow_bypass":        None,
    "application_misuse":     None,
    "file_upload_validation": None,
    "malicious_file_upload":  lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_business_logic_vuln_confirmed_field_set(client, pipeline_result):
    """Assert business_logic vulnerabilities have the confirmed field explicitly set."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "business_logic"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No business_logic vulnerabilities found"
    for v in vulns:
        assert v["confirmed"] is not None, (
            f"Business logic vulnerability {v['id']} has null confirmed field"
        )
```

- [ ] **Step 5: Verify collection**

```bash
pytest tests/e2e/test_input_validation.py tests/e2e/test_error_handling.py tests/e2e/test_cryptography.py tests/e2e/test_business_logic.py -v --collect-only
```

Expected: all new test functions collected.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/test_input_validation.py tests/e2e/test_error_handling.py tests/e2e/test_cryptography.py tests/e2e/test_business_logic.py
git commit -m "test(e2e): add result assertions and edge-case tests for input_validation/error_handling/crypto/business_logic"
```

---

## Task 5: Worker result assertions — asset workers + info_gathering

Target workers: `client_side`, `config_mgmt`, `identity_mgmt`, `info_gathering` (edge-case only).

**Files:**
- Modify: `tests/e2e/test_client_side.py`
- Modify: `tests/e2e/test_config_mgmt.py`
- Modify: `tests/e2e/test_identity_mgmt.py`
- Modify: `tests/e2e/test_info_gathering.py`

- [ ] **Step 1: Update `test_client_side.py`**

```python
# Add assert_vulnerabilities to imports
from conftest import (
    assert_job_completed, assert_vulnerabilities, cleanup_target, create_target,
)

# Change LAST_STAGE assertion (malicious_upload_client)
STAGE_ASSERTIONS = {
    "dom_xss":                           None,
    "clickjacking":                      None,
    "csrf_tokens":                       None,
    "csp_bypass":                        None,
    "html5_injection":                   None,
    "web_storage":                       None,
    "client_side_logic":                 None,
    "dom_based_injection":               None,
    "client_side_resource_manipulation": None,
    "client_side_auth":                  None,
    "xss_client_side":                   None,
    "css_injection":                     None,
    "malicious_upload_client":           lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_client_side_vulns_have_source_tool(client, pipeline_result):
    """Assert every client_side vulnerability records which tool produced it."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "client_side"},
    )
    assert res.status_code == 200
    vulns = res.json()["vulnerabilities"]
    assert vulns, "No client_side vulnerabilities found"
    for v in vulns:
        assert v["source_tool"] is not None and v["source_tool"].strip() != "", (
            f"Client-side vulnerability {v['id']} has null source_tool"
        )
```

- [ ] **Step 2: Update `test_config_mgmt.py`**

```python
# Add assert_vulnerabilities to imports (already imports assert_assets)
from conftest import (
    assert_assets, assert_job_completed, assert_vulnerabilities,
    cleanup_target, create_target,
)

# Change LAST_STAGE assertion (security_headers)
STAGE_ASSERTIONS = {
    "network_config":               None,
    "network_config_cred_test":     None,
    "platform_config":              lambda c, tid: assert_assets(c, tid),
    "file_extension_handling":      None,
    "backup_files":                 None,
    "admin_interface_enumeration":  None,
    "api_discovery":                None,
    "http_methods":                 None,
    "hsts_testing":                 None,
    "rpc_testing":                  None,
    "file_permission":              None,
    "file_inclusion":               None,
    "subdomain_takeover":           None,
    "cloud_storage":                None,
    "csp_testing":                  None,
    "path_confusion":               None,
    "security_headers":             lambda c, tid: assert_vulnerabilities(c, tid),
}
```

Append edge-case test:

```python
async def test_config_mgmt_assets_have_type(client, pipeline_result):
    """Assert config_mgmt assets all have a non-null asset_type."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/assets",
        params={"target_id": target_id},
    )
    assert res.status_code == 200
    assets = res.json()["assets"]
    assert assets, "No assets found for config_mgmt target"
    for a in assets:
        assert a["asset_type"] is not None and a["asset_type"].strip() != "", (
            f"Asset {a['id']} ({a['asset_value']!r}) has null asset_type"
        )
```

- [ ] **Step 3: Update `test_identity_mgmt.py`**

```python
# Add assert_assets to imports
from conftest import (
    assert_assets, assert_job_completed, cleanup_target, create_target,
)

# Change LAST_STAGE assertion (account_enumeration)
STAGE_ASSERTIONS = {
    "role_definitions":    None,
    "registration_process": None,
    "account_provisioning": None,
    "account_enumeration": lambda c, tid: assert_assets(c, tid),
}
```

Append edge-case test:

```python
async def test_identity_mgmt_assets_have_value(client, pipeline_result):
    """Assert identity_mgmt assets all have non-empty asset_value."""
    target_id, _ = pipeline_result
    res = await client.get("/api/v1/assets", params={"target_id": target_id})
    assert res.status_code == 200
    assets = res.json()["assets"]
    assert assets, "No assets found for identity_mgmt target"
    for a in assets:
        assert a["asset_value"] is not None and a["asset_value"].strip() != "", (
            f"Asset {a['id']} has empty asset_value"
        )
```

- [ ] **Step 4: Add edge-case test to `test_info_gathering.py`** (imports already correct)

Append at end of file:

```python
async def test_info_gathering_asset_types_diverse(client, pipeline_result):
    """Assert info_gathering produced ≥3 distinct asset_type values (multiple tool categories ran)."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/assets",
        params={"target_id": target_id, "page_size": 500},
    )
    assert res.status_code == 200
    assets = res.json()["assets"]
    assert assets, "No assets found for info_gathering target"
    asset_types = {a["asset_type"] for a in assets if a.get("asset_type")}
    assert len(asset_types) >= 3, (
        f"Expected ≥3 distinct asset_type values; got {asset_types}"
    )
```

- [ ] **Step 5: Verify collection**

```bash
pytest tests/e2e/test_client_side.py tests/e2e/test_config_mgmt.py tests/e2e/test_identity_mgmt.py tests/e2e/test_info_gathering.py -v --collect-only
```

Expected: all new test functions collected.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/test_client_side.py tests/e2e/test_config_mgmt.py tests/e2e/test_identity_mgmt.py tests/e2e/test_info_gathering.py
git commit -m "test(e2e): add result assertions and edge-case tests for client_side/config_mgmt/identity_mgmt/info_gathering"
```

---

## Task 6: Worker result assertions — chain_worker + reporting_worker

**Files:**
- Modify: `tests/e2e/test_chain_worker.py`
- Modify: `tests/e2e/test_reporting_worker.py`

- [ ] **Step 1: Update `test_chain_worker.py`**

```python
# Add assert_chain_findings to imports
from conftest import (
    assert_chain_findings, assert_job_completed, cleanup_target, create_target,
)

# Change LAST_STAGE assertion (reporting)
STAGE_ASSERTIONS = {
    "data_collection":    None,
    "chain_evaluation":   None,
    "ai_chain_discovery": None,
    "chain_execution":    None,
    "reporting":          lambda c, tid: assert_chain_findings(c, tid),
}
```

Append edge-case test:

```python
async def test_chain_worker_findings_have_severity(client, pipeline_result):
    """Assert all chain findings have a non-null severity value."""
    target_id, _ = pipeline_result
    res = await client.get(
        "/api/v1/vulnerabilities",
        params={"target_id": target_id, "worker_type": "chain_worker"},
    )
    assert res.status_code == 200
    findings = res.json()["vulnerabilities"]
    assert findings, "No chain findings found — chain_worker did not produce results"
    for f in findings:
        assert f["severity"] is not None and f["severity"] != "", (
            f"Chain finding {f['id']} ({f['title']!r}) has null severity"
        )
```

- [ ] **Step 2: Add edge-case test to `test_reporting_worker.py`**

`reporting_worker` already has `assert_assets` on the `export` stage. Only the new edge-case test is needed.

```python
# Add assert_reports to imports (existing imports stay)
from conftest import (
    assert_assets, assert_job_completed, assert_reports,
    cleanup_target, create_target,
)
```

Append edge-case test:

```python
async def test_reporting_worker_report_downloadable(client, pipeline_result):
    """Assert all listed report files can be downloaded (HEAD returns 200)."""
    target_id, _ = pipeline_result
    reports = await assert_reports(client, target_id, min_count=1)
    for report in reports:
        filename = report["filename"]
        res = await client.head(f"/api/v1/targets/{target_id}/reports/{filename}")
        assert res.status_code == 200, (
            f"HEAD /api/v1/targets/{target_id}/reports/{filename} returned {res.status_code}"
        )
```

- [ ] **Step 3: Verify collection**

```bash
pytest tests/e2e/test_chain_worker.py tests/e2e/test_reporting_worker.py -v --collect-only
```

Expected: new test functions collected.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_chain_worker.py tests/e2e/test_reporting_worker.py
git commit -m "test(e2e): add chain_worker result assertion and reporting_worker downloadable test"
```

---

## Task 7: Infrastructure worker functional tests

**Files:**
- Modify: `tests/e2e/test_proxy.py`
- Modify: `tests/e2e/test_callback.py`
- Modify: `tests/e2e/test_sandbox_worker.py`

### Proxy

The proxy rule manager API runs on port 8081 inside the container (not exposed on the host). Tests use `docker exec` to reach it.

- [ ] **Step 1: Add proxy rule manager tests to `test_proxy.py`**

```python
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
    assert result.stdout.strip() == "running"


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
    """Rule manager REST API (port 8081 internal) returns 200 on GET /rules."""
    data = _exec_curl("/rules")
    assert isinstance(data, list), f"Expected list of rules, got: {data}"


def test_proxy_rule_manager_add_and_delete_rule():
    """Add a rule, verify it appears in list, then delete it."""
    rule_payload = json.dumps({
        "pattern": ".*example\\.com.*",
        "action": "block",
        "enabled": True,
    })
    created = _exec_curl("/rules", method="POST", data=rule_payload)
    assert "id" in created, f"Expected 'id' in created rule response: {created}"
    rule_id = created["id"]

    rules = _exec_curl("/rules")
    ids = [r["id"] for r in rules]
    assert rule_id in ids, f"Newly created rule {rule_id} not found in rule list: {ids}"

    deleted = _exec_curl(f"/rules/{rule_id}", method="DELETE")
    assert deleted.get("deleted") == rule_id or deleted.get("success") is True, (
        f"Unexpected delete response: {deleted}"
    )
```

### Callback

- [ ] **Step 2: Add callback functional tests to `test_callback.py`**

```python
"""E2E health + functional tests for callback worker (OOB interaction listener)."""
import subprocess
import pytest
import httpx

pytestmark = pytest.mark.e2e

CONTAINER = "webbh-callback"
_CALLBACK_BASE = "http://localhost:9090"


def test_callback_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "running"


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
    """Register a callback ID, poll it, record an interaction, then delete it."""
    async with httpx.AsyncClient(base_url=_CALLBACK_BASE, timeout=10.0) as client:
        # Register
        res = await client.post("/callbacks", json={"protocols": ["http", "dns"]})
        assert res.status_code == 201, f"POST /callbacks returned {res.status_code}: {res.text}"
        cb_id = res.json()["id"]
        assert cb_id, "Expected a callback ID in response"

        # Poll — should return the registered callback (no interactions yet)
        res = await client.get(f"/callbacks/{cb_id}")
        assert res.status_code == 200, f"GET /callbacks/{cb_id} returned {res.status_code}"
        cb_data = res.json()
        assert cb_data.get("id") == cb_id or "id" in cb_data

        # Record an interaction
        res = await client.post(
            f"/callbacks/{cb_id}/interaction",
            json={"protocol": "http", "source_ip": "1.2.3.4", "data": "ping"},
        )
        assert res.status_code == 200
        assert res.json().get("recorded") is True

        # Delete
        res = await client.delete(f"/callbacks/{cb_id}")
        assert res.status_code == 200
        assert res.json().get("deleted") == cb_id


async def test_callback_poll_nonexistent_returns_404():
    """Polling a non-existent callback ID returns 404."""
    async with httpx.AsyncClient(base_url=_CALLBACK_BASE, timeout=10.0) as client:
        res = await client.get("/callbacks/nonexistent-id-12345")
        assert res.status_code == 404
```

### Sandbox

- [ ] **Step 3: Add sandbox functional tests to `test_sandbox_worker.py`**

```python
"""E2E health + functional tests for sandbox_worker."""
import subprocess
import pytest

pytestmark = pytest.mark.e2e

CONTAINER = "webbh-sandbox-worker"


def test_sandbox_worker_container_running():
    result = subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "running"


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
    """POST /api/v1/sandbox/mutate returns non-empty variant list for XSS payload."""
    res = await client.post(
        "/api/v1/sandbox/mutate",
        json={"vuln_type": "xss", "base_payload": "<script>alert(1)</script>"},
    )
    assert res.status_code == 200, f"POST /api/v1/sandbox/mutate returned {res.status_code}: {res.text}"
    data = res.json()
    assert isinstance(data["variants"], list), "Expected 'variants' to be a list"
    assert len(data["variants"]) >= 1, "Expected ≥1 mutation variant"
    assert data["count"] == len(data["variants"])


async def test_sandbox_waf_fingerprint_endpoint(client):
    """POST /api/v1/sandbox/fingerprint returns a WAF profile dict."""
    res = await client.post(
        "/api/v1/sandbox/fingerprint",
        json={
            "headers": {"Server": "cloudflare"},
            "body": "error 1020",
            "status_code": 403,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "waf_profile" in data


async def test_sandbox_corpus_endpoint(client):
    """GET /api/v1/sandbox/corpus returns corpus dict with at least xss entries."""
    res = await client.get("/api/v1/sandbox/corpus", params={"vuln_type": "xss"})
    assert res.status_code == 200
    data = res.json()
    assert "corpus" in data
    assert len(data["corpus"]) >= 1, "Expected at least one corpus entry for vuln_type=xss"
```

- [ ] **Step 4: Verify collection**

```bash
pytest tests/e2e/test_proxy.py tests/e2e/test_callback.py tests/e2e/test_sandbox_worker.py -v --collect-only
```

Expected: all new functions collected.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/test_proxy.py tests/e2e/test_callback.py tests/e2e/test_sandbox_worker.py
git commit -m "test(e2e): add functional/HTTP tests for proxy, callback, and sandbox_worker"
```

---

## Task 8: Orchestrator API — control plane tests

**Files:**
- Create: `tests/e2e/test_orchestrator_api.py`

- [ ] **Step 1: Create `tests/e2e/test_orchestrator_api.py` with boilerplate and control plane tests**

```python
"""E2E tests for orchestrator API surface — control plane, data APIs, edge cases.

Each class manages its own target lifecycle. Tests use scope="function" to
guarantee cleanup even on failure. The single-active-target enforcement means
each test must kill/delete before the next one creates.
"""
from __future__ import annotations

import asyncio
import json
import time
import subprocess

import httpx
import pytest

from conftest import (
    _BASE_URL, _read_api_key,
    assert_assets, assert_vulnerabilities,
    cleanup_target, create_target,
    seed_asset, seed_vulnerability,
    wait_for_worker_status,
)

pytestmark = pytest.mark.e2e


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------

class TestControlPlane:
    """Tests for kill, control, rescan, clean-slate, delete endpoints."""

    @pytest.fixture(autouse=True)
    async def _teardown(self, client):
        """Kill all active jobs and delete any orphaned targets after each test."""
        yield
        await client.post("/api/v1/kill")
        res = await client.get("/api/v1/targets")
        for t in res.json().get("targets", []):
            await client.delete(f"/api/v1/targets/{t['id']}")

    async def test_kill_all_marks_jobs_killed(self, client):
        """POST /api/v1/kill transitions all active jobs to KILLED status."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Kill-Test", worker="info_gathering")

        # Wait until at least one job is QUEUED or RUNNING
        await wait_for_worker_status(client, target_id, "info_gathering", {"QUEUED", "RUNNING"}, timeout=60)

        res = await client.post("/api/v1/kill")
        assert res.status_code == 200
        data = res.json()
        assert data["killed_count"] >= 1
        assert "info_gathering" in data["containers"]

        # All jobs must now be KILLED
        status_res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = status_res.json()["jobs"]
        active = [j for j in jobs if j["status"] not in ("KILLED", "COMPLETED", "STOPPED")]
        assert active == [], f"Unexpected non-killed jobs: {active}"

    async def test_control_invalid_container_rejected(self, client):
        """POST /api/v1/control with container not starting with 'webbh-' returns 400."""
        res = await client.post("/api/v1/control", json={
            "container_name": "not-webbh-anything",
            "action": "pause",
        })
        assert res.status_code == 400

    async def test_control_unknown_action_rejected(self, client):
        """POST /api/v1/control with unknown action returns 400."""
        res = await client.post("/api/v1/control", json={
            "container_name": "webbh-info_gathering",
            "action": "explode",
        })
        assert res.status_code == 400

    async def test_rescan_queues_snapshot(self, client):
        """POST /api/v1/targets/{id}/rescan returns 201 and creates scan_number=1."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Rescan-Test", worker="info_gathering")

        # Let info_gathering complete so assets exist for snapshotting
        await wait_for_worker_status(client, target_id, "info_gathering", {"COMPLETED"}, timeout=600)

        await client.post("/api/v1/kill")
        res = await client.post(f"/api/v1/targets/{target_id}/rescan")
        assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
        data = res.json()
        assert data["scan_number"] == 1
        assert data["status"] == "queued"

    async def test_clean_slate_wipes_data(self, client):
        """POST /api/v1/targets/{id}/clean-slate removes all assets and jobs."""
        target_id = await create_target(client, "e2e_info_gathering", "API-CleanSlate", worker="info_gathering")
        # Seed data directly so we don't need to wait for the pipeline
        await seed_asset(target_id)

        assets_before = (await client.get("/api/v1/assets", params={"target_id": target_id})).json()["total"]
        assert assets_before >= 1

        await client.post("/api/v1/kill")
        res = await client.post(f"/api/v1/targets/{target_id}/clean-slate")
        assert res.status_code == 200
        assert res.json()["success"] is True

        assets_after = (await client.get("/api/v1/assets", params={"target_id": target_id})).json()["total"]
        assert assets_after == 0, f"Expected 0 assets after clean-slate, got {assets_after}"

        jobs_after = (await client.get("/api/v1/status", params={"target_id": target_id})).json()["jobs"]
        assert jobs_after == [], f"Expected no jobs after clean-slate, got {jobs_after}"

    async def test_delete_target_removes_it(self, client):
        """DELETE /api/v1/targets/{id} removes target from list."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Delete-Test")
        await client.post("/api/v1/kill")

        res = await client.delete(f"/api/v1/targets/{target_id}")
        assert res.status_code == 200
        assert res.json()["success"] is True

        targets = (await client.get("/api/v1/targets")).json()["targets"]
        ids = [t["id"] for t in targets]
        assert target_id not in ids, f"Target {target_id} still in list after delete"

    async def test_health_endpoint(self, client):
        """GET /health returns 200 with status=ok."""
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    async def test_target_create_empty_company_name_rejected(self, client):
        """POST /api/v1/targets with empty company_name returns 422."""
        res = await client.post("/api/v1/targets", json={
            "company_name": "",
            "base_domain": "testphp.vulnweb.com",
        })
        assert res.status_code == 422, f"Expected 422, got {res.status_code}"

    async def test_target_create_short_domain_rejected(self, client):
        """POST /api/v1/targets with base_domain too short (< 3 chars) returns 422."""
        res = await client.post("/api/v1/targets", json={
            "company_name": "Test Corp",
            "base_domain": "x",
        })
        assert res.status_code == 422, f"Expected 422, got {res.status_code}"
```

- [ ] **Step 2: Verify collection of control plane tests**

```bash
pytest tests/e2e/test_orchestrator_api.py::TestControlPlane -v --collect-only
```

Expected: 8 test functions collected.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_orchestrator_api.py
git commit -m "test(e2e): add orchestrator API control plane tests"
```

---

## Task 9: Orchestrator API — data API tests

**Files:**
- Modify: `tests/e2e/test_orchestrator_api.py` (append `TestDataAPIs` class)

- [ ] **Step 1: Append `TestDataAPIs` class to `test_orchestrator_api.py`**

```python
# ---------------------------------------------------------------------------
# Data APIs
# ---------------------------------------------------------------------------

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
        target_id = await create_target(client, "e2e_info_gathering", "API-Bounty-Test")
        vuln = await seed_vulnerability(target_id)
        await client.post("/api/v1/kill")

        # Create
        res = await client.post("/api/v1/bounties", json={
            "target_id": target_id,
            "vulnerability_id": vuln["id"],
            "platform": "hackerone",
            "status": "submitted",
            "expected_payout": 500.0,
        })
        assert res.status_code == 201, f"POST /api/v1/bounties returned {res.status_code}: {res.text}"
        bounty_id = res.json()["id"]

        # List
        res = await client.get("/api/v1/bounties", params={"target_id": target_id})
        assert res.status_code == 200
        bounties = res.json()
        assert any(b["id"] == bounty_id for b in bounties), f"Bounty {bounty_id} not in list"

        # Update
        res = await client.patch(f"/api/v1/bounties/{bounty_id}", json={
            "status": "triaged",
            "actual_payout": 350.0,
        })
        assert res.status_code == 200
        assert res.json()["status"] == "triaged"

    async def test_bounty_stats_returns_roi(self, client):
        """GET /api/v1/bounties/stats returns a stats dict with at least one key."""
        res = await client.get("/api/v1/bounties/stats")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, dict) and len(data) >= 1, f"Expected stats dict, got: {data}"

    async def test_campaign_crud(self, client):
        """POST → GET → PATCH lifecycle for campaigns."""
        res = await client.post("/api/v1/campaigns", json={
            "name": "E2E Test Campaign",
            "description": "Created by e2e test",
            "rate_limit": 20,
        })
        assert res.status_code == 201
        campaign_id = res.json()["id"]

        # GET single
        res = await client.get(f"/api/v1/campaigns/{campaign_id}")
        assert res.status_code == 200
        assert res.json()["name"] == "E2E Test Campaign"

        # PATCH
        res = await client.patch(f"/api/v1/campaigns/{campaign_id}", json={"name": "Updated Campaign"})
        assert res.status_code == 200
        assert res.json()["name"] == "Updated Campaign"

        # Appears in list
        campaigns = (await client.get("/api/v1/campaigns")).json()
        ids = [c["id"] for c in campaigns]
        assert campaign_id in ids

    async def test_campaign_not_found_returns_404(self, client):
        """GET /api/v1/campaigns/999999 returns 404."""
        res = await client.get("/api/v1/campaigns/999999")
        assert res.status_code == 404

    async def test_search_finds_seeded_asset(self, client):
        """GET /api/v1/search finds an asset by its value."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Search-Test")
        asset = await seed_asset(target_id)
        await client.post("/api/v1/kill")

        # The asset value is "http://testphp.vulnweb.com/seeded-{target_id}"
        search_term = f"seeded-{target_id}"
        res = await client.get("/api/v1/search", params={"target_id": target_id, "q": search_term})
        assert res.status_code == 200
        results = res.json()["results"]
        asset_results = [r for r in results if r["type"] == "asset"]
        assert len(asset_results) >= 1, f"Expected asset result for q={search_term!r}"

    async def test_attack_graph_returns_nodes(self, client):
        """GET /api/v1/targets/{id}/graph returns nodes including a target node."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Graph-Test")
        await seed_asset(target_id)
        await client.post("/api/v1/kill")

        res = await client.get(f"/api/v1/targets/{target_id}/graph")
        assert res.status_code == 200
        data = res.json()
        assert len(data["nodes"]) >= 1, "Expected ≥1 node in attack graph"
        target_nodes = [n for n in data["nodes"] if n["type"] == "target"]
        assert len(target_nodes) == 1, "Expected exactly one target node"

    async def test_vuln_draft_report_hackerone(self, client):
        """GET /api/v1/vulnerabilities/{id}/draft returns non-empty draft markdown."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Draft-Test")
        asset = await seed_asset(target_id)
        vuln = await seed_vulnerability(target_id, asset_id=asset["id"])
        await client.post("/api/v1/kill")

        res = await client.get(
            f"/api/v1/vulnerabilities/{vuln['id']}/draft",
            params={"platform": "hackerone"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data.get("draft") and len(data["draft"].strip()) > 10, (
            f"Expected non-empty draft, got: {data.get('draft')!r}"
        )

    async def test_playbook_list_includes_wide_recon(self, client):
        """GET /api/v1/playbooks returns list including 'wide_recon'."""
        res = await client.get("/api/v1/playbooks")
        assert res.status_code == 200
        names = [p.get("name") for p in res.json()]
        assert "wide_recon" in names, f"'wide_recon' not in playbook list: {names}"

    async def test_unknown_playbook_rejected_on_target_create(self, client):
        """POST /api/v1/targets with unknown playbook name is rejected."""
        res = await client.post("/api/v1/targets", json={
            "company_name": "Test Corp",
            "base_domain": "testphp.vulnweb.com",
            "playbook": "nonexistent_playbook_xyz",
        })
        # Either 400 (bad request) or 422 (validation error) — not 201
        assert res.status_code in (400, 422, 404), (
            f"Expected rejection of unknown playbook, got {res.status_code}"
        )

    async def test_scheduled_scan_crud(self, client):
        """POST → GET → PATCH lifecycle for scheduled scans."""
        target_id = await create_target(client, "e2e_info_gathering", "API-Schedule-Test")
        await client.post("/api/v1/kill")

        res = await client.post("/api/v1/schedules", json={
            "target_id": target_id,
            "cron_expression": "0 * * * *",
            "playbook": "wide_recon",
        })
        assert res.status_code == 201, f"POST /api/v1/schedules returned {res.status_code}: {res.text}"
        schedule_id = res.json()["id"]

        # List
        res = await client.get("/api/v1/schedules", params={"target_id": target_id})
        assert res.status_code == 200
        schedule_ids = [s["id"] for s in res.json()]
        assert schedule_id in schedule_ids

        # Disable
        res = await client.patch(f"/api/v1/schedules/{schedule_id}", json={"enabled": False})
        assert res.status_code == 200

    async def test_queue_health_returns_all_queues(self, client):
        """GET /api/v1/queue_health returns health info for known queues."""
        res = await client.get("/api/v1/queue_health")
        assert res.status_code == 200
        queues = res.json()["queues"]
        assert "info_gathering_queue" in queues
        assert "chain_worker_queue" in queues
        assert "reporting_worker_queue" in queues
        for name, info in queues.items():
            assert "pending" in info and "health" in info, (
                f"Queue {name} missing pending/health fields: {info}"
            )
```

- [ ] **Step 2: Verify collection**

```bash
pytest tests/e2e/test_orchestrator_api.py::TestDataAPIs -v --collect-only
```

Expected: 11 test functions collected.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_orchestrator_api.py
git commit -m "test(e2e): add orchestrator data API tests (bounties, campaigns, search, attack graph, playbooks, schedules)"
```

---

## Task 10: Orchestrator API — edge cases, auth, metrics, resource guard

**Files:**
- Modify: `tests/e2e/test_orchestrator_api.py` (append `TestEdgeCases` class)

- [ ] **Step 1: Append `TestEdgeCases` class to `test_orchestrator_api.py`**

```python
# ---------------------------------------------------------------------------
# Edge cases, auth, metrics, resource guard
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Auth rejection, rate limiting, SSE reconnect, metrics, resource guard."""

    @pytest.fixture(autouse=True)
    async def _teardown(self, client):
        yield
        await client.post("/api/v1/kill")
        res = await client.get("/api/v1/targets")
        for t in res.json().get("targets", []):
            await client.delete(f"/api/v1/targets/{t['id']}")

    async def test_missing_api_key_returns_401(self):
        """GET /api/v1/targets without X-API-KEY header returns 401."""
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=10.0) as anon:
            res = await anon.get("/api/v1/targets")
        assert res.status_code == 401, (
            f"Expected 401 for missing API key, got {res.status_code}. "
            "Is the API key middleware from Task 1 deployed?"
        )

    async def test_wrong_api_key_returns_401(self):
        """GET /api/v1/targets with wrong X-API-KEY returns 401."""
        async with httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={"X-API-KEY": "totally-bogus-key-xyz"},
            timeout=10.0,
        ) as bad_client:
            res = await bad_client.get("/api/v1/targets")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    async def test_health_endpoint_no_auth_required(self):
        """GET /health returns 200 even without X-API-KEY (unprotected path)."""
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=10.0) as anon:
            res = await anon.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    async def test_correlation_id_echoed_in_response(self, client):
        """X-Correlation-ID sent in request is echoed back in response headers."""
        res = await client.get(
            "/api/v1/targets",
            headers={"X-Correlation-ID": "trace-abc123"},
        )
        assert res.status_code == 200
        assert res.headers.get("x-correlation-id") == "trace-abc123", (
            f"Expected X-Correlation-ID=trace-abc123 in response, got: {dict(res.headers)}"
        )

    async def test_rate_limiter_triggers_429_on_burst(self, client):
        """Sending >200 rapid GET requests to /api/v1/status triggers 429."""
        # The GET rate limit is 200 requests per 60s window (RATE_LIMIT_READ env var).
        # We send 220 concurrent requests and assert at least one 429.
        tasks = [
            client.get("/api/v1/status")
            for _ in range(220)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        statuses = [
            r.status_code for r in responses
            if isinstance(r, httpx.Response)
        ]
        assert 429 in statuses, (
            f"Expected at least one 429 in {len(statuses)} responses. "
            f"Status distribution: {set(statuses)}"
        )

    async def test_sse_last_event_id_replay(self, client):
        """SSE reconnect with Last-Event-ID replays missed events."""
        target_id = await create_target(client, "e2e_info_gathering", "API-SSE-Test", worker="info_gathering")

        # Collect 3 events from the stream
        collected_ids: list[str] = []
        api_key = _read_api_key()

        async with httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={"X-API-KEY": api_key},
            timeout=httpx.Timeout(None),
        ) as stream_client:
            async with stream_client.stream("GET", f"/api/v1/stream/{target_id}") as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("id: "):
                        collected_ids.append(line[4:].strip())
                    if len(collected_ids) >= 3:
                        break

        if len(collected_ids) < 2:
            pytest.skip("Not enough SSE events collected to test replay")

        # Reconnect with Last-Event-ID = second-to-last event ID
        replay_from = collected_ids[-2]
        replayed_ids: list[str] = []

        async with httpx.AsyncClient(
            base_url=_BASE_URL,
            headers={"X-API-KEY": api_key, "Last-Event-ID": replay_from},
            timeout=httpx.Timeout(10.0),
        ) as reconnect_client:
            try:
                async with reconnect_client.stream("GET", f"/api/v1/stream/{target_id}") as resp:
                    async for line in resp.aiter_lines():
                        if line.startswith("id: "):
                            replayed_ids.append(line[4:].strip())
                        if len(replayed_ids) >= 2:
                            break
            except httpx.ReadTimeout:
                pass

        # The last event ID (collected_ids[-1]) must appear in replayed events
        assert collected_ids[-1] in replayed_ids, (
            f"Expected event {collected_ids[-1]} to be replayed after Last-Event-ID={replay_from}. "
            f"Got replayed IDs: {replayed_ids}"
        )

    async def test_metrics_endpoint_prometheus_format(self):
        """GET /metrics returns valid Prometheus text with expected metric names."""
        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=10.0) as anon:
            res = await anon.get("/metrics")
        assert res.status_code == 200
        assert "text/plain" in res.headers.get("content-type", ""), (
            f"Expected text/plain Content-Type, got: {res.headers.get('content-type')}"
        )
        body = res.text
        assert "api_latency_seconds" in body, "Expected 'api_latency_seconds' metric in /metrics"
        assert "targets_created_total" in body, "Expected 'targets_created_total' metric in /metrics"

    async def test_resource_status_returns_tier(self, client):
        """GET /api/v1/resources/status returns current tier and thresholds."""
        res = await client.get("/api/v1/resources/status")
        assert res.status_code == 200
        data = res.json()
        assert data["tier"] in {"normal", "high", "critical"}, (
            f"Unexpected tier: {data['tier']}"
        )
        assert isinstance(data["thresholds"], dict) and len(data["thresholds"]) >= 1

    async def test_resource_override_then_clear(self, client):
        """POST /api/v1/resources/override sets tier; posting without tier clears it."""
        # Set override
        res = await client.post("/api/v1/resources/override", json={"tier": "critical"})
        assert res.status_code == 200
        assert res.json()["override"] == "critical"

        status = (await client.get("/api/v1/resources/status")).json()
        assert status["tier"] == "critical"

        # Clear override
        res = await client.post("/api/v1/resources/override", json={})
        assert res.status_code == 200

        status_after = (await client.get("/api/v1/resources/status")).json()
        assert status_after["tier"] != "critical", (
            "Expected tier to revert from 'critical' after clearing override"
        )
```

- [ ] **Step 2: Verify collection**

```bash
pytest tests/e2e/test_orchestrator_api.py::TestEdgeCases -v --collect-only
```

Expected: 9 test functions collected.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_orchestrator_api.py
git commit -m "test(e2e): add orchestrator edge-case tests (auth, rate limit, SSE replay, metrics, resource guard)"
```

---

## Task 11: Event engine dispatch tests

**Files:**
- Create: `tests/e2e/test_event_engine.py`

- [ ] **Step 1: Create `tests/e2e/test_event_engine.py`**

```python
"""E2E tests for event engine dispatch logic.

These tests observe which workers get dispatched (via GET /api/v1/status)
to verify dependency ordering and credential-gating without mocking.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from conftest import (
    _REPO_ROOT, _read_api_key,
    cleanup_target, create_target,
    wait_for_worker_status,
)

pytestmark = pytest.mark.e2e

_CREDENTIAL_GATED = {"identity_mgmt", "authentication", "authorization", "session_mgmt", "input_validation"}
_CHAIN_PREREQUISITES = {"input_validation", "error_handling", "cryptography", "business_logic", "client_side"}


@pytest.fixture(scope="module")
async def client(stack):
    import httpx
    async with httpx.AsyncClient(
        base_url="http://localhost:8001",
        headers={"X-API-KEY": _read_api_key(), "Content-Type": "application/json"},
        timeout=30.0,
    ) as c:
        yield c


async def _kill_and_delete_all(client):
    await client.post("/api/v1/kill")
    res = await client.get("/api/v1/targets")
    for t in res.json().get("targets", []):
        await client.delete(f"/api/v1/targets/{t['id']}")


async def _poll_dispatched_workers(client, target_id: int, wait_seconds: int = 30) -> set[str]:
    """Return set of worker container_names that appeared in job list within wait_seconds."""
    deadline = time.monotonic() + wait_seconds
    seen: set[str] = set()
    while time.monotonic() < deadline:
        res = await client.get("/api/v1/status", params={"target_id": target_id})
        jobs = res.json().get("jobs", [])
        seen.update(j["container_name"] for j in jobs)
        await asyncio.sleep(2)
    return seen


async def test_no_credentials_skips_credential_gated_workers(client):
    """Without credentials.json, CREDENTIAL_REQUIRED workers are never dispatched."""
    await _kill_and_delete_all(client)

    # Create target WITHOUT writing credentials.json (do not call _write_stub_credentials)
    res = await client.post("/api/v1/targets", json={
        "company_name": "EE-NoCreds",
        "base_domain": "testphp.vulnweb.com",
        "playbook": "wide_recon",
    })
    assert res.status_code == 201
    target_id = res.json()["target_id"]

    try:
        dispatched = await _poll_dispatched_workers(client, target_id, wait_seconds=30)
        gated_and_dispatched = dispatched & _CREDENTIAL_GATED
        assert gated_and_dispatched == set(), (
            f"Expected credential-gated workers to be skipped, but these were dispatched: "
            f"{gated_and_dispatched}"
        )
        assert "info_gathering" in dispatched, (
            f"Expected info_gathering to be dispatched; got: {dispatched}"
        )
    finally:
        await _kill_and_delete_all(client)


async def test_with_credentials_dispatches_auth_workers(client):
    """With credentials.json present, identity_mgmt is dispatched after info_gathering."""
    await _kill_and_delete_all(client)

    res = await client.post("/api/v1/targets", json={
        "company_name": "EE-WithCreds",
        "base_domain": "testphp.vulnweb.com",
        "playbook": "wide_recon",
    })
    assert res.status_code == 201
    target_id = res.json()["target_id"]

    # Write credentials so credential-gated workers are unlocked
    config_dir = _REPO_ROOT / "shared" / "config" / str(target_id)
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "credentials.json").write_text(
        json.dumps({"tester": None, "testing_user": None})
    )

    try:
        # Wait for info_gathering to complete (identity_mgmt depends on config_mgmt which depends on it)
        await wait_for_worker_status(client, target_id, "info_gathering", {"COMPLETED"}, timeout=600)

        # After info_gathering completes, config_mgmt should eventually be dispatched
        dispatched = await _poll_dispatched_workers(client, target_id, wait_seconds=60)
        assert "config_mgmt" in dispatched or "identity_mgmt" in dispatched, (
            f"Expected config_mgmt or identity_mgmt to be dispatched; got: {dispatched}"
        )
    finally:
        await _kill_and_delete_all(client)


async def test_dependency_config_mgmt_waits_for_info_gathering(client):
    """config_mgmt is never QUEUED before info_gathering is COMPLETED."""
    await _kill_and_delete_all(client)

    res = await client.post("/api/v1/targets", json={
        "company_name": "EE-DepOrder",
        "base_domain": "testphp.vulnweb.com",
        "playbook": "wide_recon",
    })
    assert res.status_code == 201
    target_id = res.json()["target_id"]

    violation_found = False
    deadline = time.monotonic() + 300
    try:
        while time.monotonic() < deadline:
            res = await client.get("/api/v1/status", params={"target_id": target_id})
            jobs = {j["container_name"]: j["status"] for j in res.json().get("jobs", [])}

            config_active = jobs.get("config_mgmt") in {"QUEUED", "RUNNING"}
            info_done = jobs.get("info_gathering") == "COMPLETED"

            if config_active and not info_done:
                violation_found = True
                break

            if jobs.get("config_mgmt") in {"COMPLETED", "SKIPPED"}:
                break

            await asyncio.sleep(5)
    finally:
        await _kill_and_delete_all(client)

    assert not violation_found, (
        "config_mgmt was QUEUED/RUNNING before info_gathering was COMPLETED — dependency ordering broken"
    )


async def test_disabled_worker_never_dispatched(client):
    """A worker disabled in the playbook is never dispatched."""
    await _kill_and_delete_all(client)

    # Use the e2e_info_gathering playbook (only enables info_gathering — others are implicitly absent)
    res = await client.post("/api/v1/targets", json={
        "company_name": "EE-Disabled",
        "base_domain": "testphp.vulnweb.com",
        "playbook": "e2e_info_gathering",
    })
    assert res.status_code == 201
    target_id = res.json()["target_id"]

    try:
        await wait_for_worker_status(client, target_id, "info_gathering", {"COMPLETED"}, timeout=600)
        dispatched = await _poll_dispatched_workers(client, target_id, wait_seconds=30)
        # chain_worker should NOT be dispatched because its prerequisites never ran
        assert "chain_worker" not in dispatched, (
            f"chain_worker was dispatched even though its prerequisites didn't run: {dispatched}"
        )
    finally:
        await _kill_and_delete_all(client)


async def test_event_engine_resumes_after_kill(client):
    """After POST /api/v1/kill, the event engine resumes dispatching for a new target."""
    await _kill_and_delete_all(client)

    # Start target A
    res = await client.post("/api/v1/targets", json={
        "company_name": "EE-TargetA",
        "base_domain": "testphp.vulnweb.com",
        "playbook": "e2e_info_gathering",
    })
    assert res.status_code == 201
    target_a = res.json()["target_id"]

    await wait_for_worker_status(client, target_a, "info_gathering", {"QUEUED", "RUNNING"}, timeout=60)
    await client.post("/api/v1/kill")
    await asyncio.sleep(3)

    # Delete target A and create target B
    await client.delete(f"/api/v1/targets/{target_a}")
    res = await client.post("/api/v1/targets", json={
        "company_name": "EE-TargetB",
        "base_domain": "testphp.vulnweb.com",
        "playbook": "e2e_info_gathering",
    })
    assert res.status_code == 201
    target_b = res.json()["target_id"]

    try:
        # The event engine should resume and dispatch info_gathering for target B
        status = await wait_for_worker_status(
            client, target_b, "info_gathering", {"QUEUED", "RUNNING", "COMPLETED"}, timeout=60
        )
        assert status in {"QUEUED", "RUNNING", "COMPLETED"}, (
            f"Event engine did not resume dispatching after kill; status={status}"
        )
    finally:
        await _kill_and_delete_all(client)
```

- [ ] **Step 2: Verify collection**

```bash
pytest tests/e2e/test_event_engine.py -v --collect-only
```

Expected: 5 test functions collected.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_event_engine.py
git commit -m "test(e2e): add event engine dispatch ordering and credential-gating tests"
```

---

## Self-Review

### Spec coverage check

| Spec requirement | Task covering it |
|---|---|
| Worker result assertions (13 workers) | Tasks 3–6 |
| info_gathering edge-case (asset_types_diverse) | Task 5 |
| authentication: vuln severity check | Task 3 |
| authorization: vuln description check | Task 3 |
| session_mgmt: source_tool check | Task 3 |
| input_validation: vuln_types_diverse | Task 4 |
| error_handling: poc field check | Task 4 |
| cryptography: severity set | Task 4 |
| business_logic: confirmed field | Task 4 |
| client_side: source_tool check | Task 5 |
| config_mgmt: asset_type populated | Task 5 |
| identity_mgmt: asset_value check | Task 5 |
| chain_worker: findings have severity | Task 6 |
| reporting_worker: report downloadable | Task 6 |
| Proxy: rule manager API tests | Task 7 |
| Callback: register/poll/delete lifecycle | Task 7 |
| Sandbox: mutate + WAF fingerprint + corpus | Task 7 |
| kill_all marks KILLED | Task 8 |
| control plane: invalid container / unknown action | Task 8 |
| rescan creates snapshot | Task 8 |
| clean_slate wipes data | Task 8 |
| delete target | Task 8 |
| health endpoint | Task 8 |
| target create validation (empty name, short domain) | Task 8 |
| bounty CRUD lifecycle | Task 9 |
| bounty stats | Task 9 |
| campaign CRUD | Task 9 |
| search finds asset | Task 9 |
| attack graph nodes | Task 9 |
| vuln draft report | Task 9 |
| playbook list | Task 9 |
| scheduled scan CRUD | Task 9 |
| queue health | Task 9 |
| missing API key → 401 | Tasks 1 + 10 |
| wrong API key → 401 | Task 10 |
| health no auth required | Task 10 |
| correlation ID echoed | Task 10 |
| rate limiter → 429 | Task 10 |
| SSE Last-Event-ID replay | Task 10 |
| Prometheus /metrics | Task 10 |
| resource guard status + override | Task 10 |
| no-creds skips gated workers | Task 11 |
| creds enables auth workers | Task 11 |
| dependency ordering enforced | Task 11 |
| disabled worker not dispatched | Task 11 |
| engine resumes after kill | Task 11 |

All 44 spec requirements are covered. ✓

### Placeholder scan

No TBD, TODO, or "similar to" references present. All code blocks are complete. ✓

### Type consistency

- `seed_vulnerability(target_id)` → `dict` with keys `id`, `title`, `severity`, `target_id` — used correctly in Tasks 9 and 10.
- `seed_asset(target_id)` → `dict` with keys `id`, `asset_value`, `target_id` — used correctly in Tasks 9 and 10.
- `wait_for_worker_status(client, target_id, worker, expected_statuses, ...)` → `str` — used correctly in Tasks 8 and 11.
- `assert_chain_findings(client, target_id)` → `list` — used in Task 6.
- `assert_reports(client, target_id)` → `list` — used in Task 6. ✓
