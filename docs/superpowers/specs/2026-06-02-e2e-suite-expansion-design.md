# E2E Suite Expansion — Design Spec

**Date:** 2026-06-02  
**Scope:** Backend pytest e2e tests (`tests/e2e/`) — worker result assertions, orchestrator API coverage, event engine dispatch logic, and infrastructure worker functional/HTTP probes.

---

## Background

The existing e2e suite verifies that each worker's pipeline stages fire in order and that container logs are clean. It does **not** verify:

- That workers actually wrote findings (assets, vulnerabilities, chain findings) to the database
- That the orchestrator's ~40 API endpoints behave correctly
- That the event engine enforces dependency ordering and credential-gating
- That the three infrastructure workers (proxy, callback, sandbox) are functionally operable

This spec defines the additions to close those gaps. Frontend Playwright tests are already broad and are out of scope for this expansion.

---

## Approach

**Option A** (chosen): extend existing `test_<worker>.py` files in-place; add two new modules (`test_orchestrator_api.py`, `test_event_engine.py`); upgrade three infra worker tests in-place. No directory restructure.

---

## Section 1 — Worker Result Assertions

### Principle

Add a result-assertion callable to the `LAST_STAGE` entry in `STAGE_ASSERTIONS` for every worker that currently has `None` there. Additionally, add one or two new test functions per worker to cover edge cases that stage-completion alone cannot catch.

### Per-worker changes

| Worker | `LAST_STAGE` assertion | New edge-case test(s) |
|---|---|---|
| `info_gathering` | Already has `assert_assets` | `test_info_gathering_asset_types_diverse` — assert ≥3 distinct `asset_type` values (proves multiple tool categories ran) |
| `authentication` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_authentication_vuln_severity_set` — assert every vuln row has a non-null `severity` field |
| `authorization` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_authorization_vuln_has_description` — assert every vuln has a non-empty `description` |
| `session_mgmt` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_session_mgmt_no_duplicate_findings` — re-run pipeline on same target, assert vuln count does not double |
| `input_validation` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_input_validation_vuln_types_diverse` — assert ≥2 distinct `vuln_type` values |
| `error_handling` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_error_handling_no_duplicate_findings` |
| `cryptography` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_cryptography_vuln_severity_set` |
| `business_logic` | `assert_vulnerabilities(c, tid, min_count=1)` | `test_business_logic_no_duplicate_findings` |
| `client_side` | `assert_assets(c, tid, min_count=1)` | `test_client_side_asset_has_source_tool` — assert every asset has non-null `source_tool` |
| `config_mgmt` | `assert_assets(c, tid, min_count=1)` | `test_config_mgmt_no_duplicate_findings` |
| `identity_mgmt` | `assert_assets(c, tid, min_count=1)` | `test_identity_mgmt_asset_type_populated` — assert at least one asset has `asset_type` in expected set |
| `chain_worker` | assert ≥1 `chain_findings` row via GET `/api/v1/chain_findings?target_id={id}` (or direct DB query) | `test_chain_worker_findings_have_severity` — assert all chain findings have non-null `severity` |
| `reasoning_worker` | Stage completion only (no direct DB write expected) | — |
| `reporting_worker` | Assert `GET /api/v1/targets/{id}/reports` returns ≥1 file | `test_reporting_worker_report_downloadable` — HEAD each listed file URL, assert 200 |

### Idempotency pattern

For the `no_duplicate_findings` tests: use the same `pipeline_result` fixture (no second pipeline run needed). Instead, record the vuln/asset count after the first run, call a no-op (GET status), then re-check — a second run would require a separate fixture so skip that complexity. Instead, assert that vuln count equals the count returned by the pipeline fixture (i.e., the pipeline wrote deterministically once, not twice).

A deeper idempotency test (run the same target twice) is deferred to a future spec because it conflicts with the single-active-target enforcement.

---

## Section 2 — Orchestrator API Tests (`tests/e2e/test_orchestrator_api.py`)

New module using `scope="function"` fixtures (each test class manages its own target lifecycle to avoid 409 conflicts).

### 2a — Control Plane

```
TestControlPlane:
  test_kill_all_marks_jobs_killed
    - Create target, wait for ≥1 QUEUED job
    - POST /api/v1/kill
    - Assert response: killed_count ≥ 1
    - Assert GET /api/v1/status all jobs → KILLED

  test_control_pause_unpause
    - Create target, wait for RUNNING job
    - POST /api/v1/control {container_name: "webbh-info_gathering", action: "pause"}
    - Assert job status → PAUSED
    - POST /api/v1/control {action: "unpause"}
    - Assert job status → RUNNING

  test_control_invalid_container_rejected
    - POST /api/v1/control {container_name: "not-webbh-anything", action: "pause"}
    - Assert 400

  test_control_unknown_action_rejected
    - POST /api/v1/control {container_name: "webbh-info_gathering", action: "explode"}
    - Assert 400

  test_rescan_queues_snapshot
    - Create target, run info_gathering to completion
    - POST /api/v1/targets/{id}/rescan
    - Assert 201, body.scan_number == 1
    - GET /api/v1/status, assert info_gathering job reappears with status QUEUED

  test_clean_slate_wipes_data
    - Create target, run info_gathering to completion, assert assets > 0
    - POST /api/v1/targets/{id}/clean-slate
    - Assert 200
    - GET /api/v1/assets?target_id={id}, assert total == 0
    - GET /api/v1/status?target_id={id}, assert no jobs

  test_delete_target_removes_config
    - Create target
    - DELETE /api/v1/targets/{id}
    - Assert 200, body.success == true
    - GET /api/v1/targets, assert id not in list
```

### 2b — Data APIs

```
TestDataAPIs:
  test_bounty_crud_lifecycle
    - Create target + vulnerability (seed via direct DB insert or run a worker)
    - POST /api/v1/bounties {target_id, vulnerability_id, platform: "hackerone", status: "submitted"}
    - Assert 201, body.id present
    - GET /api/v1/bounties?target_id={id}, assert ≥1 bounty
    - PATCH /api/v1/bounties/{bounty_id} {status: "triaged"}
    - Assert 200, body.status == "triaged"

  test_bounty_stats_returns_roi
    - Create 2 bounties with actual_payout values
    - GET /api/v1/bounties/stats
    - Assert response has total_earned ≥ sum of payouts

  test_campaign_crud
    - POST /api/v1/campaigns {name: "Test Campaign", rate_limit: 20}
    - Assert 201, body.id present
    - GET /api/v1/campaigns/{id}, assert name matches
    - PATCH /api/v1/campaigns/{id} {name: "Updated Campaign"}
    - Assert 200, body.name == "Updated Campaign"
    - GET /api/v1/campaigns, assert campaign appears in list

  test_search_finds_asset
    - Create target, run info_gathering (or seed asset via API)
    - GET /api/v1/search?target_id={id}&q=<known_asset_value>
    - Assert results non-empty, result.type == "asset"

  test_attack_graph_has_nodes_and_edges
    - Create target, run info_gathering to completion
    - GET /api/v1/targets/{id}/graph
    - Assert nodes non-empty, edges non-empty
    - Assert one node has type == "target"

  test_vuln_draft_report_hackerone
    - Create target + vulnerability
    - GET /api/v1/vulnerabilities/{vuln_id}/draft?platform=hackerone
    - Assert 200, body.draft is non-empty string

  test_playbook_list_includes_builtins
    - GET /api/v1/playbooks
    - Assert 200, body list includes "wide_recon"
    - POST /api/v1/targets with playbook="nonexistent_playbook", assert 4xx

  test_scheduled_scan_crud
    - Create target
    - POST /api/v1/schedules {target_id, cron_expression: "0 * * * *", playbook: "wide_recon"}
    - Assert 201
    - GET /api/v1/schedules?target_id={id}, assert ≥1
    - PATCH /api/v1/schedules/{id} {enabled: false}
    - Assert 200
```

### 2c — Edge Cases, Auth, Metrics

```
TestEdgeCases:
  test_missing_api_key_returns_401
    - GET /api/v1/targets (no X-API-KEY header)
    - Assert 401 or 403

  test_wrong_api_key_returns_401
    - GET /api/v1/targets (X-API-KEY: "totally-bogus")
    - Assert 401 or 403

  test_correlation_id_echoed_in_response
    - GET /api/v1/targets with header X-Correlation-ID: "trace-abc123"
    - Assert response header X-Correlation-ID == "trace-abc123"

  test_rate_limiter_triggers_429
    - Fire 200 rapid sequential requests to GET /api/v1/status
    - Assert at least one response has status 429

  test_sse_last_event_id_replay
    - Create target, subscribe to SSE stream
    - Collect first 5 events, record last event ID
    - Disconnect
    - Reconnect with header Last-Event-ID: <recorded_id>
    - Assert at least the events after that ID are replayed
    - (No duplicate of the Last-Event-ID event itself)

  test_metrics_endpoint_prometheus_format
    - GET /metrics
    - Assert 200
    - Assert Content-Type contains "text/plain"
    - Assert body contains "api_latency_seconds"
    - Assert body contains "targets_created_total"

  test_resource_status_returns_tier
    - GET /api/v1/resources/status
    - Assert 200, body.tier in {"normal", "high", "critical"}
    - Assert body.thresholds is non-null dict

  test_resource_override_then_clear
    - POST /api/v1/resources/override {tier: "critical"}
    - GET /api/v1/resources/status, assert tier == "critical"
    - POST /api/v1/resources/override {} (no tier)
    - GET /api/v1/resources/status, assert tier != "critical" (reverts)

  test_health_endpoint
    - GET /health
    - Assert 200, body.status == "ok"

  test_target_creation_validation
    - POST /api/v1/targets {company_name: "", base_domain: "x.com"}
    - Assert 422 (empty company_name violates min_length=1)
    - POST /api/v1/targets {company_name: "Co", base_domain: "x"}
    - Assert 422 (domain too short, min_length=3)
```

---

## Section 3 — Event Engine Dispatch Tests (`tests/e2e/test_event_engine.py`)

These test behavioral invariants of the event engine by observing job dispatch through the `/api/v1/status` endpoint.

```
TestEventEngineDispatch:
  test_no_credentials_skips_credential_gated_workers
    - Create target WITHOUT writing credentials.json
    - Wait 30s (enough for first poll cycle)
    - GET /api/v1/status
    - Assert none of {identity_mgmt, authentication, authorization,
      session_mgmt, input_validation} appear in job list
    - Assert info_gathering IS dispatched

  test_with_credentials_dispatches_credential_gated_workers
    - Create target WITH credentials.json stub {"tester": null, "testing_user": null}
    - Wait 30s
    - GET /api/v1/status
    - Assert info_gathering appears
    - After info_gathering COMPLETED: assert identity_mgmt is QUEUED or RUNNING

  test_dependency_ordering_config_mgmt_waits_for_info_gathering
    - Create target
    - Poll /api/v1/status every 5s for up to 300s
    - Assert: whenever config_mgmt status transitions to QUEUED, 
      info_gathering status is already COMPLETED

  test_dependency_ordering_chain_worker_waits_for_prerequisites
    - Run wide_recon playbook
    - Poll /api/v1/status; when chain_worker first appears as QUEUED,
      assert all 5 prerequisites {input_validation, error_handling,
      cryptography, business_logic, client_side} are COMPLETED

  test_priority_high_target_dispatched_promptly
    - Create target with priority=90
    - Poll /api/v1/status every 2s for up to 30s
    - Assert info_gathering appears within 15s

  test_disabled_worker_skipped_in_pipeline
    - Create target with a playbook that has info_gathering disabled
    - Wait 30s
    - GET /api/v1/status
    - Assert info_gathering never appears in job list

  test_event_engine_resumes_after_kill
    - Create target A, let a worker reach RUNNING
    - POST /api/v1/kill
    - Wait 5s
    - Create target B
    - Assert target B's info_gathering appears within 30s (engine resumed)
```

---

## Section 4 — Infrastructure Worker Functional Tests (upgrade in-place)

### proxy (`tests/e2e/test_proxy.py`)

Keep existing tests. Add:

```
test_proxy_http_listener_responds
  - Look up proxy container's exposed port from docker inspect
    (or use a fixed known port from docker-compose.yml)
  - GET http://localhost:<proxy_port>/
  - Assert response status is not 5xx (200, 302, or 404 all acceptable)

test_proxy_passes_through_request
  - Configure a simple target URL routed through the proxy
  - GET <proxy_url>/testphp.vulnweb.com/
  - Assert response body is non-empty
  - Assert no Connection Refused or timeout
```

### callback (`tests/e2e/test_callback.py`)

Keep existing tests. Add:

```
test_callback_webhook_endpoint_accepts_post
  - Determine callback container's webhook port from docker-compose.yml
  - POST http://localhost:<callback_port>/webhook
    body: {"event": "test", "target_id": 0}
  - Assert HTTP 200 or 202

test_callback_health_check
  - GET http://localhost:<callback_port>/health (or equivalent)
  - Assert 200
```

### sandbox_worker (`tests/e2e/test_sandbox_worker.py`)

Keep existing tests. Add:

```
test_sandbox_accepts_queue_task
  - Push a task to sandbox_worker_queue via redis-cli through docker exec
    (same pattern as _purge_worker_queue)
  - Wait 15s
  - GET /api/v1/status or check docker logs
  - Assert sandbox_worker consumed the message (no pending entries in stream)
  - (Or: assert no Traceback in logs after the task push)
```

---

## File Layout After Changes

```
tests/e2e/
  conftest.py                    (no changes)
  test_info_gathering.py         (add 1 edge-case test)
  test_authentication.py         (add LAST_STAGE assertion + 1 edge-case test)
  test_authorization.py          (add LAST_STAGE assertion + 1 edge-case test)
  test_session_mgmt.py           (add LAST_STAGE assertion + 1 edge-case test)
  test_input_validation.py       (add LAST_STAGE assertion + 1 edge-case test)
  test_error_handling.py         (add LAST_STAGE assertion + 1 edge-case test)
  test_cryptography.py           (add LAST_STAGE assertion + 1 edge-case test)
  test_business_logic.py         (add LAST_STAGE assertion + 1 edge-case test)
  test_client_side.py            (add LAST_STAGE assertion + 1 edge-case test)
  test_config_mgmt.py            (add LAST_STAGE assertion + 1 edge-case test)
  test_identity_mgmt.py          (add LAST_STAGE assertion + 1 edge-case test)
  test_chain_worker.py           (add LAST_STAGE assertion + 1 edge-case test)
  test_reasoning_worker.py       (no change)
  test_reporting_worker.py       (add LAST_STAGE assertion + 1 edge-case test)
  test_proxy.py                  (add 2 functional/HTTP tests)
  test_callback.py               (add 2 functional/HTTP tests)
  test_sandbox_worker.py         (add 1 functional test)
  test_orchestrator_api.py       [NEW] ~25 tests across 3 test classes
  test_event_engine.py           [NEW] ~7 tests
```

**Total new tests: ~55** (13 LAST_STAGE assertions + 13 edge-case per worker + 25 orchestrator + 7 event-engine + 5 infra functional)

---

## conftest.py helpers needed

The following helpers need to be added to `tests/conftest.py`:

```python
async def assert_chain_findings(client, target_id, min_count=1) -> list:
    """Assert ≥ min_count chain_findings rows exist for target."""

async def assert_reports(client, target_id, min_count=1) -> list:
    """Assert ≥ min_count report files are listed for target."""

async def wait_for_worker_status(
    client, target_id, worker, expected_statuses, poll_interval=5, timeout=300
) -> str:
    """Poll until worker reaches one of expected_statuses; return actual status."""

async def seed_vulnerability(client, target_id, asset_id=None) -> dict:
    """Directly insert a vulnerability row for use in data-API tests."""
```

The `seed_vulnerability` helper is needed for orchestrator tests that require a vulnerability row without running a full pipeline. It inserts directly via `lib_webbh.get_session()` (the same pattern used by existing unit tests in `tests/unit/`). Do NOT use `POST /api/v1/test/seed` — that endpoint seeds a full target fixture, not an individual vulnerability.

---

## Constraints and risks

- **Single-active-target enforcement** — `test_orchestrator_api.py` tests must kill/delete before creating the next target. Each test class uses `autouse` teardown fixtures to guarantee cleanup even on failure.
- **Chain findings endpoint** — if `GET /api/v1/chain_findings` does not yet exist, chain_worker assertions fall back to checking that `GET /api/v1/vulnerabilities?worker_type=chain_worker` returns ≥1 row.
- **Proxy/callback ports** — actual exposed ports must be read from `docker inspect` at test time, not hardcoded, to avoid brittleness across environments.
- **SSE Last-Event-ID replay** — requires the target to still have events in the Redis stream. The test must not `XTRIM` or delete the stream before reconnecting.
- **Rate limiter test** — 200 requests may saturate the test machine; use `httpx.AsyncClient` with `asyncio.gather` to keep wall-clock time short. Adjust burst count based on the configured `RATE_LIMIT_MAX_REQUESTS` env var.
