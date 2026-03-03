# Phase 2 Orchestrator — Audit & Hardening Design

**Date:** 2026-03-01
**Scope:** Review existing `orchestrator/` code against the Phase 2 spec, fix bugs, close security gaps, and fill spec gaps.

---

## Audit Summary

The orchestrator (`main.py`, `event_engine.py`, `worker_manager.py`) implements the core Phase 2 spec: API endpoints, event-driven triggers, heartbeat/zombie cleanup, SSE streaming, and config generation. However, the audit identified 17 issues across four priority tiers. No tests exist for any orchestrator module.

---

## P0 — Bug Fixes

### 1. Correct status mappings for pause/stop

**File:** `orchestrator/main.py:207`

The `/control` endpoint maps `pause` to `QUEUED` and `stop` to `COMPLETED`. Both are semantically wrong. `QUEUED` means "waiting for resources" and `COMPLETED` means the job finished successfully.

**Fix:** Change the mapping:

```python
# Before
new_status = {"pause": "QUEUED", "stop": "COMPLETED", "restart": "RUNNING"}

# After
new_status = {"pause": "PAUSED", "stop": "STOPPED", "restart": "RUNNING"}
```

Update all trigger exclusion queries in `event_engine.py` (`_check_cloud_trigger`, `_check_web_trigger`, `_check_api_trigger`) to include `PAUSED` and `STOPPED` alongside `RUNNING` and `QUEUED` when filtering out targets that already have active jobs. These statuses represent admin-controlled states that should not be overridden by automatic triggers.

### 2. Web trigger must check `Location.state`

**File:** `orchestrator/event_engine.py:207`

The spec says trigger when port 80/443 is *open*. The current query only checks `Location.port.in_([80, 443])` without filtering on state. A closed or filtered port would incorrectly trigger fuzzing and webapp workers.

**Fix:** Add `.where(Location.state == "open")` to the web trigger query's existing `where` clause.

### 3. Heartbeat grace period for vanished containers

**File:** `orchestrator/event_engine.py:306-345`

If a container vanishes but `last_seen` is still within the zombie timeout, the current code immediately marks the job FAILED. This conflicts with Docker's `on-failure:3` restart policy — the container could be mid-restart.

**Fix:** Three-state logic per job in `_heartbeat_cycle`:

1. **Container running** — update `last_seen` (unchanged).
2. **Container gone, `last_seen` within timeout** — log a warning, leave status as `RUNNING`. Grace period for Docker restart policy to recover.
3. **Container gone, `last_seen` beyond timeout** — zombie kill + mark `FAILED` + create alert (unchanged).

### 4. Always write config files

**File:** `orchestrator/main.py:268-288`

`custom_headers.json` and `rate_limits.json` are only written when the profile contains non-empty values. `scope.json` is always written. This inconsistency means workers cannot assume a predictable file set per target and may raise `FileNotFoundError`.

**Fix:** Remove the `if custom_headers:` and `if rate_limits:` guards. Always write the files with empty-dict defaults `{}`. Workers get a consistent set of files for every target: `target_profile.json`, `custom_headers.json`, `rate_limits.json`, `scope.json`.

---

## P1 — Security & Spec Fixes

### 5. Validate container names in `/control`

**File:** `orchestrator/main.py:192-217`

The `container_name` from the request body is passed directly to the Docker SDK. An attacker with a valid API key could stop or restart any container on the host, not just webbh workers.

**Fix:** Add a prefix guard at the top of `control_worker`:

```python
if not body.container_name.startswith("webbh-"):
    raise HTTPException(status_code=400, detail="Can only control webbh worker containers")
```

### 6. Warn on missing API key at startup

**File:** `orchestrator/main.py` — inside `lifespan`, before background task creation.

If `WEB_APP_BH_API_KEY` is not set, all endpoints are fully open. No log message is emitted. This is a production footgun.

**Fix:** Add a warning log:

```python
if not API_KEY:
    logger.warning("WEB_APP_BH_API_KEY is not set — all endpoints are unauthenticated")
```

No behavior change — just observability.

### 7. Use UUID for SSE consumer names

**File:** `orchestrator/main.py:236`

`id(request)` returns the memory address of the Python object, which can be reused after garbage collection. Two SSE consumers could collide.

**Fix:** Replace `f"sse-{id(request)}"` with `f"sse-{uuid4().hex}"`. Add `from uuid import uuid4` to imports.

### 8. Expose `unpause` in `/control`

**File:** `orchestrator/main.py:193-207`

`worker_manager.py` has `unpause_worker()` but the `/control` endpoint only maps `pause | stop | restart`. Once paused, there is no API to resume a container.

**Fix:** Add `"unpause"` to the actions dict and status mapping:

```python
actions = {
    "pause": worker_manager.pause_worker,
    "stop": worker_manager.stop_worker,
    "restart": worker_manager.restart_worker,
    "unpause": worker_manager.unpause_worker,
}

new_status = {
    "pause": "PAUSED",
    "stop": "STOPPED",
    "restart": "RUNNING",
    "unpause": "RUNNING",
}
```

### 9. Cloud trigger must distinguish new assets from stale

**File:** `orchestrator/event_engine.py:170-190`

The current query fires the cloud worker for any target that has `cloud_assets` and no active cloud job. After a cloud job completes, it immediately re-triggers on the same stale assets.

**Fix:** Join `cloud_assets` with the latest completed/stopped cloud `job_state` for that target. Only trigger if the most recent `cloud_assets.created_at` is after the latest cloud job's `last_seen`. Concretely:

```sql
SELECT ca.target_id
FROM cloud_assets ca
LEFT JOIN job_state js ON (
    js.target_id = ca.target_id
    AND js.container_name LIKE 'webbh-cloud_testing-%'
    AND js.status IN ('RUNNING', 'QUEUED', 'PAUSED')
)
LEFT JOIN job_state js_done ON (
    js_done.target_id = ca.target_id
    AND js_done.container_name LIKE 'webbh-cloud_testing-%'
    AND js_done.status IN ('COMPLETED', 'STOPPED', 'FAILED')
)
WHERE js.id IS NULL
GROUP BY ca.target_id
HAVING MAX(ca.created_at) > COALESCE(MAX(js_done.last_seen), '1970-01-01')
```

This ensures only genuinely new cloud assets (created after the last cloud job finished) trigger a new worker.

---

## P2 — Quality & Robustness

### 10. Zombie cleanup should restart the worker

**File:** `orchestrator/event_engine.py:310-335`

The alert type is `ZOMBIE_RESTART` but the code only kills and marks FAILED. It never actually restarts the worker.

**Fix:** After killing the zombie and creating the alert, call `_trigger_worker` with the same `target_id`, `worker_key`, and `phase` to spin up a fresh replacement. Add a retry guard: count existing `ZOMBIE_RESTART` alerts for this container name. If the count exceeds `ZOMBIE_MAX_RETRIES` (env var, default 3), mark as permanently FAILED and emit a `CRITICAL_ALERT` instead of retrying.

```python
ZOMBIE_MAX_RETRIES = int(os.environ.get("ZOMBIE_MAX_RETRIES", "3"))
```

### 11. Pass API key to worker environment

**File:** `orchestrator/event_engine.py:107-118`

`_worker_env()` passes DB and Redis credentials but not `WEB_APP_BH_API_KEY`. Workers that need to call back to the orchestrator API cannot authenticate.

**Fix:** Add to `_worker_env`:

```python
"WEB_APP_BH_API_KEY": os.environ.get("WEB_APP_BH_API_KEY", ""),
```

### 12. Batch heartbeat session usage

**File:** `orchestrator/event_engine.py:295-355`

The current heartbeat opens N+1 database sessions per cycle (one to query RUNNING jobs, then one per job update). The zombie path opens two additional sessions. This is wasteful and introduces stale-read risk.

**Fix:** Restructure `_heartbeat_cycle` into two phases:

1. **Read phase (session 1):** Query all RUNNING jobs. Gather container statuses via `asyncio.gather` on `get_container_status` calls. Classify each job into one of three lists: `healthy` (container running), `grace` (container gone, within timeout), `zombie` (container gone, past timeout).
2. **Write phase (session 2):** In a single session: bulk-update `last_seen` for healthy jobs, kill + mark FAILED + create alerts for zombies, trigger restarts for zombies within retry limit.

Reduces per-cycle DB round-trips from ~3N to 2.

### 13. SSE pending message cleanup

**File:** `orchestrator/main.py:243-261`

Messages read via `XREADGROUP` but not `XACK`'d when the client disconnects sit in the pending entries list forever. No cleanup mechanism exists.

**Fix:** Two changes:

1. **On disconnect:** Wrap `_generate()` iteration in a `try/finally` that calls `redis.xautoclaim(queue, group, consumer, min_idle_time=0)` to release claimed-but-unacked messages.
2. **In heartbeat:** Add a periodic `XAUTOCLAIM` sweep for the `sse_consumers` group on all active `events:{target_id}` streams. Reclaim any messages pending for >60s. This catches cases where the `finally` block didn't fire (process crash, network drop).

### 14. Non-blocking CPU check

**File:** `orchestrator/worker_manager.py:271`

`psutil.cpu_percent(interval=1)` blocks for 1 full second in the executor. Called by `should_queue()` on every `_trigger_worker` invocation and during heartbeat queue promotion. Five queued jobs means 5+ seconds of blocking per heartbeat cycle.

**Fix:** Replace `interval=1` with `interval=None`. This returns CPU usage since the last call instead of blocking. The first call after import returns `0.0` (always "healthy"), which is acceptable — by the second poll cycle (15s later) the value is meaningful.

### 15. TOCTOU race in `_trigger_worker` (accepted risk)

`should_queue()` is checked before `start_worker()` runs. Between the check and the start, another trigger could also pass the resource check. The 15-second polling interval and single-threaded event loop make actual collision unlikely.

**Decision:** Document as a known limitation. A proper fix requires a distributed lock (Redis `SETNX`) which adds complexity disproportionate to the risk. Revisit if we move to concurrent trigger evaluation.

---

## P3 — Missing Spec Feature: Redis Background Listener

### 16. Add Redis stream listener

**File:** `orchestrator/event_engine.py` — new function `run_redis_listener`

The Phase 2 spec requires: *"Implement a background listener for Redis. If a new web location (port 80/443) is added to the DB, push the ID to the `fuzzing_queue`."*

The current implementation relies solely on DB polling. This adds a real-time reactive path via Redis Streams. Workers performing recon push discoveries to `recon_queue` (the stream name from the Phase 0 design doc). The orchestrator consumes and fans out.

**Design:** Add `run_redis_listener()` as a third background task started in `lifespan`. It uses `listen_queue` from `lib_webbh.messaging` on the `recon_queue` stream with consumer group `orchestrator` and consumer name `event-engine`.

The callback inspects the payload's `asset_type` field:

- `asset_type == "location"` and `port in (80, 443)` and `state == "open"` → push to `fuzzing_queue` and `webapp_queue` via `push_task`
- `asset_type == "cloud_asset"` → push to `cloud_queue`
- `asset_type == "param"` → push to `api_queue`

The DB poll loop remains as a safety net for missed events and startup catch-up. The Redis listener provides sub-second reactivity for the common path.

**Lifespan change:**

```python
redis_task = asyncio.create_task(event_engine.run_redis_listener(), name="redis-listener")
```

Add to the cancel/cleanup block alongside the existing two tasks.

---

## Testing Strategy

No orchestrator tests exist. The implementation plan should include tests for each module:

- **`test_main.py`:** Use `httpx.AsyncClient` with FastAPI's `TestClient`. Test all endpoints: target creation (DB row + file generation), status query, control actions (mock `worker_manager`), SSE stream (mock Redis). Test auth rejection and container-name validation.
- **`test_event_engine.py`:** Use SQLite in-memory DB (matching existing `tests/conftest.py` pattern). Seed DB with test data, call trigger functions directly, assert correct worker starts (mock `worker_manager`). Test zombie cleanup, auto-resume, grace period logic, and zombie retry limit.
- **`test_worker_manager.py`:** Mock `docker.DockerClient`. Test start/stop/restart/pause/unpause/kill flows, container-not-found handling, resource guard thresholds.

---

## Deliverables

1. Fixed `orchestrator/main.py` — all P0/P1/P2 changes
2. Fixed `orchestrator/event_engine.py` — all P0/P1/P2/P3 changes
3. Fixed `orchestrator/worker_manager.py` — P2 CPU check fix
4. New `tests/test_main.py`
5. New `tests/test_event_engine.py`
6. New `tests/test_worker_manager.py`
