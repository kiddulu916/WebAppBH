---
name: new-worker
description: Scaffold a new Docker worker with base_tool, pipeline, concurrency, tools dir, Dockerfile, docker-compose entry, and test stubs following the project's worker pattern
---

# Scaffold a New Worker

Create a new worker type for the WebAppBH framework. Every worker follows the exact same structural pattern.

## Arguments

The user must provide:
- **Worker name**: e.g., `network_worker` (used as directory name under `workers/`)
- **Queue name**: Redis stream this worker listens on (e.g., `network_queue`)
- **Consumer group**: Redis consumer group name (e.g., `network_group`)
- **Base tool class name**: e.g., `NetworkTool` (the abstract base class name)
- **Stages**: List of pipeline stage names and what tools go in each

If the user doesn't provide these, ask before proceeding.

## Files to Create

### 1. `workers/{name}/__init__.py`
Empty init file.

### 2. `workers/{name}/concurrency.py`
Copy the exact pattern from `workers/recon_core/concurrency.py`:
- `WeightClass` enum with HEAVY/LIGHT
- Module-level semaphore singletons
- `get_semaphores()` and `get_semaphore(weight)` functions
- Reads `HEAVY_CONCURRENCY` and `LIGHT_CONCURRENCY` from env

### 3. `workers/{name}/base_tool.py`
Follow the pattern from `workers/recon_core/base_tool.py`:
- Import from `lib_webbh`: `get_session`, relevant models, `push_task`, `setup_logger`
- Import `ScopeManager` from `lib_webbh.scope`
- Import `WeightClass, get_semaphore` from the local `concurrency` module
- Abstract base class with `name` and `weight_class` class attributes
- Abstract methods appropriate for the worker type
- `run()` method with: scope check → cooldown check → semaphore acquire → subprocess exec → parse output → DB insert
- Use `asyncio.create_subprocess_exec` (NEVER `shell=True`)
- Respect `TOOL_TIMEOUT` and `COOLDOWN_HOURS` env vars

### 4. `workers/{name}/tools/__init__.py`
Exports all tool classes.

### 5. `workers/{name}/pipeline.py`
Follow `workers/recon_core/pipeline.py`:
- `Stage` dataclass with `name` and `tools` list
- `Pipeline` class with `target_id` and `container_name`
- `STAGES` list defining ordered stages
- `run()` method: iterate stages, `asyncio.gather` tools within each stage, checkpoint to `job_state` table

### 6. `workers/{name}/main.py`
Follow `workers/recon_core/main.py`:
- `handle_message()`: validate message, load target, create/update `JobState`, run pipeline with heartbeat
- `_heartbeat_loop()`: update `job_state.last_seen` every `HEARTBEAT_INTERVAL` seconds
- `main()`: call `listen_queue()` with the worker's queue and group
- Entry point: `asyncio.run(main())`

### 7. `workers/{name}/requirements.txt`
Worker-specific Python dependencies (if any beyond lib_webbh).

### 8. `docker/Dockerfile.{short_name}`
Follow multi-stage build pattern from `docker/Dockerfile.recon`:
- Stage 1: Build any Go/compiled tools needed
- Stage 2 (optional): Build any Python tool dependencies
- Final stage: `python:3.10-slim-bookworm` base
  - Install system deps
  - Copy compiled binaries from builder stages
  - `COPY shared/lib_webbh /app/shared/lib_webbh` + `pip install`
  - `mkdir -p /app/shared/raw /app/shared/config /app/shared/logs`
  - `COPY workers/__init__.py` + `COPY workers/{name}`
  - Verify import: `RUN python -c "from workers.{name}.main import main; print('{name} OK')"`
  - `ENTRYPOINT ["python", "-m", "workers.{name}.main"]`

### 9. Docker Compose entry
Add to `docker-compose.yml` following the existing worker service pattern:
- Build context `.`, dockerfile `docker/Dockerfile.{short_name}`
- Depends on `postgres` and `redis` (both `service_healthy`)
- Standard env vars: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS`, `REDIS_HOST`, `REDIS_PORT`
- Volume: `./shared:/app/shared`
- Network: `webbh-net`

### 10. Test stubs
Create `tests/test_{name}_pipeline.py` and `tests/test_{name}_tools.py` with:
- Standard imports: `pytest`, `anyio`, model imports from `lib_webbh`
- `pytest_plugins` referencing `conftest_orchestrator` if needed
- Stub test functions for each tool and pipeline stage
- Use `anyio_backend = "asyncio"` and aiosqlite for in-memory SQLite

## Checklist Before Done

- [ ] All files created following exact patterns from `workers/recon_core/`
- [ ] Imports use `lib_webbh` for all DB/messaging/logging
- [ ] No `shell=True` in any subprocess call
- [ ] Scope checking in base_tool `run()` method
- [ ] Dockerfile verifies import at build time
- [ ] Docker Compose service added with health dependencies
- [ ] Test stubs created
