# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAppBH is a modular, event-driven Bug Bounty Framework. The stack is PostgreSQL + Redis + a FastAPI orchestrator + 18 active Docker workers (plus one legacy stub dir) + a Next.js dashboard + an Ollama sidecar for the `reasoning_worker`. The codebase was restructured from 7 generic workers (recon/api/fuzzing/cloud/etc.) into WSTG-aligned specialized workers via the M1–M11 restructure (now complete — legacy worker dirs and Dockerfiles have been removed).

## Planning workflow

Active design docs and implementation plans live in:
- `docs/plans/design/YYYY-MM-DD-<topic>-design.md`
- `docs/plans/implementation/YYYY-MM-DD-<topic>.md`

The historical "what-was-built" map is the M-numbered restructure series (`docs/plans/design/2026-03-29-restructure-00-overview.md` through `restructure-12-migration.md`). For new work, scan recent plans (e.g. `2026-05-07-flow-page-playbook-rebuild-design.md`) for context and shape, then create today's design + implementation pair following the same naming convention.

**Do not do extensive research when writing plans.** Reference the design doc and existing implementation plans directly.

## Build & Run

```bash
# Full stack
docker compose up --build

# Individual services
docker compose up postgres redis           # infra only
docker compose up orchestrator             # API (port 8001)
docker compose up dashboard                # Next.js (port 3000)

# Optional observability overlay (Prometheus/Grafana/Loki/cAdvisor)
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up

# Mobile stack — requires host KVM support (/dev/kvm)
docker compose up mobile-worker mobsf docker-android   # MobSF on port 8000
```

On first run, `shared/setup_env.py` generates DB/Redis credentials and the framework API key into `shared/config/.env`.

### Shared library (editable install for dev)
```bash
pip install -e shared/lib_webbh                # installs lib_webbh
pip install -e "shared/lib_webbh[dev]"         # + pytest, pytest-asyncio, aiosqlite
```

### Dashboard
```bash
cd dashboard && npm install
npm run dev          # next dev (port 3000)
npm run build        # next build
npm run lint         # eslint
npm run test:e2e     # playwright e2e suite under dashboard/e2e/
```

### Tests
```bash
pytest                                                          # all tests
pytest tests/test_scope.py                                      # single file
pytest tests/test_recon_tools_passive.py -k "test_subfinder"    # single test
```

Tests use the `anyio_backend = "asyncio"` fixture (defined in `tests/conftest.py`) and aiosqlite for an in-memory SQLite database. Orchestrator-specific fixtures live in `tests/conftest_orchestrator.py` and are auto-loaded via `pytest_plugins`.

## Architecture

### Monorepo layout
- `shared/lib_webbh/` — Core Python library shared by all services. See its `__init__.py` for the canonical export list.
- `shared/` — Also holds `setup_env.py`, `schema.sql`, `models.py`, `interfaces.ts`, `config/`, `raw/`, `logs/`, `mobile_analysis/`, `mobile_binaries/`.
- `orchestrator/` — FastAPI app on port 8001 with prefix `/api/v1/`. Key files: `main.py`, `event_engine.py`, `worker_manager.py`, `target_expander.py`, `dependency_map.py`, `resource_guard.py`, `rate_limit.py`, `metrics.py`. Sub-route modules in `orchestrator/routes/` (`campaigns.py`, `resources.py`).
- `workers/` — 19 specialized worker containers. Each follows the same internal layout (see "Worker pattern" below).
- `dashboard/` — Next.js 16.1 + React 19.2 + Zustand 5 + TanStack Table 8 + `@xyflow/react` (flow page) + Tailwind v4 + Geist font + Sonner toasts + Lucide icons. Playwright e2e under `dashboard/e2e/`.
- `docker/` — One Dockerfile per service, all inheriting from `Dockerfile.base`.
- `alembic/` and `shared/lib_webbh/alembic/` — schema migrations.
- `tests/` — pytest suite (asyncio + aiosqlite).

### Worker inventory (18 active)

`info_gathering`, `identity_mgmt`, `authentication`, `authorization`, `session_mgmt`, `input_validation`, `error_handling`, `cryptography`, `business_logic`, `client_side`, `config_mgmt`, `chain_worker`, `mobile_worker`, `reporting_worker`, `reasoning_worker`, `sandbox_worker`, `proxy`, `callback`. The `workers/reporting/` directory is a near-empty legacy stub kept alongside the full `workers/reporting_worker/` implementation — do not add code there.

`reasoning_worker` calls a local Ollama instance (default `qwen3:14b`); without the `ollama` service the worker will fail its enrichment stage. `mobile_worker` depends on the `mobsf` and `docker-android` sidecars and host KVM.

### Shared library (`lib_webbh`)

All services import from `lib_webbh`. The full export surface lives in `shared/lib_webbh/__init__.py` — always check there for canonical names. Common entry points:

```python
from lib_webbh import (
    get_session, push_task, listen_queue, listen_priority_queues,
    setup_logger, redact_sensitive, ScopeManager,
    Target, Asset, Vulnerability, JobState, Campaign, ChainFinding,
)
```

Module families:
- `database.py` — Async SQLAlchemy engine (asyncpg) and 25 ORM models (Target, Asset, Identity, Location, Observation, CloudAsset, Parameter, Vulnerability, JobState, Alert, ApiSchema, MobileApp, AssetSnapshot, BountySubmission, ScheduledScan, ScopeViolation, CustomPlaybook, Campaign, EscalationContext, ChainFinding, VulnerabilityInsight, ToolHitRate, MutationOutcome, …).
- `messaging.py` — Redis Streams wrapper. Stream convention: `<worker>_queue` (e.g. `info_gathering_queue`, `input_validation_queue`, `chain_worker_queue`, `reasoning_queue`, `reporting_queue`); priority variants `push_priority_task` / `listen_priority_queues`. Per-target SSE events publish to `events:{target_id}`.
- `scope.py` — `ScopeManager` (tldextract + netaddr + regex), returns `ScopeResult`. Logs out-of-scope hits via `record_scope_violation`.
- `logger.py` — `setup_logger(name)` returns a structlog `BoundLogger` with a JSON formatter. Use `redact_sensitive` to sanitize log payloads. Bind context with `.bind(target_id=N, asset_type="…")`.
- Helpers: `batch_insert`, `correlation`, `cron_utils`, `deep_classifier`, `diffing`, `infra_mixin`, `intel_enrichment`, `llm_client`, `pipeline_checkpoint` (`CheckpointMixin`), `playbooks`, `queue_monitor`, `rate_limiter`, `report_templates`, `scan_intelligence`, `secret_scanner`, `secrets`, `shared_infra`, `wildcard`. Plus `platform_api/` and `prompts/` subpackages.

Always use `lib_webbh` models for DB interactions. Do not invent table names or import paths.

### Worker pattern

Every worker in `workers/` follows this internal layout:
1. `base_tool.py` — Abstract base class named `<Worker>Tool` (e.g. `InfoGatheringTool`, `InputValidationTool`, `AuthenticationTool`, `ChainTestTool`, `MobileTestTool`). Provides the subprocess runner (always `asyncio.create_subprocess_exec`, never `shell=True`), cooldown checks, scope checks, and DB insert helpers.
2. `tools/` — One file per external tool, subclassing the worker's base class and implementing `async execute(self, target_id, **kwargs)`.
3. `pipeline.py` — Defines an ordered list of `Stage` objects, runs tools concurrently within each stage via `asyncio.gather`, and checkpoints progress in the `job_state` table (via `CheckpointMixin`).
4. `concurrency.py` — Semaphore-based concurrency control with `WeightClass` enum (HEAVY / LIGHT). Reads `HEAVY_CONCURRENCY` and `LIGHT_CONCURRENCY` from env.
5. `main.py` — Entry point: calls `listen_queue` / `listen_priority_queues` and runs the pipeline on each message, with a heartbeat loop updating `job_state.last_seen`.
6. `requirements.txt` — Worker-specific Python deps (if any beyond `lib_webbh`).

`workers/info_gathering/` is the canonical reference implementation — copy its shape when scaffolding a new worker.

### Event flow

1. Target is created via the orchestrator API (`POST /api/v1/targets`).
2. Profile config is written to `shared/config/{target_id}/`.
3. The event engine pushes a task to the relevant Redis stream.
4. A worker consumes it via a Redis consumer group and runs the pipeline stages.
5. Results are written to the database.
6. SSE events are published on the `events:{target_id}` stream.
7. The dashboard subscribes via `GET /api/v1/stream/{target_id}` (Next.js SSE route at `dashboard/src/app/api/sse/[targetId]/route.ts`).

### Environment variables

- DB: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`
- Redis: `REDIS_HOST`, `REDIS_PORT`
- Auth: `WEB_APP_BH_API_KEY` (sent as the `X-API-KEY` header on every `/api/v1/` request)
- Worker: `TOOL_TIMEOUT` (default `600`s), `COOLDOWN_HOURS` (default `24`), `HEAVY_CONCURRENCY`, `LIGHT_CONCURRENCY`
- LLM (`reasoning_worker`): `LLM_BASE_URL` (default `http://ollama:11434`), `LLM_MODEL` (default `qwen3:14b`)
- Optional enrichment: `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`

`shared/setup_env.py` generates these into `shared/config/.env` on first run.
