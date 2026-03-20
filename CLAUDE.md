# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAppBH is a 12-phase modular, event-driven Bug Bounty Framework. It uses PostgreSQL + Redis + FastAPI orchestrator + Docker workers + Next.js dashboard.

## Phase System

Always refer to `docs/plans/intro_prompt.md` when beginning a new phase. Phase spec prompts live in `docs/plans/phase_prompts/phase{N}.md`. Design docs go in `docs/plans/design/`, implementation plans in `docs/plans/implementation/` (naming: `YYYY-MM-DD-<topic>.md`).

**Do not do extensive research when writing plans.** Reference the design doc and existing docs directly.

## Build & Run

```bash
# Full stack
docker compose up --build

# Individual services
docker compose up postgres redis           # infra only
docker compose up orchestrator             # API (port 8001)
docker compose up dashboard                # Next.js (port 3000)
```

### Shared library (editable install for dev)
```bash
pip install -e shared/lib_webbh            # installs lib_webbh
pip install -e "shared/lib_webbh[dev]"     # + pytest, pytest-asyncio, aiosqlite
```

### Dashboard
```bash
cd dashboard && npm install
npm run dev                                # next dev
npm run build                              # next build
npm run lint                               # eslint
```

### Tests
```bash
pytest                                     # all tests
pytest tests/test_scope.py                 # single file
pytest tests/test_recon_tools_passive.py -k "test_subfinder"  # single test
```

Tests use `anyio_backend = "asyncio"` and aiosqlite for in-memory SQLite. Orchestrator-specific fixtures are in `tests/conftest_orchestrator.py` (loaded via `pytest_plugins`).

## Architecture

### Monorepo layout
- `shared/lib_webbh/` — Core Python library used by all services (DB models, Redis messaging, scope checker, JSON logger)
- `orchestrator/` — FastAPI app (main.py, event_engine.py, worker_manager.py). Runs on port 8001, API prefix `/api/v1/`
- `workers/` — Docker worker containers, each with its own `base_tool.py`, `pipeline.py`, `concurrency.py`, and `tools/` dir
- `dashboard/` — Next.js 16 + React 19 + Zustand + TanStack Table + Tailwind v4
- `docker/` — One Dockerfile per service, all inherit from `Dockerfile.base`

### Shared library (`lib_webbh`)

All services import from `lib_webbh`:
```python
from lib_webbh import get_session, Asset, Target, push_task, setup_logger
```

Key modules:
- `database.py` — Async SQLAlchemy engine (asyncpg), all ORM models (Target, Asset, Identity, Location, Observation, CloudAsset, Parameter, Vulnerability, JobState, Alert, ApiSchema)
- `messaging.py` — Redis Streams wrapper (`push_task`, `listen_queue`, `get_pending`). Stream names: `recon_queue`, `fuzzing_queue`, `cloud_queue`, `api_queue`, `events:{target_id}`
- `scope.py` — `ScopeManager` with tldextract + netaddr + regex. Returns `ScopeResult` dataclass
- `logger.py` — `setup_logger(name)` returns a BoundLogger with JSON formatter. Use `.bind(target_id=N, asset_type="...")` for context

Use the `lib_webbh` database models for all DB interactions. Do not invent table names or paths.

### Worker pattern

Every worker type follows the same pattern:
1. `base_tool.py` — Abstract base class (`ReconTool` or `ApiTestTool`) with subprocess runner, cooldown check, scope-check, DB insert helpers
2. `tools/` — One file per external tool, subclassing the base. Implements `build_command()`/`parse_output()` (recon) or `execute()` (api)
3. `pipeline.py` — Defines ordered `Stage` list, runs tools concurrently within each stage via `asyncio.gather`, checkpoints progress in `job_state` table
4. `concurrency.py` — Semaphore-based concurrency control with weight classes
5. `main.py` — Entry point, calls `listen_queue` and runs pipeline on each message

### Event flow

Target created via orchestrator API → profile config written to `shared/config/{target_id}/` → task pushed to Redis stream → worker picks up via consumer group → runs pipeline stages → results written to DB → SSE events pushed to `events:{target_id}` stream → dashboard consumes via `/api/v1/stream/{target_id}`

### Environment variables

DB: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`
Redis: `REDIS_HOST`, `REDIS_PORT`
Auth: `WEB_APP_BH_API_KEY` (X-API-KEY header)
Worker: `TOOL_TIMEOUT` (default 600s), `COOLDOWN_HOURS` (default 24)

`shared/setup_env.py` generates these into `shared/config/.env` on first run.

### Dashboard stack

Next.js 16, React 19, Zustand for state, TanStack React Table, Lucide icons, Sonner toasts, Tailwind CSS v4. SSE route at `src/app/api/sse/[targetId]/route.ts`. Campaign pages under `src/app/campaign/`.
