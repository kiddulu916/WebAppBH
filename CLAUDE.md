# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAppBH is a modular, event-driven Bug Bounty Framework organized into 12 phases. The stack is PostgreSQL + Redis + a FastAPI orchestrator + Docker workers + a Next.js dashboard.

## Phase System

When beginning a new phase, start by reading `docs/plans/phase_prompts/intro_prompt.md` for project context and role, then `docs/plans/phase_prompts/phase{N}.md` for the phase spec. Place new design docs in `docs/plans/design/` and implementation plans in `docs/plans/implementation/`, using the file-name convention `YYYY-MM-DD-<topic>.md`.

**Do not do extensive research when writing plans.** Reference the phase prompt, the design doc, and existing docs directly.

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

Tests run on the `anyio_backend = "asyncio"` fixture (defined in `tests/conftest.py`) and use aiosqlite for an in-memory SQLite database. Orchestrator-specific fixtures live in `tests/conftest_orchestrator.py` and are auto-loaded via `pytest_plugins`.

## Architecture

### Monorepo layout
- `shared/lib_webbh/` — Core Python library shared by all services (DB models, Redis messaging, scope checker, JSON logger, plus rate limiting, secret scanning, intel enrichment, and other helpers).
- `orchestrator/` — FastAPI app (`main.py`, `event_engine.py`, `worker_manager.py`). Runs on port 8001 with API prefix `/api/v1/`.
- `workers/` — Docker worker containers; each follows the same layout: `base_tool.py`, `pipeline.py`, `concurrency.py`, `main.py`, and a `tools/` subdirectory.
- `dashboard/` — Next.js 16 + React 19 + Zustand + TanStack Table + Tailwind v4.
- `docker/` — One Dockerfile per service, all inheriting from `Dockerfile.base`.

### Shared library (`lib_webbh`)

All services import from `lib_webbh`:
```python
from lib_webbh import get_session, Asset, Target, push_task, setup_logger
```

Key modules:
- `database.py` — Async SQLAlchemy engine (asyncpg) and the canonical ORM models (`Target`, `Asset`, `Identity`, `Location`, `Observation`, `CloudAsset`, `Parameter`, `Vulnerability`, `JobState`, `Alert`, `ApiSchema`, `Campaign`, `ChainFinding`, and others — see `lib_webbh/__init__.py` for the full export list).
- `messaging.py` — Redis Streams wrapper (`push_task`, `listen_queue`, `get_pending`, plus priority variants). Stream names follow the convention `<worker>_queue` (e.g. `recon_queue`, `fuzzing_queue`, `cloud_queue`, `api_queue`); per-target SSE events are published on `events:{target_id}`.
- `scope.py` — `ScopeManager` (tldextract + netaddr + regex) returning a `ScopeResult` dataclass.
- `logger.py` — `setup_logger(name)` returns a structlog `BoundLogger` with a JSON formatter. Attach context with `.bind(target_id=N, asset_type="...")`.

Always use `lib_webbh` models for DB interactions. Do not invent table names or import paths.

### Worker pattern

Every worker type follows the same internal layout:
1. `base_tool.py` — Abstract base class named `<Worker>Tool` (e.g. `InfoGatheringTool`, `InputValidationTool`, `AuthenticationTool`, `ChainTestTool`, `MobileTestTool`). Provides the subprocess runner, cooldown checks, scope checks, and DB insert helpers.
2. `tools/` — One file per external tool, subclassing the worker's base class and implementing the abstract `async execute(self, target_id, **kwargs)` method.
3. `pipeline.py` — Defines an ordered list of `Stage` objects, runs tools concurrently within each stage via `asyncio.gather`, and checkpoints progress in the `job_state` table.
4. `concurrency.py` — Semaphore-based concurrency control with weight classes.
5. `main.py` — Entry point: calls `listen_queue` and runs the pipeline on each message.

### Event flow

1. Target is created via the orchestrator API.
2. Profile config is written to `shared/config/{target_id}/`.
3. A task is pushed to the relevant Redis stream.
4. A worker consumes it via a Redis consumer group and runs the pipeline stages.
5. Results are written to the database.
6. SSE events are published on the `events:{target_id}` stream.
7. The dashboard subscribes via `/api/v1/stream/{target_id}`.

### Environment variables

- DB: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`
- Redis: `REDIS_HOST`, `REDIS_PORT`
- Auth: `WEB_APP_BH_API_KEY` (sent as the `X-API-KEY` header)
- Worker: `TOOL_TIMEOUT` (default `600`s), `COOLDOWN_HOURS` (default `24`)

On first run, `shared/setup_env.py` generates these values into `shared/config/.env`.

### Dashboard stack

Next.js 16, React 19, Zustand for state, TanStack React Table, Lucide icons, Sonner toasts, and Tailwind CSS v4. The SSE route lives at `src/app/api/sse/[targetId]/route.ts`; campaign pages live under `src/app/campaign/`.
