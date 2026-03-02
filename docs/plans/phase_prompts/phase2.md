# Phase 2: The Framework Orchestrator

Act as a Lead Systems Architect.
Task: Create the "Framework Orchestrator" using FastAPI. This is the central control unit that manages targets, state, and event-driven worker execution.

## 1. API Architecture & Security

- **Framework**: FastAPI (Python 3.10+).
- **Security**: Enforce `X-API-KEY` authentication for all endpoints (Next.js frontend communication).
- **Target Init**: `POST /api/v1/targets/initialize` to receive scope data, save to Postgres, and generate `target_profile.json` in the shared volume.
**API Endpoints**: 
   - `POST /api/v1/targets`: Initialize a new scan and generate a `target_profile.json` in the shared volume.
   - `GET /api/v1/status`: Return real-time job states from the `job_state` table.
   - `POST /api/v1/control`: Pause/Stop/Restart specific worker containers via Docker SDK.

## 2. Event-Driven Worker Engine

Implement an "Observation Listener" that monitors the database and triggers containers via the Docker SDK:

- **Cloud Trigger**: If a new entry appears in `cloud_assets`, spin up the "Cloud Environment Testing" container.
- **Web Trigger**: If a `location` shows port 80/443 is open, trigger "Fuzzing" and "Web App Testing" workers.
- **API Trigger**: If the `parameters` table for a domain hits a specific threshold (e.g., >20 unique keys), trigger "API Testing".
- **Resource Guard**: Use `psutil` or Docker stats to check CPU/RAM. If resources are low, set job status to `QUEUED` instead of `RUNNING`.
- Implement a background listener for Redis. Example: If a new web location (port 80/443) is added to the DB, push the ID to the `fuzzing_queue`.

## 3. Health Checks & State Recovery

- **Heartbeat System**: Every 60 seconds, check the health of all active Docker containers and the `job_state` table.
- **Zombie Cleanup**: If a container is unresponsive or hasn't updated the DB in 10 minutes, kill the process and log a "ZOMBIE_RESTART" event.
- **Auto-Resume**: On startup, identify any "RUNNING" jobs from the DB that have no active container and restart them from the `last_tool_executed`.

## 4. Real-time Visuals (SSE)

- Implement `GET /api/v1/stream/{target_id}` using **Server-Sent Events (SSE)**.
- Stream JSON events to the Next.js frontend: `TOOL_PROGRESS`, `NEW_ASSET`, `CRITICAL_ALERT`, and `WORKER_SPAWNED` (triggered by the event engine).

## 5. Config Generation

- Dynamically generate tool-specific configs (headers, user-agents) in `/app/shared/config/` based on the `custom_headers` and `rate_limit` defined in the target profile.

Deliverables: FastAPI main.py, event_engine.py, worker_manager.py, and a Dockerfile with host Docker-socket access.