# WSTG-Aligned Restructure — 09 Orchestrator & Event Engine

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-08-target-expansion-resources
**Scope:** Dependency graph, event engine, poll cycle, worker lifecycle

---

## Overview

The orchestrator is the central coordinator. It does not perform any testing — it manages the dependency graph between workers, decides when to fire the next worker based on completion events, and manages the lifecycle of worker containers.

The restructured orchestrator replaces the current sequential phase system with a dependency-driven event engine that maximizes parallelism while respecting data dependencies.

---

## Dependency Graph

### Worker Dependencies

```
info_gathering
    |
    +--> TargetExpander (post-processing, not a worker)
    |
    v
config_mgmt
    |
    v
identity_mgmt (skipped if no credentials)
    |
    v
authentication (skipped if no credentials)
    |
    +----+----+
    |         |
    v         v
authorization  session_mgmt    (parallel)
    |         |
    +----+----+
         |
         v
input_validation
    |
    +-------+-------+-------+
    |       |       |       |
    v       v       v       v
error_handling  cryptography  business_logic  client_side    (parallel)
    |       |       |       |
    +-------+-------+-------+
                |
                v
          chain_worker
                |
                v
           reporting
```

### Dependency Map

```python
# orchestrator/dependency_map.py

DEPENDENCY_MAP = {
    "info_gathering":   [],                           # No dependencies — runs first
    "config_mgmt":      ["info_gathering"],            # Needs asset inventory
    "identity_mgmt":    ["config_mgmt"],               # Needs platform config
    "authentication":   ["identity_mgmt"],             # Needs identity context
    "authorization":    ["authentication"],             # Needs auth session
    "session_mgmt":     ["authentication"],             # Needs auth session
    "input_validation": ["authorization", "session_mgmt"],  # Needs auth + session context
    "error_handling":   ["config_mgmt"],               # Only needs platform info
    "cryptography":     ["config_mgmt"],               # Only needs platform info
    "business_logic":   ["authorization", "session_mgmt"],  # Needs auth + session context
    "client_side":      ["config_mgmt"],               # Only needs platform info
    "chain_worker":     [                              # Needs all testing workers
        "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side"
    ],
    "reporting":        ["chain_worker"],               # Needs all findings
}

# Workers that require credentials — skipped if no credentials provided
CREDENTIAL_REQUIRED = {
    "identity_mgmt", "authentication", "authorization",
    "session_mgmt", "input_validation", "business_logic"
}
```

### Skip Logic

When no credentials are provided in the campaign configuration, the orchestrator skips credential-dependent workers and adjusts the dependency graph:

```python
def resolve_effective_dependencies(target_id):
    """Resolve the dependency graph, accounting for skipped workers.

    If a worker is skipped, its dependents inherit its dependencies.
    """
    has_credentials = _check_credentials(target_id)

    effective_map = {}
    for worker, deps in DEPENDENCY_MAP.items():
        if worker in CREDENTIAL_REQUIRED and not has_credentials:
            continue  # Skip this worker entirely

        # Replace skipped dependencies with their dependencies
        resolved_deps = set()
        for dep in deps:
            if dep in CREDENTIAL_REQUIRED and not has_credentials:
                # This dependency is skipped — inherit its dependencies
                resolved_deps.update(
                    _resolve_skipped(dep, DEPENDENCY_MAP, CREDENTIAL_REQUIRED)
                )
            else:
                resolved_deps.add(dep)

        effective_map[worker] = list(resolved_deps)

    return effective_map


def _resolve_skipped(worker, dep_map, skip_set):
    """Walk up the dependency tree past skipped workers."""
    result = set()
    for dep in dep_map.get(worker, []):
        if dep in skip_set:
            result.update(_resolve_skipped(dep, dep_map, skip_set))
        else:
            result.add(dep)
    return result
```

**No-credential dependency graph:**

```
info_gathering -> config_mgmt -> error_handling + cryptography + client_side (parallel)
                                 -> chain_worker -> reporting
```

When credentials are absent, input_validation and business_logic are also skipped (they require authenticated testing). Error handling, cryptography, and client-side testing proceed because they can operate without authentication (they test server-side error handling, TLS config, and client-side injection surfaces using unauthenticated requests).

---

## Event Engine

### Core Loop

The event engine runs as an async background task in the orchestrator. It polls for completed workers and evaluates which workers can be started next.

```python
# orchestrator/event_engine.py

class EventEngine:
    """Evaluates worker dependencies and dispatches next workers.

    Runs on a poll cycle, checking for newly completed workers
    and firing any workers whose dependencies are now satisfied.
    """

    def __init__(self, resource_guard: ResourceGuard):
        self.resource_guard = resource_guard
        self._poll_interval = 5  # seconds

    async def run(self):
        """Main event loop."""
        while True:
            try:
                await self._poll_cycle()
            except Exception as e:
                logger.error("Event engine error", error=str(e))
            await asyncio.sleep(self._poll_interval)

    async def _poll_cycle(self):
        """Single poll cycle — check all targets for runnable workers."""
        # Check resource guard
        tier = await self.resource_guard.get_current_tier()
        if tier == "critical":
            return  # No new work when resources are critical

        # Get all active targets (seed + child)
        async with get_session() as session:
            targets = await session.execute(
                select(Target)
                .where(Target.status.in_(["pending", "running"]))
            )
            targets = targets.scalars().all()

        for target in targets:
            await self._evaluate_target(target, tier)

    async def _evaluate_target(self, target, resource_tier):
        """Evaluate which workers can run for a specific target."""
        dep_map = resolve_effective_dependencies(target.id)
        worker_states = await self._get_worker_states(target.id)

        for worker_name, dependencies in dep_map.items():
            # Skip if already running or completed
            if worker_states.get(worker_name) in ("running", "complete"):
                continue

            # Skip if already queued
            if worker_states.get(worker_name) == "queued":
                continue

            # Check if all dependencies are complete
            all_deps_met = all(
                worker_states.get(dep) == "complete"
                for dep in dependencies
            )

            if all_deps_met:
                # Check resource guard allows this priority
                batch_config = self.resource_guard.get_batch_config(resource_tier)
                priority = target.priority or 50

                # Map priority to queue tier
                if priority >= 90:
                    queue_tier = "critical"
                elif priority >= 70:
                    queue_tier = "high"
                elif priority >= 50:
                    queue_tier = "normal"
                else:
                    queue_tier = "low"

                if queue_tier not in batch_config["queues"]:
                    continue  # Resource guard blocks this tier

                # Dispatch the worker
                await self._dispatch_worker(target, worker_name, queue_tier)

    async def _dispatch_worker(self, target, worker_name, queue_tier):
        """Enqueue a worker for execution."""
        queue_name = f"{worker_name}_queue:{queue_tier}"

        await push_task(
            queue_name,
            {
                "target_id": target.id,
                "worker": worker_name,
                "priority": target.priority,
            }
        )

        # Record the dispatch in job_state
        async with get_session() as session:
            job = JobState(
                target_id=target.id,
                worker_type=worker_name,
                status="queued",
                queued_at=datetime.utcnow(),
            )
            session.add(job)
            await session.commit()

        logger.info(
            "Worker dispatched",
            worker=worker_name,
            target_id=target.id,
            queue=queue_name,
        )

    async def _get_worker_states(self, target_id):
        """Get the current status of all workers for a target."""
        async with get_session() as session:
            jobs = await session.execute(
                select(JobState)
                .where(JobState.target_id == target_id)
                .order_by(JobState.created_at.desc())
            )
            states = {}
            for job in jobs.scalars().all():
                if job.worker_type not in states:
                    states[job.worker_type] = job.status
            return states
```

### Special Events

Beyond the standard dependency evaluation, the event engine handles special events:

**Target Expansion Event:**
```python
async def on_info_gathering_complete(self, target_id):
    """Fires TargetExpander after info_gathering completes."""
    expander = TargetExpander()
    await expander.expand(target_id)
    # Normal dependency evaluation will pick up config_mgmt for the parent
    # and config_mgmt for all newly created children
```

**Worker Failure Event:**
```python
async def on_worker_failed(self, target_id, worker_name, error):
    """Handle worker failure — mark dependents as blocked."""
    async with get_session() as session:
        job = await session.execute(
            select(JobState)
            .where(JobState.target_id == target_id)
            .where(JobState.worker_type == worker_name)
            .order_by(JobState.created_at.desc())
            .limit(1)
        )
        job = job.scalar_one_or_none()
        if job:
            job.status = "failed"
            job.error = str(error)
            await session.commit()

    # Push failure event to SSE stream
    await push_task(
        f"events:{target_id}",
        {
            "event": "worker_failed",
            "worker": worker_name,
            "error": str(error),
            "target_id": target_id,
        }
    )
```

**Skip Event:**
```python
async def on_worker_skipped(self, target_id, worker_name, reason):
    """Record a worker skip — dependents treat skipped as complete."""
    async with get_session() as session:
        job = JobState(
            target_id=target_id,
            worker_type=worker_name,
            status="complete",  # Treated as complete for dependency resolution
            skipped=True,
            skip_reason=reason,
        )
        session.add(job)
        await session.commit()
```

---

## Worker Lifecycle

### Container Management

Each worker type runs as a Docker container. The orchestrator manages container scaling via the Docker API or docker-compose:

```python
# orchestrator/worker_manager.py

class WorkerManager:
    """Manages worker container lifecycle.

    Starts worker containers on demand and stops idle containers
    to free resources.
    """

    # Maximum concurrent containers per worker type
    MAX_CONTAINERS = {
        "info_gathering": 2,
        "config_mgmt": 3,
        "identity_mgmt": 2,
        "authentication": 2,
        "authorization": 2,
        "session_mgmt": 2,
        "input_validation": 2,
        "error_handling": 3,
        "cryptography": 3,
        "business_logic": 2,
        "client_side": 2,
        "chain_worker": 1,
        "reporting": 1,
    }

    async def ensure_worker_running(self, worker_type):
        """Start a worker container if none is running."""
        running = await self._count_running(worker_type)
        if running < self.MAX_CONTAINERS[worker_type]:
            await self._start_container(worker_type)

    async def scale_down_idle(self):
        """Stop worker containers that have been idle for > 5 minutes."""
        for worker_type in self.MAX_CONTAINERS:
            containers = await self._get_containers(worker_type)
            for container in containers:
                if await self._is_idle(container, timeout=300):
                    await self._stop_container(container)
```

### Worker Main Loop

Each worker follows the same main loop pattern:

```python
# workers/{worker_type}/main.py

async def main():
    worker_type = os.environ["WORKER_TYPE"]
    consumer_group = f"{worker_type}_group"
    consumer_name = f"{worker_type}_{socket.gethostname()}"

    # Create consumer group if not exists
    await ensure_consumer_group(f"{worker_type}_queue", consumer_group)

    async for message in listen_priority_queues(
        f"{worker_type}_queue", consumer_group, consumer_name
    ):
        target_id = message["target_id"]

        try:
            # Update job state to running
            await update_job_state(target_id, worker_type, "running")

            # Run the pipeline
            pipeline = Pipeline(target_id, worker_type)
            await pipeline.run()

            # Update job state to complete
            await update_job_state(target_id, worker_type, "complete")

            # Push completion event
            await push_task(
                f"events:{target_id}",
                {"event": "worker_complete", "worker": worker_type}
            )

        except Exception as e:
            await update_job_state(
                target_id, worker_type, "failed", error=str(e)
            )
            await push_task(
                f"events:{target_id}",
                {"event": "worker_failed", "worker": worker_type, "error": str(e)}
            )

        # Acknowledge the message
        await ack_message(message)
```

---

## Orchestrator API Endpoints

### Campaign Management

```
POST /api/v1/campaigns                  — Create campaign with seed targets
GET  /api/v1/campaigns                  — List all campaigns
GET  /api/v1/campaigns/{id}             — Get campaign details
POST /api/v1/campaigns/{id}/start       — Start campaign (enqueue seed targets)
POST /api/v1/campaigns/{id}/pause       — Pause all workers for campaign
POST /api/v1/campaigns/{id}/resume      — Resume paused campaign
POST /api/v1/campaigns/{id}/cancel      — Cancel campaign (stop all workers)
```

### Target Management

```
GET  /api/v1/targets/{id}               — Get target details + worker states
GET  /api/v1/targets/{id}/children      — List child targets with status
GET  /api/v1/targets/{id}/pipeline      — Get pipeline progress (all workers)
GET  /api/v1/targets/{id}/findings      — Get all vulnerabilities for target
```

### Worker Management

```
GET  /api/v1/workers/status             — All worker container statuses
POST /api/v1/workers/{type}/scale       — Scale worker container count
GET  /api/v1/workers/{type}/logs        — Stream worker container logs
```

### Resource Management

```
GET  /api/v1/resources/status           — Current resource tier + metrics
POST /api/v1/resources/override         — Override resource tier manually
GET  /api/v1/resources/thresholds       — Get current thresholds
PUT  /api/v1/resources/thresholds       — Update thresholds
```

### SSE Event Stream

```
GET  /api/v1/stream/{target_id}         — SSE stream for target events
```

Events pushed to the stream:
- `worker_queued` — Worker enqueued for target
- `worker_started` — Worker container picked up the target
- `worker_complete` — Worker finished successfully
- `worker_failed` — Worker encountered an error
- `worker_skipped` — Worker skipped (no credentials, etc.)
- `stage_started` — Pipeline stage started within a worker
- `stage_complete` — Pipeline stage completed
- `finding` — New vulnerability discovered
- `escalated_access` — Escalated access detected
- `target_expanded` — Child targets created

---

## Campaign Creation Flow

```
1. User submits campaign via dashboard:
   - Seed target domains
   - Scope configuration (in-scope patterns, out-of-scope patterns)
   - Tester Credentials (optional)
   - Testing User (optional, required if Tester Credentials provided)
   - Rate limit settings

2. Orchestrator creates:
   - Campaign record in database
   - Target records for each seed domain
   - Credential config files in shared/config/{target_id}/
   - Scope config files in shared/config/{target_id}/

3. Orchestrator enqueues seed targets:
   - Each seed target pushed to info_gathering_queue:critical
   - JobState records created with status "queued"

4. Event engine takes over:
   - Poll cycle detects queued info_gathering jobs
   - Ensures info_gathering worker container is running
   - Worker picks up target, runs pipeline
   - On completion, event engine evaluates next dependencies
   - TargetExpander creates child targets
   - Cycle continues until all workers complete for all targets
```
