# Flow Page & Playbook Rebuild Design

**Date:** 2026-05-07
**Scope:** Rebuild the Phase Flow page and update playbook data model to reflect the 18-worker WSTG pipeline architecture.

## Problem

The Phase Flow page (`campaign/flow/page.tsx`) and playbook system (`playbooks.py`) still reference 7 flat recon stages (`passive_discovery`, `active_discovery`, etc.) from the original single-pipeline architecture. The actual system now has 15 pipeline workers + 3 infrastructure workers, each with WSTG-aligned internal stages and a dependency graph between them.

## Playbook Data Model

### Current (flat)

```python
PlaybookConfig:
  name: str
  description: str
  stages: list[StageConfig]          # 7 flat recon stages
  concurrency: ConcurrencyConfig
```

### New (hierarchical)

```python
StageConfig:
  name: str
  enabled: bool = True
  tool_timeout: int = 600

WorkerConfig:
  name: str
  enabled: bool = True
  stages: list[StageConfig]
  concurrency: ConcurrencyConfig

PlaybookConfig:
  name: str
  description: str
  workers: list[WorkerConfig]        # 15 pipeline workers
```

Infrastructure workers (`proxy`, `callback`, `sandbox_worker`) are excluded from playbooks — they are always-on.

A helper `build_worker_config(worker_name, ...)` generates a `WorkerConfig` with all stages enabled by default, allowing selective disabling.

## Built-in Playbooks

All 4 playbooks explicitly list all 15 pipeline workers. Stage names come from each worker's pipeline definition.

### wide_recon

Full pipeline, every worker and stage enabled. High concurrency (`heavy=2, light=8`). The "run everything" default for large targets with unknown surface area.

### deep_webapp

All workers enabled except `mobile_worker` (disabled). Within `info_gathering`, disables `search_engine_recon` and `enumerate_subdomains` (assumes target scope is already known). Bumps concurrency on `input_validation` and `session_mgmt` workers (`heavy=3, light=6`). Designed for a known web app where you want thorough coverage without mobile or broad recon overhead.

### api_focused

Disables `client_side`, `mobile_worker`, and `session_mgmt`. Within `info_gathering`, only enables `web_server_fingerprint`, `identify_entry_points`, `map_execution_paths`, and `map_application` (the 4 stages most relevant to API surface mapping). Keeps `input_validation` fully enabled (API fuzzing is the core value). Lower concurrency (`heavy=1, light=4`) since API targets are typically single-host.

### cloud_first

All workers enabled. Within `config_mgmt`, bumps `cloud_storage` and `api_discovery` tool timeouts to 900s. Higher concurrency on `info_gathering` (`heavy=3, light=8`). Designed for targets with significant cloud infrastructure.

All four playbooks include `reasoning_worker`, `chain_worker`, and `reporting` — always-on tail-end workers.

## Flow Page Layout

Two-panel split (same structure as current), with Gantt timeline at bottom.

### Left Panel: Playbook Configurator

**Playbook selector** — Dropdown (wide_recon, deep_webapp, api_focused, cloud_first, plus custom). Selection populates the worker tree.

**Worker tree** — Collapsible cards in dependency order. Each card shows:
- Worker name (e.g., `info_gathering`)
- Toggle switch (enable/disable entire worker)
- Stage count badge (e.g., `7/10` enabled)
- Expand chevron

Expanded view shows individual stages with toggle + tool timeout slider. Stage rows show section ID in muted text (e.g., `INFO-01`).

**Dependency awareness** — Disabling a worker auto-disables downstream dependents (muted + "blocked by: {worker}" label). Uses `WORKER_DEPENDENCIES` from `schema.ts`. Re-enabling the upstream worker restores them.

**Action buttons** — "Save as Custom Playbook" and "Apply to Target". Serializes the full worker->stage tree.

`DEFAULT_STAGES` constant is removed.

### Right Panel: Execution Monitor

**Worker progress cards** — Each worker shows:
- Name + status icon (pending/queued/running/completed/failed/skipped)
- Progress bar (e.g., `4/10 stages`) for running workers
- Currently executing tool name
- Expand chevron -> individual stage entries with status

**Behavior:**
- Dependency order listing
- Completed workers auto-collapse
- Skipped workers show muted with skip reason
- Failed workers stay expanded with error visible
- 10-second polling interval (unchanged)

**Gantt timeline** — `ScanTimeline` at bottom, unchanged.

## TypeScript Types

```typescript
interface WorkerConfig {
  name: string;
  enabled: boolean;
  stages: StageConfig[];
  concurrency: { heavy: number; light: number };
}

// PlaybookRow: stages -> workers
interface PlaybookRow {
  name: string;
  description: string;
  builtin: boolean;
  workers: WorkerConfig[];
}

interface WorkerExecution {
  name: string;
  status: "pending" | "queued" | "running" | "completed" | "failed" | "skipped";
  stages: StageExecution[];
  current_tool?: string;
  error?: string;
  skip_reason?: string;
}

// ExecutionState: stages -> workers
interface ExecutionState {
  playbook: string;
  workers: WorkerExecution[];
}
```

Stage display names sourced from `WORKER_STAGES` in `worker-stages.ts` (already correct).

## Files Changed

### Backend
1. `shared/lib_webbh/playbooks.py` — New data model + 4 rebuilt playbooks
2. `orchestrator/main.py` — Update playbook CRUD + `/execution` response shape

### Frontend
3. `dashboard/src/lib/api.ts` — Update `PlaybookRow`, add `WorkerConfig`, update `ExecutionState`
4. `dashboard/src/types/schema.ts` — Add `WorkerExecution` type
5. `dashboard/src/app/campaign/flow/page.tsx` — Full rewrite

### Unchanged
- `worker-stages.ts` — Already correct
- `PipelineGrid.tsx` — Separate C2 component
- `schema.ts` WORKER_DEPENDENCIES — Already correct
- Individual worker `pipeline.py` files — Stage definitions already exist

## Build Order

Backend first (playbooks model -> orchestrator endpoints), then frontend (types -> API -> page rewrite).
