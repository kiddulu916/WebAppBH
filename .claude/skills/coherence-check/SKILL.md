---
name: coherence-check
description: Cross-layer coherence checker for the WebAppBH bug bounty framework. Runs in two modes: (1) change-focused — use after /simplify and before code review to verify recent changes ripple correctly through all layers; (2) full-scan — standalone codebase audit that hunts for any inconsistencies across all 18 workers, shared library, orchestrator, and dashboard without relying on a git diff. Triggers on: "coherence check", "check coherence", "run a coherence check", "scan the codebase for inconsistencies", "check everything is consistent", "verify everything is wired up", "make sure everything lines up", "cross-layer check", "verify integration", "audit the framework", or automatically before code review after /simplify. Applies fixes for unambiguous mismatches and produces a structured report of everything that needs attention.
---

# Framework Coherence Check

You are performing a thorough cross-layer coherence verification of the WebAppBH bug bounty framework. The framework has four tightly coupled layers: **workers**, **shared library (lib_webbh)**, **orchestrator**, and **dashboard**. Your job: find every break across all of them, fix what is unambiguous, and report everything else.

---

## Phase 0 — Choose Mode

Before doing anything else, determine which mode to run:

**Mode A — Change-focused** (triggered before code review, or when the user describes a specific change):
> "I just added X", "I renamed Y", "I refactored Z", invoked as part of the pre-commit ritual.
→ Proceed to **Phase 1** (git diff → ripple outward).

**Mode B — Full-scan** (standalone audit, no specific change described):
> "run a coherence check", "scan the codebase", "check everything", no change mentioned.
→ Skip to **Phase 1B** (iterate all 18 workers and all cross-layer contracts).

---

## Phase 1 — Discover What Changed (Mode A only)

Run all of these to understand the full scope of recent changes:

```bash
git diff HEAD~1 --name-only
git diff HEAD~1 --stat
git diff HEAD~1
git log --oneline -10
git diff --name-only          # unstaged
git diff --cached --name-only # staged
```

Read the full diff carefully — not just file names. Understand *what* changed within each file (new method, renamed field, added stage, removed import). Then proceed to **Phase 2**.

Categorize every changed file into its layer(s):

| Layer | Paths |
|-------|-------|
| **Worker** | `workers/<name>/tools/*.py`, `workers/<name>/pipeline.py`, `workers/<name>/base_tool.py`, `workers/<name>/concurrency.py`, `workers/<name>/main.py` |
| **Shared lib** | `shared/lib_webbh/*.py`, `shared/lib_webbh/__init__.py`, `shared/schema.sql`, `shared/models.py` |
| **Orchestrator** | `orchestrator/*.py`, `orchestrator/routes/*.py` |
| **Dashboard** | `dashboard/src/**/*.tsx`, `dashboard/src/**/*.ts`, `dashboard/e2e/**/*.ts` |

---

## Phase 1B — Full-Scan Checklist (Mode B only)

Work through every active worker and every cross-layer contract. Run checks in parallel where possible.

### Per-worker checks (repeat for all 18 active workers)

For each worker in: `info_gathering`, `identity_mgmt`, `authentication`, `authorization`, `session_mgmt`, `input_validation`, `error_handling`, `cryptography`, `business_logic`, `client_side`, `config_mgmt`, `chain_worker`, `mobile_worker`, `reporting_worker`, `reasoning_worker`, `sandbox_worker`, `proxy`, `callback`:

1. Read `workers/<W>/pipeline.py` — extract all stage names.
2. Read `shared/lib_webbh/playbooks.py` `PIPELINE_STAGES[<W>]` — compare counts and names. Every stage name in `pipeline.py` must appear verbatim in playbooks.
3. For `info_gathering` only: do any two sequential stages share a `section_id`? → auto-fix (see Phase 4).
4. Does every tool class referenced in pipeline stages exist as a file in `workers/<W>/tools/`?
5. Grep `workers/<W>/tools/*.py` for `from lib_webbh import` lines — verify every imported symbol exists in `shared/lib_webbh/__init__.py`.
6. Read `workers/<W>/concurrency.py` — do `TOOL_WEIGHTS` entries match actual tool files in `tools/`?
7. Read `workers/<W>/main.py` — does the queue name consumed match `<worker_name>_queue`?
8. Grep `tests/` for assertions that hardcode stage counts for this worker (e.g., `len(wc.stages) == N` or `== N` near stage variables) — verify N matches the actual current stage count.

### Cross-layer contract checks

**ORM vs SQL (run for every model):**
- Read all ORM models in `shared/lib_webbh/database.py`.
- Read the corresponding table definitions in `shared/schema.sql`.
- Flag any column present in the ORM but missing from the DDL, or vice versa.

**TypeScript interfaces:**
- Read `shared/interfaces.ts` — do field names match ORM model columns for `Asset`, `Vulnerability`, `JobState`, `Target`, `Campaign`, and any other exported interface?
- Read `dashboard/src/types/schema.ts` — same check.
- The most complete definition for a type wins; stale interfaces must be updated.

**Orchestrator queue contracts:**
- Grep `orchestrator/event_engine.py` for all `push_task` / `push_priority_task` calls — extract stream names.
- Grep all worker `main.py` files for `listen_queue` / `listen_priority_queues` calls — extract stream names.
- Every pushed stream must have a consumer. Every consumer must have a pusher.

**Dashboard stage references:**
- Read `dashboard/src/lib/worker-stages.ts` — extract all `stageName` values per worker.
- Compare against current `pipeline.py` stage names for each worker. Flag mismatches.
- Read `dashboard/src/components/campaign/WorkflowBuilder.tsx` — extract stage name arrays. Verify against playbooks.

**E2E test stage names:**
- Grep `dashboard/e2e/` for `data-testid` values containing stage names (pattern: `flow-monitor-stage-<name>`).
- Verify each stage name in those selectors still exists in the corresponding `pipeline.py`.

After building this checklist, proceed directly to **Phase 3**.

---

## Phase 2 — Build the Ripple Map (Mode A only)

For each changed file, trace every downstream contract it could affect. Follow each chain until you reach a dead end — do not stop at one hop.

### Worker tool changed (`workers/<W>/tools/<tool>.py`)
1. Does the tool class appear in `workers/<W>/pipeline.py` in the correct stage's `tools` list?
2. Does every `lib_webbh` symbol imported in this tool exist in `shared/lib_webbh/__init__.py` under that exact name?
3. Does every DB model field written or read by this tool exist in `shared/lib_webbh/database.py` under that exact field name?
4. Does `shared/schema.sql` contain the corresponding column for every field used?
5. Does the `WeightClass` assigned to this tool in `workers/<W>/concurrency.py` match its actual resource profile (HEAVY for subprocess-intensive, LIGHT for lightweight)?
6. If this tool writes findings (`Vulnerability`, `ChainFinding`, `Observation`, etc.), do the field names match what `chain_worker` or `reasoning_worker` expects to consume?
7. Do any E2E tests in `dashboard/e2e/` reference stage names that include this tool — and do those names still match `pipeline.py`?
8. Grep `tests/` for stage count assertions (`len(wc.stages) == N`) — verify N still matches if new stages were added.

### Worker pipeline changed (`workers/<W>/pipeline.py`)
1. Does every `Stage.name` appear verbatim in `shared/lib_webbh/playbooks.py` under `PIPELINE_STAGES[<worker>]`?
2. For `info_gathering`: does every `Stage` have a `section_id` in `"4.X.Y"` format? Other workers do NOT use `section_id`.
3. Do any two sequential stages share the same `section_id`? → auto-fix with `a`/`b` suffix (see Phase 4).
4. Does every tool class referenced in stage `tools` lists exist in `workers/<W>/tools/`?
5. Does `workers/<W>/main.py` consume from `<worker_name>_queue`?
6. Do dashboard components rendering stage progress reference the current stage names?
7. Do E2E seed fixtures set `current_phase` to a value matching a current stage name?
8. Did stage order change? Does `playbooks.py` reflect the new order?
9. Grep `tests/` for hardcoded stage count assertions — update them to match the new count.

### Worker base_tool changed (`workers/<W>/base_tool.py`)
1. Do all tool subclasses in `workers/<W>/tools/` still satisfy the updated base class interface?
2. `InfrastructureMixin` belongs on auth-heavy workers only — NOT on `InfoGatheringTool`. Verify.
3. If scope-check or subprocess patterns changed: verify all subclasses still call the correct methods.

### Worker main.py changed (`workers/<W>/main.py`)
1. Does the queue name match what `orchestrator/event_engine.py` pushes to?
2. Does the consumer group name follow `<worker_name>-group`?
3. If heartbeat logic changed, does it still update `job_state.last_seen` correctly?

### Worker concurrency.py changed (`workers/<W>/concurrency.py`)
1. Do all tool classes in `TOOL_WEIGHTS` still exist in `workers/<W>/tools/`?
2. Are `HEAVY_CONCURRENCY` / `LIGHT_CONCURRENCY` env var names consistent with other workers?

### Shared lib changed (`shared/lib_webbh/*.py`)

**`__init__.py` changes:**
1. For every symbol renamed or removed: grep all 18 workers, orchestrator, and dashboard. Update every reference.
2. For every new export added: verify the implementation exists in the correct module file.

**`database.py` changes:**
1. For every field added, renamed, or removed: grep all workers and orchestrator for the old field name.
2. Do ORM columns in `database.py` match `shared/schema.sql` for the same table?
3. Do dashboard TypeScript interfaces reference these field names — update if so.

**`playbooks.py` changes:**
1. For every stage name changed: grep all worker `pipeline.py` files — `Stage(name=...)` must match exactly.
2. Does stage order in playbooks match the order in each worker's `pipeline.py`?

**`messaging.py` changes:**
1. For every stream name changed: grep all workers' `main.py` and orchestrator's `event_engine.py`.
2. Do SSE event type strings match what the dashboard SSE handler expects?

**Any other helper module changed:**
1. Grep all workers, orchestrator, and dashboard for usages of the changed API surface.

### Orchestrator changed (`orchestrator/*.py`, `orchestrator/routes/*.py`)

**Route path changed:**
1. Grep `dashboard/src/` for hardcoded fetch URLs referencing the old path. Update them.

**Response shape changed:**
1. Do dashboard components consuming this endpoint use the new field names?
2. Does `shared/interfaces.ts` need updating?

**`event_engine.py` changed (new worker push):**
1. Does the target worker have a consumer for this stream in `main.py`?
2. Does `orchestrator/dependency_map.py` reflect updated execution order?

**`worker_manager.py` changed:**
1. Docker container names use hyphens. Redis queues use underscores. Python modules use underscores. Verify.

### Dashboard changed (`dashboard/src/**`)

**API calls changed:**
1. Does the target route exist in the orchestrator at that exact path and method?
2. Does the response shape match what the component destructures?

**SSE event handling changed:**
1. Does a worker publish the event type the dashboard listens for on `events:{target_id}`?

**`data-testid` changed:**
1. Grep `dashboard/e2e/` for the old testid — update all references.

**TypeScript type / interface changed:**
1. Do field names match actual DB model fields in `database.py` and what the orchestrator serializes?
2. Check all components that import and use this type.

**Zustand store changed:**
1. Does the store field get populated from the correct API response or SSE event field?

### DB model changed (`database.py` or `schema.sql`)
1. Are both in sync — same table, same columns, compatible types?
2. Grep all 18 workers for uses of the changed model.
3. Grep orchestrator routes for uses of the changed model.
4. Check `shared/interfaces.ts` and dashboard TypeScript types.

---

## Phase 3 — Execute the Checks

Work through your checklist (from Phase 1B or Phase 2). For each check:

1. **Search** — use Grep with exact symbol, field name, stage name, or path. Don't assume — verify.
2. **Assess** — genuine mismatch, or code correct as-is?
3. **Classify** — auto-fixable or needs human review?

Run all independent checks in parallel. Serialize only when one finding determines what to search for next.

### Baseline searches (both modes, every session)

```
# Stage name drift — most common issue
For each active worker: grep pipeline.py for Stage(name=) values.
Grep playbooks.py PIPELINE_STAGES[worker] for those exact strings.
Flag any stage name in pipeline.py not in playbooks, or playbooks count != pipeline count.

# Stage count assertion staleness
Grep tests/ for "len(wc.stages) ==" or "len(stages) ==" patterns.
Verify the asserted count matches the current pipeline.py stage count for each worker.

# Queue name drift
Grep all main.py files for listen_queue / listen_priority_queues arguments.
Grep orchestrator/event_engine.py for push_task / push_priority_task arguments.
Every listened queue must be pushed by the orchestrator. Every pushed queue must have a consumer.

# Import drift
Grep all workers for "from lib_webbh import" lines.
Compare to shared/lib_webbh/__init__.py exports.
Flag any imported name not in __init__.py.

# DB field drift
For every ORM model touched: read the class in database.py, read the table in schema.sql.
Compare column sets. Flag any column in ORM missing from DDL or vice versa.

# Container name consistency
Grep orchestrator/ for worker container/service references.
Docker names → hyphens. Redis queue names → underscores. Python modules → underscores.
```

---

## Phase 4 — Fix What You Can

Apply fixes only for unambiguous, low-risk mismatches:

**Auto-fix these:**
- Missing stage name in `playbooks.py` `PIPELINE_STAGES` — add it matching `pipeline.py` `Stage.name` exactly, in the correct position
- **Duplicate `section_id` on sequential stages** — when two separate `Stage` objects in `pipeline.py` share the same `section_id` string, rename them: the stage that appears first in the list gets `Xa` suffix, the later one gets `Xb` (e.g., both at `"4.1.6"` → `"4.1.6a"` and `"4.1.6b"`; both at `"4.1.5"` → `"4.1.5a"` and `"4.1.5b"`). Do NOT apply to tools within the same stage — that is concurrent execution, not sequential, and should be flagged for review instead.
- Stale import name in a worker — rename to match current `__init__.py` export
- Stale `data-testid` in an E2E test — update to match the component attribute
- Missing tool class in a pipeline stage's `tools` list — add it if the tool file clearly belongs there
- `schema.sql` column missing that exists in the ORM model — add the column with the correct type
- Wrong queue name constant in `main.py` — fix to match `event_engine.py`
- Stale stage count in a test assertion (`len(wc.stages) == N`) — update N to match current `pipeline.py` stage count
- Missing stage name in dashboard `worker-stages.ts` — add it matching pipeline.py stage name and order
- Missing stage name in `WorkflowBuilder.tsx` stage arrays — add it in the correct position

**Do NOT auto-fix — report for human review:**
- Any DB schema change that requires an Alembic migration (note it as a migration needed)
- Business logic changes inside worker tool `execute()` methods
- Changes to orchestrator route contracts affecting multiple consumers
- Anything requiring design judgment about which layer "owns" the correct value
- Removals of any kind (fields, stages, routes) — removing can break downstream consumers silently
- Two tools within the same pipeline stage sharing a `section_id` — this is concurrent execution, needs design review

For every fix: `FIXED: <what> → <file>:<line>`

---

## Phase 5 — Structured Report

```
## Coherence Check Report
Mode: [Change-focused (N changed files across layers) | Full-scan (all 18 workers)]
Checks performed: <N>
Issues: <N total> — <M auto-fixed>, <K need manual review>

### Auto-Fixed
- [FIXED] <description> — `<file>:<line>`

### Needs Manual Review
- [MISMATCH] <clear description of what doesn't align>
  Found:    `<actual value in file A>` (`<fileA>:<line>`)
  Expected: `<value that file B requires>` (`<fileB>:<line>`)

### Verified Clean
- <layer or specific component/file> — contracts consistent

### Coverage
Checked: <list of all files and components actually inspected>
```

If there are zero issues, say so explicitly.

---

## Framework Reference

### Active workers (18)
`info_gathering`, `identity_mgmt`, `authentication`, `authorization`, `session_mgmt`, `input_validation`, `error_handling`, `cryptography`, `business_logic`, `client_side`, `config_mgmt`, `chain_worker`, `mobile_worker`, `reporting_worker`, `reasoning_worker`, `sandbox_worker`, `proxy`, `callback`

Do NOT touch `workers/reporting/` — legacy stub. The real implementation is `workers/reporting_worker/`.

### Naming conventions
| Context | Convention | Example |
|---------|-----------|---------|
| Docker container / service | hyphen | `info-gathering` |
| Redis queue / stream | underscore | `info_gathering_queue` |
| Python module / directory | underscore | `workers/info_gathering/` |
| Stage name (pipeline + playbooks) | underscore | `"enumerate_applications"` |

### Worker Stage shape
- `info_gathering`: `Stage(name="...", section_id="4.X.Y", tools=[...])` — requires `section_id`
- All other workers: `Stage("stage_name", [ToolClass])` — no `section_id`

### Sequential vs concurrent stage execution
- **Sequential**: two separate `Stage` objects in the `pipeline.py` stages list — run one after the other
- **Concurrent**: multiple tool classes in the same `Stage`'s `tools` list — run via `asyncio.gather`
- Duplicate `section_id` on sequential stages → auto-fix with `a`/`b` suffix
- Duplicate `section_id` on concurrent tools within one stage → flag for design review

### InfrastructureMixin
Used on auth-heavy workers' `base_tool.py`. NOT on `InfoGatheringTool`. Never add it there.

### CheckpointMixin
Pipelines resume via `job_state.current_phase` / `_get_resume_stage()`. Stage name drift silently restarts from stage 0 instead of resuming.

### lib_webbh canonical import
Always verify against `shared/lib_webbh/__init__.py` before referencing any symbol. The in-module name may differ from the exported name.

### E2E seed
`ENABLE_TEST_SEED=true` activates `/api/v1/test/seed`. The `current_phase` in seed data must match an actual stage name from `pipeline.py`.
