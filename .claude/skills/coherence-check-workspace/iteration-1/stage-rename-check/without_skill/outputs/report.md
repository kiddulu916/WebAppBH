# Stage Rename Coherence Check Report

**Task:** Rename `enumerate_applications` → `map_application_endpoints` in `workers/info_gathering/pipeline.py`  
**Date:** 2026-05-16  
**Method:** Manual search (no skill used)

---

## Executive Summary

The rename **did NOT propagate consistently**. The new name `map_application_endpoints` appears **nowhere** in the codebase except the eval definition file. The pipeline itself still uses `enumerate_applications`. Every other file in the codebase (playbooks, tests, dashboard, orchestrator seed data) also uses `enumerate_applications` — meaning the pipeline is internally consistent with the rest of the system under the old name, but the stated rename has not actually been applied anywhere.

---

## Search Results

### New name (`map_application_endpoints`)

| File | Occurrences | Notes |
|------|-------------|-------|
| `.claude/skills/coherence-check/evals/evals.json` | 1 | Only in the eval prompt definition — not real code |

**Conclusion: `map_application_endpoints` does not exist in any real source file.**

### Old name (`enumerate_applications`)

| File | Line(s) | Context |
|------|---------|---------|
| `workers/info_gathering/pipeline.py` | 78 | `Stage(name="enumerate_applications", section_id="4.1.4", ...)` — the pipeline definition |
| `shared/lib_webbh/playbooks.py` | 19, 222, 248 | `PIPELINE_STAGES["info_gathering"]` list; two `disabled_stages` lists in `deep_webapp` and `api_focused` playbooks |
| `tests/test_playbooks.py` | 38, 42 | `disabled_stages=["search_engine_recon", "enumerate_applications"]` and assertion |
| `orchestrator/main.py` | 2712 | Test seed data: `"current_phase": "enumerate_applications", "status": "RUNNING"` |
| `shared/config/1/playbook.json` | 25 | Serialized playbook: `"name": "enumerate_applications"` |
| `dashboard/src/lib/worker-stages.ts` | 13 | `{ id: "4", name: "Enumerate Applications", stageName: "enumerate_applications", ... }` |
| `dashboard/src/components/campaign/WorkflowBuilder.tsx` | 28 | Stage name array includes `"enumerate_applications"` |
| `dashboard/e2e/tests/empty-states.spec.ts` | 65 | `getByTestId("flow-monitor-stage-enumerate_applications")` |
| `dashboard/e2e/tests/flows/worker-monitoring.spec.ts` | 32, 69, 89 | Three assertions on `"flow-monitor-stage-enumerate_applications"` |
| `dashboard/e2e/tests/worker-control.spec.ts` | 75 | `toContainText("enumerate_applications")` |
| `dashboard/e2e/tests/workflow-builder.spec.ts` | 78, 79, 80 | `getByTestId` and text assertions for `enumerate_applications` |

---

## Consistency Analysis by Area

### 1. `workers/info_gathering/pipeline.py` — INCONSISTENT WITH STATED RENAME

The pipeline still defines the stage as `enumerate_applications` (line 78). The rename to `map_application_endpoints` has **not been applied**.

### 2. `shared/lib_webbh/playbooks.py` — CONSISTENT WITH PIPELINE (old name)

`PIPELINE_STAGES["info_gathering"]` lists `"enumerate_applications"` at position 4. Two built-in playbooks (`deep_webapp`, `api_focused`) reference it in `disabled_stages`. This matches the pipeline's current state.

**Additional issue noted:** `playbooks.py`'s `PIPELINE_STAGES["info_gathering"]` lists 10 stages but `pipeline.py` defines 12 stages — the stages `aggregate_entry_points` (section 4.1.6) and `review_comments_deep` are present in `pipeline.py` but absent from `PIPELINE_STAGES`. This is a pre-existing drift unrelated to the rename.

### 3. `tests/test_playbooks.py` — CONSISTENT WITH PIPELINE (old name)

Tests reference `enumerate_applications` directly in `disabled_stages` lists and assertions. These pass against the current pipeline/playbook state.

### 4. `orchestrator/main.py` (test seed) — CONSISTENT WITH PIPELINE (old name)

The E2E seed fixture at line 2712 uses `"current_phase": "enumerate_applications"`.

### 5. `shared/config/1/playbook.json` — CONSISTENT WITH PIPELINE (old name)

Serialized playbook config uses `"name": "enumerate_applications"`. This is a persisted artifact that would become stale after any rename.

### 6. `dashboard/src/lib/worker-stages.ts` — CONSISTENT WITH PIPELINE (old name)

`WORKER_STAGES["info_gathering"]` has `stageName: "enumerate_applications"` at index 3.

### 7. `dashboard/src/components/campaign/WorkflowBuilder.tsx` — CONSISTENT WITH PIPELINE (old name)

`DEFAULT_PHASES` array includes `"enumerate_applications"` in the info_gathering tools list.

### 8. `dashboard/e2e/` tests — CONSISTENT WITH PIPELINE (old name)

All four E2E test files reference `enumerate_applications` in `data-testid` selectors and text assertions.

---

## What Would Need to Change If the Rename Were Applied

If `map_application_endpoints` were the intended new name, the following files would all need to be updated:

| File | Change Required |
|------|----------------|
| `workers/info_gathering/pipeline.py` | `Stage(name="map_application_endpoints", ...)` |
| `shared/lib_webbh/playbooks.py` | Update `PIPELINE_STAGES["info_gathering"]` list (line 19); update `disabled_stages` in `deep_webapp` (line 222) and `api_focused` (line 248) |
| `tests/test_playbooks.py` | Update `disabled_stages` arg and set assertion (lines 38, 42) |
| `orchestrator/main.py` | Update seed `"current_phase"` value (line 2712) |
| `shared/config/1/playbook.json` | Regenerate or manually update stage name (line 25) |
| `dashboard/src/lib/worker-stages.ts` | Update `stageName` and `name` for id="4" (line 13) |
| `dashboard/src/components/campaign/WorkflowBuilder.tsx` | Update tools array entry (line 28) |
| `dashboard/e2e/tests/empty-states.spec.ts` | Update `data-testid` selector (line 65) |
| `dashboard/e2e/tests/flows/worker-monitoring.spec.ts` | Update 3 `data-testid` assertions (lines 32, 69, 89) |
| `dashboard/e2e/tests/worker-control.spec.ts` | Update text assertion (line 75) |
| `dashboard/e2e/tests/workflow-builder.spec.ts` | Update `data-testid` and text assertions (lines 78-80) |

---

## Pre-existing Drift (Unrelated to Rename)

One pre-existing inconsistency was identified during this check:

- **`PIPELINE_STAGES` vs `pipeline.py` stage count:** `playbooks.py` lists 10 stages for `info_gathering`; `pipeline.py` defines 12. Missing from `PIPELINE_STAGES`: `aggregate_entry_points` and `review_comments_deep`.
- **`test_playbooks.py` line 26:** `assert len(wc.stages) == 10` — this count assertion would fail if `PIPELINE_STAGES` were updated to include the two missing stages.

---

## Verdict

**The rename is incomplete.** No file actually uses `map_application_endpoints`. The pipeline still uses `enumerate_applications`, and all dependent files (playbooks, tests, dashboard, E2E suite, seed data, persisted config) are in sync with each other under the old name. The codebase is internally consistent as-is, but the stated rename has not been implemented anywhere.
