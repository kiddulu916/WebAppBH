## Coherence Check Report

**Task:** Hypothetical rename of `enumerate_applications` -> `map_application_endpoints` in `workers/info_gathering/pipeline.py`

Changed files: 0 confirmed by git diff (the rename is **hypothetical** — no such change exists in any commit or working tree diff). Phase 1 adapted: the task prompt is treated as the change description, and all downstream layers are traced as if the rename had been applied only in `pipeline.py`.

Checks performed: 14
Issues: 9 total — 0 auto-fixed (rename is hypothetical; no safe auto-fix without the real change applied to pipeline.py first), 9 need manual review

---

### Auto-Fixed

_(None — the rename has not actually been applied to any file. All issues below describe what would break if the rename were made only in `pipeline.py` without updating downstream layers.)_

---

### Needs Manual Review

- [MISMATCH] `pipeline.py` STAGES list vs. `playbooks.py` PIPELINE_STAGES registry
  Found:    `Stage(name="enumerate_applications", ...)` (`workers/info_gathering/pipeline.py:78`)
  Expected: entry `"map_application_endpoints"` in `PIPELINE_STAGES["info_gathering"]` (`shared/lib_webbh/playbooks.py:19`)
  — `playbooks.py` still contains `"enumerate_applications"` at position 4. After the rename the stage filter (`_filter_stages`) would silently drop the renamed stage from every playbook-driven run because the new name would not appear in `enabled_names`. Playbook-gated pipelines would skip the subdomain/vhost/port/CT-log enumeration step entirely with no error.

- [MISMATCH] `playbooks.py` built-in playbook preset references old name
  Found:    `"disabled_stages": ["search_engine_recon", "enumerate_applications"]` (`shared/lib_webbh/playbooks.py:222`)
  Expected: `"map_application_endpoints"` in the same list after the rename
  — The `deep_webapp` preset explicitly disables `enumerate_applications`. After the rename the preset would no longer match any stage name, effectively re-enabling enumeration in all deep_webapp campaign runs — a silent behavior change.

- [MISMATCH] Dashboard TypeScript worker-stages definition
  Found:    `stageName: "enumerate_applications"` (`dashboard/src/lib/worker-stages.ts:13`)
  Expected: `stageName: "map_application_endpoints"`
  — The WORKER_STAGES constant drives campaign overview and C2 console progress indicators. SSE `STAGE_COMPLETE` events would carry the new stage name; the dashboard would fail to match them to this stage progress indicator, leaving it perpetually unhighlighted.

- [MISMATCH] Dashboard WorkflowBuilder hardcoded stage list
  Found:    `"enumerate_applications"` in `DEFAULT_PHASES[0].tools` (`dashboard/src/components/campaign/WorkflowBuilder.tsx:28`)
  Expected: `"map_application_endpoints"`
  — WorkflowBuilder renders a toggle per stage name. A name mismatch means the toggle silently has no effect (it sends the old string to the playbook config, which no longer matches any real stage).

- [MISMATCH] Playwright E2E test data-testid selectors (5 occurrences)
  Found:    `getByTestId("flow-monitor-stage-enumerate_applications")` in:
    - `dashboard/e2e/tests/empty-states.spec.ts:65`
    - `dashboard/e2e/tests/flows/worker-monitoring.spec.ts:32`
    - `dashboard/e2e/tests/flows/worker-monitoring.spec.ts:69`
    - `dashboard/e2e/tests/flows/worker-monitoring.spec.ts:89`
    - `dashboard/e2e/tests/workflow-builder.spec.ts:78`
  Expected: `getByTestId("flow-monitor-stage-map_application_endpoints")`
  — All five selectors would not find their targets after the rename, producing false-negative E2E failures.

- [MISMATCH] Playwright E2E test status testid selector
  Found:    `getByTestId("flow-monitor-status-enumerate_applications")` (`dashboard/e2e/tests/workflow-builder.spec.ts:80`)
  Expected: `getByTestId("flow-monitor-status-map_application_endpoints")`

- [MISMATCH] Playwright E2E test text content assertion
  Found:    `.toContainText("enumerate_applications")` (`dashboard/e2e/tests/worker-control.spec.ts:75`)
  Expected: `.toContainText("map_application_endpoints")`
  — Worker-control spec asserts the running card displays the current stage name. After the rename this assertion would fail.

- [MISMATCH] Orchestrator test-seed fixture references old stage name
  Found:    `"current_phase": "enumerate_applications", "status": "RUNNING"` (`orchestrator/main.py:2712`)
  Expected: `"current_phase": "map_application_endpoints"`
  — After the rename the pipeline STAGE_INDEX lookup would not find a matching entry and `_get_resume_stage()` would silently restart from stage 0 instead of resuming from this stage.

- [MISMATCH] `tests/test_playbooks.py` assertions reference old stage name
  Found:    `disabled_stages=["search_engine_recon", "enumerate_applications"]` (`tests/test_playbooks.py:38`)
            `assert {s.name for s in disabled} == {"search_engine_recon", "enumerate_applications"}` (`tests/test_playbooks.py:42`)
  Expected: `"map_application_endpoints"` in both lines after the rename is fully propagated

---

### Additional Pre-existing Drift Found (Not Caused by the Proposed Rename)

- [MISMATCH] `pipeline.py` has 12 stages; `playbooks.py` PIPELINE_STAGES["info_gathering"] lists only 10.
  Stages present in `pipeline.py` (workers/info_gathering/pipeline.py:72-99):
    search_engine_recon, web_server_fingerprint, web_server_metafiles, enumerate_applications,
    review_comments, identify_entry_points, aggregate_entry_points, map_execution_paths,
    review_comments_deep, fingerprint_framework, map_architecture, map_application
  Stages in `playbooks.py` (shared/lib_webbh/playbooks.py:17-22):
    search_engine_recon, web_server_fingerprint, web_server_metafiles, enumerate_applications,
    review_comments, identify_entry_points, map_execution_paths, fingerprint_framework,
    map_architecture, map_application
  Missing from playbooks.py: `aggregate_entry_points`, `review_comments_deep`
  — These stages cannot be selectively enabled/disabled via playbook config; CheckpointMixin
    resume cannot correctly skip them from a saved current_phase value.

- [MISMATCH] `worker-stages.ts` lists `review_comments_deep` but `playbooks.py` does not register it.
  Found:    `stageName: "review_comments_deep"` (`dashboard/src/lib/worker-stages.ts:15`)
  Expected: entry in `PIPELINE_STAGES["info_gathering"]` — absent (`shared/lib_webbh/playbooks.py:17-22`)
  — Dashboard progress tracking for this stage is wired to a name the playbook layer does not know about.

---

### Verified Clean

- `workers/info_gathering/pipeline.py` — `enumerate_applications` has `section_id="4.1.4"`, correct tools list (Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns, VHostProber, Naabu, AppPathEnumerator, CTLogSearcher), all imports present.
- Queue name consistency — stage name rename does not affect `info_gathering_queue` conventions.
- `lib_webbh/__init__.py` — no import contract is affected by a stage name rename.
- `shared/schema.sql` / `database.py` — `job_state.current_phase` is TEXT; no DDL or ORM migration needed for a rename (only in-flight row data migration).
- `tests/e2e/test_worker_pipelines.py` — no reference to `enumerate_applications` or the proposed new name; clean.

---

### Summary Table: Files That Must Change for the Rename to Be Coherent

| File | Required Change |
|------|----------------|
| `workers/info_gathering/pipeline.py` | Rename Stage name to "map_application_endpoints" (the proposed change itself) |
| `shared/lib_webbh/playbooks.py` | Update PIPELINE_STAGES["info_gathering"] (line 19) and deep_webapp preset disabled_stages (line 222) |
| `dashboard/src/lib/worker-stages.ts` | Update stageName at line 13 |
| `dashboard/src/components/campaign/WorkflowBuilder.tsx` | Update DEFAULT_PHASES[0].tools at line 28 |
| `dashboard/e2e/tests/empty-states.spec.ts` | Update testid selector at line 65 |
| `dashboard/e2e/tests/flows/worker-monitoring.spec.ts` | Update testid selectors at lines 32, 69, 89 |
| `dashboard/e2e/tests/workflow-builder.spec.ts` | Update testid selectors at lines 78, 80 |
| `dashboard/e2e/tests/worker-control.spec.ts` | Update text assertion at line 75 |
| `orchestrator/main.py` | Update test-seed current_phase at line 2712 |
| `tests/test_playbooks.py` | Update disabled_stages strings and assertion set at lines 38, 42 |

---

### Coverage

Files actually inspected:
- workers/info_gathering/pipeline.py — full file read; all 12 STAGES entries catalogued
- shared/lib_webbh/playbooks.py — PIPELINE_STAGES["info_gathering"] (lines 17-22); preset disabled_stages (lines 222, 248)
- dashboard/src/lib/worker-stages.ts — full file; all info_gathering stageName entries
- dashboard/src/components/campaign/WorkflowBuilder.tsx — DEFAULT_PHASES[0].tools (line 28)
- dashboard/e2e/tests/empty-states.spec.ts — line 65
- dashboard/e2e/tests/flows/worker-monitoring.spec.ts — lines 32, 69, 89
- dashboard/e2e/tests/worker-control.spec.ts — line 75
- dashboard/e2e/tests/workflow-builder.spec.ts — lines 78-80
- orchestrator/main.py — line 2712 (test-seed current_phase)
- tests/test_playbooks.py — lines 38, 42
- tests/e2e/test_worker_pipelines.py — scanned for enumerate_applications (none found; clean)
- Git log and diff — confirmed rename is hypothetical (last 10 commits contain no such rename)
