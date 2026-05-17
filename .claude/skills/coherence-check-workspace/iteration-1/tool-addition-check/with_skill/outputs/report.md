## Coherence Check Report
Changed files: 7 across [worker (tools), tests]
Checks performed: 28
Issues: 6 total — 4 auto-fixed, 2 need manual review

---

### Auto-Fixed

- [FIXED] `aggregate_entry_points` missing from `PIPELINE_STAGES["info_gathering"]` in playbooks — added after `identify_entry_points` and before `map_execution_paths` — `shared/lib_webbh/playbooks.py:19`

- [FIXED] `review_comments_deep` missing from `PIPELINE_STAGES["info_gathering"]` in playbooks — added after `map_execution_paths` and before `fingerprint_framework` — `shared/lib_webbh/playbooks.py:20`

- [FIXED] `aggregate_entry_points` missing from `WORKER_STAGES["info_gathering"]` in dashboard stage definitions — inserted as id "7" after `identify_entry_points`; `review_comments_deep` order corrected to id "9" (after `map_execution_paths`, matching pipeline order) — `dashboard/src/lib/worker-stages.ts:6-12`

- [FIXED] `aggregate_entry_points` missing from `DEFAULT_PHASES` tools list for `info_gathering` in WorkflowBuilder; `review_comments_deep` order corrected to appear after `map_execution_paths` — `dashboard/src/components/campaign/WorkflowBuilder.tsx:28-30`

---

### Needs Manual Review

- [MISMATCH] Duplicate `section_id` on two distinct pipeline stages. Both `identify_entry_points` and `aggregate_entry_points` are assigned `section_id="4.1.6"`. The pipeline's `_STAGE7_SECTION` constant (value `"4.1.7"`) gates the `ExecutionPathAnalyzer` post-stage invocation; the 4.1.6 collision is harmless today, but any future gate on 4.1.6 will fire for both stages. Design decision needed: should `aggregate_entry_points` keep `section_id="4.1.6"` (it consolidates INFO-06 data) or get its own sub-id?
  Found:    `Stage(name="aggregate_entry_points", section_id="4.1.6", ...)` (`workers/info_gathering/pipeline.py:90`)
  Expected: Unique section_id per stage, or explicit documented intent that INFO-06 has two sub-stages sharing the same id (`workers/info_gathering/pipeline.py:89-90`)

- [MISMATCH] `review_comments_deep` re-runs the identical tool set as `review_comments` (same five tools: `CommentHarvester`, `MetadataExtractor`, `JsSecretScanner`, `SourceMapProber`, `RedirectBodyInspector`) with the same `section_id="4.1.5"`. No guard, config knob, or intensity parameter differentiates the two runs — both execute identically against the same target state, silently doubling cost.
  Found:    `Stage(name="review_comments_deep", section_id="4.1.5", tools=[CommentHarvester, MetadataExtractor, JsSecretScanner, SourceMapProber, RedirectBodyInspector])` (`workers/info_gathering/pipeline.py:92-95`)
  Expected: Differentiated behavior from `review_comments` stage (e.g., depth/intensity param or playbook-flag gate) (`workers/info_gathering/pipeline.py:85-88`)

---

### Verified Clean

- **Worker tool — `websocket_prober.py`**: Correctly subclasses `InfoGatheringTool`. All `lib_webbh` imports (`Asset`, `get_session`) verified in `shared/lib_webbh/__init__.py`. No `shell=True`. `scope_check` called before probing. `save_asset` / `save_observation` / `_lookup_asset_id` use correct DB model field names. `asset_type="websocket"` confirmed present in `ASSET_TYPES` tuple (`shared/lib_webbh/database.py:115`). Semaphore `_MAX_CONCURRENT_PROBES=20` scoped correctly inside `execute()`.

- **Worker tool — `entry_point_aggregator.py`**: `Asset`, `Parameter`, `get_session` imports verified against `__init__.py`. `scope_check` wired correctly via new `scope_manager` kwarg. HEAD→GET fallback chain correct. `_consolidate_query_params` writes `Parameter` rows with correct ORM field names.

- **Worker tool — `form_mapper.py`**: `aiohttp.ClientSession` now reused across loop (was per-URL). `scope_check` guards before rate-limit acquisition. `seen` set deduplicates input names. All `save_observation` / `session.add(Parameter(...))` field names match ORM model. `_fetch_html` signature updated to accept `http` session — all callers updated.

- **Worker pipeline — `pipeline.py`**: `WebSocketProber` imported and placed in `identify_entry_points` stage. `EntryPointAggregator` placed in `aggregate_entry_points` stage. All tool classes imported from correct paths. `_STAGE7_SECTION = "4.1.7"` correctly gates `ExecutionPathAnalyzer` on `map_execution_paths` — unaffected by 4.1.6 stages.

- **Worker concurrency — `concurrency.py`**: `WebSocketProber` registered as `"LIGHT"` — correct (aiohttp HTTP, not subprocess). `EntryPointAggregator` registered as `"LIGHT"` — correct. No stale tool references.

- **Worker main — `main.py`**: Queue consumed is `info_gathering_queue` (underscore). Consumer group is `info_gathering_group`. Both match orchestrator pushes at `orchestrator/main.py:860,1652,1970`. Job-state container_name uses `WORKER_TYPE = "info_gathering"` — consistent.

- **Shared lib — `lib_webbh/__init__.py`**: All symbols imported by the three tools (`Asset`, `Parameter`, `get_session`) present in `__all__`. No stale import names.

- **Shared lib — `database.py` / `schema.sql`**: `Asset.asset_type` is `VARCHAR(50)` in both ORM and schema. No enum constraint — new `"websocket"` value accepted. `"websocket"` already in `ASSET_TYPES` tuple.

- **Orchestrator queue contracts**: `info_gathering_queue` pushed by orchestrator matches consumer in `main.py`. No new queue introduced.

- **E2E tests**: No E2E test references new stage names — no stale testid or `current_phase` seed values. Orchestrator seed at `main.py:2712` uses `enumerate_applications` (still a valid stage).

- **Unit tests**: `test_wstg_info06_pipeline.py` asserts `WebSocketProber in identify_entry_points.tools`, `aggregate_entry_points` follows `identify_entry_points`, `EntryPointAggregator` is sole tool, shared `section_id="4.1.6"`, both new tools are `"LIGHT"` in `TOOL_WEIGHTS`. `test_wstg_info06_websocket_prober.py` covers guard on missing target/asset_id, 101 accept, 403 reject, connection error (no writes), HTTP fallback, scope filtering, and now asserts `status == 101` in observation.

- **`InfrastructureMixin`**: Not used on `InfoGatheringTool` — correct per convention.

- **Naming conventions**: Docker `info-gathering` (hyphen), Redis `info_gathering_queue` (underscore), Python `workers/info_gathering/` (underscore) — all consistent.

---

### Coverage

Checked:
- `workers/info_gathering/tools/websocket_prober.py` (full read + diff)
- `workers/info_gathering/tools/entry_point_aggregator.py` (full read + diff)
- `workers/info_gathering/tools/form_mapper.py` (full read + diff)
- `workers/info_gathering/pipeline.py` (full read)
- `workers/info_gathering/concurrency.py` (full read)
- `workers/info_gathering/main.py` (full read)
- `workers/info_gathering/base_tool.py` (full read)
- `shared/lib_webbh/playbooks.py` (full read + edited)
- `shared/lib_webbh/__init__.py` (full read)
- `shared/lib_webbh/database.py` (ASSET_TYPES, ORM columns)
- `shared/schema.sql` (asset_type column definition)
- `dashboard/src/lib/worker-stages.ts` (full read + edited)
- `dashboard/src/components/campaign/WorkflowBuilder.tsx` (read + edited)
- `dashboard/e2e/helpers/api-client.ts` (current_phase references)
- `orchestrator/main.py` (queue push names, seed current_phase values)
- `tests/test_wstg_info06_websocket_prober.py` (full read + diff)
- `tests/test_wstg_info06_pipeline.py` (full read)
- `tests/test_wstg_info06_entry_point_aggregator.py` (diff)
- `tests/test_wstg_info06_form_mapper.py` (diff)
- Grep: all active worker `main.py` files (queue name drift baseline)
- Grep: `dashboard/e2e/` for stage name references
- Grep: `orchestrator/` for PIPELINE_STAGES and queue name references
