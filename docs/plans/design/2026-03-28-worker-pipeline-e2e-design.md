# Worker Pipeline E2E Tests — Design

**Date:** 2026-03-28
**Scope:** End-to-end tests validating worker pipeline phase progression and cross-worker orchestration

## Problem

Workers move through ordered pipeline stages (e.g., recon has 7 stages, webapp has 8), and the event engine chains workers together (recon -> downstream -> vulnscan -> chain -> reporting). No tests existed to verify:
1. Each worker's pipeline runs all stages in order and checkpoints to JobState
2. The event engine correctly triggers downstream workers when prerequisites complete
3. The full lifecycle from target creation to reporting works end-to-end

## Approach: Hybrid Testing

**In-process pipeline tests** — Import each worker's `Pipeline` class, mock `_run_stage` and Redis (`push_task`), run against in-memory SQLite. Validates stage ordering, JobState updates, resume-from-midpoint, and SSE event emission for all 9 workers.

**Event engine trigger tests** — Call individual trigger functions (`_check_recon_trigger`, `_check_web_trigger`, etc.) against seeded DB state with mocked `worker_manager`. Validates trigger conditions, negative cases, and the full 5-phase lifecycle chain.

**Docker lifecycle tests** — Simulate the complete orchestration cycle: seed a target with assets/locations/params/cloud/mobile, then run triggers in sequence marking each phase complete. Validates idempotency, resource-constrained queuing, multi-target independence, and failed-job retrigger.

## Infrastructure Gaps Fixed

- Added 5 missing entries to `WORKER_IMAGES` in `event_engine.py` (network, mobile, chain, vulnscan, reporting)
- Added 4 new trigger functions: `_check_network_trigger`, `_check_vulnscan_trigger`, `_check_mobile_trigger`, `_check_reporting_trigger`
- Wired all 9 triggers into `run_event_loop()`
- Added 4 missing worker services to `docker-compose.yml` (api-worker, cloud-worker, fuzzing-worker, vuln-scanner)

## Test Structure

```
tests/e2e/
├── __init__.py
├── test_trigger_chain.py       # 20 tests — event engine trigger evaluation
├── test_worker_pipelines.py    # 107 tests — in-process pipeline execution (9 workers)
└── test_docker_lifecycle.py    # 10 tests — cross-worker orchestration lifecycle
```

### Workers Tested (9 total)

| Worker | Stages | Key Trigger Condition |
|--------|--------|----------------------|
| recon_core | 7 (passive_discovery → deep_recon) | New target, no active recon job |
| webapp_worker | 8 (js_discovery → prototype_pollution_scan) | Recon complete + HTTP locations exist |
| fuzzing_worker | 5 (dir_fuzzing → injection_fuzzing) | Recon complete + HTTP locations exist |
| api_worker | 4 (api_discovery → abuse_testing) | Recon complete + parameters > 20 |
| cloud_worker | 4 (discovery → feedback) | Recon complete + CloudAsset records exist |
| network_worker | 4 (port_discovery → exploit_verify) | Recon complete + non-web ports open |
| mobile_worker | 5 (acquire_decompile → endpoint_feedback) | Recon complete + MobileApp records exist |
| vuln_scanner | 3 (nuclei_sweep → broad_injection_sweep) | Fuzzing + webapp + api complete |
| chain_worker | 4 (data_collection → reporting) | 5 prerequisite workers complete |

### Test Categories

**Pipeline tests** (per worker, parametrized):
- Full pipeline run completes all stages
- JobState marked COMPLETED after pipeline finishes
- Resume from midpoint skips completed stages
- Skip-all when last stage already completed
- STAGE_COMPLETE events emitted for each stage
- PIPELINE_COMPLETE event emitted at end
- Explicit per-worker tests with correct stage counts

**Trigger tests** (per trigger):
- Fires when conditions met
- Skips when prerequisite incomplete
- Skips when job already active (RUNNING/QUEUED)
- Skips when conditions not met (no assets, below threshold, etc.)
- Full 5-phase lifecycle sequence

**Lifecycle tests**:
- Phase 1-5 individual progression
- Full end-to-end lifecycle
- Idempotency (no double triggers)
- Resource-constrained queuing
- Multi-target independence
- Failed job does not block retrigger

## Result

137 tests passing, covering the complete worker pipeline and orchestration chain.
