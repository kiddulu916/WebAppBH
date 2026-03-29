"""E2E tests for all worker pipelines: full run, resume, and event emission.

Validates that each worker's pipeline correctly progresses through stages,
updates JobState, handles crash-resume, and emits expected SSE events.

Each pipeline's ``_run_stage`` is mocked so no external tools execute.
Database operations (checkpoint / mark-completed) run against an in-memory
SQLite database so we can assert on JobState rows afterward.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Environment must be set BEFORE any lib_webbh import
# ---------------------------------------------------------------------------
import os

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

# ---------------------------------------------------------------------------
# Stdlib / third-party
# ---------------------------------------------------------------------------
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select

# Patch logger before worker imports to avoid filesystem side-effects
import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, JobState, Target, get_engine, get_session

# =========================================================================
# Worker pipeline metadata
# =========================================================================

# Each entry describes one pipeline:
#   module_path     : Python import path for the pipeline module
#   stages          : ordered list of stage names
#   container       : container_name to use in tests
#   run_kwargs      : extra kwargs required by pipeline.run() beyond target+scope
#   ctor_takes_ids  : whether the Pipeline constructor takes (target_id, container_name)
#   run_takes_ids   : whether pipeline.run() takes target_id/container_name explicitly

WORKER_SPECS: list[dict[str, Any]] = [
    {
        "id": "recon_core",
        "module_path": "workers.recon_core.pipeline",
        "stages": [
            "passive_discovery", "active_discovery", "liveness_dns",
            "subdomain_takeover", "fingerprinting", "port_mapping", "deep_recon",
        ],
        "container": "recon-core-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "webapp_worker",
        "module_path": "workers.webapp_worker.pipeline",
        "stages": [
            "js_discovery", "static_js_analysis", "browser_security",
            "http_security", "path_api_discovery", "api_probing",
            "xss_scanning", "prototype_pollution_scan",
        ],
        "container": "webapp-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "api_worker",
        "module_path": "workers.api_worker.pipeline",
        "stages": [
            "api_discovery", "auth_testing", "injection_testing", "abuse_testing",
        ],
        "container": "api-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "cloud_worker",
        "module_path": "workers.cloud_worker.pipeline",
        "stages": ["discovery", "probing", "deep_scan", "feedback"],
        "container": "cloud-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "fuzzing_worker",
        "module_path": "workers.fuzzing_worker.pipeline",
        "stages": [
            "dir_fuzzing", "vhost_fuzzing", "param_discovery",
            "header_fuzzing", "injection_fuzzing",
        ],
        "container": "fuzzing-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "network_worker",
        "module_path": "workers.network_worker.pipeline",
        "stages": [
            "port_discovery", "service_scan", "credential_test", "exploit_verify",
        ],
        "container": "network-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "mobile_worker",
        "module_path": "workers.mobile_worker.pipeline",
        "stages": [
            "acquire_decompile", "secret_extraction", "configuration_audit",
            "dynamic_analysis", "endpoint_feedback",
        ],
        "container": "mobile-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
    {
        "id": "chain_worker",
        "module_path": "workers.chain_worker.pipeline",
        "stages": [
            "data_collection", "chain_evaluation", "chain_execution", "reporting",
        ],
        "container": "chain-worker-1",
        "run_kwargs": {},
        "ctor_takes_ids": False,
        "run_takes_ids": True,
    },
    {
        "id": "vuln_scanner",
        "module_path": "workers.vuln_scanner.pipeline",
        "stages": ["nuclei_sweep", "active_injection", "broad_injection_sweep"],
        "container": "vuln-scanner-1",
        "run_kwargs": {},
        "ctor_takes_ids": True,
        "run_takes_ids": False,
    },
]

# Build a mapping for easy lookup
_SPEC_MAP: dict[str, dict] = {s["id"]: s for s in WORKER_SPECS}

# =========================================================================
# Fixtures
# =========================================================================


@pytest_asyncio.fixture(autouse=True)
async def db():
    """Create all tables in a fresh SQLite in-memory DB before every test.

    We also reset the engine/session singletons to avoid stale connections
    between tests (aiosqlite in-memory DBs vanish on disconnect).
    """
    import lib_webbh.database as _db_mod

    # Reset singletons so each test gets a fresh in-memory database
    _db_mod._engine = None
    _db_mod._session_factory = None

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine

    # Dispose of the engine to release the aiosqlite connection
    await engine.dispose()
    _db_mod._engine = None
    _db_mod._session_factory = None


@pytest_asyncio.fixture
async def seed_target(db):
    """Insert a Target row and return its id."""
    async with get_session() as session:
        t = Target(
            company_name="TestCorp",
            base_domain="testcorp.com",
            target_profile={},
        )
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def mock_target():
    """MagicMock standing in for a Target ORM instance."""
    target = MagicMock()
    target.base_domain = "testcorp.com"
    target.target_profile = {}
    target.id = 1
    return target


@pytest.fixture
def mock_scope():
    """MagicMock standing in for a ScopeManager."""
    scope = MagicMock()
    scope.is_in_scope.return_value = MagicMock(
        in_scope=True, normalized="test.testcorp.com", asset_type="domain",
    )
    return scope


# =========================================================================
# Helpers
# =========================================================================

_STAGE_RESULT = {"found": 5, "in_scope": 3, "new": 2}


def _import_pipeline(module_path: str):
    """Dynamically import and return (Pipeline, STAGES, module)."""
    import importlib
    mod = importlib.import_module(module_path)
    return mod.Pipeline, mod.STAGES, mod


async def _seed_job_state(
    target_id: int,
    container_name: str,
    current_phase: str,
    status: str = "COMPLETED",
) -> int:
    """Insert a JobState row and return its id."""
    async with get_session() as session:
        job = JobState(
            target_id=target_id,
            container_name=container_name,
            current_phase=current_phase,
            status=status,
            last_seen=datetime.now(timezone.utc),
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)
        return job.id


async def _get_job_state(target_id: int, container_name: str) -> JobState | None:
    """Fetch the JobState row for this target + container."""
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


def _make_patches(spec: dict):
    """Build the list of ``patch`` context managers needed for a worker.

    Returns a list of (patch_target_string, patch_kwargs) tuples.
    Every pipeline needs at minimum:
      - ``push_task`` mocked to prevent Redis calls
      - ``_run_stage`` mocked to prevent actual tool execution
    Some workers need extra mocks (browser manager, load_oos_attacks, etc.).
    """
    mod_path = spec["module_path"]
    patches: list[tuple[str, dict]] = [
        (f"{mod_path}.push_task", {"new_callable": AsyncMock}),
    ]

    # Worker-specific extra patches
    worker_id = spec["id"]
    if worker_id == "webapp_worker":
        # Prevent real BrowserManager lifecycle
        patches.append((
            f"{mod_path}.BrowserManager",
            {"return_value": MagicMock(
                start=AsyncMock(),
                shutdown=AsyncMock(),
            )},
        ))
    elif worker_id == "network_worker":
        # load_oos_attacks reads from filesystem
        patches.append((
            f"{mod_path}.load_oos_attacks",
            {"new_callable": AsyncMock, "return_value": []},
        ))
    elif worker_id == "fuzzing_worker":
        # permutation handoff does DB queries we don't want in full-run tests
        patches.append((
            f"{mod_path}.extract_prefix",
            {"return_value": None},
        ))

    return patches


async def _run_pipeline(
    spec: dict,
    target_id: int,
    mock_target,
    mock_scope,
    *,
    extra_run_stage_side_effect=None,
) -> tuple[AsyncMock, AsyncMock]:
    """Instantiate and run a pipeline with mocked _run_stage and push_task.

    Returns (mock_run_stage, mock_push_task) so callers can assert on them.
    """
    Pipeline, STAGES, mod = _import_pipeline(spec["module_path"])

    # Build patches
    patch_specs = _make_patches(spec)

    # We'll apply patches manually so we can capture references
    active_patches = []
    mocks: dict[str, Any] = {}

    for target_str, kwargs in patch_specs:
        p = patch(target_str, **kwargs)
        mock_obj = p.start()
        active_patches.append(p)
        mocks[target_str] = mock_obj

    try:
        # Instantiate pipeline
        container = spec["container"]
        if spec["ctor_takes_ids"]:
            pipeline = Pipeline(target_id=target_id, container_name=container)
        else:
            pipeline = Pipeline()

        # Mock _run_stage on the instance
        mock_run_stage = AsyncMock(
            return_value=_STAGE_RESULT,
            side_effect=extra_run_stage_side_effect,
        )
        pipeline._run_stage = mock_run_stage

        # vuln_scanner uses _run_active_injection for the active_injection
        # stage instead of _run_stage — mock it too so it returns consistent
        # stats and the stage count assertion works.
        if hasattr(pipeline, "_run_active_injection"):
            pipeline._run_active_injection = AsyncMock(return_value=_STAGE_RESULT)

        # Build run() kwargs
        run_kwargs = dict(spec["run_kwargs"])
        if spec["run_takes_ids"]:
            run_kwargs["target_id"] = target_id
            run_kwargs["container_name"] = container

        await pipeline.run(mock_target, mock_scope, **run_kwargs)

        # Capture the push_task mock from the module-level patch
        push_task_key = f"{spec['module_path']}.push_task"
        mock_push = mocks[push_task_key]

        return mock_run_stage, mock_push

    finally:
        for p in active_patches:
            p.stop()


# =========================================================================
# Parametrized IDs for readability
# =========================================================================

_WORKER_IDS = [s["id"] for s in WORKER_SPECS]


def _spec_by_id(worker_id: str) -> dict:
    return _SPEC_MAP[worker_id]


# =========================================================================
# 1. Full-run tests (parametrized across all 9 workers)
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_full_run(
    worker_id, seed_target, mock_target, mock_scope,
):
    """Run each pipeline from scratch (no prior JobState).

    Verify that:
    - All stages are called in the correct order
    - _run_stage is called once per stage
    """
    spec = _spec_by_id(worker_id)
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]

    # Seed a RUNNING JobState so _update_phase / _mark_completed have a row to update
    await _seed_job_state(target_id, container, current_phase=None, status="RUNNING")

    mock_run_stage, mock_push = await _run_pipeline(
        spec, target_id, mock_target, mock_scope,
    )

    expected_stages = spec["stages"]

    # chain_worker and vuln_scanner have non-standard stage dispatch —
    # chain_worker runs tools inline, vuln_scanner uses _run_active_injection
    # for the active_injection stage. Verify via STAGE_COMPLETE events instead.
    if worker_id in ("chain_worker", "vuln_scanner"):
        stage_complete_calls = [
            call for call in mock_push.call_args_list
            if _is_event(call, "STAGE_COMPLETE")
        ]
        completed_stage_names = [
            call[0][1]["stage"] for call in stage_complete_calls
        ]
        assert completed_stage_names == expected_stages, (
            f"{worker_id} STAGE_COMPLETE events mismatch: "
            f"got {completed_stage_names}, expected {expected_stages}"
        )
    else:
        # All other workers: verify _run_stage was called for every stage
        assert mock_run_stage.call_count == len(expected_stages), (
            f"{worker_id}: expected {len(expected_stages)} _run_stage calls, "
            f"got {mock_run_stage.call_count}"
        )
        called_stages = _extract_stage_names(worker_id, mock_run_stage)
        assert called_stages == expected_stages, (
            f"{worker_id}: stage order mismatch: got {called_stages}, "
            f"expected {expected_stages}"
        )


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_full_run_job_state_completed(
    worker_id, seed_target, mock_target, mock_scope,
):
    """After a full run, JobState should be COMPLETED with current_phase set
    to the final stage name."""
    spec = _spec_by_id(worker_id)
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]

    await _seed_job_state(target_id, container, current_phase=None, status="RUNNING")

    await _run_pipeline(spec, target_id, mock_target, mock_scope)

    job = await _get_job_state(target_id, container)
    assert job is not None, f"{worker_id}: no JobState row found after pipeline run"
    assert job.status == "COMPLETED", (
        f"{worker_id}: expected COMPLETED, got {job.status}"
    )
    assert job.current_phase == spec["stages"][-1], (
        f"{worker_id}: expected current_phase={spec['stages'][-1]}, "
        f"got {job.current_phase}"
    )


# =========================================================================
# 2. Resume-from-midpoint tests (parametrized)
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_resume_from_midpoint(
    worker_id, seed_target, mock_target, mock_scope,
):
    """Seed JobState with a completed mid-pipeline phase, then run.

    Verify that only stages AFTER the checkpoint are executed.
    """
    spec = _spec_by_id(worker_id)
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]
    stages = spec["stages"]

    # Pick a midpoint: the stage at index len//2
    midpoint_idx = len(stages) // 2
    midpoint_stage = stages[midpoint_idx]
    expected_remaining = stages[midpoint_idx + 1:]

    # Seed JobState as if we crashed after completing midpoint_stage
    await _seed_job_state(
        target_id, container,
        current_phase=midpoint_stage,
        status="COMPLETED",
    )

    mock_run_stage, mock_push = await _run_pipeline(
        spec, target_id, mock_target, mock_scope,
    )

    if worker_id == "chain_worker":
        # chain_worker's _get_resume_index reads status != "COMPLETED" to resume,
        # and with status=="COMPLETED" it returns 0. However the spec says
        # the chain_worker _get_resume_index checks row.status != "COMPLETED".
        # When the seeded JobState has status="COMPLETED", chain_worker sees it as
        # "finished" and starts from 0. So for chain_worker we seed with
        # status="RUNNING" to test resume.
        pass
    else:
        called_stages = _extract_stage_names(worker_id, mock_run_stage)
        assert called_stages == expected_remaining, (
            f"{worker_id}: resume from '{midpoint_stage}' should run "
            f"{expected_remaining}, but got {called_stages}"
        )


@pytest.mark.anyio
async def test_chain_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """chain_worker has unique resume logic: it checks status != 'COMPLETED'.

    We seed with status='RUNNING' and a current_phase to trigger resume.
    """
    spec = _spec_by_id("chain_worker")
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]
    stages = spec["stages"]

    midpoint_idx = len(stages) // 2
    midpoint_stage = stages[midpoint_idx]
    expected_remaining = stages[midpoint_idx + 1:]

    # chain_worker resumes when status != "COMPLETED" and current_phase is set
    await _seed_job_state(
        target_id, container,
        current_phase=midpoint_stage,
        status="RUNNING",
    )

    mock_run_stage, mock_push = await _run_pipeline(
        spec, target_id, mock_target, mock_scope,
    )

    # Verify only remaining stages emitted STAGE_COMPLETE events
    stage_complete_calls = [
        call for call in mock_push.call_args_list
        if _is_event(call, "STAGE_COMPLETE")
    ]
    completed_stage_names = [
        call[0][1]["stage"] for call in stage_complete_calls
    ]
    assert completed_stage_names == expected_remaining, (
        f"chain_worker resume: expected {expected_remaining}, "
        f"got {completed_stage_names}"
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "worker_id",
    [w for w in _WORKER_IDS if w != "chain_worker"],
    ids=[w for w in _WORKER_IDS if w != "chain_worker"],
)
async def test_pipeline_resume_skips_all_if_last_stage_completed(
    worker_id, seed_target, mock_target, mock_scope,
):
    """If the last stage is already completed, no stages should run."""
    spec = _spec_by_id(worker_id)
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]
    last_stage = spec["stages"][-1]

    await _seed_job_state(
        target_id, container,
        current_phase=last_stage,
        status="COMPLETED",
    )

    mock_run_stage, _ = await _run_pipeline(
        spec, target_id, mock_target, mock_scope,
    )

    assert mock_run_stage.call_count == 0, (
        f"{worker_id}: expected 0 _run_stage calls when last stage already "
        f"completed, got {mock_run_stage.call_count}"
    )


# =========================================================================
# 3. Event emission: STAGE_COMPLETE for every stage
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_emits_stage_complete_events(
    worker_id, seed_target, mock_target, mock_scope,
):
    """Every pipeline must emit a STAGE_COMPLETE event for each stage."""
    spec = _spec_by_id(worker_id)
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]

    await _seed_job_state(target_id, container, current_phase=None, status="RUNNING")

    _, mock_push = await _run_pipeline(spec, target_id, mock_target, mock_scope)

    stage_complete_calls = [
        call for call in mock_push.call_args_list
        if _is_event(call, "STAGE_COMPLETE")
    ]
    stage_names = [call[0][1]["stage"] for call in stage_complete_calls]

    assert stage_names == spec["stages"], (
        f"{worker_id}: STAGE_COMPLETE events mismatch: "
        f"got {stage_names}, expected {spec['stages']}"
    )


# =========================================================================
# 4. Event emission: PIPELINE_COMPLETE at end
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_emits_pipeline_complete_event(
    worker_id, seed_target, mock_target, mock_scope,
):
    """Every pipeline must emit exactly one PIPELINE_COMPLETE event at the end."""
    spec = _spec_by_id(worker_id)
    target_id = seed_target
    mock_target.id = target_id
    container = spec["container"]

    await _seed_job_state(target_id, container, current_phase=None, status="RUNNING")

    _, mock_push = await _run_pipeline(spec, target_id, mock_target, mock_scope)

    pipeline_complete_calls = [
        call for call in mock_push.call_args_list
        if _is_event(call, "PIPELINE_COMPLETE")
    ]

    assert len(pipeline_complete_calls) == 1, (
        f"{worker_id}: expected exactly 1 PIPELINE_COMPLETE event, "
        f"got {len(pipeline_complete_calls)}"
    )

    # PIPELINE_COMPLETE should be the very last push_task call
    last_push = mock_push.call_args_list[-1]
    assert _is_event(last_push, "PIPELINE_COMPLETE"), (
        f"{worker_id}: last push_task call was not PIPELINE_COMPLETE: "
        f"{last_push}"
    )


# =========================================================================
# Individual pipeline full-run tests (named for discoverability)
# =========================================================================


@pytest.mark.anyio
async def test_recon_core_pipeline_full_run(seed_target, mock_target, mock_scope):
    """recon_core: explicit full-run test."""
    spec = _spec_by_id("recon_core")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 7
    assert _extract_stage_names("recon_core", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_recon_core_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """recon_core: resume after active_discovery."""
    spec = _spec_by_id("recon_core")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="active_discovery", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["liveness_dns", "subdomain_takeover", "fingerprinting", "port_mapping", "deep_recon"]
    assert _extract_stage_names("recon_core", mock_rs) == expected


@pytest.mark.anyio
async def test_webapp_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """webapp_worker: explicit full-run test."""
    spec = _spec_by_id("webapp_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 8
    assert _extract_stage_names("webapp_worker", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_webapp_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """webapp_worker: resume after browser_security."""
    spec = _spec_by_id("webapp_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="browser_security", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["http_security", "path_api_discovery", "api_probing", "xss_scanning", "prototype_pollution_scan"]
    assert _extract_stage_names("webapp_worker", mock_rs) == expected


@pytest.mark.anyio
async def test_api_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """api_worker: explicit full-run test."""
    spec = _spec_by_id("api_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 4
    assert _extract_stage_names("api_worker", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_api_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """api_worker: resume after auth_testing."""
    spec = _spec_by_id("api_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="auth_testing", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["injection_testing", "abuse_testing"]
    assert _extract_stage_names("api_worker", mock_rs) == expected


@pytest.mark.anyio
async def test_cloud_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """cloud_worker: explicit full-run test."""
    spec = _spec_by_id("cloud_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 4
    assert _extract_stage_names("cloud_worker", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_cloud_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """cloud_worker: resume after probing."""
    spec = _spec_by_id("cloud_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="probing", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["deep_scan", "feedback"]
    assert _extract_stage_names("cloud_worker", mock_rs) == expected


@pytest.mark.anyio
async def test_fuzzing_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """fuzzing_worker: explicit full-run test."""
    spec = _spec_by_id("fuzzing_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 5
    assert _extract_stage_names("fuzzing_worker", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_fuzzing_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """fuzzing_worker: resume after param_discovery."""
    spec = _spec_by_id("fuzzing_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="param_discovery", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["header_fuzzing", "injection_fuzzing"]
    assert _extract_stage_names("fuzzing_worker", mock_rs) == expected


@pytest.mark.anyio
async def test_network_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """network_worker: explicit full-run test."""
    spec = _spec_by_id("network_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 4
    assert _extract_stage_names("network_worker", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_network_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """network_worker: resume after service_scan."""
    spec = _spec_by_id("network_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="service_scan", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["credential_test", "exploit_verify"]
    assert _extract_stage_names("network_worker", mock_rs) == expected


@pytest.mark.anyio
async def test_mobile_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """mobile_worker: explicit full-run test."""
    spec = _spec_by_id("mobile_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    assert mock_rs.call_count == 5
    assert _extract_stage_names("mobile_worker", mock_rs) == spec["stages"]


@pytest.mark.anyio
async def test_mobile_worker_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """mobile_worker: resume after configuration_audit."""
    spec = _spec_by_id("mobile_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="configuration_audit", status="COMPLETED")
    mock_rs, _ = await _run_pipeline(spec, tid, mock_target, mock_scope)
    expected = ["dynamic_analysis", "endpoint_feedback"]
    assert _extract_stage_names("mobile_worker", mock_rs) == expected


@pytest.mark.anyio
async def test_chain_worker_pipeline_full_run(seed_target, mock_target, mock_scope):
    """chain_worker: explicit full-run test."""
    spec = _spec_by_id("chain_worker")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")

    _, mock_push = await _run_pipeline(spec, tid, mock_target, mock_scope)

    stage_complete_calls = [
        call for call in mock_push.call_args_list
        if _is_event(call, "STAGE_COMPLETE")
    ]
    stage_names = [call[0][1]["stage"] for call in stage_complete_calls]
    assert stage_names == spec["stages"]


@pytest.mark.anyio
async def test_vuln_scanner_pipeline_full_run(seed_target, mock_target, mock_scope):
    """vuln_scanner: explicit full-run test.

    vuln_scanner calls _run_active_injection for active_injection stage
    (not _run_stage), so _run_stage is only called for nuclei_sweep and
    broad_injection_sweep (2 calls). Verify all 3 stages via STAGE_COMPLETE.
    """
    spec = _spec_by_id("vuln_scanner")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase=None, status="RUNNING")
    mock_rs, mock_push = await _run_pipeline(spec, tid, mock_target, mock_scope)
    # _run_stage called for nuclei_sweep + broad_injection_sweep only
    assert mock_rs.call_count == 2
    # All 3 stages emit STAGE_COMPLETE
    stage_events = [
        c[0][1]["stage"] for c in mock_push.call_args_list
        if _is_event(c, "STAGE_COMPLETE")
    ]
    assert stage_events == spec["stages"]


@pytest.mark.anyio
async def test_vuln_scanner_pipeline_resume_from_midpoint(
    seed_target, mock_target, mock_scope,
):
    """vuln_scanner: resume after nuclei_sweep."""
    spec = _spec_by_id("vuln_scanner")
    tid = seed_target
    mock_target.id = tid
    await _seed_job_state(tid, spec["container"], current_phase="nuclei_sweep", status="COMPLETED")
    mock_rs, mock_push = await _run_pipeline(spec, tid, mock_target, mock_scope)
    # After nuclei_sweep, remaining stages are active_injection + broad_injection_sweep
    # _run_stage only called for broad_injection_sweep (active_injection uses special method)
    assert mock_rs.call_count == 1
    stage_events = [
        c[0][1]["stage"] for c in mock_push.call_args_list
        if _is_event(c, "STAGE_COMPLETE")
    ]
    assert stage_events == ["active_injection", "broad_injection_sweep"]


# =========================================================================
# Cross-cutting: stage count validation
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_stage_count_matches_spec(worker_id):
    """Verify that the pipeline module defines the expected number of stages."""
    spec = _spec_by_id(worker_id)
    _, STAGES, _ = _import_pipeline(spec["module_path"])
    assert len(STAGES) == len(spec["stages"]), (
        f"{worker_id}: STAGES has {len(STAGES)} entries, "
        f"expected {len(spec['stages'])}"
    )


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_stage_names_match_spec(worker_id):
    """Verify that the pipeline module defines stages in the expected order."""
    spec = _spec_by_id(worker_id)
    _, STAGES, _ = _import_pipeline(spec["module_path"])
    actual_names = [s.name for s in STAGES]
    assert actual_names == spec["stages"], (
        f"{worker_id}: stage names mismatch: got {actual_names}, "
        f"expected {spec['stages']}"
    )


# =========================================================================
# Cross-cutting: each stage has at least one tool class
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_stages_have_tools(worker_id):
    """Every stage must define at least one tool class."""
    spec = _spec_by_id(worker_id)
    _, STAGES, _ = _import_pipeline(spec["module_path"])
    for stage in STAGES:
        assert len(stage.tool_classes) > 0, (
            f"{worker_id}: stage '{stage.name}' has no tool classes"
        )


# =========================================================================
# Cross-cutting: STAGE_INDEX consistency
# =========================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("worker_id", _WORKER_IDS, ids=_WORKER_IDS)
async def test_pipeline_stage_index_consistent(worker_id):
    """STAGE_INDEX must map each stage name to its correct position."""
    spec = _spec_by_id(worker_id)
    _, STAGES, mod = _import_pipeline(spec["module_path"])
    stage_index = mod.STAGE_INDEX
    for i, stage in enumerate(STAGES):
        assert stage.name in stage_index, (
            f"{worker_id}: '{stage.name}' not in STAGE_INDEX"
        )
        assert stage_index[stage.name] == i, (
            f"{worker_id}: STAGE_INDEX['{stage.name}'] == {stage_index[stage.name]}, "
            f"expected {i}"
        )


# =========================================================================
# Helpers for stage name extraction and event detection
# =========================================================================


def _extract_stage_names(worker_id: str, mock_run_stage: AsyncMock) -> list[str]:
    """Extract the ordered list of stage names from _run_stage call args.

    Most pipelines pass the Stage dataclass as the first positional arg.
    """
    names = []
    for call in mock_run_stage.call_args_list:
        # _run_stage(stage, target, scope_manager, ...) or
        # _run_stage(stage, target, scope_manager, headers, ...)
        stage_arg = call[0][0]  # first positional arg
        if hasattr(stage_arg, "name"):
            names.append(stage_arg.name)
        else:
            # Fallback: it might be a string in some workers
            names.append(str(stage_arg))
    return names


def _is_event(call, event_name: str) -> bool:
    """Check whether a mock call to push_task is for the given event type.

    push_task signature: push_task(queue, data_dict)
    The data dict should have an "event" key.
    """
    try:
        args = call[0]  # positional args
        if len(args) >= 2 and isinstance(args[1], dict):
            return args[1].get("event") == event_name
    except (IndexError, TypeError):
        pass
    return False
