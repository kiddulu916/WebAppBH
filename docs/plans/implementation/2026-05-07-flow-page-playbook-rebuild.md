# Flow Page & Playbook Rebuild Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rebuild the Phase Flow page and playbook data model to reflect the 18-worker WSTG pipeline architecture with worker+stage level configuration.

**Architecture:** Replace the flat 7-stage playbook model with a hierarchical `workers: list[WorkerConfig]` model. Each WorkerConfig contains stage toggles and concurrency settings. The flow page becomes a two-panel collapsible worker tree (configurator + execution monitor). Backend changes flow: playbooks.py -> orchestrator endpoints -> worker _filter_stages. Frontend: types -> API client -> flow page rewrite.

**Tech Stack:** Python (dataclasses, FastAPI/Pydantic), TypeScript (Next.js, React, Tailwind CSS v4, Zustand)

**Design doc:** `docs/plans/design/2026-05-07-flow-page-playbook-rebuild-design.md`

---

## Task 1: Update Playbook Data Model

**Files:**
- Modify: `shared/lib_webbh/playbooks.py`

**Step 1: Write the failing test**

Create `tests/test_playbooks_v2.py`:

```python
"""Tests for the hierarchical playbook model."""
import pytest
from lib_webbh.playbooks import (
    BUILTIN_PLAYBOOKS, PIPELINE_STAGES, PlaybookConfig, WorkerConfig,
    StageConfig, ConcurrencyConfig, build_worker_config, get_worker_stages,
    get_playbook,
)


def test_pipeline_stages_registry_has_all_workers():
    expected = [
        "info_gathering", "config_mgmt", "identity_mgmt", "authentication",
        "authorization", "session_mgmt", "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side", "mobile_worker",
        "reasoning_worker", "chain_worker", "reporting",
    ]
    for w in expected:
        assert w in PIPELINE_STAGES, f"Missing worker: {w}"
        assert len(PIPELINE_STAGES[w]) > 0, f"Empty stages for: {w}"


def test_build_worker_config_all_enabled():
    wc = build_worker_config("info_gathering")
    assert wc.name == "info_gathering"
    assert wc.enabled is True
    assert len(wc.stages) == 10
    assert all(s.enabled for s in wc.stages)


def test_build_worker_config_disabled():
    wc = build_worker_config("mobile_worker", enabled=False)
    assert wc.enabled is False


def test_build_worker_config_with_disabled_stages():
    wc = build_worker_config(
        "info_gathering",
        disabled_stages=["search_engine_recon", "enumerate_subdomains"],
    )
    disabled = [s for s in wc.stages if not s.enabled]
    assert len(disabled) == 2
    assert {s.name for s in disabled} == {"search_engine_recon", "enumerate_subdomains"}


def test_build_worker_config_custom_concurrency():
    wc = build_worker_config("input_validation", concurrency=ConcurrencyConfig(heavy=3, light=6))
    assert wc.concurrency.heavy == 3
    assert wc.concurrency.light == 6


def test_playbook_config_has_workers():
    config = get_playbook("wide_recon")
    assert isinstance(config, PlaybookConfig)
    assert hasattr(config, "workers")
    assert len(config.workers) == 15


def test_playbook_config_serializable():
    config = get_playbook("wide_recon")
    d = config.to_dict()
    assert "workers" in d
    assert isinstance(d["workers"], list)
    assert all("stages" in w for w in d["workers"])


def test_wide_recon_all_enabled():
    config = get_playbook("wide_recon")
    for w in config.workers:
        assert w.enabled is True
        assert all(s.enabled for s in w.stages)


def test_deep_webapp_mobile_disabled():
    config = get_playbook("deep_webapp")
    mobile = next(w for w in config.workers if w.name == "mobile_worker")
    assert mobile.enabled is False


def test_api_focused_disables_client_side_session_mobile():
    config = get_playbook("api_focused")
    disabled = {w.name for w in config.workers if not w.enabled}
    assert "client_side" in disabled
    assert "mobile_worker" in disabled
    assert "session_mgmt" in disabled


def test_api_focused_info_gathering_partial():
    config = get_playbook("api_focused")
    ig = next(w for w in config.workers if w.name == "info_gathering")
    enabled_names = {s.name for s in ig.stages if s.enabled}
    assert "web_server_fingerprint" in enabled_names
    assert "identify_entry_points" in enabled_names
    assert "search_engine_recon" not in enabled_names


def test_get_worker_stages_extracts_correctly():
    config = get_playbook("wide_recon")
    d = config.to_dict()
    stages = get_worker_stages(d, "info_gathering")
    assert stages is not None
    assert len(stages) == 10


def test_get_worker_stages_disabled_worker():
    config = get_playbook("deep_webapp")
    d = config.to_dict()
    stages = get_worker_stages(d, "mobile_worker")
    assert stages == []  # Worker disabled


def test_get_worker_stages_missing_playbook():
    stages = get_worker_stages(None, "info_gathering")
    assert stages is None  # No playbook = run all


def test_get_playbook_unknown_returns_default():
    config = get_playbook("nonexistent")
    assert config.name == "wide_recon"


def test_all_four_builtins_exist():
    assert "wide_recon" in BUILTIN_PLAYBOOKS
    assert "deep_webapp" in BUILTIN_PLAYBOOKS
    assert "api_focused" in BUILTIN_PLAYBOOKS
    assert "cloud_first" in BUILTIN_PLAYBOOKS
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_playbooks_v2.py -v`
Expected: FAIL — `PIPELINE_STAGES`, `WorkerConfig`, `build_worker_config`, `get_worker_stages` don't exist yet.

**Step 3: Implement the new playbook model**

Rewrite `shared/lib_webbh/playbooks.py` with:

1. `PIPELINE_STAGES` — dict mapping worker name to list of stage name strings. Source of truth gathered from each worker's `pipeline.py`:

```python
PIPELINE_STAGES: dict[str, list[str]] = {
    "info_gathering": [
        "search_engine_recon", "web_server_fingerprint", "web_server_metafiles",
        "enumerate_subdomains", "review_comments", "identify_entry_points",
        "map_execution_paths", "fingerprint_framework", "map_architecture",
        "map_application",
    ],
    "config_mgmt": [
        "network_config", "platform_config", "file_extension_handling",
        "backup_files", "api_discovery", "http_methods", "hsts_testing",
        "rpc_testing", "file_inclusion", "subdomain_takeover", "cloud_storage",
    ],
    "identity_mgmt": [
        "role_definitions", "registration_process", "account_provisioning",
        "account_enumeration", "weak_username_policy",
    ],
    "authentication": [
        "credentials_transport", "default_credentials", "lockout_mechanism",
        "auth_bypass", "remember_password", "browser_cache",
        "weak_password_policy", "security_questions", "password_change",
        "multi_channel_auth",
    ],
    "authorization": [
        "directory_traversal", "authz_bypass", "privilege_escalation", "idor",
    ],
    "session_mgmt": [
        "session_scheme", "cookie_attributes", "session_fixation",
        "exposed_variables", "csrf", "logout_functionality", "session_timeout",
        "session_puzzling", "session_hijacking",
    ],
    "input_validation": [
        "reflected_xss", "stored_xss", "http_verb_tampering",
        "http_param_pollution", "sql_injection", "ldap_injection",
        "xml_injection", "ssti", "xpath_injection", "imap_smtp_injection",
        "code_injection", "command_injection", "format_string",
        "host_header_injection", "ssrf", "file_inclusion", "buffer_overflow",
        "http_smuggling", "websocket_injection",
    ],
    "error_handling": ["error_codes", "stack_traces"],
    "cryptography": [
        "tls_testing", "padding_oracle", "plaintext_transmission", "weak_crypto",
    ],
    "business_logic": [
        "data_validation", "request_forgery", "integrity_checks",
        "process_timing", "rate_limiting", "workflow_bypass",
        "application_misuse", "file_upload_validation", "malicious_file_upload",
    ],
    "client_side": [
        "dom_xss", "clickjacking", "csrf_tokens", "csp_bypass",
        "html5_injection", "web_storage", "client_side_logic",
        "dom_based_injection", "client_side_resource_manipulation",
        "client_side_auth", "xss_client_side", "css_injection",
        "malicious_upload_client",
    ],
    "mobile_worker": [
        "acquire_decompile", "secret_extraction", "configuration_audit",
        "dynamic_analysis", "endpoint_feedback",
    ],
    "reasoning_worker": [
        "finding_correlation", "impact_analysis", "chain_hypothesis",
    ],
    "chain_worker": [
        "data_collection", "chain_evaluation", "ai_chain_discovery",
        "chain_execution", "reporting",
    ],
    "reporting": [
        "data_gathering", "deduplication", "rendering", "export",
    ],
}
```

2. Updated dataclasses:

```python
@dataclass
class ConcurrencyConfig:
    heavy: int = 2
    light: int = 4

@dataclass
class StageConfig:
    name: str
    enabled: bool = True
    tool_timeout: int = 600

@dataclass
class WorkerConfig:
    name: str
    enabled: bool = True
    stages: list[StageConfig] = field(default_factory=list)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

@dataclass
class PlaybookConfig:
    name: str
    description: str
    workers: list[WorkerConfig] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
```

3. Helper functions:

```python
def build_worker_config(
    worker_name: str,
    *,
    enabled: bool = True,
    disabled_stages: list[str] | None = None,
    concurrency: ConcurrencyConfig | None = None,
    stage_timeouts: dict[str, int] | None = None,
) -> WorkerConfig:
    """Build a WorkerConfig with all stages enabled by default."""
    disabled = set(disabled_stages or [])
    timeouts = stage_timeouts or {}
    stages = [
        StageConfig(
            name=s,
            enabled=s not in disabled,
            tool_timeout=timeouts.get(s, 600),
        )
        for s in PIPELINE_STAGES[worker_name]
    ]
    return WorkerConfig(
        name=worker_name,
        enabled=enabled,
        stages=stages,
        concurrency=concurrency or ConcurrencyConfig(),
    )


def get_worker_stages(playbook: dict | None, worker_name: str) -> list[dict] | None:
    """Extract a worker's stage config from a serialized playbook dict.

    Returns None if no playbook (= run all stages).
    Returns [] if worker is disabled.
    Returns the stage list otherwise.
    """
    if not playbook or "workers" not in playbook:
        return None
    for w in playbook["workers"]:
        if w["name"] == worker_name:
            if not w.get("enabled", True):
                return []
            return w.get("stages", [])
    return []
```

4. Rebuild the 4 built-in playbooks using `build_worker_config()`:

- **wide_recon**: All workers, all stages, concurrency `heavy=2, light=8`
- **deep_webapp**: `mobile_worker` disabled; `info_gathering` disables `search_engine_recon`, `enumerate_subdomains`; `input_validation` and `session_mgmt` get `heavy=3, light=6`
- **api_focused**: Disables `client_side`, `mobile_worker`, `session_mgmt`; `info_gathering` only enables `web_server_fingerprint`, `identify_entry_points`, `map_execution_paths`, `map_application`; concurrency `heavy=1, light=4`
- **cloud_first**: All workers; `config_mgmt` stages `cloud_storage` and `api_discovery` get 900s timeout; `info_gathering` concurrency `heavy=3, light=8`

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_playbooks_v2.py -v`
Expected: All PASS.

**Step 5: Delete old test file and rename**

Delete `tests/test_playbooks.py` (old flat-model tests). Rename `tests/test_playbooks_v2.py` to `tests/test_playbooks.py`.

**Step 6: Commit**

```bash
git add shared/lib_webbh/playbooks.py tests/test_playbooks.py
git commit -m "feat(playbooks): rebuild data model with hierarchical worker+stage config"
```

---

## Task 2: Add get_worker_stages Helper to Workers

**Files:**
- Modify: `workers/info_gathering/pipeline.py:74-81`
- Modify: `workers/authentication/pipeline.py:59-66`
- Modify: `workers/authorization/pipeline.py:47-54`
- Modify: `workers/session_mgmt/pipeline.py:57-64`
- Modify: `workers/identity_mgmt/pipeline.py:49-56`
- Modify: `workers/client_side/pipeline.py:65-72`
- Modify: `workers/error_handling/pipeline.py:39-46`
- Modify: `workers/cryptography/pipeline.py:43-50`
- Modify: `workers/business_logic/pipeline.py:53-60`

**Step 1: Write the failing test**

Create `tests/test_worker_filter_stages.py`:

```python
"""Test that worker _filter_stages handles new playbook format."""
import pytest
from lib_webbh.playbooks import get_playbook


def test_filter_stages_new_format():
    """Verify get_worker_stages extracts correctly from new format."""
    from lib_webbh.playbooks import get_worker_stages

    pb = get_playbook("deep_webapp").to_dict()
    # info_gathering should have stages, with 2 disabled
    stages = get_worker_stages(pb, "info_gathering")
    assert stages is not None
    disabled = [s for s in stages if not s["enabled"]]
    assert len(disabled) == 2

    # mobile_worker should be empty (disabled worker)
    mobile = get_worker_stages(pb, "mobile_worker")
    assert mobile == []


def test_filter_stages_none_playbook():
    """None playbook means run all stages."""
    from lib_webbh.playbooks import get_worker_stages
    assert get_worker_stages(None, "info_gathering") is None
```

**Step 2: Run test to verify it passes** (helper was implemented in Task 1)

Run: `pytest tests/test_worker_filter_stages.py -v`
Expected: PASS

**Step 3: Update all workers' _filter_stages**

Each worker's `_filter_stages` currently does:
```python
def _filter_stages(self, playbook: dict | None) -> list[Stage]:
    if not playbook or "stages" not in playbook:
        return list(STAGES)
    enabled_names = {
        s["name"] for s in playbook["stages"] if s.get("enabled", True)
    }
    return [stage for stage in STAGES if stage.name in enabled_names]
```

Replace with (substitute `WORKER_NAME` for each worker):
```python
def _filter_stages(self, playbook: dict | None) -> list[Stage]:
    from lib_webbh.playbooks import get_worker_stages
    worker_stages = get_worker_stages(playbook, "WORKER_NAME")
    if worker_stages is None:
        return list(STAGES)
    if worker_stages == []:
        return []
    enabled_names = {
        s["name"] for s in worker_stages if s.get("enabled", True)
    }
    return [stage for stage in STAGES if stage.name in enabled_names]
```

Workers to update (9 total):
- `info_gathering` -> `"info_gathering"`
- `authentication` -> `"authentication"`
- `authorization` -> `"authorization"`
- `session_mgmt` -> `"session_mgmt"`
- `identity_mgmt` -> `"identity_mgmt"`
- `client_side` -> `"client_side"`
- `error_handling` -> `"error_handling"`
- `cryptography` -> `"cryptography"`
- `business_logic` -> `"business_logic"`

**Step 4: Run existing pipeline tests to check nothing broke**

Run: `pytest tests/ -k "pipeline or playbook" -v`
Expected: All PASS.

**Step 5: Commit**

```bash
git add workers/*/pipeline.py tests/test_worker_filter_stages.py
git commit -m "refactor(workers): update _filter_stages for hierarchical playbook format"
```

---

## Task 3: Update CustomPlaybook DB Model

**Files:**
- Modify: `shared/lib_webbh/database.py:560-573`

**Step 1: Update the CustomPlaybook model**

Change:
```python
stages: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
concurrency: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

To:
```python
workers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
```

The `workers` JSON column stores the full `[{name, enabled, stages, concurrency}, ...]` array. Concurrency is now per-worker inside each entry, so the separate `concurrency` column is removed.

**Step 2: Commit**

```bash
git add shared/lib_webbh/database.py
git commit -m "refactor(db): update CustomPlaybook model from flat stages to workers"
```

---

## Task 4: Update Orchestrator Playbook Endpoints

**Files:**
- Modify: `orchestrator/main.py:186-196` (Pydantic models)
- Modify: `orchestrator/main.py:2322-2425` (CRUD endpoints)
- Modify: `orchestrator/main.py:1637-1669` (execution state endpoint)
- Modify: `orchestrator/main.py:1673-1698` (apply-playbook endpoint)

**Step 1: Update Pydantic models**

Replace `PlaybookCreate` and `PlaybookUpdate` (lines 186-196):

```python
class PlaybookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    workers: list[dict] = Field(..., min_length=1)

class PlaybookUpdate(BaseModel):
    description: Optional[str] = None
    workers: Optional[list[dict]] = None
```

**Step 2: Update CRUD endpoints**

In `create_playbook` (line 2322): change `body.stages` -> `body.workers`, `playbook.stages` -> `playbook.workers`, `body.concurrency` -> remove (concurrency is per-worker now).

In `list_playbooks` (line 2355): built-in playbooks already use `to_dict()` which now returns `workers`. For custom playbooks, change `"stages": pb.stages` -> `"workers": pb.workers`, remove `"concurrency"`.

In `update_playbook` (line 2381): change `body.stages` -> `body.workers`, `playbook.stages` -> `playbook.workers`. Remove concurrency handling.

Response shape for all CRUD endpoints:
```python
{
    "id": playbook.id,
    "name": playbook.name,
    "description": playbook.description,
    "workers": playbook.workers,
    "builtin": False,
}
```

**Step 3: Update apply-playbook endpoint**

In `apply_playbook` (line 1679): the `get_playbook()` call and `playbook.to_dict()` already produce the new format. No changes needed beyond import cleanup (remove `_ALL_RECON_STAGES` import if present).

**Step 4: Rewrite execution state endpoint**

Replace `get_execution_state` (lines 1637-1669). Current implementation uses `_ALL_RECON_STAGES` and pattern-matches `current_phase`. New implementation:

```python
@app.get("/api/v1/targets/{target_id}/execution")
async def get_execution_state(target_id: int):
    from lib_webbh.playbooks import PIPELINE_STAGES

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        jobs = (await session.execute(
            select(JobState).where(JobState.target_id == target_id)
            .order_by(JobState.last_seen.desc())
        )).scalars().all()

    # Group jobs by container_name (= worker type)
    jobs_by_worker: dict[str, JobState] = {}
    for job in jobs:
        worker = job.container_name
        if worker and worker not in jobs_by_worker:
            jobs_by_worker[worker] = job

    workers = []
    for worker_name, stage_names in PIPELINE_STAGES.items():
        job = jobs_by_worker.get(worker_name)
        if job:
            worker_status = job.status.lower()
            current_tool = job.last_tool_executed
            error = getattr(job, "error", None)
        else:
            worker_status = "pending"
            current_tool = None
            error = None

        # Build stage-level status from job state
        stages = []
        for sname in stage_names:
            if job and job.current_phase == sname:
                stage_status = "running" if worker_status == "running" else worker_status
            elif job and job.last_completed_stage and sname <= (job.last_completed_stage or ""):
                stage_status = "completed"
            else:
                stage_status = "pending"
            stages.append({
                "name": sname,
                "status": stage_status,
                "tool": current_tool if stage_status == "running" else None,
            })

        workers.append({
            "name": worker_name,
            "status": worker_status,
            "stages": stages,
            "current_tool": current_tool,
            "error": error,
        })

    return {
        "target_id": target_id,
        "playbook": target.last_playbook or "wide_recon",
        "workers": workers,
    }
```

**Step 5: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat(orchestrator): update playbook endpoints for hierarchical worker model"
```

---

## Task 5: Update Orchestrator API Tests

**Files:**
- Modify: `tests/test_custom_playbooks.py`
- Modify: `tests/test_playbook_api.py`

**Step 1: Update test_custom_playbooks.py**

Change `SAMPLE_PLAYBOOK` from flat stages to workers format:

```python
SAMPLE_PLAYBOOK = {
    "name": "custom_stealth",
    "description": "Low-noise stealth recon",
    "workers": [
        {
            "name": "info_gathering",
            "enabled": True,
            "stages": [
                {"name": "search_engine_recon", "enabled": False, "tool_timeout": 300},
                {"name": "web_server_fingerprint", "enabled": True, "tool_timeout": 120},
            ],
            "concurrency": {"heavy": 1, "light": 2},
        },
    ],
}
```

Update assertions: `body["stages"]` -> `body["workers"]`, remove `body["concurrency"]` checks. The update test patches `"workers"` instead of `"stages"`.

**Step 2: Update test_playbook_api.py**

In `test_create_target_with_playbook`: the playbook.json now contains `workers` key instead of `stages`.
Change: `assert "stages" in playbook_data` -> `assert "workers" in playbook_data`

**Step 3: Run all playbook tests**

Run: `pytest tests/test_playbooks.py tests/test_custom_playbooks.py tests/test_playbook_api.py -v`
Expected: All PASS.

**Step 4: Commit**

```bash
git add tests/test_custom_playbooks.py tests/test_playbook_api.py
git commit -m "test: update playbook API tests for hierarchical model"
```

---

## Task 6: Fix worker-stages.ts — Add stageName Field + Fix Counts

**Files:**
- Modify: `dashboard/src/lib/worker-stages.ts`
- Modify: `dashboard/src/types/schema.ts:274-293` (WORKER_STAGE_COUNTS)

**Step 1: Add `stageName` field to worker-stages.ts**

Each entry currently has `{ id, name, sectionId }`. Add `stageName` matching the pipeline stage name. The `name` stays as the display name, `stageName` is the pipeline identifier used in playbook configs.

Example for `info_gathering`:
```typescript
info_gathering: [
    { id: "1", name: "Search Engine Discovery", stageName: "search_engine_recon", sectionId: "WSTG-INFO-01" },
    { id: "2", name: "Fingerprint Web Server", stageName: "web_server_fingerprint", sectionId: "WSTG-INFO-02" },
    // ... etc
],
```

Do this for ALL workers. The stageName values must exactly match the names in `PIPELINE_STAGES` from playbooks.py (Task 1). Workers with missing/mismatched stages should be aligned to the pipeline.py source of truth.

Key corrections needed:
- `identity_mgmt`: stages are `role_definitions`, `registration_process`, `account_provisioning`, `account_enumeration`, `weak_username_policy` (from pipeline.py)
- `input_validation`: pipeline has 19 stages (not 15 in current worker-stages.ts). Add missing: `http_param_pollution`, `ssti`, `format_string`, `host_header_injection`, `http_smuggling`, `websocket_injection`. Remove `Buffer Overflow` -> rename to match pipeline name.
- `chain_worker`: pipeline has 5 stages. Add `ai_chain_discovery` if missing.
- `reporting`: pipeline has 4 stages: `data_gathering`, `deduplication`, `rendering`, `export`.
- `mobile_worker`: pipeline has 5 stages (not 8). Align to: `acquire_decompile`, `secret_extraction`, `configuration_audit`, `dynamic_analysis`, `endpoint_feedback`.

**Step 2: Fix WORKER_STAGE_COUNTS in schema.ts**

Update to match actual pipeline stage counts:
```typescript
export const WORKER_STAGE_COUNTS: Record<string, number> = {
  proxy: 0,
  callback: 0,
  sandbox_worker: 0,
  info_gathering: 10,
  config_mgmt: 11,
  identity_mgmt: 5,
  authentication: 10,
  authorization: 4,
  session_mgmt: 9,
  input_validation: 19,   // was 15
  error_handling: 2,
  cryptography: 4,
  business_logic: 9,
  client_side: 13,
  mobile_worker: 5,       // was 8
  reasoning_worker: 3,
  chain_worker: 5,         // was 4
  reporting: 4,            // was 1
};
```

**Step 3: Commit**

```bash
git add dashboard/src/lib/worker-stages.ts dashboard/src/types/schema.ts
git commit -m "fix(dashboard): align worker-stages.ts with pipeline names, fix stage counts"
```

---

## Task 7: Update Dashboard Types

**Files:**
- Modify: `dashboard/src/types/schema.ts:168-180` (ExecutionState)
- Modify: `dashboard/src/lib/api.ts:213-226` (PlaybookRow, StageConfig)

**Step 1: Add WorkerExecution to schema.ts**

After the existing `StageExecution` interface (line 174), add:

```typescript
export interface WorkerExecution {
  name: string;
  status: "pending" | "queued" | "running" | "completed" | "failed" | "skipped";
  stages: StageExecution[];
  current_tool?: string;
  error?: string;
  skip_reason?: string;
}
```

Update `ExecutionState` (lines 176-180):
```typescript
export interface ExecutionState {
  target_id: number;
  playbook: string;
  workers: WorkerExecution[];
}
```

**Step 2: Update PlaybookRow and add WorkerConfig in api.ts**

Replace the StageConfig/PlaybookRow types (lines 213-226):

```typescript
export interface StageConfig {
  name: string;
  enabled: boolean;
  tool_timeout?: number;
}

export interface WorkerConfig {
  name: string;
  enabled: boolean;
  stages: StageConfig[];
  concurrency: { heavy: number; light: number };
}

export interface PlaybookRow {
  id?: number;
  name: string;
  description: string | null;
  workers: WorkerConfig[];
  builtin: boolean;
}
```

**Step 3: Update createPlaybook and updatePlaybook functions in api.ts**

Change `createPlaybook` (line 567): `stages: StageConfig[]` -> `workers: WorkerConfig[]`, remove `concurrency` param.

Change `updatePlaybook` (line 579): `stages?: StageConfig[]` -> `workers?: WorkerConfig[]`, remove `concurrency` param.

**Step 4: Commit**

```bash
git add dashboard/src/types/schema.ts dashboard/src/lib/api.ts
git commit -m "feat(dashboard): update TypeScript types for hierarchical playbook model"
```

---

## Task 8: Rewrite Flow Page

**Files:**
- Modify: `dashboard/src/app/campaign/flow/page.tsx` (full rewrite)

**Step 1: Implement WorkerCard component**

Collapsible card for the configurator panel. Shows:
- Worker name + toggle switch + stage count badge + chevron
- Expanded: individual stages with toggles + timeout sliders
- Dependency awareness: muted + "blocked by" label when upstream disabled

```typescript
function WorkerCard({
  worker,
  onToggleWorker,
  onToggleStage,
  onStageTimeoutChange,
  blockedBy,
  stageDisplayInfo,
}: {
  worker: WorkerConfig;
  onToggleWorker: () => void;
  onToggleStage: (stageIndex: number) => void;
  onStageTimeoutChange: (stageIndex: number, value: number) => void;
  blockedBy: string | null;
  stageDisplayInfo: { name: string; stageName: string; sectionId: string }[];
}) { ... }
```

Uses `WORKER_STAGES` from `worker-stages.ts` for display names. The `stageName` field maps to playbook stage names.

**Step 2: Implement WorkerMonitorCard component**

Collapsible card for the execution monitor panel. Shows:
- Worker name + status icon + progress bar + current tool
- Expanded: individual stage execution entries
- Auto-collapses when completed

```typescript
function WorkerMonitorCard({
  worker,
  stageDisplayInfo,
}: {
  worker: WorkerExecution;
  stageDisplayInfo: { name: string; stageName: string; sectionId: string }[];
}) { ... }
```

**Step 3: Rewrite FlowPage main component**

Remove all references to `DEFAULT_STAGES` and flat stage config. The page now:

1. Fetches playbooks on mount (same as before)
2. On playbook selection, populates `workers: WorkerConfig[]` state from the selected playbook
3. Left panel: renders `WorkerCard` for each worker in `PIPELINE_WORKER_NAMES` order
4. Implements dependency logic: when toggling a worker off, compute downstream workers to auto-disable using `WORKER_DEPENDENCIES` from schema.ts
5. Right panel: renders `WorkerMonitorCard` for each worker from execution state
6. Bottom: `ScanTimeline` (unchanged)

Key state:
```typescript
const [workers, setWorkers] = useState<WorkerConfig[]>([]);
```

Dependency logic helper:
```typescript
function getBlockedBy(workerName: string, workers: WorkerConfig[]): string | null {
  const deps = WORKER_DEPENDENCIES[workerName] || [];
  const disabledWorkers = new Set(workers.filter(w => !w.enabled).map(w => w.name));
  for (const dep of deps) {
    if (disabledWorkers.has(dep)) return dep;
  }
  return null;
}
```

**Step 4: Start dev server and test**

Run: `cd dashboard && npm run dev`

Test cases:
- Select a playbook -> worker tree populates with correct worker/stage counts
- Toggle a worker off -> downstream dependents get blocked
- Toggle it back on -> dependents unblock
- Expand a worker -> stages visible with toggles and timeout sliders
- Toggle individual stages -> stage count badge updates
- "Save as Custom Playbook" -> saves with new workers format
- "Apply to Target" -> applies correctly
- Execution monitor shows worker-level progress when a scan is running

**Step 5: Commit**

```bash
git add dashboard/src/app/campaign/flow/page.tsx
git commit -m "feat(dashboard): rewrite flow page with worker+stage pipeline tree"
```

---

## Task 9: Final Integration Test

**Step 1: Run all backend tests**

Run: `pytest tests/ -v`
Expected: All PASS.

**Step 2: Run dashboard build**

Run: `cd dashboard && npm run build`
Expected: Build succeeds with no type errors.

**Step 3: Manual smoke test**

Start full stack: `docker compose up --build`

1. Create a target
2. Go to Phase Flow page
3. Select `wide_recon` playbook -> all 15 workers shown, all stages enabled
4. Switch to `api_focused` -> `client_side`, `mobile_worker`, `session_mgmt` disabled
5. Apply playbook to target
6. Monitor execution in right panel

**Step 4: Final commit**

```bash
git commit -m "test: verify flow page + playbook integration"
```
