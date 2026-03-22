# Innovative Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 7 cross-cutting features that improve recon efficiency, triage quality, reporting speed, and operational visibility across the WebAppBH framework.

**Architecture:** Each feature is self-contained and independently deployable. Features touch the shared library (new DB models, messaging helpers), orchestrator (new API endpoints, event engine triggers), workers (pipeline changes), and dashboard (new pages/components). No feature depends on another — they can be built in any order.

**Tech Stack:** Python 3.12 + SQLAlchemy async + FastAPI + Redis Streams + Docker SDK + Next.js 16 + React 19 + Zustand + TanStack Table + D3.js (graph viz only)

---

## Feature 1: Campaign Playbooks

Lets users select a strategy template when creating a target. Each playbook defines which pipeline stages run, tool parameters, and concurrency weights — so a "wide recon" target runs differently from a "deep webapp" target.

---

### Task 1.1: Add Playbook Schema to Shared Library

**Files:**
- Create: `shared/lib_webbh/playbooks.py`
- Test: `tests/test_playbooks.py`

**Step 1: Write the failing test**

```python
# tests/test_playbooks.py
"""Tests for playbook loading and validation."""

import pytest
from lib_webbh.playbooks import BUILTIN_PLAYBOOKS, get_playbook, PlaybookConfig


def test_builtin_playbooks_exist():
    """All 4 built-in playbooks must be loadable."""
    assert "wide_recon" in BUILTIN_PLAYBOOKS
    assert "deep_webapp" in BUILTIN_PLAYBOOKS
    assert "api_focused" in BUILTIN_PLAYBOOKS
    assert "cloud_first" in BUILTIN_PLAYBOOKS


def test_get_playbook_returns_config():
    config = get_playbook("wide_recon")
    assert isinstance(config, PlaybookConfig)
    assert len(config.stages) > 0
    assert config.concurrency.heavy >= 1
    assert config.concurrency.light >= 1


def test_get_playbook_unknown_returns_default():
    config = get_playbook("nonexistent")
    assert isinstance(config, PlaybookConfig)
    assert config.name == "wide_recon"  # falls back to default


def test_playbook_stage_has_tools():
    config = get_playbook("deep_webapp")
    for stage in config.stages:
        assert isinstance(stage.name, str)
        assert isinstance(stage.enabled, bool)


def test_playbook_config_serializable():
    config = get_playbook("wide_recon")
    d = config.to_dict()
    assert isinstance(d, dict)
    assert "stages" in d
    assert "concurrency" in d
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_playbooks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lib_webbh.playbooks'`

**Step 3: Write minimal implementation**

```python
# shared/lib_webbh/playbooks.py
"""Built-in campaign playbooks for WebAppBH.

Each playbook defines which pipeline stages are enabled, tool-specific
parameters, and concurrency settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ConcurrencyConfig:
    heavy: int = 2
    light: int = 4


@dataclass
class StageConfig:
    name: str
    enabled: bool = True
    tool_timeout: int = 600  # seconds


@dataclass
class PlaybookConfig:
    name: str
    description: str
    stages: list[StageConfig] = field(default_factory=list)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

    def to_dict(self) -> dict:
        return asdict(self)


# All 7 recon stages (from workers/recon_core/pipeline.py)
_ALL_RECON_STAGES = [
    "passive_discovery",
    "active_discovery",
    "liveness_dns",
    "subdomain_takeover",
    "fingerprinting",
    "port_mapping",
    "deep_recon",
]

BUILTIN_PLAYBOOKS: dict[str, PlaybookConfig] = {
    "wide_recon": PlaybookConfig(
        name="wide_recon",
        description="Full 7-stage recon pipeline with high concurrency. Best for large targets with many subdomains.",
        stages=[StageConfig(name=s) for s in _ALL_RECON_STAGES],
        concurrency=ConcurrencyConfig(heavy=2, light=8),
    ),
    "deep_webapp": PlaybookConfig(
        name="deep_webapp",
        description="Focused on web application testing. Skips active discovery, emphasizes deep recon and fingerprinting.",
        stages=[
            StageConfig(name="passive_discovery"),
            StageConfig(name="active_discovery", enabled=False),
            StageConfig(name="liveness_dns"),
            StageConfig(name="subdomain_takeover", enabled=False),
            StageConfig(name="fingerprinting"),
            StageConfig(name="port_mapping"),
            StageConfig(name="deep_recon"),
        ],
        concurrency=ConcurrencyConfig(heavy=3, light=6),
    ),
    "api_focused": PlaybookConfig(
        name="api_focused",
        description="Minimal recon, maximum parameter discovery. For targets with known API surface.",
        stages=[
            StageConfig(name="passive_discovery"),
            StageConfig(name="active_discovery", enabled=False),
            StageConfig(name="liveness_dns"),
            StageConfig(name="subdomain_takeover", enabled=False),
            StageConfig(name="fingerprinting", enabled=False),
            StageConfig(name="port_mapping"),
            StageConfig(name="deep_recon"),
        ],
        concurrency=ConcurrencyConfig(heavy=1, light=4),
    ),
    "cloud_first": PlaybookConfig(
        name="cloud_first",
        description="Full recon plus aggressive cloud enumeration. For targets with significant cloud footprint.",
        stages=[StageConfig(name=s) for s in _ALL_RECON_STAGES],
        concurrency=ConcurrencyConfig(heavy=2, light=6),
    ),
}

DEFAULT_PLAYBOOK = "wide_recon"


def get_playbook(name: str) -> PlaybookConfig:
    """Return a playbook config by name, falling back to the default."""
    return BUILTIN_PLAYBOOKS.get(name, BUILTIN_PLAYBOOKS[DEFAULT_PLAYBOOK])
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_playbooks.py -v`
Expected: PASS (all 5 tests)

**Step 5: Commit**

```bash
git add shared/lib_webbh/playbooks.py tests/test_playbooks.py
git commit -m "feat(playbooks): add built-in playbook schema and loader"
```

---

### Task 1.2: Wire Playbook into Target Creation API

**Files:**
- Modify: `orchestrator/main.py:85-93` (TargetCreate model)
- Modify: `orchestrator/main.py:158-194` (create_target endpoint)
- Test: `tests/test_playbook_api.py`

**Step 1: Write the failing test**

```python
# tests/test_playbook_api.py
"""Test playbook selection via the target creation API."""

import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app

pytestmark = pytest.mark.anyio


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_create_target_with_playbook(client):
    resp = await client.post(
        "/api/v1/targets",
        json={
            "company_name": "TestCo",
            "base_domain": "test.com",
            "playbook": "deep_webapp",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["playbook"] == "deep_webapp"


async def test_create_target_default_playbook(client):
    resp = await client.post(
        "/api/v1/targets",
        json={"company_name": "TestCo2", "base_domain": "test2.com"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["playbook"] == "wide_recon"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_playbook_api.py -v`
Expected: FAIL — `playbook` field not accepted / not in response

**Step 3: Modify orchestrator/main.py**

Add to `TargetCreate` (line ~85):
```python
class TargetCreate(BaseModel):
    company_name: str
    base_domain: str
    target_profile: Optional[dict] = Field(default=None, description="Scope rules, rate limits, custom headers")
    playbook: str = Field(default="wide_recon", description="Playbook name: wide_recon, deep_webapp, api_focused, cloud_first")
```

In `create_target` endpoint (line ~158), after writing `target_profile.json`, add:
```python
    # Write playbook config
    from lib_webbh.playbooks import get_playbook
    playbook_config = get_playbook(body.playbook)
    (profile_dir / "playbook.json").write_text(
        json.dumps(playbook_config.to_dict(), indent=2)
    )
```

And in the return dict, add:
```python
    return {
        "target_id": target.id,
        "company_name": target.company_name,
        "base_domain": target.base_domain,
        "profile_path": str(profile_path),
        "playbook": playbook_config.name,
    }
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_playbook_api.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_playbook_api.py
git commit -m "feat(playbooks): wire playbook selection into target creation API"
```

---

### Task 1.3: Apply Playbook in Recon Pipeline

**Files:**
- Modify: `workers/recon_core/pipeline.py:57-97` (Pipeline class)
- Modify: `workers/recon_core/main.py` (load playbook config)
- Test: `tests/test_playbook_pipeline.py`

**Step 1: Write the failing test**

```python
# tests/test_playbook_pipeline.py
"""Test that the pipeline respects playbook stage.enabled flags."""

import pytest
from unittest.mock import AsyncMock, patch
from workers.recon_core.pipeline import Pipeline, STAGES

pytestmark = pytest.mark.anyio


def test_filter_stages_by_playbook():
    """Pipeline._filter_stages should remove disabled stages."""
    pipeline = Pipeline(target_id=1, container_name="test")
    playbook = {
        "stages": [
            {"name": "passive_discovery", "enabled": True},
            {"name": "active_discovery", "enabled": False},
            {"name": "liveness_dns", "enabled": True},
            {"name": "subdomain_takeover", "enabled": False},
            {"name": "fingerprinting", "enabled": True},
            {"name": "port_mapping", "enabled": True},
            {"name": "deep_recon", "enabled": True},
        ]
    }
    filtered = pipeline._filter_stages(playbook)
    names = [s.name for s in filtered]
    assert "active_discovery" not in names
    assert "subdomain_takeover" not in names
    assert "passive_discovery" in names
    assert len(names) == 5
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_playbook_pipeline.py -v`
Expected: FAIL — `Pipeline._filter_stages` does not exist

**Step 3: Modify workers/recon_core/pipeline.py**

Add method to `Pipeline` class:
```python
    def _filter_stages(self, playbook: dict | None) -> list[Stage]:
        """Return only the stages enabled by the playbook config."""
        if not playbook or "stages" not in playbook:
            return list(STAGES)

        enabled_names = {
            s["name"] for s in playbook["stages"] if s.get("enabled", True)
        }
        return [stage for stage in STAGES if stage.name in enabled_names]
```

Modify `Pipeline.run()` to accept and use playbook:
```python
    async def run(
        self,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        playbook: dict | None = None,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        stages = self._filter_stages(playbook)
        # ... rest uses `stages` instead of `STAGES`
```

Modify `workers/recon_core/main.py` `handle_message` to load playbook:
```python
    # After loading target_profile.json
    playbook_path = config_dir / "playbook.json"
    playbook = json.loads(playbook_path.read_text()) if playbook_path.exists() else None
    # Pass to pipeline.run(..., playbook=playbook)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_playbook_pipeline.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add workers/recon_core/pipeline.py workers/recon_core/main.py tests/test_playbook_pipeline.py
git commit -m "feat(playbooks): apply playbook stage filtering in recon pipeline"
```

---

### Task 1.4: Dashboard Playbook Selector

**Files:**
- Modify: `dashboard/src/components/campaign/CampaignPicker.tsx` (add playbook dropdown)
- Modify: `dashboard/src/lib/api.ts:28-39` (add playbook field to CreateTargetPayload)
- Modify: `dashboard/src/types/schema.ts` (add Playbook type)

**Step 1: Add TypeScript types**

Add to `dashboard/src/types/schema.ts`:
```typescript
export type PlaybookName = "wide_recon" | "deep_webapp" | "api_focused" | "cloud_first";

export interface PlaybookMeta {
  name: PlaybookName;
  label: string;
  description: string;
}

export const PLAYBOOKS: PlaybookMeta[] = [
  { name: "wide_recon", label: "Wide Recon", description: "Full 7-stage pipeline. Best for large targets." },
  { name: "deep_webapp", label: "Deep Web App", description: "Focused web testing. Skips active discovery." },
  { name: "api_focused", label: "API Focused", description: "Minimal recon, maximum param discovery." },
  { name: "cloud_first", label: "Cloud First", description: "Full recon + aggressive cloud enum." },
];
```

**Step 2: Update API client**

In `dashboard/src/lib/api.ts`, add `playbook` to `CreateTargetPayload`:
```typescript
export interface CreateTargetPayload {
  company_name: string;
  base_domain: string;
  target_profile?: TargetProfile;
  playbook?: PlaybookName;
}
```

**Step 3: Add playbook selector to CampaignPicker**

Read the existing `CampaignPicker.tsx` and add a `<select>` element for playbook selection in the campaign creation form. The select should:
- Default to `"wide_recon"`
- Show each playbook's label and description
- Pass the selected value in the `createTarget` API call

**Step 4: Verify**

Run: `cd dashboard && npm run build`
Expected: Build succeeds with no type errors

**Step 5: Commit**

```bash
git add dashboard/src/types/schema.ts dashboard/src/lib/api.ts dashboard/src/components/campaign/CampaignPicker.tsx
git commit -m "feat(dashboard): add playbook selector to campaign creation"
```

---

## Feature 2: Live Recon Diffing

Enables periodic re-scans per target and surfaces deltas (new, removed, changed assets) since the last scan. Only new assets trigger downstream workers.

---

### Task 2.1: Add AssetSnapshot Model

**Files:**
- Modify: `shared/lib_webbh/database.py` (add AssetSnapshot model)
- Test: `tests/test_asset_snapshot.py`

**Step 1: Write the failing test**

```python
# tests/test_asset_snapshot.py
"""Test AssetSnapshot model creation and querying."""

import pytest
from sqlalchemy import select
from lib_webbh import get_session, Asset, Target
from lib_webbh.database import AssetSnapshot, Base, get_engine

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def test_create_asset_snapshot():
    async with get_session() as session:
        target = Target(company_name="DiffCo", base_domain="diff.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        snapshot = AssetSnapshot(
            target_id=target.id,
            scan_number=1,
            asset_count=42,
            asset_hashes={"sub1.diff.com": "abc123", "sub2.diff.com": "def456"},
        )
        session.add(snapshot)
        await session.commit()
        await session.refresh(snapshot)

        assert snapshot.id is not None
        assert snapshot.scan_number == 1
        assert snapshot.asset_count == 42
        assert "sub1.diff.com" in snapshot.asset_hashes
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_asset_snapshot.py -v`
Expected: FAIL — `ImportError: cannot import name 'AssetSnapshot'`

**Step 3: Add model to database.py**

Add after the `Alert` model in `shared/lib_webbh/database.py`:

```python
class AssetSnapshot(TimestampMixin, Base):
    """Point-in-time snapshot of all assets for a target (recon diffing)."""

    __tablename__ = "asset_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_number: Mapped[int] = mapped_column(Integer)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    asset_hashes: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="snapshots")

    __table_args__ = (
        UniqueConstraint("target_id", "scan_number", name="uq_snapshot_target_scan"),
    )
```

Add `snapshots` relationship to `Target` model:
```python
    snapshots: Mapped[list["AssetSnapshot"]] = relationship(back_populates="target", cascade="all, delete-orphan")
```

Add `AssetSnapshot` to `__init__.py` exports.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_asset_snapshot.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_asset_snapshot.py
git commit -m "feat(diffing): add AssetSnapshot model for recon diffing"
```

---

### Task 2.2: Add Diff Computation Logic

**Files:**
- Create: `shared/lib_webbh/diffing.py`
- Test: `tests/test_diffing.py`

**Step 1: Write the failing test**

```python
# tests/test_diffing.py
"""Test asset diff computation."""

import pytest
from lib_webbh.diffing import compute_diff, DiffResult


def test_compute_diff_new_assets():
    prev = {"sub1.example.com": "hash1", "sub2.example.com": "hash2"}
    curr = {"sub1.example.com": "hash1", "sub2.example.com": "hash2", "sub3.example.com": "hash3"}
    result = compute_diff(prev, curr)
    assert isinstance(result, DiffResult)
    assert result.added == ["sub3.example.com"]
    assert result.removed == []
    assert result.unchanged == ["sub1.example.com", "sub2.example.com"]


def test_compute_diff_removed_assets():
    prev = {"sub1.example.com": "hash1", "sub2.example.com": "hash2"}
    curr = {"sub1.example.com": "hash1"}
    result = compute_diff(prev, curr)
    assert result.removed == ["sub2.example.com"]
    assert result.added == []


def test_compute_diff_empty_previous():
    prev = {}
    curr = {"sub1.example.com": "hash1"}
    result = compute_diff(prev, curr)
    assert result.added == ["sub1.example.com"]
    assert len(result.removed) == 0


def test_compute_diff_no_changes():
    prev = {"sub1.example.com": "hash1"}
    curr = {"sub1.example.com": "hash1"}
    result = compute_diff(prev, curr)
    assert result.added == []
    assert result.removed == []
    assert result.unchanged == ["sub1.example.com"]
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_diffing.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib_webbh.diffing'`

**Step 3: Write implementation**

```python
# shared/lib_webbh/diffing.py
"""Asset diff computation for live recon diffing."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiffResult:
    """Result of comparing two asset snapshots."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


def compute_diff(
    previous: dict[str, str],
    current: dict[str, str],
) -> DiffResult:
    """Compare two asset hash maps and return the diff.

    Parameters
    ----------
    previous : dict[str, str]
        Mapping of asset_value → hash from the previous snapshot.
    current : dict[str, str]
        Mapping of asset_value → hash from the current scan.
    """
    prev_keys = set(previous.keys())
    curr_keys = set(current.keys())

    added = sorted(curr_keys - prev_keys)
    removed = sorted(prev_keys - curr_keys)
    unchanged = sorted(curr_keys & prev_keys)

    return DiffResult(added=added, removed=removed, unchanged=unchanged)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_diffing.py -v`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
git add shared/lib_webbh/diffing.py tests/test_diffing.py
git commit -m "feat(diffing): add asset diff computation logic"
```

---

### Task 2.3: Add Rescan API Endpoint

**Files:**
- Modify: `orchestrator/main.py` (add POST /api/v1/targets/{target_id}/rescan)
- Test: `tests/test_rescan_api.py`

**Step 1: Write the failing test**

```python
# tests/test_rescan_api.py
"""Test the rescan endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app

pytestmark = pytest.mark.anyio


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_rescan_endpoint_exists(client):
    # First create a target
    resp = await client.post(
        "/api/v1/targets",
        json={"company_name": "RescanCo", "base_domain": "rescan.com"},
    )
    assert resp.status_code == 201
    target_id = resp.json()["target_id"]

    # Trigger rescan
    resp = await client.post(f"/api/v1/targets/{target_id}/rescan")
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "queued"
    assert data["target_id"] == target_id
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_rescan_api.py -v`
Expected: FAIL — 404 or 405, endpoint does not exist

**Step 3: Add endpoint to orchestrator/main.py**

Add after the existing report endpoints:

```python
# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/rescan — trigger a re-scan
# ---------------------------------------------------------------------------
@app.post("/api/v1/targets/{target_id}/rescan", status_code=201)
async def trigger_rescan(target_id: int):
    """Trigger a rescan for delta detection.

    Snapshots current assets, then queues a new recon run.
    When the recon completes, the diff is computed against the snapshot.
    """
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        # Snapshot current assets
        from lib_webbh.database import AssetSnapshot
        from sqlalchemy import func

        # Get next scan number
        max_scan = (await session.execute(
            select(func.coalesce(func.max(AssetSnapshot.scan_number), 0))
            .where(AssetSnapshot.target_id == target_id)
        )).scalar()
        next_scan = max_scan + 1

        # Build hash map of current assets
        assets = (await session.execute(
            select(Asset).where(Asset.target_id == target_id)
        )).scalars().all()

        asset_hashes = {a.asset_value: f"{a.asset_type}:{a.source_tool}" for a in assets}

        snapshot = AssetSnapshot(
            target_id=target_id,
            scan_number=next_scan,
            asset_count=len(assets),
            asset_hashes=asset_hashes,
        )
        session.add(snapshot)
        await session.commit()

    # Queue recon with rescan flag
    await push_task("recon_queue", {
        "target_id": target_id,
        "rescan": True,
        "snapshot_scan_number": next_scan,
    })

    return {"target_id": target_id, "status": "queued", "scan_number": next_scan}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_rescan_api.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_rescan_api.py
git commit -m "feat(diffing): add rescan API endpoint with asset snapshotting"
```

---

### Task 2.4: Compute and Emit Diff After Rescan Completes

**Files:**
- Modify: `workers/recon_core/pipeline.py` (add diff computation after pipeline completes)
- Modify: `workers/recon_core/main.py` (pass rescan context to pipeline)

**Step 1: Modify pipeline.py**

At the end of `Pipeline.run()`, after `_mark_completed()` and before the `pipeline_complete` event, add:

```python
        # If this is a rescan, compute diff against snapshot
        if playbook and playbook.get("rescan"):
            await self._compute_and_emit_diff(
                playbook["snapshot_scan_number"]
            )
```

Add the diff method:

```python
    async def _compute_and_emit_diff(self, snapshot_scan_number: int) -> None:
        """Compare current assets against the pre-scan snapshot."""
        from lib_webbh.database import AssetSnapshot
        from lib_webbh.diffing import compute_diff

        async with get_session() as session:
            # Load snapshot
            snapshot = (await session.execute(
                select(AssetSnapshot).where(
                    AssetSnapshot.target_id == self.target_id,
                    AssetSnapshot.scan_number == snapshot_scan_number,
                )
            )).scalar_one_or_none()

            if not snapshot:
                self.log.warning("No snapshot found for diff", extra={"scan": snapshot_scan_number})
                return

            # Build current asset map
            from lib_webbh import Asset
            assets = (await session.execute(
                select(Asset).where(Asset.target_id == self.target_id)
            )).scalars().all()
            current_hashes = {a.asset_value: f"{a.asset_type}:{a.source_tool}" for a in assets}

        diff = compute_diff(snapshot.asset_hashes or {}, current_hashes)

        self.log.info(
            "Rescan diff computed",
            extra={"added": len(diff.added), "removed": len(diff.removed)},
        )

        await push_task(f"events:{self.target_id}", {
            "event": "RECON_DIFF",
            "target_id": self.target_id,
            "scan_number": snapshot_scan_number,
            "added": diff.added,
            "removed": diff.removed,
            "added_count": len(diff.added),
            "removed_count": len(diff.removed),
        })
```

**Step 2: Modify main.py**

In `handle_message`, when the incoming data has `rescan: True`, pass it through to the pipeline:

```python
    playbook_data = playbook or {}
    if data.get("rescan"):
        playbook_data["rescan"] = True
        playbook_data["snapshot_scan_number"] = data["snapshot_scan_number"]
```

**Step 3: Commit**

```bash
git add workers/recon_core/pipeline.py workers/recon_core/main.py
git commit -m "feat(diffing): compute and emit asset diff after rescan completes"
```

---

### Task 2.5: Dashboard Diff Timeline

**Files:**
- Create: `dashboard/src/components/campaign/DiffTimeline.tsx`
- Modify: `dashboard/src/types/events.ts` (add RECON_DIFF event type)
- Modify: `dashboard/src/hooks/useEventStream.ts` (listen for RECON_DIFF)
- Modify: `dashboard/src/app/campaign/assets/page.tsx` (render DiffTimeline)

**Step 1: Add event type**

In `dashboard/src/types/events.ts`, add `"RECON_DIFF"` to `SSEEventType` union and add:
```typescript
export interface ReconDiffEvent extends SSEEvent {
  event: "RECON_DIFF";
  scan_number: number;
  added: string[];
  removed: string[];
  added_count: number;
  removed_count: number;
}
```

**Step 2: Update useEventStream**

Add `"RECON_DIFF"` to the event types array in `useEventStream.ts` (line ~54).

Add a toast for RECON_DIFF events:
```typescript
if (data.event === "RECON_DIFF") {
  const diff = data as ReconDiffEvent;
  toast.info(`Rescan complete: +${diff.added_count} new, -${diff.removed_count} removed`, {
    duration: 8_000,
  });
}
```

**Step 3: Create DiffTimeline component**

```tsx
// dashboard/src/components/campaign/DiffTimeline.tsx
"use client";

import { useMemo } from "react";
import type { SSEEvent } from "@/types/events";

interface Props {
  events: SSEEvent[];
}

export function DiffTimeline({ events }: Props) {
  const diffs = useMemo(
    () => events.filter((e) => e.event === "RECON_DIFF"),
    [events],
  );

  if (diffs.length === 0) return null;

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <h3 className="mb-3 text-sm font-medium text-zinc-400">Recon Diff Timeline</h3>
      <div className="space-y-2">
        {diffs.map((d, i) => {
          const diff = d as Record<string, unknown>;
          return (
            <div key={i} className="flex items-center gap-3 text-xs text-zinc-300">
              <span className="text-zinc-500">{d.timestamp}</span>
              <span className="text-green-400">+{String(diff.added_count ?? 0)} new</span>
              <span className="text-red-400">-{String(diff.removed_count ?? 0)} removed</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
```

**Step 4: Add DiffTimeline to assets page**

Import and render `<DiffTimeline events={events} />` in the assets page, passing the events from `useEventStream`.

**Step 5: Verify**

Run: `cd dashboard && npm run build`
Expected: Build succeeds

**Step 6: Commit**

```bash
git add dashboard/src/types/events.ts dashboard/src/hooks/useEventStream.ts dashboard/src/components/campaign/DiffTimeline.tsx dashboard/src/app/campaign/assets/page.tsx
git commit -m "feat(dashboard): add recon diff timeline to assets page"
```

---

## Feature 3: Report Draft Generator

One-click report generation from any vulnerability row. Template engine pulls finding data and formats for HackerOne/Bugcrowd.

---

### Task 3.1: Add Report Template Engine

**Files:**
- Create: `shared/lib_webbh/report_templates.py`
- Test: `tests/test_report_templates.py`

**Step 1: Write the failing test**

```python
# tests/test_report_templates.py
"""Test report template rendering."""

import pytest
from lib_webbh.report_templates import render_vuln_report, Platform


def test_render_hackerone_report():
    vuln = {
        "title": "Reflected XSS in Search",
        "severity": "high",
        "asset_value": "search.example.com",
        "description": "User input reflected without encoding",
        "poc": "https://search.example.com?q=<script>alert(1)</script>",
        "source_tool": "dalfox",
        "cvss_score": 7.5,
    }
    report = render_vuln_report(vuln, Platform.HACKERONE)
    assert "## Summary" in report
    assert "Reflected XSS in Search" in report
    assert "search.example.com" in report
    assert "## Steps to Reproduce" in report
    assert "## Impact" in report


def test_render_bugcrowd_report():
    vuln = {
        "title": "SQL Injection",
        "severity": "critical",
        "asset_value": "api.example.com",
        "description": "Unsanitized input in login endpoint",
        "poc": "sqlmap -u https://api.example.com/login --data='user=admin'",
        "source_tool": "sqlmap",
    }
    report = render_vuln_report(vuln, Platform.BUGCROWD)
    assert "SQL Injection" in report
    assert "api.example.com" in report


def test_render_report_missing_fields():
    vuln = {"title": "Missing Info Vuln", "severity": "low"}
    report = render_vuln_report(vuln, Platform.HACKERONE)
    assert "Missing Info Vuln" in report
    assert "N/A" in report  # placeholder for missing fields
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_report_templates.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write implementation**

```python
# shared/lib_webbh/report_templates.py
"""Vulnerability report template engine for bug bounty platforms."""

from __future__ import annotations

from enum import Enum


class Platform(Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"


_HACKERONE_TEMPLATE = """## Summary

**Title:** {title}
**Severity:** {severity}
**Affected Asset:** {asset_value}
**CVSS Score:** {cvss_score}

## Description

{description}

## Steps to Reproduce

1. Navigate to the affected asset: `{asset_value}`
2. Apply the following proof of concept:

```
{poc}
```

3. Observe the vulnerability behavior as described above.

## Impact

A {severity}-severity {title} on `{asset_value}` could allow an attacker to compromise the confidentiality, integrity, or availability of the target system. The finding was identified using `{source_tool}`.

## Supporting Material / References

- Tool: `{source_tool}`
- Asset: `{asset_value}`
"""

_BUGCROWD_TEMPLATE = """## Vulnerability: {title}

**Severity:** {severity}
**Asset:** {asset_value}
**CVSS:** {cvss_score}
**Discovery Tool:** {source_tool}

### Description

{description}

### Proof of Concept

```
{poc}
```

### Suggested Remediation

Address the identified {title} on `{asset_value}` by implementing appropriate input validation, output encoding, or access controls as applicable to this vulnerability class.
"""

_TEMPLATES = {
    Platform.HACKERONE: _HACKERONE_TEMPLATE,
    Platform.BUGCROWD: _BUGCROWD_TEMPLATE,
}


def render_vuln_report(vuln: dict, platform: Platform) -> str:
    """Render a vulnerability dict into a platform-specific report draft.

    Missing fields are replaced with "N/A".
    """
    defaults = {
        "title": "N/A",
        "severity": "N/A",
        "asset_value": "N/A",
        "description": "N/A",
        "poc": "N/A",
        "source_tool": "N/A",
        "cvss_score": "N/A",
    }
    data = {**defaults, **{k: v for k, v in vuln.items() if v is not None}}
    template = _TEMPLATES[platform]
    return template.format(**data)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_report_templates.py -v`
Expected: PASS (all 3 tests)

**Step 5: Commit**

```bash
git add shared/lib_webbh/report_templates.py tests/test_report_templates.py
git commit -m "feat(reporting): add vulnerability report template engine"
```

---

### Task 3.2: Add Draft Report API Endpoint

**Files:**
- Modify: `orchestrator/main.py` (add GET /api/v1/vulnerabilities/{vuln_id}/draft)

**Step 1: Write the failing test**

```python
# tests/test_draft_report_api.py
"""Test the draft report generation endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app
from lib_webbh import get_session, Target, Vulnerability
from lib_webbh.database import Base, get_engine

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_draft_report_hackerone(client):
    # Create target + vuln
    async with get_session() as session:
        target = Target(company_name="DraftCo", base_domain="draft.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        vuln = Vulnerability(
            target_id=target.id,
            severity="high",
            title="XSS in Search",
            description="Reflected XSS",
            poc="<script>alert(1)</script>",
            source_tool="dalfox",
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)

    resp = await client.get(f"/api/v1/vulnerabilities/{vuln.id}/draft?platform=hackerone")
    assert resp.status_code == 200
    data = resp.json()
    assert "draft" in data
    assert "XSS in Search" in data["draft"]
    assert "## Summary" in data["draft"]
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_draft_report_api.py -v`
Expected: FAIL — 404/405, endpoint does not exist

**Step 3: Add endpoint to orchestrator/main.py**

```python
@app.get("/api/v1/vulnerabilities/{vuln_id}/draft")
async def draft_vuln_report(
    vuln_id: int,
    platform: str = Query(default="hackerone", description="hackerone or bugcrowd"),
):
    """Generate a draft bug bounty report for a single vulnerability."""
    from lib_webbh.report_templates import render_vuln_report, Platform

    platform_enum = Platform.HACKERONE if platform == "hackerone" else Platform.BUGCROWD

    async with get_session() as session:
        from sqlalchemy.orm import selectinload
        vuln = (await session.execute(
            select(Vulnerability)
            .where(Vulnerability.id == vuln_id)
            .options(selectinload(Vulnerability.asset))
        )).scalar_one_or_none()
        if vuln is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        vuln_dict = {
            "title": vuln.title,
            "severity": vuln.severity,
            "asset_value": vuln.asset.asset_value if vuln.asset else "N/A",
            "description": vuln.description,
            "poc": vuln.poc,
            "source_tool": vuln.source_tool,
            "cvss_score": vuln.cvss_score,
        }

    draft = render_vuln_report(vuln_dict, platform_enum)
    return {"vuln_id": vuln_id, "platform": platform, "draft": draft}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_draft_report_api.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_draft_report_api.py
git commit -m "feat(reporting): add draft report generation endpoint"
```

---

### Task 3.3: Dashboard Draft Report Button

**Files:**
- Modify: `dashboard/src/lib/api.ts` (add getDraftReport method)
- Modify: `dashboard/src/app/campaign/vulns/page.tsx` (add "Draft Report" button per vuln row)

**Step 1: Add API method**

In `dashboard/src/lib/api.ts`, add:

```typescript
  getDraftReport(vulnId: number, platform: "hackerone" | "bugcrowd" = "hackerone") {
    return request<{ vuln_id: number; platform: string; draft: string }>(
      `/api/v1/vulnerabilities/${vulnId}/draft?platform=${platform}`,
    );
  },
```

**Step 2: Add draft report dialog to vulns page**

Read the existing `vulns/page.tsx` and add:
- A "Draft Report" button in each vulnerability row
- On click, call `api.getDraftReport(vulnId, platform)`
- Show the draft in a modal/dialog with a "Copy to Clipboard" button
- Use `navigator.clipboard.writeText()` for copy

**Step 3: Verify**

Run: `cd dashboard && npm run build`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add dashboard/src/lib/api.ts dashboard/src/app/campaign/vulns/page.tsx
git commit -m "feat(dashboard): add draft report button to vulnerability rows"
```

---

## Feature 4: Attack Graph Visualization

Force-directed graph showing relationships between assets, IPs, ports, and vulnerabilities.

---

### Task 4.1: Add Graph Data API Endpoint

**Files:**
- Modify: `orchestrator/main.py` (add GET /api/v1/targets/{target_id}/graph)
- Test: `tests/test_graph_api.py`

**Step 1: Write the failing test**

```python
# tests/test_graph_api.py
"""Test the attack graph data endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app
from lib_webbh import get_session, Target, Asset, Location, Vulnerability
from lib_webbh.database import Base, get_engine

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_graph_endpoint_returns_nodes_and_edges(client):
    async with get_session() as session:
        target = Target(company_name="GraphCo", base_domain="graph.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        asset = Asset(target_id=target.id, asset_type="subdomain", asset_value="app.graph.com")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(asset_id=asset.id, port=443, protocol="tcp", service="https", state="open")
        session.add(loc)

        vuln = Vulnerability(target_id=target.id, asset_id=asset.id, severity="high", title="XSS")
        session.add(vuln)
        await session.commit()

    resp = await client.get(f"/api/v1/targets/{target.id}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 2  # at least target + asset
    assert len(data["edges"]) >= 1  # at least target→asset
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_graph_api.py -v`
Expected: FAIL — endpoint does not exist

**Step 3: Add endpoint to orchestrator/main.py**

```python
@app.get("/api/v1/targets/{target_id}/graph")
async def get_attack_graph(target_id: int):
    """Return nodes and edges for the attack surface graph visualization."""
    nodes: list[dict] = []
    edges: list[dict] = []

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        # Target node
        nodes.append({"id": f"target-{target.id}", "label": target.base_domain, "type": "target"})

        # Assets
        assets = (await session.execute(
            select(Asset)
            .where(Asset.target_id == target_id)
            .options(selectinload(Asset.locations))
        )).scalars().all()

        for a in assets:
            node_id = f"asset-{a.id}"
            nodes.append({"id": node_id, "label": a.asset_value, "type": a.asset_type})
            edges.append({"source": f"target-{target.id}", "target": node_id})

            for loc in a.locations:
                loc_id = f"loc-{loc.id}"
                nodes.append({"id": loc_id, "label": f":{loc.port}/{loc.service or ''}", "type": "port"})
                edges.append({"source": node_id, "target": loc_id})

        # Vulnerabilities
        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
        )).scalars().all()

        for v in vulns:
            vuln_id = f"vuln-{v.id}"
            nodes.append({"id": vuln_id, "label": v.title, "type": "vulnerability", "severity": v.severity})
            if v.asset_id:
                edges.append({"source": f"asset-{v.asset_id}", "target": vuln_id})
            else:
                edges.append({"source": f"target-{target.id}", "target": vuln_id})

    return {"nodes": nodes, "edges": edges}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_graph_api.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_graph_api.py
git commit -m "feat(graph): add attack graph data endpoint"
```

---

### Task 4.2: Dashboard Graph Visualization Component

**Files:**
- Create: `dashboard/src/components/campaign/AttackGraph.tsx`
- Create: `dashboard/src/app/campaign/graph/page.tsx`
- Modify: `dashboard/src/lib/api.ts` (add getAttackGraph method)
- Modify: `dashboard/src/components/layout/Sidebar.tsx` (add Graph nav link)

**Step 1: Install D3.js**

Run: `cd dashboard && npm install d3 @types/d3`

**Step 2: Add API method**

In `dashboard/src/lib/api.ts`:

```typescript
  getAttackGraph(targetId: number) {
    return request<{
      nodes: { id: string; label: string; type: string; severity?: string }[];
      edges: { source: string; target: string }[];
    }>(`/api/v1/targets/${targetId}/graph`);
  },
```

**Step 3: Create AttackGraph component**

```tsx
// dashboard/src/components/campaign/AttackGraph.tsx
"use client";

import { useEffect, useRef } from "react";
import * as d3 from "d3";

interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity?: string;
  x?: number;
  y?: number;
}

interface GraphEdge {
  source: string | GraphNode;
  target: string | GraphNode;
}

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const NODE_COLORS: Record<string, string> = {
  target: "#3b82f6",        // blue
  subdomain: "#22c55e",     // green
  ip: "#a855f7",            // purple
  port: "#6b7280",          // gray
  vulnerability: "#ef4444", // red
  url: "#eab308",           // yellow
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f97316",
  low: "#eab308",
  info: "#6b7280",
};

export function AttackGraph({ nodes, edges }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const g = svg.append("g");

    // Zoom
    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 4])
        .on("zoom", (event) => g.attr("transform", event.transform)),
    );

    const simulation = d3
      .forceSimulation(nodes as d3.SimulationNodeDatum[])
      .force("link", d3.forceLink(edges).id((d: any) => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = g
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", "#374151")
      .attr("stroke-width", 1);

    const node = g
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", (d) => (d.type === "target" ? 12 : d.type === "vulnerability" ? 8 : 6))
      .attr("fill", (d) => {
        if (d.type === "vulnerability" && d.severity) {
          return SEVERITY_COLORS[d.severity] ?? NODE_COLORS.vulnerability;
        }
        return NODE_COLORS[d.type] ?? "#6b7280";
      })
      .attr("stroke", "#1f2937")
      .attr("stroke-width", 1)
      .call(
        d3.drag<SVGCircleElement, GraphNode>()
          .on("start", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d: any) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          }),
      );

    // Labels
    const label = g
      .selectAll("text")
      .data(nodes)
      .join("text")
      .text((d) => d.label)
      .attr("font-size", 10)
      .attr("fill", "#9ca3af")
      .attr("dx", 12)
      .attr("dy", 4);

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);
      node.attr("cx", (d: any) => d.x).attr("cy", (d: any) => d.y);
      label.attr("x", (d: any) => d.x).attr("y", (d: any) => d.y);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, edges]);

  return (
    <svg
      ref={svgRef}
      className="h-[600px] w-full rounded-lg border border-zinc-800 bg-zinc-950"
    />
  );
}
```

**Step 4: Create graph page**

```tsx
// dashboard/src/app/campaign/graph/page.tsx
"use client";

import { useEffect, useState } from "react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import { AttackGraph } from "@/components/campaign/AttackGraph";

export default function GraphPage() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [graphData, setGraphData] = useState<{
    nodes: { id: string; label: string; type: string; severity?: string }[];
    edges: { source: string; target: string }[];
  } | null>(null);

  useEffect(() => {
    if (!activeTarget) return;
    api.getAttackGraph(activeTarget.id).then(setGraphData).catch(console.error);
  }, [activeTarget]);

  if (!activeTarget) {
    return <p className="p-6 text-zinc-500">Select a target to view the attack graph.</p>;
  }

  if (!graphData) {
    return <p className="p-6 text-zinc-500">Loading graph...</p>;
  }

  return (
    <div className="p-6">
      <h2 className="mb-4 text-lg font-semibold text-zinc-100">Attack Surface Graph</h2>
      <AttackGraph nodes={graphData.nodes} edges={graphData.edges} />
      <div className="mt-4 flex gap-4 text-xs text-zinc-500">
        <span className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded-full bg-blue-500" /> Target</span>
        <span className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded-full bg-green-500" /> Subdomain</span>
        <span className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded-full bg-purple-500" /> IP</span>
        <span className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded-full bg-gray-500" /> Port</span>
        <span className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded-full bg-red-500" /> Vulnerability</span>
      </div>
    </div>
  );
}
```

**Step 5: Add nav link to Sidebar**

Read `dashboard/src/components/layout/Sidebar.tsx` and add a "Graph" link pointing to `/campaign/graph` with an appropriate Lucide icon (e.g., `Network` or `GitBranch`).

**Step 6: Verify**

Run: `cd dashboard && npm run build`
Expected: Build succeeds

**Step 7: Commit**

```bash
git add dashboard/src/components/campaign/AttackGraph.tsx dashboard/src/app/campaign/graph/page.tsx dashboard/src/lib/api.ts dashboard/src/components/layout/Sidebar.tsx
git commit -m "feat(dashboard): add interactive attack surface graph visualization"
```

---

## Feature 5: Scope Drift Detection

Extends `ScopeManager` with a confidence zone system. Pauses pipeline when assets enter "likely shared infrastructure" zone and asks for human approval.

---

### Task 5.1: Add Shared Infrastructure Fingerprint Database

**Files:**
- Create: `shared/lib_webbh/shared_infra.py`
- Test: `tests/test_shared_infra.py`

**Step 1: Write the failing test**

```python
# tests/test_shared_infra.py
"""Test shared infrastructure fingerprinting."""

import pytest
from lib_webbh.shared_infra import is_shared_infra, InfraClassification


def test_cloudflare_cdn():
    result = is_shared_infra("cdn.cloudflare.com")
    assert result.is_shared is True
    assert result.provider == "Cloudflare"
    assert result.category == "CDN"


def test_amazonaws_s3():
    result = is_shared_infra("my-bucket.s3.amazonaws.com")
    assert result.is_shared is True
    assert result.provider == "AWS"


def test_custom_domain_not_shared():
    result = is_shared_infra("app.customdomain.com")
    assert result.is_shared is False


def test_known_saas_domain():
    result = is_shared_infra("company.zendesk.com")
    assert result.is_shared is True
    assert result.category == "SaaS"


def test_ip_in_cloud_cidr():
    # Cloudflare IP range
    result = is_shared_infra("104.16.0.1")
    assert result.is_shared is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_shared_infra.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write implementation**

```python
# shared/lib_webbh/shared_infra.py
"""Shared infrastructure fingerprinting.

Identifies domains and IPs that belong to CDNs, cloud providers, or SaaS
platforms — assets that are technically in-scope but should be reviewed
before active testing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import netaddr


@dataclass
class InfraClassification:
    is_shared: bool
    provider: Optional[str] = None
    category: Optional[str] = None  # CDN, Cloud, SaaS, Hosting


# Known shared-infra domain suffixes
_SHARED_DOMAINS: list[tuple[str, str, str]] = [
    # (suffix, provider, category)
    ("cloudflare.com", "Cloudflare", "CDN"),
    ("cloudflare-dns.com", "Cloudflare", "CDN"),
    ("cloudfront.net", "AWS", "CDN"),
    ("akamaized.net", "Akamai", "CDN"),
    ("akamaihd.net", "Akamai", "CDN"),
    ("fastly.net", "Fastly", "CDN"),
    ("edgecastcdn.net", "Edgecast", "CDN"),
    ("azureedge.net", "Azure", "CDN"),
    ("googleapis.com", "Google", "Cloud"),
    ("s3.amazonaws.com", "AWS", "Cloud"),
    ("s3-*.amazonaws.com", "AWS", "Cloud"),
    ("amazonaws.com", "AWS", "Cloud"),
    ("azure-api.net", "Azure", "Cloud"),
    ("blob.core.windows.net", "Azure", "Cloud"),
    ("appspot.com", "Google", "Cloud"),
    ("firebaseapp.com", "Google", "Cloud"),
    ("herokuapp.com", "Heroku", "Hosting"),
    ("netlify.app", "Netlify", "Hosting"),
    ("vercel.app", "Vercel", "Hosting"),
    ("pages.dev", "Cloudflare", "Hosting"),
    ("zendesk.com", "Zendesk", "SaaS"),
    ("freshdesk.com", "Freshworks", "SaaS"),
    ("intercom.io", "Intercom", "SaaS"),
    ("statuspage.io", "Atlassian", "SaaS"),
    ("atlassian.net", "Atlassian", "SaaS"),
    ("hubspot.com", "HubSpot", "SaaS"),
    ("mailchimp.com", "Mailchimp", "SaaS"),
    ("shopify.com", "Shopify", "SaaS"),
    ("myshopify.com", "Shopify", "SaaS"),
    ("wordpress.com", "WordPress", "SaaS"),
    ("wixsite.com", "Wix", "SaaS"),
    ("squarespace.com", "Squarespace", "SaaS"),
]

# Known cloud provider CIDR ranges (subset — major ranges)
_SHARED_CIDRS: list[tuple[str, str]] = [
    # (cidr, provider)
    ("104.16.0.0/12", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("131.0.72.0/22", "Cloudflare"),
    ("13.32.0.0/15", "AWS CloudFront"),
    ("52.84.0.0/15", "AWS CloudFront"),
    ("99.84.0.0/16", "AWS CloudFront"),
    ("23.0.0.0/12", "Akamai"),
    ("151.101.0.0/16", "Fastly"),
]

_SHARED_NETWORKS = [(netaddr.IPNetwork(cidr), provider) for cidr, provider in _SHARED_CIDRS]


def is_shared_infra(item: str) -> InfraClassification:
    """Check if an item (domain or IP) belongs to shared infrastructure."""
    item_lower = item.lower().strip()

    # Check IP ranges
    try:
        ip = netaddr.IPAddress(item_lower)
        for network, provider in _SHARED_NETWORKS:
            if ip in network:
                return InfraClassification(is_shared=True, provider=provider, category="CDN")
        return InfraClassification(is_shared=False)
    except (netaddr.AddrFormatError, ValueError):
        pass

    # Check domain suffixes
    for suffix, provider, category in _SHARED_DOMAINS:
        if item_lower == suffix or item_lower.endswith(f".{suffix}"):
            return InfraClassification(is_shared=True, provider=provider, category=category)

    return InfraClassification(is_shared=False)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_shared_infra.py -v`
Expected: PASS (all 5 tests)

**Step 5: Commit**

```bash
git add shared/lib_webbh/shared_infra.py tests/test_shared_infra.py
git commit -m "feat(scope): add shared infrastructure fingerprint database"
```

---

### Task 5.2: Integrate Scope Drift Check into Worker Base

**Files:**
- Modify: `workers/recon_core/base_tool.py` (add shared-infra check after scope check)

**Step 1: Understand the flow**

In `base_tool.py`, the `execute()` method currently does:
1. Check cooldown
2. Acquire semaphore
3. Run subprocess
4. Parse output
5. Scope-check each result → insert if in-scope

**Step 2: Add drift detection**

After the scope check succeeds (item is in-scope), add:

```python
from lib_webbh.shared_infra import is_shared_infra

# In the loop over parsed results, after scope check:
infra = is_shared_infra(result_value)
if infra.is_shared:
    log.warning(
        "Shared infra detected — flagging for review",
        extra={
            "asset": result_value,
            "provider": infra.provider,
            "category": infra.category,
        },
    )
    # Still insert the asset, but mark it in the tech JSON
    # so the dashboard can show a warning
    tech_data = {"shared_infra": True, "provider": infra.provider, "category": infra.category}
```

When inserting the asset, merge `tech_data` into the `tech` JSON column so the dashboard can display a "shared infra" warning badge.

Also emit an SSE event:
```python
    await push_task(f"events:{target_id}", {
        "event": "SCOPE_DRIFT",
        "target_id": target_id,
        "asset_value": result_value,
        "provider": infra.provider,
        "category": infra.category,
    })
```

**Step 3: Commit**

```bash
git add workers/recon_core/base_tool.py
git commit -m "feat(scope): integrate shared-infra drift detection into recon base tool"
```

---

### Task 5.3: Dashboard Scope Drift Alerts

**Files:**
- Modify: `dashboard/src/types/events.ts` (add SCOPE_DRIFT event)
- Modify: `dashboard/src/hooks/useEventStream.ts` (handle SCOPE_DRIFT)

**Step 1: Add event type**

```typescript
export interface ScopeDriftEvent extends SSEEvent {
  event: "SCOPE_DRIFT";
  asset_value: string;
  provider: string;
  category: string;
}
```

Add `"SCOPE_DRIFT"` to `SSEEventType` union.

**Step 2: Add toast handler**

In `useEventStream.ts`, add handling:

```typescript
if (data.event === "SCOPE_DRIFT") {
  const drift = data as ScopeDriftEvent;
  toast.warning(`Shared infra detected: ${drift.asset_value}`, {
    description: `Provider: ${drift.provider} (${drift.category})`,
    duration: 10_000,
  });
}
```

Add `"SCOPE_DRIFT"` to the event type listener array.

**Step 3: Verify**

Run: `cd dashboard && npm run build`

**Step 4: Commit**

```bash
git add dashboard/src/types/events.ts dashboard/src/hooks/useEventStream.ts
git commit -m "feat(dashboard): add scope drift alert toasts"
```

---

## Feature 6: Vulnerability Correlation Engine

Groups related findings by shared infrastructure, similar descriptions, and asset relationships. Surfaces composite attack chains.

---

### Task 6.1: Add Correlation Logic

**Files:**
- Create: `shared/lib_webbh/correlation.py`
- Test: `tests/test_correlation.py`

**Step 1: Write the failing test**

```python
# tests/test_correlation.py
"""Test vulnerability correlation engine."""

import pytest
from lib_webbh.correlation import correlate_findings, CorrelationGroup


def test_group_by_shared_asset():
    vulns = [
        {"id": 1, "asset_value": "app.example.com", "title": "XSS", "severity": "high"},
        {"id": 2, "asset_value": "app.example.com", "title": "CSRF", "severity": "medium"},
        {"id": 3, "asset_value": "api.example.com", "title": "IDOR", "severity": "high"},
    ]
    groups = correlate_findings(vulns)
    assert isinstance(groups, list)
    assert all(isinstance(g, CorrelationGroup) for g in groups)
    # vulns 1 and 2 share the same asset
    app_group = next(g for g in groups if "app.example.com" in g.shared_assets)
    assert len(app_group.vuln_ids) == 2
    assert 1 in app_group.vuln_ids
    assert 2 in app_group.vuln_ids


def test_single_vuln_no_group():
    vulns = [
        {"id": 1, "asset_value": "unique.example.com", "title": "SQLi", "severity": "critical"},
    ]
    groups = correlate_findings(vulns)
    # Single vulns get their own group
    assert len(groups) == 1
    assert groups[0].vuln_ids == [1]


def test_composite_severity():
    vulns = [
        {"id": 1, "asset_value": "app.example.com", "title": "Info Disclosure", "severity": "low"},
        {"id": 2, "asset_value": "app.example.com", "title": "Auth Bypass", "severity": "medium"},
        {"id": 3, "asset_value": "app.example.com", "title": "RCE", "severity": "critical"},
    ]
    groups = correlate_findings(vulns)
    group = groups[0]
    assert group.composite_severity == "critical"  # highest in chain


def test_empty_vulns():
    groups = correlate_findings([])
    assert groups == []
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_correlation.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write implementation**

```python
# shared/lib_webbh/correlation.py
"""Vulnerability correlation engine.

Groups related findings by shared assets, similar vulnerability types,
and infrastructure overlap. Computes composite severity for chains.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = {v: k for k, v in SEVERITY_ORDER.items()}


@dataclass
class CorrelationGroup:
    """A group of correlated vulnerabilities."""

    vuln_ids: list[int] = field(default_factory=list)
    shared_assets: list[str] = field(default_factory=list)
    composite_severity: str = "info"
    chain_description: str = ""


def correlate_findings(vulns: list[dict]) -> list[CorrelationGroup]:
    """Group vulnerabilities by shared assets and compute composite severity.

    Parameters
    ----------
    vulns : list[dict]
        Each dict must have: id, asset_value, title, severity.
    """
    if not vulns:
        return []

    # Group by asset_value
    asset_groups: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        asset_value = v.get("asset_value") or "unknown"
        asset_groups[asset_value].append(v)

    groups: list[CorrelationGroup] = []

    for asset_value, group_vulns in asset_groups.items():
        vuln_ids = [v["id"] for v in group_vulns]
        severities = [v.get("severity", "info") for v in group_vulns]
        max_sev = max(SEVERITY_ORDER.get(s, 0) for s in severities)

        titles = [v.get("title", "") for v in group_vulns]
        chain_desc = f"Chain on {asset_value}: {' → '.join(titles)}" if len(titles) > 1 else titles[0]

        groups.append(CorrelationGroup(
            vuln_ids=vuln_ids,
            shared_assets=[asset_value],
            composite_severity=SEVERITY_NAMES.get(max_sev, "info"),
            chain_description=chain_desc,
        ))

    # Sort by composite severity descending
    groups.sort(key=lambda g: SEVERITY_ORDER.get(g.composite_severity, 0), reverse=True)

    return groups
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_correlation.py -v`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
git add shared/lib_webbh/correlation.py tests/test_correlation.py
git commit -m "feat(correlation): add vulnerability correlation engine"
```

---

### Task 6.2: Add Correlation API Endpoint

**Files:**
- Modify: `orchestrator/main.py` (add GET /api/v1/targets/{target_id}/correlations)
- Test: `tests/test_correlation_api.py`

**Step 1: Write the failing test**

```python
# tests/test_correlation_api.py
"""Test correlation API endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app
from lib_webbh import get_session, Target, Asset, Vulnerability
from lib_webbh.database import Base, get_engine

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_correlations_endpoint(client):
    async with get_session() as session:
        target = Target(company_name="CorrCo", base_domain="corr.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        asset = Asset(target_id=target.id, asset_type="subdomain", asset_value="app.corr.com")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        v1 = Vulnerability(target_id=target.id, asset_id=asset.id, severity="high", title="XSS")
        v2 = Vulnerability(target_id=target.id, asset_id=asset.id, severity="medium", title="CSRF")
        session.add_all([v1, v2])
        await session.commit()

    resp = await client.get(f"/api/v1/targets/{target.id}/correlations")
    assert resp.status_code == 200
    data = resp.json()
    assert "groups" in data
    assert len(data["groups"]) >= 1
    group = data["groups"][0]
    assert "vuln_ids" in group
    assert "composite_severity" in group
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_correlation_api.py -v`

**Step 3: Add endpoint**

```python
@app.get("/api/v1/targets/{target_id}/correlations")
async def get_correlations(target_id: int):
    """Return correlated vulnerability groups for a target."""
    from lib_webbh.correlation import correlate_findings

    async with get_session() as session:
        vulns = (await session.execute(
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset))
        )).scalars().all()

    vuln_dicts = [
        {
            "id": v.id,
            "asset_value": v.asset.asset_value if v.asset else None,
            "title": v.title,
            "severity": v.severity,
        }
        for v in vulns
    ]

    groups = correlate_findings(vuln_dicts)

    return {
        "groups": [
            {
                "vuln_ids": g.vuln_ids,
                "shared_assets": g.shared_assets,
                "composite_severity": g.composite_severity,
                "chain_description": g.chain_description,
            }
            for g in groups
        ]
    }
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_correlation_api.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_correlation_api.py
git commit -m "feat(correlation): add vulnerability correlation API endpoint"
```

---

### Task 6.3: Dashboard Correlation View

**Files:**
- Create: `dashboard/src/components/campaign/CorrelationView.tsx`
- Modify: `dashboard/src/app/campaign/findings/page.tsx` (add correlation groups section)
- Modify: `dashboard/src/lib/api.ts` (add getCorrelations method)

**Step 1: Add API method**

```typescript
  getCorrelations(targetId: number) {
    return request<{
      groups: {
        vuln_ids: number[];
        shared_assets: string[];
        composite_severity: string;
        chain_description: string;
      }[];
    }>(`/api/v1/targets/${targetId}/correlations`);
  },
```

**Step 2: Create CorrelationView component**

```tsx
// dashboard/src/components/campaign/CorrelationView.tsx
"use client";

interface CorrelationGroup {
  vuln_ids: number[];
  shared_assets: string[];
  composite_severity: string;
  chain_description: string;
}

interface Props {
  groups: CorrelationGroup[];
}

const SEVERITY_BG: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

export function CorrelationView({ groups }: Props) {
  if (groups.length === 0) return null;

  // Only show groups with 2+ vulns (actual correlations)
  const multiGroups = groups.filter((g) => g.vuln_ids.length > 1);
  if (multiGroups.length === 0) return null;

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <h3 className="mb-3 text-sm font-medium text-zinc-400">Attack Chains</h3>
      <div className="space-y-3">
        {multiGroups.map((g, i) => (
          <div
            key={i}
            className={`rounded border p-3 ${SEVERITY_BG[g.composite_severity] ?? SEVERITY_BG.info}`}
          >
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{g.chain_description}</span>
              <span className="rounded px-2 py-0.5 text-xs font-medium uppercase">
                {g.composite_severity}
              </span>
            </div>
            <div className="mt-1 text-xs opacity-70">
              {g.vuln_ids.length} findings on {g.shared_assets.join(", ")}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

**Step 3: Integrate into findings page**

Read `dashboard/src/app/campaign/findings/page.tsx` and add `<CorrelationView groups={correlationGroups} />` above the findings table. Fetch correlation data with `api.getCorrelations(targetId)` in a `useEffect`.

**Step 4: Verify**

Run: `cd dashboard && npm run build`

**Step 5: Commit**

```bash
git add dashboard/src/components/campaign/CorrelationView.tsx dashboard/src/app/campaign/findings/page.tsx dashboard/src/lib/api.ts
git commit -m "feat(dashboard): add attack chain correlation view"
```

---

## Feature 7: Worker Auto-Scaling with Backpressure

Monitors Redis stream queue depth and scales worker container replicas up/down.

---

### Task 7.1: Add Queue Depth Monitor

**Files:**
- Create: `shared/lib_webbh/queue_monitor.py`
- Test: `tests/test_queue_monitor.py`

**Step 1: Write the failing test**

```python
# tests/test_queue_monitor.py
"""Test queue depth monitoring."""

import pytest
from lib_webbh.queue_monitor import QueueHealth, assess_queue_health


def test_healthy_queue():
    health = assess_queue_health(pending=5, threshold=50)
    assert health == QueueHealth.HEALTHY
    assert health.should_scale_up is False


def test_pressure_queue():
    health = assess_queue_health(pending=60, threshold=50)
    assert health == QueueHealth.PRESSURE
    assert health.should_scale_up is True


def test_critical_queue():
    health = assess_queue_health(pending=200, threshold=50)
    assert health == QueueHealth.CRITICAL
    assert health.should_scale_up is True


def test_empty_queue():
    health = assess_queue_health(pending=0, threshold=50)
    assert health == QueueHealth.IDLE
    assert health.should_scale_down is True
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_queue_monitor.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write implementation**

```python
# shared/lib_webbh/queue_monitor.py
"""Queue depth monitoring for worker auto-scaling."""

from __future__ import annotations

from enum import Enum


class QueueHealth(Enum):
    IDLE = "idle"           # 0 pending — can scale down
    HEALTHY = "healthy"     # below threshold — normal operation
    PRESSURE = "pressure"   # above threshold — should scale up
    CRITICAL = "critical"   # 4x threshold — urgent scale up

    @property
    def should_scale_up(self) -> bool:
        return self in (QueueHealth.PRESSURE, QueueHealth.CRITICAL)

    @property
    def should_scale_down(self) -> bool:
        return self == QueueHealth.IDLE


def assess_queue_health(pending: int, threshold: int = 50) -> QueueHealth:
    """Assess the health of a queue based on pending message count.

    Parameters
    ----------
    pending : int
        Number of pending (unacknowledged) messages in the stream.
    threshold : int
        The threshold above which the queue is considered under pressure.
    """
    if pending == 0:
        return QueueHealth.IDLE
    if pending <= threshold:
        return QueueHealth.HEALTHY
    if pending <= threshold * 4:
        return QueueHealth.PRESSURE
    return QueueHealth.CRITICAL
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_queue_monitor.py -v`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
git add shared/lib_webbh/queue_monitor.py tests/test_queue_monitor.py
git commit -m "feat(autoscale): add queue depth health assessment"
```

---

### Task 7.2: Add Auto-Scale Loop to Event Engine

**Files:**
- Modify: `orchestrator/event_engine.py` (add `run_autoscaler` coroutine)
- Modify: `orchestrator/main.py` (start autoscaler background task)

**Step 1: Add autoscaler to event_engine.py**

Add at the end of `event_engine.py`:

```python
# ---------------------------------------------------------------------------
# Auto-scaling — monitor queue depth and scale workers
# ---------------------------------------------------------------------------
AUTOSCALE_INTERVAL = int(os.environ.get("AUTOSCALE_INTERVAL", "30"))  # seconds
QUEUE_PRESSURE_THRESHOLD = int(os.environ.get("QUEUE_PRESSURE_THRESHOLD", "50"))

# Map queue names to worker keys
QUEUE_TO_WORKER = {
    "recon_queue": "recon",
    "fuzzing_queue": "fuzzing",
    "webapp_queue": "webapp_testing",
    "cloud_queue": "cloud_testing",
    "api_queue": "api_testing",
}


async def run_autoscaler() -> None:
    """Monitor queue depths and log scaling recommendations."""
    from lib_webbh.messaging import get_pending
    from lib_webbh.queue_monitor import assess_queue_health

    logger.info("Autoscaler started", extra={"interval": AUTOSCALE_INTERVAL})
    await asyncio.sleep(5)  # let services stabilize

    while True:
        try:
            for queue_name, worker_key in QUEUE_TO_WORKER.items():
                try:
                    info = await get_pending(queue_name, f"{worker_key}_group")
                    pending = info.get("pending", 0)
                except Exception:
                    pending = 0

                health = assess_queue_health(pending, QUEUE_PRESSURE_THRESHOLD)

                if health.should_scale_up:
                    logger.warning(
                        "Queue pressure detected — scale up recommended",
                        extra={
                            "queue": queue_name,
                            "pending": pending,
                            "health": health.value,
                            "worker": worker_key,
                        },
                    )
                    await _emit_event(0, "AUTOSCALE_RECOMMENDATION", {
                        "queue": queue_name,
                        "worker": worker_key,
                        "pending": pending,
                        "action": "scale_up",
                    })
                elif health.should_scale_down:
                    logger.debug(
                        "Queue idle — scale down possible",
                        extra={"queue": queue_name, "worker": worker_key},
                    )
        except Exception:
            logger.exception("Error in autoscaler cycle")

        await asyncio.sleep(AUTOSCALE_INTERVAL)
```

**Step 2: Start autoscaler in main.py lifespan**

In `orchestrator/main.py` `lifespan` function, add after the redis_task line:

```python
    autoscale_task = asyncio.create_task(event_engine.run_autoscaler(), name="autoscaler")
```

And in the shutdown section:
```python
    autoscale_task.cancel()
    for task in (engine_task, heartbeat_task, redis_task, autoscale_task):
```

**Step 3: Commit**

```bash
git add orchestrator/event_engine.py orchestrator/main.py
git commit -m "feat(autoscale): add queue depth autoscaler loop to event engine"
```

---

### Task 7.3: Add Queue Health API Endpoint

**Files:**
- Modify: `orchestrator/main.py` (add GET /api/v1/queue_health)

**Step 1: Write the failing test**

```python
# tests/test_queue_health_api.py
"""Test queue health endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from orchestrator.main import app

pytestmark = pytest.mark.anyio


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_queue_health_endpoint(client):
    resp = await client.get("/api/v1/queue_health")
    assert resp.status_code == 200
    data = resp.json()
    assert "queues" in data
    assert isinstance(data["queues"], list)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_queue_health_api.py -v`

**Step 3: Add endpoint**

```python
@app.get("/api/v1/queue_health")
async def get_queue_health():
    """Return health status for all worker queues."""
    from lib_webbh.messaging import get_pending
    from lib_webbh.queue_monitor import assess_queue_health

    queues_config = {
        "recon_queue": "recon_group",
        "fuzzing_queue": "fuzzing_group",
        "webapp_queue": "webapp_group",
        "cloud_queue": "cloud_group",
        "api_queue": "api_group",
        "report_queue": "reporting_group",
    }

    results = []
    for queue_name, group_name in queues_config.items():
        try:
            info = await get_pending(queue_name, group_name)
            pending = info.get("pending", 0)
        except Exception:
            pending = 0

        health = assess_queue_health(pending)
        results.append({
            "queue": queue_name,
            "pending": pending,
            "health": health.value,
            "should_scale_up": health.should_scale_up,
            "should_scale_down": health.should_scale_down,
        })

    return {"queues": results}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_queue_health_api.py -v`

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_queue_health_api.py
git commit -m "feat(autoscale): add queue health API endpoint"
```

---

### Task 7.4: Dashboard Queue Health Widget

**Files:**
- Create: `dashboard/src/components/c2/QueueHealth.tsx`
- Modify: `dashboard/src/app/campaign/c2/page.tsx` (add QueueHealth widget)
- Modify: `dashboard/src/lib/api.ts` (add getQueueHealth method)

**Step 1: Add API method**

```typescript
  getQueueHealth() {
    return request<{
      queues: {
        queue: string;
        pending: number;
        health: string;
        should_scale_up: boolean;
        should_scale_down: boolean;
      }[];
    }>("/api/v1/queue_health");
  },
```

**Step 2: Create QueueHealth component**

```tsx
// dashboard/src/components/c2/QueueHealth.tsx
"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface QueueStatus {
  queue: string;
  pending: number;
  health: string;
  should_scale_up: boolean;
  should_scale_down: boolean;
}

const HEALTH_STYLES: Record<string, string> = {
  idle: "text-zinc-500",
  healthy: "text-green-400",
  pressure: "text-yellow-400",
  critical: "text-red-400",
};

export function QueueHealth() {
  const [queues, setQueues] = useState<QueueStatus[]>([]);

  useEffect(() => {
    const fetch = () => api.getQueueHealth().then((d) => setQueues(d.queues)).catch(() => {});
    fetch();
    const interval = setInterval(fetch, 15_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <h3 className="mb-3 text-sm font-medium text-zinc-400">Queue Health</h3>
      <div className="space-y-2">
        {queues.map((q) => (
          <div key={q.queue} className="flex items-center justify-between text-xs">
            <span className="font-mono text-zinc-300">{q.queue.replace("_queue", "")}</span>
            <div className="flex items-center gap-3">
              <span className="text-zinc-500">{q.pending} pending</span>
              <span className={`font-medium uppercase ${HEALTH_STYLES[q.health] ?? ""}`}>
                {q.health}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

**Step 3: Add to C2 page**

Import and render `<QueueHealth />` in the C2 page alongside the existing StatusBoard.

**Step 4: Verify**

Run: `cd dashboard && npm run build`

**Step 5: Commit**

```bash
git add dashboard/src/components/c2/QueueHealth.tsx dashboard/src/app/campaign/c2/page.tsx dashboard/src/lib/api.ts
git commit -m "feat(dashboard): add queue health monitoring widget to C2 page"
```

---

## Summary

| Feature | Tasks | New Files | Modified Files |
|---------|-------|-----------|----------------|
| 1. Campaign Playbooks | 4 | `playbooks.py`, tests | `main.py`, `pipeline.py`, `worker/main.py`, dashboard |
| 2. Live Recon Diffing | 5 | `diffing.py`, `AssetSnapshot` model, `DiffTimeline.tsx`, tests | `database.py`, `main.py`, `pipeline.py`, dashboard |
| 3. Report Draft Generator | 3 | `report_templates.py`, tests | `main.py`, dashboard |
| 4. Attack Graph | 2 | `AttackGraph.tsx`, `graph/page.tsx`, tests | `main.py`, `api.ts`, sidebar |
| 5. Scope Drift Detection | 3 | `shared_infra.py`, tests | `base_tool.py`, dashboard events |
| 6. Vuln Correlation | 3 | `correlation.py`, `CorrelationView.tsx`, tests | `main.py`, dashboard findings |
| 7. Worker Auto-Scaling | 4 | `queue_monitor.py`, `QueueHealth.tsx`, tests | `event_engine.py`, `main.py`, dashboard |

**Total: 24 tasks, ~30 commits**

All features are independent — build in any order. Recommended priority:
1. Campaign Playbooks (lowest effort, highest daily impact)
2. Live Recon Diffing (medium effort, continuous coverage)
3. Report Draft Generator (medium effort, high user value)
4. Attack Graph (medium effort, strong UX)
5. Scope Drift Detection (medium effort, safety improvement)
6. Vuln Correlation (medium effort, triage quality)
7. Worker Auto-Scaling (medium-high effort, operational)
