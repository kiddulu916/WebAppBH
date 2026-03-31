# M3: Orchestrator Event Engine Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the sequential phase orchestrator with a dependency-driven event engine that evaluates worker readiness per-target, dispatches to priority queues, and manages the resource guard and target expansion.

**Architecture:** `dependency_map.py` defines the static graph. `event_engine.py` polls every 5s, evaluates all active targets, dispatches runnable workers. `resource_guard.py` monitors CPU/memory/worker counts and throttles queue consumption. `target_expander.py` creates child targets from info_gathering results.

**Tech Stack:** Python 3.10, FastAPI, asyncio, psutil, lib_webbh (SQLAlchemy async, Redis Streams)

**Design docs:** `docs/plans/design/2026-03-29-restructure-08-target-expansion-resources.md`, `docs/plans/design/2026-03-29-restructure-09-orchestrator.md`

---

## Task 1: Dependency Map Module

**Files:**
- Create: `orchestrator/dependency_map.py`
- Test: `tests/test_dependency_map.py`

**Step 1: Write the failing test**

```python
# tests/test_dependency_map.py
import pytest


def test_dependency_map_has_all_workers():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    expected_workers = {
        "info_gathering", "config_mgmt", "identity_mgmt", "authentication",
        "authorization", "session_mgmt", "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side", "chain_worker", "reporting",
    }
    assert set(DEPENDENCY_MAP.keys()) == expected_workers


def test_info_gathering_has_no_deps():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    assert DEPENDENCY_MAP["info_gathering"] == []


def test_config_mgmt_depends_on_info_gathering():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    assert DEPENDENCY_MAP["config_mgmt"] == ["info_gathering"]


def test_authorization_and_session_parallel():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    assert DEPENDENCY_MAP["authorization"] == ["authentication"]
    assert DEPENDENCY_MAP["session_mgmt"] == ["authentication"]


def test_chain_worker_depends_on_all_testing():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    chain_deps = set(DEPENDENCY_MAP["chain_worker"])
    assert chain_deps == {
        "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side",
    }


def test_credential_required_set():
    from orchestrator.dependency_map import CREDENTIAL_REQUIRED

    assert "identity_mgmt" in CREDENTIAL_REQUIRED
    assert "authentication" in CREDENTIAL_REQUIRED
    assert "info_gathering" not in CREDENTIAL_REQUIRED
    assert "error_handling" not in CREDENTIAL_REQUIRED


def test_resolve_effective_no_creds():
    from orchestrator.dependency_map import resolve_effective_dependencies

    effective = resolve_effective_dependencies(has_credentials=False)

    # Credential-required workers should be absent
    assert "identity_mgmt" not in effective
    assert "authentication" not in effective
    assert "authorization" not in effective
    assert "session_mgmt" not in effective
    assert "input_validation" not in effective
    assert "business_logic" not in effective

    # Non-credential workers should remain
    assert "info_gathering" in effective
    assert "config_mgmt" in effective
    assert "error_handling" in effective
    assert "cryptography" in effective
    assert "client_side" in effective
    assert "chain_worker" in effective

    # error_handling should depend on config_mgmt (not on skipped workers)
    assert effective["error_handling"] == ["config_mgmt"]

    # chain_worker should depend only on remaining workers
    chain_deps = set(effective["chain_worker"])
    assert "input_validation" not in chain_deps
    assert "error_handling" in chain_deps


def test_resolve_effective_with_creds():
    from orchestrator.dependency_map import resolve_effective_dependencies

    effective = resolve_effective_dependencies(has_credentials=True)

    # All workers should be present
    assert len(effective) == 13
    assert "identity_mgmt" in effective
    assert "authentication" in effective
```

**Step 2: Run test, verify fail.**

**Step 3: Write dependency_map.py**

```python
# orchestrator/dependency_map.py

DEPENDENCY_MAP = {
    "info_gathering":   [],
    "config_mgmt":      ["info_gathering"],
    "identity_mgmt":    ["config_mgmt"],
    "authentication":   ["identity_mgmt"],
    "authorization":    ["authentication"],
    "session_mgmt":     ["authentication"],
    "input_validation": ["authorization", "session_mgmt"],
    "error_handling":   ["config_mgmt"],
    "cryptography":     ["config_mgmt"],
    "business_logic":   ["authorization", "session_mgmt"],
    "client_side":      ["config_mgmt"],
    "chain_worker":     [
        "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side",
    ],
    "reporting":        ["chain_worker"],
}

CREDENTIAL_REQUIRED = {
    "identity_mgmt", "authentication", "authorization",
    "session_mgmt", "input_validation", "business_logic",
}


def resolve_effective_dependencies(has_credentials: bool) -> dict[str, list[str]]:
    """Resolve the dependency graph accounting for skipped workers."""
    effective = {}
    for worker, deps in DEPENDENCY_MAP.items():
        if worker in CREDENTIAL_REQUIRED and not has_credentials:
            continue

        resolved_deps = set()
        for dep in deps:
            if dep in CREDENTIAL_REQUIRED and not has_credentials:
                resolved_deps.update(
                    _resolve_skipped(dep, DEPENDENCY_MAP, CREDENTIAL_REQUIRED)
                )
            else:
                resolved_deps.add(dep)

        effective[worker] = sorted(resolved_deps)

    return effective


def _resolve_skipped(worker, dep_map, skip_set):
    result = set()
    for dep in dep_map.get(worker, []):
        if dep in skip_set:
            result.update(_resolve_skipped(dep, dep_map, skip_set))
        else:
            result.add(dep)
    return result
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add orchestrator/dependency_map.py tests/test_dependency_map.py
git commit -m "feat(orchestrator): add dependency map with credential-aware skip resolution"
```

---

## Task 2: Resource Guard

**Files:**
- Create: `orchestrator/resource_guard.py`
- Test: `tests/test_resource_guard.py`

**Step 1: Write the failing test**

```python
# tests/test_resource_guard.py
import pytest
from unittest.mock import patch, AsyncMock

pytestmark = pytest.mark.anyio


def test_get_batch_config_green():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("green")
    assert "critical" in config["queues"]
    assert "low" in config["queues"]
    assert config["batch_multiplier"] == 1.0
    assert config["delay_seconds"] == 0


def test_get_batch_config_yellow():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("yellow")
    assert "low" not in config["queues"]
    assert config["batch_multiplier"] == 0.5


def test_get_batch_config_red():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("red")
    assert set(config["queues"]) == {"critical", "high"}
    assert config["delay_seconds"] == 5


def test_get_batch_config_critical():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    config = guard.get_batch_config("critical")
    assert config["queues"] == []
    assert config["batch_multiplier"] == 0


def test_manual_override():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    guard.set_override("red")
    # Override should return the overridden tier
    assert guard._override == "red"

    guard.clear_override()
    assert guard._override is None


async def test_get_tier_with_override():
    from orchestrator.resource_guard import ResourceGuard

    guard = ResourceGuard()
    guard.set_override("critical")
    tier = await guard.get_current_tier()
    assert tier == "critical"
```

**Step 2: Run test, verify fail.**

**Step 3: Write resource_guard.py**

```python
# orchestrator/resource_guard.py
import os
from typing import Optional


class ResourceGuard:
    """Monitors system resources and controls processing throughput."""

    THRESHOLDS = {
        "green":  {
            "cpu": int(os.environ.get("RESOURCE_GUARD_CPU_GREEN", "60")),
            "memory": int(os.environ.get("RESOURCE_GUARD_MEM_GREEN", "60")),
            "workers": int(os.environ.get("RESOURCE_GUARD_WORKERS_GREEN", "8")),
        },
        "yellow": {
            "cpu": int(os.environ.get("RESOURCE_GUARD_CPU_YELLOW", "80")),
            "memory": int(os.environ.get("RESOURCE_GUARD_MEM_YELLOW", "80")),
            "workers": int(os.environ.get("RESOURCE_GUARD_WORKERS_YELLOW", "12")),
        },
        "red": {
            "cpu": int(os.environ.get("RESOURCE_GUARD_CPU_RED", "90")),
            "memory": int(os.environ.get("RESOURCE_GUARD_MEM_RED", "90")),
            "workers": int(os.environ.get("RESOURCE_GUARD_WORKERS_RED", "16")),
        },
    }

    def __init__(self):
        self._override: Optional[str] = None

    def set_override(self, tier: str):
        self._override = tier

    def clear_override(self):
        self._override = None

    async def get_current_tier(self) -> str:
        if self._override:
            return self._override

        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory().percent
        except ImportError:
            cpu = 0
            memory = 0

        active_workers = await self._count_active_workers()

        if (cpu > self.THRESHOLDS["red"]["cpu"] or
            memory > self.THRESHOLDS["red"]["memory"] or
            active_workers > self.THRESHOLDS["red"]["workers"]):
            return "critical"
        elif (cpu > self.THRESHOLDS["yellow"]["cpu"] or
              memory > self.THRESHOLDS["yellow"]["memory"] or
              active_workers > self.THRESHOLDS["yellow"]["workers"]):
            return "red"
        elif (cpu > self.THRESHOLDS["green"]["cpu"] or
              memory > self.THRESHOLDS["green"]["memory"] or
              active_workers > self.THRESHOLDS["green"]["workers"]):
            return "yellow"
        else:
            return "green"

    def get_batch_config(self, tier: str) -> dict:
        configs = {
            "green": {
                "queues": ["critical", "high", "normal", "low"],
                "batch_multiplier": 1.0,
                "delay_seconds": 0,
            },
            "yellow": {
                "queues": ["critical", "high", "normal"],
                "batch_multiplier": 0.5,
                "delay_seconds": 1,
            },
            "red": {
                "queues": ["critical", "high"],
                "batch_multiplier": 0.25,
                "delay_seconds": 5,
            },
            "critical": {
                "queues": [],
                "batch_multiplier": 0,
                "delay_seconds": 10,
            },
        }
        return configs[tier]

    async def _count_active_workers(self) -> int:
        from lib_webbh.database import get_session, JobState
        from sqlalchemy import select, func

        try:
            async with get_session() as session:
                result = await session.execute(
                    select(func.count(JobState.id))
                    .where(JobState.status == "running")
                )
                return result.scalar() or 0
        except Exception:
            return 0
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add orchestrator/resource_guard.py tests/test_resource_guard.py
git commit -m "feat(orchestrator): add ResourceGuard with tiered throttling"
```

---

## Task 3: Target Expander

**Files:**
- Create: `orchestrator/target_expander.py`
- Test: `tests/test_target_expander.py`

**Step 1: Write the failing test**

```python
# tests/test_target_expander.py
import pytest

pytestmark = pytest.mark.anyio


def test_score_priority_high_value_prefix():
    from orchestrator.target_expander import TargetExpander

    expander = TargetExpander()
    score = expander._score_priority(
        {"hostname": "api.target.com", "ips": {"1.2.3.4"}, "sources": ["subfinder", "amass", "httpx"]},
        None,
    )
    # api prefix (+15) + unique IP (+20) + 3 sources (+10) + base 50 = 95
    assert score >= 85


def test_score_priority_cdn_low():
    from orchestrator.target_expander import TargetExpander

    expander = TargetExpander()
    score = expander._score_priority(
        {"hostname": "cdn.target.com", "ips": set(), "sources": ["subfinder"]},
        None,
    )
    # cdn prefix (-15) + single source (-5) + base 50 = 30
    assert score <= 40


def test_score_priority_wildcard():
    from orchestrator.target_expander import TargetExpander

    expander = TargetExpander()
    score = expander._score_priority(
        {"hostname": "wild.target.com", "ips": set(), "sources": ["subfinder"], "wildcard": True},
        None,
    )
    # wildcard (-30) + single source (-5) + base 50 = 15
    assert score <= 25


def test_deduplicate_removes_duplicates():
    from orchestrator.target_expander import TargetExpander
    from unittest.mock import MagicMock

    expander = TargetExpander()

    assets = [
        MagicMock(asset_type="subdomain", data={"hostname": "api.target.com", "ip": "1.1.1.1"}, source_tool="subfinder"),
        MagicMock(asset_type="subdomain", data={"hostname": "api.target.com", "ip": "1.1.1.1"}, source_tool="amass"),
        MagicMock(asset_type="subdomain", data={"hostname": "web.target.com", "ip": "2.2.2.2"}, source_tool="subfinder"),
    ]

    unique = expander._deduplicate(assets)
    hostnames = [h["hostname"] for h in unique]
    assert len(hostnames) == 2
    assert "api.target.com" in hostnames
    assert "web.target.com" in hostnames
```

**Step 2: Run test, verify fail.**

**Step 3: Write target_expander.py**

```python
# orchestrator/target_expander.py
import shutil
import os
from collections import defaultdict
from pathlib import Path
from typing import Optional

from lib_webbh.database import get_session, Target, Asset
from lib_webbh.messaging import push_priority_task
from lib_webbh.scope import ScopeManager
from sqlalchemy import select


class TargetExpander:
    """Creates child targets from info_gathering results."""

    async def expand(self, parent_target_id: int):
        async with get_session() as session:
            assets = await session.execute(
                select(Asset)
                .where(Asset.target_id == parent_target_id)
                .where(Asset.asset_type.in_(["subdomain", "vhost", "live_url"]))
            )
            assets = assets.scalars().all()
            parent = await session.get(Target, parent_target_id)

            unique_hosts = self._deduplicate(assets)

            for host_info in unique_hosts:
                if host_info["hostname"] == parent.base_domain:
                    continue

                priority = self._score_priority(host_info, parent)

                child = Target(
                    company_name=parent.company_name,
                    base_domain=host_info["hostname"],
                    parent_target_id=parent_target_id,
                    campaign_id=parent.campaign_id,
                    target_type="child",
                    priority=priority,
                    wildcard=host_info.get("wildcard", False),
                    wildcard_count=host_info.get("wildcard_count"),
                )
                session.add(child)

            await session.commit()

            children = await session.execute(
                select(Target)
                .where(Target.parent_target_id == parent_target_id)
                .where(Target.target_type == "child")
            )
            for child in children.scalars().all():
                self._copy_credentials(parent_target_id, child.id)
                await push_priority_task(
                    "config_mgmt_queue",
                    {"target_id": child.id, "parent_target_id": parent_target_id},
                    priority_score=child.priority,
                )

    def _deduplicate(self, assets):
        by_hostname = {}
        for asset in assets:
            hostname = asset.data.get("hostname", "").lower().strip(".")
            if not hostname:
                continue
            if hostname not in by_hostname:
                by_hostname[hostname] = {
                    "hostname": hostname,
                    "ips": set(),
                    "sources": [],
                    "asset_type": asset.asset_type,
                }
            if asset.data.get("ip"):
                by_hostname[hostname]["ips"].add(asset.data["ip"])
            by_hostname[hostname]["sources"].append(asset.source_tool)

        ip_groups = defaultdict(list)
        for info in by_hostname.values():
            for ip in info["ips"]:
                ip_groups[ip].append(info)

        for ip, hosts in ip_groups.items():
            if len(hosts) > 50:
                for host in hosts[1:]:
                    host["skip"] = True
                hosts[0]["wildcard"] = True
                hosts[0]["wildcard_count"] = len(hosts)

        return [h for h in by_hostname.values() if not h.get("skip")]

    def _score_priority(self, host_info, parent) -> int:
        score = 50

        if host_info.get("is_seed"):
            return 100

        if len(host_info.get("ips", set())) == 1:
            score += 20

        hostname = host_info["hostname"]
        high_value = ["api", "admin", "portal", "app", "dashboard", "login",
                      "auth", "sso", "internal", "staging", "dev", "test", "uat", "preprod"]
        for prefix in high_value:
            if hostname.startswith(f"{prefix}."):
                score += 15
                break

        low_value = ["cdn", "static", "assets", "img", "images", "media", "fonts", "css", "js"]
        for prefix in low_value:
            if hostname.startswith(f"{prefix}."):
                score -= 15
                break

        source_count = len(set(host_info.get("sources", [])))
        if source_count >= 3:
            score += 10
        elif source_count == 1:
            score -= 5

        if host_info.get("wildcard"):
            score -= 30

        return max(0, min(100, score))

    def _copy_credentials(self, parent_id: int, child_id: int):
        parent_creds = Path(f"shared/config/{parent_id}/credentials.json")
        child_dir = Path(f"shared/config/{child_id}")
        child_dir.mkdir(parents=True, exist_ok=True)
        if parent_creds.exists():
            shutil.copy2(parent_creds, child_dir / "credentials.json")
            os.chmod(child_dir / "credentials.json", 0o600)
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add orchestrator/target_expander.py tests/test_target_expander.py
git commit -m "feat(orchestrator): add TargetExpander with dedup, priority scoring, credential propagation"
```

---

## Task 4: Event Engine

**Files:**
- Create: `orchestrator/event_engine.py`
- Test: `tests/test_event_engine.py`

**Step 1: Write the failing test**

```python
# tests/test_event_engine.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


async def test_evaluate_target_dispatches_ready_worker(db_session):
    from orchestrator.event_engine import EventEngine
    from orchestrator.resource_guard import ResourceGuard
    from lib_webbh.database import Target, JobState

    target = Target(company_name="Test", base_domain="target.com", priority=100)
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # Simulate info_gathering complete
    job = JobState(
        target_id=target.id,
        container_name="info_gathering",
        status="complete",
    )
    db_session.add(job)
    await db_session.commit()

    guard = ResourceGuard()
    engine = EventEngine(guard)

    with patch.object(engine, "_dispatch_worker", new_callable=AsyncMock) as mock_dispatch:
        await engine._evaluate_target(target, "green")
        # config_mgmt should be dispatched (its only dep is info_gathering which is complete)
        dispatched_workers = [call.args[1] for call in mock_dispatch.call_args_list]
        assert "config_mgmt" in dispatched_workers


async def test_evaluate_target_skips_pending_deps(db_session):
    from orchestrator.event_engine import EventEngine
    from orchestrator.resource_guard import ResourceGuard
    from lib_webbh.database import Target

    target = Target(company_name="Test", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # No jobs at all — info_gathering not complete
    guard = ResourceGuard()
    engine = EventEngine(guard)

    with patch.object(engine, "_dispatch_worker", new_callable=AsyncMock) as mock_dispatch:
        await engine._evaluate_target(target, "green")
        # Only info_gathering should be dispatched (no deps)
        dispatched_workers = [call.args[1] for call in mock_dispatch.call_args_list]
        assert "info_gathering" in dispatched_workers
        assert "config_mgmt" not in dispatched_workers
```

**Step 2: Run test, verify fail.**

**Step 3: Write event_engine.py**

```python
# orchestrator/event_engine.py
import asyncio
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh.database import get_session, Target, JobState
from lib_webbh.messaging import push_priority_task
from lib_webbh import setup_logger

from .dependency_map import resolve_effective_dependencies, CREDENTIAL_REQUIRED
from .resource_guard import ResourceGuard

logger = setup_logger("event_engine")


class EventEngine:
    """Evaluates worker dependencies and dispatches next workers."""

    def __init__(self, resource_guard: ResourceGuard):
        self.resource_guard = resource_guard
        self._poll_interval = 5

    async def run(self):
        while True:
            try:
                await self._poll_cycle()
            except Exception as e:
                logger.error("Event engine error", error=str(e))
            await asyncio.sleep(self._poll_interval)

    async def _poll_cycle(self):
        tier = await self.resource_guard.get_current_tier()
        if tier == "critical":
            return

        async with get_session() as session:
            targets = await session.execute(
                select(Target).where(Target.target_type.in_(["seed", "child"]))
            )
            targets = targets.scalars().all()

        for target in targets:
            await self._evaluate_target(target, tier)

    async def _evaluate_target(self, target, resource_tier):
        has_creds = self._check_credentials(target.id)
        dep_map = resolve_effective_dependencies(has_credentials=has_creds)
        worker_states = await self._get_worker_states(target.id)

        for worker_name, dependencies in dep_map.items():
            if worker_states.get(worker_name) in ("running", "complete", "queued"):
                continue

            all_deps_met = all(
                worker_states.get(dep) == "complete"
                for dep in dependencies
            )

            if not all_deps_met:
                continue

            batch_config = self.resource_guard.get_batch_config(resource_tier)
            priority = target.priority or 50

            if priority >= 90:
                queue_tier = "critical"
            elif priority >= 70:
                queue_tier = "high"
            elif priority >= 50:
                queue_tier = "normal"
            else:
                queue_tier = "low"

            if queue_tier not in batch_config["queues"]:
                continue

            await self._dispatch_worker(target, worker_name, queue_tier)

    async def _dispatch_worker(self, target, worker_name, queue_tier):
        queue_name = f"{worker_name}_queue"
        await push_priority_task(
            queue_name,
            {"target_id": target.id, "worker": worker_name},
            priority_score=target.priority or 50,
        )

        async with get_session() as session:
            job = JobState(
                target_id=target.id,
                container_name=worker_name,
                status="queued",
                queued_at=datetime.now(timezone.utc),
            )
            session.add(job)
            await session.commit()

        logger.info("Worker dispatched", worker=worker_name, target_id=target.id)

    async def _get_worker_states(self, target_id):
        async with get_session() as session:
            jobs = await session.execute(
                select(JobState)
                .where(JobState.target_id == target_id)
                .order_by(JobState.created_at.desc())
            )
            states = {}
            for job in jobs.scalars().all():
                if job.container_name not in states:
                    states[job.container_name] = job.status
            return states

    def _check_credentials(self, target_id):
        from pathlib import Path
        return Path(f"shared/config/{target_id}/credentials.json").exists()
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add orchestrator/event_engine.py tests/test_event_engine.py
git commit -m "feat(orchestrator): add EventEngine with dependency-driven worker dispatch"
```

---

## Task 5: Campaign API Endpoints

**Files:**
- Modify: `orchestrator/main.py`
- Test: `tests/test_campaign_api.py`

**Step 1: Write the failing test**

```python
# tests/test_campaign_api.py
import pytest
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.anyio


async def test_create_campaign(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/campaigns", json={
            "name": "Test Campaign",
            "targets": [{"domain": "target.com"}],
            "scope_config": {"in_scope": ["*.target.com"]},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Campaign"
        assert data["id"] is not None


async def test_list_campaigns(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/campaigns", json={
            "name": "Campaign 1",
            "targets": [{"domain": "a.com"}],
        })
        resp = await client.get("/api/v1/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
```

**Step 2: Run test, verify fail.**

**Step 3: Add campaign endpoints to orchestrator/main.py**

Add a new router at `orchestrator/routes/campaigns.py`:

```python
# orchestrator/routes/campaigns.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from lib_webbh.database import get_session, Campaign, Target

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[dict]
    scope_config: dict | None = None
    tester_credentials: dict | None = None
    testing_user: dict | None = None
    rate_limit: int = 50


@router.post("", status_code=201)
async def create_campaign(body: CampaignCreate):
    async with get_session() as session:
        campaign = Campaign(
            name=body.name,
            description=body.description,
            scope_config=body.scope_config,
            rate_limit=body.rate_limit,
            has_credentials=body.tester_credentials is not None,
        )
        session.add(campaign)
        await session.flush()

        for t in body.targets:
            target = Target(
                company_name=t.get("company_name", body.name),
                base_domain=t["domain"],
                campaign_id=campaign.id,
                target_type="seed",
                priority=100,
            )
            session.add(target)

        await session.commit()
        await session.refresh(campaign)

        return {"id": campaign.id, "name": campaign.name, "status": campaign.status}


@router.get("")
async def list_campaigns():
    from sqlalchemy import select
    async with get_session() as session:
        result = await session.execute(select(Campaign))
        campaigns = result.scalars().all()
        return [{"id": c.id, "name": c.name, "status": c.status} for c in campaigns]
```

Include the router in `orchestrator/main.py`:
```python
from orchestrator.routes.campaigns import router as campaigns_router
app.include_router(campaigns_router)
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add orchestrator/routes/campaigns.py orchestrator/main.py tests/test_campaign_api.py
git commit -m "feat(orchestrator): add campaign CRUD API endpoints"
```

---

## Task 6: Resource Guard API Endpoints

**Files:**
- Create: `orchestrator/routes/resources.py`
- Test: `tests/test_resource_api.py`

**Step 1: Write the failing test**

```python
# tests/test_resource_api.py
import pytest
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.anyio


async def test_get_resource_status(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/resources/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "tier" in data


async def test_override_resource_tier(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/resources/override", json={"tier": "red"})
        assert resp.status_code == 200

        resp = await client.get("/api/v1/resources/status")
        data = resp.json()
        assert data["tier"] == "red"

        # Clear override
        resp = await client.post("/api/v1/resources/override", json={"tier": None})
        assert resp.status_code == 200
```

**Step 2: Run test, verify fail.**

**Step 3: Write resources.py**

```python
# orchestrator/routes/resources.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/v1/resources", tags=["resources"])

# Resource guard instance injected at app startup
_guard = None


def set_guard(guard):
    global _guard
    _guard = guard


class OverrideRequest(BaseModel):
    tier: Optional[str] = None


@router.get("/status")
async def get_status():
    tier = await _guard.get_current_tier()
    return {"tier": tier, "thresholds": _guard.THRESHOLDS}


@router.post("/override")
async def override_tier(body: OverrideRequest):
    if body.tier:
        _guard.set_override(body.tier)
    else:
        _guard.clear_override()
    return {"override": body.tier}
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add orchestrator/routes/resources.py tests/test_resource_api.py
git commit -m "feat(orchestrator): add resource guard API endpoints"
```

---

## Task 7: Full Regression

**Step 1: Run all tests**

Run: `pytest tests/ -v --tb=short`
Expected: All PASS

**Step 2: Commit if fixups needed**
