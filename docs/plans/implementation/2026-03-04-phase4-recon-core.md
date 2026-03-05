# Phase 4: Recon-Core Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the Recon-Core Dockerized worker that consumes jobs from `recon_queue`, runs a 5-stage reconnaissance pipeline, and writes results to PostgreSQL via `lib_webbh`.

**Architecture:** Long-lived Docker container using `listen_queue()` from `lib_webbh.messaging`. Abstract `ReconTool` base class with per-tool subclasses. Dual semaphore concurrency (heavy/light). Per-stage checkpointing via `JobState`. Critical findings pushed to Redis for SSE.

**Tech Stack:** Python 3.10, asyncio, lib_webbh (SQLAlchemy async, Redis Streams), Go recon tools (Subfinder, Amass, Httpx, Naabu, Katana, etc.), Docker multi-stage build.

**Design doc:** `docs/plans/design/2026-03-04-phase4-recon-core-design.md`

---

## Task 1: Scaffold Worker Directory

**Files:**
- Create: `workers/__init__.py`
- Create: `workers/recon_core/__init__.py`
- Create: `workers/recon_core/tools/__init__.py`
- Create: `workers/recon_core/requirements.txt`

**Step 1: Create directory structure and empty init files**

```bash
mkdir -p workers/recon_core/tools
```

```python
# workers/__init__.py
# (empty)
```

```python
# workers/recon_core/__init__.py
# (empty)
```

```python
# workers/recon_core/tools/__init__.py
# (empty — will be populated as tool wrappers are added)
```

**Step 2: Create requirements.txt**

```txt
# workers/recon_core/requirements.txt
# lib_webbh is installed from shared/ in the Dockerfile
# All recon tools are Go/system binaries called via asyncio subprocess
# No additional Python dependencies required beyond lib_webbh
```

**Step 3: Commit**

```bash
git add workers/
git commit -m "chore(recon-core): scaffold worker directory structure"
```

---

## Task 2: Concurrency Module

**Files:**
- Create: `workers/recon_core/concurrency.py`
- Create: `tests/test_recon_concurrency.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_concurrency.py
import asyncio
import os
from unittest.mock import patch


def test_get_semaphores_returns_bounded_semaphores():
    from workers.recon_core.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.BoundedSemaphore)
    assert isinstance(light, asyncio.BoundedSemaphore)


def test_heavy_concurrency_from_env():
    with patch.dict(os.environ, {"HEAVY_CONCURRENCY": "3"}):
        from workers.recon_core import concurrency
        heavy, _ = concurrency.get_semaphores(force_new=True)
        loop = asyncio.new_event_loop()

        async def try_acquire():
            for _ in range(3):
                await heavy.acquire()

        loop.run_until_complete(try_acquire())
        loop.close()


def test_light_concurrency_defaults_to_cpu_count():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("LIGHT_CONCURRENCY", None)
        from workers.recon_core import concurrency
        _, light = concurrency.get_semaphores(force_new=True)
        assert isinstance(light, asyncio.BoundedSemaphore)
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_concurrency.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'workers.recon_core'`

**Step 3: Write minimal implementation**

```python
# workers/recon_core/concurrency.py
"""Semaphore pools for heavy and light recon tools."""

import asyncio
import os
from enum import Enum

_heavy: asyncio.BoundedSemaphore | None = None
_light: asyncio.BoundedSemaphore | None = None


class WeightClass(Enum):
    HEAVY = "heavy"
    LIGHT = "light"


def get_semaphores(
    force_new: bool = False,
) -> tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
    """Return (heavy, light) semaphore pair.

    Reads HEAVY_CONCURRENCY and LIGHT_CONCURRENCY from env.
    Defaults: heavy=2, light=cpu_count().
    """
    global _heavy, _light
    if _heavy is None or _light is None or force_new:
        heavy_cap = int(os.environ.get("HEAVY_CONCURRENCY", "2"))
        light_cap = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))
        _heavy = asyncio.BoundedSemaphore(heavy_cap)
        _light = asyncio.BoundedSemaphore(light_cap)
    return _heavy, _light


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    """Return the semaphore for the given weight class."""
    heavy, light = get_semaphores()
    return heavy if weight is WeightClass.HEAVY else light
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_recon_concurrency.py -v
```

Expected: 3 PASSED

**Step 5: Commit**

```bash
git add workers/recon_core/concurrency.py tests/test_recon_concurrency.py
git commit -m "feat(recon-core): add concurrency module with dual semaphore pools"
```

---

## Task 3: ReconTool Base Class

**Files:**
- Create: `workers/recon_core/base_tool.py`
- Create: `tests/test_recon_base_tool.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_base_tool.py
import asyncio
from unittest.mock import MagicMock

import pytest


def test_recon_tool_is_abstract():
    from workers.recon_core.base_tool import ReconTool
    with pytest.raises(TypeError):
        ReconTool()


def test_subclass_must_implement_build_command_and_parse_output():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class Incomplete(ReconTool):
        name = "incomplete"
        weight_class = WeightClass.LIGHT

    with pytest.raises(TypeError):
        Incomplete()


def test_concrete_subclass_can_instantiate():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class FakeTool(ReconTool):
        name = "fake"
        weight_class = WeightClass.LIGHT

        def build_command(self, target, headers=None):
            return ["echo", "hello"]

        def parse_output(self, stdout):
            return stdout.strip().splitlines()

    tool = FakeTool()
    assert tool.name == "fake"
    assert tool.weight_class == WeightClass.LIGHT


def test_build_command_returns_list():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class FakeTool(ReconTool):
        name = "fake"
        weight_class = WeightClass.LIGHT

        def build_command(self, target, headers=None):
            return ["echo", target.base_domain]

        def parse_output(self, stdout):
            return [stdout.strip()]

    tool = FakeTool()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert cmd == ["echo", "example.com"]


@pytest.mark.anyio
async def test_run_subprocess_captures_stdout():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class EchoTool(ReconTool):
        name = "echo_tool"
        weight_class = WeightClass.LIGHT

        def build_command(self, target, headers=None):
            return ["echo", "sub.example.com"]

        def parse_output(self, stdout):
            return [line for line in stdout.strip().splitlines() if line]

    tool = EchoTool()
    stdout = await tool.run_subprocess(["echo", "sub.example.com"], timeout=5)
    assert "sub.example.com" in stdout
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_base_tool.py -v
```

Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

Key reference points in existing codebase:
- `lib_webbh.database` — `Asset` (line 151), `Location` (line 186), `Parameter` (line 235), `Observation` (line 204), `JobState` (line 273), `Alert` (line 291)
- `lib_webbh.scope` — `ScopeManager.is_in_scope()` returns `ScopeResult` with `.in_scope`, `.normalized`, `.asset_type`, `.path`
- `lib_webbh.messaging` — `push_task(queue, data)` for Redis events
- `lib_webbh.database` — `Asset` has UniqueConstraint on `(target_id, asset_type, asset_value)` (line 155-157)

```python
# workers/recon_core/base_tool.py
"""Abstract base class for recon tool wrappers."""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select

from lib_webbh import (
    Asset,
    Alert,
    JobState,
    Location,
    Observation,
    Parameter,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager, ScopeResult

from workers.recon_core.concurrency import WeightClass, get_semaphore

logger = setup_logger("recon-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# Patterns and ports that trigger critical alerts
CRITICAL_PATHS = {".git", ".env", ".DS_Store", "wp-config.php", ".htpasswd", "web.config"}
CRITICAL_PORTS = {3389, 5900, 27017, 9200, 6379, 11211, 2375}


class ReconTool(ABC):
    """Base class for all recon tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class attributes
    and implement ``build_command()`` and ``parse_output()``.
    """

    name: str
    weight_class: WeightClass

    @abstractmethod
    def build_command(self, target, headers: dict | None = None) -> list[str]:
        """Return the CLI command as a list of strings."""

    @abstractmethod
    def parse_output(self, stdout: str) -> list:
        """Parse tool stdout into a list of results.

        Returns:
            list[str] for domain/IP strings (inserted as Asset rows)
            list[dict] with 'port' key (inserted as Location rows)
            list[dict] with 'param_name' key (inserted as Parameter rows)
        """

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        """Run a command and return stdout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise

        return stdout_bytes.decode("utf-8", errors="replace")

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        """Return True if this tool was completed within COOLDOWN_HOURS."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=COOLDOWN_HOURS)
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
                JobState.status == "COMPLETED",
                JobState.last_tool_executed == self.name,
                JobState.last_seen >= cutoff,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        """Full tool lifecycle: cooldown, subprocess, parse, scope-check, DB insert.

        Returns stats dict: {found, in_scope, new, skipped_cooldown}.
        """
        log = logger.bind(target_id=target_id, asset_type="job")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # 2. Acquire semaphore
        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            log.info(f"Running {self.name}", extra={"tool": self.name})

            # 3. Build and run command
            cmd = self.build_command(target, headers)
            try:
                stdout = await self.run_subprocess(cmd)
            except asyncio.TimeoutError:
                log.warning(f"{self.name} timed out after {TOOL_TIMEOUT}s")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}
            except FileNotFoundError:
                log.error(f"{self.name} binary not found — is it installed?")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            # 4. Parse output
            raw_results = self.parse_output(stdout)
            found = len(raw_results)

            # 5. Scope-check and insert
            new_count = 0
            in_scope_count = 0

            for item in raw_results:
                inserted = await self._process_result(
                    item, scope_manager, target_id, log
                )
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            # 6. Update job_state
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.now(timezone.utc)
                    await session.commit()

            stats = {
                "found": found,
                "in_scope": in_scope_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
            log.info(
                f"{self.name} complete",
                extra={"tool": self.name, **stats},
            )
            return stats

        finally:
            sem.release()

    async def _process_result(self, item, scope_manager, target_id, log) -> bool | None:
        """Process one parsed result. Returns True=new, False=dup, None=out-of-scope."""
        if isinstance(item, dict):
            return await self._process_dict_result(item, scope_manager, target_id, log)

        # String result — domain/IP asset
        scope_result = scope_manager.is_in_scope(item)
        if not scope_result.in_scope:
            return None

        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type == scope_result.asset_type,
                Asset.asset_value == scope_result.normalized,
            )
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                return False

            asset = Asset(
                target_id=target_id,
                asset_type=scope_result.asset_type,
                asset_value=scope_result.normalized,
                source_tool=self.name,
            )
            session.add(asset)
            await session.commit()

            if scope_result.path:
                await self._check_critical_path(
                    scope_result.path, scope_result.normalized, target_id, log
                )

            return True

    async def _process_dict_result(self, item, scope_manager, target_id, log) -> bool | None:
        """Process a dict result (port or param)."""
        if "port" in item:
            ip = item.get("ip", item.get("host", ""))
            port = item["port"]
            protocol = item.get("protocol", "tcp")

            scope_result = scope_manager.is_in_scope(ip)
            if not scope_result.in_scope:
                return None

            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == scope_result.normalized,
                )
                result = await session.execute(stmt)
                asset = result.scalar_one_or_none()
                if asset is None:
                    asset = Asset(
                        target_id=target_id,
                        asset_type=scope_result.asset_type,
                        asset_value=scope_result.normalized,
                        source_tool=self.name,
                    )
                    session.add(asset)
                    await session.flush()

                loc_stmt = select(Location).where(
                    Location.asset_id == asset.id,
                    Location.port == port,
                    Location.protocol == protocol,
                )
                loc_result = await session.execute(loc_stmt)
                if loc_result.scalar_one_or_none() is not None:
                    return False

                location = Location(
                    asset_id=asset.id,
                    port=port,
                    protocol=protocol,
                    service=item.get("service"),
                    state="open",
                )
                session.add(location)
                await session.commit()

                if port in CRITICAL_PORTS:
                    await self._create_alert(
                        target_id,
                        f"Critical port {port} open on {scope_result.normalized}",
                        log,
                    )

                return True

        elif "param_name" in item:
            url = item.get("source_url", "")
            scope_result = scope_manager.is_in_scope(url) if url else None

            if not scope_result or not scope_result.in_scope:
                return None

            async with get_session() as session:
                stmt = select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == scope_result.normalized,
                )
                result = await session.execute(stmt)
                asset = result.scalar_one_or_none()
                if asset is None:
                    return None

                param_stmt = select(Parameter).where(
                    Parameter.asset_id == asset.id,
                    Parameter.param_name == item["param_name"],
                )
                param_result = await session.execute(param_stmt)
                if param_result.scalar_one_or_none() is not None:
                    return False

                param = Parameter(
                    asset_id=asset.id,
                    param_name=item["param_name"],
                    param_value=item.get("param_value"),
                    source_url=url,
                )
                session.add(param)
                await session.commit()
                return True

        return None

    async def _check_critical_path(self, path, domain, target_id, log) -> None:
        """Check if a discovered path matches a critical pattern."""
        path_lower = path.lower().lstrip("/")
        for pattern in CRITICAL_PATHS:
            if pattern in path_lower:
                await self._create_alert(
                    target_id,
                    f"Exposed {pattern} at {domain}{path}",
                    log,
                )
                break

    async def _create_alert(self, target_id, message, log) -> None:
        """Write alert to DB and push to Redis for SSE."""
        log.warning(f"CRITICAL: {message}")
        async with get_session() as session:
            alert = Alert(
                target_id=target_id,
                alert_type="critical",
                message=message,
            )
            session.add(alert)
            await session.commit()
            alert_id = alert.id

        await push_task(f"events:{target_id}", {
            "event": "critical_alert",
            "alert_id": alert_id,
            "message": message,
        })
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_recon_base_tool.py -v
```

Expected: 5 PASSED

**Step 5: Commit**

```bash
git add workers/recon_core/base_tool.py tests/test_recon_base_tool.py
git commit -m "feat(recon-core): add ReconTool abstract base class with execute lifecycle"
```

---

## Task 4: Pipeline Module

**Files:**
- Create: `workers/recon_core/pipeline.py`
- Create: `tests/test_recon_pipeline.py`

**Note:** This task depends on all tool wrappers existing (Tasks 5-9). Implement those first, then return here. Alternatively, create pipeline.py with lazy imports and test with mocks.

**Step 1: Write the failing test**

```python
# tests/test_recon_pipeline.py
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.recon_core.pipeline import STAGES
    assert len(STAGES) == 5
    assert STAGES[0].name == "passive_discovery"
    assert STAGES[1].name == "active_discovery"
    assert STAGES[2].name == "liveness_dns"
    assert STAGES[3].name == "port_mapping"
    assert STAGES[4].name == "deep_recon"


def test_each_stage_has_tools():
    from workers.recon_core.pipeline import STAGES
    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_recon_tool_subclasses():
    from workers.recon_core.pipeline import STAGES
    from workers.recon_core.base_tool import ReconTool
    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, ReconTool), f"{tool_cls} is not a ReconTool"


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.recon_core.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="active_discovery"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "in_scope": 0, "new": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.recon_core.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 3
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        assert called_stages == ["liveness_dns", "port_mapping", "deep_recon"]
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_pipeline.py -v
```

**Step 3: Write implementation**

```python
# workers/recon_core/pipeline.py
"""Recon pipeline: 5 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.tools import (
    Subfinder,
    Assetfinder,
    Chaos,
    AmassPassive,
    Sublist3r,
    Knockpy,
    AmassActive,
    Massdns,
    HttpxTool,
    Naabu,
    Katana,
    Hakrawler,
    Waybackurls,
    Gauplus,
    Paramspider,
)

logger = setup_logger("recon-pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[ReconTool]]


STAGES = [
    Stage("passive_discovery", [Subfinder, Assetfinder, Chaos, AmassPassive]),
    Stage("active_discovery", [Sublist3r, Knockpy, AmassActive]),
    Stage("liveness_dns", [Massdns, HttpxTool]),
    Stage("port_mapping", [Naabu]),
    Stage("deep_recon", [Katana, Hakrawler, Waybackurls, Gauplus, Paramspider]),
]

STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


class Pipeline:
    """Orchestrates the 5-stage recon pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str):
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    async def run(
        self, target, scope_manager: ScopeManager, headers: dict | None = None
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        completed_phase = await self._get_completed_phase()
        start_index = 0

        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        for stage in STAGES[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            stats = await self._run_stage(stage, target, scope_manager, headers)

            self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
            await push_task(f"events:{self.target_id}", {
                "event": "stage_complete",
                "stage": stage.name,
                "stats": stats,
            })

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "pipeline_complete",
            "target_id": self.target_id,
        })

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
    ) -> dict:
        """Run all tools in a stage concurrently, return aggregated stats."""
        tools = [cls() for cls in stage.tool_classes]

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                headers=headers,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(f"Tool failed in {stage.name}", extra={"error": str(r)})
                continue
            aggregated["found"] += r.get("found", 0)
            aggregated["in_scope"] += r.get("in_scope", 0)
            aggregated["new"] += r.get("new", 0)

        return aggregated

    async def _get_completed_phase(self) -> str | None:
        """Query job_state for the last completed phase."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
                JobState.status == "COMPLETED",
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            return job.current_phase if job else None

    async def _update_phase(self, phase: str) -> None:
        """Update job_state with current phase."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.current_phase = phase
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self) -> None:
        """Mark the job as COMPLETED."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_recon_pipeline.py -v
```

Expected: 4 PASSED (requires tool wrappers from Tasks 5-9 to exist)

**Step 5: Commit**

```bash
git add workers/recon_core/pipeline.py tests/test_recon_pipeline.py
git commit -m "feat(recon-core): add pipeline module with 5-stage orchestration and resumability"
```

---

## Task 5: Tool Wrappers — Passive Discovery

**Files:**
- Create: `workers/recon_core/tools/subfinder.py`
- Create: `workers/recon_core/tools/assetfinder.py`
- Create: `workers/recon_core/tools/chaos.py`
- Create: `workers/recon_core/tools/amass.py`
- Modify: `workers/recon_core/tools/__init__.py`
- Create: `tests/test_recon_tools_passive.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_tools_passive.py
import json
from unittest.mock import MagicMock

from workers.recon_core.concurrency import WeightClass


def test_subfinder_is_light():
    from workers.recon_core.tools.subfinder import Subfinder
    assert Subfinder.weight_class == WeightClass.LIGHT


def test_subfinder_build_command():
    from workers.recon_core.tools.subfinder import Subfinder
    tool = Subfinder()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "subfinder" in cmd[0]
    assert "-d" in cmd
    assert "example.com" in cmd


def test_subfinder_parse_output_json():
    from workers.recon_core.tools.subfinder import Subfinder
    tool = Subfinder()
    output = '{"host":"a.example.com"}\n{"host":"b.example.com"}\n'
    results = tool.parse_output(output)
    assert results == ["a.example.com", "b.example.com"]


def test_subfinder_parse_output_plain():
    from workers.recon_core.tools.subfinder import Subfinder
    tool = Subfinder()
    output = "a.example.com\nb.example.com\n"
    results = tool.parse_output(output)
    assert results == ["a.example.com", "b.example.com"]


def test_assetfinder_is_light():
    from workers.recon_core.tools.assetfinder import Assetfinder
    assert Assetfinder.weight_class == WeightClass.LIGHT


def test_assetfinder_build_command():
    from workers.recon_core.tools.assetfinder import Assetfinder
    tool = Assetfinder()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "assetfinder" in cmd[0]
    assert "example.com" in cmd


def test_chaos_is_light():
    from workers.recon_core.tools.chaos import Chaos
    assert Chaos.weight_class == WeightClass.LIGHT


def test_amass_passive_is_heavy():
    from workers.recon_core.tools.amass import AmassPassive
    assert AmassPassive.weight_class == WeightClass.HEAVY


def test_amass_passive_build_command():
    from workers.recon_core.tools.amass import AmassPassive
    tool = AmassPassive()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "amass" in cmd[0]
    assert "enum" in cmd
    assert "-passive" in cmd


def test_amass_active_is_heavy():
    from workers.recon_core.tools.amass import AmassActive
    assert AmassActive.weight_class == WeightClass.HEAVY
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_tools_passive.py -v
```

**Step 3: Write implementations**

```python
# workers/recon_core/tools/subfinder.py
"""Subfinder wrapper — passive subdomain enumeration."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Subfinder(ReconTool):
    name = "subfinder"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["subfinder", "-d", target.base_domain, "-silent", "-json"]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if host:
                    results.append(host)
            except json.JSONDecodeError:
                results.append(line)
        return results
```

```python
# workers/recon_core/tools/assetfinder.py
"""Assetfinder wrapper — passive subdomain discovery."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Assetfinder(ReconTool):
    name = "assetfinder"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["assetfinder", "--subs-only", target.base_domain]

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
```

```python
# workers/recon_core/tools/chaos.py
"""Chaos (ProjectDiscovery) wrapper — passive subdomain enumeration."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Chaos(ReconTool):
    name = "chaos"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["chaos", "-d", target.base_domain, "-silent", "-json"]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", data.get("subdomain", ""))
                if host:
                    results.append(host)
            except json.JSONDecodeError:
                results.append(line)
        return results
```

```python
# workers/recon_core/tools/amass.py
"""Amass wrapper — both passive and active modes."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class AmassPassive(ReconTool):
    name = "amass_passive"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        return [
            "amass", "enum", "-passive", "-d", target.base_domain,
            "-json", "/dev/stdout",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    results.append(name)
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    results.append(line)
        return results


class AmassActive(ReconTool):
    name = "amass_active"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        return [
            "amass", "enum", "-active", "-d", target.base_domain,
            "-json", "/dev/stdout",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    results.append(name)
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    results.append(line)
        return results
```

**Step 4: Update `tools/__init__.py`**

```python
# workers/recon_core/tools/__init__.py
from workers.recon_core.tools.subfinder import Subfinder
from workers.recon_core.tools.assetfinder import Assetfinder
from workers.recon_core.tools.chaos import Chaos
from workers.recon_core.tools.amass import AmassPassive, AmassActive
```

**Step 5: Run test, commit**

```bash
pytest tests/test_recon_tools_passive.py -v
git add workers/recon_core/tools/ tests/test_recon_tools_passive.py
git commit -m "feat(recon-core): add passive discovery tool wrappers (subfinder, assetfinder, chaos, amass)"
```

---

## Task 6: Tool Wrappers — Active Discovery

**Files:**
- Create: `workers/recon_core/tools/sublist3r.py`
- Create: `workers/recon_core/tools/knockpy.py`
- Modify: `workers/recon_core/tools/__init__.py` — add `Sublist3r`, `Knockpy`
- Create: `tests/test_recon_tools_active.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_tools_active.py
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_sublist3r_is_light():
    from workers.recon_core.tools.sublist3r import Sublist3r
    assert Sublist3r.weight_class == WeightClass.LIGHT


def test_sublist3r_build_command():
    from workers.recon_core.tools.sublist3r import Sublist3r
    tool = Sublist3r()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "example.com" in cmd


def test_sublist3r_parse_output():
    from workers.recon_core.tools.sublist3r import Sublist3r
    tool = Sublist3r()
    output = "a.example.com\nb.example.com\n"
    results = tool.parse_output(output)
    assert results == ["a.example.com", "b.example.com"]


def test_knockpy_is_light():
    from workers.recon_core.tools.knockpy import Knockpy
    assert Knockpy.weight_class == WeightClass.LIGHT


def test_knockpy_build_command():
    from workers.recon_core.tools.knockpy import Knockpy
    tool = Knockpy()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "knockpy" in cmd[0]
    assert "example.com" in cmd
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_tools_active.py -v
```

**Step 3: Write implementations**

```python
# workers/recon_core/tools/sublist3r.py
"""Sublist3r wrapper — active subdomain enumeration."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Sublist3r(ReconTool):
    name = "sublist3r"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["sublist3r", "-d", target.base_domain, "-o", "/dev/stdout"]

    def parse_output(self, stdout):
        return [
            line.strip()
            for line in stdout.strip().splitlines()
            if line.strip() and "." in line
        ]
```

```python
# workers/recon_core/tools/knockpy.py
"""Knockpy wrapper — DNS subdomain scanning."""

import json

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Knockpy(ReconTool):
    name = "knockpy"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["knockpy", target.base_domain, "--json"]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    for domain in data.keys():
                        if "." in domain:
                            results.append(domain)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, str) and "." in item:
                            results.append(item)
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    results.append(line)
        return results
```

**Step 4: Append to `tools/__init__.py`**

```python
from workers.recon_core.tools.sublist3r import Sublist3r
from workers.recon_core.tools.knockpy import Knockpy
```

**Step 5: Run test, commit**

```bash
pytest tests/test_recon_tools_active.py -v
git add workers/recon_core/tools/ tests/test_recon_tools_active.py
git commit -m "feat(recon-core): add active discovery tool wrappers (sublist3r, knockpy)"
```

---

## Task 7: Tool Wrappers — Liveness & DNS

**Files:**
- Create: `workers/recon_core/tools/massdns.py`
- Create: `workers/recon_core/tools/httpx_tool.py`
- Create: `workers/recon_core/resolvers.txt`
- Modify: `workers/recon_core/tools/__init__.py` — add `Massdns`, `HttpxTool`
- Create: `tests/test_recon_tools_liveness.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_tools_liveness.py
import json
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_massdns_is_light():
    from workers.recon_core.tools.massdns import Massdns
    assert Massdns.weight_class == WeightClass.LIGHT


def test_httpx_is_light():
    from workers.recon_core.tools.httpx_tool import HttpxTool
    assert HttpxTool.weight_class == WeightClass.LIGHT


def test_httpx_build_command_includes_headers():
    from workers.recon_core.tools.httpx_tool import HttpxTool
    tool = HttpxTool()
    tool._input_file = "/tmp/test.txt"
    target = MagicMock(base_domain="example.com")
    headers = {"Authorization": "Bearer token123"}
    cmd = tool.build_command(target, headers=headers)
    assert "-H" in cmd
    idx = cmd.index("-H")
    assert "Authorization: Bearer token123" in cmd[idx + 1]


def test_httpx_parse_output():
    from workers.recon_core.tools.httpx_tool import HttpxTool
    tool = HttpxTool()
    line1 = json.dumps({
        "url": "https://a.example.com",
        "status_code": 200,
        "title": "Home",
        "tech": ["nginx"],
    })
    line2 = json.dumps({
        "url": "https://b.example.com",
        "status_code": 403,
        "title": "Forbidden",
        "tech": [],
    })
    output = f"{line1}\n{line2}\n"
    results = tool.parse_output(output)
    assert len(results) == 2
    assert results[0]["url"] == "https://a.example.com"
    assert results[0]["status_code"] == 200
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_tools_liveness.py -v
```

**Step 3: Write implementations**

```python
# workers/recon_core/tools/massdns.py
"""Massdns wrapper — high-performance DNS resolution."""

import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, get_session

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass

RESOLVERS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "resolvers.txt"
)


class Massdns(ReconTool):
    name = "massdns"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "massdns", "-r", RESOLVERS_PATH, "-t", "A",
            "-o", "S", "-w", "/dev/stdout",
            self._input_file or "/dev/null",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "A":
                domain = parts[0].rstrip(".")
                results.append(domain)
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file of domains before running."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(domains))
            self._input_file = f.name

        try:
            return await super().execute(
                target, scope_manager, target_id, container_name, headers
            )
        finally:
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
```

```python
# workers/recon_core/tools/httpx_tool.py
"""Httpx wrapper — HTTP probing and technology detection."""

import asyncio
import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session, setup_logger

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass, get_semaphore


class HttpxTool(ReconTool):
    name = "httpx"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        cmd = [
            "httpx", "-l", self._input_file or "/dev/null",
            "-json", "-silent", "-status-code", "-title",
            "-tech-detect", "-follow-redirects",
        ]
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                    "headers": data.get("header", {}),
                })
            except json.JSONDecodeError:
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file and insert Observation rows."""
        log = setup_logger("recon-tool").bind(target_id=target_id)

        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(domains))
            self._input_file = f.name

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            cmd = self.build_command(target, headers)
            try:
                stdout = await self.run_subprocess(cmd)
            except (asyncio.TimeoutError, FileNotFoundError):
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            results = self.parse_output(stdout)
            new_count = 0

            for item in results:
                url = item.get("url", "")
                scope_result = scope_manager.is_in_scope(url)
                if not scope_result.in_scope:
                    continue

                async with get_session() as session:
                    stmt = select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == scope_result.normalized,
                    )
                    result = await session.execute(stmt)
                    asset = result.scalar_one_or_none()
                    if asset is None:
                        continue

                    obs = Observation(
                        asset_id=asset.id,
                        status_code=item.get("status_code"),
                        page_title=item.get("title"),
                        tech_stack=item.get("tech"),
                        headers=item.get("headers"),
                    )
                    session.add(obs)
                    await session.commit()
                    new_count += 1

            return {
                "found": len(results),
                "in_scope": new_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
        finally:
            sem.release()
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
```

**Step 4: Create resolvers.txt**

```
# workers/recon_core/resolvers.txt
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
```

**Step 5: Append to `tools/__init__.py`**

```python
from workers.recon_core.tools.massdns import Massdns
from workers.recon_core.tools.httpx_tool import HttpxTool
```

**Step 6: Run test, commit**

```bash
pytest tests/test_recon_tools_liveness.py -v
git add workers/recon_core/ tests/test_recon_tools_liveness.py
git commit -m "feat(recon-core): add liveness/DNS tool wrappers (massdns, httpx)"
```

---

## Task 8: Tool Wrappers — Port Mapping

**Files:**
- Create: `workers/recon_core/tools/naabu.py`
- Modify: `workers/recon_core/tools/__init__.py` — add `Naabu`
- Create: `tests/test_recon_tools_ports.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_tools_ports.py
import json
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_naabu_is_heavy():
    from workers.recon_core.tools.naabu import Naabu
    assert Naabu.weight_class == WeightClass.HEAVY


def test_naabu_build_command():
    from workers.recon_core.tools.naabu import Naabu
    tool = Naabu()
    tool._input_file = "/tmp/ips.txt"
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "naabu" in cmd[0]
    assert "-list" in cmd
    assert "/tmp/ips.txt" in cmd
    assert "-json" in cmd


def test_naabu_parse_output():
    from workers.recon_core.tools.naabu import Naabu
    tool = Naabu()
    line1 = json.dumps({"ip": "1.2.3.4", "port": 80})
    line2 = json.dumps({"ip": "1.2.3.4", "port": 443})
    line3 = json.dumps({"ip": "5.6.7.8", "port": 22})
    output = f"{line1}\n{line2}\n{line3}\n"
    results = tool.parse_output(output)
    assert len(results) == 3
    assert results[0] == {"ip": "1.2.3.4", "port": 80}
    assert results[2] == {"ip": "5.6.7.8", "port": 22}
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_tools_ports.py -v
```

**Step 3: Write implementation**

```python
# workers/recon_core/tools/naabu.py
"""Naabu wrapper — fast port scanning."""

import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, get_session

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Naabu(ReconTool):
    name = "naabu"
    weight_class = WeightClass.HEAVY

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "naabu", "-list", self._input_file or "/dev/null",
            "-json", "-top-ports", "1000", "-silent",
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ip = data.get("ip", data.get("host", ""))
                port = data.get("port")
                if ip and port is not None:
                    results.append({"ip": ip, "port": int(port)})
            except (json.JSONDecodeError, ValueError):
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file of live hosts."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["ip", "domain"]),
            )
            result = await session.execute(stmt)
            hosts = [row[0] for row in result.all()]

        if not hosts:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(hosts))
            self._input_file = f.name

        try:
            return await super().execute(
                target, scope_manager, target_id, container_name, headers
            )
        finally:
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
```

**Step 4: Append to `tools/__init__.py`, run test, commit**

```python
from workers.recon_core.tools.naabu import Naabu
```

```bash
pytest tests/test_recon_tools_ports.py -v
git add workers/recon_core/tools/ tests/test_recon_tools_ports.py
git commit -m "feat(recon-core): add port mapping tool wrapper (naabu)"
```

---

## Task 9: Tool Wrappers — Deep Recon

**Files:**
- Create: `workers/recon_core/tools/katana.py`
- Create: `workers/recon_core/tools/hakrawler.py`
- Create: `workers/recon_core/tools/waybackurls.py`
- Create: `workers/recon_core/tools/gauplus.py`
- Create: `workers/recon_core/tools/paramspider.py`
- Modify: `workers/recon_core/tools/__init__.py` — add all 5 imports
- Create: `tests/test_recon_tools_deep.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_tools_deep.py
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_katana_is_heavy():
    from workers.recon_core.tools.katana import Katana
    assert Katana.weight_class == WeightClass.HEAVY


def test_katana_build_command_with_headers():
    from workers.recon_core.tools.katana import Katana
    tool = Katana()
    target = MagicMock(base_domain="example.com")
    headers = {"Cookie": "session=abc"}
    cmd = tool.build_command(target, headers=headers)
    assert "katana" in cmd[0]
    assert "-H" in cmd


def test_katana_parse_output():
    from workers.recon_core.tools.katana import Katana
    tool = Katana()
    output = "https://a.example.com/path1\nhttps://a.example.com/path2\n"
    results = tool.parse_output(output)
    assert len(results) == 2


def test_hakrawler_is_light():
    from workers.recon_core.tools.hakrawler import Hakrawler
    assert Hakrawler.weight_class == WeightClass.LIGHT


def test_waybackurls_is_light():
    from workers.recon_core.tools.waybackurls import Waybackurls
    assert Waybackurls.weight_class == WeightClass.LIGHT


def test_waybackurls_parse_output():
    from workers.recon_core.tools.waybackurls import Waybackurls
    tool = Waybackurls()
    output = "https://a.example.com/old-page\nhttps://a.example.com/api/v1\n"
    results = tool.parse_output(output)
    assert len(results) == 2


def test_gauplus_is_light():
    from workers.recon_core.tools.gauplus import Gauplus
    assert Gauplus.weight_class == WeightClass.LIGHT


def test_paramspider_is_light():
    from workers.recon_core.tools.paramspider import Paramspider
    assert Paramspider.weight_class == WeightClass.LIGHT


def test_paramspider_parse_output():
    from workers.recon_core.tools.paramspider import Paramspider
    tool = Paramspider()
    output = (
        "https://a.example.com/page?id=FUZZ\n"
        "https://a.example.com/search?q=FUZZ&lang=FUZZ\n"
    )
    results = tool.parse_output(output)
    assert any(r["param_name"] == "id" for r in results)
    assert any(r["param_name"] == "q" for r in results)
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_tools_deep.py -v
```

**Step 3: Write implementations**

```python
# workers/recon_core/tools/katana.py
"""Katana wrapper — web crawling."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Katana(ReconTool):
    name = "katana"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        cmd = ["katana", "-u", target.base_domain, "-silent", "-depth", "3"]
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
```

```python
# workers/recon_core/tools/hakrawler.py
"""Hakrawler wrapper — web crawling."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Hakrawler(ReconTool):
    name = "hakrawler"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        cmd = [
            "hakrawler", "-url", target.base_domain,
            "-depth", "2", "-plain",
        ]
        if headers:
            for key, value in headers.items():
                cmd.extend(["-h", f"{key}: {value}"])
        return cmd

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
```

```python
# workers/recon_core/tools/waybackurls.py
"""Waybackurls wrapper — historical URL discovery."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Waybackurls(ReconTool):
    name = "waybackurls"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["waybackurls", target.base_domain]

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
```

```python
# workers/recon_core/tools/gauplus.py
"""Gauplus wrapper — URL discovery from multiple sources."""

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Gauplus(ReconTool):
    name = "gauplus"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["gauplus", "-t", "5", "-random-agent", target.base_domain]

    def parse_output(self, stdout):
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
```

```python
# workers/recon_core/tools/paramspider.py
"""Paramspider wrapper — URL parameter extraction."""

from urllib.parse import urlparse, parse_qs

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass


class Paramspider(ReconTool):
    name = "paramspider"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return [
            "paramspider", "-d", target.base_domain,
            "--level", "high", "-o", "/dev/stdout",
        ]

    def parse_output(self, stdout):
        results = []
        seen = set()
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or "?" not in line:
                continue
            try:
                parsed = urlparse(line)
                params = parse_qs(parsed.query)
                for param_name in params:
                    key = (parsed.hostname or "", param_name)
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "param_name": param_name,
                            "param_value": params[param_name][0]
                            if params[param_name]
                            else None,
                            "source_url": line,
                        })
            except Exception:
                continue
        return results
```

**Step 4: Final `tools/__init__.py`**

```python
# workers/recon_core/tools/__init__.py
from workers.recon_core.tools.subfinder import Subfinder
from workers.recon_core.tools.assetfinder import Assetfinder
from workers.recon_core.tools.chaos import Chaos
from workers.recon_core.tools.amass import AmassPassive, AmassActive
from workers.recon_core.tools.sublist3r import Sublist3r
from workers.recon_core.tools.knockpy import Knockpy
from workers.recon_core.tools.massdns import Massdns
from workers.recon_core.tools.httpx_tool import HttpxTool
from workers.recon_core.tools.naabu import Naabu
from workers.recon_core.tools.katana import Katana
from workers.recon_core.tools.hakrawler import Hakrawler
from workers.recon_core.tools.waybackurls import Waybackurls
from workers.recon_core.tools.gauplus import Gauplus
from workers.recon_core.tools.paramspider import Paramspider

__all__ = [
    "Subfinder", "Assetfinder", "Chaos", "AmassPassive", "AmassActive",
    "Sublist3r", "Knockpy",
    "Massdns", "HttpxTool",
    "Naabu",
    "Katana", "Hakrawler", "Waybackurls", "Gauplus", "Paramspider",
]
```

**Step 5: Run test, commit**

```bash
pytest tests/test_recon_tools_deep.py -v
git add workers/recon_core/tools/ tests/test_recon_tools_deep.py
git commit -m "feat(recon-core): add deep recon tool wrappers (katana, hakrawler, waybackurls, gauplus, paramspider)"
```

---

## Task 10: Main Entry Point

**Files:**
- Create: `workers/recon_core/main.py`
- Create: `tests/test_recon_main.py`

**Step 1: Write the failing test**

```python
# tests/test_recon_main.py
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


@pytest.mark.anyio
async def test_handle_message_creates_job_state_and_runs_pipeline():
    with patch("workers.recon_core.main.Pipeline") as MockPipeline, \
         patch("workers.recon_core.main.get_session") as mock_get_session:

        mock_pipeline_instance = MagicMock()
        mock_pipeline_instance.run = AsyncMock()
        MockPipeline.return_value = mock_pipeline_instance

        mock_session = AsyncMock()
        mock_target = MagicMock(
            id=1,
            base_domain="example.com",
            target_profile={
                "in_scope_domains": ["*.example.com"],
                "custom_headers": {"X-Bug-Bounty": "true"},
            },
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_target
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.add = MagicMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_get_session.return_value = mock_ctx

        from workers.recon_core.main import handle_message

        await handle_message("msg-001", {"target_id": 1, "action": "full_recon"})

        MockPipeline.assert_called_once()
        mock_pipeline_instance.run.assert_awaited_once()


def test_container_name_from_hostname():
    with patch.dict(os.environ, {"HOSTNAME": "recon-core-abc123"}):
        from workers.recon_core.main import get_container_name
        assert get_container_name() == "recon-core-abc123"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_recon_main.py -v
```

**Step 3: Write implementation**

```python
# workers/recon_core/main.py
"""Recon-Core worker entry point.

Listens on ``recon_queue`` and runs the 5-stage reconnaissance
pipeline for each incoming target.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_queue,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.recon_core.pipeline import Pipeline

logger = setup_logger("recon-core")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "recon-core-unknown")


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single recon_queue message."""
    target_id = data.get("target_id")
    action = data.get("action", "full_recon")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info(f"Received {action}", extra={"msg_id": msg_id})

    # Load target
    async with get_session() as session:
        stmt = select(Target).where(Target.id == target_id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

    if target is None:
        log.error(f"Target {target_id} not found in database")
        return

    container_name = get_container_name()
    profile = target.target_profile or {}
    headers = profile.get("custom_headers", {})
    scope_manager = ScopeManager(profile)

    # Ensure job_state row
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if job is None:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                current_phase="init",
                status="RUNNING",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.now(timezone.utc)
        await session.commit()

    # Run pipeline with heartbeat
    pipeline = Pipeline(target_id=target_id, container_name=container_name)
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(target_id, container_name)
    )

    try:
        await pipeline.run(target, scope_manager, headers=headers)
    except Exception:
        log.exception("Pipeline failed")
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "FAILED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    """Update job_state.last_seen every HEARTBEAT_INTERVAL seconds."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass


async def main() -> None:
    """Entry point: listen on recon_queue forever."""
    container_name = get_container_name()
    logger.info("Recon-Core starting", extra={"container": container_name})

    await listen_queue(
        queue="recon_queue",
        group="recon_group",
        consumer=container_name,
        callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 4: Run test, commit**

```bash
pytest tests/test_recon_main.py -v
git add workers/recon_core/main.py tests/test_recon_main.py
git commit -m "feat(recon-core): add main entry point with Redis listener and heartbeat"
```

---

## Task 11: Dockerfile

**Files:**
- Create: `docker/Dockerfile.recon`

**Step 1: Write the Dockerfile**

```dockerfile
# docker/Dockerfile.recon
# ============================================================
# Stage 1: Go tool builder
# ============================================================
FROM golang:1.22-bookworm AS go-builder

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    go install github.com/owasp-amass/amass/v4/...@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/bp0lr/gauplus@latest

# ============================================================
# Stage 2: Python tool builder
# ============================================================
FROM python:3.10-slim-bookworm AS py-builder

RUN pip install --no-cache-dir --target=/py-tools \
    sublist3r \
    knockpy \
    paramspider

# ============================================================
# Stage 3: Runtime
# ============================================================
FROM python:3.10-slim-bookworm

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libpq-dev libpcap-dev massdns git && \
    rm -rf /var/lib/apt/lists/*

# Go binaries
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/
COPY --from=go-builder /go/bin/chaos /usr/local/bin/
COPY --from=go-builder /go/bin/amass /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/naabu /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/hakrawler /usr/local/bin/
COPY --from=go-builder /go/bin/gauplus /usr/local/bin/

# Python tools
COPY --from=py-builder /py-tools /usr/local/lib/python3.10/site-packages/

# Install lib_webbh
COPY shared/lib_webbh /app/shared/lib_webbh
RUN pip install --no-cache-dir /app/shared/lib_webbh

# Shared directories
RUN mkdir -p /app/shared/raw /app/shared/config /app/shared/logs

# Worker source
COPY workers/__init__.py /app/workers/__init__.py
COPY workers/recon_core /app/workers/recon_core

# Verify
RUN python -c "from workers.recon_core.main import main; print('recon-core OK')"

ENTRYPOINT ["python", "-m", "workers.recon_core.main"]
```

**Step 2: Commit**

```bash
git add docker/Dockerfile.recon
git commit -m "feat(recon-core): add multi-stage Dockerfile for recon worker"
```

---

## Task 12: Wire Orchestrator

**Files:**
- Modify: `orchestrator/event_engine.py:49-54` — add recon worker to `WORKER_IMAGES`
- Modify: `orchestrator/event_engine.py:290-305` — add `_check_recon_trigger()` and call it in `run_event_loop()`

**Step 1: Add recon to WORKER_IMAGES**

At `orchestrator/event_engine.py:49`, add the recon entry:

```python
WORKER_IMAGES = {
    "recon":           os.environ.get("WORKER_IMAGE_RECON",   "webbh/recon-core:latest"),
    "cloud_testing":   os.environ.get("WORKER_IMAGE_CLOUD",   "webbh/cloud-worker:latest"),
    "fuzzing":         os.environ.get("WORKER_IMAGE_FUZZING",  "webbh/fuzzing-worker:latest"),
    "webapp_testing":  os.environ.get("WORKER_IMAGE_WEBAPP",   "webbh/webapp-worker:latest"),
    "api_testing":     os.environ.get("WORKER_IMAGE_API",      "webbh/api-worker:latest"),
}
```

**Step 2: Add recon trigger function**

After `_check_api_trigger()` (~line 284), add:

```python
async def _check_recon_trigger() -> None:
    """Trigger recon worker for new targets with no active/completed recon job."""
    async with get_session() as session:
        active_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-recon-%"),
                JobState.status.in_(ACTIVE_STATUSES),
            )
        ).subquery()

        completed_sub = (
            select(JobState.target_id)
            .where(
                JobState.container_name.like("webbh-recon-%"),
                JobState.status == "COMPLETED",
            )
        ).subquery()

        stmt = (
            select(Target.id)
            .where(
                Target.id.notin_(select(active_sub.c.target_id)),
                Target.id.notin_(select(completed_sub.c.target_id)),
            )
        )
        result = await session.execute(stmt)
        target_ids = [row[0] for row in result.all()]

    for tid in target_ids:
        logger.info("Recon trigger fired", extra={"target_id": tid})
        await _trigger_worker(tid, "recon", "passive_discovery")
```

**Step 3: Call it in run_event_loop()**

In `run_event_loop()` (~line 297), add `await _check_recon_trigger()` as the first trigger check:

```python
async def run_event_loop() -> None:
    logger.info("Event engine started", extra={"poll_interval": POLL_INTERVAL})
    await asyncio.sleep(3)

    while True:
        try:
            await _check_recon_trigger()
            await _check_cloud_trigger()
            await _check_web_trigger()
            await _check_api_trigger()
        except Exception:
            logger.exception("Error in event loop cycle")

        await asyncio.sleep(POLL_INTERVAL)
```

**Step 4: Commit**

```bash
git add orchestrator/event_engine.py
git commit -m "feat(orchestrator): add recon worker image config and auto-trigger for new targets"
```

---

## Task 13: Integration Test

**Files:**
- Create: `tests/test_recon_integration.py`

**Step 1: Write the integration test**

```python
# tests/test_recon_integration.py
"""Integration: run a tool with mocked subprocess, verify scope + DB inserts."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"

from lib_webbh import Base, get_engine, get_session, Target, Asset, JobState
from sqlalchemy import select


@pytest.fixture
async def setup_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def seed_target(setup_db):
    async with get_session() as session:
        target = Target(
            company_name="TestCorp",
            base_domain="example.com",
            target_profile={
                "in_scope_domains": ["*.example.com"],
                "out_scope_domains": [],
                "in_scope_cidrs": [],
                "in_scope_regex": [],
            },
        )
        session.add(target)
        await session.commit()
        return target.id


@pytest.mark.anyio
async def test_subfinder_inserts_in_scope_assets_only(seed_target):
    target_id = seed_target

    async with get_session() as session:
        result = await session.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one()

    # Create job_state
    async with get_session() as session:
        job = JobState(
            target_id=target_id,
            container_name="test-recon",
            current_phase="init",
            status="RUNNING",
        )
        session.add(job)
        await session.commit()

    subfinder_output = "api.example.com\nwww.example.com\noutofscope.evil.com\n"

    async def mock_subprocess(*cmd, **kwargs):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(subfinder_output.encode(), b"")
        )
        return mock_proc

    from lib_webbh.scope import ScopeManager
    from workers.recon_core.tools.subfinder import Subfinder

    scope_mgr = ScopeManager(target.target_profile)
    tool = Subfinder()

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
        stats = await tool.execute(
            target=target,
            scope_manager=scope_mgr,
            target_id=target_id,
            container_name="test-recon",
        )

    assert stats["found"] == 3
    assert stats["in_scope"] == 2
    assert stats["new"] == 2

    async with get_session() as session:
        result = await session.execute(
            select(Asset).where(Asset.target_id == target_id)
        )
        assets = result.scalars().all()
        values = {a.asset_value for a in assets}

    assert "api.example.com" in values
    assert "www.example.com" in values
    assert "outofscope.evil.com" not in values
```

**Step 2: Run test**

```bash
pytest tests/test_recon_integration.py -v
```

Expected: PASSED

**Step 3: Commit**

```bash
git add tests/test_recon_integration.py
git commit -m "test(recon-core): add integration test with mocked subprocess and scope filtering"
```

---

## Task 14: Full Test Suite Verification

**Step 1: Run all tests**

```bash
pytest tests/ -v --tb=short
```

Expected: All tests pass including existing Phase 0-3 tests.

**Step 2: Verify imports work end-to-end**

```bash
python -c "from workers.recon_core.main import main; print('Entry point OK')"
python -c "from workers.recon_core.pipeline import STAGES; print(f'{len(STAGES)} stages')"
python -c "from workers.recon_core.tools import Subfinder, Naabu, Katana; print('Tools OK')"
```

**Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix(recon-core): address issues from full test suite run"
```

---

## Task Dependency Order

Tasks must be implemented in this order due to import dependencies:

```
Task 1 (scaffold)
  └── Task 2 (concurrency)
       └── Task 3 (base_tool)
            ├── Task 5 (passive tools)
            ├── Task 6 (active tools)
            ├── Task 7 (liveness tools)
            ├── Task 8 (port tools)
            └── Task 9 (deep recon tools)
                 └── Task 4 (pipeline — imports all tools)
                      └── Task 10 (main — imports pipeline)
                           ├── Task 11 (Dockerfile)
                           ├── Task 12 (orchestrator wiring)
                           └── Task 13 (integration test)
                                └── Task 14 (full verification)
```

Tasks 5-9 can be implemented in parallel since they're independent tool wrappers.
