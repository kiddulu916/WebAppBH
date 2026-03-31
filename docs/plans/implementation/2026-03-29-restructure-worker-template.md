# Worker Implementation Template

> **For Claude:** This template is referenced by M4–M8 implementation plans. Each worker plan specifies its unique tools, stages, and base_tool helpers — then follows this template for the structural scaffolding.

**Goal:** Provide a DRY pattern for implementing any WSTG-aligned worker. Each worker plan fills in the variables marked with `{VARIABLE}` below.

---

## Template Variables

Each worker plan defines:

| Variable | Example (info_gathering) |
|----------|------------------------|
| `{WORKER_NAME}` | `info_gathering` |
| `{WORKER_DIR}` | `workers/info_gathering` |
| `{QUEUE_NAME}` | `info_gathering_queue` |
| `{BASE_TOOL_CLASS}` | `InfoGatheringTool` |
| `{STAGES}` | list of Stage objects |
| `{TOOL_WEIGHTS}` | dict mapping tool name → HEAVY/LIGHT |
| `{TOOLS}` | list of tool classes to implement |
| `{DOCKER_BINARIES}` | list of external tools to install in Dockerfile |
| `{BASE_TOOL_HELPERS}` | worker-specific helper methods on the base class |

---

## Task T1: Scaffold Worker Directory

**Files:**
- Create: `{WORKER_DIR}/__init__.py`
- Create: `{WORKER_DIR}/tools/__init__.py`
- Create: `{WORKER_DIR}/requirements.txt`
- Create: `tests/test_{WORKER_NAME}/` directory

**Step 1: Create directory structure**

```bash
mkdir -p {WORKER_DIR}/tools tests/test_{WORKER_NAME}
touch {WORKER_DIR}/__init__.py {WORKER_DIR}/tools/__init__.py
touch tests/test_{WORKER_NAME}/__init__.py
```

**Step 2: Create requirements.txt**

```txt
# {WORKER_DIR}/requirements.txt
# lib_webbh installed from shared/ in Dockerfile
# External tools are system binaries called via asyncio subprocess
```

**Step 3: Commit**

```bash
git add {WORKER_DIR}/ tests/test_{WORKER_NAME}/
git commit -m "chore({WORKER_NAME}): scaffold worker directory structure"
```

---

## Task T2: Concurrency Module

**Files:**
- Create: `{WORKER_DIR}/concurrency.py`
- Test: `tests/test_{WORKER_NAME}/test_concurrency.py`

**Step 1: Write the failing test**

```python
# tests/test_{WORKER_NAME}/test_concurrency.py
import asyncio


def test_get_semaphores_returns_bounded_semaphores():
    from {WORKER_DIR_IMPORT}.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.Semaphore)
    assert isinstance(light, asyncio.Semaphore)


def test_tool_weights_contains_all_tools():
    from {WORKER_DIR_IMPORT}.concurrency import TOOL_WEIGHTS

    # Every tool must have a weight entry
    expected_tools = {TOOL_NAMES_LIST}
    assert set(TOOL_WEIGHTS.keys()) == expected_tools


def test_tool_weights_valid_values():
    from {WORKER_DIR_IMPORT}.concurrency import TOOL_WEIGHTS

    for tool, weight in TOOL_WEIGHTS.items():
        assert weight in ("HEAVY", "LIGHT"), f"{tool} has invalid weight: {weight}"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_{WORKER_NAME}/test_concurrency.py -v`

**Step 3: Write concurrency.py**

```python
# {WORKER_DIR}/concurrency.py
import asyncio
import os

HEAVY_LIMIT = 2
LIGHT_LIMIT = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))

TOOL_WEIGHTS = {
    # Filled in by each worker plan
    {TOOL_WEIGHTS_DICT}
}


def get_semaphores() -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
    return asyncio.Semaphore(HEAVY_LIMIT), asyncio.Semaphore(LIGHT_LIMIT)
```

**Step 4: Run test, verify pass. Commit.**

---

## Task T3: Base Tool Class

**Files:**
- Create: `{WORKER_DIR}/base_tool.py`
- Test: `tests/test_{WORKER_NAME}/test_base_tool.py`

**Step 1: Write the failing test**

```python
# tests/test_{WORKER_NAME}/test_base_tool.py
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from {WORKER_DIR_IMPORT}.base_tool import {BASE_TOOL_CLASS}

    assert issubclass({BASE_TOOL_CLASS}, ABC)

    with pytest.raises(TypeError):
        {BASE_TOOL_CLASS}()  # Cannot instantiate abstract class


def test_base_tool_has_worker_type():
    from {WORKER_DIR_IMPORT}.base_tool import {BASE_TOOL_CLASS}

    assert {BASE_TOOL_CLASS}.worker_type == "{WORKER_NAME}"
```

**Step 2: Run test, verify fail.**

**Step 3: Write base_tool.py**

```python
# {WORKER_DIR}/base_tool.py
from abc import ABC, abstractmethod
from lib_webbh import get_session, Vulnerability


class {BASE_TOOL_CLASS}(ABC):
    """Abstract base for all {WORKER_NAME} tools."""

    worker_type = "{WORKER_NAME}"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        """Run this tool against the target. Must be implemented by subclasses."""
        ...

    async def save_vulnerability(self, target_id, **kwargs):
        """Helper: insert a Vulnerability record."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                worker_type=self.worker_type,
                **kwargs,
            )
            session.add(vuln)
            await session.commit()
            return vuln.id

    {BASE_TOOL_HELPERS}
```

Each worker plan fills in `{BASE_TOOL_HELPERS}` with worker-specific methods (e.g., `get_tester_session()` for credential-dependent workers, `get_browser_context()` for client_side, `request_via_proxy()` for proxy-enabled workers).

**Step 4: Run test, verify pass. Commit.**

---

## Task T4: Implement Each Tool (Repeat per tool)

For each tool in `{TOOLS}`:

**Files:**
- Create: `{WORKER_DIR}/tools/{tool_filename}.py`
- Test: `tests/test_{WORKER_NAME}/test_{tool_filename}.py`

**Step 1: Write the failing test**

Each tool test verifies:
- The tool subclasses `{BASE_TOOL_CLASS}`
- `execute()` exists and is not abstract
- Output is stored correctly (Vulnerability or Observation records)
- For subprocess tools: `build_command()` returns expected command list, `parse_output()` handles sample output

```python
# tests/test_{WORKER_NAME}/test_{tool_filename}.py
import pytest

pytestmark = pytest.mark.anyio


def test_{tool_name}_subclasses_base():
    from {WORKER_DIR_IMPORT}.tools.{tool_filename} import {ToolClass}
    from {WORKER_DIR_IMPORT}.base_tool import {BASE_TOOL_CLASS}

    assert issubclass({ToolClass}, {BASE_TOOL_CLASS})


async def test_{tool_name}_execute(db_session):
    """Test that execute runs and produces expected output type."""
    # Tool-specific test — see individual worker plans for exact test content
    ...
```

**Step 2: Run test, verify fail.**

**Step 3: Implement the tool**

```python
# {WORKER_DIR}/tools/{tool_filename}.py
from {WORKER_DIR_IMPORT}.base_tool import {BASE_TOOL_CLASS}


class {ToolClass}({BASE_TOOL_CLASS}):
    """Tool description from design doc."""

    async def execute(self, target_id: int, **kwargs):
        # Implementation from design doc
        ...
```

**Step 4: Run test, verify pass. Commit.**

Commit message: `feat({WORKER_NAME}): add {ToolClass}`

---

## Task T5: Pipeline Module

**Files:**
- Create: `{WORKER_DIR}/pipeline.py`
- Test: `tests/test_{WORKER_NAME}/test_pipeline.py`

**Step 1: Write the failing test**

```python
# tests/test_{WORKER_NAME}/test_pipeline.py
import pytest

pytestmark = pytest.mark.anyio


def test_pipeline_stages_defined():
    from {WORKER_DIR_IMPORT}.pipeline import STAGES

    assert len(STAGES) == {EXPECTED_STAGE_COUNT}
    assert all(hasattr(s, "name") for s in STAGES)
    assert all(hasattr(s, "section_id") for s in STAGES)
    assert all(hasattr(s, "tools") for s in STAGES)


def test_pipeline_stages_ordered():
    from {WORKER_DIR_IMPORT}.pipeline import STAGES

    section_ids = [s.section_id for s in STAGES]
    # Verify stages are in WSTG section order
    assert section_ids == sorted(section_ids)


def test_pipeline_all_tools_have_weights():
    from {WORKER_DIR_IMPORT}.pipeline import STAGES
    from {WORKER_DIR_IMPORT}.concurrency import TOOL_WEIGHTS

    all_tools = set()
    for stage in STAGES:
        for tool_cls in stage.tools:
            all_tools.add(tool_cls.__name__)

    assert all_tools == set(TOOL_WEIGHTS.keys())
```

**Step 2: Run test, verify fail.**

**Step 3: Write pipeline.py**

```python
# {WORKER_DIR}/pipeline.py
from dataclasses import dataclass, field


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


# Import all tool classes
from .tools.{tool1} import {Tool1Class}
from .tools.{tool2} import {Tool2Class}
# ... etc

STAGES = [
    Stage(name="{stage1_name}", section_id="{section_id}", tools=[{Tool1Class}, {Tool2Class}]),
    # ... one Stage per WSTG sub-section
]
```

**Step 4: Run test, verify pass. Commit.**

---

## Task T6: Main Entry Point

**Files:**
- Create: `{WORKER_DIR}/main.py`

**Step 1: Write main.py**

```python
# {WORKER_DIR}/main.py
import asyncio
import os
import socket

from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.database import get_session, JobState
from lib_webbh import setup_logger

from .pipeline import STAGES
from .concurrency import get_semaphores, TOOL_WEIGHTS

logger = setup_logger("{WORKER_NAME}")

WORKER_TYPE = "{WORKER_NAME}"


async def run_pipeline(target_id: int):
    """Run all stages sequentially, tools within each stage concurrently."""
    heavy_sem, light_sem = get_semaphores()

    for stage_idx, stage in enumerate(STAGES):
        logger.info("Stage started", stage=stage.name, section_id=stage.section_id)

        # Update job state
        async with get_session() as session:
            from sqlalchemy import select, update
            await session.execute(
                update(JobState)
                .where(JobState.target_id == target_id)
                .where(JobState.container_name == WORKER_TYPE)
                .values(
                    current_phase=stage.name,
                    current_section_id=stage.section_id,
                    last_tool_executed=None,
                )
            )
            await session.commit()

        # Run tools concurrently within the stage
        async def run_tool(tool_cls):
            weight = TOOL_WEIGHTS.get(tool_cls.__name__, "LIGHT")
            sem = heavy_sem if weight == "HEAVY" else light_sem
            async with sem:
                tool = tool_cls()
                await tool.execute(target_id)

        await asyncio.gather(*(run_tool(t) for t in stage.tools))

        logger.info("Stage complete", stage=stage.name)


async def main():
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

    async for message in listen_priority_queues(
        f"{WORKER_TYPE}_queue", consumer_group, consumer_name
    ):
        target_id = message["payload"]["target_id"]
        logger.info("Job received", target_id=target_id)

        try:
            # Create/update job state
            async with get_session() as session:
                from datetime import datetime, timezone
                job = JobState(
                    target_id=target_id,
                    container_name=WORKER_TYPE,
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                session.add(job)
                await session.commit()

            await run_pipeline(target_id)

            # Mark complete
            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="complete", completed_at=datetime.now(timezone.utc))
                )
                await session.commit()

        except Exception as e:
            logger.error("Job failed", target_id=target_id, error=str(e))
            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="failed", error=str(e))
                )
                await session.commit()

        # ACK the message
        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 2: Commit**

```bash
git add {WORKER_DIR}/main.py
git commit -m "feat({WORKER_NAME}): add main entry point with priority queue consumer"
```

---

## Task T7: Dockerfile

**Files:**
- Create: `docker/Dockerfile.{WORKER_NAME}`
- Modify: `docker-compose.yml`

**Step 1: Write Dockerfile**

```dockerfile
# docker/Dockerfile.{WORKER_NAME}
FROM webbh-base:latest

# Install external tool binaries
{DOCKER_INSTALL_COMMANDS}

# Copy worker code
COPY workers/{WORKER_NAME}/ /app/workers/{WORKER_NAME}/
COPY shared/ /app/shared/

# Install lib_webbh
RUN pip install -e /app/shared/lib_webbh

WORKDIR /app
ENV WORKER_TYPE={WORKER_NAME}

CMD ["python", "-m", "workers.{WORKER_NAME}.main"]
```

**Step 2: Add docker-compose entry**

```yaml
  worker_{WORKER_NAME}:
    build:
      context: .
      dockerfile: docker/Dockerfile.{WORKER_NAME}
    depends_on:
      - postgres
      - redis
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=${DB_USER}
      - DB_PASS=${DB_PASS}
      - DB_NAME=${DB_NAME}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - WORKER_TYPE={WORKER_NAME}
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 2G
    networks:
      - webbh_net
```

**Step 3: Commit**

```bash
git add docker/Dockerfile.{WORKER_NAME} docker-compose.yml
git commit -m "feat({WORKER_NAME}): add Dockerfile and docker-compose entry"
```

---

## Task T8: Integration Test

**Files:**
- Create: `tests/test_{WORKER_NAME}/test_integration.py`

**Step 1: Write integration test**

```python
# tests/test_{WORKER_NAME}/test_integration.py
import pytest

pytestmark = pytest.mark.anyio


async def test_pipeline_runs_all_stages(db_session):
    """Verify pipeline executes all stages without error against a test target."""
    from lib_webbh.database import Target
    from {WORKER_DIR_IMPORT}.pipeline import STAGES

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    # Each stage should be importable and its tools instantiable
    for stage in STAGES:
        for tool_cls in stage.tools:
            tool = tool_cls()
            assert hasattr(tool, "execute")
            assert tool.worker_type == "{WORKER_NAME}"
```

**Step 2: Run test, verify pass. Commit.**

```bash
git add tests/test_{WORKER_NAME}/test_integration.py
git commit -m "test({WORKER_NAME}): add integration test for pipeline stages"
```
