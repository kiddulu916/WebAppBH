# Phase 8 — API Testing Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `api_worker` Dockerized worker with a 4-stage pipeline for API discovery, auth testing, injection testing, and abuse testing.

**Architecture:** Sequential 4-stage pipeline with concurrent tools per stage, following the exact same `Stage`/`Pipeline`/`BaseTool` pattern from `workers/vuln_scanner/`. New `ApiSchema` model in `shared/lib_webbh/database.py`. All tools self-contained in `workers/api_worker/tools/`.

**Tech Stack:** Python 3.10, asyncio, SQLAlchemy async, httpx[http2], ffuf (Go), jwt_tool, nosqlmap, CORScanner, graphql-cop, InQL, TruffleHog

**Design doc:** `docs/plans/design/2026-03-10-phase8-api-testing-worker-design.md`

---

### Task 1: Add ApiSchema model to database.py

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Modify: `shared/lib_webbh/__init__.py`
- Test: `tests/test_database.py`

**Step 1: Write the failing test**

Append to `tests/test_database.py`:

```python
def test_api_schema_model_importable():
    from lib_webbh import ApiSchema
    assert ApiSchema.__tablename__ == "api_schemas"


@pytest.mark.anyio
async def test_api_schema_crud():
    await _create_tables()
    from lib_webbh import ApiSchema, Target, get_session

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()

        schema = ApiSchema(
            target_id=t.id,
            method="GET",
            path="/api/v1/users",
            params={"query": ["id", "page"]},
            auth_required=True,
            content_type="application/json",
            source_tool="openapi_parser",
            spec_type="openapi",
        )
        session.add(schema)
        await session.commit()

        from sqlalchemy import select
        stmt = select(ApiSchema).where(ApiSchema.target_id == t.id)
        result = await session.execute(stmt)
        row = result.scalar_one()
        assert row.method == "GET"
        assert row.path == "/api/v1/users"
        assert row.params == {"query": ["id", "page"]}
        assert row.auth_required is True
        assert row.spec_type == "openapi"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_database.py::test_api_schema_model_importable -v`
Expected: FAIL with `ImportError: cannot import name 'ApiSchema'`

**Step 3: Add ApiSchema model to database.py**

Add after the `Alert` class in `shared/lib_webbh/database.py`:

```python
class ApiSchema(TimestampMixin, Base):
    """Discovered API endpoint (path + method + params) for a target."""

    __tablename__ = "api_schemas"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "asset_id", "method", "path",
            name="uq_api_schemas_target_asset_method_path",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("assets.id"), nullable=True
    )
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2000))
    params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    auth_required: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    spec_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    target: Mapped["Target"] = relationship(back_populates="api_schemas")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="api_schemas")
```

Add to `Target` class: `api_schemas: Mapped[list["ApiSchema"]] = relationship(back_populates="target", cascade="all, delete-orphan")`

Add to `Asset` class: `api_schemas: Mapped[list["ApiSchema"]] = relationship(back_populates="asset")`

Update `shared/lib_webbh/__init__.py` — add `ApiSchema` to imports and `__all__`.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_database.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add shared/lib_webbh/database.py shared/lib_webbh/__init__.py tests/test_database.py
git commit -m "feat(lib_webbh): add ApiSchema model for API endpoint discovery"
```

---

### Task 2: Create api_worker skeleton — concurrency.py, __init__.py

**Files:**
- Create: `workers/api_worker/__init__.py`
- Create: `workers/api_worker/concurrency.py`
- Test: `tests/test_api_worker_pipeline.py` (start file)

**Step 1: Write the failing test**

Create `tests/test_api_worker_pipeline.py`:

```python
import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_concurrency_semaphore_defaults():
    from workers.api_worker.concurrency import WeightClass, get_semaphores
    heavy, light = get_semaphores(force_new=True)
    assert heavy._value == 2
    assert light._value >= 1


def test_weight_class_enum():
    from workers.api_worker.concurrency import WeightClass
    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api_worker_pipeline.py::test_concurrency_semaphore_defaults -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'workers.api_worker'`

**Step 3: Create the files**

`workers/api_worker/__init__.py`: empty file

`workers/api_worker/concurrency.py` — copy from `workers/vuln_scanner/concurrency.py` (identical logic):

```python
"""Semaphore pools for heavy and light API testing tools."""

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
    global _heavy, _light
    if _heavy is None or _light is None or force_new:
        heavy_cap = int(os.environ.get("HEAVY_CONCURRENCY", "2"))
        light_cap = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))
        _heavy = asyncio.BoundedSemaphore(heavy_cap)
        _light = asyncio.BoundedSemaphore(light_cap)
    return _heavy, _light


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    heavy, light = get_semaphores()
    return heavy if weight is WeightClass.HEAVY else light
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_pipeline.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/__init__.py workers/api_worker/concurrency.py tests/test_api_worker_pipeline.py
git commit -m "feat(api-worker): add worker skeleton with concurrency module"
```

---

### Task 3: Create base_tool.py — ApiTestTool ABC

**Files:**
- Create: `workers/api_worker/base_tool.py`
- Modify: `tests/test_api_worker_pipeline.py`

**Step 1: Write the failing tests**

Append to `tests/test_api_worker_pipeline.py`:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _make_dummy_tool():
    from workers.api_worker.base_tool import ApiTestTool
    from workers.api_worker.concurrency import WeightClass

    class DummyApiTool(ApiTestTool):
        name = "dummy-api"
        weight_class = WeightClass.LIGHT

        async def execute(self, target, scope_manager, target_id, container_name,
                          headers=None, **kwargs):
            return {"found": 0, "in_scope": 0, "new": 0}

    return DummyApiTool()


@pytest.mark.anyio
async def test_api_base_tool_check_cooldown_no_job():
    await _create_tables()
    tool = _make_dummy_tool()
    result = await tool.check_cooldown(999, "test-container")
    assert result is False


@pytest.mark.anyio
async def test_api_base_tool_save_vulnerability():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/api")
        session.add(a)
        await session.commit()
        tid, aid = t.id, a.id

    tool = _make_dummy_tool()
    with patch.object(tool, "_create_alert", new_callable=AsyncMock):
        vuln_id = await tool._save_vulnerability(
            target_id=tid, asset_id=aid, severity="high",
            title="Test JWT bypass", description="Algorithm confusion",
            poc="eyJ...",
        )
    assert vuln_id > 0


@pytest.mark.anyio
async def test_api_base_tool_save_api_schema():
    await _create_tables()
    from lib_webbh import Target, get_session

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.commit()
        tid = t.id

    tool = _make_dummy_tool()
    schema_id = await tool._save_api_schema(
        target_id=tid, asset_id=None, method="GET",
        path="/api/v1/users", params={"query": ["id"]},
        content_type="application/json", source_tool="ffuf_api",
        spec_type="discovered",
    )
    assert schema_id > 0

    # Upsert — same method+path should return same id
    schema_id2 = await tool._save_api_schema(
        target_id=tid, asset_id=None, method="GET",
        path="/api/v1/users", params={"query": ["id", "page"]},
        content_type="application/json", source_tool="openapi_parser",
        spec_type="openapi",
    )
    assert schema_id2 == schema_id


@pytest.mark.anyio
async def test_api_base_tool_get_api_urls():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a1 = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/api/v1/users")
        a2 = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/about")
        a3 = Asset(target_id=t.id, asset_type="url", asset_value="https://acme.com/graphql")
        session.add_all([a1, a2, a3])
        await session.commit()
        tid = t.id

    tool = _make_dummy_tool()
    api_urls = await tool._get_api_urls(tid)
    values = [u[1] for u in api_urls]
    assert "https://acme.com/api/v1/users" in values
    assert "https://acme.com/graphql" in values
    assert "https://acme.com/about" not in values
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api_worker_pipeline.py::test_api_base_tool_check_cooldown_no_job -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'workers.api_worker.base_tool'`

**Step 3: Create base_tool.py**

Create `workers/api_worker/base_tool.py`. This mirrors `workers/vuln_scanner/base_tool.py` but adds API-specific helpers. See design doc Section 3 for full helper list. Key implementation details:

- Import `ApiSchema` from `lib_webbh`
- Import `String` from `sqlalchemy` for the `_get_tech_filtered_urls` cast
- `API_URL_PATTERNS` list for filtering API URLs
- `OAUTH_PATH_PATTERNS` list for OAuth endpoint detection
- `JWT_RE` regex for JWT token detection in headers
- `PATH_PARAM_RE` regex for path parameter detection
- `_save_api_schema()` does upsert: select existing by (target_id, asset_id, method, path), update if found, insert if not
- `_get_jwt_tokens()` iterates observation headers looking for Authorization Bearer tokens matching JWT pattern
- `_get_tech_filtered_urls()` casts tech_stack JSON to String for ILIKE matching

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_pipeline.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/base_tool.py tests/test_api_worker_pipeline.py
git commit -m "feat(api-worker): add ApiTestTool base class with API-specific helpers"
```

---

### Task 4: Create pipeline.py

**Files:**
- Create: `workers/api_worker/pipeline.py`
- Create: `workers/api_worker/tools/__init__.py` (empty initially)
- Modify: `tests/test_api_worker_pipeline.py`

**Step 1: Write the failing test**

Append to `tests/test_api_worker_pipeline.py`:

```python
@pytest.mark.anyio
async def test_pipeline_stages_defined():
    from workers.api_worker.pipeline import STAGES, STAGE_INDEX
    assert len(STAGES) == 4
    assert STAGES[0].name == "api_discovery"
    assert STAGES[1].name == "auth_testing"
    assert STAGES[2].name == "injection_testing"
    assert STAGES[3].name == "abuse_testing"
    assert "api_discovery" in STAGE_INDEX
    assert STAGE_INDEX["api_discovery"] == 0


@pytest.mark.anyio
async def test_pipeline_resumes_from_checkpoint():
    await _create_tables()
    from lib_webbh import Target, JobState, get_session
    from workers.api_worker.pipeline import Pipeline

    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        job = JobState(
            target_id=t.id, container_name="test-api",
            current_phase="api_discovery", status="COMPLETED",
        )
        session.add(job)
        await session.commit()
        tid = t.id

    pipeline = Pipeline(target_id=tid, container_name="test-api")
    phase = await pipeline._get_completed_phase()
    assert phase == "api_discovery"


@pytest.mark.anyio
async def test_pipeline_aggregate_results():
    from workers.api_worker.pipeline import Pipeline
    p = Pipeline(target_id=1, container_name="test")
    results = [
        {"found": 5, "in_scope": 3, "new": 2},
        {"found": 10, "in_scope": 8, "new": 6},
        ValueError("tool failed"),
    ]
    agg = p._aggregate_results("test_stage", results)
    assert agg["found"] == 15
    assert agg["in_scope"] == 11
    assert agg["new"] == 8
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api_worker_pipeline.py::test_pipeline_stages_defined -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Create pipeline.py and tools/__init__.py**

Create `workers/api_worker/tools/__init__.py` with empty `__all__ = []`.

Create `workers/api_worker/pipeline.py` following the vuln_scanner pipeline pattern. 4 stages defined with empty tool_classes lists (tools wired in later tasks). Same checkpointing logic: `_get_completed_phase()`, `_update_phase()`, `_mark_completed()`. Same `_run_stage()` with `asyncio.gather`. Same `_aggregate_results()` with exception handling.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_pipeline.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/pipeline.py workers/api_worker/tools/__init__.py tests/test_api_worker_pipeline.py
git commit -m "feat(api-worker): add 4-stage Pipeline with checkpointing"
```

---

### Task 5: Create main.py — queue listener

**Files:**
- Create: `workers/api_worker/main.py`
- Modify: `tests/test_api_worker_pipeline.py`

**Step 1: Write the failing test**

Append to `tests/test_api_worker_pipeline.py`:

```python
@pytest.mark.anyio
async def test_main_handle_message_creates_job_state():
    await _create_tables()
    from lib_webbh import Target, JobState, get_session
    from workers.api_worker.main import handle_message

    async with get_session() as session:
        t = Target(
            company_name="Acme", base_domain="acme.com",
            target_profile={"scope": ["*.acme.com"]},
        )
        session.add(t)
        await session.commit()
        tid = t.id

    with (
        patch("workers.api_worker.main.Pipeline") as MockPipeline,
        patch("workers.api_worker.main.get_container_name", return_value="test-api"),
    ):
        mock_pipeline = MagicMock()
        mock_pipeline.run = AsyncMock()
        MockPipeline.return_value = mock_pipeline

        await handle_message("msg-1", {"target_id": tid})

    async with get_session() as session:
        from sqlalchemy import select
        stmt = select(JobState).where(
            JobState.target_id == tid,
            JobState.container_name == "test-api",
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()
        assert job is not None


@pytest.mark.anyio
async def test_main_handle_message_skips_missing_target():
    await _create_tables()
    from workers.api_worker.main import handle_message

    # Should not raise — just logs error
    await handle_message("msg-2", {"target_id": 99999})
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api_worker_pipeline.py::test_main_handle_message_creates_job_state -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Create main.py**

Create `workers/api_worker/main.py` — identical pattern to `workers/vuln_scanner/main.py`. Queue: `api_queue`, group: `api_group`. Loads Target, builds ScopeManager, ensures JobState row, runs Pipeline with heartbeat.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_pipeline.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/main.py tests/test_api_worker_pipeline.py
git commit -m "feat(api-worker): add main.py queue listener entry point"
```

---

### Task 6: Stage 1 tools — FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool

**Files:**
- Create: `workers/api_worker/tools/ffuf_api_tool.py`
- Create: `workers/api_worker/tools/openapi_parser.py`
- Create: `workers/api_worker/tools/graphql_introspect.py`
- Create: `workers/api_worker/tools/trufflehog_tool.py`
- Modify: `workers/api_worker/tools/__init__.py`
- Modify: `workers/api_worker/pipeline.py` (wire Stage 1)
- Create: `tests/test_api_worker_tools.py`

**Step 1: Write the failing tests**

Create `tests/test_api_worker_tools.py`:

```python
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


# ---------------------------------------------------------------------------
# FfufApiTool tests
# ---------------------------------------------------------------------------

SAMPLE_FFUF_API_OUTPUT = json.dumps({
    "results": [
        {"url": "https://acme.com/api/v1/users", "status": 200, "length": 500},
        {"url": "https://acme.com/api/v1/admin", "status": 401, "length": 50},
        {"url": "https://acme.com/api/v1/health", "status": 200, "length": 20},
    ]
})


def test_ffuf_api_parse_output():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool
    tool = FfufApiTool()
    results = tool.parse_output(SAMPLE_FFUF_API_OUTPUT)
    assert len(results) == 3
    assert results[0]["url"] == "https://acme.com/api/v1/users"


def test_ffuf_api_build_command():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool
    tool = FfufApiTool()
    cmd = tool.build_command(
        url="https://acme.com/api/FUZZ",
        wordlist="/app/wordlists/api-endpoints.txt",
        rate_limit=50,
        method="GET",
        headers={"Authorization": "Bearer tok"},
        output_file="/tmp/ffuf.json",
    )
    assert "ffuf" in cmd
    assert "-X" in cmd
    assert "GET" in cmd
    assert "-H" in cmd


@pytest.mark.anyio
async def test_ffuf_api_skips_on_cooldown():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool
    tool = FfufApiTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# OpenapiParserTool tests
# ---------------------------------------------------------------------------

SAMPLE_OPENAPI_SPEC = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0"},
    "paths": {
        "/api/v1/users": {
            "get": {
                "parameters": [
                    {"name": "page", "in": "query"},
                    {"name": "limit", "in": "query"},
                ]
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string"},
                                }
                            }
                        }
                    }
                }
            },
        },
        "/api/v1/users/{id}": {
            "get": {},
            "delete": {},
        },
    },
})


def test_openapi_parser_extracts_endpoints():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool
    tool = OpenapiParserTool()
    endpoints = tool.parse_spec(json.loads(SAMPLE_OPENAPI_SPEC))
    assert len(endpoints) == 4
    methods = {(e["method"], e["path"]) for e in endpoints}
    assert ("GET", "/api/v1/users") in methods
    assert ("POST", "/api/v1/users") in methods
    assert ("GET", "/api/v1/users/{id}") in methods
    assert ("DELETE", "/api/v1/users/{id}") in methods


def test_openapi_parser_extracts_params():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool
    tool = OpenapiParserTool()
    endpoints = tool.parse_spec(json.loads(SAMPLE_OPENAPI_SPEC))
    get_users = [e for e in endpoints if e["method"] == "GET" and e["path"] == "/api/v1/users"][0]
    assert "page" in str(get_users.get("params", {}))


@pytest.mark.anyio
async def test_openapi_parser_skips_on_cooldown():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool
    tool = OpenapiParserTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# GraphqlIntrospectTool tests
# ---------------------------------------------------------------------------

SAMPLE_INTROSPECTION_RESPONSE = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {"name": "users", "args": [{"name": "limit"}]},
                        {"name": "user", "args": [{"name": "id"}]},
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {"name": "createUser", "args": [{"name": "input"}]},
                        {"name": "deleteUser", "args": [{"name": "id"}]},
                    ],
                },
            ],
        }
    }
})


def test_graphql_introspect_parses_schema():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool
    tool = GraphqlIntrospectTool()
    data = json.loads(SAMPLE_INTROSPECTION_RESPONSE)
    endpoints = tool.parse_introspection(data)
    assert len(endpoints) >= 4
    names = {e["path"] for e in endpoints}
    assert "query:users" in names
    assert "mutation:createUser" in names


@pytest.mark.anyio
async def test_graphql_introspect_skips_on_cooldown():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool
    tool = GraphqlIntrospectTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# TrufflehogTool tests
# ---------------------------------------------------------------------------

SAMPLE_TRUFFLEHOG_OUTPUT = "\n".join([
    json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": "/tmp/swagger.json"}}},
                "DetectorName": "AWS", "Raw": "AKIAIOSFODNN7EXAMPLE", "Verified": True}),
    json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": "/tmp/swagger.json"}}},
                "DetectorName": "Generic", "Raw": "sk_live_abc123", "Verified": False}),
])


def test_trufflehog_parse_output():
    from workers.api_worker.tools.trufflehog_tool import TrufflehogTool
    tool = TrufflehogTool()
    findings = tool.parse_output(SAMPLE_TRUFFLEHOG_OUTPUT)
    assert len(findings) == 2
    assert findings[0]["detector"] == "AWS"
    assert findings[0]["verified"] is True


@pytest.mark.anyio
async def test_trufflehog_skips_on_cooldown():
    from workers.api_worker.tools.trufflehog_tool import TrufflehogTool
    tool = TrufflehogTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_worker_tools.py::test_ffuf_api_parse_output -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Implement all 4 Stage 1 tools**

Each tool extends `ApiTestTool`, sets `name` and `weight_class`, implements `execute()`.

**FfufApiTool** (`workers/api_worker/tools/ffuf_api_tool.py`): Weight HEAVY. `build_command()` generates ffuf CLI args with `-X` for method cycling, API content-type headers, JSON output. `parse_output()` reads ffuf JSON results. `execute()` loops through API root URLs from `_get_api_urls()`, runs ffuf per root with methods GET/POST/PUT/DELETE, saves routes to `api_schemas`, flags 401/403 as `auth_required=True`.

**OpenapiParserTool** (`workers/api_worker/tools/openapi_parser.py`): Weight LIGHT. Pure Python (httpx, no subprocess). `parse_spec()` handles OpenAPI 3.0 and Swagger 2.0 specs — extracts paths, methods, query params, body params, content types. `execute()` fetches common spec paths (`/swagger.json`, `/openapi.yaml`, `/api-docs`, `/swagger/v1/swagger.json`, `/v2/api-docs`) via httpx, parses successful responses, saves downloaded specs to `/tmp/api-specs/` for TruffleHog, bulk inserts into `api_schemas` with `spec_type='openapi'`.

**GraphqlIntrospectTool** (`workers/api_worker/tools/graphql_introspect.py`): Weight LIGHT. Pure Python (httpx). `parse_introspection()` extracts queries, mutations, types from `__schema` response. Returns list of dicts with `path` (format: `query:<name>` or `mutation:<name>`), `method` (QUERY/MUTATION), and `params` (args list). `execute()` sends full introspection query to common GraphQL paths, saves to `api_schemas` with `spec_type='graphql'`.

**TrufflehogTool** (`workers/api_worker/tools/trufflehog_tool.py`): Weight LIGHT. Wraps `trufflehog filesystem /tmp/api-specs/ --json`. `parse_output()` reads JSON-lines, extracts detector name, raw secret, verified status, source file. `execute()` runs subprocess, iterates findings — verified → severity critical, unverified → severity medium. Each finding → `_save_vulnerability()`.

Update `workers/api_worker/tools/__init__.py` with imports and `__all__`.
Update `workers/api_worker/pipeline.py` Stage 1 tool_classes list.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_tools.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/tools/ workers/api_worker/pipeline.py tests/test_api_worker_tools.py
git commit -m "feat(api-worker): add Stage 1 tools — ffuf_api, openapi_parser, graphql_introspect, trufflehog"
```

---

### Task 7: Stage 2 tools — JwtTool, OauthTesterTool, CorsScannerTool

**Files:**
- Create: `workers/api_worker/tools/jwt_tool.py`
- Create: `workers/api_worker/tools/oauth_tester.py`
- Create: `workers/api_worker/tools/cors_scanner.py`
- Modify: `workers/api_worker/tools/__init__.py`
- Modify: `workers/api_worker/pipeline.py` (wire Stage 2)
- Modify: `tests/test_api_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_api_worker_tools.py`:

```python
# ---------------------------------------------------------------------------
# JwtTool tests
# ---------------------------------------------------------------------------

SAMPLE_JWT_TOOL_OUTPUT = """
[+] Algorithm confusion vulnerability found!
[+] Token accepted with "none" algorithm
[+] kid path traversal accepted: ../../../../dev/null
"""


def test_jwt_tool_parse_output():
    from workers.api_worker.tools.jwt_tool import JwtTool
    tool = JwtTool()
    findings = tool.parse_output(SAMPLE_JWT_TOOL_OUTPUT)
    assert len(findings) >= 2
    assert any("none" in f.lower() for f in findings)


def test_jwt_tool_build_command():
    from workers.api_worker.tools.jwt_tool import JwtTool
    tool = JwtTool()
    cmd = tool.build_command(
        token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        mode="at",
    )
    assert "python3" in cmd or "jwt_tool" in " ".join(cmd)
    assert "-t" in cmd


@pytest.mark.anyio
async def test_jwt_tool_skips_on_cooldown():
    from workers.api_worker.tools.jwt_tool import JwtTool
    tool = JwtTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# OauthTesterTool tests
# ---------------------------------------------------------------------------

def test_oauth_tester_generates_redirect_variants():
    from workers.api_worker.tools.oauth_tester import OauthTesterTool
    tool = OauthTesterTool()
    variants = tool.generate_redirect_uri_variants("https://acme.com/callback")
    assert any("attacker.com" in v for v in variants)
    assert any("/../" in v for v in variants)
    assert len(variants) >= 3


@pytest.mark.anyio
async def test_oauth_tester_skips_on_cooldown():
    from workers.api_worker.tools.oauth_tester import OauthTesterTool
    tool = OauthTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# CorsScannerTool tests
# ---------------------------------------------------------------------------

SAMPLE_CORSCANNER_OUTPUT = json.dumps({
    "results": [
        {"url": "https://acme.com/api/v1/users", "type": "reflect_origin",
         "origin": "https://evil.com", "credentials": True},
        {"url": "https://acme.com/api/v1/data", "type": "null_origin",
         "origin": "null", "credentials": False},
    ]
})


def test_cors_scanner_parse_output():
    from workers.api_worker.tools.cors_scanner import CorsScannerTool
    tool = CorsScannerTool()
    findings = tool.parse_output(SAMPLE_CORSCANNER_OUTPUT)
    assert len(findings) == 2
    assert findings[0]["type"] == "reflect_origin"


@pytest.mark.anyio
async def test_cors_scanner_skips_on_cooldown():
    from workers.api_worker.tools.cors_scanner import CorsScannerTool
    tool = CorsScannerTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_worker_tools.py::test_jwt_tool_parse_output -v`
Expected: FAIL

**Step 3: Implement all 3 Stage 2 tools**

**JwtTool** (`workers/api_worker/tools/jwt_tool.py`): Weight HEAVY. Wraps `/opt/jwt_tool/jwt_tool.py`. `build_command(token, mode)` generates: `["python3", "/opt/jwt_tool/jwt_tool.py", "-t", token, "-M", mode]`. `parse_output(stdout)` extracts lines containing `[+]` vulnerability indicators. `execute()` queries `_get_jwt_tokens()`, runs jwt_tool in multiple modes: `at` (all tests), `pb` (playbook scan). Each finding line → `_save_vulnerability()`.

**OauthTesterTool** (`workers/api_worker/tools/oauth_tester.py`): Weight LIGHT. Pure httpx. `generate_redirect_uri_variants(callback_url)` returns list of bypass attempts: attacker domain substitution, path traversal, scheme downgrade, subdomain tricks, open redirect chain. `execute()` queries `_get_oauth_urls()`, for each endpoint tests: (1) state CSRF — send request without state param, (2) redirect_uri bypass — try each variant, (3) scope escalation — request admin/write/* scopes, (4) PKCE downgrade — omit code_challenge. Each confirmed finding → `_save_vulnerability()`.

**CorsScannerTool** (`workers/api_worker/tools/cors_scanner.py`): Weight LIGHT. Wraps `/opt/CORScanner/cors_scan.py`. Writes target URLs to a temp file, runs `python3 /opt/CORScanner/cors_scan.py -i <file> -o /tmp/cors-out.json`. `parse_output(raw)` reads JSON results. `execute()` queries `_get_api_urls()`, runs CORScanner, each misconfiguration → `_save_vulnerability()` (severity high for credential leakage, medium for others).

Update `__init__.py` and `pipeline.py` Stage 2.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_tools.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/tools/ workers/api_worker/pipeline.py tests/test_api_worker_tools.py
git commit -m "feat(api-worker): add Stage 2 tools — jwt_tool, oauth_tester, cors_scanner"
```

---

### Task 8: Stage 3 tools — IdorTesterTool, MassAssignTesterTool, NosqlmapTool

**Files:**
- Create: `workers/api_worker/tools/idor_tester.py`
- Create: `workers/api_worker/tools/mass_assign_tester.py`
- Create: `workers/api_worker/tools/nosqlmap_tool.py`
- Modify: `workers/api_worker/tools/__init__.py`
- Modify: `workers/api_worker/pipeline.py` (wire Stage 3)
- Modify: `tests/test_api_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_api_worker_tools.py`:

```python
# ---------------------------------------------------------------------------
# IdorTesterTool tests
# ---------------------------------------------------------------------------

def test_idor_tester_detects_path_params():
    from workers.api_worker.tools.idor_tester import IdorTesterTool
    tool = IdorTesterTool()
    assert tool.has_path_params("/api/v1/users/:id") is True
    assert tool.has_path_params("/api/v1/users/{userId}") is True
    assert tool.has_path_params("/api/v1/users") is False


def test_idor_tester_generates_test_ids():
    from workers.api_worker.tools.idor_tester import IdorTesterTool
    tool = IdorTesterTool()
    ids = tool.generate_test_ids()
    assert 1 in ids
    assert len(ids) >= 5


@pytest.mark.anyio
async def test_idor_tester_skips_on_cooldown():
    from workers.api_worker.tools.idor_tester import IdorTesterTool
    tool = IdorTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# MassAssignTesterTool tests
# ---------------------------------------------------------------------------

def test_mass_assign_sensitive_fields():
    from workers.api_worker.tools.mass_assign_tester import SENSITIVE_FIELDS
    assert "role" in SENSITIVE_FIELDS
    assert "is_admin" in SENSITIVE_FIELDS
    assert "permissions" in SENSITIVE_FIELDS
    assert "balance" in SENSITIVE_FIELDS


def test_mass_assign_severity_for_field():
    from workers.api_worker.tools.mass_assign_tester import MassAssignTesterTool
    tool = MassAssignTesterTool()
    assert tool.severity_for_field("role") == "critical"
    assert tool.severity_for_field("is_admin") == "critical"
    assert tool.severity_for_field("balance") == "high"
    assert tool.severity_for_field("verified") == "high"


@pytest.mark.anyio
async def test_mass_assign_skips_on_cooldown():
    from workers.api_worker.tools.mass_assign_tester import MassAssignTesterTool
    tool = MassAssignTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# NosqlmapTool tests
# ---------------------------------------------------------------------------

SAMPLE_NOSQLMAP_OUTPUT = """
[+] MongoDB detected
[+] $ne injection successful on parameter: username
[+] Authentication bypass confirmed
"""


def test_nosqlmap_parse_output():
    from workers.api_worker.tools.nosqlmap_tool import NosqlmapTool
    tool = NosqlmapTool()
    findings = tool.parse_output(SAMPLE_NOSQLMAP_OUTPUT)
    assert len(findings) >= 2
    assert any("injection" in f.lower() for f in findings)


@pytest.mark.anyio
async def test_nosqlmap_skips_on_cooldown():
    from workers.api_worker.tools.nosqlmap_tool import NosqlmapTool
    tool = NosqlmapTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_worker_tools.py::test_idor_tester_detects_path_params -v`
Expected: FAIL

**Step 3: Implement all 3 Stage 3 tools**

**IdorTesterTool** (`workers/api_worker/tools/idor_tester.py`): Weight HEAVY. Pure httpx. `has_path_params(path)` checks for `/:param` or `/{param}` patterns via `PATH_PARAM_RE`. `generate_test_ids()` returns list: [1, 2, 3, 5, 10, 100, 0, -1] plus UUID variants. `execute()` queries `_get_api_schemas()`, filters for endpoints with path params, substitutes test IDs, compares responses. If `target_profile.auth_tokens` has user_a/user_b, tests cross-user access. Response difference (status code change or >50% body length change) = finding. Severity: high (horizontal), critical (vertical).

**MassAssignTesterTool** (`workers/api_worker/tools/mass_assign_tester.py`): Weight LIGHT. Pure httpx. `SENSITIVE_FIELDS` dict maps field names to severity: `role`/`is_admin`/`permissions` → critical, `balance`/`verified`/`email_confirmed`/`active`/`plan` → high. `severity_for_field(field)` returns the severity. `execute()` queries `_get_api_schemas()` for POST/PUT/PATCH endpoints, GETs current resource, attempts to set each sensitive field, GETs again to verify. Each stuck change → `_save_vulnerability()`.

**NosqlmapTool** (`workers/api_worker/tools/nosqlmap_tool.py`): Weight HEAVY. Wraps `/opt/nosqlmap/nosqlmap.py`. `parse_output(stdout)` extracts `[+]` lines containing injection/bypass indicators. `execute()` queries `_get_tech_filtered_urls(target_id, ["mongodb", "couchdb", "express", "node"])`, runs nosqlmap against each URL, parses output. Each finding → `_save_vulnerability()` with severity high.

Update `__init__.py` and `pipeline.py` Stage 3.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_tools.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/tools/ workers/api_worker/pipeline.py tests/test_api_worker_tools.py
git commit -m "feat(api-worker): add Stage 3 tools — idor_tester, mass_assign_tester, nosqlmap"
```

---

### Task 9: Stage 4 tools — RateLimitTesterTool, GraphqlCopTool

**Files:**
- Create: `workers/api_worker/tools/rate_limit_tester.py`
- Create: `workers/api_worker/tools/graphql_cop_tool.py`
- Modify: `workers/api_worker/tools/__init__.py`
- Modify: `workers/api_worker/pipeline.py` (wire Stage 4)
- Modify: `tests/test_api_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_api_worker_tools.py`:

```python
# ---------------------------------------------------------------------------
# RateLimitTesterTool tests
# ---------------------------------------------------------------------------

def test_rate_limit_tester_identifies_sensitive_endpoints():
    from workers.api_worker.tools.rate_limit_tester import RateLimitTesterTool
    tool = RateLimitTesterTool()
    assert tool.is_sensitive_endpoint("/api/v1/login") is True
    assert tool.is_sensitive_endpoint("/api/v1/reset-password") is True
    assert tool.is_sensitive_endpoint("/api/v1/otp/verify") is True
    assert tool.is_sensitive_endpoint("/api/v1/users") is False


def test_rate_limit_tester_respects_oos():
    from workers.api_worker.tools.rate_limit_tester import RateLimitTesterTool
    tool = RateLimitTesterTool()
    assert tool.should_skip_dos(["No DoS"]) is True
    assert tool.should_skip_dos(["No Brute Force"]) is False
    assert tool.should_skip_dos([]) is False


@pytest.mark.anyio
async def test_rate_limit_tester_skips_on_cooldown():
    from workers.api_worker.tools.rate_limit_tester import RateLimitTesterTool
    tool = RateLimitTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# GraphqlCopTool tests
# ---------------------------------------------------------------------------

SAMPLE_GRAPHQLCOP_OUTPUT = json.dumps([
    {"title": "Introspection Enabled", "severity": "LOW", "description": "Introspection is enabled"},
    {"title": "Batch Query Attack", "severity": "HIGH", "description": "Batch queries are allowed without limit"},
    {"title": "Field Suggestions", "severity": "INFO", "description": "Field suggestions expose schema"},
])


def test_graphql_cop_parse_output():
    from workers.api_worker.tools.graphql_cop_tool import GraphqlCopTool
    tool = GraphqlCopTool()
    findings = tool.parse_output(SAMPLE_GRAPHQLCOP_OUTPUT)
    assert len(findings) == 3
    assert findings[0]["title"] == "Introspection Enabled"


def test_graphql_cop_severity_mapping():
    from workers.api_worker.tools.graphql_cop_tool import GraphqlCopTool
    tool = GraphqlCopTool()
    assert tool.map_severity("HIGH") == "high"
    assert tool.map_severity("LOW") == "low"
    assert tool.map_severity("INFO") == "info"
    assert tool.map_severity("MEDIUM") == "medium"


@pytest.mark.anyio
async def test_graphql_cop_skips_on_cooldown():
    from workers.api_worker.tools.graphql_cop_tool import GraphqlCopTool
    tool = GraphqlCopTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_worker_tools.py::test_rate_limit_tester_identifies_sensitive_endpoints -v`
Expected: FAIL

**Step 3: Implement both Stage 4 tools**

**RateLimitTesterTool** (`workers/api_worker/tools/rate_limit_tester.py`): Weight LIGHT. Pure httpx. `SENSITIVE_PATTERNS` list: login, reset, otp, register, transfer, payment, verify. `is_sensitive_endpoint(path)` checks if any pattern appears in the path. `should_skip_dos(oos_attacks)` returns True if "No DoS" in the list. `execute()` reads `_get_api_schemas()`, filters sensitive endpoints, fires burst of N requests via `asyncio.gather` (N from `target_profile.get("rate_limit_burst", 50)`). Checks for any 429 response or Retry-After header. No rate limiting detected → `_save_vulnerability()` with severity medium.

**GraphqlCopTool** (`workers/api_worker/tools/graphql_cop_tool.py`): Weight LIGHT. Wraps `python3 /opt/graphql-cop/graphql-cop.py -t <url> -o json`. `parse_output(raw)` loads JSON array of findings. `map_severity(cop_sev)` maps: HIGH→high, MEDIUM→medium, LOW→low, INFO→info. `execute()` queries `_get_api_schemas()` for `spec_type='graphql'`, runs graphql-cop per endpoint, each finding → `_save_vulnerability()`.

Update `__init__.py` and `pipeline.py` Stage 4.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_worker_tools.py -v`
Expected: ALL PASS

**Step 5: Commit**

```
git add workers/api_worker/tools/ workers/api_worker/pipeline.py tests/test_api_worker_tools.py
git commit -m "feat(api-worker): add Stage 4 tools — rate_limit_tester, graphql_cop"
```

---

### Task 10: Create Dockerfile.api

**Files:**
- Create: `docker/Dockerfile.api`

**Step 1: Write the Dockerfile**

Multi-stage build. Stage 1: Go builder (ffuf + trufflehog binary download). Stage 2: Python pip builder (httpx[http2]). Stage 3: Runtime — system packages (gcc, libpq-dev, git, wget), Go binaries from builder, Python packages from builder, git-clone security tools (jwt_tool, nosqlmap, CORScanner, graphql-cop, inql), install their requirements.txt, create symlinks, download SecLists API wordlists, install lib_webbh, copy worker source, verify import chain, set entrypoint.

See design doc Dockerfile section for exact commands.

**Step 2: Verify the Dockerfile builds** (optional, requires Docker)

Run: `docker build -f docker/Dockerfile.api -t webbh-api-worker .`

**Step 3: Commit**

```
git add docker/Dockerfile.api
git commit -m "feat(api-worker): add Dockerfile.api with all tool dependencies"
```

---

### Task 11: Final integration test and pipeline wiring verification

**Files:**
- Modify: `tests/test_api_worker_pipeline.py`

**Step 1: Write integration test**

Append to `tests/test_api_worker_pipeline.py`:

```python
@pytest.mark.anyio
async def test_pipeline_all_tools_wired():
    """Verify all 12 tools are registered in their correct stages."""
    from workers.api_worker.pipeline import STAGES

    stage_names = {s.name: [cls.name for cls in s.tool_classes] for s in STAGES}

    # Stage 1: api_discovery
    assert "ffuf_api" in stage_names["api_discovery"]
    assert "openapi_parser" in stage_names["api_discovery"]
    assert "graphql_introspect" in stage_names["api_discovery"]
    assert "trufflehog" in stage_names["api_discovery"]

    # Stage 2: auth_testing
    assert "jwt_tool" in stage_names["auth_testing"]
    assert "oauth_tester" in stage_names["auth_testing"]
    assert "cors_scanner" in stage_names["auth_testing"]

    # Stage 3: injection_testing
    assert "idor_tester" in stage_names["injection_testing"]
    assert "mass_assign_tester" in stage_names["injection_testing"]
    assert "nosqlmap" in stage_names["injection_testing"]

    # Stage 4: abuse_testing
    assert "rate_limit_tester" in stage_names["abuse_testing"]
    assert "graphql_cop" in stage_names["abuse_testing"]


@pytest.mark.anyio
async def test_pipeline_tool_count():
    from workers.api_worker.pipeline import STAGES
    total = sum(len(s.tool_classes) for s in STAGES)
    assert total == 12


@pytest.mark.anyio
async def test_all_tools_importable():
    from workers.api_worker.tools import (
        FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool,
        JwtTool, OauthTesterTool, CorsScannerTool,
        IdorTesterTool, MassAssignTesterTool, NosqlmapTool,
        RateLimitTesterTool, GraphqlCopTool,
    )
    tools = [
        FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool,
        JwtTool, OauthTesterTool, CorsScannerTool,
        IdorTesterTool, MassAssignTesterTool, NosqlmapTool,
        RateLimitTesterTool, GraphqlCopTool,
    ]
    for tool_cls in tools:
        t = tool_cls()
        assert hasattr(t, "name")
        assert hasattr(t, "weight_class")
        assert hasattr(t, "execute")
```

**Step 2: Run all tests**

Run: `python -m pytest tests/test_api_worker_pipeline.py tests/test_api_worker_tools.py -v`
Expected: ALL PASS

**Step 3: Run full test suite to check for regressions**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — no regressions in existing workers

**Step 4: Commit**

```
git add tests/test_api_worker_pipeline.py
git commit -m "test(api-worker): add integration tests verifying all 12 tools wired"
```
