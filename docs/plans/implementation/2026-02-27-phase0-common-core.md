# Phase 0: Common Core & Library Setup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `lib_webbh` shared Python library that all WebAppBH containers depend on — database models, Redis messaging, scope checking, and structured logging.

**Architecture:** A pip-installable Python package at `shared/lib_webbh/` with async-first database access (asyncpg), Redis Streams messaging, tldextract-based scope checking, and stdlib JSON logging. A base Dockerfile pre-installs everything for downstream containers.

**Tech Stack:** Python 3.10, SQLAlchemy 2.0 (async), asyncpg, redis-py (async + hiredis), Pydantic, netaddr, tldextract, pytest + pytest-asyncio

**Design Doc:** `docs/plans/design/2026-02-27-phase0-common-core-design.md`

---

### Task 1: Project Scaffolding & Package Setup

**Files:**
- Create: `shared/lib_webbh/setup.py`
- Create: `shared/lib_webbh/__init__.py` (empty placeholder)
- Create: `shared/lib_webbh/database.py` (empty placeholder)
- Create: `shared/lib_webbh/scope.py` (empty placeholder)
- Create: `shared/lib_webbh/messaging.py` (empty placeholder)
- Create: `shared/lib_webbh/logger.py` (empty placeholder)
- Create: `tests/conftest.py`
- Create: `tests/__init__.py`
- Create: `.gitignore`

**Step 1: Create directory structure**

```bash
mkdir -p shared/lib_webbh tests
```

**Step 2: Write `setup.py`**

```python
from setuptools import setup, find_packages

setup(
    name="lib_webbh",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "sqlalchemy[asyncio]>=2.0",
        "asyncpg>=0.29",
        "redis[hiredis]>=5.0",
        "pydantic>=2.0",
        "netaddr>=0.10",
        "tldextract>=5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
            "aiosqlite>=0.20",
        ],
    },
)
```

**Step 3: Create empty module files**

Create `__init__.py`, `database.py`, `scope.py`, `messaging.py`, `logger.py` as empty files.

**Step 4: Write `.gitignore`**

```
__pycache__/
*.pyc
*.egg-info/
.env
*.log
.pytest_cache/
dist/
build/
```

**Step 5: Write `tests/conftest.py`**

```python
import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"
```

**Step 6: Create `tests/__init__.py`**

Empty file.

**Step 7: Install the package in editable mode**

```bash
cd shared/lib_webbh && pip install -e ".[dev]"
```

**Step 8: Verify install**

```bash
python -c "import lib_webbh; print('OK')"
```

Expected: `OK`

**Step 9: Initialize git and commit**

```bash
git init
git add shared/ tests/ .gitignore
git commit -m "chore: scaffold lib_webbh package structure"
```

---

### Task 2: Logger Module

**Files:**
- Create: `shared/lib_webbh/logger.py`
- Create: `tests/test_logger.py`

**Step 1: Write the failing test**

```python
# tests/test_logger.py
import json
import logging
import os
import tempfile

from lib_webbh.logger import setup_logger


def test_setup_logger_returns_bound_logger():
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-worker", log_dir=tmpdir)
        assert log is not None
        assert hasattr(log, "bind")


def test_json_format_to_stdout(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-stdout", log_dir=tmpdir)
        log.info("hello world")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["message"] == "hello world"
        assert record["level"] == "INFO"
        assert record["logger"] == "test-stdout"
        assert "timestamp" in record


def test_json_format_includes_extra(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-extra", log_dir=tmpdir)
        log.info("found asset", extra={"asset_type": "subdomain", "asset": "api.example.com"})
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["extra"]["asset_type"] == "subdomain"
        assert record["extra"]["asset"] == "api.example.com"


def test_bind_injects_context(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-bind", log_dir=tmpdir)
        bound = log.bind(target_id=42, asset_type="ipv4")
        bound.info("scanning")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["target_id"] == 42
        assert record["extra"]["asset_type"] == "ipv4"


def test_log_writes_to_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-file", log_dir=tmpdir)
        log.info("file entry")
        log_path = os.path.join(tmpdir, "test-file.log")
        assert os.path.exists(log_path)
        with open(log_path) as f:
            record = json.loads(f.readline().strip())
        assert record["message"] == "file entry"


def test_bind_extra_override(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-override", log_dir=tmpdir)
        bound = log.bind(asset_type="domain")
        bound.info("override test", extra={"asset_type": "subdomain"})
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["extra"]["asset_type"] == "subdomain"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_logger.py -v
```

Expected: FAIL — `setup_logger` not defined.

**Step 3: Implement `logger.py`**

```python
# shared/lib_webbh/logger.py
from __future__ import annotations

import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "container": os.environ.get("HOSTNAME", "unknown"),
        }

        # Inject bound context (target_id, etc.)
        bound_ctx = getattr(record, "_bound_context", {})
        for key in ("target_id",):
            if key in bound_ctx:
                log_entry[key] = bound_ctx[key]

        # Build extra — merge bound asset_type + call-site extra
        extra: dict[str, Any] = {}
        if "asset_type" in bound_ctx:
            extra["asset_type"] = bound_ctx["asset_type"]

        # Call-site extra keys (skip internal logging keys)
        _internal = {
            "message", "args", "exc_info", "exc_text", "stack_info",
            "_bound_context",
        }
        for key, val in record.__dict__.items():
            if key.startswith("_") and key != "_bound_context":
                continue
            if key in _internal or key in logging.LogRecord(
                "", 0, "", 0, "", (), None
            ).__dict__:
                continue
            extra[key] = val

        if extra:
            log_entry["extra"] = extra

        return json.dumps(log_entry, default=str)


class BoundLogger:
    def __init__(self, logger: logging.Logger, context: dict[str, Any] | None = None):
        self._logger = logger
        self._context = context or {}

    def bind(self, **kwargs: Any) -> BoundLogger:
        new_ctx = {**self._context, **kwargs}
        return BoundLogger(self._logger, new_ctx)

    def _log(self, level: int, msg: str, extra: dict[str, Any] | None = None) -> None:
        merged_extra = {**self._context}
        if extra:
            merged_extra.update(extra)
        record_extra = {"_bound_context": self._context}
        if extra:
            record_extra.update(extra)
        self._logger.log(level, msg, extra=record_extra)

    def debug(self, msg: str, extra: dict[str, Any] | None = None) -> None:
        self._log(logging.DEBUG, msg, extra)

    def info(self, msg: str, extra: dict[str, Any] | None = None) -> None:
        self._log(logging.INFO, msg, extra)

    def warning(self, msg: str, extra: dict[str, Any] | None = None) -> None:
        self._log(logging.WARNING, msg, extra)

    def error(self, msg: str, extra: dict[str, Any] | None = None) -> None:
        self._log(logging.ERROR, msg, extra)

    def critical(self, msg: str, extra: dict[str, Any] | None = None) -> None:
        self._log(logging.CRITICAL, msg, extra)


def setup_logger(
    name: str,
    log_dir: str = "/app/shared/logs/",
) -> BoundLogger:
    logger = logging.getLogger(f"webbh.{name}")
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        return BoundLogger(logger)

    formatter = JsonFormatter()

    # STDOUT handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # File handler
    os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, f"{name}.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return BoundLogger(logger)
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_logger.py -v
```

Expected: All 6 tests PASS.

**Step 5: Commit**

```bash
git add shared/lib_webbh/logger.py tests/test_logger.py
git commit -m "feat: add structured JSON logger with bind() context"
```

---

### Task 3: Database Module — Engine Singleton

**Files:**
- Create: `shared/lib_webbh/database.py`
- Create: `tests/test_database.py`

**Step 1: Write the failing tests for engine singleton**

```python
# tests/test_database.py
import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

# Use aiosqlite for testing (no Postgres needed)
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from lib_webbh.database import get_engine, get_session, Base


def test_get_engine_returns_async_engine():
    engine = get_engine()
    assert isinstance(engine, AsyncEngine)


def test_get_engine_is_singleton():
    e1 = get_engine()
    e2 = get_engine()
    assert e1 is e2


@pytest.mark.asyncio
async def test_get_session_returns_async_session():
    async with get_session() as session:
        assert isinstance(session, AsyncSession)


@pytest.mark.asyncio
async def test_create_all_tables():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # If no exception, tables created successfully
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_database.py -v
```

Expected: FAIL — `get_engine` not defined.

**Step 3: Implement engine singleton in `database.py`**

```python
# shared/lib_webbh/database.py
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from sqlalchemy import func
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Engine Singleton
# ---------------------------------------------------------------------------

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_url() -> str:
    driver = os.environ.get("DB_DRIVER", "postgresql+asyncpg")
    if driver.startswith("sqlite"):
        db_name = os.environ.get("DB_NAME", ":memory:")
        return f"{driver}:///{db_name}"
    user = os.environ.get("DB_USER", "webbh_admin")
    password = os.environ.get("DB_PASS", "")
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    db_name = os.environ.get("DB_NAME", "webbh")
    return f"{driver}://{user}:{password}@{host}:{port}/{db_name}"


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        driver = os.environ.get("DB_DRIVER", "postgresql+asyncpg")
        kwargs = {}
        if not driver.startswith("sqlite"):
            kwargs.update(pool_size=10, max_overflow=20, pool_recycle=3600)
        _engine = create_async_engine(_build_url(), **kwargs)
    return _engine


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    async with _session_factory() as session:
        yield session


# ---------------------------------------------------------------------------
# Base & Mixins
# ---------------------------------------------------------------------------


class Base(AsyncAttrs, DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
    )
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_database.py -v
```

Expected: All 4 tests PASS.

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database.py
git commit -m "feat: add async database engine singleton with Base and TimestampMixin"
```

---

### Task 4: Database Module — OAM Models (10 Tables)

**Files:**
- Modify: `shared/lib_webbh/database.py` (append models after Base)
- Modify: `tests/test_database.py` (add model tests)

**Step 1: Write the failing tests for models**

Append to `tests/test_database.py`:

```python
from lib_webbh.database import (
    Target, Asset, Identity, Location, Observation,
    CloudAsset, Parameter, Vulnerability, JobState, Alert,
)


@pytest.mark.asyncio
async def test_insert_target_and_asset():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        target = Target(company_name="TestCorp", base_domain="testcorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        asset = Asset(
            target_id=target.id,
            asset_type="subdomain",
            asset_value="api.testcorp.com",
            source_tool="amass",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        assert target.id is not None
        assert asset.target_id == target.id
        assert asset.asset_value == "api.testcorp.com"


@pytest.mark.asyncio
async def test_insert_location_linked_to_asset():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        target = Target(company_name="LocCorp", base_domain="loccorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        asset = Asset(
            target_id=target.id,
            asset_type="ip",
            asset_value="10.0.0.1",
            source_tool="nmap",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id,
            port=443,
            protocol="tcp",
            service="https",
            state="open",
        )
        session.add(loc)
        await session.commit()
        await session.refresh(loc)

        assert loc.asset_id == asset.id
        assert loc.port == 443


@pytest.mark.asyncio
async def test_insert_vulnerability_with_severity():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        target = Target(company_name="VulnCorp", base_domain="vulncorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        asset = Asset(
            target_id=target.id,
            asset_type="subdomain",
            asset_value="admin.vulncorp.com",
            source_tool="subfinder",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        vuln = Vulnerability(
            target_id=target.id,
            asset_id=asset.id,
            severity="critical",
            title="SQL Injection",
            description="Login form param 'user' is injectable",
            poc="sqlmap -u 'https://admin.vulncorp.com/login?user=test'",
            source_tool="sqlmap",
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)

        assert vuln.severity == "critical"
        assert vuln.target_id == target.id


@pytest.mark.asyncio
async def test_job_state_status_values():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        target = Target(company_name="JobCorp", base_domain="jobcorp.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)

        job = JobState(
            target_id=target.id,
            container_name="recon-core-01",
            current_phase="recon",
            status="RUNNING",
            last_tool_executed="amass",
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)

        assert job.status == "RUNNING"
        assert job.container_name == "recon-core-01"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_database.py -v
```

Expected: FAIL — model classes not defined.

**Step 3: Implement all 10 models**

Append to `shared/lib_webbh/database.py` after `TimestampMixin`:

```python
import enum
from typing import Optional

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import JSON


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Target(TimestampMixin, Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_name: Mapped[str] = mapped_column(String(255))
    base_domain: Mapped[str] = mapped_column(String(255))
    target_profile: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    asset_type: Mapped[str] = mapped_column(String(50))  # subdomain, ip, cidr
    asset_value: Mapped[str] = mapped_column(String(500))
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class Identity(TimestampMixin, Base):
    __tablename__ = "identities"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    asn: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    whois_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class Location(TimestampMixin, Base):
    __tablename__ = "locations"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)


class Observation(TimestampMixin, Base):
    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    tech_stack: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    page_title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class CloudAsset(TimestampMixin, Base):
    __tablename__ = "cloud_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    provider: Mapped[str] = mapped_column(String(20))  # aws, azure, gcp
    asset_type: Mapped[str] = mapped_column(String(100))  # bucket, function, storage
    url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    findings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class Parameter(TimestampMixin, Base):
    __tablename__ = "parameters"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    param_name: Mapped[str] = mapped_column(String(255))
    param_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("assets.id"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(20))  # critical, high, medium, low, info
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    poc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class JobState(TimestampMixin, Base):
    __tablename__ = "job_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    container_name: Mapped[str] = mapped_column(String(255))
    current_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20))  # RUNNING, COMPLETED, QUEUED, FAILED
    last_seen: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    last_tool_executed: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    vulnerability_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("vulnerabilities.id"), nullable=True
    )
    alert_type: Mapped[str] = mapped_column(String(100))
    message: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_database.py -v
```

Expected: All 8 tests PASS.

**Step 5: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database.py
git commit -m "feat: add all 10 OAM-compliant database models"
```

---

### Task 5: Scope Module

**Files:**
- Create: `shared/lib_webbh/scope.py`
- Create: `tests/test_scope.py`

**Step 1: Write the failing tests**

```python
# tests/test_scope.py
from lib_webbh.scope import ScopeManager, ScopeResult


def _make_profile(
    in_scope_domains=None,
    out_scope_domains=None,
    in_scope_cidrs=None,
    in_scope_regex=None,
):
    return {
        "in_scope_domains": in_scope_domains or [],
        "out_scope_domains": out_scope_domains or [],
        "in_scope_cidrs": in_scope_cidrs or [],
        "in_scope_regex": in_scope_regex or [],
    }


# --- Domain matching ---

def test_wildcard_domain_matches_subdomain():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("api.example.com")
    assert result.in_scope is True
    assert result.normalized == "api.example.com"
    assert result.asset_type == "domain"


def test_wildcard_domain_matches_deep_subdomain():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("deep.sub.api.example.com")
    assert result.in_scope is True
    assert result.normalized == "deep.sub.api.example.com"


def test_exact_domain_no_match():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("other.com")
    assert result.in_scope is False


def test_out_of_scope_overrides_in_scope():
    sm = ScopeManager(_make_profile(
        in_scope_domains=["*.example.com"],
        out_scope_domains=["admin.example.com"],
    ))
    result = sm.is_in_scope("admin.example.com")
    assert result.in_scope is False


# --- URL normalization ---

def test_url_strips_scheme_and_extracts_path():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("https://api.example.com/v1/users?id=1")
    assert result.in_scope is True
    assert result.normalized == "api.example.com"
    assert result.path == "/v1/users?id=1"
    assert result.asset_type == "domain"


def test_url_http_scheme_stripped():
    sm = ScopeManager(_make_profile(in_scope_domains=["*.example.com"]))
    result = sm.is_in_scope("http://app.example.com/login")
    assert result.normalized == "app.example.com"
    assert result.path == "/login"


# --- CIDR/IP matching ---

def test_ip_in_cidr_scope():
    sm = ScopeManager(_make_profile(in_scope_cidrs=["192.168.1.0/24"]))
    result = sm.is_in_scope("192.168.1.50")
    assert result.in_scope is True
    assert result.asset_type == "ip"
    assert result.normalized == "192.168.1.50"


def test_ip_outside_cidr_scope():
    sm = ScopeManager(_make_profile(in_scope_cidrs=["192.168.1.0/24"]))
    result = sm.is_in_scope("10.0.0.1")
    assert result.in_scope is False


def test_cidr_input_matched():
    sm = ScopeManager(_make_profile(in_scope_cidrs=["10.0.0.0/8"]))
    result = sm.is_in_scope("10.0.0.0/24")
    assert result.in_scope is True
    assert result.asset_type == "cidr"


# --- Regex matching ---

def test_regex_scope_match():
    sm = ScopeManager(_make_profile(in_scope_regex=[r".*\.internal\.corp$"]))
    result = sm.is_in_scope("secret.internal.corp")
    assert result.in_scope is True


def test_regex_scope_no_match():
    sm = ScopeManager(_make_profile(in_scope_regex=[r".*\.internal\.corp$"]))
    result = sm.is_in_scope("public.external.com")
    assert result.in_scope is False


# --- Dynamic rules ---

def test_add_rule_at_runtime():
    sm = ScopeManager(_make_profile())
    sm.add_rule("*.newdomain.io", in_scope=True)
    result = sm.is_in_scope("app.newdomain.io")
    assert result.in_scope is True


# --- Summary ---

def test_get_scope_summary():
    sm = ScopeManager(_make_profile(
        in_scope_domains=["*.example.com"],
        in_scope_cidrs=["10.0.0.0/8"],
        in_scope_regex=[r".*\.corp$"],
    ))
    summary = sm.get_scope_summary()
    assert "domains" in summary
    assert "networks" in summary
    assert "regex" in summary
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_scope.py -v
```

Expected: FAIL — `ScopeManager` not defined.

**Step 3: Implement `scope.py`**

```python
# shared/lib_webbh/scope.py
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

import tldextract
from netaddr import IPAddress, IPNetwork, AddrFormatError


@dataclass
class ScopeResult:
    in_scope: bool
    original: str
    normalized: str
    asset_type: str  # "domain" | "ip" | "cidr"
    path: str | None


class ScopeManager:
    def __init__(self, target_profile: dict) -> None:
        self._in_domains: list[str] = []       # registered domains (wildcard)
        self._in_exact_domains: list[str] = []  # exact domain matches
        self._out_domains: list[str] = []
        self._in_networks: list[IPNetwork] = []
        self._regex_rules: list[re.Pattern] = []

        for rule in target_profile.get("in_scope_domains", []):
            if rule.startswith("*."):
                self._in_domains.append(rule[2:].lower())
            else:
                self._in_exact_domains.append(rule.lower())

        for rule in target_profile.get("out_scope_domains", []):
            self._out_domains.append(rule.lower())

        for cidr in target_profile.get("in_scope_cidrs", []):
            self._in_networks.append(IPNetwork(cidr))

        for pattern in target_profile.get("in_scope_regex", []):
            self._regex_rules.append(re.compile(pattern))

    def is_in_scope(self, item: str) -> ScopeResult:
        original = item

        # Try IP/CIDR first
        result = self._check_network(item, original)
        if result is not None:
            return result

        # Try URL / domain
        return self._check_domain(item, original)

    def _check_network(self, item: str, original: str) -> ScopeResult | None:
        try:
            if "/" in item:
                network = IPNetwork(item)
                in_scope = any(
                    network.network in parent and network.broadcast in parent
                    for parent in self._in_networks
                )
                return ScopeResult(
                    in_scope=in_scope,
                    original=original,
                    normalized=str(network.ip),
                    asset_type="cidr",
                    path=None,
                )
            else:
                ip = IPAddress(item)
                in_scope = any(ip in net for net in self._in_networks)
                return ScopeResult(
                    in_scope=in_scope,
                    original=original,
                    normalized=str(ip),
                    asset_type="ip",
                    path=None,
                )
        except (AddrFormatError, ValueError):
            return None

    def _check_domain(self, item: str, original: str) -> ScopeResult:
        path: str | None = None

        # Strip scheme and extract path
        if "://" in item:
            parsed = urlparse(item)
            domain_str = parsed.hostname or parsed.path
            path_parts = parsed.path
            if parsed.query:
                path_parts += "?" + parsed.query
            path = path_parts if path_parts and path_parts != "/" else None
        else:
            # Could be domain or domain/path
            if "/" in item:
                domain_str, _, remainder = item.partition("/")
                path = "/" + remainder
            else:
                domain_str = item

        domain_str = domain_str.lower().strip(".")

        # Check out-of-scope first (always wins)
        if domain_str in self._out_domains:
            return ScopeResult(
                in_scope=False,
                original=original,
                normalized=domain_str,
                asset_type="domain",
                path=path,
            )

        # Check exact domain match
        if domain_str in self._in_exact_domains:
            return ScopeResult(
                in_scope=True,
                original=original,
                normalized=domain_str,
                asset_type="domain",
                path=path,
            )

        # Check wildcard domain match via tldextract
        extracted = tldextract.extract(domain_str)
        registered = f"{extracted.domain}.{extracted.suffix}".lower()

        if registered in self._in_domains or domain_str.endswith(
            tuple(f".{d}" for d in self._in_domains)
        ):
            return ScopeResult(
                in_scope=True,
                original=original,
                normalized=domain_str,
                asset_type="domain",
                path=path,
            )

        # Check regex rules
        for pattern in self._regex_rules:
            if pattern.search(domain_str):
                return ScopeResult(
                    in_scope=True,
                    original=original,
                    normalized=domain_str,
                    asset_type="domain",
                    path=path,
                )

        return ScopeResult(
            in_scope=False,
            original=original,
            normalized=domain_str,
            asset_type="domain",
            path=path,
        )

    def add_rule(self, rule: str, in_scope: bool = True) -> None:
        if not in_scope:
            self._out_domains.append(rule.lower())
            return

        # Check if CIDR
        try:
            self._in_networks.append(IPNetwork(rule))
            return
        except (AddrFormatError, ValueError):
            pass

        # Domain rule
        if rule.startswith("*."):
            self._in_domains.append(rule[2:].lower())
        else:
            self._in_exact_domains.append(rule.lower())

    def get_scope_summary(self) -> dict:
        return {
            "domains": {
                "wildcard": [f"*.{d}" for d in self._in_domains],
                "exact": list(self._in_exact_domains),
                "excluded": list(self._out_domains),
            },
            "networks": [str(n) for n in self._in_networks],
            "regex": [p.pattern for p in self._regex_rules],
        }
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_scope.py -v
```

Expected: All 13 tests PASS.

**Step 5: Commit**

```bash
git add shared/lib_webbh/scope.py tests/test_scope.py
git commit -m "feat: add ScopeManager with tldextract normalization and ScopeResult"
```

---

### Task 6: Messaging Module

**Files:**
- Create: `shared/lib_webbh/messaging.py`
- Create: `tests/test_messaging.py`

**Step 1: Write the failing tests**

```python
# tests/test_messaging.py
import asyncio
import json

import pytest

from lib_webbh.messaging import push_task, listen_queue, get_pending, get_redis


@pytest.fixture
async def redis_client():
    """Requires a running Redis on localhost:6379 (or REDIS_HOST/REDIS_PORT)."""
    client = get_redis()
    yield client
    # Cleanup test streams
    await client.delete("test_queue")
    await client.aclose()


@pytest.mark.asyncio
async def test_push_task_returns_message_id(redis_client):
    msg_id = await push_task("test_queue", {"target_id": 1, "action": "scan"})
    assert msg_id is not None
    assert isinstance(msg_id, str)
    assert "-" in msg_id  # Redis stream IDs are "timestamp-seq"


@pytest.mark.asyncio
async def test_push_and_consume(redis_client):
    received = []

    async def handler(message_id: str, data: dict) -> None:
        received.append(data)

    await push_task("test_queue", {"target_id": 1, "action": "test_consume"})

    # Run listener for a short burst
    listener_task = asyncio.create_task(
        listen_queue("test_queue", "test_group", "consumer_1", handler)
    )
    await asyncio.sleep(1)
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    assert len(received) == 1
    assert received[0]["action"] == "test_consume"


@pytest.mark.asyncio
async def test_get_pending_returns_empty_after_ack(redis_client):
    await push_task("test_queue", {"target_id": 2, "action": "pending_test"})

    async def handler(message_id: str, data: dict) -> None:
        pass  # ACK happens automatically in listen_queue

    listener_task = asyncio.create_task(
        listen_queue("test_queue", "test_group", "consumer_1", handler)
    )
    await asyncio.sleep(1)
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    pending = await get_pending("test_queue", "test_group")
    # After ACK, pending count should be 0
    assert pending["pending"] == 0
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_messaging.py -v
```

Expected: FAIL — `push_task` not defined.

**Step 3: Implement `messaging.py`**

```python
# shared/lib_webbh/messaging.py
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import redis.asyncio as aioredis

# ---------------------------------------------------------------------------
# Redis Singleton
# ---------------------------------------------------------------------------

_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        host = os.environ.get("REDIS_HOST", "localhost")
        port = int(os.environ.get("REDIS_PORT", "6379"))
        _redis = aioredis.Redis(host=host, port=port, decode_responses=True)
    return _redis


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def push_task(queue: str, data: dict[str, Any]) -> str:
    r = get_redis()
    payload = json.dumps(data, default=str)
    timestamp = datetime.now(timezone.utc).isoformat()
    msg_id: str = await r.xadd(queue, {"payload": payload, "timestamp": timestamp})
    return msg_id


async def listen_queue(
    queue: str,
    group: str,
    consumer: str,
    callback: Callable[[str, dict[str, Any]], Awaitable[None]],
) -> None:
    r = get_redis()

    # Create consumer group if it doesn't exist
    try:
        await r.xgroup_create(queue, group, id="0", mkstream=True)
    except aioredis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise

    while True:
        messages = await r.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={queue: ">"},
            count=10,
            block=5000,
        )
        if not messages:
            continue

        for stream_name, stream_messages in messages:
            for msg_id, fields in stream_messages:
                data = json.loads(fields["payload"])
                await callback(msg_id, data)
                await r.xack(queue, group, msg_id)


async def get_pending(queue: str, group: str) -> dict[str, Any]:
    r = get_redis()
    info = await r.xpending(queue, group)
    return {
        "pending": info.get("pending", 0) if isinstance(info, dict) else info[0] if info else 0,
        "raw": info,
    }
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_messaging.py -v
```

Expected: All 3 tests PASS (requires Redis running on localhost:6379).

> **Note:** These tests require a live Redis instance. In CI, use a Redis service container. Locally, run `docker run -d -p 6379:6379 redis:alpine` before testing.

**Step 5: Commit**

```bash
git add shared/lib_webbh/messaging.py tests/test_messaging.py
git commit -m "feat: add Redis Streams messaging with consumer groups"
```

---

### Task 7: Setup Env Script

**Files:**
- Create: `shared/setup_env.py`
- Create: `tests/test_setup_env.py`

**Step 1: Write the failing tests**

```python
# tests/test_setup_env.py
import os
import tempfile

from shared.setup_env import generate_env


def test_generate_env_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        assert os.path.exists(env_path)


def test_generate_env_contains_required_keys():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        with open(env_path) as f:
            content = f.read()
        assert "WEB_APP_BH_API_KEY=" in content
        assert "HOST_IP=" in content
        assert "DB_HOST=" in content
        assert "DB_PORT=" in content
        assert "DB_NAME=" in content
        assert "DB_USER=" in content
        assert "DB_PASS=" in content
        assert "REDIS_HOST=" in content
        assert "REDIS_PORT=" in content


def test_api_key_is_64_chars():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        with open(env_path) as f:
            for line in f:
                if line.startswith("WEB_APP_BH_API_KEY="):
                    key = line.strip().split("=", 1)[1]
                    assert len(key) == 64
                    break


def test_idempotent_does_not_overwrite():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        with open(env_path) as f:
            first_content = f.read()
        generate_env(output_path=env_path)
        with open(env_path) as f:
            second_content = f.read()
        assert first_content == second_content
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_setup_env.py -v
```

Expected: FAIL — `generate_env` not defined.

**Step 3: Implement `setup_env.py`**

```python
# shared/setup_env.py
from __future__ import annotations

import os
import secrets
import socket


def generate_env(output_path: str = "/app/shared/config/.env") -> None:
    if os.path.exists(output_path):
        return

    api_key = secrets.token_hex(32)
    db_pass = secrets.token_hex(16)

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        host_ip = "127.0.0.1"

    env_content = (
        f"WEB_APP_BH_API_KEY={api_key}\n"
        f"HOST_IP={host_ip}\n"
        f"DB_HOST=postgres\n"
        f"DB_PORT=5432\n"
        f"DB_NAME=webbh\n"
        f"DB_USER=webbh_admin\n"
        f"DB_PASS={db_pass}\n"
        f"REDIS_HOST=redis\n"
        f"REDIS_PORT=6379\n"
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(env_content)

    print(f"[setup_env] API Key: {api_key}")
    print(f"[setup_env] .env written to: {output_path}")


if __name__ == "__main__":
    generate_env()
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_setup_env.py -v
```

Expected: All 4 tests PASS.

**Step 5: Commit**

```bash
git add shared/setup_env.py tests/test_setup_env.py
git commit -m "feat: add setup_env.py for auto-generating .env config"
```

---

### Task 8: Package Exports (`__init__.py`)

**Files:**
- Modify: `shared/lib_webbh/__init__.py`
- Create: `tests/test_init.py`

**Step 1: Write the failing test**

```python
# tests/test_init.py

def test_all_public_exports_importable():
    from lib_webbh import (
        get_engine,
        get_session,
        Target,
        Asset,
        Identity,
        Location,
        Observation,
        CloudAsset,
        Parameter,
        Vulnerability,
        JobState,
        Alert,
        ScopeManager,
        ScopeResult,
        push_task,
        listen_queue,
        get_pending,
        setup_logger,
    )
    # If we get here, all imports succeeded
    assert True
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_init.py -v
```

Expected: FAIL — imports not available.

**Step 3: Write `__init__.py`**

```python
# shared/lib_webbh/__init__.py

# Database
from lib_webbh.database import get_engine, get_session, Base
from lib_webbh.database import (
    Target,
    Asset,
    Identity,
    Location,
    Observation,
    CloudAsset,
    Parameter,
    Vulnerability,
    JobState,
    Alert,
)

# Scope
from lib_webbh.scope import ScopeManager, ScopeResult

# Messaging
from lib_webbh.messaging import push_task, listen_queue, get_pending

# Logger
from lib_webbh.logger import setup_logger

__all__ = [
    "get_engine",
    "get_session",
    "Base",
    "Target",
    "Asset",
    "Identity",
    "Location",
    "Observation",
    "CloudAsset",
    "Parameter",
    "Vulnerability",
    "JobState",
    "Alert",
    "ScopeManager",
    "ScopeResult",
    "push_task",
    "listen_queue",
    "get_pending",
    "setup_logger",
]
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_init.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add shared/lib_webbh/__init__.py tests/test_init.py
git commit -m "feat: add public API exports to __init__.py"
```

---

### Task 9: Dockerfile.base

**Files:**
- Create: `docker/Dockerfile.base`

**Step 1: Write the Dockerfile**

```dockerfile
# docker/Dockerfile.base
FROM python:3.10-slim

WORKDIR /app

# System deps for asyncpg compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy shared library
COPY shared/lib_webbh /app/shared/lib_webbh

# Install lib_webbh (editable for dev, deps are in setup.py)
RUN pip install --no-cache-dir -e /app/shared/lib_webbh

# Copy setup_env script
COPY shared/setup_env.py /app/shared/setup_env.py

# Create shared volume directories
RUN mkdir -p /app/shared/raw /app/shared/config /app/shared/logs

# Verify install
RUN python -c "from lib_webbh import Target, ScopeManager, setup_logger; print('lib_webbh OK')"
```

**Step 2: Build to verify**

```bash
docker build -f docker/Dockerfile.base -t webbh-base:latest .
```

Expected: Successful build ending with `lib_webbh OK`.

**Step 3: Commit**

```bash
git add docker/Dockerfile.base
git commit -m "feat: add Dockerfile.base with lib_webbh pre-installed"
```

---

### Task 10: Full Integration Test & Cleanup

**Files:**
- Create: `tests/test_integration.py`

**Step 1: Write integration test**

```python
# tests/test_integration.py
"""
Integration test that exercises the full lib_webbh flow:
  Target → Asset → Location → Observation → Vulnerability → Alert
  + ScopeManager check + Logger output
Requires: aiosqlite (no Postgres needed)
"""
import json
import os
import tempfile

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from lib_webbh import (
    get_engine,
    get_session,
    Base,
    Target,
    Asset,
    Location,
    Observation,
    Vulnerability,
    Alert,
    ScopeManager,
    setup_logger,
)


@pytest.mark.asyncio
async def test_full_recon_flow(capsys):
    # 1. Create tables
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Insert a target
    async with get_session() as session:
        target = Target(
            company_name="IntegrationCorp",
            base_domain="integcorp.com",
            target_profile={
                "in_scope_domains": ["*.integcorp.com"],
                "out_scope_domains": ["admin.integcorp.com"],
                "in_scope_cidrs": ["10.0.0.0/24"],
                "in_scope_regex": [],
            },
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)

    # 3. ScopeManager check
    scope = ScopeManager(target.target_profile)
    result = scope.is_in_scope("https://api.integcorp.com/v1/health")
    assert result.in_scope is True
    assert result.normalized == "api.integcorp.com"
    assert result.path == "/v1/health"

    # Out-of-scope check
    blocked = scope.is_in_scope("admin.integcorp.com")
    assert blocked.in_scope is False

    # 4. Insert asset, location, observation, vuln, alert
    async with get_session() as session:
        asset = Asset(
            target_id=target.id,
            asset_type="subdomain",
            asset_value="api.integcorp.com",
            source_tool="amass",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(
            asset_id=asset.id, port=443, protocol="tcp", service="https", state="open"
        )
        obs = Observation(
            asset_id=asset.id,
            tech_stack={"server": "nginx", "framework": "FastAPI"},
            page_title="API Docs",
            status_code=200,
            headers={"x-powered-by": "FastAPI"},
        )
        session.add_all([loc, obs])
        await session.commit()

        vuln = Vulnerability(
            target_id=target.id,
            asset_id=asset.id,
            severity="high",
            title="IDOR on /v1/users",
            description="User ID enumeration via sequential IDs",
            poc="curl https://api.integcorp.com/v1/users/2",
            source_tool="manual",
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)

        alert = Alert(
            target_id=target.id,
            vulnerability_id=vuln.id,
            alert_type="high_severity_finding",
            message="IDOR found on api.integcorp.com",
            is_read=False,
        )
        session.add(alert)
        await session.commit()

    # 5. Logger
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("integration-test", log_dir=tmpdir)
        bound = log.bind(target_id=target.id, asset_type="vulnerability")
        bound.info("IDOR detected", extra={"asset": "api.integcorp.com", "source_tool": "manual"})

        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["target_id"] == target.id
        assert record["extra"]["asset_type"] == "vulnerability"
```

**Step 2: Run full test suite**

```bash
pytest tests/ -v --ignore=tests/test_messaging.py
```

Expected: All tests PASS. (`test_messaging.py` skipped unless Redis is running.)

**Step 3: Run messaging tests if Redis is available**

```bash
pytest tests/test_messaging.py -v
```

Expected: All 3 PASS with Redis running.

**Step 4: Final commit**

```bash
git add tests/test_integration.py
git commit -m "feat: add full integration test for lib_webbh"
```

---

## Task Summary

| Task | Description | Tests |
|---|---|---|
| 1 | Project scaffolding & `setup.py` | Install verification |
| 2 | Logger module | 6 tests |
| 3 | Database engine singleton | 4 tests |
| 4 | Database OAM models (10 tables) | 4 tests |
| 5 | Scope module | 13 tests |
| 6 | Messaging module (Redis Streams) | 3 tests |
| 7 | Setup env script | 4 tests |
| 8 | Package exports (`__init__.py`) | 1 test |
| 9 | Dockerfile.base | Docker build verification |
| 10 | Full integration test | 1 integration test |

**Total: 10 tasks, 36 tests**
