# tests/test_scope_violations.py
"""Tests for scope violation audit log: record_scope_violation() + API endpoint."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import asyncio

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, ScopeViolation, get_engine, get_session
from lib_webbh.scope import record_scope_violation


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(company_name="ScopeTest", base_domain="scope.test")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t.id


@pytest.fixture
def client():
    with patch("orchestrator.event_engine.run_event_loop", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_heartbeat", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_redis_listener", new_callable=AsyncMock), \
         patch("orchestrator.event_engine.run_autoscaler", new_callable=AsyncMock):
        from httpx import ASGITransport, AsyncClient
        from orchestrator.main import app
        transport = ASGITransport(app=app)
        return AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-KEY": "test-api-key-1234"},
        )


# ---- Unit test: record_scope_violation ----

@pytest.mark.anyio
async def test_record_scope_violation(seed_target):
    target_id = seed_target
    await record_scope_violation(
        target_id=target_id,
        tool_name="subfinder",
        input_value="evil.com",
        violation_type="domain",
    )
    async with get_session() as session:
        from sqlalchemy import select
        stmt = select(ScopeViolation).where(ScopeViolation.target_id == target_id)
        result = await session.execute(stmt)
        rows = result.scalars().all()
    assert len(rows) == 1
    assert rows[0].tool_name == "subfinder"
    assert rows[0].input_value == "evil.com"
    assert rows[0].violation_type == "domain"


# ---- API endpoint tests ----

@pytest.mark.anyio
async def test_list_scope_violations_endpoint(client, seed_target):
    target_id = seed_target
    # Seed two violations directly
    async with get_session() as session:
        session.add(ScopeViolation(
            target_id=target_id, tool_name="httpx", input_value="bad.org", violation_type="domain",
        ))
        session.add(ScopeViolation(
            target_id=target_id, tool_name="nmap", input_value="10.0.0.1", violation_type="ip",
        ))
        await session.commit()

    resp = await client.get("/api/v1/scope_violations", params={"target_id": target_id})
    assert resp.status_code == 200
    body = resp.json()
    assert "violations" in body
    assert len(body["violations"]) == 2
    tool_names = {v["tool_name"] for v in body["violations"]}
    assert tool_names == {"httpx", "nmap"}


@pytest.mark.anyio
async def test_list_scope_violations_limit(client, seed_target):
    target_id = seed_target
    async with get_session() as session:
        for i in range(5):
            session.add(ScopeViolation(
                target_id=target_id,
                tool_name=f"tool_{i}",
                input_value=f"val_{i}",
                violation_type="domain",
            ))
        await session.commit()

    resp = await client.get("/api/v1/scope_violations", params={"target_id": target_id, "limit": 2})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["violations"]) == 2


@pytest.mark.anyio
async def test_list_scope_violations_ordering(client, seed_target):
    target_id = seed_target
    from datetime import datetime, timedelta, timezone

    async with get_session() as session:
        older = ScopeViolation(
            target_id=target_id, tool_name="older_tool", input_value="old.com", violation_type="domain",
        )
        older.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        session.add(older)
        await session.flush()

        newer = ScopeViolation(
            target_id=target_id, tool_name="newer_tool", input_value="new.com", violation_type="domain",
        )
        newer.created_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
        session.add(newer)
        await session.commit()

    resp = await client.get("/api/v1/scope_violations", params={"target_id": target_id})
    assert resp.status_code == 200
    body = resp.json()
    violations = body["violations"]
    assert len(violations) == 2
    # Most recent first
    assert violations[0]["tool_name"] == "newer_tool"
    assert violations[1]["tool_name"] == "older_tool"
