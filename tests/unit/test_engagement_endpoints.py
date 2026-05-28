"""Unit tests for orchestrator engagement endpoints (no live DB/network)."""
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("DB_DRIVER", "sqlite+aiosqlite")
    monkeypatch.setenv("DB_NAME", ":memory:")
    monkeypatch.setenv("REDIS_HOST", "localhost")
    monkeypatch.setenv("WEB_APP_BH_API_KEY", "test-key")


@pytest.fixture
def client():
    # Patch the lifespan to skip DB init and Redis/event-engine startup
    async def _noop_lifespan(app):
        yield

    from contextlib import asynccontextmanager

    noop_lifespan = asynccontextmanager(_noop_lifespan)

    with patch("orchestrator.main.lifespan", noop_lifespan):
        # Re-create the app with the no-op lifespan
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from fastapi.middleware.cors import CORSMiddleware

        import importlib
        import orchestrator.main as main_mod

        # Build a minimal test app that includes only the engagement router
        test_app = FastAPI()

        from orchestrator.routes.engagements import router as engagements_router
        test_app.include_router(engagements_router)

        return TestClient(test_app)


def test_search_endpoint_rejects_unknown_platform(client):
    resp = client.post("/api/v1/engagements/search", json={
        "platform": "unknown",
        "company_name": "Acme",
    })
    assert resp.status_code == 400
    assert "Unsupported platform" in resp.json()["detail"]


def test_fetch_endpoint_rejects_unknown_platform(client):
    resp = client.post("/api/v1/engagements/fetch", json={
        "platform": "unknown",
        "handle": "acme",
        "url": "https://example.com",
    })
    assert resp.status_code == 400
    assert "Unsupported platform" in resp.json()["detail"]


def test_search_endpoint_returns_404_when_no_programs(client):
    with patch(
        "orchestrator.routes.engagements.search_programs",
        new=AsyncMock(return_value=[]),
    ):
        resp = client.post("/api/v1/engagements/search", json={
            "platform": "bugcrowd",
            "company_name": "NonExistentCorp",
        })
    assert resp.status_code == 404
    assert "No program found" in resp.json()["detail"]
