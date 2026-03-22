# tests/test_intel_enrichment.py
"""Tests for Intel Enrichment (Shodan + SecurityTrails) and API key management."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("WEB_APP_BH_API_KEY", "test-api-key-1234")

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import tests._patch_logger  # noqa: F401

from lib_webbh.database import Base, Target, Asset, get_engine, get_session
import lib_webbh.intel_enrichment as intel_mod
from lib_webbh.intel_enrichment import (
    IntelResult,
    enrich_shodan,
    enrich_securitytrails,
    get_available_intel_sources,
)


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
        t = Target(company_name="IntelCorp", base_domain="intelcorp.com")
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


# ---------------------------------------------------------------------------
# Unit tests — enrichment functions
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_shodan_no_key():
    """enrich_shodan returns empty IntelResult when no API key is set."""
    result = await enrich_shodan("example.com", api_key="")
    assert isinstance(result, IntelResult)
    assert result.source == "shodan"
    assert result.subdomains == []
    assert result.ips == []
    assert result.ports == []
    assert result.raw == {"error": "no_api_key"}


@pytest.mark.anyio
async def test_securitytrails_no_key():
    """enrich_securitytrails returns empty IntelResult when no API key is set."""
    result = await enrich_securitytrails("example.com", api_key="")
    assert isinstance(result, IntelResult)
    assert result.source == "securitytrails"
    assert result.subdomains == []
    assert result.ips == []
    assert result.ports == []
    assert result.raw == {"error": "no_api_key"}


@pytest.mark.anyio
async def test_shodan_with_results():
    """enrich_shodan extracts subdomains, IPs, and ports from mocked responses."""
    dns_response = MagicMock()
    dns_response.status_code = 200
    dns_response.json.return_value = {
        "domain": "example.com",
        "data": [
            {"subdomain": "www", "type": "A", "value": "93.184.216.34"},
            {"subdomain": "api", "type": "A", "value": "93.184.216.35"},
            {"subdomain": "mail", "type": "MX", "value": "mail.example.com"},
        ],
    }
    dns_response.raise_for_status = MagicMock()

    host_response_1 = MagicMock()
    host_response_1.status_code = 200
    host_response_1.json.return_value = {
        "data": [
            {"port": 80, "product": "nginx"},
            {"port": 443, "product": "nginx"},
        ],
    }
    host_response_1.raise_for_status = MagicMock()

    host_response_2 = MagicMock()
    host_response_2.status_code = 200
    host_response_2.json.return_value = {
        "data": [
            {"port": 8080, "_shodan": {"module": "http"}},
        ],
    }
    host_response_2.raise_for_status = MagicMock()

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        if "/dns/domain/" in url:
            return dns_response
        # Host lookups
        call_count += 1
        if call_count == 1:
            return host_response_1
        return host_response_2

    mock_client = AsyncMock()
    mock_client.get = mock_get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("lib_webbh.intel_enrichment.httpx.AsyncClient", return_value=mock_client):
        result = await enrich_shodan("example.com", api_key="test-key")

    assert result.source == "shodan"
    assert "www.example.com" in result.subdomains
    assert "api.example.com" in result.subdomains
    assert "mail.example.com" in result.subdomains
    assert "93.184.216.34" in result.ips
    assert "93.184.216.35" in result.ips
    assert len(result.ports) == 3
    assert {"ip": "93.184.216.34", "port": 80, "service": "nginx"} in result.ports
    assert {"ip": "93.184.216.34", "port": 443, "service": "nginx"} in result.ports


@pytest.mark.anyio
async def test_securitytrails_with_results():
    """enrich_securitytrails extracts subdomains and IPs from mocked responses."""
    sub_response = MagicMock()
    sub_response.status_code = 200
    sub_response.json.return_value = {
        "subdomains": ["www", "api", "staging"],
        "endpoint": "/v1/domain/example.com/subdomains",
    }
    sub_response.raise_for_status = MagicMock()

    dns_response = MagicMock()
    dns_response.status_code = 200
    dns_response.json.return_value = {
        "current_dns": {
            "a": {
                "values": [
                    {"ip": "93.184.216.34"},
                    {"ip": "93.184.216.35"},
                ],
            },
        },
    }
    dns_response.raise_for_status = MagicMock()

    async def mock_get(url, **kwargs):
        if "/subdomains" in url:
            return sub_response
        return dns_response

    mock_client = AsyncMock()
    mock_client.get = mock_get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("lib_webbh.intel_enrichment.httpx.AsyncClient", return_value=mock_client):
        result = await enrich_securitytrails("example.com", api_key="test-key")

    assert result.source == "securitytrails"
    assert "www.example.com" in result.subdomains
    assert "api.example.com" in result.subdomains
    assert "staging.example.com" in result.subdomains
    assert "93.184.216.34" in result.ips
    assert "93.184.216.35" in result.ips


def test_get_available_sources():
    """get_available_intel_sources returns correct bool dict based on module vars."""
    original_shodan = intel_mod.SHODAN_API_KEY
    original_st = intel_mod.SECURITYTRAILS_API_KEY

    try:
        intel_mod.SHODAN_API_KEY = "some-key"
        intel_mod.SECURITYTRAILS_API_KEY = ""

        sources = get_available_intel_sources()
        assert sources["shodan"] is True
        assert sources["securitytrails"] is False

        intel_mod.SHODAN_API_KEY = ""
        intel_mod.SECURITYTRAILS_API_KEY = "another-key"

        sources = get_available_intel_sources()
        assert sources["shodan"] is False
        assert sources["securitytrails"] is True

        intel_mod.SHODAN_API_KEY = ""
        intel_mod.SECURITYTRAILS_API_KEY = ""

        sources = get_available_intel_sources()
        assert sources["shodan"] is False
        assert sources["securitytrails"] is False
    finally:
        intel_mod.SHODAN_API_KEY = original_shodan
        intel_mod.SECURITYTRAILS_API_KEY = original_st


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_api_key_status_endpoint(client, db):
    """GET /api/v1/config/api_keys returns correct key status."""
    original_shodan = intel_mod.SHODAN_API_KEY
    original_st = intel_mod.SECURITYTRAILS_API_KEY

    try:
        intel_mod.SHODAN_API_KEY = ""
        intel_mod.SECURITYTRAILS_API_KEY = ""

        resp = await client.get("/api/v1/config/api_keys")
        assert resp.status_code == 200
        body = resp.json()
        assert "keys" in body
        assert body["keys"]["shodan"] is False
        assert body["keys"]["securitytrails"] is False
    finally:
        intel_mod.SHODAN_API_KEY = original_shodan
        intel_mod.SECURITYTRAILS_API_KEY = original_st


@pytest.mark.anyio
async def test_enrich_target_endpoint(client, seed_target):
    """POST /api/v1/targets/{id}/enrich creates assets from mocked enrichment."""
    mock_shodan = IntelResult(
        source="shodan",
        subdomains=["www.intelcorp.com", "api.intelcorp.com"],
        ips=["10.0.0.1"],
        ports=[{"ip": "10.0.0.1", "port": 443, "service": "nginx"}],
    )
    mock_st = IntelResult(
        source="securitytrails",
        subdomains=["staging.intelcorp.com", "api.intelcorp.com"],  # overlap
        ips=["10.0.0.2"],
    )

    with patch("orchestrator.main.enrich_shodan", new_callable=AsyncMock, return_value=mock_shodan), \
         patch("orchestrator.main.enrich_securitytrails", new_callable=AsyncMock, return_value=mock_st):
        resp = await client.post(f"/api/v1/targets/{seed_target}/enrich")

    assert resp.status_code == 200
    body = resp.json()
    assert body["target_id"] == seed_target
    assert body["domain"] == "intelcorp.com"
    assert body["total_subdomains"] == 3  # www, api, staging (deduped)
    assert body["total_ips"] == 2  # 10.0.0.1, 10.0.0.2
    assert body["inserted_subdomains"] == 3
    assert body["inserted_ips"] == 2
    assert body["sources"]["shodan"]["subdomains"] == 2
    assert body["sources"]["securitytrails"]["subdomains"] == 2

    # Verify assets in DB
    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(Asset).where(Asset.target_id == seed_target)
        )
        assets = result.scalars().all()
        assert len(assets) == 5  # 3 subdomains + 2 IPs
        subdomain_vals = {a.asset_value for a in assets if a.asset_type == "subdomain"}
        ip_vals = {a.asset_value for a in assets if a.asset_type == "ip"}
        assert subdomain_vals == {"www.intelcorp.com", "api.intelcorp.com", "staging.intelcorp.com"}
        assert ip_vals == {"10.0.0.1", "10.0.0.2"}
        for a in assets:
            assert a.source_tool == "intel_enrichment"


@pytest.mark.anyio
async def test_enrich_target_not_found(client, db):
    """POST /api/v1/targets/99999/enrich returns 404."""
    resp = await client.post("/api/v1/targets/99999/enrich")
    assert resp.status_code == 404
    assert "Target not found" in resp.json()["detail"]


@pytest.mark.anyio
async def test_enrich_target_dedup(client, seed_target):
    """POST /api/v1/targets/{id}/enrich skips duplicate assets."""
    # Pre-insert an asset
    async with get_session() as session:
        session.add(Asset(
            target_id=seed_target,
            asset_type="subdomain",
            asset_value="www.intelcorp.com",
            source_tool="manual",
        ))
        await session.commit()

    mock_shodan = IntelResult(
        source="shodan",
        subdomains=["www.intelcorp.com"],  # already exists
        ips=[],
    )
    mock_st = IntelResult(
        source="securitytrails",
        subdomains=["new.intelcorp.com"],
        ips=[],
    )

    with patch("orchestrator.main.enrich_shodan", new_callable=AsyncMock, return_value=mock_shodan), \
         patch("orchestrator.main.enrich_securitytrails", new_callable=AsyncMock, return_value=mock_st):
        resp = await client.post(f"/api/v1/targets/{seed_target}/enrich")

    assert resp.status_code == 200
    body = resp.json()
    assert body["inserted_subdomains"] == 1  # only new.intelcorp.com
    assert body["total_subdomains"] == 2  # www + new
