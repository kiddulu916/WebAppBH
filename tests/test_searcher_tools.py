"""Tests for ShodanSearcher, CensysSearcher, and SecurityTrailsSearcher."""

import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# ShodanSearcher
# ---------------------------------------------------------------------------

class TestShodanSearcher:
    @pytest.mark.anyio
    async def test_skips_when_no_api_key(self):
        from workers.info_gathering.tools.shodan_searcher import ShodanSearcher

        with patch.dict(os.environ, {"SHODAN_API_KEY": ""}, clear=False):
            tool = ShodanSearcher()
            result = await tool.execute(target_id=1, domain="example.com")
        assert result["skipped"] is True
        assert result["reason"] == "no_api_key"

    @pytest.mark.anyio
    async def test_saves_subdomains_and_ips(self):
        from workers.info_gathering.tools.shodan_searcher import ShodanSearcher

        @dataclass
        class FakeIntelResult:
            source: str = "shodan"
            subdomains: list = field(default_factory=lambda: ["api.example.com", "www.example.com"])
            ips: list = field(default_factory=lambda: ["1.2.3.4"])
            ports: list = field(default_factory=list)
            raw: dict = field(default_factory=dict)

        tool = ShodanSearcher()
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-key"}), \
             patch("lib_webbh.intel_enrichment.enrich_shodan",
                   new_callable=AsyncMock, return_value=FakeIntelResult()), \
             patch.object(tool, "save_asset", new_callable=AsyncMock, return_value=1):
            result = await tool.execute(target_id=1, domain="example.com", scope_manager=AsyncMock())
        assert result["found"] == 3  # 2 subdomains + 1 IP

    @pytest.mark.anyio
    async def test_returns_found_zero_when_no_domain(self):
        from workers.info_gathering.tools.shodan_searcher import ShodanSearcher

        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-key"}):
            tool = ShodanSearcher()
            result = await tool.execute(target_id=1)
        assert result == {"found": 0}


# ---------------------------------------------------------------------------
# CensysSearcher
# ---------------------------------------------------------------------------

class TestCensysSearcher:
    @pytest.mark.anyio
    async def test_skips_when_no_api_id(self):
        from workers.info_gathering.tools.censys_searcher import CensysSearcher

        with patch.dict(os.environ, {"CENSYS_API_ID": "", "CENSYS_API_SECRET": ""}, clear=False):
            tool = CensysSearcher()
            result = await tool.execute(target_id=1, domain="example.com")
        assert result["skipped"] is True

    @pytest.mark.anyio
    async def test_skips_when_only_id_set(self):
        from workers.info_gathering.tools.censys_searcher import CensysSearcher

        with patch.dict(os.environ, {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": ""}, clear=False):
            tool = CensysSearcher()
            result = await tool.execute(target_id=1, domain="example.com")
        assert result["skipped"] is True

    @pytest.mark.anyio
    async def test_returns_found_zero_when_no_domain(self):
        from workers.info_gathering.tools.censys_searcher import CensysSearcher

        with patch.dict(os.environ, {"CENSYS_API_ID": "id", "CENSYS_API_SECRET": "secret"}):
            tool = CensysSearcher()
            result = await tool.execute(target_id=1)
        assert result == {"found": 0}


# ---------------------------------------------------------------------------
# SecurityTrailsSearcher
# ---------------------------------------------------------------------------

class TestSecurityTrailsSearcher:
    @pytest.mark.anyio
    async def test_skips_when_no_api_key(self):
        from workers.info_gathering.tools.securitytrails_searcher import SecurityTrailsSearcher

        with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": ""}, clear=False):
            tool = SecurityTrailsSearcher()
            result = await tool.execute(target_id=1, domain="example.com")
        assert result["skipped"] is True
        assert result["reason"] == "no_api_key"

    @pytest.mark.anyio
    async def test_returns_found_zero_when_no_domain(self):
        from workers.info_gathering.tools.securitytrails_searcher import SecurityTrailsSearcher

        with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "test-key"}):
            tool = SecurityTrailsSearcher()
            result = await tool.execute(target_id=1)
        assert result == {"found": 0}
