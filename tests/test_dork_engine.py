"""Tests for DorkEngine rewrite and dork_patterns library."""

import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.dork_engine import DorkEngine
from workers.info_gathering.tools.dork_patterns import DORK_CATEGORIES, get_dorks_for_domain


class TestDorkPatterns:
    def test_categories_count(self):
        assert len(DORK_CATEGORIES) == 8

    def test_get_dorks_interpolates_domain(self):
        dorks = get_dorks_for_domain("example.com")
        assert any("site:example.com" in d for d in dorks)
        assert len(dorks) >= 60

    def test_all_dorks_contain_domain_reference(self):
        dorks = get_dorks_for_domain("example.com")
        domain_dorks = [d for d in dorks if "example.com" in d]
        assert len(domain_dorks) >= len(dorks) * 0.8

    def test_categories_are_named(self):
        expected = {
            "exposed_files",
            "admin_panels",
            "sensitive_dirs",
            "config_leaks",
            "error_pages",
            "login_pages",
            "api_endpoints",
            "backup_files",
        }
        assert set(DORK_CATEGORIES.keys()) == expected

    def test_no_empty_categories(self):
        for name, templates in DORK_CATEGORIES.items():
            assert len(templates) > 0, f"Category {name} is empty"


class TestDorkEngine:
    @pytest.mark.anyio
    async def test_rotates_across_engines(self):
        """Queries should be distributed across multiple search engines."""
        engine = DorkEngine()
        with patch.object(
            engine, "_scrape_engine", new_callable=AsyncMock, return_value=[]
        ), patch(
            "workers.info_gathering.tools.dork_engine.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            await engine.execute(
                target_id=1, domain="example.com", scope_manager=AsyncMock()
            )
            calls = engine._scrape_engine.call_args_list
            engines_used = {c.args[0] for c in calls}
            assert len(engines_used) >= 2

    @pytest.mark.anyio
    async def test_returns_stats_dict(self):
        """Execute should return a stats dict with 'found' count."""
        engine = DorkEngine()
        with patch.object(
            engine, "_scrape_engine", new_callable=AsyncMock, return_value=[]
        ), patch(
            "workers.info_gathering.tools.dork_engine.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            result = await engine.execute(
                target_id=1, domain="example.com", scope_manager=AsyncMock()
            )
            assert isinstance(result, dict)
            assert "found" in result

    @pytest.mark.anyio
    async def test_deduplicates_results(self):
        """Duplicate URLs from different engines should be deduplicated."""
        engine = DorkEngine()
        fake_results = [
            {"url": "https://example.com/admin", "title": "Admin"},
            {"url": "https://example.com/admin", "title": "Admin"},
        ]
        with patch.object(
            engine, "_scrape_engine", new_callable=AsyncMock, return_value=fake_results
        ), patch.object(
            engine, "save_asset", new_callable=AsyncMock, return_value=1
        ), patch(
            "workers.info_gathering.tools.dork_engine.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            await engine.execute(
                target_id=1, domain="example.com", scope_manager=AsyncMock()
            )
            saved_urls = [
                call.kwargs.get("asset_value") or call.args[2]
                for call in engine.save_asset.call_args_list
            ]
            assert len(saved_urls) == len(set(saved_urls))
