# tests/test_app_path_enumerator.py
"""Tests for AppPathEnumerator — WSTG-INFO-04 non-standard URL path discovery."""
from __future__ import annotations

import json
import os
import tempfile

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.app_path_enumerator import (
    AppPathEnumerator,
    APP_PATHS,
    HIT_CODES,
)


@pytest.fixture
def tool():
    return AppPathEnumerator()


@pytest.fixture
def mock_target():
    t = MagicMock()
    t.base_domain = "example.com"
    return t


def _write_ffuf_output(results: list) -> str:
    """Write a ffuf JSON output file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"results": results}, f)
        return f.name


class TestConstants:
    def test_wordlist_contains_key_app_paths(self):
        for path in ("admin", "portal", "webmail", "graphql", "swagger", "dashboard"):
            assert path in APP_PATHS

    def test_hit_codes_exclude_404(self):
        assert 404 not in HIT_CODES

    def test_hit_codes_include_auth_denials(self):
        assert 401 in HIT_CODES
        assert 403 in HIT_CODES

    def test_hit_codes_include_redirects(self):
        for code in (301, 302, 307, 308):
            assert code in HIT_CODES


class TestParseAndSave:
    @pytest.mark.anyio
    async def test_saves_200_hit_as_url_asset_and_observation(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/admin", "status": 200, "length": 1234, "redirectlocation": ""},
        ])
        saved_assets = []
        saved_obs = []

        async def fake_save_asset(target_id, asset_type, value, source, scope_manager=None, **kw):
            saved_assets.append({"type": asset_type, "value": value})
            return 42

        async def fake_save_observation(asset_id, **kw):
            saved_obs.append({"asset_id": asset_id, **kw})
            return 1

        tool.save_asset = fake_save_asset
        tool.save_observation = fake_save_observation

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 1}
        assert saved_assets[0] == {"type": "url", "value": "https://example.com/admin"}
        assert saved_obs[0]["asset_id"] == 42
        assert saved_obs[0]["status_code"] == 200

    @pytest.mark.anyio
    async def test_drops_404_responses(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/notfound", "status": 404, "length": 0, "redirectlocation": ""},
        ])
        tool.save_asset = AsyncMock(return_value=1)

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 0}
        tool.save_asset.assert_not_awaited()

    @pytest.mark.anyio
    async def test_saves_401_and_403_hits(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/admin", "status": 401, "length": 100, "redirectlocation": ""},
            {"url": "https://example.com/internal", "status": 403, "length": 200, "redirectlocation": ""},
        ])
        tool.save_asset = AsyncMock(side_effect=[42, 43])
        tool.save_observation = AsyncMock(return_value=1)

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 2}

    @pytest.mark.anyio
    async def test_records_redirect_url_in_observation(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/portal", "status": 302,
             "length": 0, "redirectlocation": "https://example.com/portal/login"},
        ])
        saved_obs = []

        tool.save_asset = AsyncMock(return_value=42)

        async def fake_save_observation(asset_id, **kw):
            saved_obs.append(kw)
            return 1

        tool.save_observation = fake_save_observation

        try:
            await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert saved_obs[0]["headers"]["redirect_url"] == "https://example.com/portal/login"

    @pytest.mark.anyio
    async def test_returns_zero_for_missing_output_file(self, tool):
        result = await tool._parse_and_save(1, "/tmp/no_such_ffuf_output_xyz.json", "example.com", None)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_skips_hit_when_save_asset_returns_none(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/admin", "status": 200, "length": 500, "redirectlocation": ""},
        ])
        tool.save_asset = AsyncMock(return_value=None)
        tool.save_observation = AsyncMock(return_value=1)

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 0}
        tool.save_observation.assert_not_awaited()


class TestExecute:
    @pytest.mark.anyio
    async def test_returns_zero_without_target(self, tool):
        result = await tool.execute(1)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_returns_zero_when_ffuf_fails(self, tool, mock_target):
        tool.run_subprocess = AsyncMock(side_effect=Exception("ffuf not found"))
        result = await tool.execute(1, target=mock_target, scope_manager=None)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_cleans_up_temp_files_on_success(self, tool, mock_target):
        created_paths = []

        async def capture_and_run(cmd, **kw):
            for i, arg in enumerate(cmd):
                if arg in ("-w", "-o"):
                    created_paths.append(cmd[i + 1])
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                json.dump({"results": []}, f)

        tool.run_subprocess = capture_and_run
        await tool.execute(1, target=mock_target, scope_manager=None)

        for path in created_paths:
            assert not os.path.exists(path), f"Temp file not cleaned up: {path}"
