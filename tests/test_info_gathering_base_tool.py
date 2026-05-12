# tests/test_info_gathering_base_tool.py
"""Regression tests for InfoGatheringTool base helpers."""
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.httpx import Httpx


class _Dummy(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> None:
        ...


class TestSaveObservation:
    @pytest.mark.anyio
    async def test_save_observation_accepts_asset_id_keyword(self):
        """Locks the kwarg contract: save_observation(asset_id=..., tech_stack=..., status_code=..., headers=...)."""
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            sess.add = MagicMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            sess.refresh = AsyncMock(side_effect=lambda obs: setattr(obs, "id", 42))
            obs_id = await tool.save_observation(
                asset_id=501,
                tech_stack={"_probe": "banner", "server": "nginx"},
                status_code=200,
                headers={"Server": "nginx"},
            )
        sess.add.assert_called_once()
        sess.commit.assert_awaited_once()
        sess.refresh.assert_awaited_once()
        assert obs_id == 42


class TestHttpxObservationLinkage:
    @pytest.mark.anyio
    async def test_httpx_writes_observation_against_asset_id(self, tmp_path):
        """Httpx must call save_observation with asset_id, not target_id."""
        tool = Httpx()
        line = json.dumps({"url": "https://a.com", "status_code": 200, "title": "T", "tech": ["nginx"]})

        fake = MagicMock()
        fake.name = str(tmp_path / "hosts.txt")
        fake.__enter__ = MagicMock(return_value=fake)
        fake.__exit__ = MagicMock(return_value=False)
        fake.write = MagicMock()

        with patch("workers.info_gathering.tools.httpx.tempfile.NamedTemporaryFile",
                   return_value=fake), \
             patch("workers.info_gathering.tools.httpx.os.path.exists", return_value=False), \
             patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=line), \
             patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1) as save:
            await tool.execute(target_id=1, asset_id=501, host="a.com")

        kwargs = save.call_args.kwargs
        assert "asset_id" in kwargs
        assert kwargs["asset_id"] == 501
        assert "target_id" not in kwargs
